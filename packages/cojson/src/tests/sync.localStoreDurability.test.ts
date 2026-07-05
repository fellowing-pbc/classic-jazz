import { beforeEach, describe, expect, test, vi } from "vitest";
import { WasmNode } from "../node/WasmNode.js";
import { LocalNode } from "../localNode";
import {
  SyncMessagesLog,
  getSyncServerConnectedPeer,
  loadCoValueOrFail,
  setupTestNode,
  waitFor,
} from "./testUtils";
import { getDbPath, registerStorageCleanupRunner } from "./testStorage";

const Crypto = await WasmNode.create();

let jazzCloud: ReturnType<typeof setupTestNode>;

beforeEach(async () => {
  registerStorageCleanupRunner();
  SyncMessagesLog.clear();
  jazzCloud = setupTestNode({ isSyncServer: true });
});

describe("StorageAPI.store done callback", () => {
  test("async storage invokes done after the write completes", async () => {
    const client = setupTestNode();
    const group = client.node.createGroup();
    // Attach storage after creating the group so our manual store is the only write
    const { storage } = await client.addAsyncStorage();

    const content = group.core.newContentSince(undefined)!;
    const done = vi.fn();

    storage.store(content[0]!, () => undefined, done);

    expect(done).not.toHaveBeenCalled();
    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });

  test("sync storage invokes done synchronously", async () => {
    const client = setupTestNode();
    const group = client.node.createGroup();
    const { storage } = client.addStorage();

    const content = group.core.newContentSince(undefined)!;
    const done = vi.fn();

    storage.store(content[0]!, () => undefined, done);

    expect(done).toHaveBeenCalledTimes(1);
  });

  test("async storage invokes done after a successful correction round-trip", async () => {
    const client = setupTestNode();
    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("a", 1, "trusting");
    const { storage } = await client.addAsyncStorage();

    const fullContent = map.core.newContentSince(undefined)!;
    // Content without the header, stored into empty storage → triggers a correction
    const withoutHeader = map.core.newContentSince({
      id: map.id,
      header: true,
      sessions: {},
    })!;
    const done = vi.fn();

    storage.store(withoutHeader[0]!, () => fullContent, done);

    await waitFor(() => expect(done).toHaveBeenCalledTimes(1));
  });
});

describe("local store durability window", () => {
  test("opens before the first peer send and closes when async storage drains", async () => {
    const client = setupTestNode();
    await client.addAsyncStorage();
    const { peerState } = client.connectToSyncServer();

    // Instrument the actual outgoing push: the window must open before any
    // content message physically leaves the node
    let contentSent = false;
    const originalPush = peerState.pushOutgoingMessage.bind(peerState);
    vi.spyOn(peerState, "pushOutgoingMessage").mockImplementation((msg) => {
      if (msg.action === "content") {
        contentSent = true;
      }
      return originalPush(msg);
    });

    const events: Array<{ hasPending: boolean; contentSentAlready: boolean }> =
      [];
    client.node.syncManager.onLocalStoreDurabilityChange = (hasPending) => {
      events.push({ hasPending, contentSentAlready: contentSent });
    };

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    await waitFor(() => expect(events.some((e) => !e.hasPending)).toBe(true));

    // The window opened BEFORE any content was sent to a peer
    expect(events[0]).toEqual({ hasPending: true, contentSentAlready: false });
    // ...and eventually closed once storage drained
    expect(events.at(-1)!.hasPending).toBe(false);
  });

  test("reopens for a new local edit after the previous window closed", async () => {
    const client = setupTestNode();
    await client.addAsyncStorage();
    client.connectToSyncServer();

    const events: boolean[] = [];
    client.node.syncManager.onLocalStoreDurabilityChange = (hasPending) => {
      events.push(hasPending);
    };

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    // First window: opened and closed once storage drained
    await waitFor(() => expect(events).toEqual([true, false]));

    // A second local edit reopens the window and it closes again on drain
    map.set("second", "batch", "trusting");

    await waitFor(() => expect(events).toEqual([true, false, true, false]));
  });

  test("reports the node's current session ID", async () => {
    const client = setupTestNode();
    await client.addAsyncStorage();
    client.connectToSyncServer();

    const sessions: string[] = [];
    client.node.syncManager.onLocalStoreDurabilityChange = (
      _hasPending,
      sessionID,
    ) => {
      sessions.push(sessionID);
    };

    const group = client.node.createGroup();
    group.createMap().set("hello", "world", "trusting");

    await waitFor(() => expect(sessions.length).toBeGreaterThan(0));
    expect(sessions.every((s) => s === client.node.currentSessionID)).toBe(
      true,
    );
  });

  test("does not fire with synchronous storage", async () => {
    const client = setupTestNode();
    client.addStorage();
    client.connectToSyncServer();

    const listener = vi.fn();
    client.node.syncManager.onLocalStoreDurabilityChange = listener;

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    await map.core.waitForSync();
    expect(listener).not.toHaveBeenCalled();
  });

  test("does not fire when there are no peers to send to", async () => {
    const client = setupTestNode(); // not connected
    await client.addAsyncStorage();

    const listener = vi.fn();
    client.node.syncManager.onLocalStoreDurabilityChange = listener;

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    await client.node.syncManager.waitForStorageSync(map.id);
    expect(listener).not.toHaveBeenCalled();
  });

  test("remote content does not open the window on the receiving node", async () => {
    const server = setupTestNode({ isSyncServer: true });
    await server.addAsyncStorage({ ourName: "server" });

    const listener = vi.fn();
    server.node.syncManager.onLocalStoreDurabilityChange = listener;

    const client = setupTestNode({ connected: true });
    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    await map.core.waitForSync();
    expect(listener).not.toHaveBeenCalled();
  });

  test("window stays open when storage writes never complete (crash window)", async () => {
    const client = setupTestNode();
    const { storage } = await client.addAsyncStorage();
    const { peerState } = client.connectToSyncServer();

    // Simulate the crash window: storage accepts writes but never completes them
    storage.store = async () => {};

    const events: boolean[] = [];
    client.node.syncManager.onLocalStoreDurabilityChange = (hasPending) =>
      events.push(hasPending);

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    // Wait for the content to reach the server (peer sync only) — storage sync
    // never resolves in this scenario since store() is stubbed to a no-op, so
    // we can't use map.core.waitForSync() here, which also waits on storage.
    await client.node.syncManager.waitForSyncWithPeer(
      peerState.id,
      map.id,
      5000,
    );
    expect(events).toEqual([true]); // opened, never closed
  });

  test("opens when pending content is sent through reconnection reconciliation", async () => {
    const client = setupTestNode();
    const { storage } = await client.addAsyncStorage();

    // Writes never complete: the local edit below stays pending forever
    storage.store = async () => {};

    const events: boolean[] = [];
    client.node.syncManager.onLocalStoreDurabilityChange = (hasPending) =>
      events.push(hasPending);

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    // Not connected yet: nothing was sent, so the window must not be open
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(events).toEqual([]);

    // Connecting sends the pending content through reconciliation
    // (sendNewContent), not through syncContent — the window must still open
    const { peerState } = client.connectToSyncServer();
    await client.node.syncManager.waitForSyncWithPeer(
      peerState.id,
      map.id,
      5000,
    );

    expect(events).toEqual([true]);
  });
});

describe("LocalNode creation options", () => {
  test("withNewlyCreatedAccount wires onLocalStoreDurabilityChange into the node's syncManager", async () => {
    const listener = vi.fn();

    const { node } = await LocalNode.withNewlyCreatedAccount({
      creationProps: { name: "test" },
      crypto: Crypto,
      peers: [],
      onLocalStoreDurabilityChange: listener,
    });

    expect(node.syncManager.onLocalStoreDurabilityChange).toBe(listener);
    await node.gracefulShutdown();
  });

  test("withLoadedAccount wires onLocalStoreDurabilityChange", async () => {
    const listener = vi.fn();

    const created = await LocalNode.withNewlyCreatedAccount({
      creationProps: { name: "test" },
      crypto: Crypto,
      peers: [],
    });

    const { peer } = getSyncServerConnectedPeer({
      peerId: created.accountID,
    });

    // Sync the account to the server so it can be loaded
    created.node.syncManager.addPeer(peer);
    await created.node.syncManager.waitForAllCoValuesSync();

    const { peer: peer2 } = getSyncServerConnectedPeer({
      peerId: "loadingNode",
    });

    const node = await LocalNode.withLoadedAccount({
      accountID: created.accountID,
      accountSecret: created.accountSecret,
      sessionID: undefined,
      peers: [peer2],
      crypto: Crypto,
      onLocalStoreDurabilityChange: listener,
    });

    expect(node.syncManager.onLocalStoreDurabilityChange).toBe(listener);
    await node.gracefulShutdown();
    await created.node.gracefulShutdown();
  });
});

describe("crash recovery with a fresh session", () => {
  test("restarting with a new session over the same storage recovers and syncs cleanly", async () => {
    const client = setupTestNode();
    const dbPath = getDbPath();
    const { storage } = await client.addAsyncStorage({ filename: dbPath });
    const { peerState } = client.connectToSyncServer();

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await map.core.waitForSync();

    // Enter the crash window: further writes reach the server but not storage
    storage.store = async () => {};
    map.set("crashed", "yes", "trusting");
    await client.node.syncManager.waitForSyncWithPeer(
      peerState.id,
      map.id,
      5000,
    );

    // "Crash": abandon the node without flushing (no graceful shutdown), then
    // restart with the SAME agent, SAME storage file, but a NEW session — which
    // is exactly what the session providers do when the durability marker is set.
    client.disconnect();
    const restarted = setupTestNode({ secret: client.node.agentSecret });
    await restarted.addAsyncStorage({ filename: dbPath });
    restarted.connectToSyncServer();

    // The fresh session is load-bearing: reusing the crashed session could fork its hash chain
    expect(restarted.node.currentSessionID).not.toBe(
      client.node.currentSessionID,
    );

    // The crashed transaction comes back down from the server
    const mapOnRestart = await loadCoValueOrFail(restarted.node, map.id);
    await waitFor(() => expect(mapOnRestart.get("crashed")).toEqual("yes"));

    // New writes from the fresh session sync cleanly — no signature rejection
    mapOnRestart.set("recovered", "yes", "trusting");
    await mapOnRestart.core.waitForSync();

    const mapOnServer = await loadCoValueOrFail(jazzCloud.node, map.id);
    expect(mapOnServer.get("recovered")).toEqual("yes");
    expect(mapOnServer.get("crashed")).toEqual("yes");
  });
});
