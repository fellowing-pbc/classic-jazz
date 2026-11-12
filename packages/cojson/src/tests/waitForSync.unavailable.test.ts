import { beforeEach, describe, expect, test } from "vitest";
import {
  SyncMessagesLog,
  TEST_NODE_CONFIG,
  blockMessageTypeOnOutgoingPeer,
  createUnloadedCoValue,
  setupTestNode,
  shouldNotResolve,
} from "./testUtils";

const WAIT_TIMEOUT = 2_000;

beforeEach(() => {
  // Peers answer a tick later, so a load is still in flight when the wait starts
  TEST_NODE_CONFIG.withAsyncPeers = true;

  SyncMessagesLog.clear();
  setupTestNode({ isSyncServer: true });
});

describe("waitForSync on a CoValue that exists nowhere", () => {
  test("resolves when a load in flight ends unavailable", async () => {
    const client = setupTestNode({ connected: true });
    const { id } = createUnloadedCoValue(client.node);

    const load = client.node.loadCoValueCore(id, undefined, true);
    expect(client.node.getCoValue(id).loadingState).toBe("loading");

    await client.node.syncManager.waitForSync(id, WAIT_TIMEOUT);

    expect((await load).loadingState).toBe("unavailable");
  });

  test("resolves at once when the CoValue is already unavailable", async () => {
    const client = setupTestNode({ connected: true });
    const { id } = createUnloadedCoValue(client.node);

    await client.node.loadCoValueCore(id, undefined, true);
    expect(client.node.getCoValue(id).loadingState).toBe("unavailable");

    await client.node.syncManager.waitForSync(id, WAIT_TIMEOUT);
  });

  test("holds while another server has not answered yet", async () => {
    const client = setupTestNode({ connected: true });
    const otherServer = setupTestNode();
    const { peerOnServer } = client.connectToSyncServer({
      syncServer: otherServer.node,
      syncServerName: "other-server",
    });
    const { id } = createUnloadedCoValue(client.node);
    blockMessageTypeOnOutgoingPeer(peerOnServer, "known", { id });

    void client.node.loadCoValueCore(id, undefined, true);
    const wait = client.node.syncManager.waitForSync(id, WAIT_TIMEOUT);

    await shouldNotResolve(wait, { timeout: 300 });
    expect(client.node.getCoValue(id).loadingState).toBe("loading");
  });

  test("holds a CoValue loaded with content until the server has it", async () => {
    const client = setupTestNode();
    const { storage } = client.addStorage({ ourName: "client" });
    const map = client.node.createGroup().createMap();
    map.set("hello", "world", "trusting");

    await client.restart();
    client.addStorage({ storage });
    const { peer } = client.connectToSyncServer();
    const upload = blockMessageTypeOnOutgoingPeer(peer, "content", {});

    await client.node.loadCoValueCore(map.id);
    const wait = client.node.syncManager.waitForSync(map.id, WAIT_TIMEOUT);

    await shouldNotResolve(wait, { timeout: 300 });

    upload.unblock();
    await upload.sendBlockedMessages();

    await wait;
  });

  test("rejects at the timeout when the load never answers, leaving no listeners", async () => {
    const client = setupTestNode();
    const { peer } = client.connectToSyncServer();
    blockMessageTypeOnOutgoingPeer(peer, "load", {});
    const { id } = createUnloadedCoValue(client.node);

    void client.node.loadCoValueCore(id, undefined, true);
    const coValue = client.node.getCoValue(id);
    expect(coValue.loadingState).toBe("loading");
    const listenersBefore = coValue.listeners.size;

    await expect(client.node.syncManager.waitForSync(id, 200)).rejects.toThrow(
      "Timeout on waiting for sync",
    );

    expect(coValue.listeners.size).toBe(listenersBefore);
    const syncStateListeners =
      client.node.syncManager.syncState["listenersByPeersAndCoValues"];
    expect(syncStateListeners.get(peer.id)?.get(id)?.size ?? 0).toBe(0);
  });
});
