/**
 * Representative, hand-written multi-peer scenarios for the differential harness.
 *
 * These adapt the shapes exercised by the existing `sync*.test.ts` suite — the
 * current correctness bar — into the harness contract. Each returns the named
 * CoValue cores and nodes to snapshot; the harness captures the wire trace, the
 * per-node confirmed+optimistic known-state, and the convergence verdict, then
 * freezes them as golden fixtures.
 *
 * The set deliberately spans the failure-mode-bearing paths called out by the
 * scoping pass: basic two-peer sync, reconnect-with-offline-writes, streaming
 * large content, deletion/tombstones, load/correction on assumed-invalid state,
 * and concurrent multi-peer fan-out.
 *
 * TEST-ONLY. No production import.
 */
import type { RawCoMap } from "../../coValues/coMap.js";
import { fillCoMapWithLargeData, waitFor } from "../testUtils.js";
import type { Scenario } from "./harness.js";
import {
  attachStorage,
  connect,
  disconnect,
  makeNode,
  stabilize,
  type MeshNode,
} from "./mesh.js";

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise<void>((resolve) => queueMicrotask(resolve));
  }
}

async function settle(...nodes: MeshNode[]): Promise<void> {
  await flush();
  await Promise.all(
    nodes.map((n) =>
      n.node.syncManager.waitForAllCoValuesSync(10_000).catch(() => {}),
    ),
  );
  await flush();
}

function nodeMap(...nodes: MeshNode[]) {
  return Object.fromEntries(nodes.map((n) => [n.name, n.node]));
}

/** 1. Basic two-peer sync through a relay server, then a third peer loads. */
export const basicTwoPeerSync: Scenario = {
  name: "basic_two_peer_sync",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    map.set("count", 1, "trusting");

    await settle(server, clientA, clientB);
    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 2. Reconnect with offline writes: client writes while disconnected, then
 * reconnects — exercises the server's persistent PeerState + the optimistic
 * reset on reconnect. */
export const reconnectWithDataLoss: Scenario = {
  name: "reconnect_with_data_loss",
  run: async () => {
    const server = makeNode("server");
    const client = makeNode("client");
    connect(server, client);

    const group = client.node.createGroup();
    group.addMember("everyone", "writer");
    const map = group.createMap();
    map.set("k1", "v1", "trusting");
    await settle(server, client);

    // Drop the connection, keep writing offline.
    disconnect(server, client);
    map.set("k2", "v2", "trusting");
    map.set("k3", "v3", "trusting");
    await flush();

    // Reconnect: server's persistent known-state is reused via
    // newPeerStateFrom -> cloneWithoutOptimistic.
    connect(server, client);
    await stabilize([server, client], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, client),
    };
  },
};

/** 3. Streaming large content in chunks, then a second peer streams it in. */
export const streamingLargeContent: Scenario = {
  name: "streaming_large_content",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    fillCoMapWithLargeData(map as unknown as RawCoMap);

    await settle(server, clientA, clientB);
    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(map.core.id);
      if (!core.isAvailable() || core.isStreaming())
        throw new Error("map not fully streamed to clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 4. Deletion: a synced CoValue is deleted; a fresh peer loads only the
 * tombstone. */
export const deletion: Scenario = {
  name: "deletion",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(server, clientA, clientB);

    map.core.deleteCoValue();
    await settle(server, clientA, clientB);
    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(map.core.id);
      if (!core.isDeleted) throw new Error("tombstone not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 5. Correction: server suffers local data loss, so the client's next push
 * lands on an assumed-invalid state and the server issues a KNOWN CORRECTION. */
export const correctionInvalidState: Scenario = {
  name: "correction_invalid_state_assumed",
  run: async () => {
    const server = makeNode("server");
    const client = makeNode("client");
    connect(server, client);

    const group = client.node.createGroup();
    group.addMember("everyone", "writer");
    const map = group.createMap({ seed: "initial" });
    await settle(server, client);

    // Simulate server-side data loss for the map.
    server.node.internalDeleteCoValue(map.core.id);

    // Client's optimistic known-state now disagrees with the server -> correction.
    map.set("seed", "updated", "trusting");
    await settle(server, client);
    await waitFor(() => {
      const core = server.node.expectCoValueLoaded(map.core.id);
      if (!core.isAvailable()) throw new Error("server has not recovered map");
    });
    await stabilize([server, client], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, client),
    };
  },
};

/** 6. Concurrent multi-peer fan-out: three clients each write a distinct key on
 * a shared map; all must converge. */
export const concurrentFanOut: Scenario = {
  name: "concurrent_multi_peer_fanout",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    const clientC = makeNode("clientC");
    connect(server, clientA);
    connect(server, clientB);
    connect(server, clientC);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "writer");
    const map = group.createMap();
    map.set("a", 0, "trusting");
    await settle(server, clientA, clientB, clientC);

    // All three load the map.
    for (const c of [clientB, clientC]) {
      await waitFor(async () => {
        const core = await c.node.loadCoValueCore(map.core.id);
        if (!core.isAvailable()) throw new Error("map not yet loaded");
      });
    }
    await settle(server, clientA, clientB, clientC);

    // Concurrent writes from each client's own session.
    const mapA = map;
    const mapB = (
      await clientB.node.loadCoValueCore(map.core.id)
    ).getCurrentContent() as unknown as RawCoMap;
    const mapC = (
      await clientC.node.loadCoValueCore(map.core.id)
    ).getCurrentContent() as unknown as RawCoMap;
    mapA.set("fromA", "A", "trusting");
    mapB.set("fromB", "B", "trusting");
    mapC.set("fromC", "C", "trusting");

    await stabilize(
      [server, clientA, clientB, clientC],
      [group.core.id, map.core.id],
    );

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB, clientC),
    };
  },
};

/** 7. Storage-backed response: a node with a real SQLite storage but zero
 * in-memory knowledge of a CoValue answers a fresh peer's load purely from
 * disk. */
export const storageBackedResponse: Scenario = {
  name: "load_storage_backed_response",
  run: async () => {
    const writer = makeNode("writer");
    const dbPath = attachStorage(writer);

    const group = writer.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await map.core.waitForSync();
    await writer.node.gracefulShutdown();

    // A fresh, unrelated node attaches to the SAME storage file — it has
    // zero in-memory knowledge of this CoValue, only what's in the DB.
    const storageOnly = makeNode("storageOnly");
    attachStorage(storageOnly, dbPath);

    const requester = makeNode("requester");
    connect(storageOnly, requester);

    const loaded = await requester.node.loadCoValueCore(map.core.id);
    await waitFor(() => {
      if (!loaded.isAvailable()) throw new Error("not yet loaded");
    });
    await stabilize([storageOnly, requester], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(storageOnly, requester),
    };
  },
};

/** 8. Load with no storage forwards to peers: a peer requests a CoValue this
 * node has never heard of and has no storage for — it must forward the
 * request to its own server peers (`loadFromPeersAndRespond`) rather than
 * answering directly. */
export const loadForwardsToPeers: Scenario = {
  name: "load_no_storage_forwards_to_peers",
  run: async () => {
    const origin = makeNode("origin");
    const relay = makeNode("relay");
    const requester = makeNode("requester");
    connect(origin, relay);
    connect(relay, requester);

    const group = origin.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(origin, relay);

    // requester asks relay for a CoValue relay has never independently
    // touched from requester's session — relay has no storage, so it must
    // forward the request to its own server peer (origin).
    const loaded = await requester.node.loadCoValueCore(map.core.id);
    await waitFor(() => {
      if (!loaded.isAvailable()) throw new Error("not yet loaded");
    });
    await stabilize([origin, relay, requester], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(origin, relay, requester),
    };
  },
};

/** 9. Peer already has all content: a node whose only knowledge of a CoValue
 * comes from storage (never loaded it into memory) receives a `load` message
 * from a peer that has already fully synced that CoValue elsewhere. The
 * storage-check inside `handleLoad` (`sync.ts:924-936`) finds the peer's
 * reported known-state already covers everything storage holds, so it
 * replies with a KNOWN ack — not a CONTENT resend — and calls
 * `coValue.loadFromPeers(serverPeers, "low-priority")` to keep the
 * subscription alive for future updates rather than dropping it.
 *
 * Note: a node re-requesting a CoValue it created itself never produces this
 * branch — its own in-memory copy short-circuits `handleLoad`'s fast path
 * before the storage check ever runs. Instead, `requester` primes itself by
 * loading the CoValue from `writer` first (so it holds full content in
 * memory), then `writer` is torn down and a brand-new `storageOnly` node
 * attaches to the same on-disk storage (zero in-memory knowledge, only what
 * `writer` persisted). Reconnecting `requester` to `storageOnly` makes
 * `requester`'s own peer-reconciliation resend a `load` message carrying its
 * own full known-state — exactly the condition `peerHasAllContent` checks
 * for against `storageOnly`'s storage-backed known-state. */
export const loadPeerHasAllContent: Scenario = {
  name: "load_peer_has_all_content_keeps_subscription",
  run: async () => {
    const writer = makeNode("writer");
    const dbPath = attachStorage(writer);

    const group = writer.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await map.core.waitForSync();

    // requester loads the CoValue directly from writer (still in memory
    // there), so requester ends up holding the full content itself.
    const requester = makeNode("requester");
    connect(writer, requester);
    const primed = await requester.node.loadCoValueCore(map.core.id);
    await waitFor(() => {
      if (!primed.isAvailable()) throw new Error("not primed on requester");
    });

    disconnect(writer, requester);
    await writer.node.gracefulShutdown();

    // A fresh node attaches to the SAME storage file — it has zero in-memory
    // knowledge of group/map, only what writer persisted to disk.
    const storageOnly = makeNode("storageOnly");
    attachStorage(storageOnly, dbPath);

    // requester still holds group/map fully in memory, so reconnecting it as
    // a client of storageOnly makes it resend LOAD messages carrying its own
    // full known-state for both — the peer-has-all-content condition.
    connect(storageOnly, requester);
    await settle(storageOnly, requester);
    await stabilize([storageOnly, requester], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(storageOnly, requester),
    };
  },
};

export const scenarios: Scenario[] = [
  basicTwoPeerSync,
  reconnectWithDataLoss,
  streamingLargeContent,
  deletion,
  correctionInvalidState,
  concurrentFanOut,
  storageBackedResponse,
  loadForwardsToPeers,
  loadPeerHasAllContent,
];
