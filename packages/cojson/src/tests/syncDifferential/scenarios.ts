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
import { expectMap } from "../../coValue.js";
import type { RawCoList } from "../../coValues/coList.js";
import type { RawCoMap } from "../../coValues/coMap.js";
import type { Signature } from "../../crypto/crypto.js";
import { emptyKnownState } from "../../knownState.js";
import type { JsonValue } from "../../jsonValue.js";
import type { Stringified } from "../../jsonStringify.js";
import { CO_VALUE_PRIORITY } from "../../priority.js";
import { fillCoMapWithLargeData, waitFor } from "../testUtils.js";
import type { Scenario } from "./harness.js";
import {
  attachStorage,
  connect,
  disconnect,
  makeNode,
  peerStateFor,
  restartNode,
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
 * for against `storageOnly`'s storage-backed known-state.
 *
 * `core` is layered in upstream of both `writer` and `storageOnly` as a
 * *persistent server-role peer* (present before `requester` ever connects to
 * `storageOnly`) so that the branch's `getServerPeers(msg.id, peer.id)` call
 * resolves to a non-empty list — without it, `storageOnly` would have no
 * server peer of its own and `coValue.loadFromPeers([], "low-priority")`
 * would be an unobservable no-op.
 *
 * `writer` connects to `core` as a CLIENT (not the other way around) for two
 * reasons: (1) it lets `core` pick up the content automatically as `writer`
 * writes it — a client's local writes push straight to its connected
 * peers — with no separate priming step; (2) it makes `core` a *persistent*
 * server peer of `writer`, so once `map.core.waitForSync()` resolves the
 * durability tracker records the CoValues as synced-to-a-persistent-peer in
 * `writer`'s storage file. That matters because `storageOnly` reopens that
 * very file: if the CoValues were still flagged unsynced on disk, wiring
 * `core` in as `storageOnly`'s own persistent server peer below would make
 * `storageOnly`'s connection-time reconciliation (`resumeUnsyncedCoValues`)
 * eagerly reload them into memory on its own — which would make the
 * CoValues already `isAvailable()` by the time `requester`'s load arrives,
 * short-circuiting `handleLoad`'s fast path (`sync.ts:896`) before the
 * `peerHasAllContent` branch under test ever runs. */
export const loadPeerHasAllContent: Scenario = {
  name: "load_peer_has_all_content_keeps_subscription",
  run: async () => {
    const writer = makeNode("writer");
    const dbPath = attachStorage(writer);

    // core is writer's persistent server peer, so writer's writes below
    // propagate to it automatically, and the durability tracker in writer's
    // storage file records the CoValues as synced once core acks them.
    const core = makeNode("core");
    connect(core, writer);

    const group = writer.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await map.core.waitForSync();

    const coreMap = core.node.getCoValue(map.core.id);
    await waitFor(() => {
      if (!coreMap.isAvailable()) throw new Error("not synced to core");
    });

    // requester loads the CoValue directly from writer (still in memory
    // there), so requester ends up holding the full content itself.
    const requester = makeNode("requester");
    connect(writer, requester);
    const primed = await requester.node.loadCoValueCore(map.core.id);
    await waitFor(() => {
      if (!primed.isAvailable()) throw new Error("not primed on requester");
    });

    disconnect(core, writer);
    disconnect(writer, requester);
    await writer.node.gracefulShutdown();

    // A fresh node attaches to the SAME storage file — it has zero in-memory
    // knowledge of group/map, only what writer persisted to disk.
    const storageOnly = makeNode("storageOnly");
    attachStorage(storageOnly, dbPath);

    // Wire storageOnly to core FIRST — as core's client, so core is a
    // persistent server-role peer on storageOnly's side by the time
    // requester's load arrives below. This is the peer the
    // peerHasAllContent branch's loadFromPeers(serverPeers, ...) call will
    // target.
    connect(core, storageOnly);
    await settle(core, storageOnly);

    // requester still holds group/map fully in memory, so reconnecting it as
    // a client of storageOnly makes it resend LOAD messages carrying its own
    // full known-state for both — the peer-has-all-content condition.
    connect(storageOnly, requester);
    await settle(storageOnly, requester);
    await stabilize(
      [core, storageOnly, requester],
      [group.core.id, map.core.id],
    );

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(core, storageOnly, requester),
    };
  },
};

/** 10. Known-state merge triggers immediate send: a third peer announces its
 * own (empty) known state to the server via a bare, unprompted `known`
 * message for each CoValue — NOT a `load` message. This is structurally
 * distinct from `basic_two_peer_sync`'s third-peer cold-load (which exercises
 * `handleLoad`'s overwrite semantics, `peer.setKnownState`): here the server
 * already holds both CoValues in memory (`coValue.isAvailable()`), so the
 * incoming `known` message routes through `handleKnownState`'s
 * `combineWith`-merge branch (sync.ts:1027,1038) and fires an immediate
 * `sendNewContent` off the merge itself — with no `load` round-trip anywhere
 * in the exchange. */
export const knownStateTriggersSend: Scenario = {
  name: "known_state_merge_triggers_immediate_send",
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
    await settle(server, clientA);

    // clientB is already connected but has never asked about Group/Map. A
    // cold-loading peer normally issues an explicit LOAD here (exercising
    // handleLoad's overwrite semantics, `peer.setKnownState` -- see
    // `basic_two_peer_sync`). Instead, clientB announces its own (empty)
    // state via a bare, unprompted KNOWN message for each CoValue -- exactly
    // what a peer's "here's what I currently have" announcement looks like on
    // the wire. Server already holds both in memory, so `handleKnownState`'s
    // `combineWith`-merge branch (sync.ts:1027,1038) fires directly off the
    // incoming KNOWN and immediately pushes full content back -- no LOAD
    // round-trip anywhere in the exchange.
    const serverPeerFromClientB = peerStateFor(clientB, server);
    for (const id of [group.core.id, map.core.id]) {
      serverPeerFromClientB.pushOutgoingMessage({
        action: "known",
        id,
        header: false,
        sessions: {},
      });
    }

    await waitFor(() => {
      const core = clientB.node.getCoValue(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 11. Known-state merge triggers deferred load: `handleKnownState`'s OTHER
 * branch (sync.ts:1039-1044) from `known_state_merge_triggers_immediate_send`
 * above. There, the server held both CoValues in memory, so the incoming
 * `known` fired `sendNewContent` directly off the merge. Here, the server has
 * unmounted its in-memory copy of `map` down to a knownState-only shell
 * (`internalUnmountCoValue` -- garbage-collected/shell state: not
 * `isAvailable()`, but `isKnownStateAvailable()`), so the merge instead falls
 * through to `this.local.loadCoValueCore(msg.id).then(() =>
 * this.sendNewContent(...))` -- a load (here, satisfied from the server's own
 * attached storage, with no further wire traffic) THEN a send, rather than an
 * immediate send off the merge.
 *
 * As with the immediate-send scenario, a normal cold-connecting peer's own
 * reconciliation flow (`startPeerReconciliation` / `handleReconcile`'s
 * `maybeSendLoadRequest`, sync.ts ~1088-1108) only ever emits an explicit
 * `load`, never a spontaneous `known` -- so a plain
 * `clientB.node.loadCoValueCore(...)` call would land in `handleLoad`, not
 * `handleKnownState`, and never reach this branch at all. We reuse the same
 * hand-crafted, bare KNOWN message technique from the immediate-send
 * scenario, but aim it at the CoValue the server has unmounted. */
export const knownStateTriggersDeferredLoad: Scenario = {
  name: "known_state_merge_triggers_deferred_load",
  run: async () => {
    const server = makeNode("server");
    attachStorage(server);
    const clientA = makeNode("clientA");
    connect(server, clientA);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(server, clientA);

    // Force server's in-memory copy out (garbage-collected shell state, only
    // knownState cached, not full content) so the next known-state message
    // about it must go through the deferred-load-then-send path. Requires
    // storage attached (`setGarbageCollectedState` is a no-op without it),
    // no listeners/dependants on `map`, and `map` already synced to server's
    // (zero) server peers -- all true right after `settle`.
    const unmounted = server.node.internalUnmountCoValue(map.core.id);
    if (!unmounted) {
      throw new Error("failed to unmount map on server");
    }
    const shell = server.node.getCoValue(map.core.id);
    if (shell.isAvailable() || !shell.isKnownStateAvailable()) {
      throw new Error(
        "expected map to be unavailable-but-known-state-available on server after unmount",
      );
    }

    const clientB = makeNode("clientB");
    connect(server, clientB);

    // clientB announces its own (empty) state via a bare, unprompted KNOWN
    // message for each CoValue -- not the LOAD its real reconciliation flow
    // would send (see `known_state_merge_triggers_immediate_send`). Server
    // has `group` fully in memory (hits the sibling immediate-send branch)
    // but only a knownState shell for `map` (hits the deferred-load branch
    // this scenario targets).
    const serverPeerFromClientB = peerStateFor(clientB, server);
    for (const id of [group.core.id, map.core.id]) {
      serverPeerFromClientB.pushOutgoingMessage({
        action: "known",
        id,
        header: false,
        sessions: {},
      });
    }

    await waitFor(() => {
      const core = clientB.node.getCoValue(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 12. Correction after full-content request: the OTHER production call site
 * for a KNOWN CORRECTION -- `requestFullContent` (sync.ts:1006-1014), reached
 * from inside `handleNewContent` (sync.ts:1210-1244) when a peer sends a
 * CONTENT message with no header for a CoValue we have neither in memory nor
 * in storage ("the peer/import has assumed we already have the CoValue").
 *
 * This is a DIFFERENT branch from `correction_invalid_state_assumed` above:
 * that scenario's correction comes from `invalidStateAssumed`, deep inside the
 * per-session transaction loop (sync.ts:1318,1389) -- the CoValue IS already
 * verified/in-memory there, but a session's transactions don't line up with
 * what we already have. Here, the CoValue has never been instantiated at
 * all -- the correction fires purely off the missing header, before any
 * transaction is ever looked at.
 *
 * It is ALSO different from a normal cold load (`basic_two_peer_sync`'s
 * third-peer case): a real `loadCoValueCore` call sends a `load` message,
 * which is handled entirely by `handleLoad` -- `requestFullContent` is never
 * called from there. A from-scratch peer's cold-load "not found" reply
 * (`handleLoadNotFound`, sync.ts:993-1001) sends a plain `known` with
 * `header: false` and NO `isCorrection` flag. `requestFullContent` is only
 * reachable via `handleNewContent`, which requires an inbound CONTENT
 * message -- something the ordinary load path never sends to a peer that has
 * nothing. So we hand-craft that CONTENT message directly (same low-level
 * peer-push technique as `known_state_merge_triggers_immediate_send` /
 * `..._deferred_load` above, but pushed the other direction -- server to
 * clientB), simulating a peer that wrongly assumes clientB already holds
 * map's header and sends only incremental (headerless) content. clientB has
 * no storage and no in-memory knowledge of map at all, so `loadFromStorage`
 * reports not-found synchronously and `requestFullContent` fires, replying
 * with a KNOWN CORRECTION (`isCorrection: true, header: false, sessions: {}`)
 * attributable to this call site specifically. Server then merges that
 * (empty) corrected known-state and -- because it already holds map in
 * memory -- immediately re-sends the full content (including the `group`
 * dependency) back to clientB via the ordinary `handleKnownState` ->
 * `sendNewContent` path. */
export const correctionAfterFullContentRequest: Scenario = {
  name: "correction_after_full_content_request",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    connect(server, clientA);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(server, clientA);

    // clientB is a fresh peer with NO storage and NO in-memory knowledge of
    // map at all -- not even a header.
    const clientB = makeNode("clientB");
    connect(server, clientB);

    // Hand-craft a bare CONTENT message with no header, as if server
    // wrongly assumed clientB already held map's header and were only
    // sending incremental content. On clientB, `handleNewContent` sees
    // `!coValue.hasVerifiedContent() && !msg.header`, tries
    // `loadFromStorage` (no storage attached -> reports not-found
    // synchronously), and calls `requestFullContent`, replying with a KNOWN
    // CORRECTION.
    const serverPeerToClientB = peerStateFor(server, clientB);
    serverPeerToClientB.pushOutgoingMessage({
      action: "content",
      id: map.core.id,
      header: undefined,
      priority: CO_VALUE_PRIORITY.MEDIUM,
      new: {},
    });

    await waitFor(() => {
      const core = clientB.node.getCoValue(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 13. Content arrives for a CoValue whose dependency (its owning group) isn't
 * loaded yet on the receiving node -- exercises `handleNewContent`'s
 * dependency-gating branch (sync.ts:1176-1205): `coValue.addDependenciesFrom
 * ContentMessage(msg)` finds a missing dependency, so the content is deferred
 * into `newContentQueue` and an immediate `load` for the dependency is issued
 * FROM WITHIN content-handling, before the deferred content is ever applied.
 *
 * The plan's initial idea -- have `clientB` cold-load `map` directly via
 * `loadCoValueCore` without ever touching `group` first -- does NOT reach
 * this branch. `#sendNewContent`'s `includeDependencies` (sync.ts:322-327)
 * sends a dependency's CONTENT ahead of the dependent's CONTENT to any peer
 * with `role !== "server"`, and message processing is a strict, non-reentrant
 * FIFO drain (see the note on `correction_after_full_content_request`'s
 * sibling comment above about `IncomingMessagesQueue`/`processQueues`), so by
 * the time `map`'s CONTENT reaches `handleNewContent`, `group`'s CONTENT has
 * already been fully processed and `group` is already `isAvailable()` --
 * `hasMissingDependencies()` is never true. A normal cold load transparently
 * resolves the dependency first; it never arrives "out of order" on the wire.
 *
 * So instead, reuse the hand-crafted low-level peer-push technique from
 * `correction_after_full_content_request` (and `known_state_merge_triggers_*`
 * above), but for a FULL content push rather than a headerless one: `clientB`
 * connects to `server` but never loads or subscribes to `group` or `map` at
 * all, so it starts with zero in-memory knowledge of either. `server`
 * proactively pushes ONLY `map`'s full content (header + all sessions, built
 * directly off `server`'s own settled copy via `newContentSince`) straight
 * onto its outgoing queue to `clientB` -- `group`'s content is never sent.
 * `clientB`'s `handleNewContent` genuinely receives `map`'s CONTENT first,
 * with `group` still an empty, never-touched shell, so
 * `addDependenciesFromContentMessage` (which reads the dependency straight
 * off `msg.header.ruleset.group`, independent of any already-verified state)
 * finds `group` missing and takes the defer-and-load path for real.
 *
 * We wait on `clientB.node.getCoValue(map.core.id)` rather than calling
 * `loadCoValueCore` -- same reasoning as the sibling hand-crafted-message
 * scenarios: an explicit top-level `loadCoValueCore` call would itself issue
 * a competing top-level `load` for `map`, muddying which LOAD in the trace is
 * the one the dependency-gating branch issues for `group`. */
export const contentMissingDependencies: Scenario = {
  name: "content_missing_dependencies_deferred",
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
    await settle(server, clientA);

    // clientB is connected but has never loaded or subscribed to group or map
    // -- zero in-memory knowledge of either. Hand-craft a bare CONTENT push
    // carrying ONLY map's full content, sourced from server's own settled
    // copy, straight onto server's outgoing queue to clientB -- group's
    // content is never sent alongside it, unlike a real load reply would.
    const serverMapCore = server.node.expectCoValueLoaded(map.core.id);
    const mapContent = serverMapCore.newContentSince(
      emptyKnownState(map.core.id),
    );
    const serverPeerToClientB = peerStateFor(server, clientB);
    for (const msg of mapContent ?? []) {
      serverPeerToClientB.pushOutgoingMessage(msg);
    }

    await waitFor(() => {
      const core = clientB.node.getCoValue(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** On "correction ordering under concurrent arrival" -- a scenario was
 * attempted here (`correction_ordering_interleaved_with_known`, since
 * removed) meant to prove that when two messages for the SAME (peer,
 * CoValue) pair are both independently queued before either is processed,
 * `handleCorrection`'s unconditional known-state overwrite still applies
 * them in strict arrival order rather than racing.
 *
 * That scenario turned out to be unfalsifiable, and worse, unnecessary: it
 * was byte-for-byte structurally identical (confirmed via diff of the
 * recorded trace) to `correction_invalid_state_assumed` above. Tracing
 * through the actual queue mechanics in sync.ts and
 * queue/IncomingMessagesQueue.ts shows why no such scenario CAN exist --
 * this ordering property is enforced by construction, not by any
 * processing discipline that needs a test to pin down:
 *
 * - `IncomingMessagesQueue.push()` (queue/IncomingMessagesQueue.ts:76-97)
 *   unconditionally calls `this.processQueues()` as its last step (line 96),
 *   on every single push, no exceptions.
 * - `SyncManager.processQueues()` (sync.ts:747-805) is guarded by one
 *   boolean, `this.processing` (declared sync.ts:719, checked/set
 *   sync.ts:748-752, cleared sync.ts:804), and its `while (true)` loop
 *   (sync.ts:757-802) drains the queue -- via `messagesQueue.pull()`,
 *   sync.ts:759 -- until BOTH the incoming-message queue and the storage
 *   streaming queue are empty (sync.ts:788-790) before it returns and
 *   clears the flag.
 * - The only call site of `SyncManager.pushMessage()`
 *   (defined sync.ts:721-723) outside its own definition is sync.ts:833,
 *   invoked from a peer's `incoming.onMessage` transport callback.
 *
 * Chain those three facts together: a second message for the same (peer,
 * CoValue) pair can only be sitting in the queue while a first message is
 * still unprocessed if that second message arrived DURING the synchronous
 * drain triggered by the first message's own `push()` call -- i.e. it was
 * produced as a direct, synchronous, causal consequence of processing the
 * first message (a correction reply, a re-send triggered by a `known`
 * merge, etc.). A second, genuinely independent arrival cannot land in the
 * "still queued behind an unprocessed peer" state at all, because the
 * auto-drain-on-push design means `processQueues` has already fully
 * drained the queue by the time control returns to any caller that could
 * push again. There is no window for two unrelated messages to contend for
 * the pull loop's ordering.
 *
 * In other words, "message B follows message A for the same pair" can only
 * ever be a causal-reply shape, never a race -- and `correction_invalid_
 * state_assumed` (above) and `correction_after_full_content_request`
 * (below) are exactly that shape, exercised via the two distinct
 * production call sites that emit a KNOWN CORRECTION
 * (`invalidStateAssumed`, sync.ts:1318,1389, and `requestFullContent`,
 * sync.ts:1006-1014). Those two scenarios are the only reachable
 * instances of this property, and they already cover it. This is a
 * settled finding: no additional differential scenario is needed here,
 * and none should be added without a new, concrete mechanism that
 * violates the auto-drain guarantee above. */

/** 14. A corrupted-signature transaction on ONE session of one CoValue
 * (`badMap`) is rejected -- and that specific coValue/session is marked
 * errored for the peer that sent it, via `markErrored` (sync.ts:1335-1359)
 * -- without preventing a DIFFERENT, legitimately-signed CoValue
 * (`goodMap`) from continuing to sync normally in the same overall
 * exchange.
 *
 * Corrupting the signature is done directly via the local, public
 * `tryAddTransactions` API (not by hand-crafting message CONTENTS -- the
 * write API cannot itself produce an invalid signature, so this bypasses it
 * with `skipVerify: true` to force-store a real transaction re-signed with
 * garbage directly into the server's own copy of badMap's session log,
 * simulating e.g. a corrupted disk/replication write landing on the
 * server). That corruption alone is inert, though: `tryAddTransactions` is
 * the ingestion primitive `handleNewContent` calls internally -- it does
 * not itself push anything to other peers (only content actually RECEIVED
 * over the wire triggers the relay-to-subscribed-peers loop at the bottom
 * of `handleNewContent`). So, exactly as `content_missing_dependencies_
 * deferred` does for a differently-shaped gap, the now-corrupted session
 * log is handed to a fresh peer (clientB, which has never touched badMap)
 * via the established `peerStateFor`/`pushOutgoingMessage` hand-delivery
 * technique -- reusing server's own `newContentSince` output verbatim, not
 * a fabricated message. This is what lets clientB's real `handleNewContent`
 * (with a real peer) verify it, fail, and call `markErrored` for real. */
export const contentInvalidSessionRejectedOthersContinue: Scenario = {
  name: "content_invalid_session_rejected_others_continue",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");

    const goodMap = group.createMap();
    goodMap.set("hello", "world", "trusting");

    const badMap = group.createMap();
    badMap.set("k1", "v1", "trusting");
    await settle(server, clientA);

    // Corrupt badMap's session directly on the server: append another
    // transaction to clientA's real, already-populated session but signed
    // with garbage, forced past verification with `skipVerify: true` (the
    // normal write API can't produce an invalid signature at all).
    const badMapOnServer = server.node.expectCoValueLoaded(badMap.core.id);
    const validTx = badMapOnServer.getValidSortedTransactions()[0]!;
    const corruptedSignature = "signature_zCORRUPTED" as Signature;
    const injectionError = badMapOnServer.tryAddTransactions(
      validTx.txID.sessionID,
      [
        {
          privacy: "trusting",
          madeAt: Date.now(),
          changes: "[]" as Stringified<JsonValue[]>,
        },
      ],
      corruptedSignature,
      true, // skipVerify: force the corrupted signature into the log
    );
    if (injectionError) {
      throw new Error(
        `expected skipVerify injection to succeed, got: ${JSON.stringify(injectionError)}`,
      );
    }

    // Hand-deliver server's now-corrupted badMap content to clientB, which
    // has never touched it -- exactly the technique
    // `content_missing_dependencies_deferred` uses, just with a corrupted
    // source instead of a partial one.
    const badMapContent = badMapOnServer.newContentSince(
      emptyKnownState(badMap.core.id),
    );
    const serverPeerToClientB = peerStateFor(server, clientB);
    for (const msg of badMapContent ?? []) {
      serverPeerToClientB.pushOutgoingMessage(msg);
    }

    await waitFor(() => {
      const core = clientB.node.getCoValue(badMap.core.id);
      if (!core.isErroredInPeer(server.node.currentSessionID)) {
        throw new Error("badMap not yet marked errored on clientB");
      }
    });

    // goodMap, entirely unrelated, must still sync normally to clientB in
    // the same exchange -- via a normal load, unaffected by badMap's state.
    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(goodMap.core.id);
      if (!core.isAvailable()) throw new Error("goodMap not yet on clientB");
      const content = expectMap(core.getCurrentContent());
      if (content.get("hello") !== "world") {
        throw new Error("goodMap content incomplete");
      }
    });
    // badMap stays permanently unsynced on clientB (it errored, by design),
    // so `stabilize`'s internal `waitForAllCoValuesSync` -- which sweeps
    // every coValue clientB has ever touched, not just the ones passed here
    // -- would otherwise block for its full default timeout waiting on a
    // sync that can never complete. A short override is enough: group and
    // goodMap converge almost immediately, and that's all this scenario's
    // convergence check cares about.
    await stabilize(
      [server, clientA, clientB],
      [group.core.id, goodMap.core.id],
      2_000,
    );

    return {
      // BadMap is included so its id gets a stable trace label (rather than
      // leaking a random per-run id into the golden fixture) -- but it is
      // excluded from the convergence gate below: it is DELIBERATELY left
      // divergent across nodes (server has the corrupted extra transaction,
      // clientA has only the original one, clientB rejected the session
      // outright), which is exactly the isolation this scenario proves.
      coValues: {
        Group: group.core,
        GoodMap: goodMap.core,
        BadMap: badMap.core,
      },
      nodes: nodeMap(server, clientA, clientB),
      excludedFromConvergence: ["BadMap"],
    };
  },
};

/** 15. `handleNewContent`'s fan-out loop (sync.ts:1448-1464) iterates
 * `this.getPeers(coValue.id)` and, per peer, either forwards the new content
 * directly (if the peer `isCoValueSubscribedToPeer`, i.e. relay already has a
 * per-CoValue known-state entry for it -- set the moment that peer has ever
 * sent/received a load, known-state, or content message about this id) or, for
 * a "server"-role peer that ISN'T subscribed, enqueues a low-priority LOAD
 * request instead.
 *
 * Investigated: contrary to a natural reading of "getPeers(coValue.id)" as a
 * per-CoValue subscriber set, `getPeers` (sync.ts:212) is NOT filtered by
 * subscription to `id` at all -- it is `getServerPeers(id).concat(
 * getClientPeers())`, and by default (no `serverPeerSelector` configured)
 * both of those simply return every currently-connected peer of that role,
 * full stop. The `id` parameter only matters if a node opts into peer
 * sharding. So the loop DOES reach every connected peer on every piece of
 * new content, including ones that have never asked about this specific
 * CoValue -- the subscribed/not-subscribed branch inside the loop body is
 * what actually differentiates behavior, not which peers get visited.
 *
 * That means the scenario needs no trick to reach the "not subscribed server
 * peer" arm: `relay` has two peers -- `upstream` (server role, from relay's
 * side) and `writer` (client role) -- and `upstream` is connected but has
 * never exchanged a single message about `map`/`group` before `writer`
 * pushes its content to `relay`. So the very first time `relay` runs this
 * loop for that content, `upstream` is simply not yet in `relay`'s
 * per-CoValue known-state map, hits the `else if (peer.role === "server")`
 * arm, and gets `sendLoadRequest(coValue, "low-priority")` -- a proactive
 * LOAD from relay to upstream, immediately, well before upstream ever asks
 * for anything. This is confirmed in the captured trace: the very first
 * messages for `Group`/`Map` from `relay` are `relay -> upstream | LOAD`,
 * not `relay -> upstream | CONTENT`, while the same fan-out loop's other arm
 * (peer `writer`, already subscribed because it's the content's source) is
 * exercised by the initial `writer -> relay` push itself.
 *
 * That low-priority LOAD is itself enough to converge `upstream` -- no
 * `upstream -> relay | LOAD` ever appears in the trace. `upstream` receives
 * `relay`'s LOAD (which carries relay's known state), has nothing yet, so
 * replies with `KNOWN ... sessions: empty`; relay's known-state-merge path
 * (the same mechanism as `known_state_merge_triggers_immediate_send`) then
 * sees upstream needs everything and pushes `CONTENT` unprompted. All of
 * this happens reactively during `settle(relay, writer)`, so by the time the
 * scenario reaches the explicit `upstream.node.loadCoValueCore(...)` call,
 * the CoValue is already locally available on `upstream` and that call
 * resolves without touching the wire at all -- it is present only as an
 * explicit convergence check for the golden snapshot, not as the thing that
 * produces the interesting trace segment. */
export const contentFanoutDirectVsLoadRequest: Scenario = {
  name: "content_fanout_direct_vs_load_request",
  run: async () => {
    const upstream = makeNode("upstream");
    const relay = makeNode("relay");
    connect(upstream, relay);

    // Connect the writer to relay AFTER the upstream link is established,
    // and create the CoValue only after both connections exist, so relay's
    // "upstream" server peer has never been told about this id (not
    // subscribed) before content for it arrives from `writer`.
    const writer = makeNode("writer");
    connect(relay, writer);

    const group = writer.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(relay, writer);

    // upstream never asked for this CoValue -- relay's fan-out to upstream
    // must be a low-priority load request, not a direct content forward.
    await waitFor(async () => {
      const core = await upstream.node.loadCoValueCore(map.core.id);
      if (!core.isAvailable()) throw new Error("not yet loaded on upstream");
    });
    await stabilize([upstream, relay, writer], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(upstream, relay, writer),
    };
  },
};

/** 16. Every other scenario in this harness uses `"trusting"` (plaintext)
 * transactions. `Group.createMap`'s default privacy is actually `"private"`
 * (encrypted) -- every scenario above explicitly opts OUT of that default.
 * This scenario exercises the encrypted path instead: `map.set(..., "private")`
 * produces an encrypted transaction, and `handleNewContent` on the receiving
 * side has a materially different decryption/validation branch for it than
 * for trusting transactions. `group.addMember("everyone", "reader")` already
 * grants every node the read key needed to decrypt via the "everyone"
 * read-key-sharing mechanism, so no extra wiring is needed for clientB to
 * decrypt -- confirmed by the explicit decrypted-value assertion below. */
export const privateTransactionSync: Scenario = {
  name: "private_transaction_sync",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("secret", "shh", "private");
    await settle(server, clientA);

    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(map.core.id);
      if (!core.isAvailable()) throw new Error("map not yet on clientB");
      const content = expectMap(core.getCurrentContent());
      if (content.get("secret") !== "shh") {
        throw new Error("clientB could not decrypt private content");
      }
    });
    await stabilize([server, clientA, clientB], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 17. CoList (RGA) concurrent append -- transaction-set convergence only:
 * unlike every scenario above (all `RawCoMap`), this exercises `RawCoList`'s
 * RGA-based sync path -- genuinely different machinery than map key overwrite.
 * Two clients each append a distinct item at the same anchor position
 * (`after: 0`, immediately following the shared, already-synced `"first"`
 * item) concurrently, with no coordination between them.
 *
 * What this scenario DOES demonstrate: both concurrent appends propagate to
 * every node and no transaction is lost or rejected -- i.e. the mechanical
 * CRDT sync (transaction delivery/merge) converges. `stabilize()` here only
 * confirms matching known-state transaction counts across nodes; it does not
 * inspect materialized list content or order.
 *
 * What this scenario does NOT demonstrate: that all nodes materialize the
 * same final item ORDER. When two different sessions insert at the same
 * anchor with tied `effective_made_at` timestamps, the RGA tie-break falls
 * back to `arrival_seq` (see `co_list.rs`, mirrored by the equivalent
 * ordering in `coValueCore.ts`'s `compareTransactions` /
 * `getValidSortedTransactions`), which reflects each node's own local
 * processing order rather than a value agreed on by all nodes. Repeated
 * reproduction (20 runs with realistic async delivery) found nodes can
 * permanently land on different final orders for such same-millisecond ties,
 * even though every node ends up holding byte-identical transaction sets.
 * This is a pre-existing characteristic of cojson's CoList implementation
 * (present in both the native and TypeScript code paths), not a regression
 * and not something this scenario is asserting or fixing -- it is simply not
 * safe to read this scenario's pass as evidence either way about final order
 * agreement. */
export const colistConcurrentAppend: Scenario = {
  name: "colist_concurrent_append_convergence",
  run: async () => {
    const server = makeNode("server");
    const clientA = makeNode("clientA");
    const clientB = makeNode("clientB");
    connect(server, clientA);
    connect(server, clientB);

    const group = clientA.node.createGroup();
    group.addMember("everyone", "writer");
    const list = group.createList<RawCoList<string>>();
    list.append("first", 0, "trusting");
    await settle(server, clientA);

    await waitFor(async () => {
      const core = await clientB.node.loadCoValueCore(list.core.id);
      if (!core.isAvailable()) throw new Error("list not yet on clientB");
    });

    const listOnB = clientB.node
      .getCoValue(list.core.id)
      .getCurrentContent() as RawCoList<string>;

    // Concurrent appends from both clients at the same anchor position.
    list.append("fromA", 0, "trusting");
    listOnB.append("fromB", 0, "trusting");

    await settle(server, clientA, clientB);
    await stabilize([server, clientA, clientB], [group.core.id, list.core.id]);

    return {
      coValues: { Group: group.core, List: list.core },
      nodes: nodeMap(server, clientA, clientB),
    };
  },
};

/** 18. Storage-reconciliation decision path (`handleReconcile`, sync.ts:
 * 1052-1125): a manually-triggered `startStorageReconciliation` call surfaces
 * a hash mismatch and the server responds with a `load` for the CoValue it's
 * behind on.
 *
 * `startStorageReconciliation` (sync.ts:422-428) has two preconditions that
 * dictate which side calls it and how: (1) `this.local.storage` must be
 * truthy for the CALLING side — i.e. it is called ON the side that has
 * storage, not targeting a peer that has storage; (2) the `peer` argument
 * must be a persistent "server"-role `PeerState` from the CALLER's own
 * perspective (`isPersistentServerPeer`, sync.ts:135-137). In this mesh,
 * `connect(server, client)` gives `client` a `role: "server", persistent:
 * true` peer for `server` (mirroring the real client -> sync-server wiring,
 * see `connectedPeersWithMessagesTracking`'s default persistence rule) — so
 * it is `client.node.syncManager.startStorageReconciliation(peerToServer)`
 * that is meaningful here, never the reverse (`server`'s peer for `client` is
 * `role: "client"`, so `isPersistentServerPeer` would immediately reject it
 * and the call would be a silent no-op).
 *
 * There's a second precondition, easy to miss: `buildStorageReconciliationEntries`
 * (sync.ts:506-542) filters the reconciled batch down to CoValues NOT
 * currently in the CALLER's own memory. `client` created `map` itself, so it
 * never naturally leaves client's memory — calling reconciliation while `map`
 * is still in-memory would enumerate zero entries and reconcile nothing.
 * `restartNode` (mesh.ts) closes this gap the same way the referenced
 * production test does it (`sync.storageReconciliation.test.ts`'s "...for
 * outdated CoValues"): tear down and recreate `client`'s `LocalNode` reusing
 * the same agent + session identity (so the already-synced first transaction
 * and the reconnect are still recognized as the same session) with the same
 * on-disk storage reattached — a "session-continuity" break, not the
 * full-identity-swap technique `storageBackedResponse`/
 * `loadPeerHasAllContent` use for an unrelated fresh peer picking up someone
 * else's storage. After the restart, `map` (and `group`) exist only in
 * client's storage, so reconciliation's storage-backed hash for `map` (2
 * sessions: header/2) genuinely disagrees with what `server` still has in
 * memory (1 transaction, from before the disconnect) — the mismatch
 * `handleReconcile` is built to detect. */
export const reconcileHashMismatch: Scenario = {
  name: "reconcile_hash_mismatch_triggers_load",
  run: async () => {
    const client = makeNode("client");
    attachStorage(client);
    const server = makeNode("server");
    connect(server, client);

    const group = client.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("k1", "v1", "trusting");
    await map.core.waitForSync();

    // A second transaction reaches client's own storage but is deliberately
    // NOT synced to server: disconnect first, so there's no window for it to
    // propagate.
    disconnect(server, client);
    map.set("k2", "v2", "trusting");
    await flush();

    // Simulate the client process restarting (same agent + session identity,
    // storage reattached) so `map`/`group` are storage-only on client, not
    // in-memory -- required for startStorageReconciliation to consider them
    // at all.
    await restartNode(client);

    // Reconnect (server's persistent PeerState for this session id is
    // reused) with automatic reconciliation suppressed on the client's side:
    // otherwise `addPeer`'s own `startPeerReconciliation` -> `resumeUnsyncedCoValues`
    // would eagerly load `map` back into memory and sync it via an ordinary
    // `load` before our manual call below ever runs, masking whether
    // reconciliation itself does anything.
    connect(server, client, { skipReconciliation: true });
    const peerToServer = peerStateFor(client, server);
    await new Promise<void>((resolve) => {
      client.node.syncManager.startStorageReconciliation(
        peerToServer,
        0,
        resolve,
      );
    });

    await waitFor(async () => {
      const core = await server.node.loadCoValueCore(map.core.id);
      if (!core.isAvailable()) throw new Error("not yet reconciled");
      const content = expectMap(core.getCurrentContent());
      if (content.get("k2") !== "v2") {
        throw new Error("k2 not yet reconciled");
      }
    });
    await stabilize([server, client], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, client),
    };
  },
};

/** 19. Peer reconciliation fills missing known-state entries:
 * `startPeerReconciliation`'s per-CoValue loop (sync.ts:683-702) walks EVERY
 * CoValue the local node knows about and, for any that don't yet have a
 * known-state entry for the peer this reconciliation run is for, fills in an
 * "empty" entry (`peer.setKnownState(coValue.id, "empty")`) before the
 * ordered dependency-aware send loop below it (sync.ts:704-715) issues LOAD
 * requests for each.
 *
 * The plan's initial idea -- have `server` hold pre-synced CoValues and have
 * a brand-new `clientB` connect to it -- does NOT reach this loop with any
 * real CoValue at all. `addPeer` (sync.ts:823) only calls
 * `startPeerReconciliation` when the newly-added `PeerState`'s OWN role is
 * `"server"` -- i.e. reconciliation always runs on the side that sees the
 * other as its upstream server, using THAT side's own `this.local.
 * allCoValues()`. In `connect(server, client)` (mesh.ts), it is always the
 * *client* argument whose `addPeer` call gets a peer with role `"server"`;
 * the *server* argument's own `addPeer` call for the new connection gets role
 * `"client"` and never calls `startPeerReconciliation` at all. So targeting
 * `server` (the pre-existing-data holder) as the connect-time recipient of a
 * new peer, as in the original idea, never runs this loop over `server`'s own
 * CoValues -- confirmed by direct instrumentation: with that shape, every
 * `startPeerReconciliation` call in the scenario fired with
 * `this.local.allCoValues()` empty (0 entries) on the connecting side, so the
 * loop body never executed for a single real CoValue.
 *
 * So this scenario inverts which side plays which mesh role: `clientA`
 * creates `group`/`mapA`/`mapB`/`mapC` entirely on its own, with NO peer
 * connected at all yet -- all four are fully `isAvailable()` in memory
 * immediately (CoValue creation is a local operation, no network needed). A
 * brand-new `server` node then connects, with `clientA` passed as the
 * *client* argument to `connect()` -- so `clientA`'s own `addPeer` call for
 * the new peer has role `"server"`, and its automatic
 * `startPeerReconciliation` call runs synchronously with all four CoValues
 * already resident in `this.local.allCoValues()`. Each is `isAvailable()`, so
 * each takes the `buildOrderedCoValueList` branch (dependency order: group,
 * then mapA/mapB/mapC), gets its known-state entry filled to `"empty"`, and
 * is then proactively sent a low-priority LOAD by the ordered-send loop --
 * `clientA -> server | LOAD Group/MapA/MapB/MapC`, all four, in one
 * reconciliation pass, before `server` has asked for anything at all. */
export const peerReconciliationFillsEntries: Scenario = {
  name: "peer_reconciliation_fills_missing_known_state_entries",
  run: async () => {
    // clientA creates several CoValues entirely on its own, with no peer
    // connected yet -- all fully in-memory/available before any reconciliation
    // can run.
    const clientA = makeNode("clientA");
    const group = clientA.node.createGroup();
    group.addMember("everyone", "reader");
    const mapA = group.createMap();
    mapA.set("a", "1", "trusting");
    const mapB = group.createMap();
    mapB.set("b", "2", "trusting");
    const mapC = group.createMap();
    mapC.set("c", "3", "trusting");

    // A brand-new peer connects. clientA is passed as the *client* argument
    // so its own `addPeer` call sees the new peer with role "server" --
    // the only role that makes `addPeer` auto-run `startPeerReconciliation`
    // (sync.ts:823) -- and that reconciliation runs over clientA's own
    // already-populated `allCoValues()`, exercising the entry-fill loop for
    // real.
    const server = makeNode("server");
    connect(server, clientA);

    await waitFor(async () => {
      for (const map of [mapA, mapB, mapC]) {
        const core = await server.node.loadCoValueCore(map.core.id);
        if (!core.isAvailable()) {
          throw new Error(`${map.core.id} not yet on server`);
        }
      }
    });
    await stabilize(
      [server, clientA],
      [group.core.id, mapA.core.id, mapB.core.id, mapC.core.id],
    );

    return {
      coValues: {
        Group: group.core,
        MapA: mapA.core,
        MapB: mapB.core,
        MapC: mapC.core,
      },
      nodes: nodeMap(server, clientA),
    };
  },
};

/** 20. `syncContent`'s per-peer fan-out loop (sync.ts:1538-1574) only ever
 * runs on the node that performs a genuinely LOCAL transaction: it is wired
 * up in `coValueCore.makeNewTransaction` (coValueCore.ts:2000) as
 * `this.node.syncManager.syncLocalTransaction(...)`, which feeds THAT node's
 * own `LocalTransactionsSyncQueue` -> `syncContent`, iterating THAT node's
 * own `getPeers(coValue.id)`. It is a structurally similar but entirely
 * distinct loop from the one inside `handleNewContent` that forwards
 * already-received content on to other peers (`sendNewContent`/
 * `sendLoadRequest`) -- that second loop is what
 * `content_fanout_direct_vs_load_request` already exercises.
 *
 * The plan's initial idea -- create `group`/`map` via `clients[0]` (`clientA`)
 * and call the write "on server" -- does NOT reach `syncContent`'s
 * multi-peer loop at all: in this star topology `clientA`'s own peer set is
 * just `[server]` (clients are never connected to each other), so `clientA`
 * authoring its own transaction only ever drives `syncContent` with ONE
 * peer. The visible 3-way fan-out once `server` relays that content on to
 * `clientB`/`clientC`/`clientD` runs through `handleNewContent`'s forwarding
 * loop, not `syncContent` -- confirmed by `syncLocalTransaction`'s single
 * call site, which fires only for the node performing the mutating call.
 *
 * So `group`/`map` are created on `server` itself -- the one node genuinely
 * connected to all 4 clients -- so the local write below runs `syncContent`
 * on the node that actually has a 4-peer fan-out to perform. That alone is
 * still not sufficient, though: `syncContent`'s loop also skips any
 * client-role peer that isn't already `isCoValueSubscribedToPeer` -- and
 * right after creation none of the 4 clients have asked about the map yet,
 * so a write at that point would be silently skipped for all of them. Each
 * client therefore explicitly loads the map first (establishing that
 * subscription), and only THEN does the second write happen, so its
 * `syncContent` call is a real single-call, 4-peer fan-out: confirmed in the
 * captured trace by four back-to-back `server -> clientX | CONTENT`
 * messages for `Map` (`New: 1`, the lone "update" transaction) immediately
 * following `server`'s local `set("update", ...)`, none of them preceded by
 * a LOAD from that client. */
export const localTransactionFanoutMultiPeer: Scenario = {
  name: "local_transaction_fanout_multi_peer",
  run: async () => {
    const server = makeNode("server");
    const clients = [
      makeNode("clientA"),
      makeNode("clientB"),
      makeNode("clientC"),
      makeNode("clientD"),
    ];
    for (const client of clients) {
      connect(server, client);
    }

    // Created on `server` (not a client) so the local write below runs
    // `syncContent` on the node that actually has 4 connected peers -- see
    // the comment above for why creating it on a client would not exercise
    // the multi-peer loop at all.
    const group = server.node.createGroup();
    group.addMember("everyone", "reader");
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await settle(server, ...clients);

    // Every client loads (and thereby subscribes to) the map BEFORE the
    // second write below. `syncContent`'s subscription check
    // (`peer.role === "client" && !peer.isCoValueSubscribedToPeer(...)`)
    // skips any client-role peer that isn't already subscribed -- without
    // this step none of the 4 clients would be subscribed yet, and the
    // second write's `syncContent` call would silently skip every one of
    // them instead of fanning out to them directly (confirmed by an earlier
    // attempt without this step: the "update" transaction never appeared as
    // a direct multi-peer push, only bundled into each client's own later
    // on-demand LOAD response).
    for (const client of clients) {
      await waitFor(async () => {
        const core = await client.node.loadCoValueCore(map.core.id);
        if (!core.isAvailable()) throw new Error("map not yet loaded");
      });
    }
    await settle(server, ...clients);

    // One local write on server must fan out correctly to all 4 subscribed
    // peers in a single syncContent call.
    map.set("update", "fanned-out", "trusting");
    for (const client of clients) {
      await waitFor(async () => {
        const core = await client.node.loadCoValueCore(map.core.id);
        if (!core.isAvailable()) throw new Error("not yet synced");
        const content = expectMap(core.getCurrentContent());
        if (content.get("update") !== "fanned-out") {
          throw new Error("update not yet received");
        }
      });
    }
    await stabilize([server, ...clients], [group.core.id, map.core.id]);

    return {
      coValues: { Group: group.core, Map: map.core },
      nodes: nodeMap(server, ...clients),
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
  knownStateTriggersSend,
  knownStateTriggersDeferredLoad,
  correctionAfterFullContentRequest,
  contentMissingDependencies,
  contentInvalidSessionRejectedOthersContinue,
  contentFanoutDirectVsLoadRequest,
  privateTransactionSync,
  colistConcurrentAppend,
  reconcileHashMismatch,
  peerReconciliationFillsEntries,
  localTransactionFanoutMultiPeer,
];
