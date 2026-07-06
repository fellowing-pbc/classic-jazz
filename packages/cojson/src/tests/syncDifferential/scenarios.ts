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
];
