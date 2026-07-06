/**
 * Low-level tracked-mesh helpers for the differential harness.
 *
 * Deliberately built on the raw node + `connectedPeersWithMessagesTracking`
 * primitives (rather than `setupTestNode`) so the harness owns the full node
 * lifecycle: no `onTestFinished` cleanup fires between scenarios/seeds, and the
 * exact same node identity can be disconnected and reconnected while its peer's
 * persistent known-state survives (exercising the `cloneWithoutOptimistic`
 * reconnect path). Every connection routes through the message tracker so the
 * ordered wire trace is captured.
 *
 * TEST-ONLY. No production import.
 */
import type { RawCoID } from "../../ids.js";
import type { CoValueKnownState } from "../../knownState.js";
import { LocalNode } from "../../localNode.js";
import type { PeerState } from "../../PeerState.js";
import type { Peer } from "../../sync.js";
import {
  connectedPeersWithMessagesTracking,
  nodeWithRandomAgentAndSessionID,
} from "../testUtils.js";
import { createSyncStorage, getDbPath } from "../testStorage.js";

export type MeshNode = {
  name: string;
  node: LocalNode;
};

export function makeNode(name: string): MeshNode {
  return { name, node: nodeWithRandomAgentAndSessionID() };
}

/**
 * Attaches a fresh SQLite-backed storage to `node`, at a caller-supplied
 * `dbPath` (so a second, independent node can attach to the SAME file to
 * simulate "storage has this content, but I never loaded it into memory").
 * Returns the path used, generating one if not supplied.
 */
export function attachStorage(node: MeshNode, dbPath?: string): string {
  const path = dbPath ?? getDbPath();
  const storage = createSyncStorage({
    filename: path,
    nodeName: node.name,
    storageName: `${node.name}-storage`,
  });
  node.node.setStorage(storage);
  return path;
}

/**
 * Connect a client node to a server node through the message tracker, mirroring
 * the real `getSyncServerConnectedPeer` + `connectToSyncServer` wiring (server
 * peer persistent, client peer not). Safe to call again with the same nodes to
 * model a reconnect: the peer ids are stable (node session ids), so the server's
 * persistent `PeerState` is reused via `newPeerStateFrom`.
 *
 * `opts.skipReconciliation`, forwarded to the client's own `addPeer` call,
 * mirrors `connectToSyncServer({ skipReconciliation: true })`: it suppresses
 * the automatic `startPeerReconciliation` that would otherwise fire the
 * moment this (persistent, "server"-role) peer is added — including
 * `resumeUnsyncedCoValues`, which would eagerly load any storage-flagged
 * "unsynced" CoValue into memory and sync it via an ordinary `load` on its
 * own. Scenarios that manually drive `startStorageReconciliation` need that
 * suppressed, or the automatic path races (and usually wins) ahead of the
 * manual call, masking whatever the manual call would otherwise prove.
 */
export function connect(
  server: MeshNode,
  client: MeshNode,
  opts?: { skipReconciliation?: boolean },
): void {
  const { peer1, peer2 } = connectedPeersWithMessagesTracking({
    peer1: {
      id: server.node.currentSessionID,
      role: "server",
      name: server.name,
    },
    peer2: {
      id: client.node.currentSessionID,
      role: "client",
      name: client.name,
    },
  });

  // Server holds the client-facing peer (peer2); client holds the server-facing
  // peer (peer1) — exactly as the production helpers do.
  server.node.syncManager.addPeer(peer2);
  client.node.syncManager.addPeer(peer1, opts?.skipReconciliation);
}

/**
 * Look up the `PeerState` that `from` holds for its connection to `to` (i.e.
 * how `from` sees `to`), throwing if the two aren't connected. Several
 * scenarios need to hand-craft a low-level wire message — bypassing the
 * normal load/known/content APIs — to reach a specific sync.ts branch that
 * those APIs never produce on their own; this is the repeated "peer lookup +
 * null check" half of that technique, factored out once it showed up a third
 * time.
 */
export function peerStateFor(from: MeshNode, to: MeshNode): PeerState {
  const peer = from.node.syncManager.peers[to.node.currentSessionID];
  if (!peer) {
    throw new Error(`${from.name} has no peer state for ${to.name}`);
  }
  return peer;
}

/** Gracefully close the peer connections between two nodes without deleting
 * persistent state — the realistic "network dropped" disconnect. */
export function disconnect(a: MeshNode, b: MeshNode): void {
  const aPeer = a.node.syncManager.peers[b.node.currentSessionID];
  const bPeer = b.node.syncManager.peers[a.node.currentSessionID];
  aPeer?.gracefulShutdown();
  bPeer?.gracefulShutdown();
}

/**
 * Simulate a real process restart of `node`: tears down its current
 * `LocalNode` and replaces it with a fresh instance that reuses the SAME
 * agent secret and session ID — so any peer's book-keeping about this
 * session (and the transactions already signed under it) stays valid — with
 * its previously-attached storage (if any) reattached. Every in-memory
 * `CoValueCore` is gone afterwards; only what storage persisted survives.
 *
 * This is a "session-continuity" break, NOT a full identity change: contrast
 * with wiring a brand-new `makeNode(...)`-created node against the same db
 * file (as `storageBackedResponse`/`loadPeerHasAllContent` do in
 * scenarios.ts), which models an entirely different actor picking up
 * someone else's storage rather than the same actor restarting.
 */
export async function restartNode(node: MeshNode): Promise<void> {
  const { agentSecret, currentSessionID, crypto, storage } = node.node;
  await node.node.gracefulShutdown();
  node.node = new LocalNode(agentSecret, currentSessionID, crypto);
  if (storage) {
    node.node.setStorage(storage);
  }
}

/** Canonical, order-independent serialization of a known-state for comparison. */
function canonicalKnownState(ks: CoValueKnownState): string {
  const sessions: Record<string, number> = {};
  for (const key of Object.keys(ks.sessions).sort()) {
    sessions[key] = (ks.sessions as Record<string, number>)[key]!;
  }
  return JSON.stringify({ header: ks.header, sessions });
}

/**
 * Yield to the macrotask queue and poll until every node that HOLDS each tracked
 * CoValue agrees on its authoritative known-state (i.e. the mesh has actually
 * converged), or the timeout elapses. Uses `setTimeout` rather than microtask
 * flushes because the realistic async-peer transport (`withAsyncPeers`) delivers
 * on macrotasks.
 *
 * Returns true if converged, false on timeout — callers assert convergence
 * separately, so a timeout simply surfaces as a non-converged snapshot.
 */
export async function stabilize(
  nodes: MeshNode[],
  coreIds: RawCoID[],
  timeoutMs = 20_000,
): Promise<boolean> {
  const start = Date.now();
  // First let each node's own sync bookkeeping quiesce.
  await Promise.all(
    nodes.map((n) =>
      n.node.syncManager.waitForAllCoValuesSync(timeoutMs).catch(() => {}),
    ),
  );

  while (Date.now() - start < timeoutMs) {
    let converged = true;
    for (const id of coreIds) {
      const states = nodes
        .map((n) => n.node.getCoValue(id))
        .filter((c) => c.isAvailable())
        .map((c) => canonicalKnownState(c.knownState()));
      if (states.some((s) => s !== states[0])) {
        converged = false;
        break;
      }
    }
    if (converged) return true;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  return false;
}

/** Fully tear a node down (end of scenario/seed) so it stops emitting into the
 * shared message log. */
export async function shutdown(...nodes: MeshNode[]): Promise<void> {
  await Promise.all(
    nodes.map((n) => n.node.gracefulShutdown().catch(() => {})),
  );
}

export type { Peer };
