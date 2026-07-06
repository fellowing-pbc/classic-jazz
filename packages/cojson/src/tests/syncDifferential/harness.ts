/**
 * Differential / golden-trace harness for the sync protocol.
 *
 * This is the ORACLE that a future native-sync port will be diffed against. It
 * runs multi-peer scenarios through the CURRENT (all-TypeScript) SyncManager and
 * captures three things:
 *
 *   1. The full ordered wire-message trace (via the existing `SyncMessagesLog` /
 *      `connectedPeersWithMessagesTracking` machinery, rendered ID-free through
 *      `toSimplifiedMessages`).
 *   2. The final known-state of every node for every tracked CoValue: both the
 *      node's own authoritative core known-state AND, per connected peer, the
 *      confirmed + optimistic `PeerKnownState` view (this is exactly where the
 *      optimistic-vs-confirmed / reconnect failure modes live).
 *   3. A convergence verdict: do all nodes that hold a CoValue agree on its
 *      known-state?
 *
 * Everything non-deterministic about identity (random CoValue ids, random session
 * ids) is normalized to stable positional/semantic labels so that two runs of the
 * same scenario produce BYTE-IDENTICAL output. That normalization is what makes
 * the golden fixtures stable and the determinism meta-test meaningful.
 *
 * IMPORTANT: this harness is TEST-ONLY. It does not import, wire into, or modify
 * any production sync code path — it only observes public read surfaces
 * (`core.knownState()`, `PeerState.getKnownState` / `getOptimisticKnownState`).
 */
import type { CoValueCore } from "../../coValueCore/coValueCore.js";
import type { RawCoID, SessionID } from "../../ids.js";
import type { CoValueKnownState } from "../../knownState.js";
import type { LocalNode } from "../../localNode.js";
import { toSimplifiedMessages } from "../messagesTestUtils.js";
import { SyncMessagesLog } from "../testUtils.js";

/** A normalized known-state: id dropped (redundant with the CoValue label), header
 * kept, sessions relabeled and sorted for order-independence. */
export type NormalizedKnownState = {
  header: boolean;
  sessions: Record<string, number>;
};

export type PeerViewSnapshot = {
  confirmed: NormalizedKnownState | null;
  optimistic: NormalizedKnownState | null;
};

export type NodeSnapshot = {
  /** node's own authoritative core known-state per tracked CoValue */
  core: Record<string, NormalizedKnownState | "unavailable">;
  /** per connected peer, that peer's confirmed+optimistic view per CoValue */
  peers: Record<string, Record<string, PeerViewSnapshot>>;
};

export type GoldenSnapshot = {
  scenario: string;
  /** ordered, ID-free wire-message trace */
  trace: string[];
  /** per node label -> snapshot */
  nodes: Record<string, NodeSnapshot>;
  /** per CoValue label -> did all holders converge */
  convergence: Record<string, boolean>;
  converged: boolean;
};

export type ScenarioResult = {
  /** named CoValue cores: label -> core (drives both trace mapping and snapshot) */
  coValues: Record<string, CoValueCore>;
  /** named nodes: label -> node (the peers whose state we snapshot) */
  nodes: Record<string, LocalNode>;
  /**
   * Labels (keys of `coValues`) that are deliberately, permanently NOT
   * expected to converge -- e.g. a CoValue one node rejected outright (a
   * corrupted signature, a permission violation) and so never holds the
   * same known-state as its peers. Still included in `coValues` so its id
   * gets a stable trace label instead of leaking a random per-run id into
   * the golden fixture (which would fail the determinism meta-test); still
   * recorded in `convergence` for visibility; just excluded from the
   * all-scenarios-converge gate (`converged`).
   */
  excludedFromConvergence?: string[];
};

export type Scenario = {
  name: string;
  run: () => Promise<ScenarioResult>;
};

/**
 * Deterministic symbol table: maps random CoValue ids and session ids to stable
 * labels. CoValue ids come straight from the caller's naming; session ids are
 * mapped to their owning node when possible, otherwise assigned a stable
 * positional `ext/<n>` label on first sight during a fixed traversal.
 */
class SymbolTable {
  private coValueLabels = new Map<string, string>();
  private sessionLabels = new Map<string, string>();
  private nodeBySession = new Map<string, string>();
  private extCounter = 0;

  constructor(
    coValues: Record<string, CoValueCore>,
    nodes: Record<string, LocalNode>,
  ) {
    for (const [label, core] of Object.entries(coValues)) {
      this.coValueLabels.set(core.id, label);
    }
    // Sorted for deterministic label assignment order.
    for (const label of Object.keys(nodes).sort()) {
      const node = nodes[label]!;
      this.nodeBySession.set(node.currentSessionID, label);
    }
  }

  coValue(id: string): string {
    return this.coValueLabels.get(id) ?? `co/${id.slice(0, 6)}`;
  }

  session(sessionId: string): string {
    const existing = this.sessionLabels.get(sessionId);
    if (existing) return existing;

    // Owned by a known node? label it by node.
    const owner = this.nodeBySession.get(sessionId);
    if (owner) {
      this.sessionLabels.set(sessionId, owner);
      return owner;
    }
    // Peer id may be prefixed with "peer:".
    if (sessionId.startsWith("peer:")) {
      const stripped = sessionId.slice("peer:".length);
      const strippedOwner = this.nodeBySession.get(stripped);
      if (strippedOwner) {
        this.sessionLabels.set(sessionId, strippedOwner);
        return strippedOwner;
      }
    }
    const label = `ext/${this.extCounter++}`;
    this.sessionLabels.set(sessionId, label);
    return label;
  }

  peerLabel(peerId: string): string {
    return this.session(peerId);
  }
}

function normalizeKnownState(
  ks: CoValueKnownState,
  syms: SymbolTable,
): NormalizedKnownState {
  const sessions: Record<string, number> = {};
  for (const [sid, count] of Object.entries(ks.sessions)) {
    sessions[syms.session(sid)] = count as number;
  }
  // Sort by label for order-independent, byte-stable output.
  const sorted: Record<string, number> = {};
  for (const key of Object.keys(sessions).sort()) {
    sorted[key] = sessions[key]!;
  }
  return { header: ks.header, sessions: sorted };
}

function captureNodeSnapshot(
  node: LocalNode,
  coValues: Record<string, CoValueCore>,
  syms: SymbolTable,
): NodeSnapshot {
  const core: NodeSnapshot["core"] = {};
  const peers: NodeSnapshot["peers"] = {};

  const coValueLabels = Object.keys(coValues).sort();

  for (const label of coValueLabels) {
    const id = coValues[label]!.id as RawCoID;
    const localCore = node.getCoValue(id);
    core[label] = localCore.isAvailable()
      ? normalizeKnownState(localCore.knownState(), syms)
      : // Track whether the node has *any* recollection (last known state) vs
        // truly nothing. Both render as a normalized state if known, else the
        // literal "unavailable".
        normalizeIfKnown(localCore, syms);
  }

  // Peer views: what this node believes each connected peer holds. Peers are
  // keyed by a random session id, so we map to stable labels FIRST and emit in
  // label order — otherwise the output object's key order would depend on random
  // ids and break byte-determinism.
  const labeledPeers: {
    label: string;
    view: Record<string, PeerViewSnapshot>;
  }[] = [];
  for (const [peerId, peerState] of Object.entries(node.syncManager.peers)) {
    const peerLabel = syms.peerLabel(peerId);
    const perCoValue: Record<string, PeerViewSnapshot> = {};
    for (const label of coValueLabels) {
      const id = coValues[label]!.id as RawCoID;
      const confirmed = peerState.getKnownState(id);
      const optimistic = peerState.getOptimisticKnownState(id);
      // Only record CoValues this peer is actually subscribed to (avoids noise).
      if (!confirmed && !optimistic) continue;
      perCoValue[label] = {
        confirmed: confirmed ? normalizeKnownState(confirmed, syms) : null,
        optimistic: optimistic ? normalizeKnownState(optimistic, syms) : null,
      };
    }
    if (Object.keys(perCoValue).length > 0) {
      labeledPeers.push({ label: peerLabel, view: perCoValue });
    }
  }
  for (const { label, view } of labeledPeers.sort((a, b) =>
    a.label.localeCompare(b.label),
  )) {
    peers[label] = view;
  }

  return { core, peers };
}

function normalizeIfKnown(
  localCore: CoValueCore,
  syms: SymbolTable,
): NormalizedKnownState | "unavailable" {
  const ks = localCore.knownState();
  // An empty, header-less state means the node truly knows nothing.
  if (!ks.header && Object.keys(ks.sessions).length === 0) {
    return "unavailable";
  }
  return normalizeKnownState(ks, syms);
}

function checkConvergence(
  nodes: Record<string, NodeSnapshot>,
  coValueLabels: string[],
  excludedFromConvergence: string[] = [],
): { convergence: Record<string, boolean>; converged: boolean } {
  const convergence: Record<string, boolean> = {};
  let converged = true;

  for (const label of coValueLabels) {
    const states: string[] = [];
    for (const snapshot of Object.values(nodes)) {
      const s = snapshot.core[label];
      if (s && s !== "unavailable") {
        states.push(JSON.stringify(s));
      }
    }
    // Converged if every node that holds it agrees (or nobody holds it).
    const allEqual = states.every((s) => s === states[0]);
    convergence[label] = allEqual;
    if (!allEqual && !excludedFromConvergence.includes(label)) {
      converged = false;
    }
  }

  return { convergence, converged };
}

/**
 * Run a scenario and capture the full golden snapshot. Clears the shared
 * `SyncMessagesLog` first so the trace is scoped to this scenario. Scenarios must
 * therefore be run sequentially (the log is a process-global).
 */
export async function captureScenario(
  scenario: Scenario,
): Promise<GoldenSnapshot> {
  SyncMessagesLog.clear();

  const result = await scenario.run();

  const trace = SyncMessagesLog.getMessages(result.coValues);

  const syms = new SymbolTable(result.coValues, result.nodes);
  const coValueLabels = Object.keys(result.coValues).sort();

  const nodes: Record<string, NodeSnapshot> = {};
  for (const nodeLabel of Object.keys(result.nodes).sort()) {
    nodes[nodeLabel] = captureNodeSnapshot(
      result.nodes[nodeLabel]!,
      result.coValues,
      syms,
    );
  }

  const { convergence, converged } = checkConvergence(
    nodes,
    coValueLabels,
    result.excludedFromConvergence,
  );

  // Tear the scenario's nodes down so they stop emitting into the shared
  // process-global message log — critical for isolation when the same scenario
  // is captured twice (determinism meta-test) or many seeds run in sequence.
  await Promise.all(
    Object.values(result.nodes).map((node) =>
      node.gracefulShutdown().catch(() => {}),
    ),
  );

  return {
    scenario: scenario.name,
    trace,
    nodes,
    convergence,
    converged,
  };
}

/** Stable JSON serialization for byte-comparison + golden files. The trailing
 * newline matches the repo formatter so committed golden files and freshly
 * serialized output stay byte-identical. */
export function serializeGolden(snapshot: GoldenSnapshot): string {
  return `${JSON.stringify(snapshot, null, 2)}\n`;
}

/** Utility: wait for a node's whole sync surface to quiesce. */
export async function settle(...nodes: LocalNode[]): Promise<void> {
  // Flush microtasks a few times, then wait for the sync manager's own notion of
  // "all CoValues synced". Kept generous but bounded.
  for (let i = 0; i < 3; i++) {
    await new Promise<void>((resolve) => queueMicrotask(resolve));
  }
  await Promise.all(
    nodes.map((node) =>
      node.syncManager.waitForAllCoValuesSync(10_000).catch(() => {
        /* best-effort: convergence is asserted separately */
      }),
    ),
  );
  for (let i = 0; i < 3; i++) {
    await new Promise<void>((resolve) => queueMicrotask(resolve));
  }
}

export { SessionID };
