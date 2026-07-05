/**
 * Differential / golden-trace harness for the STORAGE layer.
 *
 * Phase 0 of the storage-layer port. This is the ORACLE that a future native
 * storage port (if ever authorized) would be diffed against. It runs
 * representative storage scenarios through the CURRENT (all-TypeScript) storage
 * clients and captures, per scenario, three load-bearing things:
 *
 *   1. The ordered storage message trace (via the existing `SyncMessagesLog` /
 *      `trackStorageMessages` machinery, rendered ID-free through
 *      `toSimplifiedMessages`). This encodes the observable store / load /
 *      correction / known callback contract and its ORDER.
 *   2. The exact DB row-state after each checkpoint operation — coValue headers,
 *      per-session transaction counters (`lastIdx`), transaction-row counts,
 *      signature checkpoints (`signatureAfter`), the delete queue, and any
 *      reconciliation-lock rows — read directly out of SQLite through a
 *      READ-ONLY second connection. Random identities are normalized to stable
 *      labels so two runs produce byte-identical output.
 *   3. For durability scenarios: the exact `onLocalStoreDurabilityChange`
 *      callback-timing sequence — the crash-window contract the team recently
 *      hardened.
 *
 * IMPORTANT: this harness is TEST-ONLY and OBSERVATIONAL. It never modifies,
 * wires into, or imports mutably any production storage read/write path. It only
 * opens its own read-only SQLite connection and calls existing public surfaces
 * (`storage.store` / `storage.load` via the node, the lock client methods). No
 * `store()` / `load()` / `DBClient` write path is changed.
 */
import Database, { type Database as DatabaseT } from "libsql";
import type { LocalNode } from "../../localNode.js";
import type { CoValueCore } from "../../coValueCore/coValueCore.js";
import { toSimplifiedMessages } from "../messagesTestUtils.js";
import { SyncMessagesLog } from "../testUtils.js";

/** A single session's normalized DB row shape. */
export type NormalizedSession = {
  /** highest stored transaction index for the session */
  lastIdx: number;
  /** number of transaction rows physically stored for the session */
  txCount: number;
  /** whether the session row carries a rolling `lastSignature` */
  hasLastSignature: boolean;
  /** transaction indices at which an intermediate `signatureAfter` checkpoint
   *  exists (empty for sub-threshold content) */
  signatureCheckpoints: number[];
};

/** A single coValue's normalized DB row shape. */
export type NormalizedCoValue = {
  header: boolean;
  /** sessionLabel -> session row (sorted by label for order-independence) */
  sessions: Record<string, NormalizedSession>;
};

export type NormalizedDbSnapshot = {
  /** the scenario's named coValues (label -> row shape) */
  covalues: Record<string, NormalizedCoValue>;
  /** number of coValue rows NOT among the named ones (deps: account/profile) */
  otherCovalueCount: number;
  /** named coValues present in the delete table, label -> status
   *  ("pending" = queued for erasure, "done" = history erased, tombstone kept) */
  deletedQueue: Record<string, string>;
  /** number of storageReconciliationLocks rows */
  reconciliationLockCount: number;
};

export type LockDecisionCapture = {
  label: string;
  result: unknown;
  resultRow: unknown;
};

export type StorageGoldenSnapshot = {
  scenario: string;
  /** ordered, ID-free storage message trace */
  trace: string[];
  /** checkpoint label -> DB snapshot at that point */
  dbStates: Record<string, NormalizedDbSnapshot>;
  /** durability-window callback sequence (crash-window scenarios) */
  durabilityWindow?: boolean[];
  /** reconciliation-lock decision outcomes (lock scenarios) */
  lockDecisions?: LockDecisionCapture[];
};

export type StorageScenario = {
  name: string;
  run: () => Promise<Omit<StorageGoldenSnapshot, "scenario">>;
};

/**
 * Read-only inspector over a storage SQLite file. Opens its own connection and
 * only ever issues SELECTs — it never writes, and thus cannot perturb the
 * storage under test.
 */
export class DbInspector {
  private readonly db: DatabaseT;
  private readonly idToLabel: Map<string, string>;
  private readonly sessionLabels = new Map<string, string>();
  private extCounter = 0;

  constructor(
    dbPath: string,
    namedCoValues: Record<string, CoValueCore>,
    /** the node whose own session is labeled "self" */
    selfSessionId: string,
  ) {
    this.db = new Database(dbPath, {});
    this.idToLabel = new Map(
      Object.entries(namedCoValues).map(([label, core]) => [core.id, label]),
    );
    this.sessionLabels.set(selfSessionId, "self");
  }

  private sessionLabel(sessionId: string): string {
    const existing = this.sessionLabels.get(sessionId);
    if (existing) return existing;
    const label = `ext/${this.extCounter++}`;
    this.sessionLabels.set(sessionId, label);
    return label;
  }

  snapshot(): NormalizedDbSnapshot {
    type CoRow = { rowID: number; id: string; header: string | null };
    type SessRow = {
      rowID: number;
      coValue: number;
      sessionID: string;
      lastIdx: number | null;
      lastSignature: string | null;
    };

    const coRows = this.db
      .prepare("SELECT rowID, id, header FROM coValues ORDER BY rowID")
      .all([]) as CoRow[];
    const sessRows = this.db
      .prepare(
        "SELECT rowID, coValue, sessionID, lastIdx, lastSignature FROM sessions ORDER BY rowID",
      )
      .all([]) as SessRow[];

    const txCounts = new Map<number, number>();
    for (const row of this.db
      .prepare("SELECT ses, COUNT(*) as c FROM transactions GROUP BY ses")
      .all([]) as { ses: number; c: number }[]) {
      txCounts.set(row.ses, row.c);
    }

    const sigCheckpoints = new Map<number, number[]>();
    for (const row of this.db
      .prepare("SELECT ses, idx FROM signatureAfter ORDER BY ses, idx")
      .all([]) as { ses: number; idx: number }[]) {
      const list = sigCheckpoints.get(row.ses) ?? [];
      list.push(row.idx);
      sigCheckpoints.set(row.ses, list);
    }

    const coValueLabelByRowId = new Map<number, string | null>();
    let otherCovalueCount = 0;
    for (const co of coRows) {
      const label = this.idToLabel.get(co.id) ?? null;
      coValueLabelByRowId.set(co.rowID, label);
      if (label === null) otherCovalueCount++;
    }

    const covalues: Record<string, NormalizedCoValue> = {};
    for (const co of coRows) {
      const label = coValueLabelByRowId.get(co.rowID);
      if (!label) continue; // dependency coValue: counted, not detailed
      covalues[label] = { header: co.header != null, sessions: {} };
    }

    // Build sessions, ordered by rowID for deterministic ext/ labeling.
    for (const sess of sessRows) {
      const coLabel = coValueLabelByRowId.get(sess.coValue);
      if (!coLabel) continue;
      const sLabel = this.sessionLabel(sess.sessionID);
      covalues[coLabel]!.sessions[sLabel] = {
        lastIdx: sess.lastIdx ?? 0,
        txCount: txCounts.get(sess.rowID) ?? 0,
        hasLastSignature: sess.lastSignature != null,
        signatureCheckpoints: sigCheckpoints.get(sess.rowID) ?? [],
      };
    }

    // Sort session keys within each coValue for order-independence.
    for (const co of Object.values(covalues)) {
      co.sessions = sortRecord(co.sessions);
    }

    const deletedRows = this.db
      .prepare("SELECT coValueID, status FROM deletedCoValues")
      .all([]) as { coValueID: string; status: number }[];
    const deletedQueue: Record<string, string> = {};
    for (const r of deletedRows) {
      const label = this.idToLabel.get(r.coValueID);
      if (label == null) continue;
      // 0 = Pending (queued), 1 = Done (history erased, tombstone preserved).
      deletedQueue[label] = r.status === 0 ? "pending" : "done";
    }

    const lockCount = (
      this.db
        .prepare("SELECT COUNT(*) as c FROM storageReconciliationLocks")
        .get([]) as { c: number }
    ).c;

    return {
      covalues: sortRecord(covalues),
      otherCovalueCount,
      deletedQueue: sortRecord(deletedQueue),
      reconciliationLockCount: lockCount,
    };
  }

  close(): void {
    this.db.close();
  }
}

function sortRecord<T>(rec: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const key of Object.keys(rec).sort()) {
    out[key] = rec[key]!;
  }
  return out;
}

/**
 * The ID-free storage message trace for a scenario, rendered from the shared
 * `SyncMessagesLog` through the named coValues.
 */
export function captureTrace(
  namedCoValues: Record<string, CoValueCore>,
): string[] {
  return SyncMessagesLog.getMessages(namedCoValues);
}

/** Convenience for scenarios: build an inspector for a node+db. */
export function inspectorFor(
  dbPath: string,
  namedCoValues: Record<string, CoValueCore>,
  node: LocalNode,
): DbInspector {
  return new DbInspector(dbPath, namedCoValues, node.currentSessionID);
}

/** Run a scenario, scoping the shared message log to it. */
export async function captureStorageScenario(
  scenario: StorageScenario,
): Promise<StorageGoldenSnapshot> {
  SyncMessagesLog.clear();
  const result = await scenario.run();
  return { scenario: scenario.name, ...result };
}

/** Stable JSON serialization + trailing newline (matches the repo formatter). */
export function serializeStorageGolden(
  snapshot: StorageGoldenSnapshot,
): string {
  return `${JSON.stringify(snapshot, null, 2)}\n`;
}

export { toSimplifiedMessages };
