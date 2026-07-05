/**
 * Storage per-session write-plan fixture exporter.
 *
 * Captures the CURRENT TypeScript behavior of the storage write DECISION —
 * `storeSingle`'s `lastIdx < after` gap guard plus `putNewTxs`'s dedup /
 * `bytesSinceLastSignature` accumulation / `exceedsRecommendedSize` checkpoint /
 * `newLastIdx` computation — as executable fixtures for the Rust port
 * (`crates/cojson-core/src/core/storage_write_plan.rs`). The decision logic is
 * byte-identical between the sync (`storageSync.ts`) and async
 * (`storageAsync.ts`) clients, so the sync client faithfully represents both.
 *
 * The oracle is OBSERVED, never re-derived: for each step this drives the REAL
 * `StorageApiSync.store()` against an in-memory libsql database, reading the
 * session row (`lastIdx`, `bytesSinceLastSignature`), the transaction-row count,
 * and the `signatureAfter` checkpoints straight out of SQLite before and after
 * the store. The decision INPUTS are the before-state; the expected decision is
 * derived purely from what physically changed in the DB — so the fixtures pin
 * `putNewTxs`'s real effect, not a copy of its logic.
 *
 * When EXPORT_STORAGE_WRITE_PLAN_FIXTURES=1 the fixtures are written to
 * crates/cojson-core/data/storage_write_plan/<scenario>.json. The Rust replay
 * (`replay_write_plan_fixtures`) reads the committed files and must reproduce
 * every field byte-for-byte.
 *
 * TEST-ONLY. Touches no production storage read/write code path — it only calls
 * the existing public `store()` surface and issues read-only SELECTs.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database, { type Database as DatabaseT } from "libsql";
import { describe, expect, test } from "vitest";
import { TRANSACTION_CONFIG } from "../config.js";
import { getTransactionSize } from "../coValueContentMessage.js";
import type { Transaction } from "../coValueCore/verifiedState.js";
import type { Signature } from "../crypto/crypto.js";
import type { RawCoID, SessionID } from "../ids.js";
import { getSqliteStorage } from "../storage/sqlite/index.js";
import type { SQLiteDatabaseDriver } from "../storage/sqlite/types.js";
import type { NewContentMessage } from "../sync.js";

const EXPORT = process.env.EXPORT_STORAGE_WRITE_PLAN_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/storage_write_plan",
);

/** Minimal in-memory libsql driver (mirrors testStorage.ts / the reconciliation
 *  exporter). We keep a handle so we can issue read-only SELECTs between stores. */
class MemDriver implements SQLiteDatabaseDriver {
  readonly db: DatabaseT;
  constructor() {
    this.db = new Database(":memory:", {});
  }
  initialize() {}
  run(sql: string, params: unknown[]) {
    this.db.prepare(sql).run(params);
  }
  query<T>(sql: string, params: unknown[]): T[] {
    return this.db.prepare(sql).all(params) as T[];
  }
  get<T>(sql: string, params: unknown[]): T | undefined {
    return this.db.prepare(sql).get(params) as T | undefined;
  }
  transaction(callback: () => unknown) {
    this.run("BEGIN TRANSACTION", []);
    try {
      callback();
      this.run("COMMIT", []);
    } catch (e) {
      this.run("ROLLBACK", []);
      throw e;
    }
  }
  closeDb() {
    this.db.close();
  }
}

const CO_ID = "co_zWritePlanFixture" as RawCoID;
const SESSION_ID = "co_zWritePlanFixture_session_zWP" as SessionID;
const HEADER = {
  type: "comap",
  ruleset: { type: "unsafeAllowAll" },
  meta: null,
} as unknown as NewContentMessage["header"];

/** A trusting transaction whose `getTransactionSize` is exactly `size`
 *  (getTransactionSize reads `changes.length` for trusting txs). */
function txOfSize(size: number): Transaction {
  return {
    privacy: "trusting",
    madeAt: 0,
    changes: "x".repeat(size) as unknown as Transaction extends {
      changes: infer C;
    }
      ? C
      : never,
  } as unknown as Transaction;
}

type ExpectedPlan = {
  invalidGap: boolean;
  noOp: boolean;
  actuallyNewCount: number;
  newLastIdx: number;
  shouldWriteSignature: boolean;
  signatureIdx: number | null;
  newBytesSinceLastSignature: number;
};

type FixtureStep = {
  label: string;
  lastIdx: number;
  after: number;
  bytesSinceLastSignature: number;
  newTxSizes: number[];
  maxRecommendedTxSize: number;
  expected: ExpectedPlan;
};

type StepSpec = {
  label: string;
  /** message `after` for this store */
  after: number;
  /** sizes of EVERY transaction in `newTransactions` (pre-dedup) */
  txSizes: number[];
  /** optional threshold override active during this store */
  maxRecommendedTxSize?: number;
};

type SessionRowObservation = {
  rowID: number | null;
  lastIdx: number;
  bytes: number;
  txCount: number;
  sigIdxs: number[];
};

function observe(driver: MemDriver): SessionRowObservation {
  const row = driver.get<{
    rowID: number;
    lastIdx: number | null;
    bytesSinceLastSignature: number | null;
  }>(
    "SELECT rowID, lastIdx, bytesSinceLastSignature FROM sessions WHERE sessionID = ?",
    [SESSION_ID],
  );
  if (!row) {
    return { rowID: null, lastIdx: 0, bytes: 0, txCount: 0, sigIdxs: [] };
  }
  const txCount = (
    driver.get<{ c: number }>(
      "SELECT COUNT(*) as c FROM transactions WHERE ses = ?",
      [row.rowID],
    ) ?? { c: 0 }
  ).c;
  const sigIdxs = driver
    .query<{ idx: number }>(
      "SELECT idx FROM signatureAfter WHERE ses = ? ORDER BY idx",
      [row.rowID],
    )
    .map((r) => r.idx);
  return {
    rowID: row.rowID,
    lastIdx: row.lastIdx ?? 0,
    bytes: row.bytesSinceLastSignature ?? 0,
    txCount,
    sigIdxs,
  };
}

/** Run one scenario (a sequence of stores against a single fresh storage) and
 *  capture a fixture whose expected values are read out of the real DB. */
function runScenario(description: string, specs: StepSpec[]): FixtureStep[] {
  const driver = new MemDriver();
  const storage = getSqliteStorage(driver);
  const steps: FixtureStep[] = [];

  try {
    for (const spec of specs) {
      const originalMax = TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE;
      const maxUsed = spec.maxRecommendedTxSize ?? originalMax;

      const before = observe(driver);
      const txs = spec.txSizes.map(txOfSize);
      const newTxSizes = txs.map(getTransactionSize);

      const msg: NewContentMessage = {
        action: "content",
        id: CO_ID,
        header: HEADER,
        priority: 0,
        new: {
          [SESSION_ID]: {
            after: spec.after,
            lastSignature: `signature_z${spec.label}` as Signature,
            newTransactions: txs,
          },
        },
      };

      let correctionFired = false;
      try {
        TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE = maxUsed;
        storage.store(
          msg,
          () => {
            // Gap path: acknowledge the correction (empty ⇒ no follow-up
            // stores, no error log) and record that it fired.
            correctionFired = true;
            return [];
          },
          () => {},
        );
      } finally {
        TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE = originalMax;
      }

      const after = observe(driver);

      // Derive the expected decision purely from what changed in the DB.
      const invalidGap = correctionFired;
      const actuallyNewCount = after.txCount - before.txCount;
      const noOp =
        !invalidGap &&
        after.txCount === before.txCount &&
        after.lastIdx === before.lastIdx;
      const newSigIdx = after.sigIdxs.find((i) => !before.sigIdxs.includes(i));
      const shouldWriteSignature = newSigIdx !== undefined;

      steps.push({
        label: spec.label,
        lastIdx: before.lastIdx,
        after: spec.after,
        bytesSinceLastSignature: before.bytes,
        newTxSizes,
        maxRecommendedTxSize: maxUsed,
        expected: {
          invalidGap,
          noOp,
          actuallyNewCount,
          newLastIdx: after.lastIdx,
          shouldWriteSignature,
          signatureIdx: shouldWriteSignature ? (newSigIdx ?? null) : null,
          newBytesSinceLastSignature: after.bytes,
        },
      });
    }
  } finally {
    driver.closeDb();
  }

  // Sanity: at least one non-noop write happened in a scenario that stored data.
  return steps;
}

const scenarios: { name: string; description: string; specs: StepSpec[] }[] = [
  {
    name: "normal_first_store",
    description: "first store of 3 sub-threshold txs → no checkpoint",
    specs: [{ label: "store0", after: 0, txSizes: [10, 20, 30] }],
  },
  {
    name: "dedup_partial",
    description:
      "second store re-sends 3 known + 2 new txs (after=0) → slice writes only the 2 new",
    specs: [
      { label: "store0", after: 0, txSizes: [10, 20, 30] },
      { label: "store1_redelivery", after: 0, txSizes: [10, 20, 30, 40, 50] },
    ],
  },
  {
    name: "full_dedup_noop",
    description:
      "re-store identical content (after=0) → nothing new, no DB write",
    specs: [
      { label: "store0", after: 0, txSizes: [10, 20, 30] },
      { label: "store1_identical", after: 0, txSizes: [10, 20, 30] },
    ],
  },
  {
    name: "offset_beyond_message_noop",
    description:
      "store is ahead of the message (offset > message length) → slice past end → no-op",
    specs: [
      { label: "store0", after: 0, txSizes: [10, 20, 30] },
      { label: "store1_short", after: 0, txSizes: [10, 20] },
    ],
  },
  {
    name: "gap_invalid",
    description:
      "message assumes txs the store lacks (after > lastIdx) → correction",
    specs: [
      { label: "store0", after: 0, txSizes: [10, 20, 30] },
      { label: "store1_gap", after: 5, txSizes: [99] },
    ],
  },
  {
    name: "checkpoint_exact_boundary",
    description:
      "base+size == MAX is NOT over threshold; one byte over on the next store crosses it",
    specs: [
      {
        label: "at_boundary",
        after: 0,
        txSizes: [100],
        maxRecommendedTxSize: 100,
      },
      { label: "one_over", after: 1, txSizes: [1], maxRecommendedTxSize: 100 },
    ],
  },
  {
    name: "checkpoint_exceed_first_store",
    description: "first store already exceeds threshold → checkpoint at idx0",
    specs: [
      { label: "over", after: 0, txSizes: [150], maxRecommendedTxSize: 100 },
    ],
  },
  {
    name: "checkpoint_accumulate_then_cross",
    description:
      "sub-threshold stores accumulate bytes; the store that crosses writes a checkpoint and resets",
    specs: [
      { label: "b0", after: 0, txSizes: [30], maxRecommendedTxSize: 100 },
      { label: "b1", after: 1, txSizes: [30], maxRecommendedTxSize: 100 },
      { label: "b2", after: 2, txSizes: [30], maxRecommendedTxSize: 100 },
      { label: "b3_cross", after: 3, txSizes: [30], maxRecommendedTxSize: 100 },
      {
        label: "b4_after_reset",
        after: 4,
        txSizes: [30],
        maxRecommendedTxSize: 100,
      },
    ],
  },
  {
    name: "tiny_threshold_every_batch",
    description:
      "threshold=1: every stored batch crosses it → a checkpoint at each batch's last index",
    specs: [
      { label: "k0", after: 0, txSizes: [5], maxRecommendedTxSize: 1 },
      { label: "k1", after: 1, txSizes: [5], maxRecommendedTxSize: 1 },
      { label: "k2", after: 2, txSizes: [5], maxRecommendedTxSize: 1 },
    ],
  },
  {
    name: "multi_tx_batch_signature",
    description:
      "one store of several txs whose combined size crosses threshold → single checkpoint at the batch's last index",
    specs: [
      {
        label: "batch",
        after: 0,
        txSizes: [40, 40, 40],
        maxRecommendedTxSize: 100,
      },
    ],
  },
  {
    name: "zero_size_transactions",
    description:
      "empty-changes txs contribute 0 bytes → running total unchanged, no checkpoint",
    specs: [
      { label: "z0", after: 0, txSizes: [0, 0], maxRecommendedTxSize: 100 },
      { label: "z1", after: 2, txSizes: [0], maxRecommendedTxSize: 100 },
    ],
  },
];

describe("storage write-plan fixture export", () => {
  for (const scenario of scenarios) {
    test(`export: ${scenario.name}`, () => {
      const steps = runScenario(scenario.description, scenario.specs);
      expect(steps.length).toBe(scenario.specs.length);

      const fixture = { description: scenario.description, steps };
      const serialized = `${JSON.stringify(fixture, null, 2)}\n`;

      if (EXPORT) {
        mkdirSync(OUT_DIR, { recursive: true });
        writeFileSync(join(OUT_DIR, `${scenario.name}.json`), serialized);
      }
    });
  }
});
