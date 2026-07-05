/**
 * OngoingStorageReconciliationTracker fixture exporter.
 *
 * Captures the CURRENT TypeScript behavior of
 * `packages/cojson/src/OngoingStorageReconciliationTracker.ts` as executable
 * fixtures for the Rust port
 * (`crates/cojson-core/src/core/storage_reconciliation.rs`,
 * `StorageReconciliationRegistry` ongoing-batch surface).
 *
 * For each scenario it drives the REAL tracker through an operation sequence
 * and records, per op, the return value of `markItemComplete` (the completed
 * batch ids) plus the final peer count. The Rust replay
 * (`replay_ongoing_fixtures`) reproduces every result byte-for-byte.
 *
 * Export with EXPORT_STORAGE_RECONCILIATION_FIXTURES=1 →
 * crates/cojson-core/data/storage_reconciliation_ongoing/<scenario>.json.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { OngoingStorageReconciliationTracker } from "../OngoingStorageReconciliationTracker.js";
import type { RawCoID } from "../ids.js";
import type { PeerID, ReconcileBatchID } from "../sync.js";

const EXPORT = process.env.EXPORT_STORAGE_RECONCILIATION_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/storage_reconciliation_ongoing",
);

type Op =
  | { op: "trackBatch"; peerId: string; batchId: string; pending: string[] }
  | { op: "markItemComplete"; peerId: string; covalueId: string }
  | { op: "clearPeer"; peerId: string };

type Fixture = {
  description: string;
  ops: Op[];
  expected: {
    results: (string[] | null)[];
    ongoingPeerCount: number;
  };
};

function run(name: string, description: string, ops: Op[]): Fixture {
  const tracker = new OngoingStorageReconciliationTracker();
  const results: (string[] | null)[] = [];

  for (const op of ops) {
    switch (op.op) {
      case "trackBatch":
        tracker.trackBatch(
          op.peerId as PeerID,
          op.batchId as ReconcileBatchID,
          new Set(op.pending as RawCoID[]),
        );
        results.push(null);
        break;
      case "markItemComplete":
        results.push(
          tracker.markItemComplete(
            op.peerId as PeerID,
            op.covalueId as RawCoID,
          ) as string[],
        );
        break;
      case "clearPeer":
        tracker.clearPeer(op.peerId as PeerID);
        results.push(null);
        break;
    }
  }

  // @ts-expect-error - reconcileBatches is private
  const ongoingPeerCount: number = tracker.reconcileBatches.size;

  const fixture: Fixture = {
    description,
    ops,
    expected: { results, ongoingPeerCount },
  };

  if (EXPORT) {
    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(
      join(OUT_DIR, `${name}.json`),
      JSON.stringify(fixture, null, 2),
    );
  }
  return fixture;
}

describe("ongoing storage reconciliation fixtures", () => {
  test("empty_batch_ignored", () => {
    const f = run("empty_batch_ignored", "empty batches are not tracked", [
      { op: "trackBatch", peerId: "peer-1", batchId: "batch-1", pending: [] },
    ]);
    expect(f.expected.ongoingPeerCount).toBe(0);
  });

  test("completes_when_all_done", () => {
    const f = run(
      "completes_when_all_done",
      "a batch completes only when all its covalues are marked",
      [
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-1",
          pending: ["co_A", "co_B"],
        },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_A" },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_B" },
      ],
    );
    expect(f.expected.results).toEqual([null, [], ["batch-1"]]);
    expect(f.expected.ongoingPeerCount).toBe(0);
  });

  test("covalue_in_multiple_batches", () => {
    const f = run(
      "covalue_in_multiple_batches",
      "a covalue in several batches completes all that become empty, in order",
      [
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-1",
          pending: ["co_A"],
        },
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-2",
          pending: ["co_A", "co_B"],
        },
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-3",
          pending: ["co_B"],
        },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_A" },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_B" },
      ],
    );
    expect(f.expected.results).toEqual([
      null,
      null,
      null,
      ["batch-1"],
      ["batch-2", "batch-3"],
    ]);
    expect(f.expected.ongoingPeerCount).toBe(0);
  });

  test("isolated_by_peer", () => {
    const f = run("isolated_by_peer", "state is isolated per peer", [
      {
        op: "trackBatch",
        peerId: "peer-1",
        batchId: "batch-A",
        pending: ["co_A"],
      },
      {
        op: "trackBatch",
        peerId: "peer-2",
        batchId: "batch-B",
        pending: ["co_A"],
      },
      { op: "markItemComplete", peerId: "peer-1", covalueId: "co_A" },
      { op: "markItemComplete", peerId: "peer-2", covalueId: "co_A" },
    ]);
    expect(f.expected.results).toEqual([null, null, ["batch-A"], ["batch-B"]]);
  });

  test("clear_peer_removes_only_that_peer", () => {
    const f = run(
      "clear_peer_removes_only_that_peer",
      "clearPeer drops one peer's state and leaves the other",
      [
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-A",
          pending: ["co_A"],
        },
        {
          op: "trackBatch",
          peerId: "peer-2",
          batchId: "batch-B",
          pending: ["co_B"],
        },
        { op: "clearPeer", peerId: "peer-1" },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_A" },
        { op: "markItemComplete", peerId: "peer-2", covalueId: "co_B" },
      ],
    );
    expect(f.expected.results).toEqual([null, null, null, [], ["batch-B"]]);
  });

  test("unknown_covalue_noop", () => {
    const f = run(
      "unknown_covalue_noop",
      "marking a covalue that is not tracked returns no completed batches",
      [
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-1",
          pending: ["co_A"],
        },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_Z" },
      ],
    );
    expect(f.expected.results).toEqual([null, []]);
    expect(f.expected.ongoingPeerCount).toBe(1);
  });

  test("partial_then_remaining", () => {
    const f = run(
      "partial_then_remaining",
      "three-covalue batch completes only on the last mark",
      [
        {
          op: "trackBatch",
          peerId: "peer-1",
          batchId: "batch-1",
          pending: ["co_A", "co_B", "co_C"],
        },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_B" },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_A" },
        { op: "markItemComplete", peerId: "peer-1", covalueId: "co_C" },
      ],
    );
    expect(f.expected.results).toEqual([null, [], [], ["batch-1"]]);
  });
});
