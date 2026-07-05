/**
 * StorageReconciliationServerAckTracker fixture exporter.
 *
 * Captures the CURRENT TypeScript behavior of
 * `packages/cojson/src/StorageReconciliationAckTracker.ts` as executable
 * fixtures for the Rust port
 * (`crates/cojson-core/src/core/storage_reconciliation.rs`,
 * `StorageReconciliationRegistry` ack surface).
 *
 * For each scenario it drives the REAL tracker (with real `PeerState` objects)
 * through an operation sequence and records the ordered callback contract as an
 * event log:
 *   - "immediate:<id>"  a waitForAck whose callback fired synchronously
 *   - "offset:<n>"      the nextOffset returned by a handleAck
 *   - "ack:<id>"        a deferred callback fired by handleAck
 *   - "cancel:<id>"     a wait cancelled by a peer close (callback NEVER fires)
 * plus the final pendingReconciliationAck snapshot. The callback ORDER is the
 * load-bearing contract. The Rust replay (`replay_ack_fixtures`) reproduces the
 * event log and pending snapshot byte-for-byte.
 *
 * Export with EXPORT_STORAGE_RECONCILIATION_FIXTURES=1 →
 * crates/cojson-core/data/storage_reconciliation_ack/<scenario>.json.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { PeerState } from "../PeerState.js";
import { StorageReconciliationServerAckTracker } from "../StorageReconciliationAckTracker.js";
import { ConnectedPeerChannel } from "../streamUtils.js";
import type { Peer } from "../sync.js";

const EXPORT = process.env.EXPORT_STORAGE_RECONCILIATION_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/storage_reconciliation_ack",
);

type Op =
  | { op: "trackBatch"; batchId: string; peerId: string; nextOffset: number }
  | { op: "waitForAck"; batchId: string; peerId: string; waitId: number }
  | { op: "handleAck"; batchId: string; peerId: string }
  | { op: "peerClose"; peerId: string };

type Fixture = {
  description: string;
  ops: Op[];
  expected: {
    eventLog: string[];
    pending: [string, number][];
  };
};

function createPeerState(id: string): PeerState {
  const peer: Peer = {
    id,
    role: "server",
    persistent: true,
    incoming: new ConnectedPeerChannel(),
    outgoing: new ConnectedPeerChannel(),
  };
  return new PeerState(peer, undefined);
}

function run(name: string, description: string, ops: Op[]): Fixture {
  const tracker = new StorageReconciliationServerAckTracker();
  const eventLog: string[] = [];

  // Real PeerState per peer id, reused across ops.
  const peers = new Map<string, PeerState>();
  const peerFor = (id: string) => {
    let p = peers.get(id);
    if (!p) {
      p = createPeerState(id);
      peers.set(id, p);
    }
    return p;
  };

  // Track outstanding (registered, not-yet-fired) waits in registration order,
  // to emit deterministic "cancel" events on peer close (the TS close listeners
  // fire in registration order and never invoke the callback).
  const outstanding: { waitId: number; peerId: string }[] = [];

  for (const op of ops) {
    switch (op.op) {
      case "trackBatch":
        tracker.trackBatch(op.batchId, op.peerId, op.nextOffset);
        break;
      case "waitForAck": {
        const peer = peerFor(op.peerId);
        let firedDuringWait = false;
        const cb = () => {
          if (firedDuringWait) {
            eventLog.push(`immediate:${op.waitId}`);
          } else {
            eventLog.push(`ack:${op.waitId}`);
            const idx = outstanding.findIndex((o) => o.waitId === op.waitId);
            if (idx >= 0) outstanding.splice(idx, 1);
          }
        };
        firedDuringWait = true;
        // If this fires synchronously, cb sees firedDuringWait === true.
        const before = eventLog.length;
        tracker.waitForAck(op.batchId, peer, cb);
        firedDuringWait = false;
        // If not fired synchronously, it is a real outstanding wait.
        if (eventLog.length === before) {
          outstanding.push({ waitId: op.waitId, peerId: op.peerId });
        }
        break;
      }
      case "handleAck": {
        const start = eventLog.length;
        const nextOffset = tracker.handleAck(op.batchId, op.peerId);
        // Rust emits offset BEFORE the ack callbacks of the same handleAck.
        if (nextOffset !== undefined) {
          eventLog.splice(start, 0, `offset:${nextOffset}`);
        }
        break;
      }
      case "peerClose": {
        const peer = peerFor(op.peerId);
        // Cancelled waits (callback never fires): emit in registration order.
        const cancelled = outstanding.filter((o) => o.peerId === op.peerId);
        peer.gracefulShutdown();
        for (const c of cancelled) {
          eventLog.push(`cancel:${c.waitId}`);
          const idx = outstanding.findIndex((o) => o.waitId === c.waitId);
          if (idx >= 0) outstanding.splice(idx, 1);
        }
        break;
      }
    }
  }

  const pending: [string, number][] = [
    ...tracker.pendingReconciliationAck.entries(),
  ].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const fixture: Fixture = {
    description,
    ops,
    expected: { eventLog, pending },
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

describe("ack storage reconciliation fixtures", () => {
  test("ack_fires_callback", () => {
    const f = run(
      "ack_fires_callback",
      "a tracked batch fires its wait callback on ack, returning the offset",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 100,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["offset:100", "ack:1"]);
    expect(f.expected.pending).toEqual([]);
  });

  test("immediate_when_not_pending", () => {
    const f = run(
      "immediate_when_not_pending",
      "waiting on a batch that is not pending fires the callback immediately",
      [{ op: "waitForAck", batchId: "missing", peerId: "peer-1", waitId: 1 }],
    );
    expect(f.expected.eventLog).toEqual(["immediate:1"]);
  });

  test("all_listeners_fire", () => {
    const f = run(
      "all_listeners_fire",
      "every wait registered for a batch fires on ack, in registration order",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 50,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 2 },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["offset:50", "ack:1", "ack:2"]);
  });

  test("peer_close_cancels", () => {
    const f = run(
      "peer_close_cancels",
      "a peer close cancels the wait, clears pending, and never fires the callback",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 50,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "peerClose", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["cancel:1"]);
    expect(f.expected.pending).toEqual([]);
  });

  test("ack_then_close_fires_once", () => {
    const f = run(
      "ack_then_close_fires_once",
      "a close after the ack does not re-fire or re-cancel the wait",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 50,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
        { op: "peerClose", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["offset:50", "ack:1"]);
  });

  test("close_before_ack_suppresses", () => {
    const f = run(
      "close_before_ack_suppresses",
      "after a peer close the batch is no longer pending, so a later ack fires nothing",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 50,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "peerClose", peerId: "peer-1" },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["cancel:1"]);
  });

  test("multi_peer_isolation", () => {
    const f = run(
      "multi_peer_isolation",
      "acks and closes are isolated per peer",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 10,
        },
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-2",
          nextOffset: 20,
        },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-1", waitId: 1 },
        { op: "waitForAck", batchId: "batch-1", peerId: "peer-2", waitId: 2 },
        { op: "peerClose", peerId: "peer-1" },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-2" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["cancel:1", "offset:20", "ack:2"]);
    expect(f.expected.pending).toEqual([]);
  });

  test("handle_ack_no_wait_returns_offset", () => {
    const f = run(
      "handle_ack_no_wait_returns_offset",
      "handleAck with no registered wait still returns and clears the offset",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 77,
        },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["offset:77"]);
    expect(f.expected.pending).toEqual([]);
  });

  test("pending_survives_until_ack", () => {
    const f = run(
      "pending_survives_until_ack",
      "multiple tracked batches stay pending until each is acked",
      [
        {
          op: "trackBatch",
          batchId: "batch-1",
          peerId: "peer-1",
          nextOffset: 11,
        },
        {
          op: "trackBatch",
          batchId: "batch-2",
          peerId: "peer-1",
          nextOffset: 22,
        },
        { op: "handleAck", batchId: "batch-1", peerId: "peer-1" },
      ],
    );
    expect(f.expected.eventLog).toEqual(["offset:11"]);
    expect(f.expected.pending).toEqual([["batch-2#peer-1", 22]]);
  });
});
