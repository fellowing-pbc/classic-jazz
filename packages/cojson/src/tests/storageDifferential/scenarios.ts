/**
 * Representative, hand-written storage scenarios for the differential harness.
 *
 * These adapt the shapes exercised by the existing storage suites
 * (`StorageApiSync.test.ts`, `sync.localStoreDurability.test.ts`, the delete
 * flow) into the harness contract. Each returns the captured golden snapshot
 * (message trace + per-checkpoint DB row-state + durability window / lock
 * decisions) which the driver freezes as a committed fixture and diff-checks.
 *
 * The set spans the storage-critical paths the scoping pass flagged: a normal
 * store+load round trip, a correction-triggering header gap, delete + erasure
 * (tombstone preservation), concurrent coValues, deterministic signature
 * checkpoints, the crash-window durability contract (the single highest-value
 * capture, recently hardened by the team), and the reconciliation-lock decision
 * surface.
 *
 * TEST-ONLY. Observational: no production storage read/write path is modified.
 */
import { vi } from "vitest";
import Database, { type Database as DatabaseT } from "libsql";
import {
  STORAGE_RECONCILIATION_CONFIG,
  TRANSACTION_CONFIG,
} from "../../config.js";
import { emptyKnownState } from "../../knownState.js";
import type { NewContentMessage, PeerID } from "../../sync.js";
import type { SessionID } from "../../ids.js";
import { getSqliteStorage } from "../../storage/sqlite/index.js";
import type { SQLiteDatabaseDriver } from "../../storage/sqlite/types.js";
import type {
  StorageReconciliationAcquireResult,
  StorageReconciliationLockRow,
} from "../../storage/types.js";
import { createSyncStorage, getDbPath } from "../testStorage.js";
import { setupTestNode, waitFor } from "../testUtils.js";
import {
  captureTrace,
  inspectorFor,
  type LockDecisionCapture,
  type NormalizedDbSnapshot,
  type StorageScenario,
} from "./harness.js";

function syncStorageAt(dbPath: string) {
  return createSyncStorage({
    filename: dbPath,
    nodeName: "client",
    storageName: "storage",
  });
}

/** 1. Normal store + load round trip (sync storage, node-driven). */
const normalStoreLoad: StorageScenario = {
  name: "normal_store_load",
  run: async () => {
    const dbPath = getDbPath();
    const node = setupTestNode();
    const { storage } = node.addStorage({ storage: syncStorageAt(dbPath) });

    const group = node.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");
    await map.core.waitForSync();

    const named = { Group: group.core, Map: map.core };
    const insp = inspectorFor(dbPath, named, node.node);
    const dbStates: Record<string, NormalizedDbSnapshot> = {
      afterStore: insp.snapshot(),
    };
    insp.close();

    // Round-trip load (exercises + logs the load path).
    await new Promise<void>((resolve) => {
      storage.load(
        map.id,
        () => {},
        () => resolve(),
      );
    });

    return { trace: captureTrace(named), dbStates };
  },
};

/** 2. Correction-triggering header gap: store header-less content into empty
 *  storage, forcing a correction round trip (mirrors the durability suite). */
const correctionGap: StorageScenario = {
  name: "correction_gap",
  run: async () => {
    const dbPath = getDbPath();
    const node = setupTestNode();
    const group = node.node.createGroup();
    const map = group.createMap();
    map.set("a", 1, "trusting");

    const { storage } = node.addStorage({ storage: syncStorageAt(dbPath) });

    const fullContent = map.core.newContentSince(undefined)!;
    const withoutHeader = map.core.newContentSince({
      id: map.id,
      header: true,
      sessions: {},
    })!;

    await new Promise<void>((resolve) => {
      storage.store(
        withoutHeader[0]!,
        () => fullContent,
        () => resolve(),
      );
    });

    const named = { Group: group.core, Map: map.core };
    const insp = inspectorFor(dbPath, named, node.node);
    const dbStates = { afterCorrection: insp.snapshot() };
    insp.close();

    return { trace: captureTrace(named), dbStates };
  },
};

/** 3. Delete + erasure: tombstone preserved, history erased, queue drained. */
const deleteErasure: StorageScenario = {
  name: "delete_erasure",
  run: async () => {
    const dbPath = getDbPath();
    const node = setupTestNode();
    const { storage } = node.addStorage({ storage: syncStorageAt(dbPath) });

    const group = node.node.createGroup();
    const map = group.createMap();
    map.set("k", "v", "trusting");
    await map.core.waitForSync();

    const named = { Group: group.core, Map: map.core };
    const insp = inspectorFor(dbPath, named, node.node);
    const dbStates: Record<string, NormalizedDbSnapshot> = {
      afterStore: insp.snapshot(),
    };

    map.core.deleteCoValue();
    await map.core.waitForSync();
    dbStates.afterDelete = insp.snapshot();

    await storage.eraseAllDeletedCoValues();
    dbStates.afterErasure = insp.snapshot();
    insp.close();

    return { trace: captureTrace(named), dbStates };
  },
};

/** 4. Concurrent coValues under one group. */
const concurrentCovalues: StorageScenario = {
  name: "concurrent_covalues",
  run: async () => {
    const dbPath = getDbPath();
    const node = setupTestNode();
    node.addStorage({ storage: syncStorageAt(dbPath) });

    const group = node.node.createGroup();
    const mapA = group.createMap();
    const mapB = group.createMap();
    mapA.set("a", 1, "trusting");
    mapB.set("b", 2, "trusting");
    mapB.set("b2", 3, "trusting");
    await mapA.core.waitForSync();
    await mapB.core.waitForSync();

    const named = { Group: group.core, MapA: mapA.core, MapB: mapB.core };
    const insp = inspectorFor(dbPath, named, node.node);
    const dbStates = { afterStore: insp.snapshot() };
    insp.close();

    return { trace: captureTrace(named), dbStates };
  },
};

/** 5. Deterministic signature checkpoints: with a tiny recommended-tx-size
 *  threshold every stored batch crosses the boundary, so a `signatureAfter`
 *  checkpoint lands at each batch's last index — deterministic regardless of
 *  per-transaction byte size. */
const signatureCheckpoints: StorageScenario = {
  name: "signature_checkpoints",
  run: async () => {
    const dbPath = getDbPath();
    // No storage attached to the node: we drive a STANDALONE storage manually so
    // the node's own content generation keeps the default threshold (avoiding
    // pathological chunking), while storage sees a tiny threshold that forces a
    // checkpoint on every stored batch.
    const node = setupTestNode();
    const group = node.node.createGroup();
    const map = group.createMap();

    // Build the incremental content batches up front, under the DEFAULT
    // threshold, so `newContentSince` behaves normally.
    const batches: NewContentMessage[] = [];
    let known = emptyKnownState(map.id);
    for (let i = 0; i < 3; i++) {
      map.set(`k${i}`, i, "trusting");
      const content = map.core.newContentSince(known);
      if (content?.[0]) batches.push(content[0]);
      known = map.core.knownState();
    }

    const storage = syncStorageAt(dbPath);
    const originalMax = TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE;
    try {
      // Tiny threshold: every stored batch exceeds it → a `signatureAfter`
      // checkpoint at each batch's last index, independent of byte size.
      TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE = 1;
      for (const batch of batches) {
        await new Promise<void>((resolve) => {
          storage.store(
            batch,
            () => undefined,
            () => resolve(),
          );
        });
      }
    } finally {
      TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE = originalMax;
    }

    const named = { Map: map.core };
    const insp = inspectorFor(dbPath, named, node.node);
    const dbStates = { afterBatches: insp.snapshot() };
    insp.close();

    return { trace: captureTrace(named), dbStates };
  },
};

/** 6. Crash-window durability: async storage that accepts writes but never
 *  completes them. The durability window must OPEN (before any peer send) and
 *  never CLOSE. This is the single highest-value capture — the exact
 *  callback-timing sequence the team recently hardened
 *  (`sync.localStoreDurability.test.ts`). */
const crashWindowDurability: StorageScenario = {
  name: "crash_window_durability",
  run: async () => {
    setupTestNode({ isSyncServer: true });

    const client = setupTestNode();
    const { storage } = await client.addAsyncStorage();
    const { peerState } = client.connectToSyncServer();

    // Simulate the crash window: storage accepts writes but never completes.
    // (Instance-level stub, exactly as the existing durability test does — no
    // production storage code is changed.)
    storage.store = async () => {};

    const durabilityWindow: boolean[] = [];
    client.node.syncManager.onLocalStoreDurabilityChange = (hasPending) =>
      durabilityWindow.push(hasPending);

    const group = client.node.createGroup();
    const map = group.createMap();
    map.set("hello", "world", "trusting");

    // Content reaches the peer (peer sync only) — storage never drains.
    await client.node.syncManager.waitForSyncWithPeer(
      peerState.id,
      map.id,
      5000,
    );

    return { trace: [], dbStates: {}, durabilityWindow };
  },
};

// ---- reconciliation-lock decision oracle (real sync client) ----

class MemDriver implements SQLiteDatabaseDriver {
  private readonly db: DatabaseT;
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
    } catch {
      this.run("ROLLBACK", []);
    }
  }
  closeDb() {
    this.db.close();
  }
}

type LockClient = {
  getStorageReconciliationLock(
    key: string,
  ): StorageReconciliationLockRow | undefined;
  putStorageReconciliationLock(entry: StorageReconciliationLockRow): void;
  tryAcquireStorageReconciliationLock(
    s: SessionID,
    p: PeerID,
  ): StorageReconciliationAcquireResult;
};

const PEER_ID = "peer_lock" as PeerID;
const LOCK_KEY = `lock#${PEER_ID}`;
const LOCK_TTL_MS = 1000;
const INTERVAL_MS = 10_000;

function stripKey(row: StorageReconciliationLockRow | undefined) {
  if (!row) return null;
  const out: Record<string, unknown> = {
    holderSessionId: row.holderSessionId,
    acquiredAt: row.acquiredAt,
    lastProcessedOffset: row.lastProcessedOffset,
  };
  if (row.releasedAt != null) out.releasedAt = row.releasedAt;
  return out;
}

type SeedLockRow = {
  holderSessionId: string;
  acquiredAt: number;
  releasedAt?: number;
  lastProcessedOffset: number;
};

function captureAcquire(
  label: string,
  seed: SeedLockRow | null,
  sessionId: string,
  now: number,
): LockDecisionCapture {
  const storage = getSqliteStorage(new MemDriver());
  // @ts-expect-error - dbClient is private (read-only decision surface)
  const client = storage.dbClient as LockClient;
  if (seed)
    client.putStorageReconciliationLock({
      key: LOCK_KEY,
      ...seed,
    } as StorageReconciliationLockRow);
  vi.setSystemTime(now);
  const result = client.tryAcquireStorageReconciliationLock(
    sessionId as SessionID,
    PEER_ID,
  );
  const resultRow = stripKey(client.getStorageReconciliationLock(LOCK_KEY));
  return { label, result, resultRow };
}

/** 7. Reconciliation-lock decision outcomes. */
const reconciliationLock: StorageScenario = {
  name: "reconciliation_lock",
  run: async () => {
    const originalTtl = STORAGE_RECONCILIATION_CONFIG.LOCK_TTL_MS;
    const originalInterval =
      STORAGE_RECONCILIATION_CONFIG.RECONCILIATION_INTERVAL_MS;
    vi.useFakeTimers();
    STORAGE_RECONCILIATION_CONFIG.LOCK_TTL_MS = LOCK_TTL_MS;
    STORAGE_RECONCILIATION_CONFIG.RECONCILIATION_INTERVAL_MS = INTERVAL_MS;

    let lockDecisions: LockDecisionCapture[];
    try {
      lockDecisions = [
        captureAcquire("no_row", null, "session_a", 500),
        captureAcquire(
          "not_due",
          {
            holderSessionId: "session_b",
            acquiredAt: 0,
            releasedAt: 100,
            lastProcessedOffset: 5,
          },
          "session_a",
          100 + INTERVAL_MS - 1,
        ),
        captureAcquire(
          "lock_held",
          {
            holderSessionId: "session_b",
            acquiredAt: 200,
            lastProcessedOffset: 3,
          },
          "session_a",
          200 + LOCK_TTL_MS - 1,
        ),
        captureAcquire(
          "takeover_expired",
          {
            holderSessionId: "session_b",
            acquiredAt: 200,
            lastProcessedOffset: 3,
          },
          "session_a",
          200 + LOCK_TTL_MS + 1,
        ),
      ];
    } finally {
      vi.useRealTimers();
      STORAGE_RECONCILIATION_CONFIG.LOCK_TTL_MS = originalTtl;
      STORAGE_RECONCILIATION_CONFIG.RECONCILIATION_INTERVAL_MS =
        originalInterval;
    }

    return { trace: [], dbStates: {}, lockDecisions };
  },
};

export const storageScenarios: StorageScenario[] = [
  normalStoreLoad,
  correctionGap,
  deleteErasure,
  concurrentCovalues,
  signatureCheckpoints,
  crashWindowDurability,
  reconciliationLock,
];

export { waitFor };
