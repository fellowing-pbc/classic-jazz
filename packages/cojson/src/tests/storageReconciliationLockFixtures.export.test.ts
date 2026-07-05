/**
 * Storage reconciliation-lock fixture exporter.
 *
 * Captures the CURRENT TypeScript behavior of the reconciliation-lock decision
 * (`tryAcquireStorageReconciliationLock` / `renewStorageReconciliationLock` /
 * `releaseStorageReconciliationLock`) as executable fixtures for the Rust port
 * (`crates/cojson-core/src/core/storage_reconciliation.rs`).
 *
 * The decision logic is duplicated byte-for-byte between the sync
 * (`storage/sqlite/client.ts`) and async (`storage/sqliteAsync/client.ts`)
 * clients. This exporter drives the REAL sync `SQLiteClient` against an
 * in-memory libsql database: it seeds a lock row, freezes wall-clock time with
 * fake timers, runs the real method, and records the acquire result and the
 * resulting stored lock row. Because the two clients share identical decision
 * code, the sync client faithfully represents both.
 *
 * When EXPORT_STORAGE_RECONCILIATION_FIXTURES=1 the fixtures are written to
 * crates/cojson-core/data/storage_reconciliation_lock/<scenario>.json.
 * Regardless of export, the suite asserts internal consistency so it has value
 * in CI. The Rust replay (`replay_lock_fixtures`) reads the committed files and
 * must reproduce every field byte-for-byte.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database, { type Database as DatabaseT } from "libsql";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { STORAGE_RECONCILIATION_CONFIG } from "../config.js";
import type { PeerID } from "../sync.js";
import type { SessionID } from "../ids.js";
import { getSqliteStorage } from "../storage/sqlite/index.js";
import type { SQLiteDatabaseDriver } from "../storage/sqlite/types.js";
import type {
  StorageReconciliationAcquireResult,
  StorageReconciliationLockRow,
} from "../storage/types.js";

const EXPORT = process.env.EXPORT_STORAGE_RECONCILIATION_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/storage_reconciliation_lock",
);

/** Minimal in-memory libsql driver, mirroring the one in testStorage.ts. */
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

type LockRowFixture = {
  holderSessionId: string;
  acquiredAt: number;
  releasedAt?: number;
  lastProcessedOffset: number;
};

type LockFixture = {
  description: string;
  op: "acquire" | "renew" | "release";
  seedRow: LockRowFixture | null;
  sessionId: string;
  now: number;
  offset?: number;
  config: { lockTtlMs: number; reconciliationIntervalMs: number };
  expected: {
    acquireResult?: StorageReconciliationAcquireResult;
    resultRow: LockRowFixture | null;
  };
};

const PEER_ID = "peer_fixture" as PeerID;
const LOCK_KEY = `lock#${PEER_ID}`;

// A tiny, easy-to-read config so `now` values in fixtures stay small.
const LOCK_TTL_MS = 1000;
const RECONCILIATION_INTERVAL_MS = 10_000;

/** Access the real SQLiteClient behind the StorageApiSync facade. */
function newClient() {
  const storage = getSqliteStorage(new MemDriver());
  // dbClient is private but is the exact production decision surface.
  // @ts-expect-error - dbClient is private
  return storage.dbClient as {
    getStorageReconciliationLock(
      key: string,
    ): StorageReconciliationLockRow | undefined;
    putStorageReconciliationLock(entry: StorageReconciliationLockRow): void;
    tryAcquireStorageReconciliationLock(
      s: SessionID,
      p: PeerID,
    ): StorageReconciliationAcquireResult;
    renewStorageReconciliationLock(s: SessionID, p: PeerID, o: number): void;
    releaseStorageReconciliationLock(s: SessionID, p: PeerID): void;
  };
}

/** Normalize a stored row to the fixture shape (drop derived `key`). */
function toFixtureRow(
  row: StorageReconciliationLockRow | undefined,
): LockRowFixture | null {
  if (!row) return null;
  const out: LockRowFixture = {
    holderSessionId: row.holderSessionId,
    acquiredAt: row.acquiredAt,
    lastProcessedOffset: row.lastProcessedOffset,
  };
  if (row.releasedAt !== undefined && row.releasedAt !== null) {
    out.releasedAt = row.releasedAt;
  }
  return out;
}

beforeEach(() => {
  vi.useFakeTimers();
  STORAGE_RECONCILIATION_CONFIG.LOCK_TTL_MS = LOCK_TTL_MS;
  STORAGE_RECONCILIATION_CONFIG.RECONCILIATION_INTERVAL_MS =
    RECONCILIATION_INTERVAL_MS;
});

afterEach(() => {
  vi.useRealTimers();
  // Restore production defaults for other suites.
  STORAGE_RECONCILIATION_CONFIG.LOCK_TTL_MS = 24 * 60 * 60 * 1000;
  STORAGE_RECONCILIATION_CONFIG.RECONCILIATION_INTERVAL_MS =
    30 * 24 * 60 * 60 * 1000;
});

function exportAcquire(
  name: string,
  description: string,
  seedRow: LockRowFixture | null,
  sessionId: string,
  now: number,
): LockFixture {
  const client = newClient();
  if (seedRow) {
    client.putStorageReconciliationLock({
      key: LOCK_KEY,
      ...seedRow,
    } as StorageReconciliationLockRow);
  }
  vi.setSystemTime(now);
  const acquireResult = client.tryAcquireStorageReconciliationLock(
    sessionId as SessionID,
    PEER_ID,
  );
  const resultRow = toFixtureRow(client.getStorageReconciliationLock(LOCK_KEY));

  const fixture: LockFixture = {
    description,
    op: "acquire",
    seedRow,
    sessionId,
    now,
    config: {
      lockTtlMs: LOCK_TTL_MS,
      reconciliationIntervalMs: RECONCILIATION_INTERVAL_MS,
    },
    expected: { acquireResult, resultRow },
  };
  writeFixture(name, fixture);
  return fixture;
}

function exportRenew(
  name: string,
  description: string,
  seedRow: LockRowFixture | null,
  sessionId: string,
  offset: number,
): LockFixture {
  const client = newClient();
  if (seedRow) {
    client.putStorageReconciliationLock({
      key: LOCK_KEY,
      ...seedRow,
    } as StorageReconciliationLockRow);
  }
  vi.setSystemTime(1); // renew ignores time
  client.renewStorageReconciliationLock(
    sessionId as SessionID,
    PEER_ID,
    offset,
  );
  const resultRow = toFixtureRow(client.getStorageReconciliationLock(LOCK_KEY));

  const fixture: LockFixture = {
    description,
    op: "renew",
    seedRow,
    sessionId,
    now: 1,
    offset,
    config: {
      lockTtlMs: LOCK_TTL_MS,
      reconciliationIntervalMs: RECONCILIATION_INTERVAL_MS,
    },
    expected: { resultRow },
  };
  writeFixture(name, fixture);
  return fixture;
}

function exportRelease(
  name: string,
  description: string,
  seedRow: LockRowFixture | null,
  sessionId: string,
  now: number,
): LockFixture {
  const client = newClient();
  if (seedRow) {
    client.putStorageReconciliationLock({
      key: LOCK_KEY,
      ...seedRow,
    } as StorageReconciliationLockRow);
  }
  vi.setSystemTime(now);
  client.releaseStorageReconciliationLock(sessionId as SessionID, PEER_ID);
  const resultRow = toFixtureRow(client.getStorageReconciliationLock(LOCK_KEY));

  const fixture: LockFixture = {
    description,
    op: "release",
    seedRow,
    sessionId,
    now,
    config: {
      lockTtlMs: LOCK_TTL_MS,
      reconciliationIntervalMs: RECONCILIATION_INTERVAL_MS,
    },
    expected: { resultRow },
  };
  writeFixture(name, fixture);
  return fixture;
}

function writeFixture(name: string, fixture: LockFixture) {
  if (EXPORT) {
    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(
      join(OUT_DIR, `${name}.json`),
      JSON.stringify(fixture, null, 2),
    );
  }
}

describe("storage reconciliation lock fixtures", () => {
  test("acquire_no_row", () => {
    const f = exportAcquire(
      "acquire_no_row",
      "no existing lock: acquired with offset 0",
      null,
      "session_a",
      500,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: true,
      lastProcessedOffset: 0,
    });
    expect(f.expected.resultRow).toEqual({
      holderSessionId: "session_a",
      acquiredAt: 500,
      lastProcessedOffset: 0,
    });
  });

  test("acquire_not_due_within_interval", () => {
    const f = exportAcquire(
      "acquire_not_due_within_interval",
      "released recently, interval not elapsed: not_due, no write",
      {
        holderSessionId: "session_b",
        acquiredAt: 0,
        releasedAt: 100,
        lastProcessedOffset: 5,
      },
      "session_a",
      100 + RECONCILIATION_INTERVAL_MS - 1,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: false,
      reason: "not_due",
    });
    // unchanged row
    expect(f.expected.resultRow?.releasedAt).toBe(100);
  });

  test("acquire_due_after_interval", () => {
    const f = exportAcquire(
      "acquire_due_after_interval",
      "released long ago, interval elapsed: re-acquired with offset reset to 0",
      {
        holderSessionId: "session_b",
        acquiredAt: 0,
        releasedAt: 100,
        lastProcessedOffset: 5,
      },
      "session_a",
      100 + RECONCILIATION_INTERVAL_MS,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: true,
      lastProcessedOffset: 0,
    });
    expect(f.expected.resultRow).toEqual({
      holderSessionId: "session_a",
      acquiredAt: 100 + RECONCILIATION_INTERVAL_MS,
      lastProcessedOffset: 0,
    });
  });

  test("acquire_lock_held_by_other", () => {
    const f = exportAcquire(
      "acquire_lock_held_by_other",
      "another session holds a live, non-expired lock: lock_held, no write",
      {
        holderSessionId: "session_b",
        acquiredAt: 200,
        lastProcessedOffset: 3,
      },
      "session_a",
      200 + LOCK_TTL_MS - 1,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: false,
      reason: "lock_held",
    });
    expect(f.expected.resultRow?.holderSessionId).toBe("session_b");
  });

  test("acquire_takeover_expired_other", () => {
    const f = exportAcquire(
      "acquire_takeover_expired_other",
      "another session's lock has expired (TTL): taken over, offset carried",
      {
        holderSessionId: "session_b",
        acquiredAt: 200,
        lastProcessedOffset: 3,
      },
      "session_a",
      200 + LOCK_TTL_MS + 1,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: true,
      lastProcessedOffset: 3,
    });
    expect(f.expected.resultRow?.holderSessionId).toBe("session_a");
  });

  test("acquire_same_session_carries_offset", () => {
    const f = exportAcquire(
      "acquire_same_session_carries_offset",
      "same session re-acquires its own live lock: offset carried forward",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        lastProcessedOffset: 9,
      },
      "session_a",
      300,
    );
    expect(f.expected.acquireResult).toEqual({
      acquired: true,
      lastProcessedOffset: 9,
    });
    expect(f.expected.resultRow).toEqual({
      holderSessionId: "session_a",
      acquiredAt: 300,
      lastProcessedOffset: 9,
    });
  });

  test("renew_owned_live", () => {
    const f = exportRenew(
      "renew_owned_live",
      "owner renews a live lock: offset updated",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        lastProcessedOffset: 1,
      },
      "session_a",
      77,
    );
    expect(f.expected.resultRow?.lastProcessedOffset).toBe(77);
    expect(f.expected.resultRow?.acquiredAt).toBe(200);
  });

  test("renew_wrong_session_noop", () => {
    const f = exportRenew(
      "renew_wrong_session_noop",
      "a non-owner renew is a no-op",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        lastProcessedOffset: 1,
      },
      "session_b",
      77,
    );
    expect(f.expected.resultRow?.lastProcessedOffset).toBe(1);
  });

  test("renew_released_noop", () => {
    const f = exportRenew(
      "renew_released_noop",
      "renewing a released lock is a no-op",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        releasedAt: 250,
        lastProcessedOffset: 1,
      },
      "session_a",
      77,
    );
    expect(f.expected.resultRow?.lastProcessedOffset).toBe(1);
  });

  test("release_owned", () => {
    const f = exportRelease(
      "release_owned",
      "owner releases: releasedAt set, offset reset to 0",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        lastProcessedOffset: 8,
      },
      "session_a",
      999,
    );
    expect(f.expected.resultRow?.releasedAt).toBe(999);
    expect(f.expected.resultRow?.lastProcessedOffset).toBe(0);
  });

  test("release_wrong_session_noop", () => {
    const f = exportRelease(
      "release_wrong_session_noop",
      "a non-owner release is a no-op",
      {
        holderSessionId: "session_a",
        acquiredAt: 200,
        lastProcessedOffset: 8,
      },
      "session_b",
      999,
    );
    expect(f.expected.resultRow?.releasedAt).toBeUndefined();
    expect(f.expected.resultRow?.lastProcessedOffset).toBe(8);
  });
});
