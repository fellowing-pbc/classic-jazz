import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("expo-sqlite", () => ({
  openDatabaseAsync: vi.fn(async () => ({
    execAsync: vi.fn(),
  })),
  deleteDatabaseAsync: vi.fn(),
}));

import { openDatabaseAsync } from "expo-sqlite";
import { ExpoSQLiteAdapter } from "../storage/expo-sqlite-adapter.js";

/**
 * Reproduces expo-sqlite's `withTransactionAsync` semantics: transactions are
 * not exclusive, a nested BEGIN throws, and a failed BEGIN still triggers a
 * ROLLBACK that aborts whichever transaction is currently active.
 */
function createFakeTransactionalDb() {
  let inTransaction = false;

  const execAsync = vi.fn(async (sql: string) => {
    if (sql === "BEGIN") {
      if (inTransaction) {
        throw new Error("cannot start a transaction within a transaction");
      }
      inTransaction = true;
    } else if (sql === "COMMIT") {
      if (!inTransaction) {
        throw new Error("cannot commit - no transaction is active");
      }
      inTransaction = false;
    } else if (sql === "ROLLBACK") {
      if (!inTransaction) {
        throw new Error("cannot rollback - no transaction is active");
      }
      inTransaction = false;
    }
  });

  return {
    execAsync,
    async withTransactionAsync(task: () => Promise<void>) {
      try {
        await execAsync("BEGIN");
        await task();
        await execAsync("COMMIT");
      } catch (e) {
        await execAsync("ROLLBACK");
        throw e;
      }
    },
  };
}

function createStubDb(overrides: Record<string, unknown> = {}) {
  return {
    execAsync: vi.fn(async () => {}),
    getAllAsync: vi.fn(async (): Promise<unknown[]> => []),
    getFirstAsync: vi.fn(async (): Promise<unknown> => null),
    runAsync: vi.fn(async () => {}),
    withTransactionAsync: vi.fn(async (task: () => Promise<void>) => {
      await task();
    }),
    ...overrides,
  };
}

function asDb(db: unknown) {
  return db as Parameters<typeof ExpoSQLiteAdapter.withDB>[0];
}

/**
 * The rejection expo-modules-core produces on Android when the native
 * `NativeDatabase` shared object was released while the JS wrapper survived
 * (`UsingReleasedSharedObjectException`), as observed in Sentry.
 */
function releasedObjectError() {
  return new Error(
    "Call to function 'NativeDatabase.prepareAsync' has been rejected.\n" +
      "→ Caused by: The 2nd argument cannot be cast to type expo.modules.sqlite.NativeStatement (received class java.lang.Integer)\n" +
      "→ Caused by: Cannot use shared object that was already released",
  );
}

describe("ExpoSQLiteAdapter", () => {
  describe("getInstance", () => {
    it("returns the same instance for the same database name", async () => {
      const adapter1 = ExpoSQLiteAdapter.getInstance("test-db");
      const adapter2 = ExpoSQLiteAdapter.getInstance("test-db");

      expect(adapter1).toBe(adapter2);
    });

    it("returns different instances for different database names", async () => {
      const adapter1 = ExpoSQLiteAdapter.getInstance("test-db-a");
      const adapter2 = ExpoSQLiteAdapter.getInstance("test-db-b");

      expect(adapter1).not.toBe(adapter2);
    });

    it("initializes the database connection only once", async () => {
      const adapter1 = ExpoSQLiteAdapter.getInstance("test-db");
      const adapter2 = ExpoSQLiteAdapter.getInstance("test-db");
      const promise1 = adapter1.initialize();
      const promise2 = adapter2.initialize();

      await promise1;
      await promise2;

      // @ts-expect-error - db is private
      expect(adapter1.db?.execAsync).toHaveBeenCalledTimes(1);
    });
  });

  describe("transaction", () => {
    it("serializes concurrent transactions on the same connection", async () => {
      const db = createFakeTransactionalDb();
      const adapter = ExpoSQLiteAdapter.withDB(asDb(db));

      const order: string[] = [];

      // Without serialization, the interleaved BEGINs throw
      // "cannot start a transaction within a transaction" and the resulting
      // ROLLBACK aborts the other transaction.
      await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          adapter.transaction(async () => {
            order.push(`start-${i}`);
            // Yield so a concurrent transaction would interleave here
            await new Promise((resolve) => setTimeout(resolve, (5 - i) * 2));
            order.push(`end-${i}`);
          }),
        ),
      );

      for (let i = 0; i < 5; i++) {
        expect(order[i * 2]).toBe(`start-${i}`);
        expect(order[i * 2 + 1]).toBe(`end-${i}`);
      }
    });

    it("keeps processing transactions after one fails", async () => {
      const db = createFakeTransactionalDb();
      const adapter = ExpoSQLiteAdapter.withDB(asDb(db));

      const failing = adapter.transaction(async () => {
        throw new Error("boom");
      });
      const succeeding = adapter.transaction(async () => {});

      await expect(failing).rejects.toThrow("boom");
      await expect(succeeding).resolves.not.toThrow();

      // The failed transaction rolled back exactly once, without touching
      // the following transaction.
      const rollbacks = db.execAsync.mock.calls.filter(
        ([sql]) => sql === "ROLLBACK",
      );
      expect(rollbacks).toHaveLength(1);
    });
  });

  describe("released shared object recovery", () => {
    beforeEach(() => {
      vi.mocked(openDatabaseAsync).mockReset();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("reopens the database and retries once when the native object was released", async () => {
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb({
        getAllAsync: vi.fn(async () => [{ id: 1 }]),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-retry");
      await adapter.initialize();

      await expect(adapter.query("SELECT * FROM t")).resolves.toEqual([
        { id: 1 },
      ]);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
      // The reopened connection goes through full initialization again.
      expect(freshDb.execAsync).toHaveBeenCalledWith(
        "PRAGMA journal_mode = WAL",
      );
    });

    it("retries get once when the native object was released", async () => {
      const deadDb = createStubDb({
        getFirstAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb({
        getFirstAsync: vi.fn(async () => ({ id: 3 })),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-get");
      await adapter.initialize();

      await expect(
        adapter.get("SELECT * FROM t WHERE id = 3"),
      ).resolves.toEqual({ id: 3 });
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
    });

    it("retries run once when the native object was released", async () => {
      const deadDb = createStubDb({
        runAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb();
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-run");
      await adapter.initialize();

      await expect(adapter.run("DELETE FROM t")).resolves.toBeUndefined();
      expect(freshDb.runAsync).toHaveBeenCalledTimes(1);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
    });

    it("detects the released object through a nested cause chain", async () => {
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw new Error(
            "Call to function 'NativeDatabase.prepareAsync' has been rejected.",
            {
              cause: new Error(
                "Cannot use shared object that was already released",
              ),
            },
          );
        }),
      });
      const freshDb = createStubDb({
        getAllAsync: vi.fn(async () => [{ id: 2 }]),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-cause-chain");
      await adapter.initialize();

      await expect(adapter.query("SELECT 1")).resolves.toEqual([{ id: 2 }]);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
    });

    it("does not reopen on errors other than a released shared object", async () => {
      const db = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw new Error("no such table: unknown");
        }),
      });
      vi.mocked(openDatabaseAsync).mockResolvedValueOnce(asDb(db));

      const adapter = new ExpoSQLiteAdapter("plain-error");
      await adapter.initialize();

      await expect(adapter.query("SELECT 1")).rejects.toThrow(
        "no such table: unknown",
      );
      expect(openDatabaseAsync).toHaveBeenCalledTimes(1);
    });

    it("retries at most once per operation", async () => {
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const alsoDeadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(alsoDeadDb));

      const adapter = new ExpoSQLiteAdapter("released-twice");
      await adapter.initialize();

      await expect(adapter.query("SELECT 1")).rejects.toThrow(
        /already released/,
      );
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
      expect(alsoDeadDb.getAllAsync).toHaveBeenCalledTimes(1);
    });

    it("shares a single reopen across concurrent failing operations", async () => {
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb({
        getAllAsync: vi.fn(async () => [{ ok: true }]),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-concurrent");
      await adapter.initialize();

      const [a, b] = await Promise.all([
        adapter.query("SELECT 1"),
        adapter.query("SELECT 2"),
      ]);

      expect(a).toEqual([{ ok: true }]);
      expect(b).toEqual([{ ok: true }]);
      // Initial open plus exactly one reopen, not one reopen per failing op.
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
    });

    it("recovers on a later operation when the reopen itself fails", async () => {
      vi.useFakeTimers();
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb({
        getAllAsync: vi.fn(async () => [{ id: 7 }]),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockRejectedValueOnce(new Error("disk I/O error"))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-reopen-fails");
      await adapter.initialize();

      await expect(adapter.query("SELECT 1")).rejects.toThrow("disk I/O error");
      // The failed reopen must not leave the adapter permanently
      // uninitialized: once the cooldown has passed, the next operation
      // attempts the reopen again.
      vi.advanceTimersByTime(1_000);
      await expect(adapter.query("SELECT 1")).resolves.toEqual([{ id: 7 }]);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(3);
    });

    it("suppresses reopen attempts during the cooldown after a failed reopen", async () => {
      vi.useFakeTimers();
      const deadDb = createStubDb({
        getAllAsync: vi.fn(async () => {
          throw releasedObjectError();
        }),
      });
      const freshDb = createStubDb({
        getAllAsync: vi.fn(async () => [{ id: 9 }]),
      });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockRejectedValueOnce(new Error("disk I/O error"))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-cooldown");
      await adapter.initialize();

      await expect(adapter.query("SELECT 1")).rejects.toThrow("disk I/O error");
      // Inside the cooldown the released-object error propagates untouched
      // and no reopen is attempted.
      await expect(adapter.query("SELECT 1")).rejects.toThrow(
        /already released/,
      );
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(1_000);
      await expect(adapter.query("SELECT 1")).resolves.toEqual([{ id: 9 }]);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(3);
    });

    it("reruns the whole transaction on a reopened connection instead of retrying inside it", async () => {
      const deadRun = vi.fn(async () => {
        throw releasedObjectError();
      });
      const deadDb = createStubDb({ runAsync: deadRun });
      const freshRun = vi.fn(async () => {});
      const freshDb = createStubDb({ runAsync: freshRun });
      vi.mocked(openDatabaseAsync)
        .mockResolvedValueOnce(asDb(deadDb))
        .mockResolvedValueOnce(asDb(freshDb));

      const adapter = new ExpoSQLiteAdapter("released-transaction");
      await adapter.initialize();

      const callback = vi.fn(async (tx: ExpoSQLiteAdapter) => {
        await tx.run("INSERT INTO t VALUES (1)");
      });
      await adapter.transaction(callback);

      expect(callback).toHaveBeenCalledTimes(2);
      // The sub-adapter inside the transaction must not retry on the dead
      // connection (a retry on a fresh one would run outside the transaction).
      expect(deadRun).toHaveBeenCalledTimes(1);
      expect(freshRun).toHaveBeenCalledTimes(1);
      expect(openDatabaseAsync).toHaveBeenCalledTimes(2);
    });
  });
});
