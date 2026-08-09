import { deleteDatabaseAsync, openDatabaseAsync } from "expo-sqlite";
import type { SQLiteBindValue, SQLiteDatabase } from "expo-sqlite";
import { type SQLiteDatabaseDriverAsync } from "jazz-tools/react-native-core";

/**
 * Matches the rejection expo-modules-core produces when a call touches a
 * native shared object that was released out from under its JS wrapper
 * (Android `UsingReleasedSharedObjectException`). On Android the host can
 * release the `NativeDatabase` during Activity teardown or under memory
 * pressure while the JS runtime — and this adapter's `db` reference —
 * survives. The rejection message carries the caused-by chain:
 *
 *   Call to function 'NativeDatabase.prepareAsync' has been rejected.
 *   → Caused by: The 2nd argument cannot be cast to type
 *     expo.modules.sqlite.NativeStatement (received class java.lang.Integer)
 *   → Caused by: Cannot use shared object that was already released
 *
 * The Integer cast failure is the same condition surfacing during argument
 * marshaling — the wrapper's shared-object id no longer resolves to a live
 * native object — so it is matched as a fallback in case the root cause line
 * is dropped from the chain.
 */
function isReleasedObjectError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    /already released/i.test(message) ||
    (/cannot be cast/i.test(message) && message.includes("java.lang.Integer"))
  );
}

export class ExpoSQLiteAdapter implements SQLiteDatabaseDriverAsync {
  private static adapterByDbName = new Map<string, ExpoSQLiteAdapter>();
  private db: SQLiteDatabase | null = null;
  private initializing: Promise<SQLiteDatabase> | null = null;
  private dbName: string;
  /**
   * Sub-adapters created by `withDB` operate on a connection they do not own
   * (e.g. inside a `transaction` callback) and must never reopen it: a retry
   * on a fresh connection would run outside the transaction. Recovery for
   * transactions happens in the owning adapter's `transaction`, which reruns
   * the whole callback on the reopened connection.
   */
  private ownsConnection = true;
  /**
   * Serializes transactions at the connection level. The adapter is shared
   * across providers/contexts (see `getInstance`), each with its own storage
   * client and transaction queue, and `withTransactionAsync` is not exclusive:
   * without serialization here, a second BEGIN on the same connection fails
   * with "cannot start a transaction within a transaction" and its ROLLBACK
   * aborts the other caller's active transaction.
   */
  private txQueue: Promise<unknown> = Promise.resolve();

  static withDB(db: SQLiteDatabase): ExpoSQLiteAdapter {
    const adapter = new ExpoSQLiteAdapter();
    adapter.db = db;
    adapter.ownsConnection = false;
    return adapter;
  }

  /**
   * Returns a shared adapter instance for the given database name.
   * Multiple providers in the same runtime reuse the same adapter.
   */
  static getInstance(dbName: string = "jazz-storage"): ExpoSQLiteAdapter {
    const existing = ExpoSQLiteAdapter.adapterByDbName.get(dbName);
    if (existing) {
      return existing;
    }

    const adapter = new ExpoSQLiteAdapter(dbName);
    ExpoSQLiteAdapter.adapterByDbName.set(dbName, adapter);
    return adapter;
  }

  public constructor(dbName: string = "jazz-storage") {
    this.dbName = dbName;
  }

  public async initialize(): Promise<void> {
    if (this.db) {
      return;
    }

    if (!this.initializing) {
      this.initializing = (async () => {
        const db = await openDatabaseAsync(this.dbName, {
          useNewConnection: true,
        });
        await db.execAsync("PRAGMA journal_mode = WAL");
        return db;
      })();
    }

    try {
      this.db = await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  private async acquireDb(): Promise<SQLiteDatabase> {
    if (this.db) {
      return this.db;
    }

    // `db` is only null mid-reopen (see `reopenAfterRelease`); join the
    // in-flight open instead of failing.
    if (this.initializing) {
      await this.initialize();
      if (this.db) {
        return this.db;
      }
    }

    throw new Error("Database not initialized");
  }

  /**
   * Replaces a connection whose native object was released. Guarded so that a
   * burst of failing operations produces exactly one reopen: only the first
   * caller still holding the failed handle tears it down (later callers see
   * `db !== failed` and just join `initialize`, which no-ops once `db` is
   * live again). If the reopen itself fails, the dead handle is restored so
   * the next operation triggers another reopen attempt instead of leaving the
   * adapter permanently uninitialized.
   */
  private async reopenAfterRelease(failed: SQLiteDatabase): Promise<void> {
    if (this.db === failed) {
      this.db = null;
    }

    try {
      await this.initialize();
    } catch (error) {
      if (this.db === null) {
        this.db = failed;
      }
      throw error;
    }
  }

  /**
   * Runs an operation against the current connection; when it fails with a
   * released-shared-object error, reopens the database and retries exactly
   * once. A genuinely failing operation (or a second released-object failure)
   * propagates.
   */
  private async withReopenRetry<T>(
    op: (db: SQLiteDatabase) => Promise<T>,
  ): Promise<T> {
    const db = await this.acquireDb();

    try {
      return await op(db);
    } catch (error) {
      if (!this.ownsConnection || !isReleasedObjectError(error)) {
        throw error;
      }

      await this.reopenAfterRelease(db);
      return await op(await this.acquireDb());
    }
  }

  public async query<T>(sql: string, params?: unknown[]): Promise<T[]> {
    const result = await this.withReopenRetry((db) =>
      db.getAllAsync(sql, params?.map((p) => p as SQLiteBindValue) ?? []),
    );

    return result as T[];
  }

  public async get<T>(sql: string, params?: unknown[]): Promise<T | undefined> {
    const result = await this.withReopenRetry((db) =>
      db.getFirstAsync(sql, params?.map((p) => p as SQLiteBindValue) ?? []),
    );

    return (result as T) ?? undefined;
  }

  public async run(sql: string, params?: unknown[]) {
    await this.withReopenRetry((db) =>
      db.runAsync(sql, params?.map((p) => p as SQLiteBindValue) ?? []),
    );
  }

  public transaction(callback: (tx: ExpoSQLiteAdapter) => unknown) {
    const run = () =>
      this.withReopenRetry((db) =>
        db.withTransactionAsync(async () => {
          await callback(ExpoSQLiteAdapter.withDB(db));
        }),
      );

    const next = this.txQueue.then(run, run);
    this.txQueue = next;
    return next;
  }

  /**
   * Deletes and re-initialises the database.
   * Dropping every table would not account for internal data, such as PRAGMAs, so deletion is required to completely clear the database.
   */
  public async clearLocalData(): Promise<void> {
    if (!this.db) {
      throw new Error("Database not initialized");
    }

    // We must close the database before attempting to delete it.
    // However, this may fail if the database was already closed; if so, we can still proceed to deletion.
    try {
      await this.db.closeAsync();
    } catch (e) {
      console.error(e);
    }

    await deleteDatabaseAsync(this.dbName);
    this.db = null;
    await this.initialize();
  }

  public async closeDb(): Promise<void> {
    // Keeping the database open and reusing the same connection over multiple ctx instances.
  }
}
