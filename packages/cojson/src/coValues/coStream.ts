import { CoID, RawCoValue } from "../coValue.js";
import { AvailableCoValueCore } from "../coValueCore/coValueCore.js";
import { AgentID, SessionID, TransactionID } from "../ids.js";
import { JsonObject, JsonValue } from "../jsonValue.js";
import { accountOrAgentIDfromSessionID } from "../typeUtils/accountOrAgentIDfromSessionID.js";
import { isAccountID } from "../typeUtils/isAccountID.js";
import { isCoValue } from "../typeUtils/isCoValue.js";
import { RawAccountID } from "./account.js";
import { RawGroup } from "./group.js";
import { RawCoID } from "../ids.js";
import { CoValueFrontier } from "../knownState.js";

export type CoStreamItem<Item extends JsonValue> = {
  value: Item;
  tx: TransactionID;
  madeAt: number;
};

/**
 * The rich per-session delta the native (Rust-resident) coStream materializer
 * emits (`crates/cojson-core/src/core/co_stream.rs`'s `CoStreamView::delta`).
 * Each `sessions[sid]` is the FULL ordered `CoStreamItem[]` for a changed
 * session — a straight adopt-and-replace, never an incremental patch. `reset`
 * signals the consumer to clear and rebuild from the full delta.
 */
export type NativeStreamDelta = {
  version: number;
  reset: boolean;
  sessions: Record<string, CoStreamItem<JsonValue>[]>;
};

/**
 * Implemented by every coStream-shaped content class (plain `RawCoStreamView`
 * and `RawBinaryCoStreamView`) so `CoValueCore` can drive native materialization
 * uniformly. `consumeNativeStreamDelta` returns the native view's new monotonic
 * version (the core stores it as the next `sinceVersion`).
 */
export interface NativeStreamConsumer {
  consumeNativeStreamDelta(delta: NativeStreamDelta): number;
  rebuildFromCore(): void;
}

export class RawCoStreamView<
  Item extends JsonValue = JsonValue,
  Meta extends JsonObject | null = JsonObject | null,
> implements RawCoValue
{
  id: CoID<this>;
  type = "costream" as const;
  core: AvailableCoValueCore;

  /** The internal state of RawCoStream */
  items: {
    [key: SessionID]: CoStreamItem<Item>[];
  };
  knownTransactions: Record<RawCoID, number>;
  totalValidTransactions: number = 0;
  version: number = 0;

  /** @internal */
  atFrontierFilter?: CoValueFrontier = undefined;

  /**
   * True when this coStream's `items` are fed by the native (Rust-resident)
   * materializer via {@link consumeNativeStreamDelta} instead of the TS
   * {@link processNewTransactions} walk over `getValidTransactions`. Set once at
   * construction from {@link CoValueCore.isNativeCoStream}. A time-travel
   * (`atFrontier`) view keeps the TS path — the native delta carries the full
   * un-filtered per-session lists, and the TS walk already applies the frontier
   * filter at build time.
   */
  readonly nativeMaterialization: boolean = false;

  /**
   * Refcount of `sessionID:txIndex` -> number of items currently in `items` that
   * come from that transaction. Drives {@link totalValidTransactions} (its
   * `size` = distinct contributing valid transactions) under the native path,
   * where the rich delta replaces a session's whole item-list at once and a
   * single transaction may contribute several items. Unused on the TS path.
   */
  #nativeTxRefcount = new Map<string, number>();
  /** Whether the native view has been materialized into this content at least
   * once — the first materialization does NOT bump {@link version} (it is the
   * initial build); later full rebuilds (`reset` deltas) do. */
  #nativeMaterializedOnce = false;

  private resetInternalState() {
    this.items = {};
    this.knownTransactions = { [this.core.id]: 0 };
    this.totalValidTransactions = 0;
    this.#nativeTxRefcount.clear();
  }

  constructor(
    core: AvailableCoValueCore,
    options?: {
      atFrontierFilter?: CoValueFrontier;
    },
  ) {
    this.id = core.id as CoID<this>;
    this.core = core;
    this.items = {};
    this.knownTransactions = { [core.id]: 0 };
    this.atFrontierFilter = options?.atFrontierFilter;

    this.nativeMaterialization =
      !this.atFrontierFilter && this.core.isNativeCoStream();

    if (this.nativeMaterialization) {
      this.core.materializeNativeCoStreamContent(this);
    } else {
      this.processNewTransactions();
    }
  }

  /**
   * Rebuild `items` from a native rich delta (`{version, reset, sessions}`, each
   * `sessions[sid]` a full ordered `CoStreamItem[]`). On `reset` the store is
   * cleared and rebuilt; otherwise each changed session's list is replaced
   * wholesale. The resulting `CoStreamItem` shape is identical to the TS path's,
   * so every reader is unchanged. Returns the native view's new version.
   */
  consumeNativeStreamDelta(delta: NativeStreamDelta): number {
    if (delta.reset) {
      if (this.#nativeMaterializedOnce) {
        this.version += 1;
      }
      this.items = {};
      this.#nativeTxRefcount.clear();
    }

    const items = this.items as Record<string, CoStreamItem<Item>[]>;
    for (const sid in delta.sessions) {
      const list = delta.sessions[sid]! as CoStreamItem<Item>[];
      const previous = items[sid];
      if (previous) {
        for (const it of previous) this.#decNativeTxRef(it.tx);
      }
      items[sid] = list;
      for (const it of list) this.#incNativeTxRef(it.tx);
    }

    this.totalValidTransactions = this.#nativeTxRefcount.size;
    this.#nativeMaterializedOnce = true;
    return delta.version;
  }

  #incNativeTxRef(txID: TransactionID) {
    const k = `${txID.sessionID}:${txID.txIndex}`;
    this.#nativeTxRefcount.set(k, (this.#nativeTxRefcount.get(k) ?? 0) + 1);
  }

  #decNativeTxRef(txID: TransactionID) {
    const k = `${txID.sessionID}:${txID.txIndex}`;
    const n = (this.#nativeTxRefcount.get(k) ?? 0) - 1;
    if (n <= 0) this.#nativeTxRefcount.delete(k);
    else this.#nativeTxRefcount.set(k, n);
  }

  rebuildFromCore() {
    if (this.nativeMaterialization) {
      // Full re-pull from the native view. `version` is bumped by
      // `consumeNativeStreamDelta` on the `reset` this triggers.
      this.resetInternalState();
      this.#nativeMaterializedOnce = false;
      this.version += 1;
      this.core.materializeNativeCoStreamContent(this);
      return;
    }

    this.version++;

    this.resetInternalState();
    this.processNewTransactions();
  }

  get headerMeta(): Meta {
    return this.core.verified.header.meta as Meta;
  }

  get group(): RawGroup {
    return this.core.getGroup();
  }

  /** Not yet implemented */
  atTime(_time: number): this {
    throw new Error("Not yet implemented");
  }

  atFrontier(frontier: CoValueFrontier): this {
    return new RawCoStreamView(this.core, {
      atFrontierFilter: frontier,
    }) as this;
  }

  isTimeTravelEntity() {
    return Boolean(this.atFrontierFilter);
  }

  /** @internal */
  protected compareStreamItems(
    a: CoStreamItem<Item>,
    b: CoStreamItem<Item>,
  ): number {
    return (
      a.madeAt - b.madeAt ||
      (a.tx.sessionID === b.tx.sessionID
        ? 0
        : a.tx.sessionID < b.tx.sessionID
          ? -1
          : 1) ||
      a.tx.txIndex - b.tx.txIndex
    );
  }

  /** @internal */
  processNewTransactions() {
    // Under the native path the core drives materialization through
    // `consumeNativeStreamDelta`; the TS walk is a no-op here (callers like
    // `push` still invoke it after `makeTransaction`, but the core's own
    // `processNewTransactions` already pushed the native delta).
    if (this.nativeMaterialization) {
      return;
    }

    const changeEntries = new Set<CoStreamItem<Item>[]>();

    const newValidTransactions = this.core.getValidTransactions({
      ignorePrivateTransactions: false,
      knownTransactions: this.knownTransactions,
    });

    if (newValidTransactions.length === 0) {
      return;
    }

    for (const { txID, madeAt, changes } of newValidTransactions) {
      if (
        this.atFrontierFilter &&
        txID.txIndex >= (this.atFrontierFilter[txID.sessionID] ?? -1)
      ) {
        continue;
      }

      for (const changeUntyped of changes) {
        const change = changeUntyped as Item;
        let entries = this.items[txID.sessionID];
        if (!entries) {
          entries = [];
          this.items[txID.sessionID] = entries;
        }
        entries.push({ value: change, madeAt, tx: txID });
        changeEntries.add(entries);
      }
    }

    for (const entries of changeEntries) {
      entries.sort(this.compareStreamItems);
    }

    this.totalValidTransactions += newValidTransactions.length;
  }

  getSingleStream(): Item[] | undefined {
    const streams = Object.values(this.items);
    const firstStream = streams[0];

    if (!firstStream) {
      return undefined;
    }

    if (streams.length > 1) {
      throw new Error(
        "CoStream.getSingleStream() can only be called when there is exactly one stream",
      );
    }

    return firstStream.map((item) => item.value);
  }

  sessions(): SessionID[] {
    return Object.keys(this.items) as SessionID[];
  }

  accounts(): Set<RawAccountID> {
    return new Set(
      this.sessions().map(accountOrAgentIDfromSessionID).filter(isAccountID),
    );
  }

  nthItemIn(
    sessionID: SessionID,
    n: number,
  ):
    | {
        by: RawAccountID | AgentID;
        tx: TransactionID;
        at: Date;
        value: Item;
      }
    | undefined {
    const items = this.items[sessionID];
    if (!items) return;

    const item = items[n];
    if (!item) return;

    return {
      by: accountOrAgentIDfromSessionID(sessionID),
      tx: item.tx,
      at: new Date(item.madeAt),
      value: item.value,
    };
  }

  lastItemIn(sessionID: SessionID):
    | {
        by: RawAccountID | AgentID;
        tx: TransactionID;
        at: Date;
        value: Item;
      }
    | undefined {
    const items = this.items[sessionID];
    if (!items) return;
    return this.nthItemIn(sessionID, items.length - 1);
  }

  *itemsIn(sessionID: SessionID) {
    const items = this.items[sessionID];
    if (!items) return;
    for (const item of items) {
      yield {
        by: accountOrAgentIDfromSessionID(sessionID),
        tx: item.tx,
        at: new Date(item.madeAt),
        value: item.value as Item,
      };
    }
  }

  lastItemBy(account: RawAccountID | AgentID):
    | {
        by: RawAccountID | AgentID;
        tx: TransactionID;
        at: Date;
        value: Item;
      }
    | undefined {
    let latestItem:
      | {
          by: RawAccountID | AgentID;
          tx: TransactionID;
          at: Date;
          value: Item;
        }
      | undefined;

    for (const sessionID of Object.keys(this.items)) {
      if (sessionID.startsWith(account)) {
        const item = this.lastItemIn(sessionID as SessionID);
        if (!item) continue;
        if (!latestItem || item.at > latestItem.at) {
          latestItem = {
            by: item.by,
            tx: item.tx,
            at: item.at,
            value: item.value,
          };
        }
      }
    }

    return latestItem;
  }

  *itemsBy(account: RawAccountID | AgentID) {
    // TODO: this can be made more lazy without a huge collect and sort
    const items = Object.keys(this.items).flatMap((sessionID) =>
      sessionID.startsWith(account)
        ? [...this.itemsIn(sessionID as SessionID)].map((item) => ({
            in: sessionID as SessionID,
            ...item,
          }))
        : [],
    );

    items.sort((a, b) => a.at.getTime() - b.at.getTime());

    for (const item of items) {
      yield item;
    }
  }

  toJSON(): {
    [key: SessionID]: Item[];
  } {
    return Object.fromEntries(
      Object.entries(this.items).map(([sessionID, items]) => [
        sessionID,
        items.map((item) => item.value),
      ]),
    );
  }

  subscribe(listener: (coStream: this) => void): () => void {
    return this.core.subscribe((core) => {
      listener(core.getCurrentContent() as this);
    });
  }
}

export class RawCoStream<
    Item extends JsonValue = JsonValue,
    Meta extends JsonObject | null = JsonObject | null,
  >
  extends RawCoStreamView<Item, Meta>
  implements RawCoValue
{
  override atFrontier(frontier: CoValueFrontier): this {
    return new RawCoStream(this.core, {
      atFrontierFilter: frontier,
    }) as this;
  }

  push(item: Item, privacy: "private" | "trusting" = "private"): void {
    if (this.isTimeTravelEntity()) {
      throw new Error("Cannot mutate a time travel entity");
    }

    this.core.makeTransaction([isCoValue(item) ? item.id : item], privacy);
    this.processNewTransactions();
  }
}
