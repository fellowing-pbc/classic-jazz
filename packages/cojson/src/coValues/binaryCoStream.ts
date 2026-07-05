import { base64URLtoBytes, bytesToBase64url } from "../base64url.js";
import type { CoID, RawCoValue } from "../coValue.js";
import type { AvailableCoValueCore } from "../coValueCore/coValueCore.js";
import type { RawCoID, TransactionID } from "../ids.js";
import type { JsonObject, JsonValue } from "../jsonValue.js";
import type { RawGroup } from "./group.js";
import { CoValueFrontier } from "../knownState.js";
import type {
  CoStreamItem,
  NativeStreamConsumer,
  NativeStreamDelta,
} from "./coStream.js";

export type BinaryStreamInfo = {
  mimeType: string;
  fileName?: string;
  totalSizeBytes?: number;
};

export type BinaryStreamStart = {
  type: "start";
} & BinaryStreamInfo;

export type BinaryStreamChunk = {
  type: "chunk";
  chunk: `binary_U${string}`;
};

export type BinaryStreamEnd = {
  type: "end";
};

export type BinaryCoStreamMeta = JsonObject & { type: "binary" };

export type BinaryStreamItem =
  | BinaryStreamStart
  | BinaryStreamChunk
  | BinaryStreamEnd;

const binary_U_prefixLength = 8; // "binary_U".length;

export class RawBinaryCoStreamView<
  Meta extends BinaryCoStreamMeta = { type: "binary" },
> implements RawCoValue
{
  id: CoID<this>;
  type = "costream" as const;
  core: AvailableCoValueCore;
  knownTransactions: Record<RawCoID, number>;
  totalValidTransactions: number = 0;
  version: number = 0;
  private chunks: string[];
  private start: BinaryStreamStart | undefined;
  private ended: boolean;

  /** @internal */
  atFrontierFilter?: CoValueFrontier = undefined;

  /**
   * True when this binary stream's projection is fed by the native (Rust-
   * resident) coStream materializer (which validates + decrypts), then walked in
   * TS into {@link chunks}/{@link start}/{@link ended}. Set once at construction
   * from {@link CoValueCore.isNativeCoStream} (gated by the binary flag). A
   * time-travel (`atFrontier`) view keeps the TS path.
   */
  readonly nativeMaterialization: boolean = false;

  /** Per-session native item lists (`sessionID -> CoStreamItem[]`), kept so a
   * rich delta that replaces one session's list can re-derive the ordered
   * chunk/start/end projection. Unused on the TS path. */
  #nativeSessions: Record<string, CoStreamItem<JsonValue>[]> = {};
  #nativeTxRefcount = new Map<string, number>();
  #nativeMaterializedOnce = false;

  private resetInternalState() {
    this.chunks = [];
    this.start = undefined;
    this.ended = false;
    this.knownTransactions = { [this.core.id]: 0 };
    this.totalValidTransactions = 0;
    this.#nativeSessions = {};
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
    this.ended = false;
    this.chunks = [];
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
   * Adopt a native rich delta (`{version, reset, sessions}`) and re-derive the
   * binary projection. Each `sessions[sid]` is the full ordered item list for a
   * changed session; the native view already validated + decrypted them. Returns
   * the native view's new version. Implements {@link NativeStreamConsumer}.
   */
  consumeNativeStreamDelta(delta: NativeStreamDelta): number {
    if (delta.reset) {
      if (this.#nativeMaterializedOnce) {
        this.version += 1;
      }
      this.#nativeSessions = {};
      this.#nativeTxRefcount.clear();
    }

    for (const sid in delta.sessions) {
      const list = delta.sessions[sid]!;
      const previous = this.#nativeSessions[sid];
      if (previous) {
        for (const it of previous) this.#decNativeTxRef(it.tx);
      }
      this.#nativeSessions[sid] = list;
      for (const it of list) this.#incNativeTxRef(it.tx);
    }

    this.totalValidTransactions = this.#nativeTxRefcount.size;
    this.#rederiveBinaryProjection();
    this.#nativeMaterializedOnce = true;
    return delta.version;
  }

  /** Rebuild `chunks`/`start`/`ended` from {@link #nativeSessions}, merging all
   * sessions into one stream ordered like the TS `compareStreamItems`
   * (`madeAt`, then `sessionID`, then `txIndex`) and walking the items. Binary
   * streams are single-writer in practice, so this is normally a single session
   * in `txIndex` order. */
  #rederiveBinaryProjection() {
    this.chunks = [];
    this.start = undefined;
    this.ended = false;

    const items: CoStreamItem<JsonValue>[] = [];
    for (const sid in this.#nativeSessions) {
      for (const it of this.#nativeSessions[sid]!) items.push(it);
    }
    items.sort(
      (a, b) =>
        a.madeAt - b.madeAt ||
        (a.tx.sessionID === b.tx.sessionID
          ? 0
          : a.tx.sessionID < b.tx.sessionID
            ? -1
            : 1) ||
        a.tx.txIndex - b.tx.txIndex,
    );

    for (const it of items) {
      const change = it.value as BinaryStreamItem;
      if (change.type === "chunk") {
        this.chunks.push(change.chunk.slice(binary_U_prefixLength));
      } else if (change.type === "start") {
        this.start = change;
      } else if (change.type === "end") {
        this.ended = true;
        // Freeze at the first `end`, exactly like the TS
        // {@link processNewTransactions} path (`if (this.ended) return`): once a
        // binary stream has ended, any later `start`/`chunk`/`end` items (e.g. a
        // second start/chunk/end sequence pushed onto the same CoValue) are
        // ignored rather than accumulated. Without this break the native rebuild
        // walks EVERY item and appends every chunk, retaining stale chunks from
        // before the mutation (4 chunks where 2 are expected).
        break;
      }
    }
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
    return new RawBinaryCoStreamView(this.core, {
      atFrontierFilter: frontier,
    }) as this;
  }

  isTimeTravelEntity(): boolean {
    return Boolean(this.atFrontierFilter);
  }

  processNewTransactions() {
    // Under the native path the core drives materialization through
    // `consumeNativeStreamDelta`; the TS walk is a no-op here.
    if (this.nativeMaterialization) {
      return;
    }

    if (this.ended) return;

    const newValidTransactions = this.core.getValidTransactions({
      ignorePrivateTransactions: false,
      knownTransactions: this.knownTransactions,
    });

    if (newValidTransactions.length === 0) {
      return;
    }

    for (const { txID, changes } of newValidTransactions) {
      if (
        this.atFrontierFilter &&
        txID.txIndex >= (this.atFrontierFilter[txID.sessionID] ?? -1)
      ) {
        continue;
      }

      for (const changeUntyped of changes) {
        const change = changeUntyped as BinaryStreamItem;

        if (change.type === "chunk") {
          this.chunks.push(change.chunk.slice(binary_U_prefixLength));
        } else if (change.type === "start") {
          this.start = change;
        } else if (change.type === "end") {
          this.ended = true;
        }
      }
    }

    this.totalValidTransactions += newValidTransactions.length;
  }

  isBinaryStreamEnded() {
    return this.ended;
  }

  getBinaryStreamInfo(): BinaryStreamInfo | undefined {
    if (!this.start) return;

    const start = this.start;

    return {
      mimeType: start.mimeType,
      fileName: start.fileName,
      totalSizeBytes: start.totalSizeBytes,
    };
  }

  getBinaryChunks(allowUnfinished?: boolean):
    | (BinaryStreamInfo & {
        chunks: Uint8Array<ArrayBuffer>[];
        finished: boolean;
      })
    | undefined {
    if (!this.start) return;
    if (!this.ended && !allowUnfinished) return;

    const start = this.start;

    return {
      mimeType: start.mimeType,
      fileName: start.fileName,
      totalSizeBytes: start.totalSizeBytes,
      chunks: this.chunks.map(base64URLtoBytes),
      finished: this.ended,
    };
  }

  toJSON() {
    return {};
  }

  subscribe(listener: (coStream: this) => void): () => void {
    return this.core.subscribe((core) => {
      listener(core.getCurrentContent() as this);
    });
  }
}

export class RawBinaryCoStream<
    Meta extends BinaryCoStreamMeta = { type: "binary" },
  >
  extends RawBinaryCoStreamView<Meta>
  implements RawCoValue
{
  override atFrontier(frontier: CoValueFrontier): this {
    return new RawBinaryCoStream(this.core, {
      atFrontierFilter: frontier,
    }) as this;
  }

  /** @internal */
  push(
    item: BinaryStreamItem,
    privacy: "private" | "trusting" = "private",
    updateView: boolean = true,
  ): void {
    if (this.isTimeTravelEntity()) {
      throw new Error("Cannot mutate a time travel entity");
    }

    this.core.makeTransaction([item], privacy);
    if (updateView) {
      this.processNewTransactions();
    }
  }

  startBinaryStream(
    settings: BinaryStreamInfo,
    privacy: "private" | "trusting" = "private",
  ): void {
    this.push(
      {
        type: "start",
        ...settings,
      } satisfies BinaryStreamStart,
      privacy,
      false,
    );
  }

  pushBinaryStreamChunk(
    chunk: Uint8Array,
    privacy: "private" | "trusting" = "private",
  ): void {
    this.push(
      {
        type: "chunk",
        chunk: `binary_U${bytesToBase64url(chunk)}`,
      } satisfies BinaryStreamChunk,
      privacy,
      false,
    );
  }

  endBinaryStream(privacy: "private" | "trusting" = "private") {
    this.push(
      {
        type: "end",
      } satisfies BinaryStreamEnd,
      privacy,
      true,
    );
  }
}
