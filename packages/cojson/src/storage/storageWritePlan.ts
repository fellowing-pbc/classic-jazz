import { getTransactionSize } from "../coValueContentMessage.js";
import { TRANSACTION_CONFIG } from "../config.js";
import { isNativeStorageWritePlanEnabled } from "../coValueCore/coValueCore.js";
import type { NodeCoreImpl } from "../crypto/crypto.js";
import type { SessionID } from "../ids.js";
import type { NewContentMessage } from "../sync.js";
import type { StoredSessionRow } from "./types.js";

/**
 * The per-session write decision produced by the native Rust
 * `plan_session_write` (`crates/cojson-core/src/core/storage_write_plan.rs`),
 * mirroring exactly what `storeSingle` + `putNewTxs` compute inline in TS. The
 * caller performs the same DB reads/writes; only these decision values change.
 *
 * Field names match the native `SessionWritePlan` camelCase JSON output.
 */
export interface SessionWritePlan {
  /** `storeSingle`'s `lastIdx < after` guard: message assumes txs the store
   *  lacks. When true, `putNewTxs` does NOT run and a correction is triggered. */
  invalidGap: boolean;
  /** `putNewTxs`'s early return: nothing actually new after dedup — no DB write,
   *  `lastIdx` unchanged. Mutually exclusive with `invalidGap`. */
  noOp: boolean;
  /** `lastIdx - after`: the `.slice()` offset of already-known leading txs. */
  actuallyNewOffset: number;
  /** `actuallyNewTransactions.length`: count of txs actually written. */
  actuallyNewCount: number;
  /** `nextIdx = lastIdx`: row index the first new tx is written at. */
  nextIdx: number;
  /** The `lastIdx` to persist in the session row. */
  newLastIdx: number;
  /** Whether an intermediate `signatureAfter` checkpoint must be written. */
  shouldWriteSignature: boolean;
  /** `newLastIdx - 1` when `shouldWriteSignature`, else null. */
  signatureIdx: number | null;
  /** The rolling `bytesSinceLastSignature` to persist. */
  newBytesSinceLastSignature: number;
}

/**
 * Whether the native storage write-decision path should be used: the flag is on,
 * a NodeCore is available, and its backend advertises the capability (napi/wasm;
 * not RN). Narrows `nodeCore` to non-undefined for the caller.
 */
export function useNativeStorageWritePlan(
  nodeCore: NodeCoreImpl | undefined,
): nodeCore is NodeCoreImpl {
  return (
    isNativeStorageWritePlanEnabled() &&
    !!nodeCore &&
    nodeCore.supportsNativeStorageWritePlan() &&
    typeof nodeCore.planSessionWrite === "function"
  );
}

/**
 * Compute one session's write decision natively. Builds `newTxSizes` from ALL
 * incoming transactions (the native decision slices them internally by `after`,
 * exactly as `putNewTxs` slices `newTransactions`), then routes the scalar+array
 * inputs through the JSON FFI wrapper and parses the resulting `SessionWritePlan`.
 *
 * The caller must have verified {@link useNativeStorageWritePlan} first, so
 * `nodeCore.planSessionWrite` is guaranteed present.
 */
export function planSessionWriteNative(
  nodeCore: NodeCoreImpl,
  msg: NewContentMessage,
  sessionID: SessionID,
  sessionRow: StoredSessionRow | undefined,
): SessionWritePlan {
  const sessionEntry = msg.new[sessionID];
  const newTransactions = sessionEntry?.newTransactions || [];

  const input = {
    lastIdx: sessionRow?.lastIdx || 0,
    after: sessionEntry?.after || 0,
    bytesSinceLastSignature: sessionRow?.bytesSinceLastSignature || 0,
    newTxSizes: newTransactions.map((tx) => getTransactionSize(tx)),
    maxRecommendedTxSize: TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE,
  };

  const out = nodeCore.planSessionWrite!(JSON.stringify(input));
  return JSON.parse(out) as SessionWritePlan;
}
