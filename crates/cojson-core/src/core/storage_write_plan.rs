//! Native-only port of cojson storage's per-session *write decision*.
//!
//! This ports the pure decision logic that today lives inside
//! `storeSingle` + `putNewTxs`, which are **byte-identical** between
//! `packages/cojson/src/storage/storageSync.ts` and `.../storageAsync.ts`.
//! Given the CURRENT stored row-state for one session (`lastIdx`,
//! `bytesSinceLastSignature`) plus the incoming content message's `after` and
//! its per-transaction sizes, it decides:
//!
//!   * whether the message assumes a state the store does not have
//!     (`invalid_gap` — the `storeSingle` guard `lastIdx < after` that triggers
//!     a correction round-trip);
//!   * how many of the incoming transactions are actually new after dedup
//!     against `after` (`actually_new_count`, from `newTransactions.slice(...)`);
//!   * whether this store is a no-op (nothing new — `putNewTxs` early-returns
//!     without touching the DB);
//!   * the new `lastIdx` to persist (`new_last_idx`);
//!   * whether an intermediate `signatureAfter` checkpoint must be written and
//!     at which index (`should_write_signature` / `signature_idx`, from
//!     `exceedsRecommendedSize`);
//!   * the new rolling `bytesSinceLastSignature` to persist.
//!
//! ## TOCTOU-safe by construction
//!
//! This is a **pure** function: the caller reads the row inside its own DB
//! transaction and passes the values in; it returns the values the caller
//! should write. It never reads or writes the DB itself. That is the exact
//! shape the storage scoping pass recommended — the decision does not own the
//! read, so it cannot introduce a read/write skew that the interleaved TS today
//! is careful to avoid.
//!
//! ## Zero production wiring
//!
//! Like every other native port that precedes it in this migration
//! (`priority.rs`, `known_state.rs`, `peer_known_state.rs`,
//! `group_key_state.rs`, `storage_reconciliation.rs`), this is a native-only
//! library primitive with **no** NodeCore/napi/wasm/rn exposure and **nothing**
//! in the TypeScript storage or sync path importing it. It sits ready for a
//! FUTURE, separately authorized wiring phase. The storage write path is the
//! single most data-loss-sensitive path in the system (a wrong decision here is
//! unrecoverable — there is no peer to resync a local-only store from), so the
//! bar for flipping wiring on is deliberately higher than for other ports.
//!
//! ## Relationship to `session_log.rs`'s checkpoint primitives
//!
//! `session_log.rs` exposes `add_to_size_tracking` / `cumulative_tx_size` /
//! `record_inbetween_signature` for the VALIDATION path. Their underlying
//! *rule* is identical to storage's (`cumulative + size > MAX` ⇒ write a
//! checkpoint and reset the running total to 0; otherwise accumulate — verified
//! by hand against `session_map.rs`). They are **not** reused literally here
//! because their ownership model differs: those primitives *mutate* an owned
//! in-memory `signature_after: HashMap` and a running `tx_size_since_last…`
//! field, whereas storage's decision is pure — the running total arrives as a
//! DB-row value and the resulting total is handed back to be persisted, and the
//! signatures live in a separate DB table, not an owned map. Reproducing the
//! rule as a small pure function (below) keeps this port TOCTOU-safe and
//! byte-faithful to `putNewTxs`, which is what the fixtures pin.
//!
//! Every field is validated against fixtures exported from the REAL current
//! TypeScript `store()` behavior (see
//! `packages/cojson/src/tests/storageWritePlanFixtures.export.test.ts` and the
//! `data/storage_write_plan` directory): the exporter drives a real SQLite
//! storage client's `store()` and reads the resulting rows back out, so the
//! oracle is observed behavior, never a re-derivation of the logic under test.

use serde::{Deserialize, Serialize};

/// TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE from `packages/cojson/src/config.ts`
/// (`100 * 1024`). The value is configurable in TS tests, so the decision takes
/// it as a parameter; this constant documents the production default and mirrors
/// `session_map.rs`'s `max_tx_size`.
pub const DEFAULT_MAX_RECOMMENDED_TX_SIZE: i64 = 100 * 1024;

/// Pure port of TS `exceedsRecommendedSize(baseSize, transactionSize)` for the
/// storage path, where `transactionSize` is always defined (`putNewTxs` always
/// passes a concrete number). Mirrors `base_size + transaction_size > max`.
#[inline]
pub fn exceeds_recommended_size(
    base_size: i64,
    transaction_size: i64,
    max_recommended_tx_size: i64,
) -> bool {
    base_size + transaction_size > max_recommended_tx_size
}

/// The decision produced by [`plan_session_write`] for a single session of one
/// incoming content message. Mirrors exactly what `storeSingle`/`putNewTxs`
/// would do, so a caller can execute the *same* `addSessionUpdate` /
/// `addSignatureAfter` / `addTransaction` writes the TS does today, parameterized
/// by these values instead of TS's own inline computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionWritePlan {
    /// `storeSingle`'s `lastIdx < after` guard: the message assumes transactions
    /// the store does not have. When `true`, `putNewTxs` does NOT run, NO DB
    /// write happens for this session, and the caller must trigger a correction.
    /// All other fields are inert in this case (`new_last_idx == last_idx`,
    /// bytes unchanged, no writes).
    pub invalid_gap: bool,
    /// `putNewTxs`'s early return: after dedup against `after` there are no
    /// actually-new transactions, so NO DB write happens and `lastIdx` is
    /// returned unchanged. Mutually exclusive with `invalid_gap`.
    pub no_op: bool,
    /// `lastIdx - after`: the number of leading incoming transactions already
    /// known to the store (the `.slice()` offset). Only meaningful when
    /// `!invalid_gap`; always `>= 0` there.
    pub actually_new_offset: i64,
    /// Count of transactions actually written (`actuallyNewTransactions.length`).
    pub actually_new_count: i64,
    /// The transaction-row index the first new transaction is written at
    /// (`nextIdx = lastIdx`); subsequent ones at `next_idx + i`.
    pub next_idx: i64,
    /// The `lastIdx` to persist in the session row (`lastIdx + actually_new_count`
    /// when writing; unchanged `lastIdx` for a no-op / gap).
    pub new_last_idx: i64,
    /// Whether an intermediate `signatureAfter` checkpoint must be written.
    pub should_write_signature: bool,
    /// The index the checkpoint is written after (`new_last_idx - 1`) when
    /// `should_write_signature`, else `None`.
    pub signature_idx: Option<i64>,
    /// The rolling `bytesSinceLastSignature` to persist in the session row
    /// (`0` right after a checkpoint, else the accumulated total). For a no-op /
    /// gap this equals the incoming value (nothing is written).
    pub new_bytes_since_last_signature: i64,
}

/// Pure port of `storeSingle`'s gap guard + `putNewTxs`'s full decision.
///
/// * `last_idx` — `sessionRow?.lastIdx || 0`.
/// * `after` — `msg.new[sessionID]?.after || 0`.
/// * `bytes_since_last_signature` — `sessionRow?.bytesSinceLastSignature || 0`.
/// * `new_tx_sizes` — `getTransactionSize` of EVERY transaction in
///   `msg.new[sessionID].newTransactions`, in order (the decision slices them
///   internally by `after`, exactly as `putNewTxs` slices `newTransactions`).
/// * `max_recommended_tx_size` — `TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE`.
pub fn plan_session_write(
    last_idx: i64,
    after: i64,
    bytes_since_last_signature: i64,
    new_tx_sizes: &[i64],
    max_recommended_tx_size: i64,
) -> SessionWritePlan {
    // storeSingle: `if ((sessionRow?.lastIdx || 0) < (msg.new[sessionID]?.after || 0))`
    // → invalidAssumptions = true; putNewTxs is NOT called.
    if last_idx < after {
        return SessionWritePlan {
            invalid_gap: true,
            no_op: false,
            actually_new_offset: last_idx - after, // negative; inert
            actually_new_count: 0,
            next_idx: last_idx,
            new_last_idx: last_idx,
            should_write_signature: false,
            signature_idx: None,
            new_bytes_since_last_signature: bytes_since_last_signature,
        };
    }

    // putNewTxs:
    //   actuallyNewOffset = lastIdx - after   (>= 0 here)
    //   actuallyNewTransactions = newTransactions.slice(actuallyNewOffset)
    let actually_new_offset = last_idx - after;
    let len = new_tx_sizes.len() as i64;
    // JS `.slice(offset)` with offset >= length yields [] → count 0.
    let actually_new_count = if actually_new_offset >= len {
        0
    } else {
        len - actually_new_offset
    };

    // `if (actuallyNewTransactions.length === 0) return lastIdx;` — no DB writes.
    if actually_new_count == 0 {
        return SessionWritePlan {
            invalid_gap: false,
            no_op: true,
            actually_new_offset,
            actually_new_count: 0,
            next_idx: last_idx,
            new_last_idx: last_idx,
            should_write_signature: false,
            signature_idx: None,
            new_bytes_since_last_signature: bytes_since_last_signature,
        };
    }

    // newTransactionsSize = getNewTransactionsSize(actuallyNewTransactions)
    // = sum over the SLICED transactions (indices [offset..]).
    let new_transactions_size: i64 = new_tx_sizes[actually_new_offset as usize..].iter().sum();

    // newLastIdx = (sessionRow?.lastIdx || 0) + actuallyNewTransactions.length
    let new_last_idx = last_idx + actually_new_count;

    // if (exceedsRecommendedSize(bytesSinceLastSignature, newTransactionsSize)) {
    //   shouldWriteSignature = true; bytesSinceLastSignature = 0;
    // } else { bytesSinceLastSignature += newTransactionsSize; }
    let (should_write_signature, new_bytes_since_last_signature) = if exceeds_recommended_size(
        bytes_since_last_signature,
        new_transactions_size,
        max_recommended_tx_size,
    ) {
        (true, 0)
    } else {
        (false, bytes_since_last_signature + new_transactions_size)
    };

    // if (shouldWriteSignature) tx.addSignatureAfter({ idx: newLastIdx - 1, ... })
    let signature_idx = if should_write_signature {
        Some(new_last_idx - 1)
    } else {
        None
    };

    SessionWritePlan {
        invalid_gap: false,
        no_op: false,
        actually_new_offset,
        actually_new_count,
        next_idx: last_idx, // nextIdx = sessionRow?.lastIdx || 0
        new_last_idx,
        should_write_signature,
        signature_idx,
        new_bytes_since_last_signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const MAX: i64 = DEFAULT_MAX_RECOMMENDED_TX_SIZE;

    // ---------------- unit tests: the exact edges ----------------

    #[test]
    fn first_store_sub_threshold_accumulates_no_signature() {
        let p = plan_session_write(0, 0, 0, &[10, 20, 30], MAX);
        assert!(!p.invalid_gap && !p.no_op);
        assert_eq!(p.actually_new_offset, 0);
        assert_eq!(p.actually_new_count, 3);
        assert_eq!(p.next_idx, 0);
        assert_eq!(p.new_last_idx, 3);
        assert!(!p.should_write_signature);
        assert_eq!(p.signature_idx, None);
        assert_eq!(p.new_bytes_since_last_signature, 60);
    }

    #[test]
    fn dedup_partial_slice_writes_only_the_tail() {
        // stored lastIdx=2 (60 bytes already), message after=0 with 5 txs →
        // offset 2, writes txs[2..5] (3 txs).
        let p = plan_session_write(2, 0, 60, &[10, 20, 30, 40, 50], MAX);
        assert_eq!(p.actually_new_offset, 2);
        assert_eq!(p.actually_new_count, 3);
        assert_eq!(p.next_idx, 2);
        assert_eq!(p.new_last_idx, 5);
        // sliced size = 30+40+50 = 120; 60+120 = 180 (< MAX) → accumulate.
        assert_eq!(p.new_bytes_since_last_signature, 180);
        assert!(!p.should_write_signature);
    }

    #[test]
    fn full_dedup_is_a_no_op() {
        // Everything already known: lastIdx=3, after=0, 3 txs → offset 3, slice [].
        let p = plan_session_write(3, 0, 42, &[10, 20, 30], MAX);
        assert!(p.no_op);
        assert!(!p.invalid_gap);
        assert_eq!(p.actually_new_count, 0);
        assert_eq!(p.new_last_idx, 3);
        assert_eq!(p.new_bytes_since_last_signature, 42); // unchanged
        assert!(!p.should_write_signature);
    }

    #[test]
    fn offset_beyond_message_length_is_a_no_op() {
        // Store is AHEAD of the message: lastIdx=5, after=0, only 3 txs → offset 5
        // > len 3 → slice [] → no-op (mirrors JS slice past the end).
        let p = plan_session_write(5, 0, 7, &[1, 2, 3], MAX);
        assert!(p.no_op);
        assert_eq!(p.actually_new_count, 0);
        assert_eq!(p.new_last_idx, 5);
    }

    #[test]
    fn gap_beyond_stored_is_invalid() {
        // lastIdx=2, after=5 → 2 < 5 → invalid_gap, no writes.
        let p = plan_session_write(2, 5, 99, &[10], MAX);
        assert!(p.invalid_gap);
        assert!(!p.no_op);
        assert_eq!(p.new_last_idx, 2);
        assert_eq!(p.new_bytes_since_last_signature, 99);
        assert!(!p.should_write_signature);
    }

    #[test]
    fn exact_boundary_does_not_trigger_signature() {
        // base 0 + size 100 == MAX(100): `> MAX` is false → no signature, bytes=100.
        let p = plan_session_write(0, 0, 0, &[100], 100);
        assert!(!p.should_write_signature);
        assert_eq!(p.new_bytes_since_last_signature, 100);
    }

    #[test]
    fn one_over_boundary_triggers_signature_and_resets() {
        // stored lastIdx=1, base 100; append one 1-byte tx (after=1, offset 0):
        // 100 + 1 = 101 > MAX(100) → signature at newLastIdx-1, bytes reset to 0.
        let p = plan_session_write(1, 1, 100, &[1], 100);
        assert_eq!(p.actually_new_count, 1);
        assert_eq!(p.new_last_idx, 2);
        assert!(p.should_write_signature);
        assert_eq!(p.signature_idx, Some(1));
        assert_eq!(p.new_bytes_since_last_signature, 0);
    }

    #[test]
    fn signature_index_is_absolute_last_written_index() {
        // stored lastIdx=4, append 3 new txs crossing threshold → checkpoint at
        // index newLastIdx-1 = 6 (absolute), not a slice-relative index.
        let p = plan_session_write(4, 4, 200, &[50, 50, 50], 100);
        assert_eq!(p.actually_new_count, 3);
        assert_eq!(p.new_last_idx, 7);
        assert!(p.should_write_signature);
        assert_eq!(p.signature_idx, Some(6));
        assert_eq!(p.new_bytes_since_last_signature, 0);
    }

    #[test]
    fn zero_size_transactions_keep_running_total() {
        // Empty-changes txs contribute 0 bytes; base stays, no signature unless
        // base already exceeds.
        let p = plan_session_write(0, 0, 40, &[0, 0], 100);
        assert_eq!(p.actually_new_count, 2);
        assert_eq!(p.new_bytes_since_last_signature, 40);
        assert!(!p.should_write_signature);
    }

    // ---------------- fixture replay ----------------
    //
    // Fixtures are exported from the REAL current TypeScript by
    // storageWritePlanFixtures.export.test.ts, which drives a real SQLite
    // `store()` and reads the resulting rows back. Each step records the
    // stored row-state BEFORE the store (the decision inputs) and the OBSERVED
    // effect AFTER (the expected decision). This replay must reproduce every
    // field.

    fn read_fixtures(dir: &str) -> Vec<(String, String)> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap_or_else(|_| panic!("{dir} must exist (run the TS exporter)"))
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        assert!(!names.is_empty(), "expected at least one fixture in {dir}");
        names
            .into_iter()
            .map(|n| {
                let raw = fs::read_to_string(format!("{dir}/{n}"))
                    .unwrap_or_else(|_| panic!("cannot read {dir}/{n}"));
                (n, raw)
            })
            .collect()
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WritePlanFixture {
        #[allow(dead_code)]
        description: String,
        steps: Vec<WritePlanStep>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WritePlanStep {
        #[allow(dead_code)]
        label: String,
        last_idx: i64,
        after: i64,
        bytes_since_last_signature: i64,
        new_tx_sizes: Vec<i64>,
        max_recommended_tx_size: i64,
        expected: WritePlanExpected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WritePlanExpected {
        invalid_gap: bool,
        no_op: bool,
        actually_new_count: i64,
        new_last_idx: i64,
        should_write_signature: bool,
        signature_idx: Option<i64>,
        new_bytes_since_last_signature: i64,
    }

    #[test]
    fn replay_write_plan_fixtures() {
        for (name, raw) in read_fixtures("data/storage_write_plan") {
            let f: WritePlanFixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            for step in &f.steps {
                let p = plan_session_write(
                    step.last_idx,
                    step.after,
                    step.bytes_since_last_signature,
                    &step.new_tx_sizes,
                    step.max_recommended_tx_size,
                );
                let e = &step.expected;
                assert_eq!(
                    p.invalid_gap, e.invalid_gap,
                    "invalid_gap mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.no_op, e.no_op,
                    "no_op mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.actually_new_count, e.actually_new_count,
                    "actually_new_count mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.new_last_idx, e.new_last_idx,
                    "new_last_idx mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.should_write_signature, e.should_write_signature,
                    "should_write_signature mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.signature_idx, e.signature_idx,
                    "signature_idx mismatch in {name} [{}]",
                    step.label
                );
                assert_eq!(
                    p.new_bytes_since_last_signature, e.new_bytes_since_last_signature,
                    "new_bytes_since_last_signature mismatch in {name} [{}]",
                    step.label
                );
            }
        }
    }
}
