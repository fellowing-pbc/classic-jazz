//! Leaf helpers shared by the materialized content views (`co_map`,
//! `co_stream`, `co_list`). Each of these was byte-identical across those
//! modules; they are consolidated here so there is a single definition. Pure,
//! stateless functions with no behavior change.

use std::collections::HashSet;

use serde_json::Value as JsonValue;

use crate::core::group_engine::engine::Verdict;
use crate::core::group_engine::tx_view::GroupTxView;
use crate::core::session_map::SessionMapImpl;

/// Escape a string as a JSON string literal into `out`, delegating to the JSON
/// wrapper itself (cheap: a single-field enum variant, not a tree). Used by
/// [`MapOp::write_json`] for `sessionID`/`key` so arbitrary (user-provided) map
/// keys are escaped exactly as `serde_json::json!` would.
pub(crate) fn write_json_escaped_str(s: &str, out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(out, "{}", JsonValue::String(s.to_string()));
}

/// `(session_id, tx_count)` in session-insertion order — the freshness key.
pub(crate) fn session_counts_of(sm: &SessionMapImpl) -> Vec<(String, u32)> {
    sm.get_session_ids()
        .into_iter()
        .map(|sid| {
            let count = sm.get_transaction_count(&sid).unwrap_or(0);
            (sid, count)
        })
        .collect()
}

/// The `meta.fww` key of a tx, if any (`coValueCore.ts:1515`).
pub(crate) fn fww_key(tx: &GroupTxView) -> Option<&str> {
    tx.meta.as_ref()?.get("fww")?.as_str()
}

/// The `txID` of a transaction: its SOURCE identity when merged
/// (`sourceTxID ?? currentTxID`, `coValueCore.ts:157`), else its stored
/// `(session_id, tx_index)`.
pub(crate) fn tx_id_of(tx: &GroupTxView) -> (String, u32) {
    (
        tx.source_session_id
            .clone()
            .unwrap_or_else(|| tx.session_id.clone()),
        tx.source_tx_index.unwrap_or(tx.tx_index),
    )
}

/// Decrypt a PRIVATE tx's changes into a parsed op array, reusing the session
/// map's decrypt primitive (no crypto duplicated here). Returns `None` when the
/// tx does not decrypt to a usable op array — a wrong/garbage key (TS's crypto
/// likewise yields nothing) or a missing session — so the caller SKIPS it,
/// exactly as TS drops an undecryptable tx from its views.
pub(crate) fn decrypt_private_changes(
    sm: &SessionMapImpl,
    tx: &GroupTxView,
    key_secret: &str,
) -> Option<Vec<JsonValue>> {
    match sm.decrypt_transaction(&tx.session_id, tx.tx_index, key_secret) {
        Ok(Some(json)) => serde_json::from_str::<Vec<JsonValue>>(&json).ok(),
        _ => None,
    }
}

/// The valid `(session_id, tx_index)` set of a verdict list.
pub(crate) fn valid_set(verdicts: &[Verdict]) -> HashSet<(String, u32)> {
    verdicts
        .iter()
        .filter(|v| v.valid)
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect()
}
