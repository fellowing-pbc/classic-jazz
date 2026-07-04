//! Rust-resident coMap materialization (R0 prototype).
//!
//! Materializes a coMap's per-key op index over the VALID transaction set of a
//! covalue, reusing the group engine's verdicts (permission validation) and the
//! `tx_view` collection/ordering primitives. TRUSTING transactions contribute
//! their plaintext changes directly; PRIVATE transactions (R1) are decrypted
//! natively via [`SessionMapImpl::decrypt_transaction`] — the SAME crypto the
//! per-tx TS decrypt loop uses — resolving each tx's `keyUsed` against the
//! `NodeCore` key store that TS feeds as it unseals secrets. A private tx whose
//! key is not yet available is SKIPPED from the view (mirroring TS, where an
//! undecryptable tx does not contribute) and its `keyUsed` is recorded so the
//! view can lazily rebuild once the secret arrives. The first-writer-wins (fww)
//! overlay from
//! `coValueCore.ts` is ported here because it decides key winners and MUST be in
//! the prototype for the TS-vs-Rust benchmark comparison to be fair.
//!
//! ## Semantics mirrored from `packages/cojson/src/coValues/coMap.ts`
//!
//! - `ops[key]` — for every key, the list of ops (set/del) that touched it, in
//!   `compareTransactions` order (effective madeAt ascending; same-effective-
//!   session ties by tx index; cross-session ties stable). We reuse
//!   [`sort_for_validation`] (the exact `compareTransactions` port) and append
//!   in that order, so each key's [`TimeBasedEntry`] is already sorted.
//! - `latest[key]` — the last op in `ops[key]` (max under the ordering). Read via
//!   [`TimeBasedEntry::get_latest`].
//! - `getRaw(key)` at a time filter — `findLast(op.madeAt <= atTime)`. Read via
//!   [`TimeBasedEntry::get_at_time`] (the same primitive the group engine's
//!   `role_history` uses).
//! - `get`/`asObject`/`keys` — a `del` (or a missing key) reads as absent; any
//!   other op reads as its `value` (including JSON `null`), matching TS `get`'s
//!   `op === "del" ? undefined : value` and `keys()`'s `op === "del"` filter.
//!
//! ## fww overlay (`coValueCore.ts:1515-1537`, `parseMetaInformation`)
//!
//! A transaction carrying `meta.fww = <key>` competes with every other tx that
//! carries the same fww key; only the FIRST writer (minimum under
//! `compareTransactions`) stays valid, every later one is marked invalid and its
//! ops are excluded from views. TS scans transactions in load (session-insertion,
//! tx-index) order and keeps the min via `compareTransactions`; because
//! [`sort_for_validation`] is the same comparator and stable, the FIRST tx in
//! sorted order for a given fww key is exactly TS's winner (ties resolve to the
//! first-loaded tx on both sides). So: fww losers = every fww-keyed tx that is
//! not the first in sorted order for its key. The winner selection scans ALL
//! collected txs (regardless of permission verdict), exactly as TS's
//! `toParseMetaTransactions` does; a tx is INCLUDED in views iff it is
//! permission-valid AND not an fww loser.
//!
//! ## Freshness and the incremental append fast-path
//!
//! A [`CoMapView`] is cached per covalue keyed by per-session tx-counts — the
//! same freshness pattern the group engines use. Unlike permission verdicts
//! (which are always full-recompute because a late transaction can flip an
//! earlier verdict), content indexing is append-friendly, so we take an
//! incremental append fast-path when it is provably safe. It is taken only when
//! ALL of these hold (else we fall back to a full recompute, which is always
//! correct):
//!
//! 1. the new session counts are a pure superset of the cached ones (no session
//!    removed, no count decreased) — appends only;
//! 2. the cached view has NO fww keys AND none of the newly-appended txs carry
//!    an fww key — fww can retroactively invalidate an already-materialized
//!    winner, so any fww presence forces full recompute;
//! 3. the fresh verdicts for the OLD tx range are byte-identical to what was
//!    materialized — i.e. no earlier verdict flipped (porter note 17: appends
//!    CAN flip earlier permission verdicts). We re-derive verdicts every call
//!    (cheap — the engine cache short-circuits), so this is a set comparison.
//!
//! When all hold, only the new valid txs' changes are inserted into the existing
//! per-key entries (`TimeBasedEntry::add_change` keeps each key sorted even for
//! an out-of-order madeAt). This is the divergence from the engine's
//! always-full-recompute discipline, and the three guards above are why it is
//! safe for content.

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde_json::Value as JsonValue;

use crate::core::group_engine::engine::{
    validate_transactions as engine_validate_transactions, GroupEngineState, Verdict,
};
use crate::core::group_engine::tx_view::{
    collect_group_txs, sort_for_validation, GroupTxView, PendingTxIn, Privacy,
};
use crate::core::group_engine::types::TimeBasedEntry;
use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// The materialized value of a key at one op: a concrete value, or a deletion.
/// A `Set` holds any JSON value (including `null`, which reads as present); a
/// `Del` reads as absent — mirroring TS `get`'s `op === "del" ? undefined :
/// value`.
#[derive(Debug, Clone, PartialEq)]
pub enum MapVal {
    Set(JsonValue),
    Del,
}

/// A cached, materialized coMap view for one covalue.
pub struct CoMapView {
    /// `(session_id, tx_count)` snapshot — the cache-validity key (same pattern
    /// as `GroupEngineState::session_counts`).
    session_counts: Vec<(String, u32)>,
    /// Per-key ordered ops. `IndexMap` so key iteration is first-appearance
    /// order (snapshots are compared order-independently, so this is only for
    /// stable/deterministic output).
    ops: IndexMap<String, TimeBasedEntry<MapVal>>,
    /// The set of `(session_id, tx_index)` that were permission-valid at build
    /// time — used by the append fast-path to detect an earlier verdict flip.
    valid_txs: HashSet<(String, u32)>,
    /// True if any collected tx carried an `meta.fww` key. Disables the append
    /// fast-path (fww needs a global recompute).
    has_fww: bool,
    /// Monotonic version, bumped once per ingest batch (append or full
    /// recompute). The delta boundary's cursor.
    version: u64,
    /// `key -> version at which this key last changed`. Drives `map_delta`.
    key_versions: HashMap<String, u64>,
    /// The `NodeCore` keys-version this view was built against. Part of the
    /// freshness key alongside `session_counts`: when a secret is provided
    /// (bumping the node's keys-version) a previously-undecryptable PRIVATE tx
    /// may now join, so the view must lazily rebuild even if no new transaction
    /// arrived (mirrors TS content appearing after `getReadKey` succeeds).
    keys_version: u64,
    /// `KeyID`s of PRIVATE transactions whose secret was unavailable at build
    /// time (their txs were SKIPPED from the view, mirroring TS: an
    /// undecryptable tx simply does not contribute). Exposed via
    /// `NodeCore::missing_key_ids` so R3 can drive key acquisition; the current
    /// TS flow already knows the needed key from each tx's `keyUsed`.
    missing_key_ids: HashSet<String>,
}

impl CoMapView {
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The `KeyID`s this view still needs a secret for (sorted for a
    /// deterministic boundary payload).
    pub fn missing_key_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.missing_key_ids.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// Latest value for `key` (`None` = absent / deleted).
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self.ops.get(key).and_then(|e| e.get_latest()) {
            Some(MapVal::Set(v)) => Some(v),
            _ => None,
        }
    }

    /// Value for `key` at `at_time` (`None` = latest); `None` result = absent.
    pub fn get_at(&self, key: &str, at_time: Option<u64>) -> Option<&JsonValue> {
        match self.ops.get(key).and_then(|e| e.get_at_time(at_time)) {
            Some(MapVal::Set(v)) => Some(v),
            _ => None,
        }
    }

    /// Whole materialized map as a `{key: latestValue}` JSON object (deleted /
    /// absent keys omitted), matching `RawCoMap.asObject`.
    pub fn snapshot(&self) -> JsonValue {
        let mut obj = serde_json::Map::new();
        for (k, e) in &self.ops {
            if let Some(MapVal::Set(v)) = e.get_latest() {
                obj.insert(k.clone(), v.clone());
            }
        }
        JsonValue::Object(obj)
    }

    /// Changed keys since `since_version`: `{version, changedKeys, deletedKeys}`.
    /// `changedKeys[k] = latestValue` for keys whose latest is a value;
    /// `deletedKeys` lists keys whose latest is a deletion. A full recompute
    /// marks every current key changed (conservative resync).
    pub fn delta(&self, since_version: u64) -> JsonValue {
        let mut changed = serde_json::Map::new();
        let mut deleted: Vec<String> = Vec::new();
        for (k, ver) in &self.key_versions {
            if *ver > since_version {
                match self.ops.get(k).and_then(|e| e.get_latest()) {
                    Some(MapVal::Set(v)) => {
                        changed.insert(k.clone(), v.clone());
                    }
                    _ => deleted.push(k.clone()),
                }
            }
        }
        serde_json::json!({
            "version": self.version,
            "changedKeys": changed,
            "deletedKeys": deleted,
        })
    }
}

/// `(session_id, tx_count)` in session-insertion order — the freshness key.
fn session_counts_of(sm: &SessionMapImpl) -> Vec<(String, u32)> {
    sm.get_session_ids()
        .into_iter()
        .map(|sid| {
            let count = sm.get_transaction_count(&sid).unwrap_or(0);
            (sid, count)
        })
        .collect()
}

/// The `meta.fww` key of a tx, if any (`coValueCore.ts:1515`).
fn fww_key(tx: &GroupTxView) -> Option<&str> {
    tx.meta.as_ref()?.get("fww")?.as_str()
}

/// Apply one coMap change to the per-key ops, returning the key it touched (so
/// the caller can bump its version). A missing `key` field is skipped (never
/// produced by real cojson). `op === "del"` is a deletion; anything else reads
/// as its `value` (matching TS `get`: `op === "del" ? undefined : value`).
fn apply_change(
    ops: &mut IndexMap<String, TimeBasedEntry<MapVal>>,
    change: &JsonValue,
    made_at: u64,
) -> Option<String> {
    let key = change.get("key").and_then(|v| v.as_str())?;
    let val = match change.get("op").and_then(|v| v.as_str()) {
        Some("del") => MapVal::Del,
        _ => MapVal::Set(change.get("value").cloned().unwrap_or(JsonValue::Null)),
    };
    ops.entry(key.to_string())
        .or_default()
        .add_change(made_at, val);
    Some(key.to_string())
}

/// Decrypt a PRIVATE tx's changes into a parsed op array, reusing the session
/// map's decrypt primitive (no crypto duplicated here). Returns `None` when the
/// tx does not decrypt to a usable op array — a wrong/garbage key (TS's crypto
/// likewise yields nothing) or a missing session — so the caller SKIPS it,
/// exactly as TS drops an undecryptable tx from its views.
fn decrypt_private_changes(
    sm: &SessionMapImpl,
    tx: &GroupTxView,
    key_secret: &str,
) -> Option<Vec<JsonValue>> {
    match sm.decrypt_transaction(&tx.session_id, tx.tx_index, key_secret) {
        Ok(Some(json)) => serde_json::from_str::<Vec<JsonValue>>(&json).ok(),
        _ => None,
    }
}

/// Apply a valid tx's changes to the per-key ops, decrypting a PRIVATE tx via
/// the key store. Records the tx's `keyUsed` in `missing` (and contributes
/// nothing) when its secret is not yet available. `touched` collects the keys
/// this tx changed so the caller can bump their versions.
fn index_tx(
    ops: &mut IndexMap<String, TimeBasedEntry<MapVal>>,
    sm: &SessionMapImpl,
    keys: &HashMap<String, String>,
    missing: &mut HashSet<String>,
    tx: &GroupTxView,
    touched: &mut dyn FnMut(String),
) {
    match tx.privacy {
        Privacy::Trusting => {
            if let Some(changes) = &tx.changes {
                for change in changes {
                    if let Some(k) = apply_change(ops, change, tx.effective_made_at) {
                        touched(k);
                    }
                }
            }
        }
        Privacy::Private => {
            let key_id = match &tx.key_used {
                Some(k) => k,
                None => return,
            };
            let secret = match keys.get(key_id) {
                Some(s) => s,
                None => {
                    missing.insert(key_id.clone());
                    return;
                }
            };
            if let Some(changes) = decrypt_private_changes(sm, tx, secret) {
                for change in &changes {
                    if let Some(k) = apply_change(ops, change, tx.effective_made_at) {
                        touched(k);
                    }
                }
            }
        }
    }
}

/// The valid `(session_id, tx_index)` set of a verdict list.
fn valid_set(verdicts: &[Verdict]) -> HashSet<(String, u32)> {
    verdicts
        .iter()
        .filter(|v| v.valid)
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect()
}

/// Full recompute of a covalue's coMap view over its whole valid tx set + fww,
/// decrypting private txs against `keys` and recording any missing key ids.
#[allow(clippy::too_many_arguments)]
fn build_full_view(
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: Vec<(String, u32)>,
    pending: &[PendingTxIn],
    keys: &HashMap<String, String>,
    keys_version: u64,
    version: u64,
) -> CoMapView {
    let mut txs = collect_group_txs(sm, pending);
    sort_for_validation(&mut txs);

    let valid = valid_set(verdicts);

    // fww winner selection over ALL collected txs, in sorted (compareTransactions)
    // order: the first tx for a given fww key wins, every later one is a loser.
    let mut fww_seen: HashSet<String> = HashSet::new();
    let mut fww_losers: HashSet<(String, u32)> = HashSet::new();
    let mut has_fww = false;
    for tx in &txs {
        if let Some(fk) = fww_key(tx) {
            has_fww = true;
            if !fww_seen.insert(fk.to_string()) {
                fww_losers.insert((tx.session_id.clone(), tx.tx_index));
            }
        }
    }

    let mut ops: IndexMap<String, TimeBasedEntry<MapVal>> = IndexMap::new();
    let mut missing_key_ids: HashSet<String> = HashSet::new();
    let mut touched = |_k: String| {}; // full recompute marks all keys below
    for tx in &txs {
        let id = (tx.session_id.clone(), tx.tx_index);
        if !valid.contains(&id) || fww_losers.contains(&id) {
            continue;
        }
        index_tx(&mut ops, sm, keys, &mut missing_key_ids, tx, &mut touched);
    }

    // A full recompute conservatively marks every current key as changed at this
    // version so any stale delta cursor resyncs the whole map.
    let mut key_versions = HashMap::new();
    for k in ops.keys() {
        key_versions.insert(k.clone(), version);
    }

    CoMapView {
        session_counts: counts,
        ops,
        valid_txs: valid,
        has_fww,
        version,
        key_versions,
        keys_version,
        missing_key_ids,
    }
}

/// Attempt the incremental append fast-path, mutating `view` in place. Returns
/// `true` if the append succeeded; `false` (leaving `view` untouched) if any
/// guard failed and the caller must full-recompute.
fn try_append(
    view: &mut CoMapView,
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: &[(String, u32)],
    pending: &[PendingTxIn],
    keys: &HashMap<String, String>,
) -> bool {
    // Guard 2a: an existing fww key means an append could flip a winner.
    if view.has_fww {
        return false;
    }

    // Guard 1: pure superset (no session removed, no count decreased).
    // Owned keys (not borrows of `view`) so we can mutably re-borrow `view`
    // during the append loop below while still consulting these counts.
    let old_counts: HashMap<String, u32> = view
        .session_counts
        .iter()
        .map(|(s, c)| (s.clone(), *c))
        .collect();
    for (sid, new_c) in counts {
        if *new_c < old_counts.get(sid.as_str()).copied().unwrap_or(0) {
            return false;
        }
    }
    let new_sessions: HashSet<&str> = counts.iter().map(|(s, _)| s.as_str()).collect();
    for (sid, _) in &view.session_counts {
        if !new_sessions.contains(sid.as_str()) {
            return false;
        }
    }

    let is_old = |sid: &str, idx: u32| old_counts.get(sid).map(|c| idx < *c).unwrap_or(false);

    // Guard 3: the OLD-range verdicts must be unchanged (no earlier flip).
    let new_valid = valid_set(verdicts);
    let new_old_range: HashSet<(String, u32)> = new_valid
        .iter()
        .filter(|(s, i)| is_old(s, *i))
        .cloned()
        .collect();
    if new_old_range != view.valid_txs {
        return false;
    }

    let mut txs = collect_group_txs(sm, pending);
    sort_for_validation(&mut txs);

    // Guard 2b: no newly-appended tx may carry an fww key.
    for tx in &txs {
        if !is_old(&tx.session_id, tx.tx_index) && fww_key(tx).is_some() {
            return false;
        }
    }

    // All guards passed — append the new valid txs' ops (decrypting private
    // txs against the key store; a still-missing key is recorded and skipped).
    view.version += 1;
    let ver = view.version;
    let CoMapView {
        ops,
        key_versions,
        missing_key_ids,
        ..
    } = &mut *view;
    for tx in &txs {
        if is_old(&tx.session_id, tx.tx_index) {
            continue;
        }
        let id = (tx.session_id.clone(), tx.tx_index);
        if !new_valid.contains(&id) {
            continue;
        }
        index_tx(ops, sm, keys, missing_key_ids, tx, &mut |k| {
            key_versions.insert(k, ver);
        });
    }
    view.valid_txs = new_valid;
    view.session_counts = counts.to_vec();
    true
}

/// Ensure `co_id`'s coMap view is fresh (materializing on demand), returning its
/// current version. Reuses the engine verdicts (which also refreshes the
/// permission engine) and takes the incremental append fast-path when safe.
///
/// Operates on `NodeCore`'s three disjoint field borrows.
#[allow(clippy::too_many_arguments)]
pub fn ensure_co_map(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_maps: &mut HashMap<String, CoMapView>,
    keys: &HashMap<String, String>,
    keys_version: u64,
    co_id: &str,
    pending: &[PendingTxIn],
) -> Result<u64, SessionMapError> {
    // Verdicts also ensure the permission engine is fresh. `co_id` presence is
    // checked by the caller (NodeCore) via UnknownCoValue.
    let verdicts = engine_validate_transactions(covalues, engines, co_id, pending)?;
    let sm = covalues
        .get(co_id)
        .ok_or_else(|| SessionMapError::CoValueNotLoaded(co_id.to_string()))?;
    let counts = session_counts_of(sm);

    let need_full = match co_maps.get_mut(co_id) {
        Some(view) => {
            if view.session_counts == counts && view.keys_version == keys_version {
                return Ok(view.version);
            }
            // A newly-provided secret (keys-version bump) can retroactively
            // decrypt an OLD private tx, which the append fast-path (new txs
            // only) cannot pick up — so any keys-version change forces a full
            // recompute. Otherwise attempt the append fast-path.
            if view.keys_version != keys_version {
                true
            } else {
                !try_append(view, sm, &verdicts, &counts, pending, keys)
            }
        }
        None => true,
    };

    if need_full {
        let version = co_maps.get(co_id).map(|v| v.version).unwrap_or(0) + 1;
        let view = build_full_view(sm, &verdicts, counts, pending, keys, keys_version, version);
        co_maps.insert(co_id.to_string(), view);
    }

    Ok(co_maps.get(co_id).map(|v| v.version).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::node::NodeCore;

    // A minimal unsafeAllowAll comap covalue: header + a single session of
    // trusting transactions, built directly on a NodeCore. Every trusting tx is
    // valid (unsafeAllowAll), isolating content materialization.
    fn make_map(
        session_id: &str,
        txs: &[(&str, serde_json::Value, Option<&str>)],
    ) -> (NodeCore, String) {
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};
        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "comap".to_string(),
            uniqueness: Uniqueness::String("comaptest".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");

        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, true)
            .unwrap();

        // Build the raw transaction objects (trusting) with ascending madeAt.
        let mut tx_objs: Vec<String> = Vec::new();
        for (i, (key, value, fww)) in txs.iter().enumerate() {
            let made_at = 1_700_000_000_000u64 + i as u64;
            let changes = serde_json::to_string(&serde_json::json!([
                {"op": "set", "key": key, "value": value}
            ]))
            .unwrap();
            let meta = match fww {
                // The trusting tx `meta` wire field is a STRINGIFIED JSON object.
                Some(fk) => format!(
                    r#","meta":{}"#,
                    serde_json::to_string(&serde_json::json!({"fww": fk}).to_string()).unwrap()
                ),
                None => String::new(),
            };
            tx_objs.push(format!(
                r#"{{"privacy":"trusting","madeAt":{made_at},"changes":{}{}}}"#,
                serde_json::to_string(&changes).unwrap(),
                meta
            ));
        }
        let txs_json = format!("[{}]", tx_objs.join(","));
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session_id, None, &txs_json, "signature_zFake", true)
            .unwrap();

        (node, co_id)
    }

    /// A 32-byte test KeySecret in the `keySecret_z<base58>` wire form the
    /// xsalsa20 key derivation expects.
    fn test_key_secret(byte: u8) -> String {
        format!("keySecret_z{}", bs58::encode([byte; 32]).into_string())
    }

    /// An unsafeAllowAll comap whose single session is a run of PRIVATE
    /// transactions encrypted under `(key_id, key_secret)`. unsafeAllowAll makes
    /// every tx permission-valid, isolating decryption. `ops` are
    /// `(op, key, value)` with `op` `"set"` or `"del"`.
    fn make_private_map(
        session_id: &str,
        key_id: &str,
        key_secret: &str,
        ops: &[(&str, &str, serde_json::Value)],
    ) -> (NodeCore, String) {
        use crate::core::keys::SignerSecret;
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "comap".to_string(),
            uniqueness: Uniqueness::String("privcomaptest".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");

        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, true)
            .unwrap();

        let signer = SignerSecret::from(SigningKey::generate(&mut OsRng)).0;
        for (i, (op, key, value)) in ops.iter().enumerate() {
            let made_at = 1_700_000_000_000u64 + i as u64;
            let change = match *op {
                "del" => serde_json::json!([{"op": "del", "key": key}]),
                _ => serde_json::json!([{"op": "set", "key": key, "value": value}]),
            };
            let changes_json = serde_json::to_string(&change).unwrap();
            node.get_mut(&co_id)
                .unwrap()
                .make_new_private_transaction(
                    session_id.to_string(),
                    signer.clone(),
                    &changes_json,
                    key_id.to_string(),
                    key_secret.to_string(),
                    None,
                    made_at,
                )
                .unwrap();
        }
        (node, co_id)
    }

    #[test]
    fn latest_and_snapshot_last_write_wins() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_map(
            session,
            &[
                ("a", serde_json::json!(1), None),
                ("b", serde_json::json!("x"), None),
                ("a", serde_json::json!(2), None), // later set wins
            ],
        );
        node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(node.map_get(&co_id, "a").unwrap(), Some("2".to_string()));
        assert_eq!(
            node.map_get(&co_id, "b").unwrap(),
            Some("\"x\"".to_string())
        );
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({"a": 2, "b": "x"}));
    }

    #[test]
    fn del_removes_from_snapshot() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_map(session, &[("a", serde_json::json!(1), None)]);
        // Append a del of "a".
        let del = format!(
            r#"[{{"privacy":"trusting","madeAt":{},"changes":{}}}]"#,
            1_700_000_000_100u64,
            serde_json::to_string(
                &serde_json::to_string(&serde_json::json!([{"op": "del", "key": "a"}])).unwrap()
            )
            .unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session, None, &del, "signature_zFake", true)
            .unwrap();
        node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(node.map_get(&co_id, "a").unwrap(), None);
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({}));
    }

    #[test]
    fn at_time_reads_history() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_map(
            session,
            &[
                ("k", serde_json::json!("v0"), None), // madeAt base+0
                ("k", serde_json::json!("v1"), None), // madeAt base+1
                ("k", serde_json::json!("v2"), None), // madeAt base+2
            ],
        );
        node.map_materialize(&co_id, &[]).unwrap();
        let base = 1_700_000_000_000u64;
        assert_eq!(
            node.map_get_at(&co_id, "k", Some(base)).unwrap(),
            Some("\"v0\"".to_string())
        );
        assert_eq!(
            node.map_get_at(&co_id, "k", Some(base + 1)).unwrap(),
            Some("\"v1\"".to_string())
        );
        assert_eq!(
            node.map_get_at(&co_id, "k", None).unwrap(),
            Some("\"v2\"".to_string())
        );
        // Before any op: absent.
        assert_eq!(node.map_get_at(&co_id, "k", Some(base - 1)).unwrap(), None);
    }

    #[test]
    fn fww_first_writer_wins_across_keys() {
        let session = "co_zA_session_zS";
        // Two txs both carrying fww key "lock", setting different map keys. The
        // earlier (first in sorted order) wins; the later is excluded entirely.
        let (mut node, co_id) = make_map(
            session,
            &[
                ("winner", serde_json::json!(1), Some("lock")),
                ("loser", serde_json::json!(2), Some("lock")),
            ],
        );
        node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(
            node.map_get(&co_id, "winner").unwrap(),
            Some("1".to_string())
        );
        assert_eq!(node.map_get(&co_id, "loser").unwrap(), None);
    }

    #[test]
    fn incremental_append_matches_full_recompute() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_map(
            session,
            &[
                ("a", serde_json::json!(1), None),
                ("b", serde_json::json!(2), None),
            ],
        );
        let v1 = node.map_materialize(&co_id, &[]).unwrap();

        // Append a new tx and re-materialize -> append fast-path (no fww, valid
        // superset). Version bumps; delta reports only the changed key.
        let more = format!(
            r#"[{{"privacy":"trusting","madeAt":{},"changes":{}}}]"#,
            1_700_000_001_000u64,
            serde_json::to_string(
                &serde_json::to_string(&serde_json::json!([{"op": "set", "key": "c", "value": 3}]))
                    .unwrap()
            )
            .unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session, None, &more, "signature_zFake", true)
            .unwrap();
        let v2 = node.map_materialize(&co_id, &[]).unwrap();
        assert!(v2 > v1, "version bumps on append");

        let delta: serde_json::Value =
            serde_json::from_str(&node.map_delta(&co_id, v1).unwrap()).unwrap();
        assert_eq!(delta["version"], v2);
        assert_eq!(delta["changedKeys"], serde_json::json!({"c": 3}));

        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({"a": 1, "b": 2, "c": 3}));
    }

    // === R1: private-transaction decryption into the view ===

    #[test]
    fn private_txs_decrypt_into_view_when_key_present() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPriv1";
        let secret = test_key_secret(7);
        let (mut node, co_id) = make_private_map(
            session,
            key_id,
            &secret,
            &[
                ("set", "a", serde_json::json!(1)),
                ("set", "b", serde_json::json!("x")),
                ("set", "a", serde_json::json!(2)), // later set wins
            ],
        );
        node.provide_key_secret(key_id, &secret);
        node.map_materialize(&co_id, &[]).unwrap();

        assert_eq!(node.map_get(&co_id, "a").unwrap(), Some("2".to_string()));
        assert_eq!(
            node.map_get(&co_id, "b").unwrap(),
            Some("\"x\"".to_string())
        );
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({"a": 2, "b": "x"}));
        assert!(node.missing_key_ids(&co_id).is_empty());
    }

    #[test]
    fn private_tx_without_key_is_skipped_and_recorded() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPriv2";
        let secret = test_key_secret(9);
        let (mut node, co_id) = make_private_map(
            session,
            key_id,
            &secret,
            &[("set", "a", serde_json::json!(1))],
        );
        // No key provided: the private tx must NOT contribute to views.
        node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(node.map_get(&co_id, "a").unwrap(), None);
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({}));
        // ...but its keyUsed is recorded so TS knows what to unseal.
        assert_eq!(node.missing_key_ids(&co_id), vec![key_id.to_string()]);
    }

    #[test]
    fn late_key_arrival_rebuilds_view() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPriv3";
        let secret = test_key_secret(11);
        let (mut node, co_id) = make_private_map(
            session,
            key_id,
            &secret,
            &[
                ("set", "a", serde_json::json!(1)),
                ("set", "b", serde_json::json!(2)),
            ],
        );

        // Before the key: empty view, key recorded.
        let v1 = node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(
            node.map_snapshot(&co_id).unwrap(),
            serde_json::json!({}).to_string()
        );
        assert_eq!(node.missing_key_ids(&co_id), vec![key_id.to_string()]);

        // Key arrives -> keys-version bumps -> next materialize rebuilds even
        // though NO new transaction was ingested (session counts unchanged).
        node.provide_key_secret(key_id, &secret);
        let v2 = node.map_materialize(&co_id, &[]).unwrap();
        assert!(v2 > v1, "view rebuilds (new version) after the key arrives");
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({"a": 1, "b": 2}));
        assert!(node.missing_key_ids(&co_id).is_empty());
    }

    #[test]
    fn provide_key_secret_is_idempotent() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPriv4";
        let secret = test_key_secret(13);
        let (mut node, co_id) = make_private_map(
            session,
            key_id,
            &secret,
            &[("set", "a", serde_json::json!(1))],
        );
        node.provide_key_secret(key_id, &secret);
        let v1 = node.map_materialize(&co_id, &[]).unwrap();
        assert!(node.has_key_secret(key_id));

        // Re-providing the SAME secret must not bump the keys-version, so a
        // re-materialize with no new txs is a cache hit (identical version).
        node.provide_key_secret(key_id, &secret);
        let v2 = node.map_materialize(&co_id, &[]).unwrap();
        assert_eq!(v1, v2, "identical re-provide must not force a rebuild");
    }

    #[test]
    fn mixed_private_and_trusting_txs_materialize_together() {
        // One private session (needs the key) plus a trusting session (plaintext).
        let priv_session = "co_zA_session_zPriv";
        let key_id = "key_zPriv5";
        let secret = test_key_secret(17);
        let (mut node, co_id) = make_private_map(
            priv_session,
            key_id,
            &secret,
            &[("set", "p", serde_json::json!("private-val"))],
        );

        // Append a trusting tx in a second session (madeAt after the private one).
        let trusting = format!(
            r#"[{{"privacy":"trusting","madeAt":{},"changes":{}}}]"#,
            1_700_000_010_000u64,
            serde_json::to_string(
                &serde_json::to_string(
                    &serde_json::json!([{"op": "set", "key": "t", "value": "trusting-val"}])
                )
                .unwrap()
            )
            .unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(
                "co_zA_session_zTrust",
                None,
                &trusting,
                "signature_zFake",
                true,
            )
            .unwrap();

        node.provide_key_secret(key_id, &secret);
        node.map_materialize(&co_id, &[]).unwrap();
        let snap: serde_json::Value =
            serde_json::from_str(&node.map_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(
            snap,
            serde_json::json!({"p": "private-val", "t": "trusting-val"})
        );
    }
}
