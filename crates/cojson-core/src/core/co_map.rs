//! Rust-resident coMap materialization (R0 prototype).
//!
//! Materializes a coMap's per-key op index over the VALID transaction set of a
//! covalue, reusing the group engine's verdicts (permission validation) and the
//! `tx_view` collection/ordering primitives. Trusting transactions only — no
//! decryption in R0. The first-writer-wins (fww) overlay from
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
use crate::core::group_engine::tx_view::{collect_group_txs, sort_for_validation, GroupTxView, PendingTxIn};
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
}

impl CoMapView {
    pub fn version(&self) -> u64 {
        self.version
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
    ops.entry(key.to_string()).or_default().add_change(made_at, val);
    Some(key.to_string())
}

/// The valid `(session_id, tx_index)` set of a verdict list.
fn valid_set(verdicts: &[Verdict]) -> HashSet<(String, u32)> {
    verdicts
        .iter()
        .filter(|v| v.valid)
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect()
}

/// Full recompute of a covalue's coMap view over its whole valid tx set + fww.
fn build_full_view(
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: Vec<(String, u32)>,
    pending: &[PendingTxIn],
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
    let mut touched: HashSet<String> = HashSet::new();
    for tx in &txs {
        let id = (tx.session_id.clone(), tx.tx_index);
        if !valid.contains(&id) || fww_losers.contains(&id) {
            continue;
        }
        let changes = match &tx.changes {
            Some(c) => c,
            None => continue,
        };
        for change in changes {
            if let Some(k) = apply_change(&mut ops, change, tx.effective_made_at) {
                touched.insert(k);
            }
        }
    }

    // A full recompute conservatively marks every current key as changed at this
    // version so any stale delta cursor resyncs the whole map.
    let mut key_versions = HashMap::new();
    for k in ops.keys() {
        key_versions.insert(k.clone(), version);
    }
    let _ = touched; // full recompute marks all keys, not only newly touched

    CoMapView {
        session_counts: counts,
        ops,
        valid_txs: valid,
        has_fww,
        version,
        key_versions,
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
) -> bool {
    // Guard 2a: an existing fww key means an append could flip a winner.
    if view.has_fww {
        return false;
    }

    // Guard 1: pure superset (no session removed, no count decreased).
    let old_counts: HashMap<&str, u32> = view
        .session_counts
        .iter()
        .map(|(s, c)| (s.as_str(), *c))
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

    // All guards passed — append the new valid txs' ops.
    view.version += 1;
    let ver = view.version;
    for tx in &txs {
        if is_old(&tx.session_id, tx.tx_index) {
            continue;
        }
        let id = (tx.session_id.clone(), tx.tx_index);
        if !new_valid.contains(&id) {
            continue;
        }
        let changes = match &tx.changes {
            Some(c) => c,
            None => continue,
        };
        for change in changes {
            if let Some(k) = apply_change(&mut view.ops, change, tx.effective_made_at) {
                view.key_versions.insert(k, ver);
            }
        }
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
pub fn ensure_co_map(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_maps: &mut HashMap<String, CoMapView>,
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
            if view.session_counts == counts {
                return Ok(view.version);
            }
            !try_append(view, sm, &verdicts, &counts, pending)
        }
        None => true,
    };

    if need_full {
        let version = co_maps.get(co_id).map(|v| v.version).unwrap_or(0) + 1;
        let view = build_full_view(sm, &verdicts, counts, pending, version);
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
    fn make_map(session_id: &str, txs: &[(&str, serde_json::Value, Option<&str>)]) -> (NodeCore, String) {
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
        node.create_co_value(&co_id, &header_json, None, true).unwrap();

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
        assert_eq!(node.map_get(&co_id, "b").unwrap(), Some("\"x\"".to_string()));
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
        assert_eq!(node.map_get(&co_id, "winner").unwrap(), Some("1".to_string()));
        assert_eq!(node.map_get(&co_id, "loser").unwrap(), None);
    }

    #[test]
    fn incremental_append_matches_full_recompute() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_map(
            session,
            &[("a", serde_json::json!(1), None), ("b", serde_json::json!(2), None)],
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
}
