//! Rust-resident coList (RGA list CRDT) materialization.
//!
//! Materializes a coList's ordered entry array over the covalue's transaction
//! set, reusing the group engine's verdicts (permission validation), the
//! `tx_view` collection/ordering primitives, and the R1 key store — exactly as
//! [`crate::core::co_map`] and [`crate::core::co_stream`] do. A coList is a
//! Replicated Growable Array: inserts anchor `after`/`before` another element
//! (or the `start`/`end` roots) and deletions are tombstones keyed by the
//! inserted opID. There is NO per-anchor tie-break comparator — determinism is
//! delegated ENTIRELY to the core's global sorted-transaction order
//! ([`sort_for_validation`], the port of `compareTransactions`): concurrent
//! inserts at the same anchor land in a `successors`/`predecessors` array in the
//! order the sorted-tx pass yields them, and the DFS emits them in that array
//! order.
//!
//! ## Semantics mirrored from `packages/cojson/src/coValues/coList.ts`
//!
//! - **Ops** (`ListOpPayload`): `app` (`{op:"app", value, after: OpID|"start"}`),
//!   `pre` (`{op:"pre", value, before: OpID|"end"}`), `del`
//!   (`{op:"del", insertion: OpID}`). `OpID = {sessionID, txIndex, branch?,
//!   changeIdx}`.
//! - **Structure**: each insertion entry holds `predecessors`/`successors`
//!   (populated by LATER inserts that reference it as their anchor) plus the
//!   roots `after_start`/`before_end`. Deletions are tombstones in
//!   `deletions_by_insertion`, never removals.
//! - **`getSessionIndex`** (`coList.ts:783-788`): an opID's bucket key is
//!   `sessionID` normally, but `${sessionID}_branch_${branch}` when `txID.branch`
//!   is set. Branch and source ops with the same session live in SEPARATE
//!   buckets. We fold this into [`OpId`] (which carries `branch`) so equality /
//!   hashing already namespaces by branch.
//! - **Merged transactions** (`branching.ts` + `coValueCore.ts:2177-2217`): a
//!   merged tx stored on the source carries `meta.{mi,t,s,b}` so its EFFECTIVE
//!   opID is the ORIGINAL branch identity `{sessionID: meta.s, txIndex: meta.mi,
//!   branch: meta.b}`. `mergeBranch` COMPRESSES `s`/`b` (and sometimes `t`)
//!   across consecutive same-session merges, so we reproduce the TS
//!   `previousTransaction` fallback in [`apply_merge_source_fallback`] before
//!   sorting (the sort tie-break reads effective `(made_at, session, tx_index)`).
//! - **Materialization** (`fillArrayFromOpID`, `coList.ts:460-512`): an explicit
//!   stack DFS per root — push predecessors (visited-guarded), emit the node
//!   itself only when NOT tombstoned AND `is_valid`, then push successors. Roots
//!   processed `after_start` then `before_end`. Reproduced byte-for-byte in
//!   [`CoListView::entries`].
//! - **`includeInvalidMetaTransactions: true`** (`coList.ts:227-231`): coList
//!   PROCESSES both valid AND meta-invalid (e.g. `source_after_current`, losing
//!   fww/init) transactions — storing their entries so later inserts can resolve
//!   anchors against them — but EMITS only `is_valid` ones. Permission-invalid
//!   transactions are NOT processed. Native-side: a tx is PROCESSABLE when its
//!   verdict is valid OR its invalid reason is the merge-meta anti-tamper reason
//!   ([`SOURCE_AFTER_CURRENT_REASON`]); an entry's `is_valid` is
//!   `verdict.valid && !fww_loser` (the fww overlay mirrors co_map/co_stream).
//!
//! ## atTime / atFrontier
//!
//! Time-travel coLists (`atTime`/`atFrontier`) construct a fresh filtered
//! `RawCoList`; the TS gate keeps those on the TS path (`nativeMaterialization =
//! !atTimeFilter && !atFrontierFilter && isNativeCoList()`), so — unlike
//! co_stream — this module needs NO frontier read surface.
//!
//! ## Freshness
//!
//! RGA order is globally reordered by any incoming transaction (an insert can
//! land anywhere), and even the TS reader recomputes its whole `_cachedEntries`
//! array on every change, so there is no safe append-only fast-path here: the
//! view fully rebuilds whenever the per-session tx-counts or the node keys
//! version change, bumping `version`. That matches the TS read cost exactly.

use std::collections::{HashMap, HashSet};

use serde_json::Value as JsonValue;

use crate::core::group_engine::engine::{
    ensure as engine_ensure, generation_of, verdicts_of, GroupEngineState, Verdict,
};
use crate::core::group_engine::tx_view::{
    collect_group_txs_keyed, sort_for_validation, GroupTxView, PendingTxIn, Privacy,
};
use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// The verbatim engine reason for the merge-meta anti-tamper failure — the ONE
/// invalidity that is a META invalidation (author passed permission, the tx is
/// still PROCESSABLE per `includeInvalidMetaTransactions`) rather than a
/// permission failure. Kept in sync with `engine.rs`'s constant of the same
/// name.
const SOURCE_AFTER_CURRENT_REASON: &str = "Transaction sourceMadeAt is after the currentMadeAt";

/// The identity of a single list change: `OpID = {sessionID, txIndex, branch?,
/// changeIdx}` (`coList.ts:14`). `branch` is folded in so equality / hashing
/// already implements `getSessionIndex`'s branch namespacing — two opIDs with
/// the same `(session, txIndex, changeIdx)` but different `branch` are DISTINCT
/// entries.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct OpId {
    session_id: String,
    tx_index: u32,
    branch: Option<String>,
    change_idx: u32,
}

impl OpId {
    /// Serialize as the TS opID JSON `{"sessionID":…,"txIndex":…,[branch,]
    /// "changeIdx":…}`, OMITTING `branch` when `None` (matches `JSON.stringify`
    /// of an opID whose `branch` is `undefined`). Field order mirrors the TS
    /// object literal (`coList.ts:273-278`).
    fn write_json(&self, out: &mut String) {
        use std::fmt::Write as _;
        out.push_str("{\"sessionID\":");
        write_json_escaped_str(&self.session_id, out);
        out.push_str(",\"txIndex\":");
        let _ = write!(out, "{}", self.tx_index);
        if let Some(b) = &self.branch {
            out.push_str(",\"branch\":");
            write_json_escaped_str(b, out);
        }
        out.push_str(",\"changeIdx\":");
        let _ = write!(out, "{}", self.change_idx);
        out.push('}');
    }
}

/// An insert-change anchor: a concrete opID, or one of the `start`/`end` roots.
#[derive(Clone, Debug)]
enum Anchor {
    Start,
    End,
    Op(OpId),
}

/// One materialized insertion entry (`InsertionEntry`, `coList.ts:37-44`).
struct InsertionEntry {
    made_at: u64,
    /// opIDs of inserts anchored `before` THIS op (populated as they arrive).
    predecessors: Vec<OpId>,
    /// opIDs of inserts anchored `after` THIS op.
    successors: Vec<OpId>,
    /// The inserted value (`change.value`).
    value: JsonValue,
    /// Whether this entry comes from a FINAL-valid transaction (emitted only if
    /// true; stored regardless so it can anchor other inserts).
    is_valid: bool,
}

/// One materialized ordered entry, the `{value, madeAt, opID}` shape
/// `RawCoList.entries()` yields (`coList.ts:423-427`).
#[derive(Debug, Clone, PartialEq)]
pub struct ListEntry {
    pub value: JsonValue,
    pub made_at: u64,
    session_id: String,
    tx_index: u32,
    branch: Option<String>,
    change_idx: u32,
}

impl ListEntry {
    /// `{"value":…,"madeAt":…,"opID":{…}}` — the per-entry payload a TS
    /// `RawCoList` rebuilds its cached `entries()` from.
    fn write_json(&self, out: &mut String) {
        use std::fmt::Write as _;
        out.push_str("{\"value\":");
        let _ = write!(out, "{}", self.value);
        out.push_str(",\"madeAt\":");
        let _ = write!(out, "{}", self.made_at);
        out.push_str(",\"opID\":");
        OpId {
            session_id: self.session_id.clone(),
            tx_index: self.tx_index,
            branch: self.branch.clone(),
            change_idx: self.change_idx,
        }
        .write_json(out);
        out.push('}');
    }
}

/// Write `s` as a JSON string literal (quotes + escaping) via `Value::String`'s
/// `Display` (serde_json's compact serializer).
fn write_json_escaped_str(s: &str, out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(out, "{}", JsonValue::String(s.to_string()));
}

/// A cached, materialized coList view for one covalue.
pub struct CoListView {
    /// `(session_id, tx_count)` snapshot — the cache-validity key.
    session_counts: Vec<(String, u32)>,
    /// The ordered materialized entries (the DFS output).
    entries: Vec<ListEntry>,
    /// The `NodeCore` keys-version this view was built against (freshness).
    keys_version: u64,
    /// Monotonic version, bumped once per rebuild. The delta cursor.
    version: u64,
    /// `KeyID`s of PRIVATE transactions whose secret was unavailable at build
    /// time (SKIPPED, mirroring TS). Drives TS key acquisition.
    missing_key_ids: HashSet<String>,
}

impl CoListView {
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The `KeyID`s this view still needs a secret for (sorted, deterministic).
    pub fn missing_key_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.missing_key_ids.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// The whole materialized list as a JSON array of VALUES, matching
    /// `RawCoList.asArray()` / `toJSON()`.
    pub fn snapshot(&self) -> String {
        let mut out = String::with_capacity(self.entries.len() * 8 + 2);
        out.push('[');
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            use std::fmt::Write as _;
            let _ = write!(out, "{}", e.value);
        }
        out.push(']');
        out
    }

    /// The whole ordered entry list as `[{value, madeAt, opID}, ...]` — the
    /// payload a TS `RawCoList` rebuilds its `entries()`/`asArray()` from.
    pub fn entries_json(&self) -> String {
        let mut out = String::with_capacity(self.entries.len() * 48 + 2);
        out.push('[');
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            e.write_json(&mut out);
        }
        out.push(']');
        out
    }

    /// `{version, reset, entries}` since `since_version`. Because the RGA order
    /// is globally recomputed on any change, a caught-up caller (`since_version
    /// == self.version`) gets an empty (`reset:false`, no `entries` key change)
    /// signal, and any stale/fresh caller gets the FULL ordered entry list with
    /// `reset:true` — the caller replaces its whole `entries()` wholesale (the
    /// same "replace wholesale" contract coStream uses per session).
    pub fn delta(&self, since_version: u64) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(self.entries.len() * 48 + 48);
        out.push_str("{\"version\":");
        let _ = write!(out, "{}", self.version);
        // A caller already at this version needs no rebuild.
        if since_version == self.version {
            out.push_str(",\"reset\":false,\"entries\":null}");
            return out;
        }
        out.push_str(",\"reset\":true,\"entries\":");
        out.push_str(&self.entries_json());
        out.push('}');
        out
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

/// The `meta.fww` key of a tx, if any (`coValueCore.ts` fww overlay).
fn fww_key(tx: &GroupTxView) -> Option<&str> {
    tx.meta.as_ref()?.get("fww")?.as_str()
}

/// Reproduce the TS `previousTransaction` fallback for a merged transaction's
/// EFFECTIVE source identity (`coValueCore.ts:2183-2217`) that `mergeBranch`'s
/// `s`/`b`/`t` compression relies on. Operates on the collected views IN
/// session-insertion order (the order `collect_group_txs_keyed` yields, which is
/// per-session, `tx_index` ascending — exactly the `previous` chain), BEFORE
/// [`sort_for_validation`], mutating `source_session_id` / `source_tx_index` /
/// `effective_made_at` in place and returning `branch_by_current[(session,
/// tx_index)]` for the branch component (which no `GroupTxView` field carries).
///
/// For each tx we track, per session, the previous tx's EFFECTIVE
/// `(session, branch, made_at)`:
/// - a MERGE tx (`meta.mi` present, i.e. `tx.is_merge`) takes
///   `session = meta.s ?? prev.session`, `txIndex = meta.mi`,
///   `branch = meta.b ?? prev.branch`, and `made_at = (currentMadeAt - meta.t)`
///   when `meta.t` is present else `prev.made_at`;
/// - a non-merge tx contributes its own `(session_id, None, current_made_at)` to
///   the chain (a following compressed merge inherits from it, matching TS).
fn apply_merge_source_fallback(txs: &mut [GroupTxView]) -> HashMap<(String, u32), Option<String>> {
    let mut branch_by_current: HashMap<(String, u32), Option<String>> = HashMap::new();
    let mut cur_session: Option<String> = None;
    // Previous tx's effective identity within the current session.
    let mut prev_session: Option<String> = None;
    let mut prev_branch: Option<String> = None;
    let mut prev_made_at: u64 = 0;

    for tx in txs.iter_mut() {
        if cur_session.as_deref() != Some(tx.session_id.as_str()) {
            cur_session = Some(tx.session_id.clone());
            prev_session = None;
            prev_branch = None;
            prev_made_at = 0;
        }

        let (eff_session, eff_branch, eff_made_at) = if tx.is_merge {
            let meta = tx.meta.as_ref();
            let mi = meta
                .and_then(|m| m.get("mi"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            let s = meta
                .and_then(|m| m.get("s"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let has_b = meta.and_then(|m| m.get("b")).is_some();
            let b = meta
                .and_then(|m| m.get("b"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let has_t = meta.and_then(|m| m.get("t")).is_some();

            // Effective session: meta.s, else the previous tx's effective session.
            let eff_session = s.clone().or_else(|| prev_session.clone());
            // Effective branch: meta.b when the key is PRESENT (branch ids are
            // always real strings here), else the previous tx's branch.
            let eff_branch = if has_b { b } else { prev_branch.clone() };
            // Effective made-at: derive already set `effective_made_at` from
            // `meta.t` when present; without `t`, fall back to prev's made-at.
            let eff_made_at = if has_t {
                tx.effective_made_at
            } else {
                prev_made_at
            };

            // Write the effective source identity back so the shared
            // `sort_for_validation` tie-break and the RGA build both see it.
            if let Some(sess) = &eff_session {
                tx.source_session_id = Some(sess.clone());
            }
            if let Some(mi) = mi {
                tx.source_tx_index = Some(mi);
            }
            tx.effective_made_at = eff_made_at;

            (eff_session, eff_branch, eff_made_at)
        } else {
            // Non-merge: its own identity feeds the chain (branch always None on
            // a native-gated, non-branch source covalue).
            (
                Some(tx.session_id.clone()),
                None,
                tx.effective_made_at,
            )
        };

        branch_by_current.insert((tx.session_id.clone(), tx.tx_index), eff_branch.clone());

        prev_session = eff_session;
        prev_branch = eff_branch;
        prev_made_at = eff_made_at;
    }

    branch_by_current
}

/// The effective opID base of a tx: `(session, tx_index, branch)` =
/// `txID = sourceTxID ?? currentTxID` (`coValueCore.ts:221-223`), with `branch`
/// pulled from the fallback map (keyed by the tx's STABLE current identity).
fn op_base(
    tx: &GroupTxView,
    branch_by_current: &HashMap<(String, u32), Option<String>>,
) -> (String, u32, Option<String>) {
    let session = tx
        .source_session_id
        .clone()
        .unwrap_or_else(|| tx.session_id.clone());
    let tx_index = tx.source_tx_index.unwrap_or(tx.tx_index);
    let branch = branch_by_current
        .get(&(tx.session_id.clone(), tx.tx_index))
        .cloned()
        .flatten();
    (session, tx_index, branch)
}

/// Parse a change's anchor field (`after`/`before`): the string `"start"`/
/// `"end"` roots, or an opID object.
fn parse_anchor(v: &JsonValue) -> Option<Anchor> {
    match v {
        JsonValue::String(s) if s == "start" => Some(Anchor::Start),
        JsonValue::String(s) if s == "end" => Some(Anchor::End),
        JsonValue::Object(_) => parse_opid(v).map(Anchor::Op),
        _ => None,
    }
}

/// Parse an opID object `{sessionID, txIndex, branch?, changeIdx}`.
fn parse_opid(v: &JsonValue) -> Option<OpId> {
    let obj = v.as_object()?;
    Some(OpId {
        session_id: obj.get("sessionID")?.as_str()?.to_string(),
        tx_index: obj.get("txIndex")?.as_u64()? as u32,
        branch: obj.get("branch").and_then(|b| b.as_str()).map(String::from),
        change_idx: obj.get("changeIdx")?.as_u64()? as u32,
    })
}

/// The mutable RGA accumulator built during the sorted-tx pass.
#[derive(Default)]
struct RgaBuild {
    insertions: HashMap<OpId, InsertionEntry>,
    /// `deletionsByInsertion`: number of tombstones per inserted opID (TS keeps
    /// the full `DeletionEntry[]`, but materialization only reads "any?").
    deletions: HashMap<OpId, usize>,
    after_start: Vec<OpId>,
    before_end: Vec<OpId>,
}

impl RgaBuild {
    /// Process one change of a processable tx (`coList.ts:270-330`). `made_at`
    /// and `is_valid` are the tx's effective made-at and final validity.
    fn process_change(
        &mut self,
        op_id: OpId,
        made_at: u64,
        is_valid: bool,
        change: &JsonValue,
    ) {
        let op = change.get("op").and_then(|v| v.as_str());
        match op {
            Some("app") | Some("pre") => {
                // Double-merge idempotency: an already-present opID is skipped
                // (createInsertionsEntry returns false, `coList.ts:172-178`).
                if self.insertions.contains_key(&op_id) {
                    return;
                }
                let value = change.get("value").cloned().unwrap_or(JsonValue::Null);
                self.insertions.insert(
                    op_id.clone(),
                    InsertionEntry {
                        made_at,
                        predecessors: Vec::new(),
                        successors: Vec::new(),
                        value,
                        is_valid,
                    },
                );

                if op == Some("pre") {
                    match change.get("before").and_then(parse_anchor) {
                        Some(Anchor::End) => self.before_end.push(op_id),
                        Some(Anchor::Op(anchor)) => {
                            // Anchor may not exist yet (references an as-yet
                            // unprocessed / invalid init tx) → entry orphaned
                            // (TS `continue`, `coList.ts:300-304`).
                            if let Some(entry) = self.insertions.get_mut(&anchor) {
                                entry.predecessors.push(op_id);
                            }
                        }
                        Some(Anchor::Start) | None => { /* malformed pre: ignore */ }
                    }
                } else {
                    match change.get("after").and_then(parse_anchor) {
                        Some(Anchor::Start) => self.after_start.push(op_id),
                        Some(Anchor::Op(anchor)) => {
                            if let Some(entry) = self.insertions.get_mut(&anchor) {
                                entry.successors.push(op_id);
                            }
                        }
                        Some(Anchor::End) | None => { /* malformed app: ignore */ }
                    }
                }
            }
            Some("del") => {
                if let Some(insertion) = change.get("insertion").and_then(parse_opid) {
                    *self.deletions.entry(insertion).or_insert(0) += 1;
                }
            }
            _ => { /* unknown op: TS throws; here we defensively ignore */ }
        }
    }

    /// The `fillArrayFromOpID` explicit-stack DFS (`coList.ts:460-512`), emitting
    /// into `out` from one root. Predecessors render before the anchor,
    /// successors after; the exact push order (and reference-identity
    /// visited-guard) is preserved so output is byte-identical to TS.
    fn fill_from(&self, root: &OpId, out: &mut Vec<ListEntry>) {
        let mut todo: Vec<OpId> = vec![root.clone()];
        let mut predecessors_visited: HashSet<OpId> = HashSet::new();

        while let Some(current) = todo.last().cloned() {
            let entry = match self.insertions.get(&current) {
                Some(e) => e,
                // TS throws "Missing op"; a consistent build never hits this.
                None => {
                    todo.pop();
                    continue;
                }
            };

            let should_traverse_predecessors =
                !entry.predecessors.is_empty() && !predecessors_visited.contains(&current);

            if should_traverse_predecessors {
                for predecessor in &entry.predecessors {
                    todo.push(predecessor.clone());
                }
                predecessors_visited.insert(current);
            } else {
                todo.pop();

                let deleted = self.deletions.get(&current).copied().unwrap_or(0) > 0;
                if !deleted && entry.is_valid {
                    out.push(ListEntry {
                        value: entry.value.clone(),
                        made_at: entry.made_at,
                        session_id: current.session_id.clone(),
                        tx_index: current.tx_index,
                        branch: current.branch.clone(),
                        change_idx: current.change_idx,
                    });
                }

                for successor in &entry.successors {
                    todo.push(successor.clone());
                }
            }
        }
    }
}

/// The valid `(session_id, tx_index)` set of a verdict list (permission-valid
/// AND not meta-invalidated).
fn valid_set(verdicts: &[Verdict]) -> HashSet<(String, u32)> {
    verdicts
        .iter()
        .filter(|v| v.valid)
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect()
}

/// The PROCESSABLE `(session_id, tx_index)` set: valid OR invalid solely for the
/// merge-meta anti-tamper reason (`includeInvalidMetaTransactions: true`).
/// Permission-invalid txs (any other reason) are excluded.
fn processable_set(verdicts: &[Verdict]) -> HashSet<(String, u32)> {
    verdicts
        .iter()
        .filter(|v| v.valid || v.reason.as_deref() == Some(SOURCE_AFTER_CURRENT_REASON))
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect()
}

/// Decrypt a PRIVATE tx's changes into a parsed change array (`None` when the
/// key/session is unavailable — the caller SKIPS it, as TS drops an
/// undecryptable tx).
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

/// Full recompute of a covalue's coList view.
#[allow(clippy::too_many_arguments)]
fn build_full_view(
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: Vec<(String, u32)>,
    pending: &[PendingTxIn],
    keys: &HashMap<String, String>,
    keys_version: u64,
    version: u64,
) -> CoListView {
    let mut txs = collect_group_txs_keyed(sm, pending, keys);
    // Fill compressed merge source identities (session/branch/made-at) BEFORE
    // sorting — the sort tie-break reads effective `(made_at, session, index)`.
    let branch_by_current = apply_merge_source_fallback(&mut txs);
    sort_for_validation(&mut txs);

    let valid = valid_set(verdicts);
    let processable = processable_set(verdicts);

    // fww winner selection over sorted txs (co_map/co_stream's identical
    // overlay): the first permission-valid tx for an fww key wins, later ones
    // are losers (stored but is_valid=false).
    let mut fww_seen: HashSet<String> = HashSet::new();
    let mut fww_losers: HashSet<(String, u32)> = HashSet::new();
    for tx in &txs {
        if let Some(fk) = fww_key(tx) {
            let id = (tx.session_id.clone(), tx.tx_index);
            if !valid.contains(&id) {
                continue;
            }
            if !fww_seen.insert(fk.to_string()) {
                fww_losers.insert(id);
            }
        }
    }

    let mut build = RgaBuild::default();
    let mut missing_key_ids: HashSet<String> = HashSet::new();

    for tx in &txs {
        let id = (tx.session_id.clone(), tx.tx_index);
        if !processable.contains(&id) {
            continue;
        }
        let is_valid = valid.contains(&id) && !fww_losers.contains(&id);
        let (session, tx_index, branch) = op_base(tx, &branch_by_current);

        // Gather this tx's changes (decrypt private; skip when key missing).
        let changes: Option<Vec<JsonValue>> = match tx.privacy {
            Privacy::Trusting => tx.changes.clone(),
            Privacy::Private => match &tx.key_used {
                None => None,
                Some(key_id) => match keys.get(key_id) {
                    Some(secret) => decrypt_private_changes(sm, tx, secret),
                    None => {
                        missing_key_ids.insert(key_id.clone());
                        None
                    }
                },
            },
        };
        let Some(changes) = changes else { continue };

        for (change_idx, change) in changes.iter().enumerate() {
            let op_id = OpId {
                session_id: session.clone(),
                tx_index,
                branch: branch.clone(),
                change_idx: change_idx as u32,
            };
            build.process_change(op_id, tx.effective_made_at, is_valid, change);
        }
    }

    // Materialize: DFS from each root, after_start then before_end.
    let mut entries: Vec<ListEntry> = Vec::new();
    for root in &build.after_start {
        build.fill_from(root, &mut entries);
    }
    for root in &build.before_end {
        build.fill_from(root, &mut entries);
    }

    CoListView {
        session_counts: counts,
        entries,
        keys_version,
        version,
        missing_key_ids,
    }
}

/// Ensure `co_id`'s coList view is fresh (materializing on demand), returning
/// its current version. Rebuilds fully whenever the per-session tx-counts or the
/// node keys-version changed (there is no safe RGA append fast-path).
#[allow(clippy::too_many_arguments)]
pub fn ensure_co_list(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_lists: &mut HashMap<String, CoListView>,
    keys: &HashMap<String, String>,
    keys_version: u64,
    co_id: &str,
    pending: &[PendingTxIn],
) -> Result<u64, SessionMapError> {
    engine_ensure(covalues, engines, keys, keys_version, co_id, pending)?;
    let verdicts = verdicts_of(engines, co_id);
    // `generation_of` is consulted to keep the engine warmed on the same code
    // path as co_map/co_stream; the RGA view keys freshness on tx-counts +
    // keys-version (a full rebuild is always correct regardless of generation).
    let _ = generation_of(engines, co_id);
    let sm = covalues
        .get(co_id)
        .ok_or_else(|| SessionMapError::CoValueNotLoaded(co_id.to_string()))?;
    let counts = session_counts_of(sm);

    if let Some(view) = co_lists.get(co_id) {
        if view.session_counts == counts && view.keys_version == keys_version {
            return Ok(view.version);
        }
    }

    let version = co_lists.get(co_id).map(|v| v.version).unwrap_or(0) + 1;
    let view = build_full_view(sm, verdicts, counts, pending, keys, keys_version, version);
    let version = view.version;
    co_lists.insert(co_id.to_string(), view);
    Ok(version)
}

#[cfg(test)]
mod tests {
    use crate::core::node::NodeCore;

    /// A minimal unsafeAllowAll colist covalue: header + a single session of
    /// trusting transactions. Each element of `txns` is a full `changes` array
    /// (a Vec of change objects) for one transaction.
    fn make_list(session_id: &str, txns: &[serde_json::Value]) -> (NodeCore, String) {
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};
        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "colist".to_string(),
            uniqueness: Uniqueness::String("colisttest".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");

        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, true).unwrap();

        let mut tx_objs: Vec<String> = Vec::new();
        for (i, changes) in txns.iter().enumerate() {
            let made_at = 1_700_000_000_000u64 + i as u64;
            let changes_str = serde_json::to_string(changes).unwrap();
            tx_objs.push(format!(
                r#"{{"privacy":"trusting","madeAt":{made_at},"changes":{}}}"#,
                serde_json::to_string(&changes_str).unwrap(),
            ));
        }
        let txs_json = format!("[{}]", tx_objs.join(","));
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session_id, None, &txs_json, "signature_zFake", true)
            .unwrap();
        (node, co_id)
    }

    fn snapshot(node: &mut NodeCore, co_id: &str) -> serde_json::Value {
        node.list_materialize(co_id, &[]).unwrap();
        serde_json::from_str(&node.list_snapshot(co_id).unwrap()).unwrap()
    }

    // opID helper for building anchored changes.
    fn opid(session: &str, tx_index: u32, change_idx: u32) -> serde_json::Value {
        serde_json::json!({"sessionID": session, "txIndex": tx_index, "changeIdx": change_idx})
    }

    #[test]
    fn appends_after_start_preserve_order() {
        let s = "co_zA_session_zS";
        // tx0: app "a" after start. tx1: app "b" after (s,0,0). tx2: app "c" after (s,1,0).
        let (mut node, co_id) = make_list(
            s,
            &[
                serde_json::json!([{"op":"app","value":"a","after":"start"}]),
                serde_json::json!([{"op":"app","value":"b","after":opid(s,0,0)}]),
                serde_json::json!([{"op":"app","value":"c","after":opid(s,1,0)}]),
            ],
        );
        assert_eq!(snapshot(&mut node, &co_id), serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn prepend_before_end_and_delete() {
        let s = "co_zA_session_zS";
        // tx0: pre "a" before end. tx1: pre "b" before end (goes before a? no: both roots
        // in beforeEnd, order = insertion order → a then b). tx2: del (s,0,0) → removes "a".
        let (mut node, co_id) = make_list(
            s,
            &[
                serde_json::json!([{"op":"pre","value":"a","before":"end"}]),
                serde_json::json!([{"op":"pre","value":"b","before":"end"}]),
                serde_json::json!([{"op":"del","insertion":opid(s,0,0)}]),
            ],
        );
        assert_eq!(snapshot(&mut node, &co_id), serde_json::json!(["b"]));
    }

    #[test]
    fn insert_after_deleted_item_still_links() {
        let s = "co_zA_session_zS";
        // a, b after a, del a, c after a (deleted anchor still resolves).
        let (mut node, co_id) = make_list(
            s,
            &[
                serde_json::json!([{"op":"app","value":"a","after":"start"}]),
                serde_json::json!([{"op":"app","value":"b","after":opid(s,0,0)}]),
                serde_json::json!([{"op":"del","insertion":opid(s,0,0)}]),
                serde_json::json!([{"op":"app","value":"c","after":opid(s,0,0)}]),
            ],
        );
        // "a" tombstoned; b and c both anchored after a. Successors of a =
        // [b, c] in insertion order; DFS pushes b then c (stack pops c first,
        // emits c, then b) — matches TS successors-in-reverse behavior.
        let snap = snapshot(&mut node, &co_id);
        // a is deleted; remaining are c then b per the stack order.
        assert_eq!(snap, serde_json::json!(["c", "b"]));
    }

    #[test]
    fn entries_carry_opid_and_madeat() {
        let s = "co_zA_session_zS";
        let (mut node, co_id) = make_list(
            s,
            &[serde_json::json!([{"op":"app","value":"x","after":"start"}])],
        );
        node.list_materialize(&co_id, &[]).unwrap();
        let entries: serde_json::Value =
            serde_json::from_str(&node.list_entries(&co_id).unwrap()).unwrap();
        assert_eq!(entries[0]["value"], serde_json::json!("x"));
        assert_eq!(entries[0]["madeAt"], serde_json::json!(1_700_000_000_000u64));
        assert_eq!(entries[0]["opID"]["sessionID"], serde_json::json!(s));
        assert_eq!(entries[0]["opID"]["txIndex"], serde_json::json!(0));
        assert_eq!(entries[0]["opID"]["changeIdx"], serde_json::json!(0));
        assert!(entries[0]["opID"].get("branch").is_none());
    }

    #[test]
    fn version_bumps_on_new_transactions() {
        let s = "co_zA_session_zS";
        let (mut node, co_id) = make_list(
            s,
            &[serde_json::json!([{"op":"app","value":"a","after":"start"}])],
        );
        let v1 = node.list_materialize(&co_id, &[]).unwrap();
        // Re-materialize with no change → same version (cached).
        assert_eq!(node.list_materialize(&co_id, &[]).unwrap(), v1);

        let made = 1_700_000_001_000u64;
        let changes = serde_json::to_string(
            &serde_json::json!([{"op":"app","value":"b","after":opid(s,0,0)}]),
        )
        .unwrap();
        let more = format!(
            r#"[{{"privacy":"trusting","madeAt":{made},"changes":{}}}]"#,
            serde_json::to_string(&changes).unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(s, None, &more, "signature_zFake", true)
            .unwrap();
        let v2 = node.list_materialize(&co_id, &[]).unwrap();
        assert!(v2 > v1, "version bumps on append");
        assert_eq!(
            snapshot(&mut node, &co_id),
            serde_json::json!(["a", "b"])
        );
    }

    #[test]
    fn concurrent_appends_at_same_anchor_use_global_sort() {
        // Two sessions both append after start. The global sort orders by
        // (madeAt, session, txIndex); afterStart is filled in that order.
        let s1 = "co_zA_session_zS1";
        let s2 = "co_zA_session_zS2";
        let (mut node, co_id) = make_list(
            s1,
            &[serde_json::json!([{"op":"app","value":"a1","after":"start"}])],
        );
        // s2 appends after start with a LATER madeAt so it sorts after s1.
        let made = 1_700_000_005_000u64;
        let changes =
            serde_json::to_string(&serde_json::json!([{"op":"app","value":"a2","after":"start"}]))
                .unwrap();
        let tx = format!(
            r#"[{{"privacy":"trusting","madeAt":{made},"changes":{}}}]"#,
            serde_json::to_string(&changes).unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(s2, None, &tx, "signature_zFake", true)
            .unwrap();
        // afterStart = [a1, a2]; DFS emits both roots in that order.
        assert_eq!(snapshot(&mut node, &co_id), serde_json::json!(["a1", "a2"]));
    }
}

// =====================================================================
// CONTENT fixtures — replay coList fixtures captured from the CURRENT TS
// `RawCoList` (exported by
// `packages/cojson/src/tests/coListContentFixtures.export.test.ts`) and assert
// the Rust materialization reproduces `asArray()` (snapshot) + the ordered
// `entries()` (value + madeAt + opID, incl. branch-namespaced opIDs on merged
// transactions) byte-for-byte. One test per `data/co_list_content/*.json`.
// These FREEZE the coList content contract, including the branch/merge cases.
// =====================================================================
#[cfg(test)]
mod content_fixture_tests {
    use crate::core::group_engine::tx_view::fixtures::FixtureCovalue;
    use crate::core::node::NodeCore;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ProvideKey {
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "keySecret")]
        key_secret: String,
    }
    #[derive(Deserialize)]
    struct ContentFixture {
        covalues: Vec<FixtureCovalue>,
        #[serde(rename = "listId")]
        list_id: String,
        #[serde(rename = "provideKeys")]
        provide_keys: Vec<ProvideKey>,
        snapshot: serde_json::Value,
        entries: serde_json::Value,
    }

    fn load(name: &str) -> ContentFixture {
        let path = format!("data/co_list_content/{name}.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    fn run(name: &str) {
        let fix = load(name);
        let mut node = NodeCore::new();
        // Ingest every covalue's raw sessions (owning group first, then list).
        for cov in &fix.covalues {
            node.create_co_value(&cov.co_id, &cov.header_json, None, true)
                .unwrap_or_else(|e| panic!("[{name}] create {}: {e}", cov.co_id));
            for s in &cov.sessions {
                let txs_json = format!("[{}]", s.transactions.join(","));
                node.get_mut(&cov.co_id)
                    .unwrap()
                    .add_transactions(&s.session_id, None, &txs_json, &s.last_signature, true)
                    .unwrap_or_else(|e| panic!("[{name}] add txs {}: {e}", s.session_id));
            }
        }
        for k in &fix.provide_keys {
            node.provide_key_secret(&k.key_id, &k.key_secret);
        }
        node.list_materialize(&fix.list_id, &[])
            .unwrap_or_else(|e| panic!("[{name}] materialize: {e}"));

        // (1) snapshot == asArray().
        let snap: serde_json::Value =
            serde_json::from_str(&node.list_snapshot(&fix.list_id).unwrap()).unwrap();
        assert_eq!(snap, fix.snapshot, "[{name}] snapshot mismatch");

        // (2) ordered entries == entries() (value + madeAt + opID, incl. branch).
        let entries: serde_json::Value =
            serde_json::from_str(&node.list_entries(&fix.list_id).unwrap()).unwrap();
        assert_eq!(entries, fix.entries, "[{name}] entries mismatch");
    }

    #[test]
    fn sequential_list() {
        run("sequential_list");
    }
    #[test]
    fn private_list() {
        run("private_list");
    }
    #[test]
    fn branch_merge_list() {
        run("branch_merge_list");
    }
    #[test]
    fn concurrent_branches_list() {
        run("concurrent_branches_list");
    }
}
