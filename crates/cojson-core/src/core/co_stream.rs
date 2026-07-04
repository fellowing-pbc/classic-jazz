//! Rust-resident coStream/coFeed materialization (R4a).
//!
//! Materializes a coStream's per-session ordered entry log over the VALID
//! transaction set of a covalue, reusing the group engine's verdicts (permission
//! validation), the `tx_view` collection/ordering primitives, and the R1 key
//! store — exactly as [`crate::core::co_map`] does. A coStream is structurally
//! SIMPLER than a coMap: it is per-session APPEND-ONLY (no per-key indexing, no
//! last-writer-wins, no `del`). Each valid transaction contributes one entry PER
//! change in its `changes` array; the change value IS the pushed item (there is
//! no `{op,key,value}` envelope — `RawCoStream.push` does
//! `makeTransaction([item], privacy)`, so each `changes` element is a whole
//! item).
//!
//! ## Semantics mirrored from `packages/cojson/src/coValues/coStream.ts`
//!
//! - `items[sessionID]` — the entries whose (source-adjusted) `txID.sessionID`
//!   equals `sessionID`, each `{value, tx, madeAt}`, sorted by
//!   `compareStreamItems` (madeAt asc; ties within a session by txIndex). Because
//!   all entries in one bucket share the same effective session id, that
//!   comparator collapses to `(madeAt, txIndex)`; we insert in
//!   [`sort_for_validation`] order (which is exactly `compareTransactions`
//!   order), so each bucket is already sorted, and [`TimeBasedEntry::add_change`]
//!   keeps it sorted even for an out-of-order `madeAt` (a backdated merge).
//! - `toJSON()` — `{sessionID: [value, ...]}`, each session's entry VALUES in
//!   order. This is [`CoStreamView::snapshot`].
//! - the per-entry `tx = txID = sourceTxID ?? currentTxID` and `madeAt =
//!   sourceTxMadeAt ?? currentMadeAt` are the SOURCE identity/time for a merged
//!   transaction (`coValueCore.ts:157-163`), so the bucket key and each entry's
//!   `tx.txIndex`/`madeAt` use the same source-adjusted `(session, tx_index,
//!   effective_made_at)` the coMap port uses via [`tx_id_of`].
//! - `atFrontier(f)` — a session's entries truncated to `txID.txIndex <
//!   f[txID.sessionID]` (default-exclude, `?? -1`); same predicate as the coMap
//!   frontier filter.
//!
//! ## fww overlay
//!
//! coStream `push` never attaches `meta.fww`, so in practice no stream entry is
//! ever an fww loser. But `coValueCore.getValidTransactions` runs
//! `parseMetaInformation` (and its fww winner selection) for EVERY covalue type,
//! so to stay byte-for-byte identical to the TS valid set we mirror the SAME fww
//! overlay [`crate::core::co_map`] uses (winner = first in
//! `compareTransactions` order among permission-valid competitors for a key).
//! When no entry carries fww (the universal stream case) `has_fww` stays false
//! and the append fast-path stays enabled.
//!
//! ## Freshness and the incremental append fast-path
//!
//! Identical strategy to the coMap view: a [`CoStreamView`] is cached per
//! covalue keyed by per-session tx-counts, the engine generation, and the node
//! keys-version. The append fast-path (append the newly-validated txs' entries
//! into the existing buckets) is taken only when the engine EXTENDED (old
//! verdicts provably unchanged), no fww is present, and no key-version bump
//! happened; otherwise a full recompute (always correct) runs. Because a stream
//! is append-only, an append never REMOVES an entry, so the only reason a stale
//! delta cursor must fully resync (`reset`) is a full recompute (a verdict flip
//! or a late key arrival re-timing history).

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde_json::Value as JsonValue;

use crate::core::group_engine::engine::{
    ensure as engine_ensure, generation_of, verdicts_of, GroupEngineState, Verdict,
};
use crate::core::group_engine::tx_view::{
    collect_group_txs_after, collect_group_txs_keyed, sort_for_validation, GroupTxView,
    PendingTxIn, Privacy,
};
use crate::core::group_engine::types::TimeBasedEntry;
use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// One materialized coStream entry: the `CoStreamItem` shape from
/// `coStream.ts:13-17` minus the bucket's session id (that is the map key, not
/// duplicated per entry):
///
/// ```ts
/// type CoStreamItem = { value: Item; tx: TransactionID; madeAt: number };
/// ```
///
/// - `tx_index` — `txID.txIndex` (source-adjusted).
/// - `made_at` — the effective ordering time and the TS `madeAt` field (also the
///   [`TimeBasedEntry`] sort key so ordering/frontier stay correct).
/// - `value` — the whole pushed item (a coStream change is the item itself).
#[derive(Debug, Clone, PartialEq)]
pub struct StreamEntry {
    /// `txID.txIndex` (source-adjusted).
    pub tx_index: u32,
    /// `madeAt` (effective; equals the [`TimeBasedEntry`] sort key).
    pub made_at: u64,
    /// The pushed item value.
    pub value: JsonValue,
}

impl StreamEntry {
    /// Write this entry as compact JSON in the TS `CoStreamItem` shape
    /// (`{"value":…,"tx":{"sessionID":…,"txIndex":…},"madeAt":…}`) directly into
    /// `out`, with no intermediate `Value` tree — a full delta serializes one of
    /// these per entry across every session, so avoiding the tree-then-stringify
    /// double pass matters at scale. `session_id` is the bucket key (the entry's
    /// `tx.sessionID`).
    fn write_json(&self, session_id: &str, out: &mut String) {
        use std::fmt::Write as _;
        out.push_str("{\"value\":");
        // `Value`'s `Display` streams through serde_json's own compact
        // serializer, embedding the already-parsed value with no extra alloc.
        let _ = write!(out, "{}", self.value);
        out.push_str(",\"tx\":{\"sessionID\":");
        write_json_escaped_str(session_id, out);
        out.push_str(",\"txIndex\":");
        let _ = write!(out, "{}", self.tx_index);
        out.push_str("},\"madeAt\":");
        let _ = write!(out, "{}", self.made_at);
        out.push('}');
    }

    /// `entry.tx.txIndex < (frontier[entry.tx.sessionID] ?? -1)` — the
    /// `atFrontierFilter` include predicate (`coStream.ts:120-123` inverted:
    /// TS `continue`s — excludes — when `txIndex >= frontier`). Default-exclude:
    /// a session absent from the frontier reads as `-1`.
    fn in_frontier(&self, session_id: &str, frontier: &HashMap<String, i64>) -> bool {
        (self.tx_index as i64) < frontier.get(session_id).copied().unwrap_or(-1)
    }
}

/// Write `s` as a JSON string literal (quotes + escaping) directly into `out`,
/// via `Value::String`'s `Display` impl (streams through serde_json's compact
/// serializer). Used for arbitrary (id-shaped) session ids.
fn write_json_escaped_str(s: &str, out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(out, "{}", JsonValue::String(s.to_string()));
}

/// A cached, materialized coStream view for one covalue.
pub struct CoStreamView {
    /// `(session_id, tx_count)` snapshot — the cache-validity key.
    session_counts: Vec<(String, u32)>,
    /// Per-(effective-)session ordered entries. `IndexMap` so session iteration
    /// is first-appearance order (deterministic output). Each bucket is a
    /// [`TimeBasedEntry`] keyed by `made_at` so ordering, `atFrontier`, and
    /// out-of-order (backdated-merge) inserts stay correct.
    sessions: IndexMap<String, TimeBasedEntry<StreamEntry>>,
    /// Verdict count this view was last materialized against — the append
    /// fast-path treats `verdicts[verdict_count..]` as exactly the new txs.
    verdict_count: usize,
    /// The engine full-recompute generation this view was built against. A
    /// change means verdicts were rebuilt (possibly reordered/flipped) so the
    /// view must fully rebuild rather than append.
    engine_generation: u64,
    /// True if any collected tx carried a `meta.fww` key. Disables the append
    /// fast-path (fww needs a global winner recompute).
    has_fww: bool,
    /// Monotonic version, bumped once per ingest batch. The delta cursor.
    version: u64,
    /// The `version` assigned by the most recent FULL recompute. A delta caller
    /// whose cursor predates this missed a recompute (a verdict flip or a late
    /// key arrival could have re-timed/removed entries — things an append-only
    /// patch cannot express), so it is told to `reset` and rebuild from the full
    /// session map. On the append fast-path this stays put.
    last_full_version: u64,
    /// `session_id -> version at which this session last gained entries`. Drives
    /// the delta's changed-session selection.
    session_versions: HashMap<String, u64>,
    /// The `NodeCore` keys-version this view was built against. Part of the
    /// freshness key: when a secret arrives (bumping the node's keys-version) a
    /// previously-undecryptable PRIVATE tx may now join, so the view rebuilds
    /// even if no new transaction arrived.
    keys_version: u64,
    /// `KeyID`s of PRIVATE transactions whose secret was unavailable at build
    /// time (their txs were SKIPPED, mirroring TS: an undecryptable tx does not
    /// contribute). Exposed so the TS delegation can drive key acquisition.
    missing_key_ids: HashSet<String>,
}

impl CoStreamView {
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The `KeyID`s this view still needs a secret for (sorted, deterministic).
    pub fn missing_key_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.missing_key_ids.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// Whole materialized stream as `{sessionID: [value, ...]}` (each session's
    /// entry VALUES in order), matching `RawCoStream.toJSON`.
    pub fn snapshot(&self) -> JsonValue {
        let mut obj = serde_json::Map::new();
        for (sid, entries) in &self.sessions {
            let values: Vec<JsonValue> = entries.iter_values().map(|e| e.value.clone()).collect();
            obj.insert(sid.clone(), JsonValue::Array(values));
        }
        JsonValue::Object(obj)
    }

    /// `toJSON` under an `atFrontier` view: each session truncated to entries
    /// whose `tx.txIndex < frontier[sessionID]`. A session with no visible entry
    /// is omitted (matches TS, where such a session never gets an `items` array).
    pub fn snapshot_at_frontier(&self, frontier: &HashMap<String, i64>) -> JsonValue {
        let mut obj = serde_json::Map::new();
        for (sid, entries) in &self.sessions {
            let values: Vec<JsonValue> = entries
                .iter_values()
                .filter(|e| e.in_frontier(sid, frontier))
                .map(|e| e.value.clone())
                .collect();
            if !values.is_empty() {
                obj.insert(sid.clone(), JsonValue::Array(values));
            }
        }
        JsonValue::Object(obj)
    }

    /// RICH delta: `{version, reset, sessions}` where each `sessions[sid]` is the
    /// FULL ordered entry-list (`CoStreamItem[]`) for a session that changed
    /// since `since_version` — the payload a TS `RawCoStream` needs to rebuild
    /// its `items[sid]` verbatim. Serialized ONCE per delta.
    ///
    /// `reset` is set when `since_version < last_full_version` — the caller
    /// missed a full recompute (which can re-time or drop entries), so it clears
    /// its `items` and rebuilds from `sessions` (which, because a full recompute
    /// stamps every current session at the new version, carries the COMPLETE
    /// current state). On the append fast-path `reset` is false and only the
    /// grown sessions are sent, so a caught-up caller applies an incremental
    /// patch (re-adopting a changed session's full — grown — entry array).
    ///
    /// Returns the compact JSON STRING directly (not a `serde_json::Value`),
    /// writing each entry straight into the buffer via [`StreamEntry::write_json`]
    /// — the hot path is a stream's FIRST full construction (`since_version = 0`,
    /// every session changed).
    pub fn delta(&self, since_version: u64) -> String {
        let reset = since_version < self.last_full_version;
        let mut out = String::with_capacity(64);
        out.push_str("{\"version\":");
        {
            use std::fmt::Write as _;
            let _ = write!(out, "{}", self.version);
        }
        out.push_str(",\"reset\":");
        out.push_str(if reset { "true" } else { "false" });
        out.push_str(",\"sessions\":{");
        let mut first_session = true;
        // Iterate in `self.sessions`'s (an `IndexMap`) first-appearance order,
        // NOT `self.session_versions`'s (a `HashMap` — randomized per-process
        // iteration order, not a stable contract).
        for sid in self.sessions.keys() {
            let ver = match self.session_versions.get(sid) {
                Some(v) => *v,
                None => continue,
            };
            if reset || ver > since_version {
                if let Some(entries) = self.sessions.get(sid) {
                    if !first_session {
                        out.push(',');
                    }
                    first_session = false;
                    write_json_escaped_str(sid, &mut out);
                    out.push_str(":[");
                    let mut first_entry = true;
                    for entry in entries.iter_values() {
                        if !first_entry {
                            out.push(',');
                        }
                        first_entry = false;
                        entry.write_json(sid, &mut out);
                    }
                    out.push(']');
                }
            }
        }
        out.push_str("}}");
        out
    }

    /// PROFILING helper: produce the same delta STRING as [`Self::delta`] but
    /// return only its byte length. Lets a bench isolate the Rust-side
    /// serialization cost from the napi string-marshaling cost (the full
    /// `delta` pays both; this pays only serialization — a single `f64` crosses
    /// FFI). Not used by any product path.
    pub fn delta_byte_len(&self, since_version: u64) -> usize {
        self.delta(since_version).len()
    }

    /// BINARY delta channel (proof-of-concept, R4a Step 2): the SAME logical
    /// payload as [`Self::delta`] packed into a length-prefixed little-endian
    /// byte buffer instead of a JSON string, so the TS side can decode it with
    /// `DataView` reads and skip `JSON.parse` of a multi-kilobyte string.
    ///
    /// Two structural wins over the JSON channel exploited here:
    ///  - the per-entry `tx.sessionID` is ALWAYS the bucket session id, so it is
    ///    stored ONCE per session (the bucket key) not once per entry.
    ///  - scalar values (number / short string / null / bool — the bulk of a
    ///    real feed) are type-tagged and copied raw, so the common case needs no
    ///    JSON decode at all; only composite values (arrays/objects) fall back to
    ///    a length-prefixed JSON blob the TS side `JSON.parse`s individually.
    ///
    /// Layout (all integers little-endian):
    /// ```text
    ///   u64  version
    ///   u8   reset (0|1)
    ///   u32  session_count
    ///   repeat session_count times:
    ///     u32  sid_len ; [sid_len] sid utf8
    ///     u32  entry_count
    ///     repeat entry_count times:
    ///       f64  made_at
    ///       u32  tx_index
    ///       u8   tag
    ///       tag payload:
    ///         1 => f64 number (8 bytes)
    ///         2 => u32 str_len ; [str_len] utf8
    ///         3 => null   (no payload)
    ///         4 => true   (no payload)
    ///         5 => false  (no payload)
    ///         0 => u32 json_len ; [json_len] utf8 (JSON.parse fallback)
    /// ```
    pub fn delta_binary(&self, since_version: u64) -> Vec<u8> {
        let reset = since_version < self.last_full_version;
        let mut out: Vec<u8> = Vec::with_capacity(4096);

        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(if reset { 1 } else { 0 });

        // Reserve the session-count slot; backfill once we know how many we wrote.
        let sc_pos = out.len();
        out.extend_from_slice(&0u32.to_le_bytes());
        let mut session_count: u32 = 0;

        for sid in self.sessions.keys() {
            let ver = match self.session_versions.get(sid) {
                Some(v) => *v,
                None => continue,
            };
            if !(reset || ver > since_version) {
                continue;
            }
            let entries = match self.sessions.get(sid) {
                Some(e) => e,
                None => continue,
            };
            session_count += 1;

            let sid_bytes = sid.as_bytes();
            out.extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(sid_bytes);

            let ec_pos = out.len();
            out.extend_from_slice(&0u32.to_le_bytes());
            let mut entry_count: u32 = 0;
            for entry in entries.iter_values() {
                entry_count += 1;
                out.extend_from_slice(&(entry.made_at as f64).to_le_bytes());
                out.extend_from_slice(&entry.tx_index.to_le_bytes());
                write_value_binary(&entry.value, &mut out);
            }
            out[ec_pos..ec_pos + 4].copy_from_slice(&entry_count.to_le_bytes());
        }
        out[sc_pos..sc_pos + 4].copy_from_slice(&session_count.to_le_bytes());
        out
    }
}

/// Encode one entry value into the binary delta buffer (see
/// [`CoStreamView::delta_binary`] for the tag table). Scalars are copied raw;
/// composites fall back to a length-prefixed JSON blob.
fn write_value_binary(value: &JsonValue, out: &mut Vec<u8>) {
    match value {
        JsonValue::Number(n) => {
            if let Some(f) = n.as_f64() {
                out.push(1);
                out.extend_from_slice(&f.to_le_bytes());
            } else {
                write_json_blob(value, out);
            }
        }
        JsonValue::String(s) => {
            out.push(2);
            let b = s.as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        JsonValue::Null => out.push(3),
        JsonValue::Bool(true) => out.push(4),
        JsonValue::Bool(false) => out.push(5),
        JsonValue::Array(_) | JsonValue::Object(_) => write_json_blob(value, out),
    }
}

/// Tag-0 fallback: the value serialized as a JSON blob (length-prefixed), for
/// composite values the scalar fast-path does not cover.
fn write_json_blob(value: &JsonValue, out: &mut Vec<u8>) {
    out.push(0);
    let json = value.to_string();
    let b = json.as_bytes();
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
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

/// The (source-adjusted) effective identity of a transaction: its SOURCE
/// `(sessionID, txIndex)` when merged (`sourceTxID ?? currentTxID`,
/// `coValueCore.ts:157`), else its stored `(session_id, tx_index)`. This is the
/// bucket key and the entry `tx` a coStream records.
fn tx_id_of(tx: &GroupTxView) -> (String, u32) {
    (
        tx.source_session_id
            .clone()
            .unwrap_or_else(|| tx.session_id.clone()),
        tx.source_tx_index.unwrap_or(tx.tx_index),
    )
}

/// Append every change of `changes` as an entry under the tx's effective
/// session bucket, returning the session id it touched (so the caller can bump
/// its version). The change value IS the item (no `{op,key,value}` envelope).
fn append_entries(
    sessions: &mut IndexMap<String, TimeBasedEntry<StreamEntry>>,
    tx: &GroupTxView,
    changes: impl ExactSizeIterator<Item = JsonValue>,
) -> Option<String> {
    if changes.len() == 0 {
        return None;
    }
    let (session_id, tx_index) = tx_id_of(tx);
    let bucket = sessions.entry(session_id.clone()).or_default();
    for change in changes {
        bucket.add_change(
            tx.effective_made_at,
            StreamEntry {
                tx_index,
                made_at: tx.effective_made_at,
                // The value is MOVED in (the private decrypt path hands us an
                // owned, about-to-be-dropped `Vec<JsonValue>`; the trusting path
                // clones at the call site since it only holds a borrow).
                value: change,
            },
        );
    }
    Some(session_id)
}

/// Decrypt a PRIVATE tx's changes into a parsed item array, reusing the session
/// map's decrypt primitive. Returns `None` when the tx does not decrypt to a
/// usable array (wrong/garbage key, or missing session) — the caller SKIPS it,
/// as TS drops an undecryptable tx from its views.
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

/// Index one valid tx's entries into the per-session buckets, decrypting a
/// PRIVATE tx via the key store. Records the tx's `keyUsed` in `missing` (and
/// contributes nothing) when its secret is not yet available. `touched` collects
/// the session this tx changed so the caller can bump its version.
fn index_tx(
    sessions: &mut IndexMap<String, TimeBasedEntry<StreamEntry>>,
    sm: &SessionMapImpl,
    keys: &HashMap<String, String>,
    missing: &mut HashSet<String>,
    tx: &GroupTxView,
    touched: &mut dyn FnMut(String),
) {
    match tx.privacy {
        Privacy::Trusting => {
            if let Some(changes) = &tx.changes {
                // Trusting changes live inside the borrowed `GroupTxView`, so the
                // values must be cloned to be owned by the entries.
                if let Some(sid) = append_entries(sessions, tx, changes.iter().cloned()) {
                    touched(sid);
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
                // The decrypted `Vec` is owned and dropped right after: MOVE its
                // values into the entries rather than cloning them.
                if let Some(sid) = append_entries(sessions, tx, changes.into_iter()) {
                    touched(sid);
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

/// fww winner selection over sorted txs (see the module doc + `co_map`'s
/// identical overlay): the first permission-valid tx for a given fww key wins;
/// later ones are losers (excluded). Returns `(losers, has_fww)`.
fn fww_losers(
    txs: &[GroupTxView],
    valid: &HashSet<(String, u32)>,
) -> (HashSet<(String, u32)>, bool) {
    let mut fww_seen: HashSet<String> = HashSet::new();
    let mut losers: HashSet<(String, u32)> = HashSet::new();
    let mut has_fww = false;
    for tx in txs {
        if let Some(fk) = fww_key(tx) {
            has_fww = true;
            let id = (tx.session_id.clone(), tx.tx_index);
            if !valid.contains(&id) {
                continue;
            }
            if !fww_seen.insert(fk.to_string()) {
                losers.insert(id);
            }
        }
    }
    (losers, has_fww)
}

/// Full recompute of a covalue's coStream view over its whole valid tx set +
/// fww, decrypting private txs against `keys` and recording missing key ids.
#[allow(clippy::too_many_arguments)]
fn build_full_view(
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: Vec<(String, u32)>,
    pending: &[PendingTxIn],
    keys: &HashMap<String, String>,
    keys_version: u64,
    engine_generation: u64,
    version: u64,
) -> CoStreamView {
    let mut txs = collect_group_txs_keyed(sm, pending, keys);
    sort_for_validation(&mut txs);

    let valid = valid_set(verdicts);
    let (losers, has_fww) = fww_losers(&txs, &valid);

    let mut sessions: IndexMap<String, TimeBasedEntry<StreamEntry>> = IndexMap::new();
    let mut missing_key_ids: HashSet<String> = HashSet::new();
    let mut touched = |_s: String| {}; // full recompute marks all sessions below
    for tx in &txs {
        let id = (tx.session_id.clone(), tx.tx_index);
        if !valid.contains(&id) || losers.contains(&id) {
            continue;
        }
        index_tx(
            &mut sessions,
            sm,
            keys,
            &mut missing_key_ids,
            tx,
            &mut touched,
        );
    }

    // A full recompute conservatively stamps every current session at this
    // version so any stale delta cursor resyncs the whole stream.
    let mut session_versions = HashMap::new();
    for sid in sessions.keys() {
        session_versions.insert(sid.clone(), version);
    }

    CoStreamView {
        session_counts: counts,
        sessions,
        verdict_count: verdicts.len(),
        engine_generation,
        has_fww,
        version,
        last_full_version: version,
        session_versions,
        keys_version,
        missing_key_ids,
    }
}

/// Append the newly-ingested transactions to `view` in place, returning `true`
/// on success or `false` (leaving `view` untouched) if the fast-path does not
/// apply and the caller must full-recompute.
///
/// PRECONDITION: the caller invokes this ONLY when the group engine reported it
/// EXTENDED (old verdicts provably unchanged, new verdicts appended at the
/// tail), so `verdicts[view.verdict_count..]` is exactly the new txs' verdicts.
fn try_append(
    view: &mut CoStreamView,
    sm: &SessionMapImpl,
    verdicts: &[Verdict],
    counts: &[(String, u32)],
    pending: &[PendingTxIn],
    keys: &HashMap<String, String>,
) -> bool {
    // fww can flip a winner retroactively — needs a full recompute.
    if view.has_fww {
        return false;
    }
    // The engine extended, so the verdict list only grew (defensive check).
    if verdicts.len() < view.verdict_count {
        return false;
    }

    let valid_new: HashSet<(String, u32)> = verdicts[view.verdict_count..]
        .iter()
        .filter(|v| v.valid)
        .map(|v| (v.session_id.clone(), v.tx_index))
        .collect();

    let old_counts: HashMap<String, u32> = view
        .session_counts
        .iter()
        .map(|(s, c)| (s.clone(), *c))
        .collect();
    let mut new_txs = collect_group_txs_after(sm, pending, &old_counts, keys);
    sort_for_validation(&mut new_txs);

    // No newly-appended tx may carry an fww key.
    for tx in &new_txs {
        if fww_key(tx).is_some() {
            return false;
        }
    }

    view.version += 1;
    let ver = view.version;
    let CoStreamView {
        sessions,
        session_versions,
        missing_key_ids,
        ..
    } = &mut *view;
    for tx in &new_txs {
        let id = (tx.session_id.clone(), tx.tx_index);
        if !valid_new.contains(&id) {
            continue;
        }
        index_tx(sessions, sm, keys, missing_key_ids, tx, &mut |s| {
            session_versions.insert(s, ver);
        });
    }
    view.verdict_count = verdicts.len();
    view.session_counts = counts.to_vec();
    true
}

/// Whether `view` can safely take the append fast-path: the engine has not
/// full-recomputed since the view was built (same generation), and no
/// key-version bump happened. When false, the caller rebuilds.
fn can_append(view: &CoStreamView, engine_generation: u64, keys_version: u64) -> bool {
    view.engine_generation == engine_generation && view.keys_version == keys_version
}

/// Ensure `co_id`'s coStream view is fresh (materializing on demand), returning
/// its current version. Reuses the engine verdicts and takes the incremental
/// append fast-path when safe. Operates on `NodeCore`'s disjoint field borrows.
#[allow(clippy::too_many_arguments)]
pub fn ensure_co_stream(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_streams: &mut HashMap<String, CoStreamView>,
    keys: &HashMap<String, String>,
    keys_version: u64,
    co_id: &str,
    pending: &[PendingTxIn],
) -> Result<u64, SessionMapError> {
    engine_ensure(covalues, engines, keys, keys_version, co_id, pending)?;
    let verdicts = verdicts_of(engines, co_id);
    let engine_generation = generation_of(engines, co_id);
    let sm = covalues
        .get(co_id)
        .ok_or_else(|| SessionMapError::CoValueNotLoaded(co_id.to_string()))?;
    let counts = session_counts_of(sm);

    let need_full = match co_streams.get_mut(co_id) {
        Some(view) => {
            if view.session_counts == counts && view.keys_version == keys_version {
                return Ok(view.version);
            }
            if !can_append(view, engine_generation, keys_version) {
                true
            } else {
                !try_append(view, sm, verdicts, &counts, pending, keys)
            }
        }
        None => true,
    };

    if need_full {
        let version = co_streams.get(co_id).map(|v| v.version).unwrap_or(0) + 1;
        let view = build_full_view(
            sm,
            verdicts,
            counts,
            pending,
            keys,
            keys_version,
            engine_generation,
            version,
        );
        co_streams.insert(co_id.to_string(), view);
    }

    Ok(co_streams.get(co_id).map(|v| v.version).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use crate::core::node::NodeCore;

    // A minimal unsafeAllowAll costream covalue: header + a single session of
    // trusting transactions, each pushing one item. Every trusting tx is valid
    // (unsafeAllowAll), isolating content materialization.
    fn make_stream(session_id: &str, items: &[serde_json::Value]) -> (NodeCore, String) {
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};
        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "costream".to_string(),
            uniqueness: Uniqueness::String("costreamtest".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");

        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, true)
            .unwrap();

        let mut tx_objs: Vec<String> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let made_at = 1_700_000_000_000u64 + i as u64;
            // A costream tx's changes array is `[item]` — the item IS the change.
            let changes = serde_json::to_string(&serde_json::json!([item])).unwrap();
            tx_objs.push(format!(
                r#"{{"privacy":"trusting","madeAt":{made_at},"changes":{}}}"#,
                serde_json::to_string(&changes).unwrap(),
            ));
        }
        let txs_json = format!("[{}]", tx_objs.join(","));
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session_id, None, &txs_json, "signature_zFake", true)
            .unwrap();

        (node, co_id)
    }

    fn test_key_secret(byte: u8) -> String {
        format!("keySecret_z{}", bs58::encode([byte; 32]).into_string())
    }

    /// An unsafeAllowAll costream whose single session is a run of PRIVATE
    /// transactions (each pushing one item) encrypted under `(key_id, secret)`.
    fn make_private_stream(
        session_id: &str,
        key_id: &str,
        key_secret: &str,
        items: &[serde_json::Value],
    ) -> (NodeCore, String) {
        use crate::core::keys::SignerSecret;
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "costream".to_string(),
            uniqueness: Uniqueness::String("privcostreamtest".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");

        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, true)
            .unwrap();

        let signer = SignerSecret::from(SigningKey::generate(&mut OsRng)).0;
        for (i, item) in items.iter().enumerate() {
            let made_at = 1_700_000_000_000u64 + i as u64;
            let changes_json = serde_json::to_string(&serde_json::json!([item])).unwrap();
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
    fn snapshot_preserves_per_session_order() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_stream(
            session,
            &[
                serde_json::json!("a"),
                serde_json::json!({"n": 1}),
                serde_json::json!("b"),
            ],
        );
        node.stream_materialize(&co_id, &[]).unwrap();
        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({ session: ["a", {"n": 1}, "b"] }));
    }

    #[test]
    fn delta_carries_full_entries_with_tx_metadata() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) =
            make_stream(session, &[serde_json::json!("a"), serde_json::json!("b")]);
        node.stream_materialize(&co_id, &[]).unwrap();

        let delta: serde_json::Value =
            serde_json::from_str(&node.stream_delta(&co_id, 0).unwrap()).unwrap();
        assert_eq!(
            delta["reset"],
            serde_json::json!(true),
            "fresh cursor resyncs"
        );
        let entries = delta["sessions"][session].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["value"], serde_json::json!("a"));
        assert_eq!(
            entries[0]["madeAt"],
            serde_json::json!(1_700_000_000_000u64)
        );
        assert_eq!(entries[0]["tx"]["sessionID"], serde_json::json!(session));
        assert_eq!(entries[0]["tx"]["txIndex"], serde_json::json!(0));
        assert_eq!(entries[1]["tx"]["txIndex"], serde_json::json!(1));
    }

    #[test]
    fn multi_session_streams_are_bucketed() {
        let s1 = "co_zA_session_zS1";
        let s2 = "co_zA_session_zS2";
        let (mut node, co_id) =
            make_stream(s1, &[serde_json::json!("x1"), serde_json::json!("x2")]);
        // Append a second session with its own items.
        let made = 1_700_000_000_500u64;
        let tx = format!(
            r#"[{{"privacy":"trusting","madeAt":{made},"changes":{}}}]"#,
            serde_json::to_string(
                &serde_json::to_string(&serde_json::json!([serde_json::json!("y1")])).unwrap()
            )
            .unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(s2, None, &tx, "signature_zFake", true)
            .unwrap();
        node.stream_materialize(&co_id, &[]).unwrap();

        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap[s1], serde_json::json!(["x1", "x2"]));
        assert_eq!(snap[s2], serde_json::json!(["y1"]));
    }

    #[test]
    fn incremental_append_matches_full_recompute() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) =
            make_stream(session, &[serde_json::json!("a"), serde_json::json!("b")]);
        let v1 = node.stream_materialize(&co_id, &[]).unwrap();

        let made = 1_700_000_001_000u64;
        let more = format!(
            r#"[{{"privacy":"trusting","madeAt":{made},"changes":{}}}]"#,
            serde_json::to_string(
                &serde_json::to_string(&serde_json::json!([serde_json::json!("c")])).unwrap()
            )
            .unwrap()
        );
        node.get_mut(&co_id)
            .unwrap()
            .add_transactions(session, None, &more, "signature_zFake", true)
            .unwrap();
        let v2 = node.stream_materialize(&co_id, &[]).unwrap();
        assert!(v2 > v1, "version bumps on append");

        // Delta since v1 carries the changed session's FULL (grown) entry list,
        // reset=false (caught-up cursor patches).
        let delta: serde_json::Value =
            serde_json::from_str(&node.stream_delta(&co_id, v1).unwrap()).unwrap();
        assert_eq!(delta["reset"], serde_json::json!(false));
        let entries = delta["sessions"][session].as_array().unwrap();
        assert_eq!(entries.len(), 3, "full grown session list");

        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap[session], serde_json::json!(["a", "b", "c"]));
    }

    // === private-transaction decryption into the view ===

    #[test]
    fn private_entries_decrypt_when_key_present() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPrivStream1";
        let secret = test_key_secret(7);
        let (mut node, co_id) = make_private_stream(
            session,
            key_id,
            &secret,
            &[serde_json::json!("chunk0"), serde_json::json!("chunk1")],
        );
        node.provide_key_secret(key_id, &secret);
        node.stream_materialize(&co_id, &[]).unwrap();

        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap[session], serde_json::json!(["chunk0", "chunk1"]));
        assert!(node.stream_missing_key_ids(&co_id).is_empty());
    }

    #[test]
    fn private_entry_without_key_is_skipped_and_recorded() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPrivStream2";
        let secret = test_key_secret(9);
        let (mut node, co_id) =
            make_private_stream(session, key_id, &secret, &[serde_json::json!("x")]);
        node.stream_materialize(&co_id, &[]).unwrap();
        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap, serde_json::json!({}));
        assert_eq!(
            node.stream_missing_key_ids(&co_id),
            vec![key_id.to_string()]
        );
    }

    #[test]
    fn late_key_arrival_rebuilds_view() {
        let session = "co_zA_session_zS";
        let key_id = "key_zPrivStream3";
        let secret = test_key_secret(11);
        let (mut node, co_id) = make_private_stream(
            session,
            key_id,
            &secret,
            &[serde_json::json!("a"), serde_json::json!("b")],
        );

        let v1 = node.stream_materialize(&co_id, &[]).unwrap();
        assert_eq!(
            node.stream_snapshot(&co_id).unwrap(),
            serde_json::json!({}).to_string()
        );
        assert_eq!(
            node.stream_missing_key_ids(&co_id),
            vec![key_id.to_string()]
        );

        node.provide_key_secret(key_id, &secret);
        let v2 = node.stream_materialize(&co_id, &[]).unwrap();
        assert!(v2 > v1, "view rebuilds after the key arrives");
        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&co_id).unwrap()).unwrap();
        assert_eq!(snap[session], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn snapshot_at_frontier_truncates_sessions() {
        let session = "co_zA_session_zS";
        let (mut node, co_id) = make_stream(
            session,
            &[
                serde_json::json!("a"),
                serde_json::json!("b"),
                serde_json::json!("c"),
            ],
        );
        node.stream_materialize(&co_id, &[]).unwrap();
        // frontier {session: 2} → entries with txIndex < 2 → ["a","b"].
        let frontier = serde_json::json!({ session: 2 }).to_string();
        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot_at_frontier(&co_id, &frontier).unwrap())
                .unwrap();
        assert_eq!(snap[session], serde_json::json!(["a", "b"]));
    }
}

// =====================================================================
// CONTENT fixtures — replay coStream fixtures captured from the CURRENT TS
// `RawCoStream` (exported by
// `packages/cojson/src/tests/coStreamContentFixtures.export.test.ts`) and assert
// the Rust materialization reproduces snapshot + per-session `CoStreamItem[]`
// entries + frontier views byte-for-byte. One test per
// `data/co_stream_content/*.json`. These FREEZE the coStream content contract.
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
    struct FrontierExpect {
        frontier: std::collections::HashMap<String, i64>,
        snapshot: serde_json::Value,
    }
    #[derive(Deserialize)]
    struct ContentFixture {
        covalues: Vec<FixtureCovalue>,
        #[serde(rename = "streamId")]
        stream_id: String,
        #[serde(rename = "provideKeys")]
        provide_keys: Vec<ProvideKey>,
        snapshot: serde_json::Value,
        sessions: serde_json::Value,
        frontier: Vec<FrontierExpect>,
    }

    fn load(name: &str) -> ContentFixture {
        let path = format!("data/co_stream_content/{name}.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    fn run(name: &str) {
        let fix = load(name);
        let mut node = NodeCore::new();
        // Ingest every covalue's raw sessions (owning group first, then stream).
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
        node.stream_materialize(&fix.stream_id, &[])
            .unwrap_or_else(|e| panic!("[{name}] materialize: {e}"));

        // (1) snapshot == toJSON().
        let snap: serde_json::Value =
            serde_json::from_str(&node.stream_snapshot(&fix.stream_id).unwrap()).unwrap();
        assert_eq!(snap, fix.snapshot, "[{name}] snapshot mismatch");

        // (2) per-session CoStreamItem[] metadata: delta.sessions == fixture.sessions.
        let delta: serde_json::Value =
            serde_json::from_str(&node.stream_delta(&fix.stream_id, 0).unwrap()).unwrap();
        assert_eq!(
            delta["sessions"], fix.sessions,
            "[{name}] per-session entry metadata mismatch"
        );

        // (3) frontier snapshots: stream_snapshot_at_frontier(f) == expected.
        for e in &fix.frontier {
            let fj = serde_json::to_string(&e.frontier).unwrap();
            let got: serde_json::Value = serde_json::from_str(
                &node
                    .stream_snapshot_at_frontier(&fix.stream_id, &fj)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(got, e.snapshot, "[{name}] frontier {fj} snapshot mismatch");
        }
    }

    #[test]
    fn trusting_stream() {
        run("trusting_stream");
    }
    #[test]
    fn private_stream() {
        run("private_stream");
    }
    #[test]
    fn mixed_stream() {
        run("mixed_stream");
    }
}
