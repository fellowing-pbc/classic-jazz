use std::collections::HashMap;

use crate::core::co_map::{ensure_co_map, CoMapView};
use crate::core::group_engine::engine::{
    role_of as engine_role_of, validate_transactions as engine_validate_transactions,
    GroupEngineState,
};
use crate::core::group_engine::tx_view::PendingTxIn;
use crate::core::group_engine::types::Role;
use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// Node-level registry owning one SessionMapImpl per CoValue, keyed by CoID.
/// One instance per LocalNode. Stage 2+ builds cross-CoValue features
/// (group engine, permissions) on top of this registry.
///
/// The built group engines live in a SEPARATE map from the session maps so that
/// a recursive engine build can borrow the session maps immutably while it
/// mutates the engine store (see `group_engine::engine`'s borrow-strategy note).
pub struct NodeCore {
    covalues: HashMap<String, SessionMapImpl>,
    engines: HashMap<String, GroupEngineState>,
    /// R0 coMap materialization (experimental): per-covalue materialized view,
    /// keyed like `engines` by per-session tx-counts. A separate field so a
    /// build can borrow `covalues`/`engines` while mutating this store.
    co_maps: HashMap<String, CoMapView>,
    /// R1 key store: `KeyID -> KeySecret`, GLOBAL (not per-covalue). TS unseals
    /// read-key secrets (via account sealer keys + revelation chains — that
    /// stays in TS) and feeds each one here as it learns it; native private-tx
    /// decryption during materialization is the ONLY consumer. A given `KeyID`
    /// always resolves to the same secret regardless of which covalue asks, so a
    /// global map mirrors TS's effective behavior: TS's `readKeyCache` is
    /// per-covalue, but `getUncachedReadKey`/`getReadKey` are pure functions of
    /// the `KeyID` (content-addressed key material), so caching globally is
    /// equivalent.
    ///
    /// SECURITY: providing a secret moves it into native memory for the process
    /// lifetime. Under wasm this is the SAME trust domain as the page (linear
    /// memory is already inspectable by the host JS); under napi it is process
    /// memory. Neither is worse than the secret's existing residence on the TS
    /// heap. There is deliberately NO getter that hands a secret back across the
    /// boundary — decryption keeps secrets inside Rust.
    keys: HashMap<String, String>,
    /// Bumped whenever a NEW (or changed) secret is provided. Part of each
    /// coMap view's freshness key so a view lazily rebuilds when a
    /// previously-missing key finally arrives (the retry path).
    keys_version: u64,
}

impl NodeCore {
    pub fn new() -> Self {
        NodeCore {
            covalues: HashMap::new(),
            engines: HashMap::new(),
            co_maps: HashMap::new(),
            keys: HashMap::new(),
            keys_version: 0,
        }
    }

    // === R1 key store (experimental) ===

    /// Feed a `KeyID -> KeySecret` mapping learned by TS (idempotent). A brand
    /// new key — or a changed secret for a known id — bumps the keys-version so
    /// coMap views that skipped a private tx for want of this key rebuild on
    /// their next materialize. Re-providing an identical secret is a no-op (no
    /// version bump, no spurious rebuild). Secrets never leave Rust again.
    pub fn provide_key_secret(&mut self, key_id: &str, key_secret: &str) {
        match self.keys.get(key_id) {
            Some(existing) if existing == key_secret => {}
            _ => {
                self.keys.insert(key_id.to_string(), key_secret.to_string());
                self.keys_version += 1;
            }
        }
    }

    /// Whether a secret for `key_id` has been provided.
    pub fn has_key_secret(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    /// The `KeyID`s that `co_id`'s materialized view still needs a secret for
    /// (private txs skipped for want of a key). Empty if the view is fully
    /// decrypted or not yet materialized.
    pub fn missing_key_ids(&self, co_id: &str) -> Vec<String> {
        self.co_maps
            .get(co_id)
            .map(|v| v.missing_key_ids())
            .unwrap_or_default()
    }

    /// Create (or replace) the SessionMapImpl for a CoValue.
    /// Replace-on-existing matches current TS semantics, where constructing a
    /// new VerifiedState for an already-known id creates a fresh SessionMap.
    pub fn create_co_value(
        &mut self,
        co_id: &str,
        header_json: &str,
        max_tx_size: Option<u32>,
        skip_verify: bool,
    ) -> Result<(), SessionMapError> {
        let session_map =
            SessionMapImpl::new_with_skip_verify(co_id, header_json, max_tx_size, skip_verify)?;
        self.covalues.insert(co_id.to_string(), session_map);
        // Any cached engine/view for this id is now stale (fresh session map).
        self.engines.remove(co_id);
        self.co_maps.remove(co_id);
        Ok(())
    }

    pub fn has_co_value(&self, co_id: &str) -> bool {
        self.covalues.contains_key(co_id)
    }

    /// Returns true if an entry was removed. Absent id is a no-op (false).
    pub fn remove_co_value(&mut self, co_id: &str) -> bool {
        self.engines.remove(co_id);
        self.co_maps.remove(co_id);
        self.covalues.remove(co_id).is_some()
    }

    /// Validate every transaction of `co_id`, returning the verdicts in
    /// validation order. Ensures the (cross-CoValue) group engine is fresh,
    /// rebuilding it — and any parent/owner engines it depends on — as needed.
    /// (Stage 2 name: `validate_group`; this is Stage 3's unified
    /// `validateTransactions` surface, which subsumes it.)
    ///
    /// `co_id` itself must already be registered: an unregistered primary
    /// coId is API misuse (`UnknownCoValue`), consistent with `get`/`get_mut`.
    /// A dependency (parent group / owning account) discovered missing during
    /// the recursive build still surfaces as `CoValueNotLoaded`, unchanged.
    pub fn validate_transactions(
        &mut self,
        co_id: &str,
        pending: &[PendingTxIn],
    ) -> Result<Vec<crate::core::group_engine::engine::Verdict>, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        let Self {
            covalues,
            engines,
            co_maps: _,
            keys: _,
            keys_version: _,
        } = self;
        engine_validate_transactions(covalues, engines, co_id, pending)
    }

    /// Drop the cached validation engine for `co_id`, forcing a full recompute
    /// on the next `validate_transactions` / `role_of`. The TS analogue is
    /// `CoValueCore.resetParsedTransactions` (coValueCore.ts:1318), which
    /// `invalidateDependants` fires on each DEPENDANT of a changed group.
    ///
    /// LOAD-BEARING CALLER CONTRACT: the engine cache is keyed ONLY by
    /// per-session transaction counts — `pending` (decrypted meta / source
    /// identities) is NOT part of the key. If pending changes without a new
    /// transaction (e.g. a private tx's meta decrypts later), verdicts stay
    /// stale until this is called. That mirrors TS exactly (verdicts persist
    /// until `resetParsedTransactions`), so the TS delegation MUST call this
    /// wherever TS calls `resetParsedTransactions`, and nowhere else.
    ///
    /// An absent id is a NO-OP (not `UnknownCoValue`): the TS caller invokes
    /// this on dependants that may never have been registered on this node, so
    /// erroring would be hostile — same rationale as `remove_co_value`.
    pub fn reset_validation(&mut self, co_id: &str) {
        self.engines.remove(co_id);
        // The materialized content view is derived from the verdicts, so drop it
        // too — TS `resetParsedTransactions` likewise rebuilds content when a
        // reset flips validity (coValueCore.ts:1349-1358).
        self.co_maps.remove(co_id);
    }

    // === R0 coMap materialization (experimental) ===
    // Three read-boundary candidates over a Rust-resident coMap view.
    // `map_materialize` is the only mutating path (validate + build/append);
    // the read methods (`map_get`, `map_get_at`, `map_snapshot`, `map_delta`)
    // are `&self` and operate on the cached view — a prior `map_materialize`
    // (or ingest) must have run. An unregistered primary coId is
    // `UnknownCoValue`, matching `validate_transactions`/`role_of`.

    /// Materialize (or incrementally refresh) `co_id`'s coMap view, returning its
    /// current monotonic version. Call after each ingest batch.
    pub fn map_materialize(
        &mut self,
        co_id: &str,
        pending: &[PendingTxIn],
    ) -> Result<u64, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        let Self {
            covalues,
            engines,
            co_maps,
            keys,
            keys_version,
        } = self;
        ensure_co_map(
            covalues,
            engines,
            co_maps,
            keys,
            *keys_version,
            co_id,
            pending,
        )
    }

    /// Boundary (a): latest value of `key` as a JSON string (`None` = absent /
    /// deleted / not-yet-materialized).
    pub fn map_get(&self, co_id: &str, key: &str) -> Result<Option<String>, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        Ok(self
            .co_maps
            .get(co_id)
            .and_then(|v| v.get(key))
            .map(|val| val.to_string()))
    }

    /// Boundary (a): value of `key` at `at_time` (`None` = latest) as a JSON
    /// string.
    pub fn map_get_at(
        &self,
        co_id: &str,
        key: &str,
        at_time: Option<u64>,
    ) -> Result<Option<String>, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        Ok(self
            .co_maps
            .get(co_id)
            .and_then(|v| v.get_at(key, at_time))
            .map(|val| val.to_string()))
    }

    /// Boundary (b): whole materialized map `{key: latestValue}` as a JSON
    /// string (empty object if not yet materialized).
    pub fn map_snapshot(&self, co_id: &str) -> Result<String, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        let snapshot = self
            .co_maps
            .get(co_id)
            .map(|v| v.snapshot())
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        Ok(snapshot.to_string())
    }

    /// Boundary (c): `{version, changedKeys, deletedKeys}` since `since_version`
    /// as a JSON string.
    pub fn map_delta(&self, co_id: &str, since_version: u64) -> Result<String, SessionMapError> {
        if !self.covalues.contains_key(co_id) {
            return Err(SessionMapError::UnknownCoValue(co_id.to_string()));
        }
        let delta = self
            .co_maps
            .get(co_id)
            .map(|v| v.delta(since_version))
            .unwrap_or_else(|| {
                serde_json::json!({
                    "version": 0,
                    "changedKeys": {},
                    "deletedKeys": [],
                })
            });
        Ok(delta.to_string())
    }

    /// Read-side role of `member` in group `group_id` at `at_time` (`None` =
    /// latest). Builds engines on demand.
    ///
    /// `group_id` itself must already be registered: an unregistered primary
    /// coId is API misuse (`UnknownCoValue`), consistent with `get`/`get_mut`.
    /// A dependency (parent group / owning account) discovered missing during
    /// the recursive build still surfaces as `CoValueNotLoaded`, unchanged.
    pub fn role_of(
        &mut self,
        group_id: &str,
        member: &str,
        at_time: Option<u64>,
    ) -> Result<Option<Role>, SessionMapError> {
        if !self.covalues.contains_key(group_id) {
            return Err(SessionMapError::UnknownCoValue(group_id.to_string()));
        }
        let Self {
            covalues,
            engines,
            co_maps: _,
            keys: _,
            keys_version: _,
        } = self;
        engine_role_of(covalues, engines, group_id, member, at_time)
    }

    pub fn co_value_count(&self) -> usize {
        self.covalues.len()
    }

    pub fn get(&self, co_id: &str) -> Result<&SessionMapImpl, SessionMapError> {
        self.covalues
            .get(co_id)
            .ok_or_else(|| SessionMapError::UnknownCoValue(co_id.to_string()))
    }

    pub fn get_mut(&mut self, co_id: &str) -> Result<&mut SessionMapImpl, SessionMapError> {
        self.covalues
            .get_mut(co_id)
            .ok_or_else(|| SessionMapError::UnknownCoValue(co_id.to_string()))
    }
}

impl Default for NodeCore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session_map::SessionMapError;

    // Build a valid header + matching co_id, mirroring session_map.rs's
    // `test_validation_with_matching_id`. NOTE: `compute_co_id_from_header` is
    // private to session_map.rs, so we rebuild the same computation here via the
    // public `short_hash_with_prefix` (see deviation note in report).
    fn valid_header() -> (String, String) {
        use crate::core::{CoValueHeader, NullableString, RulesetDef, Uniqueness};

        let header = CoValueHeader {
            created_at: NullableString::Missing,
            meta: None,
            ruleset: RulesetDef::unsafe_allow_all(),
            co_type: "comap".to_string(),
            uniqueness: Uniqueness::String("test".to_string()),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let co_id = crate::hash::blake3::short_hash_with_prefix(header_json.as_bytes(), "co_z");
        (co_id, header_json)
    }

    #[test]
    fn create_has_remove_roundtrip() {
        let (co_id, header_json) = valid_header();
        let mut node = NodeCore::new();
        assert!(!node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 0);

        node.create_co_value(&co_id, &header_json, None, false)
            .unwrap();
        assert!(node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 1);
        assert!(node.get(&co_id).is_ok());

        assert!(node.remove_co_value(&co_id));
        assert!(!node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 0);
    }

    #[test]
    fn remove_absent_is_noop() {
        let mut node = NodeCore::new();
        assert!(!node.remove_co_value("co_zDoesNotExist"));
        // double-remove after create
        let (co_id, header_json) = valid_header();
        node.create_co_value(&co_id, &header_json, None, false)
            .unwrap();
        assert!(node.remove_co_value(&co_id));
        assert!(!node.remove_co_value(&co_id));
    }

    #[test]
    fn get_unknown_covalue_errors() {
        let node = NodeCore::new();
        match node.get("co_zDoesNotExist") {
            Err(SessionMapError::UnknownCoValue(id)) => assert_eq!(id, "co_zDoesNotExist"),
            other => panic!("expected UnknownCoValue, got {other:?}"),
        }
    }

    #[test]
    fn create_replaces_existing_entry() {
        // Matches TS semantics: `new VerifiedState(sameId)` today creates a fresh
        // SessionMap; createCoValue must replace, not error.
        let (co_id, header_json) = valid_header();
        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, false)
            .unwrap();
        node.create_co_value(&co_id, &header_json, None, false)
            .unwrap();
        assert_eq!(node.co_value_count(), 1);
    }

    #[test]
    fn invalid_header_does_not_insert() {
        let mut node = NodeCore::new();
        assert!(node
            .create_co_value("co_zBogus", "{not json", None, false)
            .is_err());
        assert!(!node.has_co_value("co_zBogus"));
    }
}
