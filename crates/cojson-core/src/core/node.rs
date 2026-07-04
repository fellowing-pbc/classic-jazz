use std::collections::HashMap;

use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// Node-level registry owning one SessionMapImpl per CoValue, keyed by CoID.
/// One instance per LocalNode. Stage 2+ builds cross-CoValue features
/// (group engine, permissions) on top of this registry.
pub struct NodeCore {
    covalues: HashMap<String, SessionMapImpl>,
}

impl NodeCore {
    pub fn new() -> Self {
        NodeCore {
            covalues: HashMap::new(),
        }
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
        Ok(())
    }

    pub fn has_co_value(&self, co_id: &str) -> bool {
        self.covalues.contains_key(co_id)
    }

    /// Returns true if an entry was removed. Absent id is a no-op (false).
    pub fn remove_co_value(&mut self, co_id: &str) -> bool {
        self.covalues.remove(co_id).is_some()
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
