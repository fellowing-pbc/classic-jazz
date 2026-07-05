//! Read-only "group key-management state" query surface.
//!
//! `packages/cojson/src/coValues/group.ts`'s key-management write paths
//! (`rotateReadKey`, `addMemberInternal`, `extend`, `revealReadKeyToParentGroup`,
//! `removeMember`) decide *which* key revelations to emit by reading the group's
//! current CoMap state: `group.get("readKey")`, `group.get("groupSealer")`,
//! `group.get(memberKey)` (direct role), `writeKeyFor_*`, `parent_*`, and which
//! `${keyID}_for_*` revelation fields already exist.
//!
//! This module is a **typed lens over the already-materialized group CoMap** —
//! it duplicates NO validation and NO crypto. It consumes the exact
//! latest-value-per-key snapshot that [`crate::core::co_map::CoMapView`] produces
//! (permission-gated by the group engine's verdicts: only VALID `set` ops count,
//! last-write-wins in `compareTransactions` order), and re-exposes just the
//! key-management facts the write paths need, with the same predicates group.ts
//! uses (`canRead`, `getMemberKeys`, `getWriteOnlyKeys`, `extractSealerID` /
//! `extractReadKeyID`).
//!
//! It reads only PUBLIC (trusting) group fields — key SECRETS are never resolved
//! here (that requires the unseal/decrypt-revelation traversal of
//! `getUncachedReadKey`, which has no native equivalent and is deliberately left
//! to TS; see `group_keys.rs`).

use crate::core::group_engine::types::Role;
use serde_json::Value;
use std::collections::BTreeMap;

/// The `"everyone"` member sentinel (group.ts `EVERYONE`).
pub const EVERYONE: &str = "everyone";

/// `isAgentID` — ids.ts:31-37. An agent id is `sealer_z…/signer_z…`.
fn is_agent_id(id: &str) -> bool {
    id.starts_with("sealer_") && id.contains("/signer_")
}

/// `getMemberKeys` predicate — group.ts:854-858: a map key is a member key iff it
/// is an account id (`co_…`) or an agent id.
fn is_member_key(key: &str) -> bool {
    key.starts_with("co_") || is_agent_id(key)
}

/// `canRead` — group.ts:1760-1774. NOTE the exact set: `managerInvite` and
/// `writeOnlyInvite` are deliberately NOT readers here (they can hold roles but
/// the readKey is not re-revealed to them on rotation), and `writeOnly` is not a
/// reader. Ported verbatim — do not "fix".
fn role_can_read(role: Option<Role>) -> bool {
    matches!(
        role,
        Some(Role::Admin)
            | Some(Role::Manager)
            | Some(Role::Writer)
            | Some(Role::Reader)
            | Some(Role::AdminInvite)
            | Some(Role::WriterInvite)
            | Some(Role::ReaderInvite)
    )
}

/// A parsed `groupSealer` field value. group.ts stores the new composite form
/// `"<readKeyID>@<sealerID>"` (`formatGroupSealerValue`) but must still read the
/// legacy bare `"sealer_z…"` form. Mirrors `extractReadKeyID` /`extractSealerID`
/// (group.ts:70-90).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSealerRef {
    /// The readKeyID the sealer was derived from — `Some` for the composite
    /// form, `None` for a legacy bare-sealer value.
    pub read_key_id: Option<String>,
    /// The `sealer_z…` id.
    pub sealer_id: String,
}

impl GroupSealerRef {
    /// Parse a raw `groupSealer` field value. `idx > 0` (strictly) mirrors the TS
    /// `indexOf("@") > 0` guard: a value that merely starts with `@` is treated
    /// as a legacy value, not a composite with an empty readKeyID.
    fn parse(value: &str) -> GroupSealerRef {
        match value.find('@') {
            Some(idx) if idx > 0 => GroupSealerRef {
                read_key_id: Some(value[..idx].to_string()),
                sealer_id: value[idx + 1..].to_string(),
            },
            _ => GroupSealerRef {
                read_key_id: None,
                sealer_id: value.to_string(),
            },
        }
    }
}

/// A typed, read-only view of a group's current key-management CoMap state.
///
/// Build with [`GroupKeyState::from_snapshot`] over a materialized group CoMap
/// snapshot (`CoMapView::snapshot` / `NodeCore::map_snapshot`), or via
/// [`crate::core::node::NodeCore::group_key_state`].
#[derive(Debug, Clone)]
pub struct GroupKeyState {
    /// Latest value per group-map field, exactly as materialized (valid txs
    /// only, last-write-wins). Only string-valued fields are retained — every
    /// key-management field group.ts reads is a string; a non-string value can
    /// only be a corrupt/foreign write and is dropped so it can never be
    /// mistaken for a role/key id.
    fields: BTreeMap<String, String>,
}

impl GroupKeyState {
    /// Build from a materialized group CoMap snapshot (a JSON object of
    /// `field -> latestValue`). Non-object input yields an empty state.
    pub fn from_snapshot(snapshot: &Value) -> GroupKeyState {
        let mut fields = BTreeMap::new();
        if let Value::Object(map) = snapshot {
            for (k, v) in map {
                if let Value::String(s) = v {
                    fields.insert(k.clone(), s.clone());
                }
            }
        }
        GroupKeyState { fields }
    }

    /// Raw latest string value of a field — the analog of `group.get(key)` for
    /// string-valued fields.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// Whether a field is present with any value — used to check for the
    /// existence of a specific `${keyID}_for_*` revelation (dedup /
    /// `needsKeyRotation`).
    pub fn has_field(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// `group.get("readKey")` — the current readKeyID. This is
    /// `getCurrentReadKeyId()` for an admin/reader caller (the writeOnly/no-role
    /// branches that consult `writeKeyFor_<self>` are caller-specific and left to
    /// the caller via [`GroupKeyState::write_key_for_member`]).
    pub fn read_key_id(&self) -> Option<&str> {
        self.get("readKey")
    }

    /// Parsed `group.get("groupSealer")`.
    pub fn group_sealer(&self) -> Option<GroupSealerRef> {
        self.get("groupSealer").map(GroupSealerRef::parse)
    }

    /// Direct role of a member — `group.get(member)` parsed. Returns the RAW
    /// role including `revoked` (unlike role *resolution*, which collapses a
    /// direct `revoked` to `None`); the write paths test the raw value.
    pub fn direct_role(&self, member: &str) -> Option<Role> {
        self.get(member).and_then(Role::parse)
    }

    /// `group.get("everyone")` as a role.
    pub fn everyone_role(&self) -> Option<Role> {
        self.direct_role(EVERYONE)
    }

    /// `canRead(this, key)` over a direct role.
    pub fn can_read(&self, key: &str) -> bool {
        role_can_read(self.direct_role(key))
    }

    /// `canRead(this, EVERYONE)` — the `rotateReadKey` early-return guard: when
    /// everyone can already read, rotating is pointless (the new key would be
    /// revealed to everyone in plaintext anyway).
    pub fn everyone_can_read(&self) -> bool {
        self.can_read(EVERYONE)
    }

    /// `getMemberKeys()` — every account/agent member key, in sorted order.
    pub fn member_keys(&self) -> Vec<&str> {
        self.fields
            .keys()
            .map(|s| s.as_str())
            .filter(|k| is_member_key(k))
            .collect()
    }

    /// `getMemberKeys().filter(canRead)`, optionally excluding one member —
    /// exactly the `currentlyPermittedReaders` set `rotateReadKey` re-reveals the
    /// new read key to (pass `removed` = the member being removed, or `None`).
    pub fn currently_permitted_readers(&self, removed: Option<&str>) -> Vec<&str> {
        self.member_keys()
            .into_iter()
            .filter(|k| Some(*k) != removed && self.can_read(k))
            .collect()
    }

    /// `memberKeys.filter(role in {writeOnly, writeOnlyInvite})`, optionally
    /// excluding one member — the `writeOnlyMembers` set `rotateReadKey` gives
    /// fresh per-member write keys to.
    pub fn write_only_members(&self, removed: Option<&str>) -> Vec<&str> {
        self.member_keys()
            .into_iter()
            .filter(|k| {
                Some(*k) != removed
                    && matches!(
                        self.direct_role(k),
                        Some(Role::WriteOnly) | Some(Role::WriteOnlyInvite)
                    )
            })
            .collect()
    }

    /// `writeKeyFor_<member>` → its KeyID, if set.
    pub fn write_key_for_member(&self, member: &str) -> Option<&str> {
        self.fields
            .get(&format!("writeKeyFor_{member}"))
            .map(|s| s.as_str())
    }

    /// `getWriteOnlyKeys()` — the KeyIDs referenced by every `writeKeyFor_*`
    /// field (group.ts:802-814), in sorted-field order.
    pub fn write_only_key_ids(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(k, _)| k.starts_with("writeKeyFor_"))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Non-revoked parent-group references (`parent_<id>` with value != "revoked"),
    /// as `(parentGroupId, mappingValue)` pairs in sorted order. `mappingValue` is
    /// the raw reference role string (`"extend"` or a capped role) — the
    /// `getParentGroups()` set `rotateReadKey`/`extend` operate over.
    pub fn parent_group_refs(&self) -> Vec<(&str, &str)> {
        self.fields
            .iter()
            .filter_map(|(k, v)| {
                let id = k.strip_prefix("parent_")?;
                if v == "revoked" {
                    None
                } else {
                    Some((id, v.as_str()))
                }
            })
            .collect()
    }

    /// Whether the group already holds a specific key-for-key revelation
    /// `${childKeyID}_for_${parentKeyID}` — the `needsKeyRotation` probe
    /// (group.ts:236-240) and a dedup guard for parent reveals.
    pub fn has_key_for_key_revelation(&self, child_key_id: &str, parent_key_id: &str) -> bool {
        self.has_field(&format!("{child_key_id}_for_{parent_key_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state(obj: Value) -> GroupKeyState {
        GroupKeyState::from_snapshot(&obj)
    }

    #[test]
    fn group_sealer_parses_composite_and_legacy() {
        assert_eq!(
            GroupSealerRef::parse("key_zABC@sealer_zXYZ"),
            GroupSealerRef {
                read_key_id: Some("key_zABC".to_string()),
                sealer_id: "sealer_zXYZ".to_string()
            }
        );
        // legacy bare sealer
        assert_eq!(
            GroupSealerRef::parse("sealer_zLEGACY"),
            GroupSealerRef {
                read_key_id: None,
                sealer_id: "sealer_zLEGACY".to_string()
            }
        );
        // leading '@' → legacy (idx must be > 0)
        assert_eq!(GroupSealerRef::parse("@x").read_key_id, None);
    }

    #[test]
    fn member_and_reader_predicates() {
        let s = state(json!({
            "readKey": "key_zRK",
            "groupSealer": "key_zRK@sealer_zGS",
            "co_zAdmin": "admin",
            "co_zReader": "reader",
            "co_zWriter": "writer",
            "co_zWriteOnly": "writeOnly",
            "co_zRevoked": "revoked",
            "co_zManagerInvite": "managerInvite",
            "sealer_zA/signer_zB": "readerInvite",
            "profile": "co_zProfile",
            "root": "co_zRoot",
            "writeKeyFor_co_zWriteOnly": "key_zWO",
            "key_zRK_for_co_zReader": "sealed_Uxxx",
            "parent_co_zParent": "extend"
        }));

        // readKey / sealer
        assert_eq!(s.read_key_id(), Some("key_zRK"));
        assert_eq!(s.group_sealer().unwrap().sealer_id, "sealer_zGS");

        // member keys: accounts + agent id, NOT profile/root/readKey/parent_/writeKeyFor_/key_
        let mut members = s.member_keys();
        members.sort();
        assert_eq!(
            members,
            vec![
                "co_zAdmin",
                "co_zManagerInvite",
                "co_zReader",
                "co_zRevoked",
                "co_zWriteOnly",
                "co_zWriter",
                "sealer_zA/signer_zB",
            ]
        );

        // readers: admin, reader, writer, readerInvite agent — NOT writeOnly,
        // revoked, or managerInvite.
        let mut readers = s.currently_permitted_readers(None);
        readers.sort();
        assert_eq!(
            readers,
            vec!["co_zAdmin", "co_zReader", "co_zWriter", "sealer_zA/signer_zB"]
        );

        // excluding a removed reader
        let readers_excl = s.currently_permitted_readers(Some("co_zReader"));
        assert!(!readers_excl.contains(&"co_zReader"));
        assert!(readers_excl.contains(&"co_zAdmin"));

        // writeOnly members
        assert_eq!(s.write_only_members(None), vec!["co_zWriteOnly"]);

        // writeKeyFor lookups
        assert_eq!(s.write_key_for_member("co_zWriteOnly"), Some("key_zWO"));
        assert_eq!(s.write_only_key_ids(), vec!["key_zWO"]);

        // parent refs
        assert_eq!(s.parent_group_refs(), vec![("co_zParent", "extend")]);

        // revelation presence
        assert!(s.has_key_for_key_revelation("key_zRK", "co_zReader"));
        assert!(!s.has_key_for_key_revelation("key_zRK", "co_zAdmin"));
    }

    #[test]
    fn everyone_readable_guard_and_revoked_parent() {
        let readable = state(json!({ "everyone": "reader" }));
        assert!(readable.everyone_can_read());

        let writeonly = state(json!({ "everyone": "writeOnly" }));
        assert!(!writeonly.everyone_can_read());

        let revoked_parent = state(json!({
            "parent_co_zActive": "reader",
            "parent_co_zGone": "revoked"
        }));
        assert_eq!(
            revoked_parent.parent_group_refs(),
            vec![("co_zActive", "reader")]
        );
    }

    #[test]
    fn non_string_values_are_dropped() {
        // A corrupt/foreign numeric value must not be mistaken for a role/id.
        let s = state(json!({ "readKey": 5, "co_zAdmin": "admin" }));
        assert_eq!(s.read_key_id(), None);
        assert_eq!(s.direct_role("co_zAdmin"), Some(Role::Admin));
    }
}
