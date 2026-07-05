//! JSON wire bindings for the group key-management write paths.
//!
//! This is the FFI-facing surface for the pure orchestration functions in
//! [`crate::core::group_key_rotation`], [`crate::core::group_key_membership`] and
//! [`crate::core::group_key_extend`]. Each pure function takes a small graph of
//! Rust structs (borrowing `GroupKeyState`, slices of `KeyPair` /
//! `MemberResolution` / `ParentResolution`, secret material, …) and returns an
//! ordered list of `(field, value)` writes. Those Rust signatures do not cross a
//! napi/wasm boundary cleanly, so this module defines a **JSON-string-in /
//! JSON-string-out** wrapper per function — the same convention `co_map`'s
//! `map_snapshot` / header plumbing already uses for complex payloads.
//!
//! # Why one shared module (not per-binding-crate DTOs)
//!
//! The wire (de)serialization is the *only* new thing stage 1 must prove correct
//! (the pure logic is already byte-fixtured). Defining the serde DTOs once here,
//! rather than twice in `cojson-core-napi` and `cojson-core-wasm`, means napi and
//! wasm share **identical** wire behaviour by construction — each binding method
//! is a one-line call to the matching `*_json` function. It also lets the wire
//! layer be unit-tested inside cojson-core (see the tests below), independent of
//! either addon toolchain.
//!
//! # Wire shapes
//!
//! Every field name matches the existing golden fixtures in
//! `data/group_key_*/*.json` (camelCase), so a fixture object can be fed straight
//! through a `*_json` function — extra fixture-only fields (`description`,
//! `expectedWrites`, …) are ignored by serde. This is what makes the FFI
//! round-trip test able to assert `wire(fixture.input) == fixture.expectedWrites`,
//! which — combined with the pure-Rust fixture tests already asserting
//! `pure(fixture.input) == fixture.expectedWrites` — proves the wire layer is
//! byte-lossless.
//!
//! Outputs:
//! - the write-list functions return a JSON array `[{ "field", "value" }, …]`.
//! - [`rotate_read_key_json`] returns `{ "skipped": bool, "writes": [...] }`
//!   (rotation can early-return with no writes).
//! - [`add_everyone_write_only_json`] returns a mutation array
//!   `[{ "op": "set"|"del", "field", "value"? }, …]` (it can emit a delete).
//!
//! This module is native-only and is intentionally NOT wired into production
//! `group.ts` (stage 2).

use serde::{Deserialize, Serialize};

use crate::core::group_engine::types::Role;
use crate::core::group_key_extend::{extend, ExtendInput};
use crate::core::group_key_membership::{
    add_everyone_write_only, add_member_internal, remove_member, AddMemberInput,
    EveryoneWriteOnlyInput,
};
use crate::core::group_key_rotation::{
    rotate_read_key, KeyPair, MemberResolution, ParentResolution, RotateOutcome,
    RotateReadKeyInput, RotationTrigger,
};
use crate::core::group_key_state::GroupKeyState;
use crate::core::group_keys::{GroupKeyMutation, GroupKeyWrite};

// ---------------------------------------------------------------------------
// Shared input leaf DTOs (mirror the fixture JSON, camelCase).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KeyPairWire {
    id: String,
    secret: String,
}
impl KeyPairWire {
    fn to_key_pair(&self) -> KeyPair {
        KeyPair {
            id: self.id.clone(),
            secret: self.secret.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberWire {
    member_key: String,
    agent_sealer_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentWire {
    read_key_id: String,
    read_key_secret: String,
}

fn to_members(v: &[MemberWire]) -> Vec<MemberResolution> {
    v.iter()
        .map(|m| MemberResolution {
            member_key: m.member_key.clone(),
            agent_sealer_id: m.agent_sealer_id.clone(),
        })
        .collect()
}

fn to_keys(v: &[KeyPairWire]) -> Vec<KeyPair> {
    v.iter().map(KeyPairWire::to_key_pair).collect()
}

fn to_parents(v: &[ParentWire]) -> Vec<ParentResolution> {
    v.iter()
        .map(|p| ParentResolution {
            read_key_id: p.read_key_id.clone(),
            read_key_secret: p.read_key_secret.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Shared output leaf DTOs.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct WriteWire {
    field: String,
    value: String,
}
impl From<&GroupKeyWrite> for WriteWire {
    fn from(w: &GroupKeyWrite) -> Self {
        WriteWire {
            field: w.field.clone(),
            value: w.value.clone(),
        }
    }
}

fn writes_to_json(writes: &[GroupKeyWrite]) -> Result<String, String> {
    let wire: Vec<WriteWire> = writes.iter().map(WriteWire::from).collect();
    serde_json::to_string(&wire).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct MutationWire {
    op: &'static str,
    field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}
impl From<&GroupKeyMutation> for MutationWire {
    fn from(m: &GroupKeyMutation) -> Self {
        match m {
            GroupKeyMutation::Set(w) => MutationWire {
                op: "set",
                field: w.field.clone(),
                value: Some(w.value.clone()),
            },
            GroupKeyMutation::Delete { field } => MutationWire {
                op: "del",
                field: field.clone(),
                value: None,
            },
        }
    }
}

#[derive(Serialize)]
struct RotateOutputWire {
    skipped: bool,
    writes: Vec<WriteWire>,
}

fn parse_role(role: &str) -> Result<Role, String> {
    Role::parse(role).ok_or_else(|| format!("unknown role: {role}"))
}

// ===========================================================================
// 1. rotate_read_key
// ===========================================================================

#[derive(Deserialize)]
struct TriggerWire {
    kind: String,
    #[serde(default)]
    member: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RotateInputWire {
    trigger: TriggerWire,
    pub(crate) group_id: String,
    session_id: String,
    start_tx_index: u64,
    from_sealer_secret: String,
    current_read_key: KeyPairWire,
    new_read_key: KeyPairWire,
    members: Vec<MemberWire>,
    write_only_fresh_keys: Vec<KeyPairWire>,
    parents: Vec<ParentWire>,
    /// The materialized group CoMap snapshot. Optional on the wire: when omitted
    /// (`null`) the caller (a `NodeCore` method) supplies the [`GroupKeyState`]
    /// from its own already-materialized coMap view via
    /// [`rotate_read_key_from_wire`], so the snapshot never has to be re-serialized
    /// in TS and marshaled across the FFI boundary on every write.
    #[serde(default)]
    pub(crate) snapshot: serde_json::Value,
}

/// Wire wrapper for [`rotate_read_key`]. Returns
/// `{ "skipped": bool, "writes": [...] }`. Builds the [`GroupKeyState`] from the
/// snapshot embedded in the input JSON.
pub fn rotate_read_key_json(input_json: &str) -> Result<String, String> {
    let inp: RotateInputWire = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let state = GroupKeyState::from_snapshot(&inp.snapshot);
    rotate_read_key_from_wire(&inp, &state)
}

/// Run [`rotate_read_key`] over an already-parsed wire input and an externally
/// provided [`GroupKeyState`] (from a `NodeCore` coMap view). Returns
/// `{ "skipped": bool, "writes": [...] }`.
pub(crate) fn rotate_read_key_from_wire(
    inp: &RotateInputWire,
    state: &GroupKeyState,
) -> Result<String, String> {
    let trigger = match inp.trigger.kind.as_str() {
        "rotate" => RotationTrigger::Rotate,
        "removeEveryone" => RotationTrigger::RemoveEveryone,
        "removeMember" => RotationTrigger::RemoveMember(
            inp.trigger
                .member
                .clone()
                .ok_or("removeMember trigger requires a `member`")?,
        ),
        other => return Err(format!("unknown rotation trigger kind: {other}")),
    };
    let members = to_members(&inp.members);
    let wo = to_keys(&inp.write_only_fresh_keys);
    let parents = to_parents(&inp.parents);

    let rotate_input = RotateReadKeyInput {
        state,
        group_id: &inp.group_id,
        session_id: &inp.session_id,
        start_tx_index: inp.start_tx_index,
        trigger,
        from_sealer_secret: &inp.from_sealer_secret,
        current_read_key: inp.current_read_key.to_key_pair(),
        new_read_key: inp.new_read_key.to_key_pair(),
        members: &members,
        write_only_fresh_keys: &wo,
        parents: &parents,
    };
    let out = match rotate_read_key(&rotate_input).map_err(|e| e.to_string())? {
        RotateOutcome::SkippedEveryoneCanRead => RotateOutputWire {
            skipped: true,
            writes: Vec::new(),
        },
        RotateOutcome::Rotated(w) => RotateOutputWire {
            skipped: false,
            writes: w.iter().map(WriteWire::from).collect(),
        },
    };
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

// ===========================================================================
// 2. add_member_internal
// ===========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddMemberInputWire {
    pub(crate) group_id: String,
    session_id: String,
    start_tx_index: u64,
    member_key: String,
    member_agent_sealer_id: String,
    role: String,
    from_sealer_secret: String,
    current_read_key: KeyPairWire,
    existing_write_only_keys: Vec<KeyPairWire>,
    #[serde(default)]
    fresh_write_only_key: Option<KeyPairWire>,
    #[serde(default)]
    rotation_new_read_key: Option<KeyPairWire>,
    #[serde(default)]
    rotation_write_only_fresh_keys: Vec<KeyPairWire>,
    members: Vec<MemberWire>,
    parents: Vec<ParentWire>,
    /// Optional on the wire — see [`RotateInputWire::snapshot`].
    #[serde(default)]
    pub(crate) snapshot: serde_json::Value,
}

/// Wire wrapper for [`add_member_internal`]. Returns a JSON array of writes.
/// Builds the [`GroupKeyState`] from the snapshot embedded in the input JSON.
pub fn add_member_internal_json(input_json: &str) -> Result<String, String> {
    let inp: AddMemberInputWire = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let state = GroupKeyState::from_snapshot(&inp.snapshot);
    add_member_internal_from_wire(&inp, &state)
}

/// Run [`add_member_internal`] over an already-parsed wire input and an
/// externally provided [`GroupKeyState`] (from a `NodeCore` coMap view).
pub(crate) fn add_member_internal_from_wire(
    inp: &AddMemberInputWire,
    state: &GroupKeyState,
) -> Result<String, String> {
    let role = parse_role(&inp.role)?;
    let members = to_members(&inp.members);
    let parents = to_parents(&inp.parents);
    let existing = to_keys(&inp.existing_write_only_keys);
    let rotation_wo = to_keys(&inp.rotation_write_only_fresh_keys);
    let fresh = inp.fresh_write_only_key.as_ref().map(KeyPairWire::to_key_pair);
    let rotation_new = inp
        .rotation_new_read_key
        .as_ref()
        .map(KeyPairWire::to_key_pair);

    let input = AddMemberInput {
        state,
        group_id: &inp.group_id,
        session_id: &inp.session_id,
        start_tx_index: inp.start_tx_index,
        member_key: &inp.member_key,
        member_agent_sealer_id: &inp.member_agent_sealer_id,
        role,
        from_sealer_secret: &inp.from_sealer_secret,
        current_read_key: inp.current_read_key.to_key_pair(),
        existing_write_only_keys: &existing,
        fresh_write_only_key: fresh.as_ref(),
        rotation_new_read_key: rotation_new.as_ref(),
        rotation_write_only_fresh_keys: &rotation_wo,
        members: &members,
        parents: &parents,
    };
    let writes = add_member_internal(&input).map_err(|e| e.to_string())?;
    writes_to_json(&writes)
}

// ===========================================================================
// 3. add_everyone_write_only
// ===========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EveryoneWriteOnlyInputWire {
    pub(crate) group_id: String,
    session_id: String,
    start_tx_index: u64,
    from_sealer_secret: String,
    current_read_key: KeyPairWire,
    #[serde(default)]
    rotation_new_read_key: Option<KeyPairWire>,
    #[serde(default)]
    rotation_write_only_fresh_keys: Vec<KeyPairWire>,
    members: Vec<MemberWire>,
    parents: Vec<ParentWire>,
    /// Optional on the wire — see [`RotateInputWire::snapshot`].
    #[serde(default)]
    pub(crate) snapshot: serde_json::Value,
}

/// Wire wrapper for [`add_everyone_write_only`]. Returns a JSON array of
/// mutations `[{ "op": "set"|"del", "field", "value"? }, …]`. Builds the
/// [`GroupKeyState`] from the snapshot embedded in the input JSON.
pub fn add_everyone_write_only_json(input_json: &str) -> Result<String, String> {
    let inp: EveryoneWriteOnlyInputWire =
        serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let state = GroupKeyState::from_snapshot(&inp.snapshot);
    add_everyone_write_only_from_wire(&inp, &state)
}

/// Run [`add_everyone_write_only`] over an already-parsed wire input and an
/// externally provided [`GroupKeyState`] (from a `NodeCore` coMap view).
pub(crate) fn add_everyone_write_only_from_wire(
    inp: &EveryoneWriteOnlyInputWire,
    state: &GroupKeyState,
) -> Result<String, String> {
    let members = to_members(&inp.members);
    let parents = to_parents(&inp.parents);
    let rotation_wo = to_keys(&inp.rotation_write_only_fresh_keys);
    let rotation_new = inp
        .rotation_new_read_key
        .as_ref()
        .map(KeyPairWire::to_key_pair);

    let input = EveryoneWriteOnlyInput {
        state,
        group_id: &inp.group_id,
        session_id: &inp.session_id,
        start_tx_index: inp.start_tx_index,
        from_sealer_secret: &inp.from_sealer_secret,
        current_read_key: inp.current_read_key.to_key_pair(),
        rotation_new_read_key: rotation_new.as_ref(),
        rotation_write_only_fresh_keys: &rotation_wo,
        members: &members,
        parents: &parents,
    };
    let muts = add_everyone_write_only(&input).map_err(|e| e.to_string())?;
    let wire: Vec<MutationWire> = muts.iter().map(MutationWire::from).collect();
    serde_json::to_string(&wire).map_err(|e| e.to_string())
}

// ===========================================================================
// 4. remove_member
// ===========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoveMemberInputWire {
    member_key: String,
    caller_is_admin_or_manager: bool,
    pub(crate) group_id: String,
    session_id: String,
    start_tx_index: u64,
    from_sealer_secret: String,
    current_read_key: KeyPairWire,
    new_read_key: KeyPairWire,
    members: Vec<MemberWire>,
    write_only_fresh_keys: Vec<KeyPairWire>,
    parents: Vec<ParentWire>,
    /// Optional on the wire — see [`RotateInputWire::snapshot`].
    #[serde(default)]
    pub(crate) snapshot: serde_json::Value,
}

/// Wire wrapper for [`remove_member`]. The rotation trigger is always
/// `RemoveMember(member_key)` (as in `RawGroup.removeMember`). Returns a JSON
/// array of writes. Builds the [`GroupKeyState`] from the snapshot embedded in
/// the input JSON.
pub fn remove_member_json(input_json: &str) -> Result<String, String> {
    let inp: RemoveMemberInputWire = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let state = GroupKeyState::from_snapshot(&inp.snapshot);
    remove_member_from_wire(&inp, &state)
}

/// Run [`remove_member`] over an already-parsed wire input and an externally
/// provided [`GroupKeyState`] (from a `NodeCore` coMap view).
pub(crate) fn remove_member_from_wire(
    inp: &RemoveMemberInputWire,
    state: &GroupKeyState,
) -> Result<String, String> {
    let members = to_members(&inp.members);
    let wo = to_keys(&inp.write_only_fresh_keys);
    let parents = to_parents(&inp.parents);

    let rotate_input = RotateReadKeyInput {
        state,
        group_id: &inp.group_id,
        session_id: &inp.session_id,
        start_tx_index: inp.start_tx_index,
        trigger: RotationTrigger::RemoveMember(inp.member_key.clone()),
        from_sealer_secret: &inp.from_sealer_secret,
        current_read_key: inp.current_read_key.to_key_pair(),
        new_read_key: inp.new_read_key.to_key_pair(),
        members: &members,
        write_only_fresh_keys: &wo,
        parents: &parents,
    };
    let writes = remove_member(&rotate_input, &inp.member_key, inp.caller_is_admin_or_manager)
        .map_err(|e| e.to_string())?;
    writes_to_json(&writes)
}

// ===========================================================================
// 5. extend
// ===========================================================================

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtendInputWire {
    parent_id: String,
    parent_ref_value: String,
    parent: ParentWire,
    child_read_key: KeyPairWire,
    write_only_keys: Vec<KeyPairWire>,
}

/// Wire wrapper for [`extend`] (standard/account-member parent path). Returns a
/// JSON array of writes.
pub fn extend_json(input_json: &str) -> Result<String, String> {
    let inp: ExtendInputWire = serde_json::from_str(input_json).map_err(|e| e.to_string())?;
    let write_only_keys = to_keys(&inp.write_only_keys);

    let input = ExtendInput {
        parent_id: &inp.parent_id,
        parent_ref_value: &inp.parent_ref_value,
        parent: ParentResolution {
            read_key_id: inp.parent.read_key_id.clone(),
            read_key_secret: inp.parent.read_key_secret.clone(),
        },
        child_read_key: inp.child_read_key.to_key_pair(),
        write_only_keys: &write_only_keys,
    };
    let writes = extend(&input).map_err(|e| format!("{e:?}"))?;
    writes_to_json(&writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Feed each golden fixture's INPUT straight through the wire wrapper (serde
    // ignores the fixture-only `description`/`expectedWrites` fields) and assert
    // the wire OUTPUT equals the fixture's `expectedWrites` — the same bytes the
    // pure-Rust fixture tests already lock the pure functions to. Together these
    // prove the JSON wire layer is byte-lossless end to end.

    fn fixture(path: &str) -> (String, serde_json::Value) {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
        (text, value)
    }

    #[test]
    fn rotate_read_key_wire_roundtrip() {
        for name in ["readers_only", "remove_member", "write_only", "with_parent"] {
            let (text, fx) = fixture(&format!("data/group_key_rotation/{name}.json"));
            let out: serde_json::Value =
                serde_json::from_str(&rotate_read_key_json(&text).unwrap()).unwrap();
            assert_eq!(out["skipped"], json!(false), "[{name}] should not skip");
            assert_eq!(
                out["writes"], fx["expectedWrites"],
                "[{name}] rotate wire writes must equal fixture expectedWrites"
            );
        }
    }

    #[test]
    fn add_member_internal_wire_roundtrip() {
        for name in [
            "add_reader",
            "add_writer_with_existing_writeonly",
            "add_write_only",
            "create_invite_reader",
            "everyone_reader",
            "write_only_demotion",
        ] {
            let (text, fx) = fixture(&format!("data/group_key_membership/{name}.json"));
            let out: serde_json::Value =
                serde_json::from_str(&add_member_internal_json(&text).unwrap()).unwrap();
            assert_eq!(
                out, fx["expectedWrites"],
                "[{name}] add_member wire writes must equal fixture expectedWrites"
            );
        }
    }

    #[test]
    fn add_everyone_write_only_wire_roundtrip() {
        let (text, fx) = fixture("data/group_key_membership/everyone_write_only.json");
        let out: serde_json::Value =
            serde_json::from_str(&add_everyone_write_only_json(&text).unwrap()).unwrap();
        // Normalize the fixture's expectedWrites: its `op` defaults to "set" and a
        // set carries a `value`; a `del` carries none. Build the same shape the
        // wire emits and compare.
        let expected: Vec<serde_json::Value> = fx["expectedWrites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| {
                let op = w.get("op").and_then(|o| o.as_str()).unwrap_or("set");
                if op == "del" {
                    json!({ "op": "del", "field": w["field"] })
                } else {
                    json!({ "op": "set", "field": w["field"], "value": w["value"] })
                }
            })
            .collect();
        assert_eq!(out, serde_json::Value::Array(expected));
    }

    #[test]
    fn remove_member_wire_roundtrip() {
        let (text, fx) = fixture("data/group_key_membership/remove_reader.json");
        let out: serde_json::Value =
            serde_json::from_str(&remove_member_json(&text).unwrap()).unwrap();
        assert_eq!(out, fx["expectedWrites"]);
    }

    #[test]
    fn extend_wire_roundtrip() {
        for name in ["extend_basic", "extend_with_writeonly"] {
            let (text, fx) = fixture(&format!("data/group_key_extend/{name}.json"));
            let out: serde_json::Value =
                serde_json::from_str(&extend_json(&text).unwrap()).unwrap();
            assert_eq!(
                out, fx["expectedWrites"],
                "[{name}] extend wire writes must equal fixture expectedWrites"
            );
        }
    }

    #[test]
    fn unknown_trigger_kind_errors() {
        let bad = json!({
            "trigger": { "kind": "bogus" },
            "groupId": "co_z", "sessionId": "co_z_session_z", "startTxIndex": 0,
            "fromSealerSecret": "sealerSecret_z", "currentReadKey": {"id":"key_z","secret":"keySecret_z"},
            "newReadKey": {"id":"key_z2","secret":"keySecret_z2"},
            "members": [], "writeOnlyFreshKeys": [], "parents": [], "snapshot": {}
        })
        .to_string();
        assert!(rotate_read_key_json(&bad).is_err());
    }
}
