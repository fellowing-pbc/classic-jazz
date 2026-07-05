//! Native orchestration of `RawGroup.addMemberInternal` / `createInvite` /
//! `removeMember` — the group membership write surface.
//!
//! [`add_member_internal`] is a **pure, deterministic** reproduction of
//! `packages/cojson/src/coValues/group.ts`'s `addMemberInternal` (group.ts:561-681)
//! plus its `internalCreateWriteOnlyKeyForMember` helper (group.ts:683-740). Given a
//! materialized [`GroupKeyState`] snapshot plus the non-native inputs TS resolves at
//! runtime (fresh random keys, account→agent sealer-id resolution, resolved read-key
//! secrets), it emits the exact ordered `(field, value)` writes that `addMember` /
//! `createInvite` perform — byte-for-byte, via the proven leaf encoders in
//! [`crate::core::group_keys`].
//!
//! `addMember` and `createInvite` both delegate to `addMemberInternal`:
//! `createInvite(role)` is exactly `addMemberInternal(inviteAgentID, "${role}Invite")`
//! for a freshly generated invite agent id (group.ts:1491-1499), so it is covered by
//! [`add_member_internal`] with an agent-id `member_key` and an `*Invite` role — no
//! separate function is needed.
//!
//! [`remove_member`] reproduces `removeMember` (group.ts:1468-1482), which is
//! `rotateReadKey(memberKey)` (when admin/manager) followed by `set(memberKey,
//! "revoked")` — a thin composition over [`crate::core::group_key_rotation`].
//!
//! # Transaction-index invariant
//!
//! As in rotation, each `group.set(...)` is one transaction; a member seal's nonce
//! embeds `nextTransactionID().txIndex`, so the sealed VALUES depend on the write's
//! position. This function assigns `start_tx_index + i` to the i-th emitted write in
//! TS's exact emission order. (The `writeKeyFor_*` and plain-role sets carry no seal
//! but still consume a transaction, matching TS.)
//!
//! # writeOnly demotion of a reader-class member (handled)
//!
//! When an existing reader/writer/manager/admin is *changed* to
//! `writeOnly`/`writeOnlyInvite`, TS first calls `rotateReadKey(memberKey)`
//! (group.ts:646-654) BEFORE creating the writeOnly key. [`add_member_internal`]
//! reproduces this: when the demotion branch applies it internally invokes
//! [`rotate_read_key`] with `RotationTrigger::RemoveMember(member_key)` (so the
//! member — which still carries its OLD reader-class role, matching TS's call
//! order — is excluded from the re-reveal), prepends that rotation's writes, and
//! threads the rotation's write count into the subsequent writeOnly-grant writes'
//! transaction indices (the member seals are tx-index-sensitive). The caller
//! supplies the rotation's fresh read key and any rotation writeOnly fresh keys via
//! [`AddMemberInput::rotation_new_read_key`] /
//! [`AddMemberInput::rotation_write_only_fresh_keys`].
//!
//! # `everyone` → `writeOnly` (handled by a dedicated function)
//!
//! That path issues a CoMap `delete` of the `${readKey}_for_everyone` field
//! (group.ts:617) and, when demoting a prior reader/writer, a preceding
//! `rotateReadKey("everyone")`. Because a `delete` is a different op than the
//! `set`s [`add_member_internal`] models, it is handled by the dedicated
//! [`add_everyone_write_only`], which returns [`GroupKeyMutation`]s (set OR delete).
//! `add_member_internal`'s `everyone` branch still handles `everyone` → `reader` /
//! `writer` (a plaintext read-key reveal, all `set`s) and returns
//! [`AddMemberError::Deferred`] for `everyone` → `writeOnly` to point callers at the
//! dedicated function.
//!
//! This module is native-only and intentionally NOT wired into production
//! `group.ts`.

use crate::core::group_engine::types::Role;
use crate::core::group_key_extend::reveal_read_key_to_parent_group_standard;
use crate::core::group_key_rotation::{
    rotate_read_key, KeyPair, MemberResolution, ParentResolution, RotateError, RotateOutcome,
    RotateReadKeyInput, RotationTrigger,
};
use crate::core::group_key_state::{GroupKeyState, EVERYONE};
use crate::core::group_keys::{reveal_key_to_member, GroupKeyMutation, GroupKeyWrite};
use crate::crypto::error::CryptoError;

/// Error cases for [`add_member_internal`].
#[derive(Debug)]
pub enum AddMemberError {
    /// A branch that requires a CoMap `delete` was hit within the pure `set`-only
    /// model of [`add_member_internal`]; see the module-level scope note and the
    /// dedicated [`add_everyone_write_only`]. Carries a human-readable reason.
    Deferred(&'static str),
    /// `everyone` was given a role other than reader/writer/writeOnly
    /// (group.ts:574-577).
    InvalidEveryoneRole(Role),
    /// A writeOnly branch was hit but no fresh writeOnly key was supplied.
    MissingFreshWriteOnlyKey,
    /// A writeOnly *demotion of a reader-class member* was hit (which first rotates
    /// the read key) but no fresh rotation read key was supplied.
    MissingRotationReadKey,
    /// The preceding `rotateReadKey(memberKey)` of a writeOnly demotion failed.
    Rotation(RotateError),
    /// A leaf encoder failed.
    Crypto(CryptoError),
}

impl std::fmt::Display for AddMemberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddMemberError::Deferred(why) => {
                write!(f, "add_member_internal deferred branch: {why}")
            }
            AddMemberError::InvalidEveryoneRole(r) => {
                write!(
                    f,
                    "cannot make everyone {:?} (only reader/writer/writeOnly)",
                    r
                )
            }
            AddMemberError::MissingFreshWriteOnlyKey => {
                write!(f, "writeOnly branch requires a fresh writeOnly key")
            }
            AddMemberError::MissingRotationReadKey => {
                write!(
                    f,
                    "writeOnly demotion of a reader-class member requires a fresh rotation read key"
                )
            }
            AddMemberError::Rotation(e) => {
                write!(f, "preceding rotateReadKey failed in add_member_internal: {e}")
            }
            AddMemberError::Crypto(e) => write!(f, "crypto error in add_member_internal: {e:?}"),
        }
    }
}

impl std::error::Error for AddMemberError {}

impl From<CryptoError> for AddMemberError {
    fn from(e: CryptoError) -> Self {
        AddMemberError::Crypto(e)
    }
}

/// All inputs to [`add_member_internal`].
pub struct AddMemberInput<'a> {
    /// The materialized group CoMap snapshot BEFORE the add (so `direct_role` reads
    /// the member's *previous* role, matching TS's `this.get(memberKey)`).
    pub state: &'a GroupKeyState,
    /// The group's CoValue id (`in` of the seal nonce material).
    pub group_id: &'a str,
    /// The current session id (`tx.sessionID` of the seal nonce material).
    pub session_id: &'a str,
    /// `group.core.nextTransactionID().txIndex` immediately before the add.
    pub start_tx_index: u64,
    /// The member being added — an account id (`co_…`), an agent id, or `"everyone"`.
    pub member_key: &'a str,
    /// `getAgentSealerID(resolveAccountAgent(member_key))` — the sealer id member
    /// revelations are sealed *to*. Unused for the `everyone` branches.
    pub member_agent_sealer_id: &'a str,
    /// The role being granted.
    pub role: Role,
    /// The current agent's sealer secret (`getCurrentAgent().currentSealerSecret()`),
    /// the `from` of every member seal.
    pub from_sealer_secret: &'a str,
    /// The group's current read key `(id, secret)` (`getCurrentReadKey()`). Used by
    /// the reader-class and `everyone`→reader/writer branches.
    pub current_read_key: KeyPair,
    /// Existing writeOnly keys `(id, secret)` in `getWriteOnlyKeys()` order — the
    /// reader-class branch also reveals each of these to the new reader
    /// (group.ts:670-679).
    pub existing_write_only_keys: &'a [KeyPair],
    /// The fresh writeOnly key `(id, secret)` for the new member
    /// (`crypto.newRandomKeySecret()`), required by the writeOnly branch.
    pub fresh_write_only_key: Option<&'a KeyPair>,
    /// The fresh read key `(id, secret)` for the preceding `rotateReadKey(memberKey)`
    /// of a **writeOnly demotion of a reader-class member** (`crypto.newRandomKeySecret()`,
    /// consumed FIRST by the rotation). Required only on that branch; ignored otherwise.
    pub rotation_new_read_key: Option<&'a KeyPair>,
    /// One fresh writeOnly key per writeOnly member the preceding demotion rotation
    /// re-keys, in writeOnly-member order (see [`crate::core::group_key_rotation`]).
    /// Empty unless the demotion rotation has pre-existing writeOnly members.
    pub rotation_write_only_fresh_keys: &'a [KeyPair],
    /// Existing members in `getMemberKeys()` order with resolved sealer ids — the
    /// writeOnly branch reveals the fresh key to each reader-class member.
    pub members: &'a [MemberResolution],
    /// Parent groups in `getParentGroups()` order (standard/account-member path) —
    /// the writeOnly branch reveals the fresh key to each.
    pub parents: &'a [ParentResolution],
}

/// Reproduce `RawGroup.addMemberInternal` (group.ts:561-681) as a pure ordered list
/// of group-map writes. Returns an empty vec for the no-op case (`previousRole ===
/// role`). See the module scope note for the two deferred branches.
pub fn add_member_internal(
    input: &AddMemberInput<'_>,
) -> Result<Vec<GroupKeyWrite>, AddMemberError> {
    let AddMemberInput {
        state,
        group_id,
        session_id,
        start_tx_index,
        member_key,
        member_agent_sealer_id,
        role,
        from_sealer_secret,
        current_read_key,
        existing_write_only_keys,
        fresh_write_only_key,
        rotation_new_read_key,
        rotation_write_only_fresh_keys,
        members,
        parents,
    } = input;
    let role = *role;
    let member_key = *member_key;

    // --- Early return: role unchanged (group.ts:566-571) --------------------
    if state.direct_role(member_key) == Some(role) {
        return Ok(Vec::new());
    }

    let mut writes: Vec<GroupKeyWrite> = Vec::new();
    let mut tx = *start_tx_index;

    // --- everyone branch (group.ts:573-610) ---------------------------------
    if member_key == EVERYONE {
        match role {
            Role::Reader | Role::Writer => {
                // set(EVERYONE, role) (group.ts:587)
                writes.push(GroupKeyWrite {
                    field: EVERYONE.to_string(),
                    value: role.as_str().to_string(),
                });
                tx += 1;
                // set(`${readKey.id}_for_${EVERYONE}`, readKey.secret) — the read
                // key revealed to everyone in PLAINTEXT (group.ts:601-606).
                writes.push(GroupKeyWrite {
                    field: format!("{}_for_{}", current_read_key.id, EVERYONE),
                    value: current_read_key.secret.clone(),
                });
                tx += 1;
                let _ = tx;
                return Ok(writes);
            }
            Role::WriteOnly => {
                // Involves delete(`${readKey}_for_everyone`) and possibly
                // rotateReadKey("everyone"); a `delete` is not a `GroupKeyWrite`
                // (set), so this `set`-only function defers to the dedicated
                // `add_everyone_write_only`, which returns `GroupKeyMutation`s.
                return Err(AddMemberError::Deferred(
                    "everyone -> writeOnly emits a CoMap delete; use add_everyone_write_only",
                ));
            }
            other => return Err(AddMemberError::InvalidEveryoneRole(other)),
        }
    }

    // --- non-everyone: writeOnly branch (group.ts:646-664) ------------------
    if matches!(role, Role::WriteOnly | Role::WriteOnlyInvite) {
        // Demotion of a reader-class member first rotates the read key
        // (group.ts:647-654): `rotateReadKey(memberKey)` runs BEFORE
        // `set(memberKey, role)`, so at rotation time the member still carries its
        // OLD reader-class role and is excluded via `RemoveMember`. The rotation's
        // writes consume a contiguous run of transaction indices starting at
        // `start_tx_index`; the writeOnly-grant writes below continue from where the
        // rotation left off (their member seals are tx-index-sensitive).
        if matches!(
            state.direct_role(member_key),
            Some(Role::Reader) | Some(Role::Writer) | Some(Role::Manager) | Some(Role::Admin)
        ) {
            let new_read_key =
                rotation_new_read_key.ok_or(AddMemberError::MissingRotationReadKey)?;
            // Struct-literal fields need the exact `&'a _` types; the destructured
            // bindings are double-refs (match ergonomics), so deref once.
            let rotate_input = RotateReadKeyInput {
                state: *state,
                group_id: *group_id,
                session_id: *session_id,
                start_tx_index: *start_tx_index,
                trigger: RotationTrigger::RemoveMember(member_key.to_string()),
                from_sealer_secret: *from_sealer_secret,
                current_read_key: current_read_key.clone(),
                new_read_key: new_read_key.clone(),
                members: *members,
                write_only_fresh_keys: *rotation_write_only_fresh_keys,
                parents: *parents,
            };
            match rotate_read_key(&rotate_input).map_err(AddMemberError::Rotation)? {
                RotateOutcome::Rotated(rotation_writes) => {
                    // Continue the writeOnly-grant writes from where rotation left off.
                    tx += rotation_writes.len() as u64;
                    writes.extend(rotation_writes);
                }
                // `rotateReadKey` early-returned (everyone can already read); it wrote
                // nothing, so the grant writes start at `start_tx_index` unchanged.
                RotateOutcome::SkippedEveryoneCanRead => {}
            }
        }

        // set(memberKey, role) (group.ts:656)
        writes.push(GroupKeyWrite {
            field: member_key.to_string(),
            value: role.as_str().to_string(),
        });
        tx += 1;

        // internalCreateWriteOnlyKeyForMember(memberKey, agent) (group.ts:683-740)
        let fresh = fresh_write_only_key.ok_or(AddMemberError::MissingFreshWriteOnlyKey)?;

        // set(`writeKeyFor_${memberKey}`, fresh.id) (group.ts:689)
        writes.push(GroupKeyWrite {
            field: format!("writeKeyFor_{member_key}"),
            value: fresh.id.clone(),
        });
        tx += 1;

        // storeKeyRevelationForMember(memberKey, agent, fresh) — reveal to self
        // (group.ts:691-696).
        writes.push(reveal_key_to_member(
            &fresh.id,
            &fresh.secret,
            member_key,
            from_sealer_secret,
            member_agent_sealer_id,
            group_id,
            session_id,
            tx,
        )?);
        tx += 1;

        // Reveal the fresh key to every reader-class member (group.ts:699-727).
        // `can_read` is exactly TS's role set here (reader/writer/admin/manager +
        // reader/writer/admin-invite; NOT managerInvite, NOT writeOnly). The newly
        // added member carries `writeOnly` post-`set`, so it is excluded — we skip
        // `member_key` explicitly to reproduce that (in a demotion its PRE-state role
        // is still reader-class here, so the explicit skip is what excludes it; the
        // preceding rotation already excluded it via `RemoveMember`).
        for m in members.iter() {
            if m.member_key == member_key {
                continue;
            }
            if state.can_read(&m.member_key) {
                writes.push(reveal_key_to_member(
                    &fresh.id,
                    &fresh.secret,
                    &m.member_key,
                    from_sealer_secret,
                    &m.agent_sealer_id,
                    group_id,
                    session_id,
                    tx,
                )?);
                tx += 1;
            }
        }

        // Reveal the fresh key to each parent group, standard path,
        // revealAllWriteOnlyKeys: false (group.ts:730-737).
        for p in parents.iter() {
            let pw =
                reveal_read_key_to_parent_group_standard(p, &fresh.id, &fresh.secret, &[], false)?;
            tx += pw.len() as u64;
            writes.extend(pw);
        }

        let _ = tx;
        return Ok(writes);
    }

    // --- non-everyone: reader-class branch (group.ts:648-680) ---------------
    // set(memberKey, role) (group.ts:655)
    writes.push(GroupKeyWrite {
        field: member_key.to_string(),
        value: role.as_str().to_string(),
    });
    tx += 1;

    // storeKeyRevelationForMember(memberKey, agent, currentReadKey) (group.ts:663-668)
    writes.push(reveal_key_to_member(
        &current_read_key.id,
        &current_read_key.secret,
        member_key,
        from_sealer_secret,
        member_agent_sealer_id,
        group_id,
        session_id,
        tx,
    )?);
    tx += 1;

    // Also reveal every existing writeOnly key to the new member (group.ts:670-679).
    for wk in existing_write_only_keys.iter() {
        writes.push(reveal_key_to_member(
            &wk.id,
            &wk.secret,
            member_key,
            from_sealer_secret,
            member_agent_sealer_id,
            group_id,
            session_id,
            tx,
        )?);
        tx += 1;
    }

    let _ = tx;
    Ok(writes)
}

/// All inputs to [`add_everyone_write_only`].
pub struct EveryoneWriteOnlyInput<'a> {
    /// The materialized group CoMap snapshot BEFORE the add — `state.everyone_role()`
    /// gives `everyone`'s previous role, which decides whether a rotation precedes
    /// the delete.
    pub state: &'a GroupKeyState,
    /// The group's CoValue id (seal nonce material for the rotation's member seals).
    pub group_id: &'a str,
    /// The current session id (seal nonce material).
    pub session_id: &'a str,
    /// `group.core.nextTransactionID().txIndex` immediately before the add — the
    /// `set(everyone, "writeOnly")` consumes this index; the rotation (if any) starts
    /// at `start_tx_index + 1`.
    pub start_tx_index: u64,
    /// The current agent's sealer secret (`from` of every rotation member seal).
    pub from_sealer_secret: &'a str,
    /// The group's current read key `(id, secret)` (`getCurrentReadKey()`), captured
    /// BEFORE any writes: its `id` names the `${id}_for_everyone` field deleted at the
    /// end, and it is the rotation's `current_read_key`.
    pub current_read_key: KeyPair,
    /// The fresh read key `(id, secret)` for the preceding `rotateReadKey("everyone")`
    /// — required only when `everyone`'s previous role is `reader`/`writer`.
    pub rotation_new_read_key: Option<&'a KeyPair>,
    /// One fresh writeOnly key per writeOnly member the rotation re-keys, in
    /// writeOnly-member order. Empty unless the rotation runs and has writeOnly members.
    pub rotation_write_only_fresh_keys: &'a [KeyPair],
    /// Members in `getMemberKeys()` order with resolved sealer ids (rotation input).
    pub members: &'a [MemberResolution],
    /// Parent groups in `getParentGroups()` order (rotation input, standard path).
    pub parents: &'a [ParentResolution],
}

/// Reproduce `addMember(everyone, "writeOnly")` (group.ts:590-627) as an ordered
/// list of group-map [`GroupKeyMutation`]s (set OR delete).
///
/// TS emits, in order:
/// 1. `set(everyone, "writeOnly")`.
/// 2. **Only when** `everyone`'s previous role was `reader`/`writer`:
///    `rotateReadKey("everyone")` — a full rotation with the `RemoveEveryone`
///    trigger (which bypasses the "everyone can already read" early-return guard).
///    Its writes start at `start_tx_index + 1` (the `set` above consumed
///    `start_tx_index`).
/// 3. `delete(`${currentReadKey.id}_for_everyone`)` — removes the plaintext
///    read-key reveal that made the group readable by everyone. The `del` op is
///    tx-index independent, so its position after the rotation does not change its
///    bytes.
///
/// Returns an empty vec when `everyone` is already `writeOnly` (TS's
/// `previousRole === role` early return). Errors if the previous role is neither a
/// valid everyone role nor absent, or if a needed rotation read key is missing.
pub fn add_everyone_write_only(
    input: &EveryoneWriteOnlyInput<'_>,
) -> Result<Vec<GroupKeyMutation>, AddMemberError> {
    let previous = input.state.everyone_role();

    // Early return: role unchanged (group.ts:586-588).
    if previous == Some(Role::WriteOnly) {
        return Ok(Vec::new());
    }

    let mut muts: Vec<GroupKeyMutation> = Vec::new();

    // 1. set(everyone, "writeOnly") (group.ts:604) — consumes `start_tx_index`.
    muts.push(GroupKeyMutation::Set(GroupKeyWrite {
        field: EVERYONE.to_string(),
        value: Role::WriteOnly.as_str().to_string(),
    }));

    // 2. rotateReadKey("everyone") when demoting a prior reader/writer everyone
    //    (group.ts:612-615). Rotation writes follow the `set`, so they start at
    //    `start_tx_index + 1`.
    if matches!(previous, Some(Role::Reader) | Some(Role::Writer)) {
        let new_read_key = input
            .rotation_new_read_key
            .ok_or(AddMemberError::MissingRotationReadKey)?;
        let rotate_input = RotateReadKeyInput {
            state: input.state,
            group_id: input.group_id,
            session_id: input.session_id,
            start_tx_index: input.start_tx_index + 1,
            trigger: RotationTrigger::RemoveEveryone,
            from_sealer_secret: input.from_sealer_secret,
            current_read_key: input.current_read_key.clone(),
            new_read_key: new_read_key.clone(),
            members: input.members,
            write_only_fresh_keys: input.rotation_write_only_fresh_keys,
            parents: input.parents,
        };
        match rotate_read_key(&rotate_input).map_err(AddMemberError::Rotation)? {
            RotateOutcome::Rotated(w) => muts.extend(w.into_iter().map(GroupKeyMutation::Set)),
            // RemoveEveryone bypasses the guard, so a real rotation never skips; keep
            // this exhaustive rather than unreachable-panicking.
            RotateOutcome::SkippedEveryoneCanRead => {}
        }
    }

    // 3. delete(`${currentReadKey.id}_for_everyone`) (group.ts:617).
    muts.push(GroupKeyMutation::Delete {
        field: format!("{}_for_{}", input.current_read_key.id, EVERYONE),
    });

    Ok(muts)
}

/// Reproduce `RawGroup.removeMember` (group.ts:1468-1482): when the caller is an
/// admin/manager, `rotateReadKey(memberKey)` first, then `set(memberKey,
/// "revoked")`. The rotation excludes and re-reveals around the removed member; the
/// `revoked` write is appended AFTER (matching TS's call order, so the member still
/// carries its OLD role while the rotation reads state).
///
/// `rotate_input.trigger` MUST be `RotationTrigger::RemoveMember(member_key)`.
/// If the rotation early-returns (everyone can already read), only the `revoked`
/// write is produced — exactly as TS (`rotateReadKey` returns without writing).
pub fn remove_member(
    rotate_input: &RotateReadKeyInput<'_>,
    member_key: &str,
    caller_is_admin_or_manager: bool,
) -> Result<Vec<GroupKeyWrite>, RotateError> {
    let mut writes = Vec::new();

    if caller_is_admin_or_manager {
        match rotate_read_key(rotate_input)? {
            RotateOutcome::Rotated(w) => writes.extend(w),
            RotateOutcome::SkippedEveryoneCanRead => {}
        }
    }

    // set(memberKey, "revoked", "trusting") (group.ts:1475)
    writes.push(GroupKeyWrite {
        field: member_key.to_string(),
        value: Role::Revoked.as_str().to_string(),
    });

    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FROM_SECRET: &str = "sealerSecret_zCktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8";
    const SEALER_ID: &str = "sealer_z6RpVnWdJifHJvxx7WM8aAbV8ER6vSEX2nLRodqtGj3jr";
    const GROUP_ID: &str = "co_zGroupID111111111";
    const SESSION_ID: &str = "co_zAcc_session_zSess";
    const READ_KEY_ID: &str = "key_zReadKey1111111";
    const READ_KEY_SECRET: &str = "keySecret_zswqrv48gsrwpBFbftEwnP2vB4jckpvfGJfXkwaniLCC";

    fn member(key: &str) -> MemberResolution {
        MemberResolution {
            member_key: key.to_string(),
            agent_sealer_id: SEALER_ID.to_string(),
        }
    }

    fn read_key() -> KeyPair {
        KeyPair {
            id: READ_KEY_ID.to_string(),
            secret: READ_KEY_SECRET.to_string(),
        }
    }

    fn fields(writes: &[GroupKeyWrite]) -> Vec<String> {
        writes.iter().map(|w| w.field.clone()).collect()
    }

    #[test]
    fn no_op_when_role_unchanged() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zReader111111": "reader",
        }));
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            member_key: "co_zReader111111",
            member_agent_sealer_id: SEALER_ID,
            role: Role::Reader,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: &[],
            fresh_write_only_key: None,
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        assert!(add_member_internal(&input).unwrap().is_empty());
    }

    #[test]
    fn add_reader_sets_role_then_reveals_read_key() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zAdmin1111111": "admin",
        }));
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 5,
            member_key: "co_zReader111111",
            member_agent_sealer_id: SEALER_ID,
            role: Role::Reader,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: &[],
            fresh_write_only_key: None,
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        let writes = add_member_internal(&input).unwrap();
        assert_eq!(
            fields(&writes),
            vec![
                "co_zReader111111".to_string(),
                format!("{READ_KEY_ID}_for_co_zReader111111"),
            ]
        );
        assert_eq!(writes[0].value, "reader");
        // The reveal seal is emitted at tx=6 (set consumed tx=5). Cross-check the
        // exact byte value against the leaf encoder.
        let expected = reveal_key_to_member(
            READ_KEY_ID,
            READ_KEY_SECRET,
            "co_zReader111111",
            FROM_SECRET,
            SEALER_ID,
            GROUP_ID,
            SESSION_ID,
            6,
        )
        .unwrap();
        assert_eq!(writes[1].value, expected.value);
    }

    #[test]
    fn add_reader_also_reveals_existing_write_only_keys() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zAdmin1111111": "admin",
            "writeKeyFor_co_zWO111111": "key_zWOexisting111",
        }));
        let wo = KeyPair {
            id: "key_zWOexisting111".to_string(),
            secret: READ_KEY_SECRET.to_string(),
        };
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            member_key: "co_zReader111111",
            member_agent_sealer_id: SEALER_ID,
            role: Role::Reader,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: std::slice::from_ref(&wo),
            fresh_write_only_key: None,
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        let writes = add_member_internal(&input).unwrap();
        assert_eq!(
            fields(&writes),
            vec![
                "co_zReader111111".to_string(),
                format!("{READ_KEY_ID}_for_co_zReader111111"),
                "key_zWOexisting111_for_co_zReader111111".to_string(),
            ]
        );
    }

    #[test]
    fn add_write_only_member_creates_fresh_key_and_reveals() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zAdmin1111111": "admin",
        }));
        let fresh = KeyPair {
            id: "key_zFreshWO11111".to_string(),
            secret: READ_KEY_SECRET.to_string(),
        };
        let members = vec![member("co_zAdmin1111111")];
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 2,
            member_key: "co_zWO1111111111",
            member_agent_sealer_id: SEALER_ID,
            role: Role::WriteOnly,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: &[],
            fresh_write_only_key: Some(&fresh),
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &members,
            parents: &[],
        };
        let writes = add_member_internal(&input).unwrap();
        assert_eq!(
            fields(&writes),
            vec![
                "co_zWO1111111111".to_string(),
                "writeKeyFor_co_zWO1111111111".to_string(),
                "key_zFreshWO11111_for_co_zWO1111111111".to_string(),
                "key_zFreshWO11111_for_co_zAdmin1111111".to_string(),
            ]
        );
        assert_eq!(writes[0].value, "writeOnly");
        assert_eq!(writes[1].value, "key_zFreshWO11111");
        // self-reveal seal at tx=4 (set role=2, set writeKeyFor=3, reveal=4).
        let self_reveal = reveal_key_to_member(
            "key_zFreshWO11111",
            READ_KEY_SECRET,
            "co_zWO1111111111",
            FROM_SECRET,
            SEALER_ID,
            GROUP_ID,
            SESSION_ID,
            4,
        )
        .unwrap();
        assert_eq!(writes[2].value, self_reveal.value);
    }

    #[test]
    fn write_only_demotion_of_reader_rotates_then_grants() {
        // A group with an admin (self) and a reader who is being demoted to
        // writeOnly. TS first calls rotateReadKey(member) — which re-reveals the new
        // read key to the admin ONLY (member excluded) then writes old_for_new /
        // readKey / groupSealer — THEN set(member, writeOnly), writeKeyFor_, and
        // reveals the fresh writeOnly key to self + admin.
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": "key_zOLDreadkey1111",
            "co_zAdmin1111111": "admin",
            "co_zMember111111": "reader",
        }));
        let old_read_key = KeyPair {
            id: "key_zOLDreadkey1111".to_string(),
            secret: "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn".to_string(),
        };
        let new_read_key = KeyPair {
            id: "key_zNEWreadkey1111".to_string(),
            secret: READ_KEY_SECRET.to_string(),
        };
        let fresh = KeyPair {
            id: "key_zFreshWO11111".to_string(),
            secret: READ_KEY_SECRET.to_string(),
        };
        let members = vec![member("co_zAdmin1111111"), member("co_zMember111111")];
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            member_key: "co_zMember111111",
            member_agent_sealer_id: SEALER_ID,
            role: Role::WriteOnly,
            from_sealer_secret: FROM_SECRET,
            current_read_key: old_read_key,
            existing_write_only_keys: &[],
            fresh_write_only_key: Some(&fresh),
            rotation_new_read_key: Some(&new_read_key),
            rotation_write_only_fresh_keys: &[],
            members: &members,
            parents: &[],
        };
        let writes = add_member_internal(&input).unwrap();
        // Rotation writes (member excluded) come FIRST, then the writeOnly grant.
        assert_eq!(
            fields(&writes),
            vec![
                // rotation: new read key to admin only, then the standard tail
                "key_zNEWreadkey1111_for_co_zAdmin1111111".to_string(),
                "key_zOLDreadkey1111_for_key_zNEWreadkey1111".to_string(),
                "readKey".to_string(),
                "groupSealer".to_string(),
                // writeOnly grant
                "co_zMember111111".to_string(),
                "writeKeyFor_co_zMember111111".to_string(),
                "key_zFreshWO11111_for_co_zMember111111".to_string(),
                "key_zFreshWO11111_for_co_zAdmin1111111".to_string(),
            ]
        );
        // The removed/demoted member is NOT re-revealed the new READ key.
        assert!(!writes
            .iter()
            .any(|w| w.field == "key_zNEWreadkey1111_for_co_zMember111111"));
        assert_eq!(writes[4].value, "writeOnly");
        // The self-reveal of the fresh writeOnly key is emitted at tx=6: rotation
        // consumed tx 0..=3 (4 writes), set(member)=4, writeKeyFor_=5, self-reveal=6.
        let self_reveal = reveal_key_to_member(
            "key_zFreshWO11111",
            READ_KEY_SECRET,
            "co_zMember111111",
            FROM_SECRET,
            SEALER_ID,
            GROUP_ID,
            SESSION_ID,
            6,
        )
        .unwrap();
        assert_eq!(writes[6].value, self_reveal.value);
    }

    #[test]
    fn everyone_reader_reveals_read_key_in_plaintext() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zAdmin1111111": "admin",
        }));
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            member_key: EVERYONE,
            member_agent_sealer_id: SEALER_ID,
            role: Role::Reader,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: &[],
            fresh_write_only_key: None,
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        let writes = add_member_internal(&input).unwrap();
        assert_eq!(
            writes,
            vec![
                GroupKeyWrite {
                    field: "everyone".to_string(),
                    value: "reader".to_string(),
                },
                GroupKeyWrite {
                    field: format!("{READ_KEY_ID}_for_everyone"),
                    value: READ_KEY_SECRET.to_string(),
                },
            ]
        );
    }

    #[test]
    fn everyone_write_only_is_deferred() {
        let state = GroupKeyState::from_snapshot(&json!({ "readKey": READ_KEY_ID }));
        let input = AddMemberInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            member_key: EVERYONE,
            member_agent_sealer_id: SEALER_ID,
            role: Role::WriteOnly,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            existing_write_only_keys: &[],
            fresh_write_only_key: None,
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        // add_member_internal defers everyone->writeOnly to add_everyone_write_only.
        assert!(matches!(
            add_member_internal(&input),
            Err(AddMemberError::Deferred(_))
        ));
    }

    #[test]
    fn everyone_write_only_fresh_sets_then_deletes_without_rotation() {
        // everyone had no prior role → no rotation: just set(everyone,writeOnly)
        // then delete the (possibly absent) plaintext reveal.
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "co_zAdmin1111111": "admin",
        }));
        let input = EveryoneWriteOnlyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        let muts = add_everyone_write_only(&input).unwrap();
        assert_eq!(
            muts,
            vec![
                GroupKeyMutation::Set(GroupKeyWrite {
                    field: "everyone".to_string(),
                    value: "writeOnly".to_string(),
                }),
                GroupKeyMutation::Delete {
                    field: format!("{READ_KEY_ID}_for_everyone"),
                },
            ]
        );
    }

    #[test]
    fn everyone_write_only_from_reader_rotates_then_deletes() {
        // everyone was a reader → set(everyone,writeOnly), THEN a full rotation
        // (RemoveEveryone), THEN delete(oldReadKey_for_everyone).
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": "key_zOLDreadkey1111",
            "co_zAdmin1111111": "admin",
            "everyone": "reader",
        }));
        let old_read_key = KeyPair {
            id: "key_zOLDreadkey1111".to_string(),
            secret: "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn".to_string(),
        };
        let new_read_key = KeyPair {
            id: "key_zNEWreadkey1111".to_string(),
            secret: READ_KEY_SECRET.to_string(),
        };
        let members = vec![member("co_zAdmin1111111")];
        let input = EveryoneWriteOnlyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            from_sealer_secret: FROM_SECRET,
            current_read_key: old_read_key,
            rotation_new_read_key: Some(&new_read_key),
            rotation_write_only_fresh_keys: &[],
            members: &members,
            parents: &[],
        };
        let muts = add_everyone_write_only(&input).unwrap();
        let f: Vec<&str> = muts.iter().map(|m| m.field()).collect();
        assert_eq!(
            f,
            vec![
                "everyone",
                "key_zNEWreadkey1111_for_co_zAdmin1111111",
                "key_zOLDreadkey1111_for_key_zNEWreadkey1111",
                "readKey",
                "groupSealer",
                "key_zOLDreadkey1111_for_everyone",
            ]
        );
        // First mutation is the set; last is the delete.
        assert!(matches!(&muts[0], GroupKeyMutation::Set(_)));
        assert!(matches!(muts.last().unwrap(), GroupKeyMutation::Delete { .. }));
        // The admin's re-reveal seal is at tx=1 (set(everyone) consumed tx=0, so the
        // rotation begins at tx=1).
        if let GroupKeyMutation::Set(w) = &muts[1] {
            let expected = reveal_key_to_member(
                "key_zNEWreadkey1111",
                READ_KEY_SECRET,
                "co_zAdmin1111111",
                FROM_SECRET,
                SEALER_ID,
                GROUP_ID,
                SESSION_ID,
                1,
            )
            .unwrap();
            assert_eq!(w.value, expected.value);
        } else {
            panic!("expected a set");
        }
    }

    #[test]
    fn everyone_write_only_noop_when_already_writeonly() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": READ_KEY_ID,
            "everyone": "writeOnly",
        }));
        let input = EveryoneWriteOnlyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            rotation_new_read_key: None,
            rotation_write_only_fresh_keys: &[],
            members: &[],
            parents: &[],
        };
        assert!(add_everyone_write_only(&input).unwrap().is_empty());
    }

    #[test]
    fn remove_member_appends_revoked_after_rotation() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": "key_zOLDreadkey1111",
            "co_zAdmin1111111": "admin",
            "co_zReader111111": "reader",
        }));
        let members = vec![member("co_zAdmin1111111"), member("co_zReader111111")];
        let rotate_input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger: RotationTrigger::RemoveMember("co_zReader111111".to_string()),
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: "key_zOLDreadkey1111".to_string(),
                secret: "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn".to_string(),
            },
            new_read_key: KeyPair {
                id: "key_zNEWreadkey1111".to_string(),
                secret: READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[],
            parents: &[],
        };
        let writes = remove_member(&rotate_input, "co_zReader111111", true).unwrap();
        // last write is the revoked set; the removed reader is NOT re-revealed to.
        let last = writes.last().unwrap();
        assert_eq!(last.field, "co_zReader111111");
        assert_eq!(last.value, "revoked");
        assert!(!writes
            .iter()
            .any(|w| w.field == "key_zNEWreadkey1111_for_co_zReader111111"));
        assert!(writes
            .iter()
            .any(|w| w.field == "key_zNEWreadkey1111_for_co_zAdmin1111111"));
    }

    #[test]
    fn remove_member_without_admin_only_revokes() {
        let state = GroupKeyState::from_snapshot(&json!({ "readKey": READ_KEY_ID }));
        let rotate_input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger: RotationTrigger::RemoveMember("co_zX".to_string()),
            from_sealer_secret: FROM_SECRET,
            current_read_key: read_key(),
            new_read_key: read_key(),
            members: &[],
            write_only_fresh_keys: &[],
            parents: &[],
        };
        let writes = remove_member(&rotate_input, "co_zX", false).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].value, "revoked");
    }

    // -----------------------------------------------------------------------
    // Golden-fixture replay: load `data/group_key_membership/*.json` (exported by
    // `packages/cojson/src/tests/groupKeyWriteFixtures.export.test.ts` from real TS
    // `addMemberInternal` / `removeMember`) and assert the native functions
    // reproduce the EXACT ordered `(field, value)` write list byte-for-byte.
    // -----------------------------------------------------------------------
    mod fixtures {
        use super::super::*;
        use crate::core::group_key_state::GroupKeyState;
        use crate::core::group_key_test_support::{KeyPairFx, MemberFx, ParentFx, WriteFx};
        use serde::Deserialize;

        fn to_members(v: &[MemberFx]) -> Vec<MemberResolution> {
            v.iter()
                .map(|m| MemberResolution {
                    member_key: m.member_key.clone(),
                    agent_sealer_id: m.agent_sealer_id.clone(),
                })
                .collect()
        }
        fn to_keys(v: &[KeyPairFx]) -> Vec<KeyPair> {
            v.iter()
                .map(|k| KeyPair {
                    id: k.id.clone(),
                    secret: k.secret.clone(),
                })
                .collect()
        }
        fn to_parents(v: &[ParentFx]) -> Vec<ParentResolution> {
            v.iter()
                .map(|p| ParentResolution {
                    read_key_id: p.read_key_id.clone(),
                    read_key_secret: p.read_key_secret.clone(),
                })
                .collect()
        }

        fn assert_writes(name: &str, got: &[GroupKeyWrite], want: &[WriteFx]) {
            assert_eq!(
                got.len(),
                want.len(),
                "[{name}] write COUNT differs\n native: {:#?}\n TS:     {:#?}",
                got.iter().map(|w| &w.field).collect::<Vec<_>>(),
                want.iter().map(|w| &w.field).collect::<Vec<_>>(),
            );
            for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
                assert_eq!(g.field, w.field, "[{name}] write #{i} FIELD differs");
                assert_eq!(
                    g.value, w.value,
                    "[{name}] write #{i} ({}) VALUE differs (byte mismatch vs TS)",
                    w.field
                );
            }
        }

        // --- addMemberInternal fixtures -------------------------------------
        #[derive(Deserialize)]
        struct AddFx {
            #[allow(dead_code)]
            description: String,
            #[serde(rename = "groupId")]
            group_id: String,
            #[serde(rename = "sessionId")]
            session_id: String,
            #[serde(rename = "startTxIndex")]
            start_tx_index: u64,
            #[serde(rename = "memberKey")]
            member_key: String,
            #[serde(rename = "memberAgentSealerId")]
            member_agent_sealer_id: String,
            role: String,
            #[serde(rename = "fromSealerSecret")]
            from_sealer_secret: String,
            #[serde(rename = "currentReadKey")]
            current_read_key: KeyPairFx,
            #[serde(rename = "existingWriteOnlyKeys")]
            existing_write_only_keys: Vec<KeyPairFx>,
            #[serde(rename = "freshWriteOnlyKey")]
            fresh_write_only_key: Option<KeyPairFx>,
            // Only present on the writeOnly-demotion fixture; default elsewhere.
            #[serde(rename = "rotationNewReadKey", default)]
            rotation_new_read_key: Option<KeyPairFx>,
            #[serde(rename = "rotationWriteOnlyFreshKeys", default)]
            rotation_write_only_fresh_keys: Vec<KeyPairFx>,
            members: Vec<MemberFx>,
            parents: Vec<ParentFx>,
            #[serde(rename = "expectedWrites")]
            expected_writes: Vec<WriteFx>,
        }

        fn replay_add(name: &str) {
            let path = format!("data/group_key_membership/{name}.json");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let fx: AddFx =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));

            let state = GroupKeyState::from_snapshot(
                &serde_json::from_str::<serde_json::Value>(&text).unwrap()["snapshot"],
            );
            let members = to_members(&fx.members);
            let existing = to_keys(&fx.existing_write_only_keys);
            let parents = to_parents(&fx.parents);
            let fresh = fx.fresh_write_only_key.as_ref().map(|k| KeyPair {
                id: k.id.clone(),
                secret: k.secret.clone(),
            });
            let rotation_new_read_key = fx.rotation_new_read_key.as_ref().map(|k| KeyPair {
                id: k.id.clone(),
                secret: k.secret.clone(),
            });
            let rotation_wo = to_keys(&fx.rotation_write_only_fresh_keys);
            let role = Role::parse(&fx.role).unwrap_or_else(|| panic!("[{name}] bad role"));

            let input = AddMemberInput {
                state: &state,
                group_id: &fx.group_id,
                session_id: &fx.session_id,
                start_tx_index: fx.start_tx_index,
                member_key: &fx.member_key,
                member_agent_sealer_id: &fx.member_agent_sealer_id,
                role,
                from_sealer_secret: &fx.from_sealer_secret,
                current_read_key: KeyPair {
                    id: fx.current_read_key.id.clone(),
                    secret: fx.current_read_key.secret.clone(),
                },
                existing_write_only_keys: &existing,
                fresh_write_only_key: fresh.as_ref(),
                rotation_new_read_key: rotation_new_read_key.as_ref(),
                rotation_write_only_fresh_keys: &rotation_wo,
                members: &members,
                parents: &parents,
            };
            let writes = add_member_internal(&input)
                .unwrap_or_else(|e| panic!("[{name}] add_member_internal failed: {e}"));
            assert_writes(name, &writes, &fx.expected_writes);
        }

        #[test]
        fn add_reader() {
            replay_add("add_reader");
        }
        #[test]
        fn add_writer_with_existing_writeonly() {
            replay_add("add_writer_with_existing_writeonly");
        }
        #[test]
        fn add_write_only() {
            replay_add("add_write_only");
        }
        #[test]
        fn create_invite_reader() {
            replay_add("create_invite_reader");
        }
        #[test]
        fn everyone_reader() {
            replay_add("everyone_reader");
        }
        #[test]
        fn write_only_demotion() {
            replay_add("write_only_demotion");
        }

        // --- everyone -> writeOnly fixture (set + del mutations) ------------
        fn default_op() -> String {
            "set".to_string()
        }
        #[derive(Deserialize)]
        struct MutFx {
            field: String,
            #[serde(default)]
            value: Option<String>,
            #[serde(default = "default_op")]
            op: String,
        }
        #[derive(Deserialize)]
        struct EveryoneWriteOnlyFx {
            #[allow(dead_code)]
            description: String,
            #[serde(rename = "groupId")]
            group_id: String,
            #[serde(rename = "sessionId")]
            session_id: String,
            #[serde(rename = "startTxIndex")]
            start_tx_index: u64,
            #[serde(rename = "fromSealerSecret")]
            from_sealer_secret: String,
            #[serde(rename = "currentReadKey")]
            current_read_key: KeyPairFx,
            #[serde(rename = "rotationNewReadKey")]
            rotation_new_read_key: Option<KeyPairFx>,
            #[serde(rename = "rotationWriteOnlyFreshKeys")]
            rotation_write_only_fresh_keys: Vec<KeyPairFx>,
            members: Vec<MemberFx>,
            parents: Vec<ParentFx>,
            #[serde(rename = "expectedWrites")]
            expected_writes: Vec<MutFx>,
        }

        #[test]
        fn everyone_write_only() {
            let path = "data/group_key_membership/everyone_write_only.json";
            let text =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let fx: EveryoneWriteOnlyFx =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
            let state = GroupKeyState::from_snapshot(
                &serde_json::from_str::<serde_json::Value>(&text).unwrap()["snapshot"],
            );
            let members = to_members(&fx.members);
            let parents = to_parents(&fx.parents);
            let rotation_new_read_key = fx.rotation_new_read_key.as_ref().map(|k| KeyPair {
                id: k.id.clone(),
                secret: k.secret.clone(),
            });
            let rotation_wo = to_keys(&fx.rotation_write_only_fresh_keys);

            let input = EveryoneWriteOnlyInput {
                state: &state,
                group_id: &fx.group_id,
                session_id: &fx.session_id,
                start_tx_index: fx.start_tx_index,
                from_sealer_secret: &fx.from_sealer_secret,
                current_read_key: KeyPair {
                    id: fx.current_read_key.id.clone(),
                    secret: fx.current_read_key.secret.clone(),
                },
                rotation_new_read_key: rotation_new_read_key.as_ref(),
                rotation_write_only_fresh_keys: &rotation_wo,
                members: &members,
                parents: &parents,
            };
            let muts = add_everyone_write_only(&input)
                .unwrap_or_else(|e| panic!("add_everyone_write_only failed: {e}"));

            assert_eq!(
                muts.len(),
                fx.expected_writes.len(),
                "mutation COUNT differs\n native: {:#?}\n TS:     {:#?}",
                muts.iter().map(|m| m.field()).collect::<Vec<_>>(),
                fx.expected_writes.iter().map(|w| &w.field).collect::<Vec<_>>(),
            );
            for (i, (got, want)) in muts.iter().zip(fx.expected_writes.iter()).enumerate() {
                match (got, want.op.as_str()) {
                    (GroupKeyMutation::Set(w), "set") => {
                        assert_eq!(w.field, want.field, "mutation #{i} FIELD differs");
                        assert_eq!(
                            &w.value,
                            want.value.as_ref().unwrap(),
                            "mutation #{i} ({}) VALUE differs (byte mismatch vs TS)",
                            want.field
                        );
                    }
                    (GroupKeyMutation::Delete { field }, "del") => {
                        assert_eq!(field, &want.field, "mutation #{i} DELETE field differs");
                    }
                    (g, op) => panic!(
                        "mutation #{i} op mismatch: native {g:?} vs TS op={op:?} field={}",
                        want.field
                    ),
                }
            }
        }

        // --- removeMember fixture -------------------------------------------
        #[derive(Deserialize)]
        struct RemoveFx {
            #[allow(dead_code)]
            description: String,
            #[serde(rename = "memberKey")]
            member_key: String,
            #[serde(rename = "callerIsAdminOrManager")]
            caller_is_admin_or_manager: bool,
            #[serde(rename = "groupId")]
            group_id: String,
            #[serde(rename = "sessionId")]
            session_id: String,
            #[serde(rename = "startTxIndex")]
            start_tx_index: u64,
            #[serde(rename = "fromSealerSecret")]
            from_sealer_secret: String,
            #[serde(rename = "currentReadKey")]
            current_read_key: KeyPairFx,
            #[serde(rename = "newReadKey")]
            new_read_key: KeyPairFx,
            members: Vec<MemberFx>,
            #[serde(rename = "writeOnlyFreshKeys")]
            write_only_fresh_keys: Vec<KeyPairFx>,
            parents: Vec<ParentFx>,
            #[serde(rename = "expectedWrites")]
            expected_writes: Vec<WriteFx>,
        }

        fn replay_remove(name: &str) {
            let path = format!("data/group_key_membership/{name}.json");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let fx: RemoveFx =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));
            let state = GroupKeyState::from_snapshot(
                &serde_json::from_str::<serde_json::Value>(&text).unwrap()["snapshot"],
            );
            let members = to_members(&fx.members);
            let wo_keys = to_keys(&fx.write_only_fresh_keys);
            let parents = to_parents(&fx.parents);

            let rotate_input = RotateReadKeyInput {
                state: &state,
                group_id: &fx.group_id,
                session_id: &fx.session_id,
                start_tx_index: fx.start_tx_index,
                trigger: RotationTrigger::RemoveMember(fx.member_key.clone()),
                from_sealer_secret: &fx.from_sealer_secret,
                current_read_key: KeyPair {
                    id: fx.current_read_key.id.clone(),
                    secret: fx.current_read_key.secret.clone(),
                },
                new_read_key: KeyPair {
                    id: fx.new_read_key.id.clone(),
                    secret: fx.new_read_key.secret.clone(),
                },
                members: &members,
                write_only_fresh_keys: &wo_keys,
                parents: &parents,
            };
            let writes =
                remove_member(&rotate_input, &fx.member_key, fx.caller_is_admin_or_manager)
                    .unwrap_or_else(|e| panic!("[{name}] remove_member failed: {e}"));
            assert_writes(name, &writes, &fx.expected_writes);
        }

        #[test]
        fn remove_reader() {
            replay_remove("remove_reader");
        }
    }
}
