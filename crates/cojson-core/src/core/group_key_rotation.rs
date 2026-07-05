//! Native orchestration of `RawGroup.rotateReadKey` — the group key-rotation
//! write path.
//!
//! [`rotate_read_key`] is a **pure, deterministic** reproduction of
//! `packages/cojson/src/coValues/group.ts`'s `rotateReadKey` (group.ts:1092-1269):
//! given a materialized [`GroupKeyState`] snapshot plus the *non-native* inputs
//! that TS resolves at runtime (fresh random key secrets, account→agent identity
//! resolution, parent read-key access), it emits the exact ordered list of
//! `(field, value)` writes that TS's `rotateReadKey` performs — byte-for-byte,
//! because every value is produced by the already-proven leaf encoders in
//! [`crate::core::group_keys`] / [`crate::crypto`].
//!
//! # Why these inputs are parameters, not derived
//!
//! Three classes of information are *deliberately* passed in rather than derived
//! natively, because cojson-core has no equivalent:
//!
//! - **Randomness.** `crypto.newRandomKeySecret()` produces the new read key and
//!   each fresh writeOnly key. This function is deterministic; TS generates the
//!   randomness and passes the resulting `(id, secret)` pairs in.
//! - **Account→agent identity resolution.** `resolveAccountAgent` +
//!   `getAgentSealerID` map a member account id to the sealer id a revelation is
//!   sealed *to*. Native state has no account-agent graph (the earlier R5
//!   scoping finding), so the caller supplies each member's `agent_sealer_id`.
//! - **Parent read-key access.** Revealing to a parent group needs the parent's
//!   *read key secret*, which requires the unseal/decrypt traversal that lives
//!   only in TS (`getUncachedReadKey`). The caller supplies each parent's
//!   `(read_key_id, read_key_secret)`.
//!
//! Everything else — the early-return guard, *which* members are readers vs.
//! writeOnly, the exact write ORDER and per-write transaction index (which the
//! member seals depend on) — is decided here from [`GroupKeyState`], mirroring
//! TS line-for-line.
//!
//! # Transaction-index invariant
//!
//! Each `group.set(...)` in TS is one transaction, so `nextTransactionID().txIndex`
//! advances by exactly one per write (coValueCore.ts `nextTransactionID` reads
//! `getTransactionsCount(sessionID)`). A member seal's nonce embeds that txIndex,
//! so the SEALED VALUES depend on the *position* of each write in the rotation.
//! This function assigns `start_tx_index + i` to the i-th emitted write, in TS's
//! exact emission order, so the seals reproduce byte-for-byte.
//!
//! # Scope — what is NOT handled here (see the deferred branches below)
//!
//! - **The non-member parent path.** `revealReadKeyToParentGroup` has a branch
//!   for when the current account is *not* an account-member of the parent
//!   (group.ts:1350-1387): it either seals to the parent's group sealer
//!   (`sealForGroup`, which is NON-deterministic — fresh ephemeral key) or, as a
//!   legacy fallback, mutates the *parent* CoValue. This function only handles
//!   the standard path (we ARE an account member of every parent, so we reveal
//!   via the parent read key with `encryptKeySecret`). Callers whose parent
//!   requires the group-sealer path must not use this function for that parent.
//! - **Child-group recursion.** `forEachChildGroup` (group.ts:1249-1268)
//!   recursively rotates every loaded child group. Each child is a SEPARATE
//!   CoValue with its own session/tx stream; reproducing it is a separate
//!   orchestration over that child's own [`GroupKeyState`], not part of this
//!   group's write set.
//!
//! This module is native-only and is intentionally NOT wired into production
//! `group.ts` (mirrors the R1/R2/R5 pattern).

use crate::core::group_key_state::GroupKeyState;
use crate::core::group_engine::types::Role;
use crate::core::group_keys::{
    format_group_sealer_value, reveal_key_to_member, reveal_key_to_parent_group, GroupKeyWrite,
};
use crate::crypto::error::CryptoError;
use crate::crypto::key_secret::group_sealer_from_read_key;

/// A `(keyID, keySecret)` pair — a read key or a fresh writeOnly key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub id: String,
    pub secret: String,
}

/// A member that may receive a key revelation, with the identity resolution TS
/// performs via `resolveAccountAgent` + `getAgentSealerID`.
///
/// `members` must be supplied in `getMemberKeys()` order (group.ts:854-858 —
/// `keys()` insertion order), because that order determines each seal's
/// transaction index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberResolution {
    /// The account/agent map key (`co_…` or `sealer_…/signer_…`).
    pub member_key: String,
    /// `getAgentSealerID(resolveAccountAgent(member_key))` — the sealer id a
    /// revelation to this member is sealed *to*.
    pub agent_sealer_id: String,
}

/// A parent group we reveal the new read key to, via the standard
/// (account-member) path. Supplied in `getParentGroups()` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentResolution {
    pub read_key_id: String,
    pub read_key_secret: String,
}

/// Which `rotateReadKey(...)` call this is — mirrors the optional
/// `removedMemberKey` argument (group.ts:1093).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationTrigger {
    /// `rotateReadKey()` — plain rotation, no member excluded.
    Rotate,
    /// `rotateReadKey("everyone")` — demoting `everyone`; the early-return guard
    /// is bypassed.
    RemoveEveryone,
    /// `rotateReadKey(memberKey)` — the member is excluded from readers /
    /// writeOnly members (they are being removed or demoted; note TS calls
    /// rotate BEFORE writing the member's new/`revoked` role, so the member
    /// still carries its OLD role in `state`).
    RemoveMember(String),
}

/// The result of [`rotate_read_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The early-return guard fired (group.ts:1094-1098): `everyone` can already
    /// read and we are not demoting `everyone`, so rotating is useless. No writes.
    SkippedEveryoneCanRead,
    /// The ordered list of `(field, value)` writes the rotation performs, in TS's
    /// exact emission order.
    Rotated(Vec<GroupKeyWrite>),
}

/// Error cases for [`rotate_read_key`].
#[derive(Debug)]
pub enum RotateError {
    /// The number of supplied fresh writeOnly keys does not match the number of
    /// writeOnly members derived from `state`.
    WriteOnlyKeyCountMismatch { expected: usize, provided: usize },
    /// A leaf encoder failed (bad key/sealer format).
    Crypto(CryptoError),
}

impl std::fmt::Display for RotateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotateError::WriteOnlyKeyCountMismatch { expected, provided } => write!(
                f,
                "writeOnly fresh-key count mismatch: {expected} writeOnly members but {provided} keys provided"
            ),
            RotateError::Crypto(e) => write!(f, "crypto error during rotation: {e:?}"),
        }
    }
}

impl std::error::Error for RotateError {}

impl From<CryptoError> for RotateError {
    fn from(e: CryptoError) -> Self {
        RotateError::Crypto(e)
    }
}

/// All inputs to [`rotate_read_key`]. Grouped into a struct because TS's
/// `rotateReadKey` reads a lot of resolved runtime state.
pub struct RotateReadKeyInput<'a> {
    /// The materialized group CoMap snapshot at rotation time (BEFORE any of the
    /// rotation's own writes, and — for `RemoveMember` — BEFORE the member's
    /// role is overwritten, matching TS's call order).
    pub state: &'a GroupKeyState,
    /// The group's CoValue id (`in` field of the seal nonce material).
    pub group_id: &'a str,
    /// The current session id (`tx.sessionID` of the seal nonce material).
    pub session_id: &'a str,
    /// `group.core.nextTransactionID().txIndex` immediately before rotation —
    /// the txIndex of the FIRST write.
    pub start_tx_index: u64,
    /// Which `rotateReadKey(...)` overload this is.
    pub trigger: RotationTrigger,
    /// The current agent's sealer secret (`getCurrentAgent().currentSealerSecret()`),
    /// the `from` of every member seal.
    pub from_sealer_secret: &'a str,
    /// The current read key `(id, secret)` (`getCurrentReadKey()`), re-encrypted
    /// under the new key as `${oldId}_for_${newId}`.
    pub current_read_key: KeyPair,
    /// The freshly generated new read key `(id, secret)`
    /// (`crypto.newRandomKeySecret()`).
    pub new_read_key: KeyPair,
    /// Every member key in `getMemberKeys()` order, with resolved sealer ids.
    pub members: &'a [MemberResolution],
    /// One fresh writeOnly key per writeOnly member, in writeOnly-member order.
    pub write_only_fresh_keys: &'a [KeyPair],
    /// Parent groups in `getParentGroups()` order (standard/account-member path).
    pub parents: &'a [ParentResolution],
}

/// Reproduce `RawGroup.rotateReadKey` (group.ts:1092-1269) as a pure ordered
/// list of group-map writes. See the module docs for the input contract and the
/// deferred branches.
pub fn rotate_read_key(input: &RotateReadKeyInput<'_>) -> Result<RotateOutcome, RotateError> {
    let RotateReadKeyInput {
        state,
        group_id,
        session_id,
        start_tx_index,
        trigger,
        from_sealer_secret,
        current_read_key,
        new_read_key,
        members,
        write_only_fresh_keys,
        parents,
    } = input;

    // --- Early-return guard (group.ts:1094-1098) ---------------------------
    // `if (removedMemberKey !== EVERYONE && canRead(this, EVERYONE)) return;`
    // When everyone can already read, a rotated key would be revealed to
    // everyone in plaintext, so rotation is pointless — UNLESS we're in the act
    // of demoting everyone (RemoveEveryone), where we must proceed.
    if !matches!(trigger, RotationTrigger::RemoveEveryone) && state.everyone_can_read() {
        return Ok(RotateOutcome::SkippedEveryoneCanRead);
    }

    // The single member excluded from `memberKeys` (group.ts:1100-1102). Only a
    // specific removed member is excluded; "everyone" is not a member key, and a
    // plain rotate excludes nobody.
    let removed: Option<&str> = match trigger {
        RotationTrigger::RemoveMember(k) => Some(k.as_str()),
        _ => None,
    };

    // --- Classify members, preserving caller (getMemberKeys) order ----------
    // currentlyPermittedReaders = memberKeys.filter(canRead)   (group.ts:1104-1106)
    // writeOnlyMembers          = memberKeys.filter(writeOnly | writeOnlyInvite)
    //                                                           (group.ts:1108-1111)
    // Both filters are over the SAME order, so a single pass preserves it.
    let mut readers: Vec<&MemberResolution> = Vec::new();
    let mut write_only: Vec<&MemberResolution> = Vec::new();
    for m in members.iter() {
        if Some(m.member_key.as_str()) == removed {
            continue;
        }
        if state.can_read(&m.member_key) {
            readers.push(m);
        } else if matches!(
            state.direct_role(&m.member_key),
            Some(Role::WriteOnly) | Some(Role::WriteOnlyInvite)
        ) {
            write_only.push(m);
        }
    }

    if write_only.len() != write_only_fresh_keys.len() {
        return Err(RotateError::WriteOnlyKeyCountMismatch {
            expected: write_only.len(),
            provided: write_only_fresh_keys.len(),
        });
    }

    let mut writes: Vec<GroupKeyWrite> = Vec::new();
    let mut tx = *start_tx_index;

    // --- 1. Reveal the new read key to every currently-permitted reader -----
    //        (group.ts:1130-1146, storeKeyRevelationForMember)
    for r in &readers {
        writes.push(reveal_key_to_member(
            &new_read_key.id,
            &new_read_key.secret,
            &r.member_key,
            from_sealer_secret,
            &r.agent_sealer_id,
            group_id,
            session_id,
            tx,
        )?);
        tx += 1;
    }

    // --- 2. Fresh writeOnly key per writeOnly member (group.ts:1152-1198) ----
    for (i, wom) in write_only.iter().enumerate() {
        let wk = &write_only_fresh_keys[i];

        // 2a. reveal the new writeOnly key to the writeOnly member itself
        //     (group.ts:1164-1169)
        writes.push(reveal_key_to_member(
            &wk.id,
            &wk.secret,
            &wom.member_key,
            from_sealer_secret,
            &wom.agent_sealer_id,
            group_id,
            session_id,
            tx,
        )?);
        tx += 1;

        // 2b. writeKeyFor_<member> = writeOnlyKey.id (group.ts:1170)
        writes.push(GroupKeyWrite {
            field: format!("writeKeyFor_{}", wom.member_key),
            value: wk.id.clone(),
        });
        tx += 1;

        // 2c. reveal the writeOnly key to every currently-permitted reader
        //     (group.ts:1172-1188)
        for r in &readers {
            writes.push(reveal_key_to_member(
                &wk.id,
                &wk.secret,
                &r.member_key,
                from_sealer_secret,
                &r.agent_sealer_id,
                group_id,
                session_id,
                tx,
            )?);
            tx += 1;
        }

        // 2d. reveal the writeOnly key to each parent group, standard path,
        //     revealAllWriteOnlyKeys: false (group.ts:1190-1197 →
        //     revealReadKeyToParentGroup → storeKeyRevelationForParentGroup).
        for p in parents.iter() {
            writes.push(reveal_key_to_parent_group(
                &p.read_key_id,
                &p.read_key_secret,
                &wk.id,
                &wk.secret,
            )?);
            tx += 1;
        }
    }

    // --- 3. ${oldKeyId}_for_${newKeyId} (group.ts:1200-1207) ----------------
    //        encryptKeySecret({ encrypting: newReadKey, toEncrypt: currentReadKey })
    //        → field `${currentReadKey.id}_for_${newReadKey.id}`.
    writes.push(reveal_key_to_parent_group(
        &new_read_key.id,     // "encrypting" / parent
        &new_read_key.secret,
        &current_read_key.id, // "toEncrypt" / child
        &current_read_key.secret,
    )?);
    tx += 1;

    // --- 4. readKey = newReadKey.id (group.ts:1209) -------------------------
    writes.push(GroupKeyWrite {
        field: "readKey".to_string(),
        value: new_read_key.id.clone(),
    });
    tx += 1;

    // --- 5. groupSealer = "<newReadKeyId>@<sealerId>" (group.ts:1211-1221) ---
    //        Derived deterministically from the new read key secret.
    let sealer = group_sealer_from_read_key(&new_read_key.secret)?;
    writes.push(GroupKeyWrite {
        field: "groupSealer".to_string(),
        value: format_group_sealer_value(&new_read_key.id, &sealer.public_key),
    });
    tx += 1;

    // --- 6. Reveal the new read key to each parent group (group.ts:1228-1247)
    //        storeKeyRevelationForParentGroup(parentReadKey, newReadKey)
    //        → field `${newReadKey.id}_for_${parentReadKeyID}`.
    for p in parents.iter() {
        writes.push(reveal_key_to_parent_group(
            &p.read_key_id,
            &p.read_key_secret,
            &new_read_key.id,
            &new_read_key.secret,
        )?);
        tx += 1;
    }

    // Steps 3-6 do not depend on `tx` (encryptKeySecret / plain sets are
    // tx-independent), but we keep the counter advancing so it stays a faithful
    // mirror of TS's per-`set` transaction stream. Read it once to make the
    // final increment observably used.
    let _ = tx;

    Ok(RotateOutcome::Rotated(writes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Reuse the byte-verified key material from the crypto/group_keys fixtures so
    // the values below can be cross-checked against the proven leaf encoders.
    const FROM_SECRET: &str = "sealerSecret_zCktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8";
    const READER_SEALER_ID: &str = "sealer_z6RpVnWdJifHJvxx7WM8aAbV8ER6vSEX2nLRodqtGj3jr";
    const GROUP_ID: &str = "co_zGroupID111111111";
    const SESSION_ID: &str = "co_zAcc_session_zSess";

    const NEW_READ_KEY_ID: &str = "key_zNEWreadkey1111";
    const NEW_READ_KEY_SECRET: &str = "keySecret_zswqrv48gsrwpBFbftEwnP2vB4jckpvfGJfXkwaniLCC";
    const OLD_READ_KEY_ID: &str = "key_zOLDreadkey1111";
    const OLD_READ_KEY_SECRET: &str = "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn";

    fn base_state() -> GroupKeyState {
        GroupKeyState::from_snapshot(&json!({
            "readKey": OLD_READ_KEY_ID,
            "co_zAdmin1111111": "admin",
            "co_zReader111111": "reader",
        }))
    }

    fn member(key: &str) -> MemberResolution {
        MemberResolution {
            member_key: key.to_string(),
            agent_sealer_id: READER_SEALER_ID.to_string(),
        }
    }

    fn fields(outcome: &RotateOutcome) -> Vec<String> {
        match outcome {
            RotateOutcome::Rotated(w) => w.iter().map(|w| w.field.clone()).collect(),
            RotateOutcome::SkippedEveryoneCanRead => vec![],
        }
    }

    #[test]
    fn readers_only_emits_expected_field_set_and_order() {
        let state = base_state();
        let members = vec![member("co_zAdmin1111111"), member("co_zReader111111")];
        let input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 7,
            trigger: RotationTrigger::Rotate,
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                id: NEW_READ_KEY_ID.to_string(),
                secret: NEW_READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[],
            parents: &[],
        };
        let out = rotate_read_key(&input).unwrap();
        assert_eq!(
            fields(&out),
            vec![
                format!("{NEW_READ_KEY_ID}_for_co_zAdmin1111111"),
                format!("{NEW_READ_KEY_ID}_for_co_zReader111111"),
                format!("{OLD_READ_KEY_ID}_for_{NEW_READ_KEY_ID}"),
                "readKey".to_string(),
                "groupSealer".to_string(),
            ]
        );

        // readKey value + deterministic groupSealer value.
        if let RotateOutcome::Rotated(w) = &out {
            let read = w.iter().find(|w| w.field == "readKey").unwrap();
            assert_eq!(read.value, NEW_READ_KEY_ID);
            let gs = w.iter().find(|w| w.field == "groupSealer").unwrap();
            let sealer = group_sealer_from_read_key(NEW_READ_KEY_SECRET).unwrap();
            assert_eq!(
                gs.value,
                format!("{NEW_READ_KEY_ID}@{}", sealer.public_key)
            );
            // The member seal at tx=7 must match the leaf encoder called directly.
            let admin = w
                .iter()
                .find(|w| w.field == format!("{NEW_READ_KEY_ID}_for_co_zAdmin1111111"))
                .unwrap();
            let expected = reveal_key_to_member(
                NEW_READ_KEY_ID,
                NEW_READ_KEY_SECRET,
                "co_zAdmin1111111",
                FROM_SECRET,
                READER_SEALER_ID,
                GROUP_ID,
                SESSION_ID,
                7,
            )
            .unwrap();
            assert_eq!(admin.value, expected.value);
            // The second reader seal is at tx=8 (proves tx advances per write).
            let reader = w
                .iter()
                .find(|w| w.field == format!("{NEW_READ_KEY_ID}_for_co_zReader111111"))
                .unwrap();
            let expected8 = reveal_key_to_member(
                NEW_READ_KEY_ID,
                NEW_READ_KEY_SECRET,
                "co_zReader111111",
                FROM_SECRET,
                READER_SEALER_ID,
                GROUP_ID,
                SESSION_ID,
                8,
            )
            .unwrap();
            assert_eq!(reader.value, expected8.value);
        }
    }

    #[test]
    fn everyone_can_read_skips_unless_removing_everyone() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": OLD_READ_KEY_ID,
            "co_zAdmin1111111": "admin",
            "everyone": "reader",
        }));
        let members = vec![member("co_zAdmin1111111")];
        let mk = |trigger| RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger,
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                id: NEW_READ_KEY_ID.to_string(),
                secret: NEW_READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[],
            parents: &[],
        };
        // Plain rotate / remove-member: skipped.
        assert_eq!(
            rotate_read_key(&mk(RotationTrigger::Rotate)).unwrap(),
            RotateOutcome::SkippedEveryoneCanRead
        );
        assert_eq!(
            rotate_read_key(&mk(RotationTrigger::RemoveMember("co_zX".to_string()))).unwrap(),
            RotateOutcome::SkippedEveryoneCanRead
        );
        // Removing everyone bypasses the guard.
        assert!(matches!(
            rotate_read_key(&mk(RotationTrigger::RemoveEveryone)).unwrap(),
            RotateOutcome::Rotated(_)
        ));
    }

    #[test]
    fn removed_member_is_excluded_from_readers() {
        let state = base_state();
        let members = vec![member("co_zAdmin1111111"), member("co_zReader111111")];
        let input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger: RotationTrigger::RemoveMember("co_zReader111111".to_string()),
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                id: NEW_READ_KEY_ID.to_string(),
                secret: NEW_READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[],
            parents: &[],
        };
        let out = rotate_read_key(&input).unwrap();
        // Only the admin is re-revealed to; the removed reader is not.
        assert_eq!(
            fields(&out),
            vec![
                format!("{NEW_READ_KEY_ID}_for_co_zAdmin1111111"),
                format!("{OLD_READ_KEY_ID}_for_{NEW_READ_KEY_ID}"),
                "readKey".to_string(),
                "groupSealer".to_string(),
            ]
        );
    }

    #[test]
    fn write_only_member_gets_fresh_key_and_reveals() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": OLD_READ_KEY_ID,
            "co_zAdmin1111111": "admin",
            "co_zWriteOnly111": "writeOnly",
        }));
        let members = vec![member("co_zAdmin1111111"), member("co_zWriteOnly111")];
        let wo_key = KeyPair {
            id: "key_zWOfresh11111".to_string(),
            secret: OLD_READ_KEY_SECRET.to_string(),
        };
        let input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 3,
            trigger: RotationTrigger::Rotate,
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                id: NEW_READ_KEY_ID.to_string(),
                secret: NEW_READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: std::slice::from_ref(&wo_key),
            parents: &[],
        };
        let out = rotate_read_key(&input).unwrap();
        assert_eq!(
            fields(&out),
            vec![
                // reader (admin) gets the new read key
                format!("{NEW_READ_KEY_ID}_for_co_zAdmin1111111"),
                // writeOnly member: reveal fresh key to self, writeKeyFor_, reveal to admin
                format!("key_zWOfresh11111_for_co_zWriteOnly111"),
                "writeKeyFor_co_zWriteOnly111".to_string(),
                format!("key_zWOfresh11111_for_co_zAdmin1111111"),
                // then the standard tail
                format!("{OLD_READ_KEY_ID}_for_{NEW_READ_KEY_ID}"),
                "readKey".to_string(),
                "groupSealer".to_string(),
            ]
        );
        if let RotateOutcome::Rotated(w) = &out {
            let wkf = w
                .iter()
                .find(|w| w.field == "writeKeyFor_co_zWriteOnly111")
                .unwrap();
            assert_eq!(wkf.value, "key_zWOfresh11111");
        }
    }

    #[test]
    fn write_only_key_count_mismatch_errors() {
        let state = GroupKeyState::from_snapshot(&json!({
            "readKey": OLD_READ_KEY_ID,
            "co_zWriteOnly111": "writeOnly",
        }));
        let members = vec![member("co_zWriteOnly111")];
        let input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger: RotationTrigger::Rotate,
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                id: NEW_READ_KEY_ID.to_string(),
                secret: NEW_READ_KEY_SECRET.to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[], // none, but there is 1 writeOnly member
            parents: &[],
        };
        assert!(matches!(
            rotate_read_key(&input),
            Err(RotateError::WriteOnlyKeyCountMismatch {
                expected: 1,
                provided: 0
            })
        ));
    }

    #[test]
    fn parent_reveal_uses_encrypt_key_secret_deterministically() {
        // Parent read key = the proven encryptKeySecret "encrypting" material.
        let state = base_state();
        let members = vec![member("co_zAdmin1111111"), member("co_zReader111111")];
        let parent = ParentResolution {
            read_key_id: "key_zEncrypting22222222".to_string(),
            read_key_secret: "keySecret_zcGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN".to_string(),
        };
        let input = RotateReadKeyInput {
            state: &state,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 0,
            trigger: RotationTrigger::Rotate,
            from_sealer_secret: FROM_SECRET,
            current_read_key: KeyPair {
                id: OLD_READ_KEY_ID.to_string(),
                secret: OLD_READ_KEY_SECRET.to_string(),
            },
            new_read_key: KeyPair {
                // Use the proven toEncrypt material as the NEW read key so the
                // parent reveal value equals the byte-verified ENCRYPTED_REF.
                id: "key_zToEncrypt111111111".to_string(),
                secret: "keySecret_zUS517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx".to_string(),
            },
            members: &members,
            write_only_fresh_keys: &[],
            parents: std::slice::from_ref(&parent),
        };
        let out = rotate_read_key(&input).unwrap();
        if let RotateOutcome::Rotated(w) = &out {
            let field = "key_zToEncrypt111111111_for_key_zEncrypting22222222";
            let reveal = w.iter().find(|w| w.field == field).unwrap();
            assert_eq!(
                reveal.value,
                "encrypted_UaVdHfonLxB99LyOlDHPlO5-pMC6Lheyj5IYuW-tnx-6m8qoGdCkdtAveN2IjsXm9bVcQRu4-ZO8="
            );
        } else {
            panic!("expected rotation");
        }
    }
}
