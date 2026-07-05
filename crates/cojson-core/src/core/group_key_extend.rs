//! Native orchestration of `RawGroup.extend` and its `revealReadKeyToParentGroup`
//! standard (account-member) path — the parent-group linking write surface.
//!
//! [`extend`] is a **pure, deterministic** reproduction of
//! `packages/cojson/src/coValues/group.ts`'s `extend` (group.ts:1292-1322) for the
//! standard case (the current account is an account-member of the parent group, so
//! the child read key is revealed via the parent's read key with
//! `encryptKeySecret`). Given the parent reference value plus the resolved read
//! keys, it emits the exact ordered `(field, value)` writes TS performs.
//!
//! # Why these inputs are parameters, not derived
//!
//! Same contract as [`crate::core::group_key_rotation`]: the *read key secrets* of
//! the child and parent require the unseal/decrypt traversal (`getUncachedReadKey`)
//! that lives only in TS, so the caller supplies each `(id, secret)` resolved.
//!
//! # Determinism
//!
//! Every write here is a plain `set` (the `parent_<id>` reference) or an
//! `encryptKeySecret` reveal (`storeKeyRevelationForParentGroup`). `encryptKeySecret`
//! is deterministic and transaction-index independent, so — unlike the member seals
//! in rotation/`add_member_internal` — `extend`'s output does not depend on a start
//! transaction index at all.
//!
//! # The non-account-member parent path
//!
//! `revealReadKeyToParentGroup` has a branch (group.ts:1349-1387) for when the
//! current account is *not* an account-member of the parent group:
//!
//! - **Group-sealer path (handled by [`extend_to_group_sealer_parent`]).** When the
//!   parent has a `groupSealer`, TS seals the revealed key to the parent's sealer
//!   with `sealForGroup` (anonymous box) via `storeKeyRevelationForGroupSealer`
//!   (group.ts:1357-1378). `sealForGroup` uses a fresh ephemeral keypair per call,
//!   so the ciphertext is NON-deterministic and cannot be byte-fixtured; it is
//!   instead verified by ROUNDTRIP (seal then `unsealForGroup` recovers the secret),
//!   exactly as the underlying [`crate::core::group_keys::reveal_key_to_group_sealer`]
//!   primitive was originally verified.
//! - **Legacy fallback (still deferred).** When the parent has NO `groupSealer`, TS
//!   calls `parent.internalCreateWriteOnlyKeyForMember(...)` (group.ts:1382-1385),
//!   which mutates the **parent** CoValue's OWN transaction stream and then falls
//!   through to the standard path (which throws without the parent read key). A
//!   cross-CoValue mutation cannot be modeled as "an ordered list of writes to THIS
//!   group", so it is deliberately left out. In practice every modern group carries
//!   a `groupSealer`, so this fallback is unreachable for them; reproducing it would
//!   require a separate parent-CoValue write orchestration and is not attempted.
//!
//! This module is native-only and intentionally NOT wired into production
//! `group.ts`.

use crate::core::group_key_rotation::{KeyPair, ParentResolution};
use crate::core::group_keys::{
    reveal_key_to_group_sealer, reveal_key_to_parent_group, GroupKeyWrite,
};
use crate::crypto::error::CryptoError;

/// Reproduce `revealReadKeyToParentGroup`'s **standard (account-member) path**
/// (group.ts:1372-1403): reveal a child key to the parent's read key via
/// `encryptKeySecret`, and — when `reveal_all_write_only_keys` — also reveal every
/// one of this group's writeOnly keys to the parent.
///
/// - `parent`: the parent group's current read key `(id, secret)`.
/// - `child_key_id` / `child_key_secret`: the key being revealed (the child read
///   key for `extend`, or a fresh writeOnly key for the writeOnly path).
/// - `write_only_keys`: this group's writeOnly keys `(id, secret)` in
///   `getWriteOnlyKeys()` order — only used when `reveal_all_write_only_keys`.
pub fn reveal_read_key_to_parent_group_standard(
    parent: &ParentResolution,
    child_key_id: &str,
    child_key_secret: &str,
    write_only_keys: &[KeyPair],
    reveal_all_write_only_keys: bool,
) -> Result<Vec<GroupKeyWrite>, CryptoError> {
    let mut writes = Vec::new();

    // storeKeyRevelationForParentGroup(parentReadKey, childKey) — the main reveal.
    writes.push(reveal_key_to_parent_group(
        &parent.read_key_id,
        &parent.read_key_secret,
        child_key_id,
        child_key_secret,
    )?);

    // revealAllWriteOnlyKeys: reveal each writeOnly key to the parent read key too.
    if reveal_all_write_only_keys {
        for wk in write_only_keys {
            writes.push(reveal_key_to_parent_group(
                &parent.read_key_id,
                &parent.read_key_secret,
                &wk.id,
                &wk.secret,
            )?);
        }
    }

    Ok(writes)
}

/// All inputs to [`extend`].
pub struct ExtendInput<'a> {
    /// The parent group's CoValue id — the `parent_<id>` field written on the child.
    pub parent_id: &'a str,
    /// The value written to `parent_<id>`: `"extend"` when `role === "inherit"`,
    /// otherwise the capped role string (group.ts:1306).
    pub parent_ref_value: &'a str,
    /// The parent group's current read key `(id, secret)` — standard path.
    pub parent: ParentResolution,
    /// The child group's current read key `(id, secret)` (`getCurrentReadKey()`).
    pub child_read_key: KeyPair,
    /// The child group's writeOnly keys `(id, secret)` in `getWriteOnlyKeys()`
    /// order (`extend` passes `revealAllWriteOnlyKeys: true`).
    pub write_only_keys: &'a [KeyPair],
}

/// Reproduce `RawGroup.extend` (group.ts:1292-1322) as an ordered list of
/// child-group writes, for the standard (account-member) parent path.
///
/// Emits: `parent_<parentId> = value`, then the child read key revealed to the
/// parent read key, then (because `extend` requests `revealAllWriteOnlyKeys: true`)
/// each writeOnly key revealed to the parent read key.
///
/// The `myRole() === "admin"` permission check and the `isSelfExtension` early
/// return (group.ts:1296-1304) are caller/runtime concerns and are not modeled
/// here — this function assumes a legitimate extend and produces its writes.
pub fn extend(input: &ExtendInput<'_>) -> Result<Vec<GroupKeyWrite>, CryptoError> {
    let mut writes = Vec::new();

    // this.set(`parent_${parent.id}`, value, "trusting") — group.ts:1308.
    writes.push(GroupKeyWrite {
        field: format!("parent_{}", input.parent_id),
        value: input.parent_ref_value.to_string(),
    });

    // revealReadKeyToParentGroup(parent, childReadKey, { revealAllWriteOnlyKeys: true })
    writes.extend(reveal_read_key_to_parent_group_standard(
        &input.parent,
        &input.child_read_key.id,
        &input.child_read_key.secret,
        input.write_only_keys,
        true,
    )?);

    Ok(writes)
}

/// All inputs to [`extend_to_group_sealer_parent`].
pub struct ExtendToGroupSealerInput<'a> {
    /// The parent group's CoValue id — the `parent_<id>` field written on the child.
    pub parent_id: &'a str,
    /// The value written to `parent_<id>` (`"extend"` for `inherit`, else the role).
    pub parent_ref_value: &'a str,
    /// The parent group's sealer id (`extractSealerID(parent.get("groupSealer"))`) —
    /// the anonymous-box recipient every revelation is sealed *to*.
    pub parent_sealer_id: &'a str,
    /// This (child) group's CoValue id — seal nonce material (`in`).
    pub group_id: &'a str,
    /// The current session id — seal nonce material (`tx.sessionID`).
    pub session_id: &'a str,
    /// `group.core.nextTransactionID().txIndex` immediately before `extend` — the
    /// `parent_<id>` set consumes this index, so the first group-sealer reveal is at
    /// `start_tx_index + 1` (its `sealForGroup` nonce embeds that txIndex).
    pub start_tx_index: u64,
    /// The child group's current read key `(id, secret)` (`getCurrentReadKey()`).
    pub child_read_key: KeyPair,
    /// The child group's writeOnly keys `(id, secret)` in `getWriteOnlyKeys()` order
    /// (`extend` passes `revealAllWriteOnlyKeys: true`).
    pub write_only_keys: &'a [KeyPair],
}

/// Reproduce `RawGroup.extend` for the **non-account-member parent, group-sealer
/// path** (group.ts:1349-1379): the child is not an account-member of the parent, but
/// the parent has a `groupSealer`, so each revealed key is sealed to that sealer with
/// `sealForGroup` (an anonymous box) instead of encrypted under the parent read key.
///
/// Emits, in order:
/// 1. `parent_<parentId> = value` (a plain set, consuming `start_tx_index`).
/// 2. the child read key sealed to the parent sealer
///    (`<childKeyId>_sealedFor_<parentSealerId>`), at `start_tx_index + 1`.
/// 3. because `extend` requests `revealAllWriteOnlyKeys: true`, each writeOnly key
///    sealed to the parent sealer, at the following consecutive tx-indices.
///
/// **Non-deterministic:** every `sealedForGroup_…` value uses a fresh ephemeral key,
/// so two calls differ. Verify by ROUNDTRIP (`unsealForGroup` with the parent sealer
/// secret recovers the original key secret), not by byte-fixture.
pub fn extend_to_group_sealer_parent(
    input: &ExtendToGroupSealerInput<'_>,
) -> Result<Vec<GroupKeyWrite>, CryptoError> {
    let mut writes = Vec::new();

    // 1. this.set(`parent_${parent.id}`, value, "trusting") — group.ts:1325.
    writes.push(GroupKeyWrite {
        field: format!("parent_{}", input.parent_id),
        value: input.parent_ref_value.to_string(),
    });
    // The set above consumed `start_tx_index`; group-sealer nonces start after it.
    let mut tx = input.start_tx_index + 1;

    // 2. storeKeyRevelationForGroupSealer(parentSealerID, childReadKey) — the main
    //    reveal (group.ts:1358-1362).
    writes.push(reveal_key_to_group_sealer(
        input.parent_sealer_id,
        &input.child_read_key.id,
        &input.child_read_key.secret,
        input.group_id,
        input.session_id,
        tx,
    )?);
    tx += 1;

    // 3. revealAllWriteOnlyKeys: seal each writeOnly key to the parent sealer too
    //    (group.ts:1365-1377).
    for wk in input.write_only_keys {
        writes.push(reveal_key_to_group_sealer(
            input.parent_sealer_id,
            &wk.id,
            &wk.secret,
            input.group_id,
            input.session_id,
            tx,
        )?);
        tx += 1;
    }

    let _ = tx;
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reuse the byte-verified encryptKeySecret material from the crypto fixtures.
    const PARENT_KEY_ID: &str = "key_zEncrypting22222222";
    const PARENT_KEY_SECRET: &str = "keySecret_zcGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
    const CHILD_KEY_ID: &str = "key_zToEncrypt111111111";
    const CHILD_KEY_SECRET: &str = "keySecret_zUS517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
    const ENCRYPTED_REF: &str =
        "encrypted_UaVdHfonLxB99LyOlDHPlO5-pMC6Lheyj5IYuW-tnx-6m8qoGdCkdtAveN2IjsXm9bVcQRu4-ZO8=";

    fn parent() -> ParentResolution {
        ParentResolution {
            read_key_id: PARENT_KEY_ID.to_string(),
            read_key_secret: PARENT_KEY_SECRET.to_string(),
        }
    }

    #[test]
    fn extend_emits_parent_ref_then_deterministic_reveal() {
        let input = ExtendInput {
            parent_id: "co_zParent1111111",
            parent_ref_value: "extend",
            parent: parent(),
            child_read_key: KeyPair {
                id: CHILD_KEY_ID.to_string(),
                secret: CHILD_KEY_SECRET.to_string(),
            },
            write_only_keys: &[],
        };
        let writes = extend(&input).unwrap();
        assert_eq!(
            writes,
            vec![
                GroupKeyWrite {
                    field: "parent_co_zParent1111111".to_string(),
                    value: "extend".to_string(),
                },
                GroupKeyWrite {
                    // storeKeyRevelationForParentGroup field: child_for_parent.
                    field: format!("{CHILD_KEY_ID}_for_{PARENT_KEY_ID}"),
                    value: ENCRYPTED_REF.to_string(),
                },
            ]
        );
    }

    #[test]
    fn extend_with_role_writes_capped_role_value() {
        let input = ExtendInput {
            parent_id: "co_zParent1111111",
            parent_ref_value: "reader",
            parent: parent(),
            child_read_key: KeyPair {
                id: CHILD_KEY_ID.to_string(),
                secret: CHILD_KEY_SECRET.to_string(),
            },
            write_only_keys: &[],
        };
        let writes = extend(&input).unwrap();
        assert_eq!(writes[0].value, "reader");
    }

    #[test]
    fn reveal_all_write_only_keys_appends_one_reveal_per_key() {
        // A single writeOnly key revealed to the parent alongside the child key.
        // Reuse the same material so both reveals are byte-checkable.
        let wo = KeyPair {
            id: CHILD_KEY_ID.to_string(),
            secret: CHILD_KEY_SECRET.to_string(),
        };
        let writes = reveal_read_key_to_parent_group_standard(
            &parent(),
            CHILD_KEY_ID,
            CHILD_KEY_SECRET,
            std::slice::from_ref(&wo),
            true,
        )
        .unwrap();
        // main reveal + one writeOnly reveal (same field/value here).
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].value, ENCRYPTED_REF);
        assert_eq!(writes[1].value, ENCRYPTED_REF);
    }

    // --- non-account-member parent, group-sealer path (roundtrip) -----------
    #[test]
    fn extend_to_group_sealer_parent_roundtrips_every_reveal() {
        use crate::crypto::key_secret::group_sealer_from_read_key;
        use crate::crypto::seal::unseal_for_group;
        use base64::{engine::general_purpose::URL_SAFE, Engine as _};

        const GROUP_ID: &str = "co_zGroupID111111111";
        const SESSION_ID: &str = "co_zAcc_session_zSess";
        // The parent's group sealer is derived from the parent's read key secret; we
        // hold that secret only so the test can decrypt (roundtrip) — production only
        // needs the public sealer id to seal.
        let parent_read_key_secret = "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn";
        let parent_sealer = group_sealer_from_read_key(parent_read_key_secret).unwrap();

        let child_read_key = KeyPair {
            id: "key_zChildRead11111".to_string(),
            secret: "keySecret_zswqrv48gsrwpBFbftEwnP2vB4jckpvfGJfXkwaniLCC".to_string(),
        };
        let wo = KeyPair {
            id: "key_zWriteOnly11111".to_string(),
            secret: "keySecret_zUS517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx".to_string(),
        };

        let input = ExtendToGroupSealerInput {
            parent_id: "co_zParent1111111",
            parent_ref_value: "extend",
            parent_sealer_id: &parent_sealer.public_key,
            group_id: GROUP_ID,
            session_id: SESSION_ID,
            start_tx_index: 3,
            child_read_key: child_read_key.clone(),
            write_only_keys: std::slice::from_ref(&wo),
        };
        let writes = extend_to_group_sealer_parent(&input).unwrap();

        // Fields + order: parent ref, child reveal, one writeOnly reveal.
        assert_eq!(
            writes.iter().map(|w| w.field.clone()).collect::<Vec<_>>(),
            vec![
                "parent_co_zParent1111111".to_string(),
                format!("{}_sealedFor_{}", child_read_key.id, parent_sealer.public_key),
                format!("{}_sealedFor_{}", wo.id, parent_sealer.public_key),
            ]
        );
        assert_eq!(writes[0].value, "extend");

        // Roundtrip: recover each sealed secret with the parent sealer secret. The
        // set(parent) consumed tx=3, so the child reveal is nonce'd at tx=4 and the
        // writeOnly reveal at tx=5.
        let recover = |value: &str, tx: u64| -> String {
            let b64 = value.strip_prefix("sealedForGroup_U").unwrap();
            let raw = URL_SAFE.decode(b64).unwrap();
            let nonce = format!(
                "{{\"in\":\"{GROUP_ID}\",\"tx\":{{\"sessionID\":\"{SESSION_ID}\",\"txIndex\":{tx}}}}}"
            );
            let pt = unseal_for_group(&raw, &parent_sealer.secret, nonce.as_bytes()).unwrap();
            serde_json::from_slice::<String>(&pt).unwrap()
        };
        assert_eq!(recover(&writes[1].value, 4), child_read_key.secret);
        assert_eq!(recover(&writes[2].value, 5), wo.secret);
    }

    #[test]
    fn reveal_all_false_skips_write_only_keys() {
        let wo = KeyPair {
            id: CHILD_KEY_ID.to_string(),
            secret: CHILD_KEY_SECRET.to_string(),
        };
        let writes = reveal_read_key_to_parent_group_standard(
            &parent(),
            CHILD_KEY_ID,
            CHILD_KEY_SECRET,
            std::slice::from_ref(&wo),
            false,
        )
        .unwrap();
        assert_eq!(writes.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Golden-fixture replay: load `data/group_key_extend/*.json` (exported by
    // `packages/cojson/src/tests/groupKeyWriteFixtures.export.test.ts` from real TS
    // `RawGroup.extend`) and assert `extend` reproduces the EXACT ordered
    // `(field, value)` write list byte-for-byte.
    // -----------------------------------------------------------------------
    mod fixtures {
        use super::super::*;
        use crate::core::group_key_test_support::{KeyPairFx, ParentFx, WriteFx};
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct ExtendFx {
            #[allow(dead_code)]
            description: String,
            #[serde(rename = "parentId")]
            parent_id: String,
            #[serde(rename = "parentRefValue")]
            parent_ref_value: String,
            parent: ParentFx,
            #[serde(rename = "childReadKey")]
            child_read_key: KeyPairFx,
            #[serde(rename = "writeOnlyKeys")]
            write_only_keys: Vec<KeyPairFx>,
            #[serde(rename = "expectedWrites")]
            expected_writes: Vec<WriteFx>,
        }

        fn replay(name: &str) {
            let path = format!("data/group_key_extend/{name}.json");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let fx: ExtendFx =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));

            let write_only_keys: Vec<KeyPair> = fx
                .write_only_keys
                .iter()
                .map(|k| KeyPair {
                    id: k.id.clone(),
                    secret: k.secret.clone(),
                })
                .collect();

            let input = ExtendInput {
                parent_id: &fx.parent_id,
                parent_ref_value: &fx.parent_ref_value,
                parent: ParentResolution {
                    read_key_id: fx.parent.read_key_id.clone(),
                    read_key_secret: fx.parent.read_key_secret.clone(),
                },
                child_read_key: KeyPair {
                    id: fx.child_read_key.id.clone(),
                    secret: fx.child_read_key.secret.clone(),
                },
                write_only_keys: &write_only_keys,
            };
            let writes = extend(&input).unwrap_or_else(|e| panic!("[{name}] extend failed: {e:?}"));

            assert_eq!(
                writes.len(),
                fx.expected_writes.len(),
                "[{name}] write COUNT differs\n native: {:#?}\n TS:     {:#?}",
                writes.iter().map(|w| &w.field).collect::<Vec<_>>(),
                fx.expected_writes
                    .iter()
                    .map(|w| &w.field)
                    .collect::<Vec<_>>(),
            );
            for (i, (got, want)) in writes.iter().zip(fx.expected_writes.iter()).enumerate() {
                assert_eq!(got.field, want.field, "[{name}] write #{i} FIELD differs");
                assert_eq!(
                    got.value, want.value,
                    "[{name}] write #{i} ({}) VALUE differs (byte mismatch vs TS)",
                    want.field
                );
            }
        }

        #[test]
        fn extend_basic() {
            replay("extend_basic");
        }
        #[test]
        fn extend_with_writeonly() {
            replay("extend_with_writeonly");
        }
    }
}
