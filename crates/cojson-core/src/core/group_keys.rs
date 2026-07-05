//! Native encoders for a group's key-management *write* surface.
//!
//! These are the leaf operations that `packages/cojson/src/coValues/group.ts`
//! performs when it reveals a key secret into a group CoMap: each produces the
//! `(field_name, wire_value)` pair that would be written with `group.set(...)`.
//!
//! Scope note: this module deliberately does **not** materialize group state
//! (current read key, member roles, parent/child links, next transaction id).
//! That materialization does not yet exist in cojson-core, and duplicating
//! CoMap materialization is explicitly out of scope. The higher-level
//! orchestration in group.ts (`rotateReadKey`, `addMember`, `extend`,
//! `createInvite`, `removeMember`) decides *which* revelations to emit from
//! materialized state and is therefore deferred; these encoders are the
//! byte-exact building blocks it would call once that read slice exists.
//!
//! Every encoder mirrors a specific `storeKeyRevelationFor*` helper and matches
//! the TypeScript `WasmCrypto` wire format byte-for-byte (verified by tests).

use crate::crypto::error::CryptoError;
use crate::crypto::key_secret::encrypt_key_secret;
use crate::crypto::seal::{seal, seal_for_group};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};

/// A single field to write into the group CoMap: `(name, value)`, always with
/// `"trusting"` privacy in the TS equivalents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyWrite {
    pub field: String,
    pub value: String,
}

/// Build the seal/sealForGroup nonce material, matching TS
/// `stableStringify({ in: groupId, tx: { sessionID, txIndex } })`.
///
/// `stableStringify` sorts keys: `"in" < "tx"`, and `"sessionID" < "txIndex"`.
/// `txIndex` is a JSON number (unquoted). String values are JSON-encoded to
/// match TS escaping.
fn seal_nonce_material(
    group_id: &str,
    session_id: &str,
    tx_index: u64,
) -> Result<String, CryptoError> {
    let group = serde_json::to_string(group_id).map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    let session = serde_json::to_string(session_id).map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    Ok(format!(
        "{{\"in\":{},\"tx\":{{\"sessionID\":{},\"txIndex\":{}}}}}",
        group, session, tx_index
    ))
}

/// Compose the group's `groupSealer` field value: `"<readKeyID>@<sealerID>"`.
///
/// Mirrors `formatGroupSealerValue` in group.ts.
pub fn format_group_sealer_value(read_key_id: &str, sealer_id: &str) -> String {
    format!("{}@{}", read_key_id, sealer_id)
}

/// Reveal a key secret to an individual member. Mirrors
/// `storeKeyRevelationForMember`.
///
/// - `key_id` / `secret`: the key being revealed.
/// - `member_key`: the member's account/agent id (used only for the field name).
/// - `from_sealer_secret`: the current agent's sealer secret.
/// - `to_agent_sealer_id`: the member agent's sealer id (`getAgentSealerID`).
/// - `group_id`, `session_id`, `tx_index`: nonce material components.
///
/// Field: `"<keyID>_for_<memberKey>"`, value: `"sealed_U…"`.
#[allow(clippy::too_many_arguments)]
pub fn reveal_key_to_member(
    key_id: &str,
    secret: &str,
    member_key: &str,
    from_sealer_secret: &str,
    to_agent_sealer_id: &str,
    group_id: &str,
    session_id: &str,
    tx_index: u64,
) -> Result<GroupKeyWrite, CryptoError> {
    // message = stableStringify(secret) => JSON-quoted key secret string.
    let message = serde_json::to_string(secret).map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    let nonce = seal_nonce_material(group_id, session_id, tx_index)?;
    let sealed = seal(
        message.as_bytes(),
        from_sealer_secret,
        to_agent_sealer_id,
        nonce.as_bytes(),
    )?;
    Ok(GroupKeyWrite {
        field: format!("{}_for_{}", key_id, member_key),
        value: format!("sealed_U{}", URL_SAFE.encode(&sealed)),
    })
}

/// Reveal a child group's read key to a parent group's read key. Mirrors
/// `storeKeyRevelationForParentGroup`.
///
/// Field: `"<childReadKeyID>_for_<parentReadKeyID>"`, value: `"encrypted_U…"`.
pub fn reveal_key_to_parent_group(
    parent_read_key_id: &str,
    parent_read_key_secret: &str,
    child_read_key_id: &str,
    child_read_key_secret: &str,
) -> Result<GroupKeyWrite, CryptoError> {
    let value = encrypt_key_secret(
        child_read_key_id,
        child_read_key_secret,
        parent_read_key_id,
        parent_read_key_secret,
    )?;
    Ok(GroupKeyWrite {
        field: format!("{}_for_{}", child_read_key_id, parent_read_key_id),
        value,
    })
}

/// Reveal a child key to a group's sealer (anonymous box). Mirrors
/// `storeKeyRevelationForGroupSealer`.
///
/// Field: `"<childKeyID>_sealedFor_<sealerID>"`, value: `"sealedForGroup_U…"`.
///
/// Note: `seal_for_group` uses a fresh ephemeral keypair, so the value is
/// non-deterministic (only roundtrip-verifiable, not byte-fixturable).
pub fn reveal_key_to_group_sealer(
    group_sealer_id: &str,
    child_key_id: &str,
    child_key_secret: &str,
    group_id: &str,
    session_id: &str,
    tx_index: u64,
) -> Result<GroupKeyWrite, CryptoError> {
    let message = serde_json::to_string(child_key_secret)
        .map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    let nonce = seal_nonce_material(group_id, session_id, tx_index)?;
    let sealed = seal_for_group(message.as_bytes(), group_sealer_id, nonce.as_bytes())?;
    Ok(GroupKeyWrite {
        field: format!("{}_sealedFor_{}", child_key_id, group_sealer_id),
        value: format!("sealedForGroup_U{}", URL_SAFE.encode(&sealed)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seal::unseal_for_group;

    // --- Member revelation: byte-identical to TS `crypto.seal(...)` ----------
    // Reference produced by WasmCrypto for the fixed material below.
    const FROM_SECRET: &str = "sealerSecret_zCktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8";
    const TO_ID: &str = "sealer_z6RpVnWdJifHJvxx7WM8aAbV8ER6vSEX2nLRodqtGj3jr";
    const SEAL_MESSAGE: &str = "keySecret_zswqrv48gsrwpBFbftEwnP2vB4jckpvfGJfXkwaniLCC";
    const SEALED_REF: &str =
        "sealed_U4Nug5MjLKhVP1fu1st7QxwBME3DTsqy_btnqp_J85yfvd_gQfeKexfT13zYIvtov15ri6mWEUpnkzW-d1CcPpJlKvil1Ym4I";
    const GROUP_ID: &str = "co_zGroupID111111111";
    const SESSION_ID: &str = "co_zAcc_session_zSess";
    const TX_INDEX: u64 = 4;

    #[test]
    fn reveal_key_to_member_matches_ts_reference() {
        let w = reveal_key_to_member(
            "key_zKKKKKKKKKKKKK",
            SEAL_MESSAGE,
            "co_zMember1111111",
            FROM_SECRET,
            TO_ID,
            GROUP_ID,
            SESSION_ID,
            TX_INDEX,
        )
        .unwrap();
        assert_eq!(w.field, "key_zKKKKKKKKKKKKK_for_co_zMember1111111");
        assert_eq!(w.value, SEALED_REF, "sealed value must be byte-identical to TS");
    }

    #[test]
    fn nonce_material_is_stable_sorted() {
        let n = seal_nonce_material(GROUP_ID, SESSION_ID, TX_INDEX).unwrap();
        assert_eq!(
            n,
            "{\"in\":\"co_zGroupID111111111\",\"tx\":{\"sessionID\":\"co_zAcc_session_zSess\",\"txIndex\":4}}"
        );
    }

    // --- Parent-group revelation: deterministic (encryptKeySecret) -----------
    #[test]
    fn reveal_key_to_parent_group_matches_ts_reference() {
        // Same inputs/reference as crypto::key_secret fixture.
        let w = reveal_key_to_parent_group(
            "key_zEncrypting22222222",
            "keySecret_zcGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN",
            "key_zToEncrypt111111111",
            "keySecret_zUS517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx",
        )
        .unwrap();
        assert_eq!(w.field, "key_zToEncrypt111111111_for_key_zEncrypting22222222");
        assert_eq!(
            w.value,
            "encrypted_UaVdHfonLxB99LyOlDHPlO5-pMC6Lheyj5IYuW-tnx-6m8qoGdCkdtAveN2IjsXm9bVcQRu4-ZO8="
        );
    }

    #[test]
    fn format_group_sealer_value_works() {
        assert_eq!(
            format_group_sealer_value("key_zABC", "sealer_zXYZ"),
            "key_zABC@sealer_zXYZ"
        );
    }

    // --- Group-sealer revelation: non-deterministic, roundtrip only ----------
    #[test]
    fn reveal_key_to_group_sealer_roundtrips() {
        use crate::crypto::key_secret::group_sealer_from_read_key;
        let read_key = "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn";
        let gs = group_sealer_from_read_key(read_key).unwrap();

        let child_secret = "keySecret_zswqrv48gsrwpBFbftEwnP2vB4jckpvfGJfXkwaniLCC";
        let w = reveal_key_to_group_sealer(
            &gs.public_key,
            "key_zChild1111111",
            child_secret,
            GROUP_ID,
            SESSION_ID,
            TX_INDEX,
        )
        .unwrap();
        assert_eq!(w.field, format!("key_zChild1111111_sealedFor_{}", gs.public_key));

        let b64 = w.value.strip_prefix("sealedForGroup_U").unwrap();
        let raw = URL_SAFE.decode(b64).unwrap();
        let nonce = seal_nonce_material(GROUP_ID, SESSION_ID, TX_INDEX).unwrap();
        let plaintext = unseal_for_group(&raw, &gs.secret, nonce.as_bytes()).unwrap();
        // plaintext is stableStringify(secret) => JSON-quoted string.
        let recovered: String = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, child_secret);
    }
}
