//! Key-secret encryption primitives used by group key management.
//!
//! These mirror, byte-for-byte, the TypeScript `CryptoProvider` methods
//! `encryptKeySecret`, `decryptKeySecret` and `groupSealerFromReadKey`
//! (see `packages/cojson/src/crypto/crypto.ts` and `WasmCrypto.ts`).
//!
//! Wire-format notes (must stay identical to TS):
//! - `encryptKeySecret` encrypts `stableStringify(secret)` (i.e. the JSON-quoted
//!   key secret string) under the *encrypting* key, with nonce material
//!   `stableStringify({ encryptedID, encryptingID })`. The result is the
//!   `encrypted_U` + URL-safe base64 (with padding) string.
//! - `groupSealerFromReadKey` derives an X25519 sealer secret deterministically
//!   as `blake3_hash_once_with_context(readKeySecret.as_bytes(), b"groupSealer")`,
//!   base58-encoded with a `sealerSecret_z` prefix, then derives its public id.

use crate::crypto::encrypt::{decrypt, encrypt};
use crate::crypto::error::CryptoError;
use crate::crypto::x25519::get_sealer_id;
use crate::hash::blake3::blake3_hash_once_with_context;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use bs58;

/// Build the nonce material for a key-secret encryption, matching
/// `stableStringify({ encryptedID, encryptingID })` from TS.
///
/// `stableStringify` sorts object keys; `"encryptedID"` sorts before
/// `"encryptingID"`, so the order below is fixed. Values are JSON-encoded to
/// match TS string escaping exactly.
fn key_secret_nonce_material(
    encrypted_id: &str,
    encrypting_id: &str,
) -> Result<String, CryptoError> {
    let enc = serde_json::to_string(encrypted_id)
        .map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    let ing = serde_json::to_string(encrypting_id)
        .map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    Ok(format!(
        "{{\"encryptedID\":{},\"encryptingID\":{}}}",
        enc, ing
    ))
}

/// Encrypt a key secret so it can be revealed to holders of another key.
///
/// Mirrors `CryptoProvider.encryptKeySecret({ toEncrypt, encrypting }).encrypted`.
///
/// - `to_encrypt_id` / `to_encrypt_secret`: the key being revealed.
/// - `encrypting_id` / `encrypting_secret`: the key the reader already holds.
///
/// Returns the full `encrypted_U…` wire string.
pub fn encrypt_key_secret(
    to_encrypt_id: &str,
    to_encrypt_secret: &str,
    encrypting_id: &str,
    encrypting_secret: &str,
) -> Result<String, CryptoError> {
    // plaintext = stableStringify(secret) => JSON-quoted key secret string.
    let plaintext = serde_json::to_string(to_encrypt_secret)
        .map_err(|e| CryptoError::Base58Error(e.to_string()))?;
    let nonce_material = key_secret_nonce_material(to_encrypt_id, encrypting_id)?;

    let ciphertext = encrypt(
        plaintext.as_bytes(),
        encrypting_secret,
        nonce_material.as_bytes(),
    )?;

    Ok(format!("encrypted_U{}", URL_SAFE.encode(&ciphertext)))
}

/// Inverse of [`encrypt_key_secret`].
///
/// Mirrors `CryptoProvider.decryptKeySecret`. `sealing_secret` is the secret of
/// the *encrypting* key. Returns the decrypted key secret (JSON-parsed back to
/// the raw `keySecret_z…` string), or an error if the wire format / MAC / UTF-8
/// is invalid.
pub fn decrypt_key_secret(
    encrypted: &str,
    encrypted_id: &str,
    encrypting_id: &str,
    sealing_secret: &str,
) -> Result<String, CryptoError> {
    let b64 = encrypted
        .strip_prefix("encrypted_U")
        .ok_or(CryptoError::InvalidPrefix("encrypted key secret", "encrypted_U"))?;
    let ciphertext = URL_SAFE
        .decode(b64)
        .map_err(|e| CryptoError::Base58Error(e.to_string()))?;

    let nonce_material = key_secret_nonce_material(encrypted_id, encrypting_id)?;

    let plaintext = decrypt(&ciphertext, sealing_secret, nonce_material.as_bytes())?;
    let json = std::str::from_utf8(&plaintext).map_err(|_| CryptoError::CipherError)?;
    // The plaintext is stableStringify(secret) => a JSON string; parse it back.
    serde_json::from_str::<String>(json).map_err(|e| CryptoError::Base58Error(e.to_string()))
}

/// A deterministically-derived group sealer keypair.
pub struct GroupSealer {
    pub secret: String,
    pub public_key: String,
}

/// Derive the group's asymmetric sealer keypair deterministically from its read
/// key secret. Mirrors `CryptoProvider.groupSealerFromReadKey`.
///
/// Deterministic derivation is required so that concurrent admin migrations
/// produce the identical sealer.
pub fn group_sealer_from_read_key(read_key_secret: &str) -> Result<GroupSealer, CryptoError> {
    let sealer_bytes = blake3_hash_once_with_context(read_key_secret.as_bytes(), b"groupSealer");
    if sealer_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(32, sealer_bytes.len()));
    }
    let secret = format!("sealerSecret_z{}", bs58::encode(&sealer_bytes).into_string());
    let public_key = get_sealer_id(&secret)?;
    Ok(GroupSealer { secret, public_key })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference values produced by the TypeScript `WasmCrypto` implementation
    // for the fixed key material below. Regenerate with a WasmCrypto fixture
    // test if the wire format ever changes (it must not).
    const TO_ENCRYPT_ID: &str = "key_zToEncrypt111111111";
    const ENCRYPTING_ID: &str = "key_zEncrypting22222222";
    const TO_ENCRYPT_SECRET: &str = "keySecret_zUS517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
    const ENCRYPTING_SECRET: &str = "keySecret_zcGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
    const ENCRYPTED_REF: &str =
        "encrypted_UaVdHfonLxB99LyOlDHPlO5-pMC6Lheyj5IYuW-tnx-6m8qoGdCkdtAveN2IjsXm9bVcQRu4-ZO8=";

    const READ_KEY_SECRET: &str = "keySecret_zk7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn";
    const GROUP_SEALER_SECRET_REF: &str =
        "sealerSecret_zDM4VxnShBcFV5BqZrGzVPLNPxpS1B5eGMta5DhMcwwKD";
    const GROUP_SEALER_PUBLIC_REF: &str = "sealer_zGJaAPnF1bXV9889Bmtq4dbLvU48PduYkY2f9FBQADodm";

    #[test]
    fn encrypt_key_secret_matches_ts_reference() {
        let out = encrypt_key_secret(
            TO_ENCRYPT_ID,
            TO_ENCRYPT_SECRET,
            ENCRYPTING_ID,
            ENCRYPTING_SECRET,
        )
        .unwrap();
        assert_eq!(out, ENCRYPTED_REF, "wire format must be byte-identical to TS");
    }

    #[test]
    fn decrypt_key_secret_matches_ts_reference() {
        let secret =
            decrypt_key_secret(ENCRYPTED_REF, TO_ENCRYPT_ID, ENCRYPTING_ID, ENCRYPTING_SECRET)
                .unwrap();
        assert_eq!(secret, TO_ENCRYPT_SECRET);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let out =
            encrypt_key_secret(TO_ENCRYPT_ID, TO_ENCRYPT_SECRET, ENCRYPTING_ID, ENCRYPTING_SECRET)
                .unwrap();
        let back =
            decrypt_key_secret(&out, TO_ENCRYPT_ID, ENCRYPTING_ID, ENCRYPTING_SECRET).unwrap();
        assert_eq!(back, TO_ENCRYPT_SECRET);
    }

    #[test]
    fn group_sealer_from_read_key_matches_ts_reference() {
        let gs = group_sealer_from_read_key(READ_KEY_SECRET).unwrap();
        assert_eq!(gs.secret, GROUP_SEALER_SECRET_REF);
        assert_eq!(gs.public_key, GROUP_SEALER_PUBLIC_REF);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        // Encrypting-key mismatch must not silently succeed.
        let res = decrypt_key_secret(ENCRYPTED_REF, TO_ENCRYPT_ID, ENCRYPTING_ID, TO_ENCRYPT_SECRET);
        assert!(res.is_err());
    }

    #[test]
    fn decrypt_bad_prefix_fails() {
        let res = decrypt_key_secret("nope_U0000", TO_ENCRYPT_ID, ENCRYPTING_ID, ENCRYPTING_SECRET);
        assert!(matches!(res, Err(CryptoError::InvalidPrefix(..))));
    }
}
