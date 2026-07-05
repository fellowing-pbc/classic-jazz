use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};

use super::ed25519::CryptoErrorUniffi;

/// Encodes bytes to a base64url string (with padding to match JS implementation)
#[uniffi::export]
pub fn bytes_to_base64url(bytes: Vec<u8>) -> String {
    URL_SAFE.encode(&bytes)
}

/// Encodes bytes to a standard base64 string (with padding)
/// Use this for data URLs and other contexts requiring standard base64.
#[uniffi::export]
pub fn bytes_to_base64(bytes: Vec<u8>) -> String {
    STANDARD.encode(&bytes)
}

/// Decodes a base64url string to bytes (handles both padded and unpadded)
#[uniffi::export]
pub fn base64url_to_bytes(base64: String) -> Result<Vec<u8>, CryptoErrorUniffi> {
    // Try with padding first, then without padding as fallback
    URL_SAFE
        .decode(&base64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&base64))
        .map_err(|e| CryptoErrorUniffi::Base64DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth vectors captured from the TypeScript implementation
    /// (`packages/cojson/src/base64url.ts`) so the Rust binding is provably
    /// byte-for-byte identical. Mirrors `packages/cojson/src/base64url.test.ts`.
    #[test]
    fn base64url_rfc_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, expected) in cases {
            assert_eq!(&bytes_to_base64url(bytes.to_vec()), expected);
            assert_eq!(
                &base64url_to_bytes(expected.to_string()).unwrap(),
                &bytes.to_vec()
            );
        }
    }

    #[test]
    fn base64_standard_rfc_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (bytes, expected) in cases {
            assert_eq!(&bytes_to_base64(bytes.to_vec()), expected);
        }
    }

    #[test]
    fn url_safe_alphabet_differs_from_standard() {
        // 0xFB, 0xEF, 0xBE -> standard "++++", base64url "----"
        assert_eq!(bytes_to_base64url(vec![0xfb, 0xef, 0xbe]), "----");
        assert_eq!(bytes_to_base64(vec![0xfb, 0xef, 0xbe]), "++++");
        // 0xFF, 0xFF, 0xFE -> standard "///+", base64url "___-"
        assert_eq!(bytes_to_base64url(vec![0xff, 0xff, 0xfe]), "___-");
        assert_eq!(bytes_to_base64(vec![0xff, 0xff, 0xfe]), "///+");
    }

    #[test]
    fn url_safe_string_with_special_chars_round_trips() {
        let input = "What does 2 + 2.1 equal?? ~ 4".as_bytes().to_vec();
        assert_eq!(
            bytes_to_base64url(input.clone()),
            "V2hhdCBkb2VzIDIgKyAyLjEgZXF1YWw_PyB-IDQ="
        );
        assert_eq!(
            bytes_to_base64(input.clone()),
            "V2hhdCBkb2VzIDIgKyAyLjEgZXF1YWw/PyB+IDQ="
        );
        assert_eq!(
            base64url_to_bytes("V2hhdCBkb2VzIDIgKyAyLjEgZXF1YWw_PyB-IDQ=".to_string()).unwrap(),
            input
        );
    }

    #[test]
    fn decodes_unpadded_base64url_like_typescript() {
        // TS fallback strips '=' padding; the Rust decoder falls back to the
        // no-pad engine, so unpadded input decodes identically to padded.
        assert_eq!(
            base64url_to_bytes("Zg".to_string()).unwrap(),
            base64url_to_bytes("Zg==".to_string()).unwrap()
        );
        assert_eq!(
            base64url_to_bytes("Zm8".to_string()).unwrap(),
            base64url_to_bytes("Zm8=".to_string()).unwrap()
        );
        assert_eq!(
            base64url_to_bytes("Zm9vYg".to_string()).unwrap(),
            base64url_to_bytes("Zm9vYg==".to_string()).unwrap()
        );
    }

    #[test]
    fn all_byte_values_round_trip_and_match_typescript() {
        let all: Vec<u8> = (0..=255u8).collect();
        // Exact base64url string produced by the TypeScript implementation.
        let expected_url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w==";
        assert_eq!(bytes_to_base64url(all.clone()), expected_url);
        assert_eq!(
            base64url_to_bytes(bytes_to_base64url(all.clone())).unwrap(),
            all
        );
    }
}
