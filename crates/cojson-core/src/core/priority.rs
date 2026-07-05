//! CoValue message priority.
//!
//! Pure, stateless port of TypeScript `packages/cojson/src/priority.ts`.
//! The priority determines the weight given to a CoValue's content messages in
//! the weighted round-robin algorithm used by the sync layer.
//!
//! This is a leaf utility for the CoValueCore-in-Rust migration. It is a
//! byte-for-byte behavioral port of `getPriorityFromHeader`; the numeric values
//! (0 / 3 / 6) match `CO_VALUE_PRIORITY` in the TypeScript source exactly.

use super::session_map::{CoValueHeader, JsonValue, RulesetDef};

/// The priority of a `CoValue`, used as a weight in the weighted round-robin
/// message scheduler. Loosely follows the HTTP urgency range (RFC 9218) but
/// limited to three values. Numeric values match TypeScript `CO_VALUE_PRIORITY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CoValuePriority {
    High = 0,
    Medium = 3,
    Low = 6,
}

impl CoValuePriority {
    /// The underlying numeric priority (matches the TypeScript constant).
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Extract the `type` string from a header's optional `meta` object, mirroring
/// the TypeScript `header.meta?.type` optional-chaining access.
fn meta_type(meta: &Option<JsonValue>) -> Option<&str> {
    match meta {
        Some(JsonValue::Object(map)) => match map.get("type") {
            Some(JsonValue::String(s)) => Some(s.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Determine the priority of a `CoValue` from its header.
///
/// Mirrors the TypeScript `getPriorityFromHeader` branch order exactly:
/// 1. `meta.type === "account"` -> `High`
/// 2. `ruleset.type === "group"` -> `High`
/// 3. `type === "costream" && meta.type === "binary"` -> `Low`
/// 4. otherwise -> `Medium`
pub fn get_priority_from_header(header: &CoValueHeader) -> CoValuePriority {
    if meta_type(&header.meta) == Some("account") {
        return CoValuePriority::High;
    }

    if matches!(header.ruleset, RulesetDef::Group(_)) {
        return CoValuePriority::High;
    }

    if header.co_type == "costream" && meta_type(&header.meta) == Some("binary") {
        return CoValuePriority::Low;
    }

    CoValuePriority::Medium
}

/// Mirrors the full TypeScript signature
/// `getPriorityFromHeader(header: CoValueHeader | undefined | boolean)`.
///
/// The TS function returns `MEDIUM` when the header is `undefined` or a boolean;
/// in Rust those cases are represented by `None`.
pub fn get_priority_from_optional_header(header: Option<&CoValueHeader>) -> CoValuePriority {
    match header {
        Some(h) => get_priority_from_header(h),
        None => CoValuePriority::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header by parsing JSON, exactly as the TS side would receive it.
    fn header(json: &str) -> CoValueHeader {
        serde_json::from_str(json).expect("valid header JSON")
    }

    // Numeric values must match the TypeScript `CO_VALUE_PRIORITY` constant.
    #[test]
    fn numeric_values_match_typescript() {
        assert_eq!(CoValuePriority::High.as_u8(), 0);
        assert_eq!(CoValuePriority::Medium.as_u8(), 3);
        assert_eq!(CoValuePriority::Low.as_u8(), 6);
    }

    #[test]
    fn account_meta_is_high() {
        let h = header(
            r#"{"type":"comap","meta":{"type":"account"},"ruleset":{"type":"ownedByGroup","group":"co_zGroup"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::High);
    }

    #[test]
    fn group_ruleset_is_high() {
        let h = header(
            r#"{"type":"comap","meta":null,"ruleset":{"type":"group","initialAdmin":"co_zAdmin"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::High);
    }

    #[test]
    fn binary_costream_is_low() {
        let h = header(
            r#"{"type":"costream","meta":{"type":"binary"},"ruleset":{"type":"ownedByGroup","group":"co_zGroup"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::Low);
    }

    #[test]
    fn group_check_precedes_binary_costream_check() {
        // A binary costream owned by a group ruleset: the group branch runs
        // first in TS, so this must be High, not Low.
        let h = header(
            r#"{"type":"costream","meta":{"type":"binary"},"ruleset":{"type":"group","initialAdmin":"co_zAdmin"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::High);
    }

    #[test]
    fn plain_comap_is_medium() {
        let h = header(
            r#"{"type":"comap","meta":null,"ruleset":{"type":"ownedByGroup","group":"co_zGroup"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::Medium);
    }

    #[test]
    fn non_binary_costream_is_medium() {
        let h = header(
            r#"{"type":"costream","meta":null,"ruleset":{"type":"ownedByGroup","group":"co_zGroup"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::Medium);
    }

    #[test]
    fn costream_with_non_binary_meta_is_medium() {
        let h = header(
            r#"{"type":"costream","meta":{"type":"something"},"ruleset":{"type":"unsafeAllowAll"},"uniqueness":"z1"}"#,
        );
        assert_eq!(get_priority_from_header(&h), CoValuePriority::Medium);
    }

    #[test]
    fn missing_header_is_medium() {
        // Mirrors TS `getPriorityFromHeader(undefined | boolean)` -> MEDIUM.
        assert_eq!(
            get_priority_from_optional_header(None),
            CoValuePriority::Medium
        );
    }
}
