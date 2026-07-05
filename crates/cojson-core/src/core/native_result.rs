//! Shared serialization for the unified native-decision result envelope.
//!
//! Every redesigned native-decision FFI function — the sync content decision
//! (`content_to_send`), the storage write-plan (`plan_session_write`) and the
//! five group-key writes — returns a JSON string in ONE shape so the TS side can
//! parse them uniformly (`parseNativeResult` in
//! `packages/cojson/src/crypto/nativeResult.ts`).
//!
//! # Wire shape
//!
//! ```text
//! success:  {"ok":true,"value":<T>}
//! error:    {"ok":false,"kind":"error","message":"<msg>"}
//! ```
//!
//! `<T>` is the feature-specific success payload:
//!   * content decision — `NewContentMessage[]`, or `null` when nothing to send;
//!   * storage write-plan — the `SessionWritePlan` object (always present);
//!   * group-key writes — `{"skipped":true}` or
//!     `{"writes":[{"op":"set"|"delete","field":"…","value":"…"?}]}`.
//!
//! The third TS variant `{ok:false,kind:"unsupported"}` is TS-side only (it means
//! the method is absent on the backend); Rust never emits it. Any `Err(String)`
//! from a redesigned function becomes the `error` envelope so a genuine Rust-side
//! failure is distinguishable from a deliberate TS fallback (never silently
//! swallowed).

use serde::Serialize;

/// Envelope a successful value that serializes via serde as
/// `{"ok":true,"value":<value>}`.
pub fn ok_json<T: Serialize>(value: &T) -> String {
    #[derive(Serialize)]
    struct Ok_<'a, T: Serialize> {
        ok: bool,
        value: &'a T,
    }
    match serde_json::to_string(&Ok_ { ok: true, value }) {
        Ok(s) => s,
        Err(e) => error_json(&e.to_string()),
    }
}

/// Envelope an already-serialized JSON value string as
/// `{"ok":true,"value":<value_json>}`. Used when the success payload is produced
/// as a JSON string directly rather than a serde value — e.g. `content_to_send`
/// serializes its content pieces by hand to preserve session insertion order,
/// which routing through `serde_json::Value` would destroy. `value_json` MUST be
/// valid JSON (it is spliced in verbatim); pass `"null"` for the empty case.
pub fn ok_json_raw(value_json: &str) -> String {
    let mut s = String::with_capacity(value_json.len() + 19);
    s.push_str("{\"ok\":true,\"value\":");
    s.push_str(value_json);
    s.push('}');
    s
}

/// Envelope an error message as `{"ok":false,"kind":"error","message":"<msg>"}`.
pub fn error_json(message: &str) -> String {
    #[derive(Serialize)]
    struct Err_<'a> {
        ok: bool,
        kind: &'static str,
        message: &'a str,
    }
    serde_json::to_string(&Err_ {
        ok: false,
        kind: "error",
        message,
    })
    .unwrap_or_else(|_| {
        // A plain string message cannot realistically fail to serialize; emit a
        // static, still-valid envelope so the boundary always yields parseable
        // JSON.
        "{\"ok\":false,\"kind\":\"error\",\"message\":\"native result serialization error\"}"
            .to_string()
    })
}

/// Wrap a `Result<T, String>` into the envelope JSON — the standard bridge from
/// a fallible native function to the wire shape.
pub fn to_result_json<T: Serialize>(result: Result<T, String>) -> String {
    match result {
        Ok(v) => ok_json(&v),
        Err(m) => error_json(&m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ok_json_wraps_value() {
        let out: serde_json::Value = serde_json::from_str(&ok_json(&json!({"a": 1}))).unwrap();
        assert_eq!(out, json!({"ok": true, "value": {"a": 1}}));
    }

    #[test]
    fn ok_json_raw_splices_verbatim() {
        assert_eq!(ok_json_raw("null"), "{\"ok\":true,\"value\":null}");
        let out: serde_json::Value =
            serde_json::from_str(&ok_json_raw("[{\"x\":1}]")).unwrap();
        assert_eq!(out, json!({"ok": true, "value": [{"x": 1}]}));
    }

    #[test]
    fn error_json_shape() {
        let out: serde_json::Value = serde_json::from_str(&error_json("boom")).unwrap();
        assert_eq!(
            out,
            json!({"ok": false, "kind": "error", "message": "boom"})
        );
    }

    #[test]
    fn to_result_json_both_arms() {
        let ok: serde_json::Value =
            serde_json::from_str(&to_result_json::<i32>(Ok(7))).unwrap();
        assert_eq!(ok, json!({"ok": true, "value": 7}));
        let err: serde_json::Value =
            serde_json::from_str(&to_result_json::<i32>(Err("nope".to_string()))).unwrap();
        assert_eq!(err, json!({"ok": false, "kind": "error", "message": "nope"}));
    }
}
