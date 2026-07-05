//! Native, read-only reproduction of `LocalNode`'s pure identity-resolution
//! slice — a "typed lens over already-native state" (`CoValueHeader`), mirroring
//! `group_key_state.rs`.
//!
//! This ports three pure, synchronous, zero-mutation functions from
//! `packages/cojson/src/localNode.ts` / `typeUtils/accountOrAgentIDfromSessionID.ts`:
//!
//!   - [`is_agent_id`] — the `isAgentID` prefix predicate.
//!   - [`account_or_agent_id_from_session_id`] — the session-id string lens
//!     `getCurrentAccountOrAgentID()` delegates to.
//!   - [`resolve_account_agent`] — `resolveAccountAgent`: an agent id resolves to
//!     itself; an account CoValue resolves to its `ruleset.initialAdmin`; every
//!     other shape resolves to a classified error.
//!
//! There are ZERO production call sites: this module exists purely to be replayed
//! against the golden fixtures exported by
//! `packages/cojson/src/tests/identityGoldenTrace.test.ts`, establishing that a
//! future native `CoValueCore` port would reproduce TS identity resolution
//! byte-for-byte. The header it inspects is the SAME native [`CoValueHeader`]
//! already parsed by `session_map.rs`.

use crate::core::session_map::{CoValueHeader, JsonValue, RulesetDef};

/// TypeScript `isAgentID`: an agent id looks like
/// `sealer_z…/signer_z…` — i.e. starts with `sealer_` and contains `/signer_`.
pub fn is_agent_id(id: &str) -> bool {
    id.starts_with("sealer_") && id.contains("/signer_")
}

/// TypeScript `accountOrAgentIDfromSessionID`: slice the session id at the first
/// `_session`. Faithful to the TS `slice(0, indexOf(...))`, including its quirk
/// that a string WITHOUT `_session` drops its final char (`slice(0, -1)`).
pub fn account_or_agent_id_from_session_id(session_id: &str) -> &str {
    match session_id.find("_session") {
        Some(i) => &session_id[..i],
        // Mirror JS `String.slice(0, -1)` when indexOf returns -1.
        None => &session_id[..session_id.len().saturating_sub(1)],
    }
}

/// The two error classes `resolveAccountAgent` can surface, tagged to match the
/// TS harness's normalized `errorKind` ("unavailable" | "not_account").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveErrorKind {
    /// The covalue was not loaded/available (`expectCoValueLoaded` threw).
    Unavailable,
    /// The header is not an account shape, or its admin is not an agent id.
    NotAccount,
}

impl ResolveErrorKind {
    /// The stable string tag used by the golden fixtures.
    pub fn tag(self) -> &'static str {
        match self {
            ResolveErrorKind::Unavailable => "unavailable",
            ResolveErrorKind::NotAccount => "not_account",
        }
    }
}

/// Normalized outcome of [`resolve_account_agent`], matching the TS harness's
/// `{ value, errorKind }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOutcome {
    /// The resolved agent id, or `None` when an error was produced.
    pub value: Option<String>,
    /// `None` on success, else the classified error.
    pub error_kind: Option<ResolveErrorKind>,
}

impl ResolveOutcome {
    fn resolved(id: impl Into<String>) -> Self {
        ResolveOutcome {
            value: Some(id.into()),
            error_kind: None,
        }
    }
    fn err(kind: ResolveErrorKind) -> Self {
        ResolveOutcome {
            value: None,
            error_kind: Some(kind),
        }
    }
}

/// Native reproduction of `LocalNode.resolveAccountAgent`.
///
/// - `id`: the account or agent id being resolved.
/// - `available`: whether the covalue was loaded (only consulted for non-agent
///   ids; the agent-id branch short-circuits before any lookup).
/// - `header`: the loaded covalue's header (must be `Some` when `available`).
///
/// This mirrors the TS control flow exactly:
///   1. agent id -> resolves to itself;
///   2. not available -> `Unavailable`;
///   3. not (comap + group ruleset + `meta.type == "account"`) -> `NotAccount`;
///   4. `ruleset.initialAdmin` not an agent id -> `NotAccount`;
///   5. otherwise -> the `initialAdmin` agent id.
pub fn resolve_account_agent(
    id: &str,
    available: bool,
    header: Option<&CoValueHeader>,
) -> ResolveOutcome {
    if is_agent_id(id) {
        return ResolveOutcome::resolved(id);
    }

    if !available {
        return ResolveOutcome::err(ResolveErrorKind::Unavailable);
    }

    let header = match header {
        Some(h) => h,
        // An available covalue always has a header; treat a missing one as the
        // same "not an account" failure the TS header checks would produce.
        None => return ResolveOutcome::err(ResolveErrorKind::NotAccount),
    };

    let meta_is_account = matches!(
        header.meta.as_ref().and_then(|m| match m {
            JsonValue::Object(fields) => fields.get("type"),
            _ => None,
        }),
        Some(JsonValue::String(t)) if t == "account"
    );

    let initial_admin = match &header.ruleset {
        RulesetDef::Group(g) => &g.initial_admin,
        _ => return ResolveOutcome::err(ResolveErrorKind::NotAccount),
    };

    if header.co_type != "comap" || !meta_is_account {
        return ResolveOutcome::err(ResolveErrorKind::NotAccount);
    }

    if !is_agent_id(initial_admin) {
        return ResolveOutcome::err(ResolveErrorKind::NotAccount);
    }

    ResolveOutcome::resolved(initial_admin)
}

// ---------------------------------------------------------------------------
// Golden-fixture replay: load `data/identity_resolution/{resolution,session_ids}
// .json` (exported by `packages/cojson/src/tests/identityGoldenTrace.test.ts`
// from the REAL `resolveAccountAgent` / `accountOrAgentIDfromSessionID`) and
// assert the native reproduction matches byte-for-byte.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod fixtures {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ExpectedFx {
        value: Option<String>,
        #[serde(rename = "errorKind")]
        error_kind: Option<String>,
    }

    #[derive(Deserialize)]
    struct ResolutionFx {
        #[allow(dead_code)]
        description: String,
        id: String,
        available: bool,
        header: Option<CoValueHeader>,
        expected: ExpectedFx,
    }

    #[derive(Deserialize)]
    struct SessionIdFx {
        #[allow(dead_code)]
        description: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        expected: String,
    }

    fn load(name: &str) -> String {
        let path = format!("data/identity_resolution/{name}.json");
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    #[test]
    fn replays_resolution_cases() {
        let cases: Vec<ResolutionFx> =
            serde_json::from_str(&load("resolution")).expect("parse resolution.json");
        assert!(!cases.is_empty(), "no resolution fixtures");

        for case in &cases {
            let outcome = resolve_account_agent(&case.id, case.available, case.header.as_ref());
            assert_eq!(
                outcome.value, case.expected.value,
                "value mismatch for {}",
                case.description
            );
            assert_eq!(
                outcome.error_kind.map(|k| k.tag().to_string()),
                case.expected.error_kind,
                "errorKind mismatch for {}",
                case.description
            );
        }
    }

    #[test]
    fn replays_session_id_cases() {
        let cases: Vec<SessionIdFx> =
            serde_json::from_str(&load("session_ids")).expect("parse session_ids.json");
        assert!(!cases.is_empty(), "no session-id fixtures");

        for case in &cases {
            assert_eq!(
                account_or_agent_id_from_session_id(&case.session_id),
                case.expected,
                "slice mismatch for {}",
                case.description
            );
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn agent_id_predicate() {
        assert!(is_agent_id("sealer_zAAA/signer_zBBB"));
        assert!(!is_agent_id("co_zAAA"));
        assert!(!is_agent_id("sealer_zAAA")); // no signer part
    }

    #[test]
    fn session_id_slice_without_marker_drops_last_char() {
        // Faithful to JS slice(0, -1) when "_session" is absent.
        assert_eq!(account_or_agent_id_from_session_id("abcd"), "abc");
        assert_eq!(account_or_agent_id_from_session_id(""), "");
    }

    #[test]
    fn agent_id_resolves_to_itself_without_header() {
        let out = resolve_account_agent("sealer_zX/signer_zY", false, None);
        assert_eq!(out, ResolveOutcome::resolved("sealer_zX/signer_zY"));
    }
}
