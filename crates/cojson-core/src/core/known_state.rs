//! Standalone port of cojson's known-state combine algebra.
//!
//! Mirrors `packages/cojson/src/knownState.ts` exactly. A CoValue's "known
//! state" records which transactions we (or a peer) have observed: a per-session
//! transaction count plus a `header`-seen flag. The core operation is a pure,
//! crypto-free, small-data merge — a per-session `max` (plus a header OR) — used
//! by the sync layer to reconcile "what I have" against "what a peer told me".
//!
//! This module is intentionally self-contained: it has no dependency on the
//! group_engine / co_map / co_stream / session_map machinery. `session_map.rs`
//! keeps its own private helpers for the streaming path; this is the canonical,
//! testable port of the wire-facing `knownState.ts` surface.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// `sessionID -> highest known transaction count` for that session.
///
/// `IndexMap` preserves insertion order so that a combined state serializes in
/// the same key order a TypeScript object would (existing keys keep position,
/// newly-seen sessions are appended), matching the exporter fixtures byte for
/// byte. Equality is order-independent, so comparisons stay robust.
pub type KnownStateSessions = IndexMap<String, u32>;

/// Mirrors TS `CoValueKnownState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoValueKnownState {
    pub id: String,
    pub header: bool,
    pub sessions: KnownStateSessions,
}

/// `CoValueFrontier` is a plain alias of `KnownStateSessions` in TS — there is
/// no frontier-truncation logic; a frontier is just a copy of a state's
/// sessions.
pub type CoValueFrontier = KnownStateSessions;

/// Returns an empty known state for a CoValue: no header, no sessions.
///
/// Port of `emptyKnownState`.
pub fn empty_known_state(id: impl Into<String>) -> CoValueKnownState {
    CoValueKnownState {
        id: id.into(),
        header: false,
        sessions: KnownStateSessions::new(),
    }
}

/// Efficient clone of a known state.
///
/// Port of `cloneKnownState`. Provided for parity with the TS surface; callers
/// may also use the derived `Clone`.
pub fn clone_known_state(known_state: &CoValueKnownState) -> CoValueKnownState {
    known_state.clone()
}

/// Mutates `target` by combining the entries from `source`, assigning a
/// session's count only when the source value is strictly greater (per-session
/// `max`, defaulting a missing target entry to 0).
///
/// Port of `combineKnownStateSessions`. The insert-when-greater shape matches
/// the TS object assignment: existing keys keep their position, newly-seen
/// sessions are appended.
pub fn combine_known_state_sessions(target: &mut KnownStateSessions, source: &KnownStateSessions) {
    for (session_id, &count) in source {
        let current = target.get(session_id).copied().unwrap_or(0);
        if count > current {
            // IndexMap::insert keeps an existing key's position and appends a
            // new one — identical to `target[sessionID] = count` in JS.
            target.insert(session_id.clone(), count);
        }
    }
}

/// Mutates `target` by combining sessions from `source` and OR-ing the header
/// flag (a seen header is never un-seen).
///
/// Port of `combineKnownStates`.
pub fn combine_known_states(target: &mut CoValueKnownState, source: &CoValueKnownState) {
    combine_known_state_sessions(&mut target.sessions, &source.sessions);

    if source.header && !target.header {
        target.header = true;
    }
}

/// Sets the counter for a session unconditionally.
///
/// Port of `setSessionCounter`.
pub fn set_session_counter(known_state: &mut KnownStateSessions, session_id: &str, value: u32) {
    known_state.insert(session_id.to_string(), value);
}

/// Raises the counter for a session to `max(existing, value)`.
///
/// Port of `updateSessionCounter`.
pub fn update_session_counter(known_state: &mut KnownStateSessions, session_id: &str, value: u32) {
    let current = known_state.get(session_id).copied().unwrap_or(0);
    known_state.insert(session_id.to_string(), current.max(value));
}

/// Returns true when every session in `current` has an *exactly equal* counter
/// in `target` (a missing target entry counts as 0).
///
/// Port of `areCurrentSessionsInSyncWith`.
pub fn are_current_sessions_in_sync_with(
    current: &KnownStateSessions,
    target: &KnownStateSessions,
) -> bool {
    current.iter().all(|(session_id, &current_count)| {
        let target_count = target.get(session_id).copied().unwrap_or(0);
        current_count == target_count
    })
}

/// Returns true when `current` is a subset of `target`: every session in
/// `current` has a counter no greater than `target`'s (missing target = 0).
///
/// Port of `isKnownStateSubsetOf`.
pub fn is_known_state_subset_of(
    current: &KnownStateSessions,
    target: &KnownStateSessions,
) -> bool {
    current.iter().all(|(session_id, &current_count)| {
        let target_count = target.get(session_id).copied().unwrap_or(0);
        current_count <= target_count
    })
}

/// Returns true when `peer` already holds all of `own`'s content: it has the
/// header (if we do) and is a superset on every session.
///
/// Port of `peerHasAllContent`. `peer == None` maps to TS `undefined`.
pub fn peer_has_all_content(
    own: &CoValueKnownState,
    peer: Option<&CoValueKnownState>,
) -> bool {
    let Some(peer) = peer else {
        return false;
    };

    if !peer.header && own.header {
        return false;
    }

    is_known_state_subset_of(&own.sessions, &peer.sessions)
}

/// Returns the sessions where `current`'s counter exceeds `target`'s — i.e. the
/// entries `current` would need to send `target`.
///
/// Port of `getKnownStateToSend`.
pub fn get_known_state_to_send(
    current: &KnownStateSessions,
    target: &KnownStateSessions,
) -> KnownStateSessions {
    let mut to_send = KnownStateSessions::new();
    for (session_id, &current_count) in current {
        let target_count = target.get(session_id).copied().unwrap_or(0);
        if current_count > target_count {
            to_send.insert(session_id.clone(), current_count);
        }
    }
    to_send
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sessions(pairs: &[(&str, u32)]) -> KnownStateSessions {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn empty_state_shape() {
        let e = empty_known_state("co_ztest");
        assert_eq!(e.id, "co_ztest");
        assert!(!e.header);
        assert!(e.sessions.is_empty());
    }

    #[test]
    fn combine_sessions_per_session_max() {
        let mut target = sessions(&[("a", 3), ("b", 1)]);
        let source = sessions(&[("a", 2), ("b", 5), ("c", 4)]);
        combine_known_state_sessions(&mut target, &source);
        // a stays (target higher), b raised, c appended
        assert_eq!(target.get("a"), Some(&3));
        assert_eq!(target.get("b"), Some(&5));
        assert_eq!(target.get("c"), Some(&4));
        // insertion order: existing keys keep position, new appended
        let keys: Vec<&String> = target.keys().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn combine_states_header_or() {
        let mut target = empty_known_state("co_z1");
        let mut source = empty_known_state("co_z1");
        source.header = true;
        source.sessions = sessions(&[("s", 2)]);
        combine_known_states(&mut target, &source);
        assert!(target.header);
        assert_eq!(target.sessions.get("s"), Some(&2));

        // header true never flips back to false
        let mut src2 = empty_known_state("co_z1");
        src2.header = false;
        combine_known_states(&mut target, &src2);
        assert!(target.header);
    }

    #[test]
    fn subset_and_sync_predicates() {
        let a = sessions(&[("s1", 2), ("s2", 3)]);
        let b = sessions(&[("s1", 2), ("s2", 5)]);
        assert!(is_known_state_subset_of(&a, &b));
        assert!(!is_known_state_subset_of(&b, &a));
        assert!(!are_current_sessions_in_sync_with(&a, &b));
        assert!(are_current_sessions_in_sync_with(&a, &a));
        // missing target entry defaults to 0
        let c = sessions(&[("s3", 1)]);
        assert!(!is_known_state_subset_of(&c, &a));
    }

    #[test]
    fn to_send_diff() {
        let current = sessions(&[("s1", 5), ("s2", 3), ("s3", 1)]);
        let target = sessions(&[("s1", 2), ("s2", 3)]);
        let out = get_known_state_to_send(&current, &target);
        // s1 ahead, s3 new; s2 equal -> excluded
        assert_eq!(out.get("s1"), Some(&5));
        assert_eq!(out.get("s3"), Some(&1));
        assert!(!out.contains_key("s2"));
    }

    #[test]
    fn peer_has_all_content_rules() {
        let mut own = empty_known_state("co_z2");
        own.header = true;
        own.sessions = sessions(&[("s1", 3)]);

        assert!(!peer_has_all_content(&own, None));

        let mut peer = empty_known_state("co_z2");
        peer.header = false;
        peer.sessions = sessions(&[("s1", 3)]);
        // peer lacks header
        assert!(!peer_has_all_content(&own, Some(&peer)));

        peer.header = true;
        assert!(peer_has_all_content(&own, Some(&peer)));

        peer.sessions = sessions(&[("s1", 2)]);
        assert!(!peer_has_all_content(&own, Some(&peer)));
    }

    #[test]
    fn update_and_set_counter() {
        let mut ks = sessions(&[("s", 4)]);
        update_session_counter(&mut ks, "s", 2); // lower -> unchanged
        assert_eq!(ks.get("s"), Some(&4));
        update_session_counter(&mut ks, "s", 9); // higher -> raised
        assert_eq!(ks.get("s"), Some(&9));
        set_session_counter(&mut ks, "s", 1); // unconditional
        assert_eq!(ks.get("s"), Some(&1));
    }

    // ------------------------------------------------------------------
    // Fixture replay: the executable spec is generated by the TS exporter
    // (knownStateFixtures.export.test.ts) from the REAL knownState.ts
    // functions, then replayed here. Each fixture pins the full combine
    // algebra + predicate surface for one scenario. Byte-identical merge
    // results are asserted by re-serializing the combined state.
    // ------------------------------------------------------------------

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureExpected {
        combined: CoValueKnownState,
        combined_sessions: KnownStateSessions,
        to_send: KnownStateSessions,
        subset_of: bool,
        in_sync: bool,
        peer_has_all_content: bool,
    }

    #[derive(serde::Deserialize)]
    struct Fixture {
        #[allow(dead_code)]
        description: String,
        target: CoValueKnownState,
        source: CoValueKnownState,
        expected: FixtureExpected,
    }

    fn fixture_names() -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir("data/known_state")
            .expect("data/known_state directory must exist (run the TS exporter)")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn replay_known_state_fixtures() {
        let names = fixture_names();
        assert!(
            !names.is_empty(),
            "expected at least one known-state fixture in data/known_state"
        );

        for name in names {
            let path = format!("data/known_state/{name}");
            let raw = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
            let fixture: Fixture = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("cannot parse {path}: {e}"));

            // combineKnownStates(clone(target), source)
            let mut combined = clone_known_state(&fixture.target);
            combine_known_states(&mut combined, &fixture.source);
            assert_eq!(
                combined, fixture.expected.combined,
                "combined mismatch in {name}"
            );
            // byte-identical serialization
            assert_eq!(
                serde_json::to_string(&combined).unwrap(),
                serde_json::to_string(&fixture.expected.combined).unwrap(),
                "combined bytes mismatch in {name}"
            );

            // combineKnownStateSessions(clone(target.sessions), source.sessions)
            let mut combined_sessions = fixture.target.sessions.clone();
            combine_known_state_sessions(&mut combined_sessions, &fixture.source.sessions);
            assert_eq!(
                combined_sessions, fixture.expected.combined_sessions,
                "combined_sessions mismatch in {name}"
            );
            assert_eq!(
                serde_json::to_string(&combined_sessions).unwrap(),
                serde_json::to_string(&fixture.expected.combined_sessions).unwrap(),
                "combined_sessions bytes mismatch in {name}"
            );

            // getKnownStateToSend(target.sessions, source.sessions)
            let to_send =
                get_known_state_to_send(&fixture.target.sessions, &fixture.source.sessions);
            assert_eq!(to_send, fixture.expected.to_send, "to_send mismatch in {name}");

            // isKnownStateSubsetOf(target.sessions, source.sessions)
            assert_eq!(
                is_known_state_subset_of(&fixture.target.sessions, &fixture.source.sessions),
                fixture.expected.subset_of,
                "subset_of mismatch in {name}"
            );

            // areCurrentSessionsInSyncWith(target.sessions, source.sessions)
            assert_eq!(
                are_current_sessions_in_sync_with(
                    &fixture.target.sessions,
                    &fixture.source.sessions
                ),
                fixture.expected.in_sync,
                "in_sync mismatch in {name}"
            );

            // peerHasAllContent(target, source)
            assert_eq!(
                peer_has_all_content(&fixture.target, Some(&fixture.source)),
                fixture.expected.peer_has_all_content,
                "peer_has_all_content mismatch in {name}"
            );
        }
    }
}
