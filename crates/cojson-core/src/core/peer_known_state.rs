//! Standalone port of cojson's `PeerKnownState` state wrapper.
//!
//! Mirrors `packages/cojson/src/coValueCore/PeerKnownState.ts` exactly. A
//! `PeerKnownState` tracks, for one CoValue on one peer connection, two layers of
//! known state:
//!
//!   * `known_state` — the **confirmed** state: what the peer has actually
//!     acknowledged it holds.
//!   * `optimistic_known_state` — an optional **optimistic** overlay: what we
//!     *expect* the peer to hold once in-flight content we have sent lands. It is
//!     lazily cloned from the confirmed state the first time an optimistic combine
//!     happens, and is dropped whenever the confirmed state is authoritatively
//!     `set` (e.g. from a fresh known-state message) or on reconnect.
//!
//! The confirmed/optimistic split is the exact seam where the sync layer's
//! trickiest bugs live (optimistic-state loss on reconnect, optimistic-vs-confirmed
//! conflation). This module is intentionally native-only: it is a proven-correct
//! primitive built on top of the already-ported `known_state.rs` combine algebra,
//! sitting ready for a future authorized phase to consume. It has NO NodeCore /
//! napi / wasm binding and is wired into no live sync code path.

use serde::{Deserialize, Serialize};

use super::known_state::{
    clone_known_state, combine_known_states, empty_known_state, CoValueKnownState,
    KnownStateSessions,
};

/// Payload for [`PeerKnownState::set`].
///
/// Mirrors the TS `CoValueKnownState | "empty"` union: `Empty` clears the
/// confirmed state (header off, no sessions) while keeping the CoValue id;
/// `State` overwrites header + sessions from the given state (an overwrite, NOT a
/// combine).
pub enum SetPayload<'a> {
    Empty,
    State(&'a CoValueKnownState),
}

/// Port of TS `PeerKnownState`.
///
/// Field layout matches the TS class: an immutable `id`/`peer_id`, a confirmed
/// `known_state`, and an optional `optimistic_known_state` overlay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKnownState {
    pub id: String,
    pub peer_id: String,
    known_state: CoValueKnownState,
    optimistic_known_state: Option<CoValueKnownState>,
}

impl PeerKnownState {
    /// Port of the TS constructor: confirmed state starts as
    /// `emptyKnownState(id)`, no optimistic overlay.
    pub fn new(id: impl Into<String>, peer_id: impl Into<String>) -> Self {
        let id = id.into();
        let known_state = empty_known_state(id.clone());
        Self {
            id,
            peer_id: peer_id.into(),
            known_state,
            optimistic_known_state: None,
        }
    }

    /// Port of `cloneWithoutOptimistic`. Produces a fresh `PeerKnownState` for the
    /// same id/peer whose confirmed state is a copy of `self`'s confirmed state and
    /// whose optimistic overlay is dropped.
    ///
    /// This is the reconnect path: on reconnect we cannot know whether in-flight
    /// (optimistic) syncs actually landed, so the optimistic overlay must be reset
    /// to the confirmed baseline.
    pub fn clone_without_optimistic(&self) -> Self {
        let mut clone = PeerKnownState::new(self.id.clone(), self.peer_id.clone());
        // Mirrors TS `clone.set(this.knownState)`.
        clone.set(SetPayload::State(&self.known_state));
        clone
    }

    /// Port of `updateHeader`. Sets the header flag on the confirmed state and, if
    /// present, on the optimistic overlay too.
    pub fn update_header(&mut self, header: bool) {
        self.known_state.header = header;

        if let Some(optimistic) = self.optimistic_known_state.as_mut() {
            optimistic.header = header;
        }
    }

    /// Port of `combineWith`. Combines `value` into the confirmed state and, if
    /// present, into the optimistic overlay as well (confirmed progress implies
    /// optimistic progress).
    pub fn combine_with(&mut self, value: &CoValueKnownState) {
        combine_known_states(&mut self.known_state, value);

        if let Some(optimistic) = self.optimistic_known_state.as_mut() {
            combine_known_states(optimistic, value);
        }
    }

    /// Port of `combineOptimisticWith`. Lazily clones the optimistic overlay from
    /// the *confirmed* state on first use, then combines `value` into the overlay
    /// only. The lazy-clone-from-confirmed is load-bearing: an optimistic combine
    /// on a fresh state must start from what the peer confirmedly has, not from
    /// empty.
    pub fn combine_optimistic_with(&mut self, value: &CoValueKnownState) {
        if self.optimistic_known_state.is_none() {
            self.optimistic_known_state = Some(clone_known_state(&self.known_state));
        }

        // Safe: just ensured it is `Some`.
        combine_known_states(
            self.optimistic_known_state
                .as_mut()
                .expect("optimistic overlay was just initialized"),
            value,
        );
    }

    /// Port of `set`. Aligns the confirmed known state with the payload — an
    /// OVERWRITE of header + sessions (not a combine) — and clears any optimistic
    /// overlay. The CoValue id is preserved regardless of payload.
    pub fn set(&mut self, payload: SetPayload) {
        match payload {
            SetPayload::Empty => {
                self.known_state.header = false;
                self.known_state.sessions = KnownStateSessions::new();
            }
            SetPayload::State(payload) => {
                self.known_state.header = payload.header;
                // `{ ...payload.sessions }` — a fresh copy, overwriting existing.
                self.known_state.sessions = payload.sessions.clone();
            }
        }

        self.optimistic_known_state = None;
    }

    /// Port of `value()`: the confirmed known state.
    pub fn value(&self) -> &CoValueKnownState {
        &self.known_state
    }

    /// Port of `optimisticValue()`: the optimistic overlay if present, otherwise
    /// the confirmed state.
    pub fn optimistic_value(&self) -> &CoValueKnownState {
        self.optimistic_known_state
            .as_ref()
            .unwrap_or(&self.known_state)
    }

    /// Whether an optimistic overlay currently exists. Not part of the TS public
    /// surface (there it is observable via `optimisticValue() !== value()`
    /// reference identity), exposed here so fixtures can pin the lazy-clone
    /// behavior directly.
    pub fn has_optimistic(&self) -> bool {
        self.optimistic_known_state.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::known_state::KnownStateSessions;
    use std::fs;

    fn sessions(pairs: &[(&str, u32)]) -> KnownStateSessions {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn ks(id: &str, header: bool, pairs: &[(&str, u32)]) -> CoValueKnownState {
        CoValueKnownState {
            id: id.to_string(),
            header,
            sessions: sessions(pairs),
        }
    }

    #[test]
    fn fresh_state_is_empty_confirmed_no_optimistic() {
        let pk = PeerKnownState::new("co_zpk", "peer_a");
        assert_eq!(pk.id, "co_zpk");
        assert_eq!(pk.peer_id, "peer_a");
        assert!(!pk.value().header);
        assert!(pk.value().sessions.is_empty());
        assert!(!pk.has_optimistic());
        // optimisticValue falls back to confirmed
        assert_eq!(pk.optimistic_value(), pk.value());
    }

    #[test]
    fn combine_with_updates_both_layers() {
        let mut pk = PeerKnownState::new("co_zpk", "peer_a");
        pk.combine_optimistic_with(&ks("co_zpk", true, &[("s1", 2)]));
        assert!(pk.has_optimistic());
        // now a confirmed combine must move BOTH layers forward
        pk.combine_with(&ks("co_zpk", true, &[("s1", 5), ("s2", 1)]));
        assert_eq!(pk.value().sessions.get("s1"), Some(&5));
        assert_eq!(pk.value().sessions.get("s2"), Some(&1));
        assert_eq!(pk.optimistic_value().sessions.get("s1"), Some(&5));
        assert_eq!(pk.optimistic_value().sessions.get("s2"), Some(&1));
    }

    #[test]
    fn optimistic_lazy_clones_from_confirmed() {
        let mut pk = PeerKnownState::new("co_zpk", "peer_a");
        // confirm s1:3 first
        pk.combine_with(&ks("co_zpk", true, &[("s1", 3)]));
        assert!(!pk.has_optimistic());
        // optimistic combine must start from the confirmed baseline (s1:3), not empty
        pk.combine_optimistic_with(&ks("co_zpk", true, &[("s2", 7)]));
        assert!(pk.has_optimistic());
        assert_eq!(pk.optimistic_value().sessions.get("s1"), Some(&3));
        assert_eq!(pk.optimistic_value().sessions.get("s2"), Some(&7));
        // confirmed stays put
        assert_eq!(pk.value().sessions.get("s1"), Some(&3));
        assert!(pk.value().sessions.get("s2").is_none());
    }

    #[test]
    fn set_overwrites_and_clears_optimistic() {
        let mut pk = PeerKnownState::new("co_zpk", "peer_a");
        pk.combine_with(&ks("co_zpk", true, &[("s1", 9)]));
        pk.combine_optimistic_with(&ks("co_zpk", true, &[("s2", 4)]));
        assert!(pk.has_optimistic());
        // set is an OVERWRITE, not a combine: s1:9 disappears
        pk.set(SetPayload::State(&ks("co_zpk", true, &[("s3", 1)])));
        assert!(!pk.has_optimistic());
        assert_eq!(pk.value().sessions.keys().collect::<Vec<_>>(), vec!["s3"]);
        assert_eq!(pk.value().sessions.get("s3"), Some(&1));
        assert_eq!(pk.optimistic_value(), pk.value());
    }

    #[test]
    fn set_empty_clears_confirmed_but_keeps_id() {
        let mut pk = PeerKnownState::new("co_zpk", "peer_a");
        pk.combine_with(&ks("co_zpk", true, &[("s1", 9)]));
        pk.set(SetPayload::Empty);
        assert_eq!(pk.value().id, "co_zpk");
        assert!(!pk.value().header);
        assert!(pk.value().sessions.is_empty());
        assert!(!pk.has_optimistic());
    }

    #[test]
    fn clone_without_optimistic_drops_overlay_copies_confirmed() {
        let mut pk = PeerKnownState::new("co_zpk", "peer_a");
        pk.combine_with(&ks("co_zpk", true, &[("s1", 3)]));
        pk.combine_optimistic_with(&ks("co_zpk", true, &[("s2", 8)]));
        let clone = pk.clone_without_optimistic();
        assert_eq!(clone.id, "co_zpk");
        assert_eq!(clone.peer_id, "peer_a");
        assert!(!clone.has_optimistic());
        assert_eq!(clone.value().sessions.get("s1"), Some(&3));
        assert!(clone.value().sessions.get("s2").is_none());
        // original untouched
        assert!(pk.has_optimistic());
    }

    // ------------------------------------------------------------------
    // Fixture replay: the executable spec is generated by the TS exporter
    // (peerKnownStateFixtures.export.test.ts) from the REAL PeerKnownState.ts
    // class, then replayed here. Each fixture drives a full operation SEQUENCE
    // and records the resulting confirmed + optimistic state after every step;
    // the replay reproduces every step byte-for-byte.
    // ------------------------------------------------------------------

    #[derive(Deserialize)]
    #[serde(tag = "op")]
    enum Op {
        #[serde(rename = "combineWith")]
        CombineWith { value: CoValueKnownState },
        #[serde(rename = "combineOptimisticWith")]
        CombineOptimisticWith { value: CoValueKnownState },
        #[serde(rename = "updateHeader")]
        UpdateHeader { header: bool },
        #[serde(rename = "set")]
        Set { payload: CoValueKnownState },
        #[serde(rename = "setEmpty")]
        SetEmpty,
        #[serde(rename = "cloneWithoutOptimistic")]
        CloneWithoutOptimistic,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Step {
        value: CoValueKnownState,
        optimistic_value: CoValueKnownState,
        has_optimistic: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        #[allow(dead_code)]
        description: String,
        id: String,
        peer_id: String,
        ops: Vec<Op>,
        steps: Vec<Step>,
    }

    fn fixture_names() -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir("data/peer_known_state")
            .expect("data/peer_known_state directory must exist (run the TS exporter)")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn replay_peer_known_state_fixtures() {
        let names = fixture_names();
        assert!(
            !names.is_empty(),
            "expected at least one peer-known-state fixture in data/peer_known_state"
        );

        for name in names {
            let path = format!("data/peer_known_state/{name}");
            let raw = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
            let fixture: Fixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"));

            assert_eq!(
                fixture.ops.len(),
                fixture.steps.len(),
                "ops/steps length mismatch in {name}"
            );

            let mut pk = PeerKnownState::new(fixture.id.clone(), fixture.peer_id.clone());

            for (i, (op, step)) in fixture.ops.iter().zip(fixture.steps.iter()).enumerate() {
                match op {
                    Op::CombineWith { value } => pk.combine_with(value),
                    Op::CombineOptimisticWith { value } => pk.combine_optimistic_with(value),
                    Op::UpdateHeader { header } => pk.update_header(*header),
                    Op::Set { payload } => pk.set(SetPayload::State(payload)),
                    Op::SetEmpty => pk.set(SetPayload::Empty),
                    // cloneWithoutOptimistic replaces the tracked state with its
                    // reconnect clone, exactly as PeerState.newPeerStateFrom does.
                    Op::CloneWithoutOptimistic => pk = pk.clone_without_optimistic(),
                }

                // Structural equality
                assert_eq!(
                    pk.value(),
                    &step.value,
                    "confirmed value mismatch at step {i} in {name}"
                );
                assert_eq!(
                    pk.optimistic_value(),
                    &step.optimistic_value,
                    "optimistic value mismatch at step {i} in {name}"
                );
                assert_eq!(
                    pk.has_optimistic(),
                    step.has_optimistic,
                    "has_optimistic mismatch at step {i} in {name}"
                );

                // Byte-identical serialization (the strict oracle)
                assert_eq!(
                    serde_json::to_string(pk.value()).unwrap(),
                    serde_json::to_string(&step.value).unwrap(),
                    "confirmed value bytes mismatch at step {i} in {name}"
                );
                assert_eq!(
                    serde_json::to_string(pk.optimistic_value()).unwrap(),
                    serde_json::to_string(&step.optimistic_value).unwrap(),
                    "optimistic value bytes mismatch at step {i} in {name}"
                );
            }
        }
    }
}
