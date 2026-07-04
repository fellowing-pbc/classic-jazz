//! Group transaction views and validation ordering.
//!
//! Builds [`GroupTxView`]s from a [`SessionMapImpl`] — iterating sessions in
//! insertion order, transactions by index within a session, parsing each
//! transaction JSON exactly once — and sorts them with the validation
//! comparator ported from `coValueCore.ts:1842-1855` (`compareTransactions`).
//!
//! The comparator orders by `effective_made_at` ascending; ties are broken by
//! `tx_index` only WITHIN a session, and across sessions the original
//! (session-insertion) order is preserved: Rust's `Vec::sort_by` is stable, so
//! returning [`Equal`](core::cmp::Ordering::Equal) for cross-session ties keeps
//! the iteration order established by [`collect_group_txs`]. The
//! `cross_session_ties` fixture exists precisely to pin this outcome.

use crate::core::group_engine::classify::author_from_session_id;
use crate::core::session_log::Transaction;
use crate::core::SessionMapImpl;
use std::collections::HashMap;

/// Extra per-transaction info the sync/merge layer supplies (merge-meta
/// derived source times). Looked up by `(session_id, tx_index)` inside
/// [`collect_group_txs`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PendingTxIn {
    pub session_id: String,
    pub tx_index: u32,
    pub source_made_at: Option<u64>,
}

/// Privacy class of a transaction, derived from the wire [`Transaction`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privacy {
    Private,
    Trusting,
}

/// A flattened, parsed view of one group transaction, ready for the validation
/// pass. Built by [`collect_group_txs`].
#[derive(Debug, Clone)]
pub struct GroupTxView {
    pub session_id: String,
    pub tx_index: u32,
    /// `accountOrAgentIDfromSessionID(session_id)` — the transaction author.
    pub author: String,
    /// The transaction's own `madeAt` — used for permission checks.
    pub current_made_at: u64,
    /// `source_made_at.unwrap_or(current_made_at)` — the merge-meta-derived time
    /// used for ORDERING. Falls back to [`GroupTxView::current_made_at`] when no
    /// pending info is supplied for this transaction.
    pub effective_made_at: u64,
    pub privacy: Privacy,
    /// Parsed `changes` array for trusting transactions. `None` for private
    /// transactions (their changes are encrypted/opaque at this layer) and,
    /// defensively, for trusting transactions whose `changes` string is not a
    /// valid JSON array — valid cojson producers always stringify a real array,
    /// so the latter does not occur for stored state.
    pub changes: Option<Vec<serde_json::Value>>,
}

/// Collect every transaction of `sm` into views, in session-insertion order,
/// `tx_index` ascending within each session. Each transaction JSON is parsed
/// exactly once. `pending_info` supplies optional source times keyed by
/// `(session_id, tx_index)`; see [`GroupTxView::effective_made_at`].
pub fn collect_group_txs(sm: &SessionMapImpl, pending_info: &[PendingTxIn]) -> Vec<GroupTxView> {
    // Keyed source-time lookup. Only entries that carry a source time
    // participate; their absence falls back to the tx's own madeAt — matching
    // `source_made_at.unwrap_or(current_made_at)`.
    let source_times: HashMap<(&str, u32), u64> = pending_info
        .iter()
        .filter_map(|p| {
            p.source_made_at
                .map(|t| ((p.session_id.as_str(), p.tx_index), t))
        })
        .collect();

    let mut views = Vec::new();
    for (session_id, tx_jsons) in sm.iter_session_transactions() {
        for (tx_index, tx_json) in tx_jsons.iter().enumerate() {
            // SessionMapImpl stores only transactions it serialized itself, so
            // every entry re-parses as a Transaction; a failure here would
            // indicate storage corruption (and would silently change the
            // validation set, so we surface it loudly rather than skip).
            let tx: Transaction = serde_json::from_str(tx_json)
                .expect("stored transaction JSON must re-parse as Transaction");

            let (privacy, current_made_at, changes) = match tx {
                Transaction::Trusting(t) => {
                    // Cojson producers always stringify a valid JSON array; a
                    // parse failure is defensive only (treated as no usable
                    // changes, which downstream validation will reject).
                    let changes = serde_json::from_str(&t.changes).ok();
                    let made_at = t.made_at.as_u64().unwrap_or(0);
                    (Privacy::Trusting, made_at, changes)
                }
                Transaction::Private(p) => {
                    let made_at = p.made_at.as_u64().unwrap_or(0);
                    (Privacy::Private, made_at, None)
                }
            };

            let effective_made_at = source_times
                .get(&(session_id, tx_index as u32))
                .copied()
                .unwrap_or(current_made_at);

            views.push(GroupTxView {
                session_id: session_id.to_string(),
                tx_index: tx_index as u32,
                author: author_from_session_id(session_id).to_string(),
                current_made_at,
                effective_made_at,
                privacy,
                changes,
            });
        }
    }
    views
}

/// `compareTransactions` port (`coValueCore.ts:1842-1855`) + STABLE sort.
///
/// `effective_made_at` ascending; on ties, same-session pairs order by
/// `tx_index`, cross-session pairs compare [`Equal`](core::cmp::Ordering::Equal)
/// so the stable sort preserves the session-insertion order built by
/// [`collect_group_txs`].
pub fn sort_for_validation(txs: &mut [GroupTxView]) {
    txs.sort_by(|a, b| {
        match a.effective_made_at.cmp(&b.effective_made_at) {
            core::cmp::Ordering::Equal if a.session_id == b.session_id => {
                a.tx_index.cmp(&b.tx_index)
            }
            core::cmp::Ordering::Equal => core::cmp::Ordering::Equal,
            other => other,
        }
    });
}

// =====================================================================
// Test-support: fixture serde structs (reused by later group-engine tasks)
// =====================================================================

#[cfg(test)]
pub(crate) mod fixtures {
    use serde::Deserialize;
    use std::collections::HashMap;

    use crate::core::SessionMapImpl;

    /// One session's raw transaction wire JSON plus its commit signature, as
    /// stored in a fixture file.
    #[allow(dead_code)]
    #[derive(Debug, Clone, Deserialize)]
    pub struct FixtureSession {
        #[serde(rename = "sessionId")]
        pub session_id: String,
        #[serde(rename = "signerId", default)]
        pub signer_id: Option<String>,
        /// Raw wire-JSON transaction strings; each parses to a `Transaction`.
        pub transactions: Vec<String>,
        #[serde(rename = "lastSignature")]
        pub last_signature: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct FixtureCovalue {
        #[serde(rename = "coId")]
        pub co_id: String,
        #[serde(rename = "headerJson")]
        pub header_json: String,
        pub sessions: Vec<FixtureSession>,
    }

    /// A per-transaction validation verdict, keyed by coId in
    /// [`FixtureFile::verdicts`]. The ORDER of a coId's verdict list is the
    /// expected validation order — `collect_group_txs` + `sort_for_validation`
    /// must reproduce it.
    /// Read by Task 4 (validation); kept here so the fixture parses fully.
    #[allow(dead_code)]
    #[derive(Debug, Clone, Deserialize)]
    pub struct FixtureVerdict {
        #[serde(rename = "sessionId")]
        pub session_id: String,
        #[serde(rename = "txIndex")]
        pub tx_index: u32,
        pub valid: bool,
        pub reason: Option<String>,
    }

    /// Read by Task 4 (role resolution); kept here so the fixture parses fully.
    #[allow(dead_code)]
    #[derive(Debug, Clone, Deserialize)]
    pub struct FixtureRoleQuery {
        #[serde(rename = "groupId")]
        pub group_id: String,
        pub member: String,
        #[serde(rename = "atTime")]
        pub at_time: Option<u64>,
        // `null` in fixtures means "the member has no role at this time".
        #[serde(rename = "expectedRole")]
        pub expected_role: Option<String>,
    }

    /// Parsed shape of a `data/group_engine/*.json` fixture file.
    #[allow(dead_code)]
    #[derive(Debug, Clone, Deserialize)]
    pub struct FixtureFile {
        #[serde(default)]
        pub description: Option<String>,
        pub covalues: Vec<FixtureCovalue>,
        #[serde(default)]
        pub verdicts: HashMap<String, Vec<FixtureVerdict>>,
        #[serde(default, rename = "roleQueries")]
        pub role_queries: Vec<FixtureRoleQuery>,
    }

    impl FixtureFile {
        /// Load a fixture from `data/group_engine/<name>.json` relative to the
        /// crate root (where `cargo test` runs).
        pub fn load(name: &str) -> Self {
            let path = format!("data/group_engine/{name}.json");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("parse {path}: {e}"))
        }
    }

    /// Build a `SessionMapImpl` from a fixture covalue, loading every session's
    /// transactions with signature verification skipped. The group engine reads
    /// already-stored state; it does not re-verify session signatures here, and
    /// the tx views it builds are independent of the signer id.
    pub fn build_session_map(cov: &FixtureCovalue) -> SessionMapImpl {
        let mut sm = SessionMapImpl::new_with_skip_verify(&cov.co_id, &cov.header_json, None, true)
            .expect("fixture header should parse under skip_verify");
        for session in &cov.sessions {
            // `add_transactions` takes a JSON array of transaction OBJECTS; the
            // fixture stores one object per string, so splice them into an array
            // (no re-serialization that could reorder fields).
            let txs_json = format!("[{}]", session.transactions.join(","));
            // signer_id left as None: fixture `signerId`s are account/session
            // ids, not raw verifying keys, and signature verification is skipped
            // anyway — the group engine does not need a public key here.
            sm.add_transactions(
                &session.session_id,
                None,
                &txs_json,
                &session.last_signature,
                true,
            )
            .expect("fixture transactions load under skip_verify");
        }
        sm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cross_session_ties` (group covalue `co_zfF4FnTK4hX5gj2Lzss8Zxp2HTh`):
    /// three sessions, all transactions at the SAME `madeAt`. Extraction must be
    /// session-insertion / txIndex-ascending, and because every effective time is
    /// equal, the stable sort must be a no-op — both reproducing the fixture's
    /// verdict order (8 admin-session txs, then one tx each from the two
    /// conflicting sessions).
    #[test]
    fn cross_session_ties_extraction_and_order_match_verdicts() {
        let fix = fixtures::FixtureFile::load("cross_session_ties");
        let cov = fix
            .covalues
            .iter()
            .find(|c| c.co_id == "co_zfF4FnTK4hX5gj2Lzss8Zxp2HTh")
            .expect("ties group covalue present");

        let sm = fixtures::build_session_map(cov);
        let collected = collect_group_txs(&sm, &[]);

        let verdicts = fix
            .verdicts
            .get("co_zfF4FnTK4hX5gj2Lzss8Zxp2HTh")
            .expect("ties verdicts present");

        // Extraction order already equals the verdict (validation) order.
        assert_eq!(collected.len(), verdicts.len(), "tx count");
        for (v, vd) in collected.iter().zip(verdicts.iter()) {
            assert_eq!(v.session_id, vd.session_id, "session order");
            assert_eq!(v.tx_index, vd.tx_index, "tx_index order");
            // All equal madeAt, no pending info -> effective == current.
            assert_eq!(v.current_made_at, 1_700_000_000_000, "current_made_at");
            assert_eq!(v.effective_made_at, v.current_made_at, "effective_made_at");
            assert_eq!(v.privacy, Privacy::Trusting, "privacy");
            assert!(v.changes.is_some(), "trusting tx must parse changes");
        }

        // Stable sort of an all-equal set is a no-op.
        let mut sorted = collected.clone();
        sort_for_validation(&mut sorted);
        let key = |v: &GroupTxView| (v.session_id.clone(), v.tx_index);
        assert_eq!(
            sorted.iter().map(key).collect::<Vec<_>>(),
            collected.iter().map(key).collect::<Vec<_>>(),
            "stable sort must preserve insertion order on equal madeAt"
        );
    }

    /// `basic_roles` (group covalue, single session, 20 trusting txs with
    /// monotonically non-decreasing `madeAt` in txIndex order). Pins: same-session
    /// ties break by txIndex, and a single session's txIndex order is already the
    /// sorted order.
    #[test]
    fn basic_roles_single_session_order() {
        let fix = fixtures::FixtureFile::load("basic_roles");
        let cov = &fix.covalues[0];
        assert_eq!(cov.co_id, "co_zSwsoHJ9ytViWJyoLeMwG8GLJ3T");

        let sm = fixtures::build_session_map(cov);
        let mut views = collect_group_txs(&sm, &[]);

        assert_eq!(views.len(), 20, "20 trusting txs in the admin session");
        for (i, v) in views.iter().enumerate() {
            assert_eq!(v.tx_index, i as u32, "tx_index ascending");
            assert_eq!(v.privacy, Privacy::Trusting);
            assert!(v.changes.is_some());
            assert_eq!(v.effective_made_at, v.current_made_at, "no pending info");
        }

        // madeAt is non-decreasing in txIndex order in this fixture, so the
        // single-session sort (ties -> txIndex) is a no-op.
        let before: Vec<u32> = views.iter().map(|v| v.tx_index).collect();
        sort_for_validation(&mut views);
        let after: Vec<u32> = views.iter().map(|v| v.tx_index).collect();
        assert_eq!(before, after, "single-session sort preserves txIndex order");
    }

    /// `private_tx_in_group` (group covalue): 4 trusting txs followed by one
    /// private tx. A private tx must yield `Privacy::Private` with `changes`
    /// `None` (changes are encrypted/opaque here); trusting txs parse changes.
    #[test]
    fn private_tx_view_has_no_changes() {
        let fix = fixtures::FixtureFile::load("private_tx_in_group");
        let cov = &fix.covalues[0];
        let sm = fixtures::build_session_map(cov);
        let views = collect_group_txs(&sm, &[]);

        assert_eq!(views.len(), 5);
        for v in &views[0..4] {
            assert_eq!(v.privacy, Privacy::Trusting);
            assert!(v.changes.is_some(), "trusting tx parses changes");
        }
        let private = &views[4];
        assert_eq!(private.privacy, Privacy::Private);
        assert!(private.changes.is_none(), "private tx changes must be None");
        assert_eq!(private.current_made_at, 1_783_120_267_022);
    }

    /// Synthetic test pinning all three comparator branches directly:
    /// different `madeAt` orders ascending; equal `madeAt` within a session
    /// orders by txIndex; equal `madeAt` across sessions preserves insertion
    /// order (stable).
    #[test]
    fn sort_for_validation_pins_three_branches() {
        fn view(session: &str, tx_index: u32, effective_made_at: u64) -> GroupTxView {
            GroupTxView {
                session_id: session.to_string(),
                tx_index,
                author: author_from_session_id(session).to_string(),
                current_made_at: effective_made_at,
                effective_made_at,
                privacy: Privacy::Trusting,
                changes: Some(vec![]),
            }
        }

        // Insertion order: s1/0, s2/0, s1/1, s3/0
        let mut txs = vec![
            view("co_a_session_x", 0, 200),
            view("co_b_session_y", 0, 100), // earlier madeAt -> sorts first
            view("co_a_session_x", 1, 200),
            view("co_c_session_z", 0, 200),
        ];
        sort_for_validation(&mut txs);

        let order: Vec<(String, u32)> = txs
            .iter()
            .map(|t| (t.session_id.clone(), t.tx_index))
            .collect();
        assert_eq!(
            order,
            vec![
                ("co_b_session_y".to_string(), 0), // madeAt 100 ascending
                ("co_a_session_x".to_string(), 0), // madeAt 200, same session -> txIndex
                ("co_a_session_x".to_string(), 1),
                ("co_c_session_z".to_string(), 0), // madeAt 200, cross-session -> stable
            ]
        );
    }

    /// `pending_info` source times override `current_made_at` for ORDERING only:
    /// `effective_made_at = source_made_at.unwrap_or(current_made_at)`, while
    /// `current_made_at` is unchanged.
    #[test]
    fn pending_source_made_at_drives_ordering() {
        let fix = fixtures::FixtureFile::load("cross_session_ties");
        let cov = fix
            .covalues
            .iter()
            .find(|c| c.co_id == "co_zfF4FnTK4hX5gj2Lzss8Zxp2HTh")
            .unwrap();
        let sm = fixtures::build_session_map(cov);

        // Push session B's single tx to a much later source time so it lands last.
        let b_session = "co_zUGQrkaYiZrjKaNgqQgARcDd54d_session_zG8MqseX8L3A";
        let pending = vec![PendingTxIn {
            session_id: b_session.to_string(),
            tx_index: 0,
            source_made_at: Some(1_800_000_000_000),
        }];
        let mut views = collect_group_txs(&sm, &pending);
        sort_for_validation(&mut views);

        let b = views
            .iter()
            .find(|v| v.session_id == b_session)
            .expect("session B present");
        assert_eq!(b.current_made_at, 1_700_000_000_000, "current unchanged");
        assert_eq!(b.effective_made_at, 1_800_000_000_000, "effective overridden");
        assert_eq!(
            views.last().unwrap().session_id, b_session,
            "later effective time sorts last"
        );
    }
}
