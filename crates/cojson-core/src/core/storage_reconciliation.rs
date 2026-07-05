//! Native-only port of cojson's storage-reconciliation bookkeeping.
//!
//! This module ports three pieces of pure, DB-free logic that today live in
//! TypeScript:
//!
//!   * `packages/cojson/src/OngoingStorageReconciliationTracker.ts` — batch →
//!     pending-covalue-set tracking plus a reverse index, used server-side to
//!     know when every covalue in a reconcile batch has finished syncing.
//!   * `packages/cojson/src/StorageReconciliationAckTracker.ts` — pending
//!     reconcile-ack tracking with ack-listener bookkeeping and peer-close
//!     cancellation ("the reconciliation process for this peer is interrupted
//!     ... will resume once the peer reconnects").
//!   * The reconciliation-lock *decision* logic duplicated byte-for-byte
//!     between `storage/sqlite/client.ts` and `storage/sqliteAsync/client.ts`
//!     (`tryAcquireStorageReconciliationLock` / `renew` / `release`). Only the
//!     pure decision — "not due" / "lock held" / "acquired", and what the
//!     resulting lock row would be — is ported here; the surrounding DB
//!     transaction and row I/O stay in TypeScript.
//!
//! This is a native-only library primitive with **zero production wiring** —
//! no NodeCore binding, no napi/wasm/rn exposure, nothing imports it from the
//! sync or storage TypeScript. It sits ready for a FUTURE, separately
//! authorized phase, exactly like `known_state.rs` / `peer_known_state.rs` /
//! `group_key_state.rs`.
//!
//! Every function is validated against fixtures exported from the REAL current
//! TypeScript behavior (see the `storageReconciliation*Fixtures.export.test.ts`
//! suites and the `data/storage_reconciliation_*` directories).

use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};

// =====================================================================
// Reconciliation-lock pure decision (mirrors the byte-identical
// tryAcquire/renew/release logic in both sqlite clients).
// =====================================================================

/// Mirrors TS `StorageReconciliationLockRow` (minus the derived `key`, which is
/// always `lock#{peerId}` and irrelevant to the decision itself).
///
/// Times are milliseconds-since-epoch, matching JS `Date.now()`. `i64` covers
/// the full JS-`number` millisecond range with headroom.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockRow {
    pub holder_session_id: String,
    pub acquired_at: i64,
    /// `None` maps to TS `undefined`/SQL `NULL` (lock currently held, not
    /// released).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<i64>,
    pub last_processed_offset: i64,
}

/// Config knobs, mirroring the fields of TS `STORAGE_RECONCILIATION_CONFIG`
/// used by the lock decision (`BATCH_SIZE` is irrelevant to locking).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockConfig {
    pub lock_ttl_ms: i64,
    pub reconciliation_interval_ms: i64,
}

/// Result of `try_acquire`, mirroring TS `StorageReconciliationAcquireResult`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum AcquireResult {
    /// `{ acquired: true, lastProcessedOffset }`.
    Acquired { last_processed_offset: i64 },
    /// `{ acquired: false, reason: "not_due" }` — the interval since the last
    /// release has not elapsed.
    NotDue,
    /// `{ acquired: false, reason: "lock_held" }` — another session holds a
    /// non-expired lock.
    LockHeld,
}

/// Full outcome of a `try_acquire`: the decision plus the row that would be
/// written to storage (`None` when nothing is written — the `not_due` /
/// `lock_held` early returns do not touch the row).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcquireOutcome {
    pub result: AcquireResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub put_row: Option<LockRow>,
}

/// Pure port of `tryAcquireStorageReconciliationLock`'s in-transaction decision.
///
/// `lock_row` is the current stored row for `lock#{peer_id}` (`None` if absent),
/// `session_id` is the session attempting to acquire, `now` is `Date.now()`.
///
/// Mirrors the TS exactly:
/// 1. If a released lock's interval has not elapsed → `NotDue` (no write).
/// 2. Else if a live lock is held by another session and not expired →
///    `LockHeld` (no write).
/// 3. Else acquire: carry the offset forward only from a live lock held (any
///    session) that is not released, otherwise 0; write a fresh row with
///    `acquiredAt = now` and no `releasedAt`.
pub fn try_acquire(
    lock_row: Option<&LockRow>,
    session_id: &str,
    now: i64,
    config: &LockConfig,
) -> AcquireOutcome {
    // if (lockRow?.releasedAt && now - lockRow.releasedAt < INTERVAL) -> not_due
    if let Some(row) = lock_row {
        if let Some(released_at) = row.released_at {
            if now - released_at < config.reconciliation_interval_ms {
                return AcquireOutcome {
                    result: AcquireResult::NotDue,
                    put_row: None,
                };
            }
        }
    }

    // expiresAt = lockRow ? lockRow.acquiredAt + LOCK_TTL_MS : 0
    let expires_at = match lock_row {
        Some(row) => row.acquired_at + config.lock_ttl_ms,
        None => 0,
    };
    // isLockHeldByOtherSession = lockRow?.holderSessionId !== sessionId
    // (when lockRow is None the guard below short-circuits, so this only
    //  matters for a present row.)
    let is_held_by_other_session = match lock_row {
        Some(row) => row.holder_session_id != session_id,
        None => true,
    };

    // if (lockRow && !lockRow.releasedAt && expiresAt >= now && isLockHeldByOtherSession) -> lock_held
    if let Some(row) = lock_row {
        if row.released_at.is_none() && expires_at >= now && is_held_by_other_session {
            return AcquireOutcome {
                result: AcquireResult::LockHeld,
                put_row: None,
            };
        }
    }

    // lastProcessedOffset = (lockRow && !lockRow.releasedAt) ? (lockRow.lastProcessedOffset ?? 0) : 0
    let last_processed_offset = match lock_row {
        Some(row) if row.released_at.is_none() => row.last_processed_offset,
        _ => 0,
    };

    AcquireOutcome {
        result: AcquireResult::Acquired {
            last_processed_offset,
        },
        put_row: Some(LockRow {
            holder_session_id: session_id.to_string(),
            acquired_at: now,
            released_at: None,
            last_processed_offset,
        }),
    }
}

/// Pure port of `renewStorageReconciliationLock`'s decision.
///
/// Returns the row to write, or `None` when the lock is not owned by
/// `session_id` or has been released (a no-op). Only `lastProcessedOffset` is
/// updated; `acquiredAt` and `holderSessionId` are preserved.
pub fn renew(lock_row: Option<&LockRow>, session_id: &str, offset: i64) -> Option<LockRow> {
    match lock_row {
        Some(row) if row.holder_session_id == session_id && row.released_at.is_none() => {
            let mut updated = row.clone();
            updated.last_processed_offset = offset;
            Some(updated)
        }
        _ => None,
    }
}

/// Pure port of `releaseStorageReconciliationLock`'s decision.
///
/// Returns the row to write, or `None` when the lock is held by another session
/// (a no-op). On release, `releasedAt = now` and the offset is reset to 0.
/// Note the TS releases regardless of whether the row was already released, as
/// long as the holder matches.
pub fn release(lock_row: Option<&LockRow>, session_id: &str, now: i64) -> Option<LockRow> {
    match lock_row {
        Some(row) if row.holder_session_id == session_id => {
            let mut updated = row.clone();
            updated.released_at = Some(now);
            updated.last_processed_offset = 0;
            Some(updated)
        }
        _ => None,
    }
}

// =====================================================================
// StorageReconciliationRegistry: merges the ongoing-batch tracker and the
// ack tracker into one in-memory registry.
// =====================================================================

/// Merged port of `OngoingStorageReconciliationTracker` +
/// `StorageReconciliationServerAckTracker`.
///
/// All keys are plain `String`s (peer ids, batch ids, covalue ids) so the
/// module stays self-contained. Ordering is preserved via `IndexMap`/`IndexSet`
/// so completed-batch ordering and ack-firing order match the TypeScript
/// (which iterates JS `Map`/`Set` in insertion order).
#[derive(Debug, Default)]
pub struct StorageReconciliationRegistry {
    // --- ongoing-batch tracker ---
    /// peer → (batchId → pending covalues)
    reconcile_batches: IndexMap<String, IndexMap<String, IndexSet<String>>>,
    /// peer → (covalueId → batchIds referencing it)  [reverse index]
    reconcile_batches_by_covalue: IndexMap<String, IndexMap<String, IndexSet<String>>>,

    // --- ack tracker ---
    /// "batchId#peerId" → nextOffset
    pending_reconciliation_ack: IndexMap<String, i64>,
    /// "batchId#peerId" → outstanding wait ids (insertion order == firing order)
    ack_listeners: IndexMap<String, IndexSet<u64>>,
    /// wait id → its bookkeeping (for handle_ack / peer_close resolution)
    waits: IndexMap<u64, WaitEntry>,
}

#[derive(Debug, Clone)]
struct WaitEntry {
    key: String,
    peer_id: String,
    finished: bool,
}

/// Outcome of `wait_for_ack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The batch was not pending (or had no listener slot): the callback fires
    /// immediately.
    Immediate,
    /// The wait was registered; its callback fires later via `handle_ack`, or
    /// is cancelled via `peer_close`.
    Registered,
}

fn ack_key(batch_id: &str, peer_id: &str) -> String {
    format!("{batch_id}#{peer_id}")
}

impl StorageReconciliationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    // ---------------- ongoing-batch tracker ----------------

    /// Port of `OngoingStorageReconciliationTracker.trackBatch`. Empty batches
    /// are ignored.
    pub fn track_batch(
        &mut self,
        peer_id: &str,
        batch_id: &str,
        pending_covalues: &[String],
    ) {
        if pending_covalues.is_empty() {
            return;
        }

        let batches_for_peer = self
            .reconcile_batches
            .entry(peer_id.to_string())
            .or_default();
        batches_for_peer.insert(
            batch_id.to_string(),
            pending_covalues.iter().cloned().collect(),
        );

        let covalues_to_batches = self
            .reconcile_batches_by_covalue
            .entry(peer_id.to_string())
            .or_default();
        for covalue_id in pending_covalues {
            covalues_to_batches
                .entry(covalue_id.clone())
                .or_default()
                .insert(batch_id.to_string());
        }
    }

    /// Port of `OngoingStorageReconciliationTracker.markItemComplete`. Marks a
    /// covalue reconciled and returns the batch ids that thereby completed (in
    /// insertion order).
    pub fn mark_item_complete(&mut self, peer_id: &str, covalue_id: &str) -> Vec<String> {
        let Some(covalues_to_batches) = self.reconcile_batches_by_covalue.get_mut(peer_id) else {
            return Vec::new();
        };
        let Some(batches_for_peer) = self.reconcile_batches.get_mut(peer_id) else {
            return Vec::new();
        };

        let Some(batch_ids_for_covalue) = covalues_to_batches.get(covalue_id) else {
            return Vec::new();
        };
        if batch_ids_for_covalue.is_empty() {
            return Vec::new();
        }

        // Snapshot the batch ids (insertion order) before mutating.
        let batch_ids: Vec<String> = batch_ids_for_covalue.iter().cloned().collect();

        let mut completed_batch_ids: Vec<String> = Vec::new();
        for batch_id in &batch_ids {
            let Some(batch) = batches_for_peer.get_mut(batch_id) else {
                continue;
            };
            batch.shift_remove(covalue_id);
            if batch.is_empty() {
                completed_batch_ids.push(batch_id.clone());
            }
        }

        covalues_to_batches.shift_remove(covalue_id);
        for batch_id in &completed_batch_ids {
            batches_for_peer.shift_remove(batch_id);
        }

        if covalues_to_batches.is_empty() {
            self.reconcile_batches_by_covalue.shift_remove(peer_id);
        }
        if batches_for_peer.is_empty() {
            self.reconcile_batches.shift_remove(peer_id);
        }

        completed_batch_ids
    }

    /// Port of `OngoingStorageReconciliationTracker.clearPeer`.
    pub fn clear_peer(&mut self, peer_id: &str) {
        self.reconcile_batches.shift_remove(peer_id);
        self.reconcile_batches_by_covalue.shift_remove(peer_id);
    }

    /// Number of peers with tracked ongoing batches (observability for tests).
    pub fn ongoing_peer_count(&self) -> usize {
        self.reconcile_batches.len()
    }

    // ---------------- ack tracker ----------------

    /// Port of `StorageReconciliationServerAckTracker.trackBatch`.
    pub fn track_batch_ack(&mut self, batch_id: &str, peer_id: &str, next_offset: i64) {
        let key = ack_key(batch_id, peer_id);
        self.pending_reconciliation_ack.insert(key.clone(), next_offset);
        self.ack_listeners.entry(key).or_default();
    }

    /// Port of `StorageReconciliationServerAckTracker.handleAck`.
    ///
    /// Clears the pending ack, fires (returns) every still-unfinished wait id
    /// registered for the batch in insertion order, and drops the listener set.
    /// Returns the batch's `nextOffset` if it was pending (mirroring the TS
    /// return value), plus the fired wait ids.
    pub fn handle_ack(&mut self, batch_id: &str, peer_id: &str) -> HandleAckOutcome {
        let key = ack_key(batch_id, peer_id);
        let next_offset = self.pending_reconciliation_ack.shift_remove(&key);

        let mut fired: Vec<u64> = Vec::new();
        if let Some(listeners) = self.ack_listeners.get(&key) {
            let ids: Vec<u64> = listeners.iter().copied().collect();
            for id in ids {
                // onAck -> finish() guards against a wait already resolved by a
                // peer close.
                if let Some(wait) = self.waits.get_mut(&id) {
                    if !wait.finished {
                        wait.finished = true;
                        fired.push(id);
                    }
                }
            }
            self.ack_listeners.shift_remove(&key);
        }

        HandleAckOutcome { next_offset, fired }
    }

    /// Port of `StorageReconciliationServerAckTracker.waitForAck`.
    ///
    /// `wait_id` is a caller-provided listener identity (in TS this is the
    /// closure identity). Returns whether the callback fires immediately.
    pub fn wait_for_ack(&mut self, batch_id: &str, peer_id: &str, wait_id: u64) -> WaitOutcome {
        let key = ack_key(batch_id, peer_id);
        // if (!pending.has(key) || !listeners) -> callback() immediately
        if !self.pending_reconciliation_ack.contains_key(&key)
            || !self.ack_listeners.contains_key(&key)
        {
            return WaitOutcome::Immediate;
        }

        self.ack_listeners
            .get_mut(&key)
            .expect("listener set present")
            .insert(wait_id);
        self.waits.insert(
            wait_id,
            WaitEntry {
                key,
                peer_id: peer_id.to_string(),
                finished: false,
            },
        );
        WaitOutcome::Registered
    }

    /// Port of the peer-close path: every close listener registered by a
    /// `waitForAck` for `peer_id` runs (`peer.gracefulShutdown()` fires them
    /// all). For each still-unfinished wait: remove its listener, delete the
    /// batch's pending ack, and drop the listener set if it becomes empty. The
    /// callback is **never** invoked — the reconciliation for that peer is
    /// interrupted and resumes on reconnect. Returns the cancelled wait ids.
    pub fn peer_close(&mut self, peer_id: &str) -> Vec<u64> {
        let target_ids: Vec<u64> = self
            .waits
            .iter()
            .filter(|(_, w)| w.peer_id == peer_id && !w.finished)
            .map(|(id, _)| *id)
            .collect();

        let mut cancelled: Vec<u64> = Vec::new();
        for id in target_ids {
            let key = {
                let wait = self.waits.get_mut(&id).expect("wait present");
                wait.finished = true;
                wait.key.clone()
            };
            if let Some(listeners) = self.ack_listeners.get_mut(&key) {
                listeners.shift_remove(&id);
                if listeners.is_empty() {
                    self.ack_listeners.shift_remove(&key);
                }
            }
            self.pending_reconciliation_ack.shift_remove(&key);
            cancelled.push(id);
        }
        cancelled
    }

    /// Snapshot of pending acks as sorted `(key, offset)` pairs (observability).
    pub fn pending_ack_snapshot(&self) -> Vec<(String, i64)> {
        let mut out: Vec<(String, i64)> = self
            .pending_reconciliation_ack
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        out.sort();
        out
    }
}

/// Return of `handle_ack`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleAckOutcome {
    /// The batch's pending `nextOffset`, if it was pending.
    pub next_offset: Option<i64>,
    /// Wait ids whose callbacks fire, in firing order.
    pub fired: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ---------------- unit tests: lock decision ----------------

    const CFG: LockConfig = LockConfig {
        lock_ttl_ms: 24 * 60 * 60 * 1000,
        reconciliation_interval_ms: 30 * 24 * 60 * 60 * 1000,
    };

    #[test]
    fn acquire_when_no_row() {
        let out = try_acquire(None, "s1", 1000, &CFG);
        assert_eq!(
            out.result,
            AcquireResult::Acquired {
                last_processed_offset: 0
            }
        );
        let row = out.put_row.unwrap();
        assert_eq!(row.holder_session_id, "s1");
        assert_eq!(row.acquired_at, 1000);
        assert_eq!(row.released_at, None);
        assert_eq!(row.last_processed_offset, 0);
    }

    #[test]
    fn not_due_within_interval() {
        let row = LockRow {
            holder_session_id: "other".into(),
            acquired_at: 0,
            released_at: Some(500),
            last_processed_offset: 7,
        };
        let out = try_acquire(Some(&row), "s1", 500 + 1000, &CFG);
        assert_eq!(out.result, AcquireResult::NotDue);
        assert_eq!(out.put_row, None);
    }

    #[test]
    fn due_after_interval_reacquires_with_zero_offset() {
        let row = LockRow {
            holder_session_id: "other".into(),
            acquired_at: 0,
            released_at: Some(500),
            last_processed_offset: 7,
        };
        // now - releasedAt >= interval -> passes the not_due gate; released so
        // offset resets to 0.
        let now = 500 + CFG.reconciliation_interval_ms;
        let out = try_acquire(Some(&row), "s1", now, &CFG);
        assert_eq!(
            out.result,
            AcquireResult::Acquired {
                last_processed_offset: 0
            }
        );
    }

    #[test]
    fn lock_held_by_other_non_expired() {
        let row = LockRow {
            holder_session_id: "other".into(),
            acquired_at: 1000,
            released_at: None,
            last_processed_offset: 3,
        };
        // expiresAt = 1000 + TTL >= now, held by other -> lock_held
        let out = try_acquire(Some(&row), "s1", 2000, &CFG);
        assert_eq!(out.result, AcquireResult::LockHeld);
        assert_eq!(out.put_row, None);
    }

    #[test]
    fn expired_lock_of_other_can_be_taken_over() {
        let row = LockRow {
            holder_session_id: "other".into(),
            acquired_at: 1000,
            released_at: None,
            last_processed_offset: 3,
        };
        // now > acquiredAt + TTL -> expired -> acquire; not released so offset
        // carried forward.
        let now = 1000 + CFG.lock_ttl_ms + 1;
        let out = try_acquire(Some(&row), "s1", now, &CFG);
        assert_eq!(
            out.result,
            AcquireResult::Acquired {
                last_processed_offset: 3
            }
        );
    }

    #[test]
    fn same_session_reacquire_carries_offset() {
        let row = LockRow {
            holder_session_id: "s1".into(),
            acquired_at: 1000,
            released_at: None,
            last_processed_offset: 42,
        };
        // held by same session -> not lock_held; offset carried.
        let out = try_acquire(Some(&row), "s1", 2000, &CFG);
        assert_eq!(
            out.result,
            AcquireResult::Acquired {
                last_processed_offset: 42
            }
        );
    }

    #[test]
    fn renew_only_when_owned_and_live() {
        let row = LockRow {
            holder_session_id: "s1".into(),
            acquired_at: 1000,
            released_at: None,
            last_processed_offset: 1,
        };
        assert_eq!(renew(Some(&row), "s1", 99).unwrap().last_processed_offset, 99);
        assert_eq!(renew(Some(&row), "other", 99), None);
        let released = LockRow {
            released_at: Some(5),
            ..row.clone()
        };
        assert_eq!(renew(Some(&released), "s1", 99), None);
        assert_eq!(renew(None, "s1", 99), None);
    }

    #[test]
    fn release_only_when_owned() {
        let row = LockRow {
            holder_session_id: "s1".into(),
            acquired_at: 1000,
            released_at: None,
            last_processed_offset: 8,
        };
        let released = release(Some(&row), "s1", 7000).unwrap();
        assert_eq!(released.released_at, Some(7000));
        assert_eq!(released.last_processed_offset, 0);
        assert_eq!(release(Some(&row), "other", 7000), None);
        assert_eq!(release(None, "s1", 7000), None);
    }

    // ---------------- unit tests: registry ----------------

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn ongoing_completes_batch_only_when_all_done() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch("peer-1", "batch-1", &s(&["co_A", "co_B"]));
        assert_eq!(r.mark_item_complete("peer-1", "co_A"), Vec::<String>::new());
        assert_eq!(r.mark_item_complete("peer-1", "co_B"), vec!["batch-1"]);
        assert_eq!(r.ongoing_peer_count(), 0);
    }

    #[test]
    fn ongoing_multi_batch_covalue() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch("peer-1", "batch-1", &s(&["co_A"]));
        r.track_batch("peer-1", "batch-2", &s(&["co_A", "co_B"]));
        r.track_batch("peer-1", "batch-3", &s(&["co_B"]));
        assert_eq!(r.mark_item_complete("peer-1", "co_A"), vec!["batch-1"]);
        assert_eq!(
            r.mark_item_complete("peer-1", "co_B"),
            vec!["batch-2", "batch-3"]
        );
        assert_eq!(r.ongoing_peer_count(), 0);
    }

    #[test]
    fn ongoing_ignores_empty_batches() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch("peer-1", "batch-1", &[]);
        assert_eq!(r.ongoing_peer_count(), 0);
    }

    #[test]
    fn ongoing_clear_peer_isolated() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch("peer-1", "batch-A", &s(&["co_A"]));
        r.track_batch("peer-2", "batch-B", &s(&["co_B"]));
        r.clear_peer("peer-1");
        assert_eq!(r.mark_item_complete("peer-1", "co_A"), Vec::<String>::new());
        assert_eq!(r.mark_item_complete("peer-2", "co_B"), vec!["batch-B"]);
    }

    #[test]
    fn ack_fires_on_handle() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch_ack("batch-1", "peer-1", 50);
        assert_eq!(r.wait_for_ack("batch-1", "peer-1", 1), WaitOutcome::Registered);
        let out = r.handle_ack("batch-1", "peer-1");
        assert_eq!(out.next_offset, Some(50));
        assert_eq!(out.fired, vec![1]);
    }

    #[test]
    fn ack_immediate_when_not_pending() {
        let mut r = StorageReconciliationRegistry::new();
        assert_eq!(
            r.wait_for_ack("missing", "peer-1", 1),
            WaitOutcome::Immediate
        );
    }

    #[test]
    fn ack_all_listeners_fire() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch_ack("batch-1", "peer-1", 50);
        r.wait_for_ack("batch-1", "peer-1", 1);
        r.wait_for_ack("batch-1", "peer-1", 2);
        assert_eq!(r.handle_ack("batch-1", "peer-1").fired, vec![1, 2]);
    }

    #[test]
    fn ack_peer_close_cancels_and_clears() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch_ack("batch-1", "peer-1", 50);
        r.wait_for_ack("batch-1", "peer-1", 1);
        assert_eq!(r.peer_close("peer-1"), vec![1]);
        assert!(r.pending_ack_snapshot().is_empty());
        // a subsequent ack fires nothing
        assert_eq!(r.handle_ack("batch-1", "peer-1").fired, Vec::<u64>::new());
    }

    #[test]
    fn ack_only_once_when_close_after_ack() {
        let mut r = StorageReconciliationRegistry::new();
        r.track_batch_ack("batch-1", "peer-1", 50);
        r.wait_for_ack("batch-1", "peer-1", 1);
        assert_eq!(r.handle_ack("batch-1", "peer-1").fired, vec![1]);
        // close after ack -> nothing cancelled (already finished)
        assert_eq!(r.peer_close("peer-1"), Vec::<u64>::new());
    }

    // ---------------- fixture replay ----------------
    //
    // Fixtures are exported from the REAL current TypeScript by the
    // storageReconciliation*Fixtures.export.test.ts suites. Each replay reads
    // the committed JSON and reproduces every field byte-for-byte.

    fn read_fixtures(dir: &str) -> Vec<(String, String)> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap_or_else(|_| panic!("{dir} must exist (run the TS exporter)"))
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        assert!(!names.is_empty(), "expected at least one fixture in {dir}");
        names
            .into_iter()
            .map(|n| {
                let raw = fs::read_to_string(format!("{dir}/{n}"))
                    .unwrap_or_else(|_| panic!("cannot read {dir}/{n}"));
                (n, raw)
            })
            .collect()
    }

    // --- lock decision fixtures ---

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LockFixture {
        #[allow(dead_code)]
        description: String,
        op: String,
        /// stored lock row BEFORE the op (`None` == no row).
        seed_row: Option<LockRow>,
        session_id: String,
        now: i64,
        offset: Option<i64>,
        config: LockConfig,
        expected: LockExpected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LockExpected {
        /// present only for `acquire`: the TS `StorageReconciliationAcquireResult`.
        acquire_result: Option<serde_json::Value>,
        /// stored lock row AFTER the op (`None` == no row / unchanged-absent).
        result_row: Option<LockRow>,
    }

    #[test]
    fn replay_lock_fixtures() {
        for (name, raw) in read_fixtures("data/storage_reconciliation_lock") {
            let f: LockFixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            // Apply the decision to the seed to derive the resulting stored row,
            // then compare to the row the REAL TS produced.
            let result_row: Option<LockRow> = match f.op.as_str() {
                "acquire" => {
                    let out = try_acquire(f.seed_row.as_ref(), &f.session_id, f.now, &f.config);
                    assert_eq!(
                        acquire_result_to_ts(&out.result),
                        f.expected.acquire_result.expect("acquire fixtures have result"),
                        "acquire result mismatch in {name}"
                    );
                    out.put_row.or(f.seed_row.clone())
                }
                "renew" => {
                    renew(f.seed_row.as_ref(), &f.session_id, f.offset.expect("renew offset"))
                        .or(f.seed_row.clone())
                }
                "release" => {
                    release(f.seed_row.as_ref(), &f.session_id, f.now).or(f.seed_row.clone())
                }
                other => panic!("unknown lock op {other} in {name}"),
            };
            assert_eq!(
                result_row, f.expected.result_row,
                "result_row mismatch in {name}"
            );
        }
    }

    /// Render an `AcquireResult` as the exact TS `StorageReconciliationAcquireResult`
    /// JSON object so fixtures can compare against the real TS return value.
    fn acquire_result_to_ts(result: &AcquireResult) -> serde_json::Value {
        match result {
            AcquireResult::Acquired {
                last_processed_offset,
            } => serde_json::json!({
                "acquired": true,
                "lastProcessedOffset": last_processed_offset,
            }),
            AcquireResult::NotDue => serde_json::json!({
                "acquired": false,
                "reason": "not_due",
            }),
            AcquireResult::LockHeld => serde_json::json!({
                "acquired": false,
                "reason": "lock_held",
            }),
        }
    }

    // --- ongoing-tracker fixtures ---

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OngoingFixture {
        #[allow(dead_code)]
        description: String,
        ops: Vec<OngoingOp>,
        expected: OngoingExpected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OngoingOp {
        op: String,
        peer_id: String,
        batch_id: Option<String>,
        pending: Option<Vec<String>>,
        covalue_id: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OngoingExpected {
        /// aligned with `ops`: `markItemComplete` results, `null` otherwise.
        results: Vec<Option<Vec<String>>>,
        ongoing_peer_count: usize,
    }

    #[test]
    fn replay_ongoing_fixtures() {
        for (name, raw) in read_fixtures("data/storage_reconciliation_ongoing") {
            let f: OngoingFixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            let mut r = StorageReconciliationRegistry::new();
            let mut results: Vec<Option<Vec<String>>> = Vec::new();
            for op in &f.ops {
                match op.op.as_str() {
                    "trackBatch" => {
                        r.track_batch(
                            &op.peer_id,
                            op.batch_id.as_deref().expect("batchId"),
                            op.pending.as_deref().expect("pending"),
                        );
                        results.push(None);
                    }
                    "markItemComplete" => {
                        let res = r.mark_item_complete(
                            &op.peer_id,
                            op.covalue_id.as_deref().expect("covalueId"),
                        );
                        results.push(Some(res));
                    }
                    "clearPeer" => {
                        r.clear_peer(&op.peer_id);
                        results.push(None);
                    }
                    other => panic!("unknown ongoing op {other} in {name}"),
                }
            }
            assert_eq!(results, f.expected.results, "results mismatch in {name}");
            assert_eq!(
                r.ongoing_peer_count(),
                f.expected.ongoing_peer_count,
                "ongoing_peer_count mismatch in {name}"
            );
        }
    }

    // --- ack-tracker fixtures ---

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AckFixture {
        #[allow(dead_code)]
        description: String,
        ops: Vec<AckOp>,
        expected: AckExpected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AckOp {
        op: String,
        batch_id: Option<String>,
        peer_id: String,
        next_offset: Option<i64>,
        wait_id: Option<u64>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AckExpected {
        /// ordered event log, e.g. "immediate:1", "ack:2", "cancel:3", "offset:50".
        event_log: Vec<String>,
        pending: Vec<(String, i64)>,
    }

    #[test]
    fn replay_ack_fixtures() {
        for (name, raw) in read_fixtures("data/storage_reconciliation_ack") {
            let f: AckFixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}: {e}"));
            let mut r = StorageReconciliationRegistry::new();
            let mut event_log: Vec<String> = Vec::new();
            for op in &f.ops {
                match op.op.as_str() {
                    "trackBatch" => {
                        r.track_batch_ack(
                            op.batch_id.as_deref().expect("batchId"),
                            &op.peer_id,
                            op.next_offset.expect("nextOffset"),
                        );
                    }
                    "waitForAck" => {
                        let wait_id = op.wait_id.expect("waitId");
                        let outcome = r.wait_for_ack(
                            op.batch_id.as_deref().expect("batchId"),
                            &op.peer_id,
                            wait_id,
                        );
                        if outcome == WaitOutcome::Immediate {
                            event_log.push(format!("immediate:{wait_id}"));
                        }
                    }
                    "handleAck" => {
                        let out = r.handle_ack(
                            op.batch_id.as_deref().expect("batchId"),
                            &op.peer_id,
                        );
                        if let Some(offset) = out.next_offset {
                            event_log.push(format!("offset:{offset}"));
                        }
                        for id in out.fired {
                            event_log.push(format!("ack:{id}"));
                        }
                    }
                    "peerClose" => {
                        for id in r.peer_close(&op.peer_id) {
                            event_log.push(format!("cancel:{id}"));
                        }
                    }
                    other => panic!("unknown ack op {other} in {name}"),
                }
            }
            assert_eq!(event_log, f.expected.event_log, "event_log mismatch in {name}");
            assert_eq!(
                r.pending_ack_snapshot(),
                f.expected.pending,
                "pending mismatch in {name}"
            );
        }
    }
}
