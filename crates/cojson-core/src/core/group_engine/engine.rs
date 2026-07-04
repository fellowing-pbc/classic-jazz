//! Group validation and read-side role resolution over the `NodeCore` registry.
//!
//! This is the Rust port of cojson's permission engine. Two TypeScript
//! algorithms are fused here, exactly as the spec mandates, because they share
//! one accumulation pass:
//!
//! - **Validation** — `determineValidTransactions` /
//!   `determineValidTransactionsForGroup` (`packages/cojson/src/permissions.ts`):
//!   walks a CoValue's transactions in validation order and produces a
//!   [`Verdict`] (valid flag + verbatim TS reason) for every one of them.
//! - **Read-side role resolution** — `RawGroup.roleOfInternal` /
//!   `RawAccount.roleOfInternal` (`packages/cojson/src/coValues/group.ts`,
//!   `account.ts`): answers "what role does `member` have in this group at
//!   time `t`", following time-based parent inheritance.
//!
//! Two role structures are kept, and they are deliberately different (spec:
//! "TWO role structures"):
//!
//! - The **validation-order plain map** ([`ResolverState::member_roles`]) mirrors
//!   `MemberRoleResolver.memberRoles`. Direct-role lookups here IGNORE time
//!   (`permissions.ts:207-212`); only the parent walk is time-based.
//! - The **time-indexed histories** ([`GroupEngineState::role_history`],
//!   [`GroupEngineState::parent_history`]) mirror the CoMap content /
//!   `parentGroupsChanges` that `roleOfInternal` reads, and are built from
//!   VALIDATED set-role / parent ops only.
//!
//! Builds are always FULL RECOMPUTE (never incremental); a built
//! [`GroupEngineState`] is cached per CoValue and reused only while its
//! per-session transaction counts are unchanged.
//!
//! ## Borrow strategy
//!
//! Recursive engine builds walk from a child group into its parents, and a
//! build must both read many session maps (immutably) and store the engines it
//! computes (mutably). To keep those two borrows disjoint, the engine store
//! lives in a `HashMap<String, GroupEngineState>` that is a SEPARATE field of
//! `NodeCore` from the `covalues: HashMap<String, SessionMapImpl>` map. The
//! algorithms are free functions taking `(&covalues, &mut engines)`, so a
//! `NodeCore` method destructures `self` into its two fields and passes disjoint
//! borrows in. No session map is ever cloned. A single `visited` set guards
//! against build/read re-entrancy on cyclic data (impossible for valid data,
//! since `isSelfExtension` rejects cycles at validation time, but guarded
//! anyway).

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;

use crate::core::group_engine::classify::{
    account_or_agent_from_write_key_for_member, is_child_extension, is_key_for_account_field,
    is_key_for_key_field, is_key_sealed_for_group_field, is_own_write_key_revelation,
    is_parent_extension, is_write_key_for_member, parent_group_id_from_key,
};
use crate::core::group_engine::tx_view::{collect_group_txs, sort_for_validation, PendingTxIn, Privacy};
use crate::core::group_engine::types::{
    is_higher_role, is_more_permissive_and_should_inherit, ParentRoleMapping, Role, TimeBasedEntry,
};
use crate::core::session_map::{CoValueHeader, JsonValue, RulesetDef, SessionMapError, SessionMapImpl};

/// The `"everyone"` pseudo-member key (`EVERYONE`, group.ts:49).
const EVERYONE: &str = "everyone";

/// A per-transaction validation verdict, in validation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub session_id: String,
    pub tx_index: u32,
    pub valid: bool,
    /// Verbatim TS reason string when invalid; `None` when valid.
    pub reason: Option<String>,
}

/// The ruleset kind of a CoValue header, plus the facts the engine needs.
enum RulesetKind {
    Group,
    OwnedByGroup(String),
    UnsafeAllowAll,
}

/// Built by one full validation pass; cached per CoValue keyed by session
/// tx-counts.
pub struct GroupEngineState {
    /// `(session_id, tx_count)` snapshot at build time — the cache-validity key.
    pub session_counts: Vec<(String, u32)>,
    pub verdicts: Vec<Verdict>,
    /// READ state (time-indexed), built from VALIDATED set-role ops only:
    /// member -> role over time (`madeAt` = effective made-at of the op).
    pub role_history: HashMap<String, TimeBasedEntry<Role>>,
    /// parent coId -> mapping over time. `IndexMap` (not the plain `HashMap`
    /// the task sketch shows) so the parent walk iterates in first-appearance
    /// order, matching TS `parentGroupsChanges` Map iteration.
    pub parent_history: IndexMap<String, TimeBasedEntry<ParentRoleMapping>>,
    /// Header ruleset `initialAdmin` (the static agent id for accounts).
    pub initial_admin: Option<String>,
    /// Header `meta.type == "account"` — mirrors `CoValueCore.isGroup()`
    /// distinguishing accounts from plain groups.
    pub is_account: bool,
}

/// Function-local validation state (NOT stored) — mirrors `MemberRoleResolver`
/// being rebuilt per `determineValidTransactionsForGroup` call.
struct ResolverState {
    /// Plain, time-ignoring direct roles (permissions.ts:184-185).
    member_roles: HashMap<String, Role>,
    /// Current non-revoked parent mappings in validation order
    /// (`MemberRoleResolver.parentGroups`); `IndexMap` preserves the TS Map's
    /// insertion order for the parent walk.
    parent_groups: IndexMap<String, ParentRoleMapping>,
    /// member -> KeyID recorded from `writeKeyFor_` ops (last write wins).
    write_only_keys: HashMap<String, String>,
    /// The set of `writeKeyFor_` change keys already seen.
    write_keys: HashSet<String>,
}

impl ResolverState {
    fn new() -> Self {
        ResolverState {
            member_roles: HashMap::new(),
            parent_groups: IndexMap::new(),
            write_only_keys: HashMap::new(),
            write_keys: HashSet::new(),
        }
    }
}

// =====================================================================
// Header facts
// =====================================================================

fn ruleset_kind(header: &CoValueHeader) -> RulesetKind {
    match &header.ruleset {
        RulesetDef::Group(_) => RulesetKind::Group,
        RulesetDef::OwnedByGroup(o) => RulesetKind::OwnedByGroup(o.group.clone()),
        RulesetDef::UnsafeAllowAll(_) => RulesetKind::UnsafeAllowAll,
    }
}

fn initial_admin_of(header: &CoValueHeader) -> Option<String> {
    match &header.ruleset {
        RulesetDef::Group(g) => Some(g.initial_admin.clone()),
        _ => None,
    }
}

/// `header.meta?.type === "account"`.
fn header_meta_is_account(header: &CoValueHeader) -> bool {
    match &header.meta {
        Some(JsonValue::Object(obj)) => {
            matches!(obj.get("type"), Some(JsonValue::String(s)) if s == "account")
        }
        _ => false,
    }
}

/// `CoValueCore.isGroup()` — ruleset is `group` AND not an account
/// (coValueCore.ts:1758-1772).
fn header_is_group(header: &CoValueHeader) -> bool {
    matches!(header.ruleset, RulesetDef::Group(_)) && !header_meta_is_account(header)
}

/// Snapshot of `(session_id, tx_count)` in session-insertion order.
fn session_counts_of(sm: &SessionMapImpl) -> Vec<(String, u32)> {
    sm.get_session_ids()
        .into_iter()
        .map(|sid| {
            let count = sm.get_transaction_count(&sid).unwrap_or(0);
            (sid, count)
        })
        .collect()
}

// =====================================================================
// Change parsing helpers
// =====================================================================

fn change_op(change: &serde_json::Value) -> Option<&str> {
    change.get("op").and_then(|v| v.as_str())
}

fn change_key(change: &serde_json::Value) -> &str {
    change.get("key").and_then(|v| v.as_str()).unwrap_or("")
}

fn change_value_str(change: &serde_json::Value) -> Option<&str> {
    change.get("value").and_then(|v| v.as_str())
}

/// Parse a `parent_<id>` change value into a [`ParentRoleMapping`].
/// `"extend"`/`"revoked"`/a capped role string. Unrecognized values (never
/// produced by real cojson) yield `None` and are dropped from the read/resolver
/// state while the transaction still validates — see the deviation note in the
/// parent-extension branch.
fn parse_parent_mapping(value: Option<&str>) -> Option<ParentRoleMapping> {
    match value {
        Some("extend") => Some(ParentRoleMapping::Extend),
        Some("revoked") => Some(ParentRoleMapping::Revoked),
        Some(other) => Role::parse(other).map(ParentRoleMapping::Capped),
        None => None,
    }
}

/// Every string the validator accepts as a role value (permissions.ts:424-436).
fn is_valid_role_value(v: Option<&str>) -> bool {
    matches!(
        v,
        Some(
            "admin"
                | "manager"
                | "writer"
                | "reader"
                | "writeOnly"
                | "revoked"
                | "managerInvite"
                | "adminInvite"
                | "writerInvite"
                | "readerInvite"
                | "writeOnlyInvite"
        )
    )
}

// =====================================================================
// Engine freshness / build entry point
// =====================================================================

/// Rebuild `co_id`'s engine into `engines` iff its per-session tx-counts changed
/// since the last build (full recompute). No-op when a fresh engine exists or
/// when `co_id` is already mid-build (`visited` guard, cyclic data only).
fn ensure_engine(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_id: &str,
    pending: &[PendingTxIn],
    visited: &mut HashSet<String>,
) -> Result<(), SessionMapError> {
    let sm = covalues
        .get(co_id)
        .ok_or_else(|| SessionMapError::CoValueNotLoaded(co_id.to_string()))?;

    if let Some(existing) = engines.get(co_id) {
        if existing.session_counts == session_counts_of(sm) {
            return Ok(());
        }
    }

    // Re-entrant build (only reachable on cyclic parent graphs, which valid data
    // never forms): leave the engine absent; readers treat a missing engine as
    // "no roles", breaking the cycle.
    if visited.contains(co_id) {
        return Ok(());
    }

    visited.insert(co_id.to_string());
    let state = build_group_engine(covalues, engines, co_id, pending, visited);
    visited.remove(co_id);
    let state = state?;
    engines.insert(co_id.to_string(), state);
    Ok(())
}

/// Full recompute of one CoValue's engine. Dispatches on ruleset type exactly as
/// `determineValidTransactions` (permissions.ts:73-169) does.
pub fn build_group_engine(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_id: &str,
    pending: &[PendingTxIn],
    visited: &mut HashSet<String>,
) -> Result<GroupEngineState, SessionMapError> {
    let sm = covalues
        .get(co_id)
        .ok_or_else(|| SessionMapError::CoValueNotLoaded(co_id.to_string()))?;
    let header = sm.header();
    let kind = ruleset_kind(header);
    let initial_admin = initial_admin_of(header);
    let is_account = header_meta_is_account(header);
    let session_counts = session_counts_of(sm);

    let mut state = GroupEngineState {
        session_counts,
        verdicts: Vec::new(),
        role_history: HashMap::new(),
        parent_history: IndexMap::new(),
        initial_admin: initial_admin.clone(),
        is_account,
    };

    match kind {
        RulesetKind::Group => {
            build_group_ruleset(
                covalues,
                engines,
                co_id,
                &mut state,
                sm,
                initial_admin,
                is_account,
                pending,
                visited,
            )?;
        }
        RulesetKind::OwnedByGroup(group_id) => {
            build_owned_by_group(
                covalues,
                engines,
                &mut state,
                sm,
                &group_id,
                pending,
                visited,
            )?;
        }
        RulesetKind::UnsafeAllowAll => {
            // permissions.ts:157-163 — every transaction is valid.
            let mut txs = collect_group_txs(sm, pending);
            sort_for_validation(&mut txs);
            for tx in &txs {
                state.verdicts.push(Verdict {
                    session_id: tx.session_id.clone(),
                    tx_index: tx.tx_index,
                    valid: true,
                    reason: None,
                });
            }
        }
    }

    Ok(state)
}

// =====================================================================
// Group ruleset validation (determineValidTransactionsForGroup)
// =====================================================================

#[allow(clippy::too_many_arguments)]
fn build_group_ruleset(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_id: &str,
    state: &mut GroupEngineState,
    sm: &SessionMapImpl,
    initial_admin: Option<String>,
    is_account: bool,
    pending: &[PendingTxIn],
    visited: &mut HashSet<String>,
) -> Result<(), SessionMapError> {
    let mut txs = collect_group_txs(sm, pending);
    sort_for_validation(&mut txs);

    // `coValue.isGroup()` — a plain group (not an account).
    let is_group = !is_account;
    let initial_admin = initial_admin.unwrap_or_default();

    let mut resolver = ResolverState::new();

    for tx in &txs {
        let transactor = tx.author.clone();
        let made_at = tx.current_made_at;
        let effective = tx.effective_made_at;

        let transactor_role =
            resolver_role_at(covalues, engines, &resolver, &transactor, made_at, visited)?;

        macro_rules! verdict {
            (valid) => {{
                state.verdicts.push(Verdict {
                    session_id: tx.session_id.clone(),
                    tx_index: tx.tx_index,
                    valid: true,
                    reason: None,
                });
            }};
            (invalid $reason:expr) => {{
                state.verdicts.push(Verdict {
                    session_id: tx.session_id.clone(),
                    tx_index: tx.tx_index,
                    valid: false,
                    reason: Some($reason.to_string()),
                });
            }};
        }

        // --- privacy branch (permissions.ts:250-265) ---
        if tx.privacy == Privacy::Private {
            if is_group {
                verdict!(invalid "Can't make private transactions in groups");
            } else if transactor_role == Some(Role::Admin) {
                verdict!(valid);
            } else {
                verdict!(invalid "Only admins can make private transactions in groups");
            }
            continue;
        }

        // `if (!changes) continue;` (permissions.ts:269-271). Only reachable for
        // a trusting tx whose changes failed to parse (never produced by cojson);
        // no verdict is emitted, matching TS leaving the tx in its prior state.
        let changes = match &tx.changes {
            Some(c) => c,
            None => continue,
        };

        // `change = changes[0]` is read before the length check in TS, but only
        // used afterwards (permissions.ts:273-285).
        if changes.len() != 1 {
            verdict!(invalid "Group transaction must have exactly one change");
            continue;
        }
        let change = &changes[0];

        if change_op(change) != Some("set") {
            verdict!(invalid "Group transaction must set a role or readKey");
            continue;
        }

        let key = change_key(change);

        // --- fixed-key admin-only fields (permissions.ts:292-323) ---
        if key == "readKey" {
            if !Role::can_admin(transactor_role) {
                verdict!(invalid "Only admins can set readKeys");
                continue;
            }
            verdict!(valid);
            continue;
        } else if key == "groupSealer" {
            if !Role::can_admin(transactor_role) {
                verdict!(invalid "Only admins can set groupSealer");
                continue;
            }
            verdict!(valid);
            continue;
        } else if key == "profile" {
            if !Role::can_admin(transactor_role) {
                verdict!(invalid "Only admins can set profile");
                continue;
            }
            verdict!(valid);
            continue;
        } else if key == "root" {
            if !Role::can_admin(transactor_role) {
                verdict!(invalid "Only admins can set root");
                continue;
            }
            verdict!(valid);
            continue;
        } else if is_key_for_key_field(key)
            || is_key_for_account_field(key)
            || is_key_sealed_for_group_field(key)
        {
            // key revelation (permissions.ts:324-344): admins, managers and any
            // invite may reveal; anyone else only their own write key.
            let allowed = matches!(
                transactor_role,
                Some(Role::Admin)
                    | Some(Role::AdminInvite)
                    | Some(Role::Manager)
                    | Some(Role::ManagerInvite)
                    | Some(Role::WriterInvite)
                    | Some(Role::ReaderInvite)
                    | Some(Role::WriteOnlyInvite)
            );
            if !allowed && !is_own_write_key_revelation(key, &transactor, &resolver.write_only_keys)
            {
                verdict!(invalid "Only admins and managers can reveal keys");
                continue;
            }
            verdict!(valid);
            continue;
        } else if is_parent_extension(key) {
            // parent extension (permissions.ts:345-381)
            if !Role::can_admin(transactor_role) {
                verdict!(invalid "Only admins and managers can set parent extensions");
                continue;
            }

            let parent_group_id = parent_group_id_from_key(key).to_string();

            // `expectCoValueLoaded` throwing -> CoValueNotLoaded.
            let parent_sm = covalues
                .get(&parent_group_id)
                .ok_or_else(|| SessionMapError::CoValueNotLoaded(parent_group_id.clone()))?;

            if !header_is_group(parent_sm.header()) {
                verdict!(invalid "Parent group is not a group");
                continue;
            }

            if is_self_extension(covalues, engines, co_id, &parent_group_id, visited)? {
                verdict!(invalid "Parent group is a circular dependency");
                continue;
            }

            // The change value is NOT validated in TS; unrecognized values are
            // stored verbatim. This port drops values it can't map to a
            // `ParentRoleMapping` (extend / revoked / capped role) from both the
            // resolver and the read history, but still marks the tx valid —
            // behaviorally identical for every value real cojson produces.
            match parse_parent_mapping(change_value_str(change)) {
                Some(ParentRoleMapping::Revoked) => {
                    resolver.parent_groups.shift_remove(&parent_group_id);
                    state
                        .parent_history
                        .entry(parent_group_id.clone())
                        .or_default()
                        .add_change(effective, ParentRoleMapping::Revoked);
                }
                Some(mapping) => {
                    resolver.parent_groups.insert(parent_group_id.clone(), mapping);
                    state
                        .parent_history
                        .entry(parent_group_id.clone())
                        .or_default()
                        .add_change(effective, mapping);
                }
                None => {}
            }

            verdict!(valid);
            continue;
        } else if is_child_extension(key) {
            verdict!(invalid "Child extensions are not allowed anymore");
            continue;
        } else if is_write_key_for_member(key) {
            // writeKeyFor_ (permissions.ts:385-418)
            let member_key = account_or_agent_from_write_key_for_member(key).to_string();

            let first_check_fails = transactor_role != Some(Role::Admin)
                && transactor_role != Some(Role::Manager)
                && transactor_role != Some(Role::WriteOnlyInvite)
                && member_key != transactor;
            if first_check_fails {
                verdict!(invalid "Only admins and managers can set writeKeys");
                continue;
            }

            // Assigned on EVERY writeKeyFor_ tx that passes the first check,
            // BEFORE the override check — even for txs the override check then
            // rejects (porter note 6).
            if let Some(v) = change_value_str(change) {
                resolver
                    .write_only_keys
                    .insert(member_key.clone(), v.to_string());
            }

            if resolver.write_keys.contains(key) && !Role::can_admin(transactor_role) {
                verdict!(invalid "Write key already exists and can't be overridden by invite");
                continue;
            }

            resolver.write_keys.insert(key.to_string());
            verdict!(valid);
            continue;
        }

        // --- role assignment (permissions.ts:421-570) ---
        let affected_member = key.to_string();
        let assigned_role_str = change_value_str(change);

        if !is_valid_role_value(assigned_role_str) {
            verdict!(invalid "Group transaction must set a valid role");
            continue;
        }
        let assigned_role = Role::parse(assigned_role_str.unwrap()).unwrap();

        if affected_member == EVERYONE
            && !matches!(
                assigned_role,
                Role::Reader | Role::Writer | Role::WriteOnly | Role::Revoked
            )
        {
            verdict!(invalid "Everyone can only be set to reader, writer, writeOnly or revoked");
            continue;
        }

        // is first self promotion to admin (permissions.ts:468-476)
        if transactor_role.is_none()
            && transactor == initial_admin
            && affected_member == transactor
            && assigned_role == Role::Admin
        {
            resolver.member_roles.insert(affected_member.clone(), assigned_role);
            state
                .role_history
                .entry(affected_member.clone())
                .or_default()
                .add_change(effective, assigned_role);
            verdict!(valid);
            continue;
        }

        // self revoke is always valid (permissions.ts:478-482)
        if transactor == affected_member && assigned_role == Role::Revoked {
            resolver.member_roles.insert(affected_member.clone(), assigned_role);
            state
                .role_history
                .entry(affected_member.clone())
                .or_default()
                .add_change(effective, assigned_role);
            verdict!(valid);
            continue;
        }

        let affected_member_role = resolver_role_at(
            covalues,
            engines,
            &resolver,
            &affected_member,
            made_at,
            visited,
        )?;

        // admins (permissions.ts:493-505)
        if transactor_role == Some(Role::Admin) {
            if affected_member_role == Some(Role::Admin)
                && assigned_role != Role::Admin
                && affected_member != transactor
            {
                verdict!(invalid "Admins can't demote admins.");
                continue;
            }
            resolver.member_roles.insert(affected_member.clone(), assigned_role);
            state
                .role_history
                .entry(affected_member.clone())
                .or_default()
                .add_change(effective, assigned_role);
            verdict!(valid);
            continue;
        }

        // managers (permissions.ts:513-534)
        if transactor_role == Some(Role::Manager) {
            if affected_member_role == Some(Role::Admin) {
                verdict!(invalid "Managers can't demote admins.");
                continue;
            }
            if assigned_role == Role::Admin {
                verdict!(invalid "Managers can't promote to admin.");
                continue;
            }
            if assigned_role == Role::AdminInvite {
                verdict!(invalid "Managers can't invite admins.");
                continue;
            }
            if assigned_role == Role::ManagerInvite {
                verdict!(invalid "Managers can't invite managers.");
                continue;
            }
            resolver.member_roles.insert(affected_member.clone(), assigned_role);
            state
                .role_history
                .entry(affected_member.clone())
                .or_default()
                .add_change(effective, assigned_role);
            verdict!(valid);
            continue;
        }

        // invites (permissions.ts:536-566)
        let invite_ok = match transactor_role {
            Some(Role::AdminInvite) => {
                if assigned_role != Role::Admin {
                    verdict!(invalid "AdminInvites can only create admins.");
                    continue;
                }
                true
            }
            Some(Role::ManagerInvite) => {
                if assigned_role != Role::Manager {
                    verdict!(invalid "managerInvite can only create managers.");
                    continue;
                }
                true
            }
            Some(Role::WriterInvite) => {
                if assigned_role != Role::Writer {
                    verdict!(invalid "WriterInvites can only create writers.");
                    continue;
                }
                true
            }
            Some(Role::ReaderInvite) => {
                if assigned_role != Role::Reader {
                    verdict!(invalid "ReaderInvites can only create reader.");
                    continue;
                }
                true
            }
            Some(Role::WriteOnlyInvite) => {
                if assigned_role != Role::WriteOnly {
                    verdict!(invalid "WriteOnlyInvites can only create writeOnly.");
                    continue;
                }
                true
            }
            _ => false,
        };

        if !invite_ok {
            verdict!(invalid "Group transaction must be made by current admin, manager, or invite");
            continue;
        }

        resolver.member_roles.insert(affected_member.clone(), assigned_role);
        state
            .role_history
            .entry(affected_member.clone())
            .or_default()
            .add_change(effective, assigned_role);
        verdict!(valid);
    }

    Ok(())
}

// =====================================================================
// ownedByGroup validation (determineValidTransactions, permissions.ts:90-155)
// =====================================================================

#[allow(clippy::too_many_arguments)]
fn build_owned_by_group(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    state: &mut GroupEngineState,
    sm: &SessionMapImpl,
    group_id: &str,
    pending: &[PendingTxIn],
    visited: &mut HashSet<String>,
) -> Result<(), SessionMapError> {
    // The owning group must be loaded (expectCoValueLoaded, permissions.ts:92-98).
    ensure_engine(covalues, engines, group_id, &[], visited)?;
    let (group_is_account, group_initial_admin) = engines
        .get(group_id)
        .map(|e| (e.is_account, e.initial_admin.clone()))
        .unwrap_or((false, None));

    // The ownedByGroup branch iterates transactions without the group-validation
    // sort; use collection order (session-insertion, txIndex ascending).
    let txs = collect_group_txs(sm, pending);

    for tx in &txs {
        // agentInAccountOrMemberInGroup (permissions.ts:573-581): an account's
        // own id resolves to its static header agent; every other transactor is
        // used as-is (so the "Transactor not found in group" branch is
        // unreachable — this helper never returns undefined).
        let effective_transactor = if tx.author == group_id && group_is_account {
            group_initial_admin.clone().unwrap_or_else(|| tx.author.clone())
        } else {
            tx.author.clone()
        };

        let role = role_of_internal(
            covalues,
            engines,
            group_id,
            &effective_transactor,
            Some(tx.current_made_at),
            visited,
        )?;

        // The reader branch-pointer special case (permissions.ts:124-137)
        // requires `tx.meta.branch`, which no fixture exercises and which the
        // transaction view does not surface; it is intentionally not ported.
        let has_write = matches!(
            role,
            Some(Role::Admin) | Some(Role::Manager) | Some(Role::Writer) | Some(Role::WriteOnly)
        );

        if has_write {
            state.verdicts.push(Verdict {
                session_id: tx.session_id.clone(),
                tx_index: tx.tx_index,
                valid: true,
                reason: None,
            });
        } else {
            state.verdicts.push(Verdict {
                session_id: tx.session_id.clone(),
                tx_index: tx.tx_index,
                valid: false,
                reason: Some("Transactor has no write permissions".to_string()),
            });
        }
    }

    Ok(())
}

// =====================================================================
// Validation-side role resolution (MemberRoleResolver.getRoleAtTime)
// =====================================================================

/// `MemberRoleResolver.getRoleAtTime` (permissions.ts:207-226). The direct role
/// comes from the plain, time-ignoring map; each parent contributes its
/// time-based read-side role, capped/extended per its mapping and upgraded via
/// the validation comparator.
fn resolver_role_at(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    resolver: &ResolverState,
    member: &str,
    time: u64,
    visited: &mut HashSet<String>,
) -> Result<Option<Role>, SessionMapError> {
    let mut role = resolver.member_roles.get(member).copied();

    for (parent_id, mapping) in &resolver.parent_groups {
        // Cyclic-data guard: an in-progress parent contributes nothing.
        if visited.contains(parent_id) {
            continue;
        }
        let parent_role =
            role_of_internal(covalues, engines, parent_id, member, Some(time), visited)?;

        if !Role::is_inheritable(parent_role) {
            continue;
        }

        let resolved = match mapping {
            ParentRoleMapping::Extend => parent_role.unwrap(),
            ParentRoleMapping::Capped(r) => *r,
            // Revoked mappings are never present in `parent_groups` (removed on
            // revoke); listed for exhaustiveness.
            ParentRoleMapping::Revoked => continue,
        };

        if is_higher_role(resolved, role) {
            role = Some(resolved);
        }
    }

    Ok(role)
}

// =====================================================================
// Read-side role resolution (RawGroup/RawAccount.roleOfInternal)
// =====================================================================

/// Read-side role of `member` in `group_id` at `at_time` (`None` = latest).
///
/// Port of `RawGroup.roleOfInternal` (group.ts:451-488) plus the `RawAccount`
/// overrides (account.ts:68-75). Builds the group's engine (and, recursively,
/// its parents') on demand.
pub fn role_of_internal(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    group_id: &str,
    member: &str,
    at_time: Option<u64>,
    visited: &mut HashSet<String>,
) -> Result<Option<Role>, SessionMapError> {
    ensure_engine(covalues, engines, group_id, &[], visited)?;

    // Missing engine == cyclic build in progress: treat as no roles.
    let engine = match engines.get(group_id) {
        Some(e) => e,
        None => return Ok(None),
    };

    // RawAccount override (account.ts:68-75): self is always admin.
    if engine.is_account && member == group_id {
        return Ok(Some(Role::Admin));
    }

    // Direct role; a direct `revoked` collapses to `undefined` here
    // (group.ts:454-458).
    let mut role_info = match engine.role_history.get(member) {
        Some(hist) => match hist.get_at_time(at_time) {
            Some(Role::Revoked) | None => None,
            Some(r) => Some(*r),
        },
        None => None,
    };

    // Parent walk (group.ts:462-479). Collect the parent edges first so the
    // engines map is free to be mutated by the recursion.
    let parent_edges: Vec<(String, ParentRoleMapping)> = engine
        .parent_history
        .iter()
        .filter_map(|(pid, hist)| match hist.get_at_time(at_time) {
            Some(ParentRoleMapping::Revoked) | None => None,
            Some(mapping) => Some((pid.clone(), *mapping)),
        })
        .collect();

    for (parent_id, mapping) in parent_edges {
        // Cycle guard: skip an edge back into a group we are already resolving.
        if visited.contains(&parent_id) {
            continue;
        }
        let parent_role =
            role_of_internal(covalues, engines, &parent_id, member, at_time, visited)?;

        if !Role::is_inheritable(parent_role) {
            continue;
        }

        let role_to_inherit = match mapping {
            ParentRoleMapping::Extend => parent_role.unwrap(),
            ParentRoleMapping::Capped(r) => r,
            ParentRoleMapping::Revoked => continue,
        };

        if is_more_permissive_and_should_inherit(role_to_inherit, role_info) {
            role_info = Some(role_to_inherit);
        }
    }

    // Everyone fallback (group.ts:481-485) — only when no role resolved and the
    // query itself is not for "everyone".
    if role_info.is_none() && member != EVERYONE {
        // Re-borrow: the recursion above may have rebuilt/replaced the engine.
        if let Some(engine) = engines.get(group_id) {
            if let Some(hist) = engine.role_history.get(EVERYONE) {
                match hist.get_at_time(at_time) {
                    Some(Role::Revoked) | None => {}
                    Some(r) => return Ok(Some(*r)),
                }
            }
        }
    }

    Ok(role_info)
}

// =====================================================================
// isSelfExtension (group.ts:1766-1791)
// =====================================================================

/// `isSelfExtension` (group.ts:1766-1791): stack walk from the candidate
/// `parent_id` over each group's CURRENT (latest, non-revoked) parent mappings;
/// returns true if the child's own id is reached (including `parent_id ==
/// child_id`, a direct self-reference).
fn is_self_extension(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    child_id: &str,
    parent_id: &str,
    visited: &mut HashSet<String>,
) -> Result<bool, SessionMapError> {
    let mut checked: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec![parent_id.to_string()];

    while let Some(current) = queue.pop() {
        if current == child_id {
            return Ok(true);
        }
        if !checked.insert(current.clone()) {
            continue;
        }

        // getParentGroups() on `current` requires it loaded and needs its engine
        // for the current parent mappings.
        ensure_engine(covalues, engines, &current, &[], visited)?;
        let parents: Vec<String> = match engines.get(&current) {
            Some(e) => e
                .parent_history
                .iter()
                .filter_map(|(pid, hist)| match hist.get_at_time(None) {
                    Some(ParentRoleMapping::Revoked) | None => None,
                    Some(_) => Some(pid.clone()),
                })
                .collect(),
            None => Vec::new(),
        };

        for pid in parents {
            if !checked.contains(&pid) {
                queue.push(pid);
            }
        }
    }

    Ok(false)
}

// =====================================================================
// NodeCore-facing entry points
// =====================================================================

/// Validate every transaction of `co_id` and return the verdicts in validation
/// order. Operates on `NodeCore`'s disjoint field borrows.
pub fn validate_group(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    co_id: &str,
    pending: &[PendingTxIn],
) -> Result<Vec<Verdict>, SessionMapError> {
    let mut visited = HashSet::new();
    ensure_engine(covalues, engines, co_id, pending, &mut visited)?;
    Ok(engines
        .get(co_id)
        .map(|e| e.verdicts.clone())
        .unwrap_or_default())
}

/// Read-side role of `member` in `group_id` at `at_time`.
pub fn role_of(
    covalues: &HashMap<String, SessionMapImpl>,
    engines: &mut HashMap<String, GroupEngineState>,
    group_id: &str,
    member: &str,
    at_time: Option<u64>,
) -> Result<Option<Role>, SessionMapError> {
    let mut visited = HashSet::new();
    role_of_internal(covalues, engines, group_id, member, at_time, &mut visited)
}

// =====================================================================
// Fixture tests — the main gate. One test per `data/group_engine/*.json`.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::Verdict;
    use crate::core::group_engine::tx_view::fixtures::{build_session_map, FixtureFile};
    use crate::core::node::NodeCore;

    /// `(session_id, tx_index) -> madeAt` from a fixture's raw transactions.
    fn made_at_index(fix: &FixtureFile) -> std::collections::HashMap<(String, u32), u64> {
        let mut m = std::collections::HashMap::new();
        for cov in &fix.covalues {
            for s in &cov.sessions {
                for (i, raw) in s.transactions.iter().enumerate() {
                    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
                    let made = v.get("madeAt").and_then(|x| x.as_u64()).unwrap_or(0);
                    m.insert((s.session_id.clone(), i as u32), made);
                }
            }
        }
        m
    }

    /// Load a fixture into a `NodeCore`, then assert every verdict list and every
    /// role query matches EXACTLY (valid flag + verbatim reason string + role).
    ///
    /// Verdict ORDER is asserted up to the comparator's own ambiguity: cross-session
    /// transactions sharing a `madeAt` are `Equal` under `compareTransactions`
    /// (coValueCore.ts:1851-1855), so their relative order is unspecified. The check
    /// therefore requires (a) an identical `madeAt` sequence and (b) an identical set
    /// of verdicts within each equal-`madeAt` group — pinning validity, reason, and
    /// the fully-ordered part of the sequence, while allowing equal-`madeAt`
    /// cross-session ties to differ. See the report's ordering note.
    fn run_fixture(name: &str) {
        let fix = FixtureFile::load(name);
        let made_at = made_at_index(&fix);

        // Build each covalue's session map exactly as the standalone fixture
        // helper does, but inside the node's registry.
        let mut node = NodeCore::new();
        for cov in &fix.covalues {
            // Reuse the shared builder to stay identical to the tx_view tests,
            // then splice it in via a fresh create + transaction replay.
            let _ = build_session_map(cov); // sanity: header + txs parse under skip_verify
            node.create_co_value(&cov.co_id, &cov.header_json, None, true)
                .unwrap_or_else(|e| panic!("[{name}] create {}: {e}", cov.co_id));
            for session in &cov.sessions {
                let txs_json = format!("[{}]", session.transactions.join(","));
                node.get_mut(&cov.co_id)
                    .unwrap()
                    .add_transactions(&session.session_id, None, &txs_json, &session.last_signature, true)
                    .unwrap_or_else(|e| panic!("[{name}] add txs {}: {e}", session.session_id));
            }
        }

        // Verdicts: one validate_group call per verdict-bearing covalue.
        for (co_id, expected) in &fix.verdicts {
            let got = node
                .validate_group(co_id, &[])
                .unwrap_or_else(|e| panic!("[{name}] validate_group {co_id}: {e}"));
            assert_eq!(
                got.len(),
                expected.len(),
                "[{name}] verdict count mismatch for {co_id}\n got: {got:#?}"
            );

            // (a) identical madeAt sequence (the fully-ordered part of the order).
            for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
                let gm = made_at[&(g.session_id.clone(), g.tx_index)];
                let em = made_at[&(e.session_id.clone(), e.tx_index)];
                assert!(
                    gm == em,
                    "[{name}] verdict madeAt-sequence mismatch at #{i} for {co_id}: \
                     got {gm} ({} #{}), expected {em} ({} #{})",
                    g.session_id,
                    g.tx_index,
                    e.session_id,
                    e.tx_index
                );
            }

            // (b) identical verdict set within each equal-madeAt group.
            let key = |v: &Verdict| {
                (
                    made_at[&(v.session_id.clone(), v.tx_index)],
                    v.session_id.clone(),
                    v.tx_index,
                    v.valid,
                    v.reason.clone(),
                )
            };
            let mut gs: Vec<_> = got.iter().map(key).collect();
            let mut es: Vec<_> = expected
                .iter()
                .map(|e| {
                    (
                        made_at[&(e.session_id.clone(), e.tx_index)],
                        e.session_id.clone(),
                        e.tx_index,
                        e.valid,
                        e.reason.clone(),
                    )
                })
                .collect();
            gs.sort();
            es.sort();
            assert_eq!(gs, es, "[{name}] verdict set mismatch for {co_id}");
        }

        // Role queries.
        for q in &fix.role_queries {
            let got = node
                .role_of(&q.group_id, &q.member, q.at_time)
                .unwrap_or_else(|e| panic!("[{name}] role_of {} {}: {e}", q.group_id, q.member));
            let got_str = got.map(|r| r.as_str().to_string());
            assert_eq!(
                got_str.as_deref(),
                q.expected_role.as_deref(),
                "[{name}] role query group={} member={} atTime={:?}",
                q.group_id,
                q.member,
                q.at_time
            );
        }
    }

    macro_rules! fixture_test {
        ($fn_name:ident, $file:literal) => {
            #[test]
            fn $fn_name() {
                run_fixture($file);
            }
        };
    }

    fixture_test!(account_agent_resolution, "account_agent_resolution");
    fixture_test!(admin_demotion_rules, "admin_demotion_rules");
    fixture_test!(all_invites, "all_invites");
    fixture_test!(basic_roles, "basic_roles");
    fixture_test!(cross_session_ties, "cross_session_ties");
    fixture_test!(deep_parent_chain, "deep_parent_chain");
    fixture_test!(everyone_roles, "everyone_roles");
    fixture_test!(initial_admin_self_promotion, "initial_admin_self_promotion");
    fixture_test!(key_revelations, "key_revelations");
    fixture_test!(malformed_changes, "malformed_changes");
    fixture_test!(manager_rules, "manager_rules");
    fixture_test!(parent_capped, "parent_capped");
    fixture_test!(parent_extend, "parent_extend");
    fixture_test!(parent_revoked_inheritance, "parent_revoked_inheritance");
    fixture_test!(private_tx_in_group, "private_tx_in_group");
    fixture_test!(self_extension_cycle, "self_extension_cycle");
    fixture_test!(self_revoke, "self_revoke");
    fixture_test!(write_only_keys, "write_only_keys");
}
