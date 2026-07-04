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
//! - The **validation-order plain map** (`ResolverState::member_roles`) mirrors
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
use crate::core::group_engine::tx_view::{
    collect_group_txs, sort_for_validation, PendingTxIn, Privacy,
};
use crate::core::group_engine::types::{
    is_higher_role, is_more_permissive_and_should_inherit, ParentRoleMapping, Role, TimeBasedEntry,
};
use crate::core::session_map::{
    CoValueHeader, JsonValue, RulesetDef, SessionMapError, SessionMapImpl,
};

/// The `"everyone"` pseudo-member key (`EVERYONE`, group.ts:49).
const EVERYONE: &str = "everyone";

/// The three-way validation result a transaction can land in. Stage 3
/// (`validateTransactions`) adds `ValidBranchPointerOnly` for the ownedByGroup
/// reader branch-pointer special case (permissions.ts:143-156), emitted by
/// [`build_owned_by_group`]. Both `Valid` and `ValidBranchPointerOnly` are
/// non-`Invalid` outcomes, so [`Verdict::valid`] is true for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictOutcome {
    Valid,
    Invalid,
    ValidBranchPointerOnly,
}

impl VerdictOutcome {
    /// The canonical wire string, shared by the napi binding and the fixture
    /// tests — single source of truth, matching the TS union in crypto.ts.
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictOutcome::Valid => "valid",
            VerdictOutcome::Invalid => "invalid",
            VerdictOutcome::ValidBranchPointerOnly => "validBranchPointerOnly",
        }
    }
}

/// A per-transaction validation verdict, in validation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub session_id: String,
    pub tx_index: u32,
    /// `outcome != VerdictOutcome::Invalid`, derived once in [`Verdict::new`]
    /// (the sole constructor) so the flag can never drift from `outcome`.
    /// Pre-stage-3 callers that read only `valid`/`reason` are unaffected.
    pub valid: bool,
    pub outcome: VerdictOutcome,
    /// Verbatim TS reason string when invalid; `None` when valid.
    pub reason: Option<String>,
}

impl Verdict {
    /// The ONLY verdict constructor. Derives `valid = outcome !=
    /// VerdictOutcome::Invalid` so the flag can never drift from the outcome
    /// (both non-`Invalid` outcomes — `Valid` and `ValidBranchPointerOnly` —
    /// are valid). A `reason` is required exactly when the outcome is
    /// `Invalid`, and forbidden otherwise (debug-asserted).
    fn new(
        session_id: String,
        tx_index: u32,
        outcome: VerdictOutcome,
        reason: Option<String>,
    ) -> Verdict {
        debug_assert_eq!(
            outcome == VerdictOutcome::Invalid,
            reason.is_some(),
            "an Invalid verdict must carry a reason; a valid one must not"
        );
        Verdict {
            session_id,
            tx_index,
            valid: outcome != VerdictOutcome::Invalid,
            outcome,
            reason,
        }
    }
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

/// JavaScript truthiness of an optional JSON value, mirroring how TS evaluates
/// `tx.meta?.branch` / `tx.meta?.ownerId` in the reader branch-pointer guard
/// (`permissions.ts:143-147`). A missing key, `null`, `false`, `0`/`NaN`, and
/// the empty string are FALSY; every other string/number, and any array or
/// object, is truthy (JS treats `[]`/`{}` as truthy). The stage-3 fixtures use
/// non-empty string values for both keys, so this only matters for hardening.
fn is_truthy(v: Option<&serde_json::Value>) -> bool {
    match v {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => {
            n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(false)
        }
        Some(serde_json::Value::String(s)) => !s.is_empty(),
        Some(serde_json::Value::Array(_)) | Some(serde_json::Value::Object(_)) => true,
    }
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
                covalues, engines, &mut state, sm, &group_id, pending, visited,
            )?;
        }
        RulesetKind::UnsafeAllowAll => {
            // permissions.ts:157-163 — every transaction is valid.
            let mut txs = collect_group_txs(sm, pending);
            sort_for_validation(&mut txs);
            for tx in &txs {
                state.verdicts.push(Verdict::new(
                    tx.session_id.clone(),
                    tx.tx_index,
                    VerdictOutcome::Valid,
                    None,
                ));
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
                state.verdicts.push(Verdict::new(
                    tx.session_id.clone(),
                    tx.tx_index,
                    VerdictOutcome::Valid,
                    None,
                ));
            }};
            (invalid $reason:expr) => {{
                state.verdicts.push(Verdict::new(
                    tx.session_id.clone(),
                    tx.tx_index,
                    VerdictOutcome::Invalid,
                    Some($reason.to_string()),
                ));
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
                    resolver
                        .parent_groups
                        .insert(parent_group_id.clone(), mapping);
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
            resolver
                .member_roles
                .insert(affected_member.clone(), assigned_role);
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
            resolver
                .member_roles
                .insert(affected_member.clone(), assigned_role);
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
            resolver
                .member_roles
                .insert(affected_member.clone(), assigned_role);
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
            resolver
                .member_roles
                .insert(affected_member.clone(), assigned_role);
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

        resolver
            .member_roles
            .insert(affected_member.clone(), assigned_role);
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
            group_initial_admin
                .clone()
                .unwrap_or_else(|| tx.author.clone())
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

        // The reader branch-pointer special case (permissions.ts:143-156),
        // checked BEFORE the write-permission gate exactly as TS does. The guard
        // is `transactorRoleAtTxTime === "reader" && tx.meta?.branch &&
        // tx.meta?.ownerId`: the role must be EXACTLY reader (an admin posting an
        // identically-shaped {branch, ownerId} pointer is NOT trimmed — it has
        // write permission and falls through to a plain Valid), and both meta
        // keys must be JS-truthy (see `is_truthy`). The actual trim (forcing
        // changes/meta to the pointer only) stays in TS; the Rust engine merely
        // classifies the outcome as `ValidBranchPointerOnly`.
        //
        // `tx.meta` is populated from the pending tx's DECRYPTED meta first,
        // then the trusting tx's own wire meta (tx_view). A received private tx
        // has meta `None` at validation (decryption follows validation), so this
        // guard cannot fire for it — see `owned_private_tx_meta_unavailable`.
        let is_reader_branch_pointer = role == Some(Role::Reader)
            && tx
                .meta
                .as_ref()
                .is_some_and(|m| is_truthy(m.get("branch")) && is_truthy(m.get("ownerId")));

        if is_reader_branch_pointer {
            state.verdicts.push(Verdict::new(
                tx.session_id.clone(),
                tx.tx_index,
                VerdictOutcome::ValidBranchPointerOnly,
                None,
            ));
            continue;
        }

        let has_write = matches!(
            role,
            Some(Role::Admin) | Some(Role::Manager) | Some(Role::Writer) | Some(Role::WriteOnly)
        );

        if has_write {
            state.verdicts.push(Verdict::new(
                tx.session_id.clone(),
                tx.tx_index,
                VerdictOutcome::Valid,
                None,
            ));
        } else {
            state.verdicts.push(Verdict::new(
                tx.session_id.clone(),
                tx.tx_index,
                VerdictOutcome::Invalid,
                Some("Transactor has no write permissions".to_string()),
            ));
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
/// order. Operates on `NodeCore`'s disjoint field borrows. (Stage 2 name:
/// `validate_group`; renamed here as Stage 3's unified `validateTransactions`
/// surface, which subsumes it and adds the `ValidBranchPointerOnly` outcome.)
pub fn validate_transactions(
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
    /// Load every covalue of a fixture into a fresh `NodeCore`, mirroring the
    /// standalone fixture builder (create + transaction replay under
    /// skip_verify). Shared by `run_fixture` and the dedicated stage-3 tests.
    fn load_fixture_node(name: &str, fix: &FixtureFile) -> NodeCore {
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
                    .add_transactions(
                        &session.session_id,
                        None,
                        &txs_json,
                        &session.last_signature,
                        true,
                    )
                    .unwrap_or_else(|e| panic!("[{name}] add txs {}: {e}", session.session_id));
            }
        }
        node
    }

    fn run_fixture(name: &str) {
        let fix = FixtureFile::load(name);
        let made_at = made_at_index(&fix);

        // Build each covalue's session map exactly as the standalone fixture
        // helper does, but inside the node's registry.
        let mut node = load_fixture_node(name, &fix);

        // Verdicts: one validate_transactions call per verdict-bearing covalue.
        for (co_id, expected) in &fix.verdicts {
            let got = node
                .validate_transactions(co_id, &[])
                .unwrap_or_else(|e| panic!("[{name}] validate_transactions {co_id}: {e}"));
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

            // (b) identical verdict set within each equal-madeAt group. The
            // comparison honors the stage-3 `outcome` field: got's
            // `VerdictOutcome` is compared as its wire string, and an expected
            // verdict with no `outcome` derives it from `valid` (valid ->
            // "valid", invalid -> "invalid") so pre-stage-3 fixtures are
            // unaffected while `validBranchPointerOnly` is pinned exactly.
            let outcome_str = |o: super::VerdictOutcome| o.as_str();
            let key = |v: &Verdict| {
                (
                    made_at[&(v.session_id.clone(), v.tx_index)],
                    v.session_id.clone(),
                    v.tx_index,
                    v.valid,
                    v.reason.clone(),
                    outcome_str(v.outcome).to_string(),
                )
            };
            let mut gs: Vec<_> = got.iter().map(key).collect();
            let mut es: Vec<_> = expected
                .iter()
                .map(|e| {
                    let outcome = e
                        .outcome
                        .clone()
                        .unwrap_or_else(|| if e.valid { "valid" } else { "invalid" }.to_string());
                    (
                        made_at[&(e.session_id.clone(), e.tx_index)],
                        e.session_id.clone(),
                        e.tx_index,
                        e.valid,
                        e.reason.clone(),
                        outcome,
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

    // --- Stage 3: ownedByGroup / account / unsafeAllowAll + branch pointer ---
    fixture_test!(unsafe_allow_all, "unsafe_allow_all");
    fixture_test!(owned_by_account, "owned_by_account");
    fixture_test!(owned_by_group_roles, "owned_by_group_roles");
    fixture_test!(
        owned_by_group_role_change_over_time,
        "owned_by_group_role_change_over_time"
    );
    fixture_test!(owned_reader_branch_pointer, "owned_reader_branch_pointer");
    fixture_test!(
        owned_private_tx_meta_unavailable,
        "owned_private_tx_meta_unavailable"
    );

    // =====================================================================
    // merged_tx_ties: the admin branch-pointer COUNTER-case + all-valid multiset
    // =====================================================================

    /// `merged_tx_ties` (ownedByGroup) — every transaction is authored by the
    /// group's admin. One of them carries an `{branch, ownerId}` meta that is
    /// shape-identical to the reader branch-pointer trim's input; because the
    /// author is admin (NOT reader), the reader trim must NOT fire. This pins
    /// (a) the documented all-valid multiset and (b) that NO verdict is
    /// `ValidBranchPointerOnly` — the trim's `role == reader` guard.
    #[test]
    fn merged_tx_ties_admin_branch_pointer_is_not_trimmed() {
        use super::VerdictOutcome;
        use crate::core::group_engine::tx_view::PendingTxIn;

        let owned_id = "co_zSKK5oFqS8LcD3Rj14nYJQf5S6B";
        let fix = FixtureFile::load("merged_tx_ties");
        let mut node = load_fixture_node("merged_tx_ties", &fix);

        // The owning group's id — used as a truthy `ownerId` for the pointer.
        let group_id = "co_zQRoiJcPP4nRGqf8bnMWoxYJkZH";
        // The single admin session of the owned covalue.
        let admin_session = fix
            .covalues
            .iter()
            .find(|c| c.co_id == owned_id)
            .expect("owned covalue present")
            .sessions[0]
            .session_id
            .clone();

        // Force branch-pointer meta onto the (private) tx #1 so the trim's meta
        // precondition is satisfied; only the admin-vs-reader role must then
        // decide the outcome.
        let pending = vec![PendingTxIn {
            session_id: admin_session.clone(),
            tx_index: 1,
            source_made_at: None,
            meta_json: Some(format!(
                r#"{{"branch":"feature-branch","ownerId":"{group_id}"}}"#
            )),
            source_tx_id: None,
        }];

        let got = node
            .validate_transactions(owned_id, &pending)
            .expect("validate merged_tx_ties");

        assert_eq!(got.len(), 5, "5 transactions in the owned covalue");
        assert!(
            got.iter().all(|v| v.valid),
            "every merged_tx_ties transaction is valid (admin-authored): {got:#?}"
        );
        assert!(
            got.iter()
                .all(|v| v.outcome != VerdictOutcome::ValidBranchPointerOnly),
            "an admin's identically-shaped branch pointer must stay plain Valid, \
             never validBranchPointerOnly: {got:#?}"
        );
    }

    // =====================================================================
    // reset_validation: drop the cached engine, forcing a rebuild
    // =====================================================================

    /// `reset_validation` must drop the cached engine so the NEXT validate
    /// rebuilds with fresh inputs. Probe (behavioral, no counter): the engine
    /// cache is keyed by per-session tx-counts and IGNORES `pending`, so a
    /// second `validate_transactions` with changed `pending` normally hits the
    /// cache and returns the stale verdicts. `reset_validation` between the two
    /// calls forces the rebuild, letting the new pending meta take effect —
    /// flipping a reader's private write from "no write permissions" to the
    /// branch-pointer outcome.
    ///
    /// Also asserts the absent-id no-op contract.
    #[test]
    fn reset_validation_forces_rebuild_with_fresh_pending() {
        use super::VerdictOutcome;
        use crate::core::group_engine::tx_view::PendingTxIn;

        let owned_id = "co_zaNLWDF81o7S9DV94nkS9NPhLTE";
        // The reader's PRIVATE tx — meta is unavailable at validation, so it is
        // rejected until decrypted meta is supplied as pending.
        let private_session = "co_zb63hTq7sRoA9bULJuhYkkD3Ytc_session_zFf61jGJyWoS";
        let owner_group = "co_z95CafWcqPaQiGCj9YiF3QyGPrN";

        let fix = FixtureFile::load("owned_private_tx_meta_unavailable");
        let mut node = load_fixture_node("owned_private_tx_meta_unavailable", &fix);

        let private_verdict = |verdicts: &[Verdict]| -> Verdict {
            verdicts
                .iter()
                .find(|v| v.session_id == private_session && v.tx_index == 0)
                .expect("private tx verdict present")
                .clone()
        };

        // 1) Baseline: no pending meta -> reader's private write is rejected.
        let base = node.validate_transactions(owned_id, &[]).unwrap();
        assert!(
            !private_verdict(&base).valid,
            "private write rejected without meta"
        );

        // Branch-pointer meta the reader "intended" — visible only once decrypted.
        let pending = vec![PendingTxIn {
            session_id: private_session.to_string(),
            tx_index: 0,
            source_made_at: None,
            meta_json: Some(format!(
                r#"{{"branch":"feature-branch","ownerId":"{owner_group}"}}"#
            )),
            source_tx_id: None,
        }];

        // 2) Same node, NEW pending, but NO reset -> cache hit ignores pending.
        let cached = node.validate_transactions(owned_id, &pending).unwrap();
        assert!(
            !private_verdict(&cached).valid,
            "without reset, the cached engine ignores the new pending meta"
        );

        // 3) reset_validation -> the next validate rebuilds and sees the pending.
        node.reset_validation(owned_id);
        let rebuilt = node.validate_transactions(owned_id, &pending).unwrap();
        let v = private_verdict(&rebuilt);
        assert!(v.valid, "after reset, the branch pointer is honored");
        assert_eq!(
            v.outcome,
            VerdictOutcome::ValidBranchPointerOnly,
            "reader + branch-pointer meta -> validBranchPointerOnly after rebuild"
        );

        // Absent-id contract: no-op, no panic.
        node.reset_validation("co_zNeverRegistered");
    }

    // =====================================================================
    // Error taxonomy: UnknownCoValue (primary) vs CoValueNotLoaded (dependency)
    // =====================================================================

    /// An unregistered PRIMARY coId passed directly to a coId-first entry point
    /// is API misuse — `UnknownCoValue` — matching every other `NodeCore`
    /// method (e.g. `get`/`get_mut`). It must NOT surface as
    /// `CoValueNotLoaded`, which is reserved for dependencies (parent groups /
    /// owning accounts) discovered missing during a recursive build.
    #[test]
    fn validate_transactions_unknown_primary_errors() {
        use crate::core::session_map::SessionMapError;

        let mut node = NodeCore::new();

        match node.validate_transactions("co_zNope", &[]) {
            Err(SessionMapError::UnknownCoValue(id)) => assert_eq!(id, "co_zNope"),
            other => panic!("expected UnknownCoValue, got {other:?}"),
        }

        match node.role_of("co_zNope", "co_zX", None) {
            Err(SessionMapError::UnknownCoValue(id)) => assert_eq!(id, "co_zNope"),
            other => panic!("expected UnknownCoValue, got {other:?}"),
        }
    }

    /// A missing DEPENDENCY discovered while recursively building the primary
    /// coId's engine (here: the parent group referenced by a
    /// `parent_<id>` extension) must still surface as `CoValueNotLoaded`, not
    /// `UnknownCoValue` — only the primary coId gets the API-misuse treatment.
    #[test]
    fn missing_parent_dependency_is_covalue_not_loaded() {
        use crate::core::session_map::SessionMapError;

        let fix = FixtureFile::load("parent_extend");

        // The child references `parent_co_zcsomTZP9rEDbhYyqGzHvb1vC24` in its
        // transactions; find it (and its parent id) generically off the
        // fixture rather than hardcoding which covalue is "first".
        let child = fix
            .covalues
            .iter()
            .find(|cov| {
                cov.sessions.iter().any(|s| {
                    s.transactions
                        .iter()
                        .any(|raw| raw.contains("\\\"key\\\":\\\"parent_"))
                })
            })
            .expect("[parent_extend] fixture should contain a child with a parent_ extension");

        let parent_id = child
            .sessions
            .iter()
            .find_map(|s| {
                s.transactions.iter().find_map(|raw| {
                    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
                    let changes_str = v.get("changes")?.as_str()?;
                    let changes: serde_json::Value = serde_json::from_str(changes_str).ok()?;
                    let key = changes.get(0)?.get("key")?.as_str()?;
                    key.strip_prefix("parent_").map(|id| id.to_string())
                })
            })
            .expect("[parent_extend] child should have a parent_<id> extension key");

        // Load ONLY the child covalue — the parent is never registered.
        let mut node = NodeCore::new();
        let _ = build_session_map(child); // sanity: header + txs parse under skip_verify
        node.create_co_value(&child.co_id, &child.header_json, None, true)
            .unwrap_or_else(|e| panic!("[parent_extend] create {}: {e}", child.co_id));
        for session in &child.sessions {
            let txs_json = format!("[{}]", session.transactions.join(","));
            node.get_mut(&child.co_id)
                .unwrap()
                .add_transactions(
                    &session.session_id,
                    None,
                    &txs_json,
                    &session.last_signature,
                    true,
                )
                .unwrap_or_else(|e| panic!("[parent_extend] add txs {}: {e}", session.session_id));
        }

        match node.validate_transactions(&child.co_id, &[]) {
            Err(SessionMapError::CoValueNotLoaded(id)) => assert_eq!(id, parent_id),
            other => panic!("expected CoValueNotLoaded({parent_id}), got {other:?}"),
        }
    }
}
