# Group Engine (Stage 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port group/account permission validation (`determineValidTransactionsForGroup` + `MemberRoleResolver`) and read-side role resolution (`roleOfInternal` and its indices) into a Rust `GroupEngine` inside the stage-1 `NodeCore` registry, exposed as `validateGroup` and `roleOf`, with TypeScript delegating behind capability detection and the TS implementation kept as fallback + differential-test oracle.

**Architecture:** One `GroupEngine` per group/account CoValue, cached in the `NodeCore` entry, rebuilt from scratch whenever that CoValue gains transactions (full recompute — never incremental). Two distinct role structures per the spec: validation-order plain maps (time-ignoring direct-role lookups) and time-indexed `TimeBasedEntry` histories for read queries. Parent-group resolution goes through the registry with on-demand recursive engine builds and a cycle guard. Fixtures generated from the TS implementation are the executable spec; a randomized differential harness guards equivalence until the TS path is deleted (after wasm/RN native ports, out of scope here).

**Tech Stack:** Rust (cojson-core), napi-rs (cojson-core-napi), TypeScript (packages/cojson), vitest, cargo test.

**Spec:** `docs/superpowers/specs/2026-07-03-cojson-rust-permissions-migration-design.md` — the "Stage 2" section and ALL of "Fidelity constraints (normative)". Read both before starting any task.

**Prerequisite:** The stage-1 plan (`2026-07-03-nodecore-registry-stage1.md`) fully landed, including the generation-aware eviction fix and the stage-1 changeset. `NodeCore` (Rust: `crates/cojson-core/src/core/node.rs`), the napi `NodeCore` binding, and TS `NodeCoreImpl`/`ShimNodeCore`/`NapiNodeCoreAdapter` all exist.

**Working notes for the implementer:**

- Build napi after Rust changes: `pnpm build:napi` (repo root). Rust tests: `cargo test -p cojson-core` from `crates/`. TS tests: `pnpm test` inside `packages/cojson`.
- Rust fixtures live at `crates/cojson-core/data/` and are loaded in tests with `fs::read_to_string("data/<name>.json")` (cwd = crate root; see `session_log.rs:809` for the pattern). Stage-2 fixtures go under `crates/cojson-core/data/group_engine/`.
- Do NOT touch `crates/cojson-core-wasm` or `crates/cojson-core-rn` — napi-first; the TS fallback keeps wasm/RN working.
- No Claude/AI mentions in commits.

## Porting oracles (exact sources of truth)

| What | Where |
| --- | --- |
| Group validation algorithm | `packages/cojson/src/permissions.ts:229-571` (`determineValidTransactionsForGroup`) |
| Validation-side role state | `permissions.ts:183-227` (`MemberRoleResolver`; NOTE `getRoleAtTime` ignores `time` for direct roles — `permissions.ts:207-212`) |
| Validation-side comparator | `permissions.ts:171-181` (`isHigherRole`; `revoked` is never higher) |
| Read-side role resolution | `packages/cojson/src/coValues/group.ts:451-488` (`roleOfInternal`) |
| Read-side comparator | `group.ts:1693-1727` (`isMorePermissiveAndShouldInherit`; NOTE `revoked` in parent returns `true` — an inherited `revoked` OVERRIDES the child role, unlike validation-side) |
| Inheritable-role filter | `group.ts:1681-1691` (`isInheritableRole` — includes `revoked`) |
| Time-indexed entries | `group.ts:254-286` (`TimeBasedEntry`: chronological insert scanning backwards over `> madeAt` — equal-`madeAt` inserts AFTER existing equals; `getAtTime(undefined)` = latest; else `findLast(madeAt <= t)`) |
| Account overrides | `packages/cojson/src/coValues/account.ts:44-62` (`currentAgentID` = header `initialAdmin`, static) and `account.ts:68-75` (self → `"admin"`) |
| Author from session id | `packages/cojson/src/typeUtils/accountOrAgentIDfromSessionID.ts` (substring before `"_session"`) |
| Transaction ordering | `packages/cojson/src/coValueCore/coValueCore.ts:1842-1855` (`compareTransactions`: effective `madeAt` asc; `txIndex` tiebreak only within same session; cross-session ties equal → stable sort) |
| Key-shape classifiers | `permissions.ts:583-642` (`isWriteKeyForMember`, `isKeyForKeyField`, `isKeyForAccountField`, `isKeySealedForGroupField`, `isParentExtension`, `isChildExtension`, `isOwnWriteKeyRevelation`) |
| TS behavior test suites (fixture sources) | `packages/cojson/src/tests/permissions.test.ts`, `group.roleOf.test.ts`, `group.inheritance.test.ts`, `group.addMember.test.ts`, `group.removeMember.test.ts`, `group.invite.test.ts` |

## Verbatim invalid-reason strings (normative — tests assert on these)

`Can't make private transactions in groups` · `Only admins can make private transactions in groups` · `Group transaction must have exactly one change` · `Group transaction must set a role or readKey` · `Only admins can set readKeys` · `Only admins can set groupSealer` · `Only admins can set profile` · `Only admins can set root` · `Only admins and managers can reveal keys` · `Only admins and managers can set parent extensions` · `Parent group is not a group` · `Parent group is a circular dependency` · `Child extensions are not allowed anymore` · `Only admins and managers can set writeKeys` · `Write key already exists and can't be overridden by invite` · `Group transaction must set a valid role` · `Everyone can only be set to reader, writer, writeOnly or revoked` · `Admins can't demote admins.` · `Managers can't demote admins.` · `Managers can't promote to admin.` · `Managers can't invite admins.` · `Managers can't invite managers.` · `AdminInvites can only create admins.` · `managerInvite can only create managers.` · `WriterInvites can only create writers.` · `ReaderInvites can only create reader.` · `WriteOnlyInvites can only create writeOnly.` · `Group transaction must be made by current admin, manager, or invite`

(Cross-check this list against `permissions.ts` at implementation time — the file is the source of truth if it has drifted.)

---

### Task 1: Fixture exporter (TS) + corpus

**Files:**
- Create: `packages/cojson/src/tests/groupEngineFixtures.export.test.ts` (a vitest file that WRITES fixtures when `EXPORT_GROUP_ENGINE_FIXTURES=1`)
- Create: `crates/cojson-core/data/group_engine/*.json` (generated, committed)

The fixtures are the executable spec for every Rust task below. Format (one JSON file per scenario):

```json
{
  "description": "all invite kinds accept exactly their role",
  "covalues": [
    {
      "coId": "co_z...",
      "headerJson": "{...stableStringify'd header...}",
      "sessions": [
        {
          "sessionId": "co_zAcc_session_z...",
          "signerId": "signer_z...",
          "transactions": ["{...tx json...}", "..."],
          "lastSignature": "signature_z..."
        }
      ]
    }
  ],
  "verdicts": {
    "co_z<groupId>": [
      { "sessionId": "...", "txIndex": 0, "valid": true, "reason": null },
      { "sessionId": "...", "txIndex": 1, "valid": false, "reason": "Managers can't promote to admin." }
    ]
  },
  "roleQueries": [
    { "groupId": "co_z...", "member": "co_zAcc | sealer_.../signer_... agent id | everyone", "atTime": 1234567 , "expectedRole": "writer" },
    { "groupId": "co_z...", "member": "co_zAcc", "atTime": null, "expectedRole": null }
  ]
}
```

- [ ] **Step 1: Write the exporter harness**

The file is a normal vitest suite so it can reuse the repo's test helpers. Each scenario is one `test(...)`. Skeleton:

```ts
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "vitest";
// reuse the exact node-creation helper permissions.test.ts uses (read its imports and copy)

const EXPORT = process.env.EXPORT_GROUP_ENGINE_FIXTURES === "1";
const OUT_DIR = join(__dirname, "../../../../crates/cojson-core/data/group_engine");

function exportScenario(name: string, node: LocalNode, opts: {
  covalueIds: RawCoID[];          // groups/accounts the scenario touches (incl. accounts of all members)
  verdictIds: RawCoID[];          // covalues whose verdicts to record
  roleQueries: { groupId: RawCoID; member: string; atTime: number | null }[];
}) {
  // 1. covalues: for each id, read from node.nodeCore:
  //    headerJson = nodeCore.getHeader(id)
  //    for each sessionId of nodeCore.getSessionIds(id):
  //      transactions = raw JSON strings — re-stringify the parsed Transaction objects
  //        with the same stableStringify used by VerifiedState, or better: add a tiny
  //        test-only helper that reads the raw strings (nodeCore.getSessionTransactions
  //        returns parsed; JSON.stringify(tx) of the parsed object is acceptable because
  //        Rust re-parses it — key order does not matter for parsing)
  //      signerId: from the session's signer — reuse VerifiedState.getSessionLog(sessionId).signerID
  //      lastSignature: nodeCore.getLastSignature(id, sessionId)
  // 2. verdicts: for each verdictId: get the CoValueCore, call core.getValidTransactions({} /* forces parseNewTransactions */),
  //    then read core.verifiedTransactions: { sessionId: t.currentTxID.sessionID, txIndex: t.currentTxID.txIndex,
  //    valid: t.isValid, reason: t.validationErrorMessage ?? null }
  // 3. roleQueries: for each query: const g = expectGroup(node.expectCoValueLoaded(q.groupId).getCurrentContent());
  //    const view = q.atTime === null ? g : g.atTime(q.atTime);
  //    expectedRole = view.roleOfInternal(q.member) ?? null
  // 4. if (EXPORT) { mkdirSync(OUT_DIR, {recursive:true}); writeFileSync(join(OUT_DIR, `${name}.json`), JSON.stringify(fixture, null, 2)); }
  // 5. ALWAYS assert the fixture is internally consistent (verdicts non-empty, every roleQuery group present)
  //    so the suite has value even when not exporting.
}
```

- [ ] **Step 2: Write the scenario generators (one test each)**

Each scenario builds real state through public APIs (`node.createGroup()`, `group.addMember`, `group.removeMember`, `createInvite`, `group.extend`/parent-extension APIs — copy the idioms from the oracle test suites listed above). Required scenarios (file names = scenario names):

1. `basic_roles` — admin adds reader/writer/writeOnly/manager; role changes over time; roleQueries at timestamps between changes (use `map.core.verifiedTransactions` timestamps or record `Date.now()` snapshots between operations).
2. `initial_admin_self_promotion` — fresh group; first tx is the self-promotion; also a non-initialAdmin trying the same (invalid).
3. `self_revoke` — member revokes themselves (valid even without admin role).
4. `all_invites` — adminInvite/managerInvite/writerInvite/readerInvite/writeOnlyInvite each: correct acceptance (valid) + wrong-role acceptance (invalid, exact reason).
5. `admin_demotion_rules` — admin demotes admin (invalid), admin demotes self (valid), admin demotes writer (valid).
6. `manager_rules` — manager demotes admin / promotes to admin / invites admin / invites manager (all invalid) + manager adds writer (valid).
7. `write_only_keys` — writeOnly member's own writeKey set (valid), invite overriding an existing writeKey (invalid), admin overriding (valid), own write-key revelation by writeOnly member (valid).
8. `key_revelations` — readKey/groupSealer/profile/root set by admin (valid) and by writer (invalid); key_for fields revealed by admin and by each invite kind (valid).
9. `everyone_roles` — everyone set to reader/writer/writeOnly/revoked (valid) and to admin (invalid); roleQueries exercising the everyone fallback (member with no direct role) and the no-fallback-when-querying-everyone case.
10. `parent_extend` — parent group `extend` mapping; member gets role via parent; roleQueries at times before/after the parent membership change.
11. `parent_capped` — parent extension with a capping role mapping (e.g. parent admin capped to writer in child).
12. `parent_revoked_inheritance` — member has reader in child, `revoked` in parent with `extend` mapping — read-side role must come out per `isMorePermissiveAndShouldInherit("revoked", ...)` semantics (export whatever TS produces; this pins the override behavior).
13. `deep_parent_chain` — 3-level chain (grandparent → parent → child), including a revocation mid-chain and time-based queries.
14. `self_extension_cycle` — attempt to extend a group with itself / a cycle (invalid: `Parent group is a circular dependency`).
15. `account_agent_resolution` — an account-owned scenario where the transactor is the account id itself (exercises `agentInAccountOrMemberInGroup` in validation on the ACCOUNT covalue) + account self roleQuery (expects `"admin"`).
16. `malformed_changes` — a transaction with two changes; an op that isn't `set`; an invalid role value; everyone with invalid role. (Craft via `core.makeTransaction` with raw changes if the public API blocks these — copy how permissions.test.ts crafts hostile transactions.)
17. `cross_session_ties` — two sessions of different accounts with equal `madeAt` transactions (freeze `Date.now` via `vi.setSystemTime` to force ties); verdicts + role queries pin the stable-order outcome.
18. `private_tx_in_group` — a private transaction on a group (invalid: `Can't make private transactions in groups`) and on an account (export whatever TS produces — accounts take the other branch of the `isGroup` check; this pins the account/private semantics).

- [ ] **Step 3: Run without export, then with export**

Run: `cd packages/cojson && pnpm test groupEngineFixtures` → all scenarios pass their internal-consistency assertions.
Run: `EXPORT_GROUP_ENGINE_FIXTURES=1 pnpm test groupEngineFixtures` → files appear under `crates/cojson-core/data/group_engine/`.
Spot-check one file by eye: verdicts include both valid and invalid entries with exact reason strings.

- [ ] **Step 4: Commit**

```bash
git add packages/cojson/src/tests/groupEngineFixtures.export.test.ts crates/cojson-core/data/group_engine
git commit -m "test(cojson): group-engine fixture corpus exported from TS permissions oracle"
```

---

### Task 2: Rust foundation types — roles, TimeBasedEntry, key classifiers

**Files:**
- Create: `crates/cojson-core/src/core/group_engine/mod.rs` (module root: `pub mod types; pub mod classify; pub mod engine;` — engine.rs added in Task 4)
- Create: `crates/cojson-core/src/core/group_engine/types.rs`
- Create: `crates/cojson-core/src/core/group_engine/classify.rs`
- Modify: `crates/cojson-core/src/lib.rs` (add `pub mod group_engine;` + re-export inside `pub mod core`)

- [ ] **Step 1: Write failing tests for types.rs**

Tests for `Role` parsing/serialization (every variant round-trips its exact TS string: `admin`, `manager`, `writer`, `reader`, `writeOnly`, `revoked`, `adminInvite`, `managerInvite`, `writerInvite`, `readerInvite`, `writeOnlyInvite`), `is_account_role`, `can_admin` (admin|manager), `is_inheritable_role` (revoked|admin|manager|writer|reader), `is_higher_role` (validation-side, table from `permissions.ts:171-181`), `is_more_permissive_and_should_inherit` (read-side, table from `group.ts:1693-1727` — include the `revoked → true` case), and `TimeBasedEntry`:

```rust
#[test]
fn time_based_entry_matches_ts_semantics() {
    let mut e = TimeBasedEntry::new();
    e.add_change(10, "a");
    e.add_change(30, "c");
    e.add_change(20, "b");            // out-of-order insert lands in the middle
    assert_eq!(e.get_at_time(Some(15)), Some(&"a"));
    assert_eq!(e.get_at_time(Some(20)), Some(&"b"));
    assert_eq!(e.get_at_time(None), Some(&"c"));   // None = latest
    assert_eq!(e.get_at_time(Some(5)), None);
    // equal madeAt inserts AFTER existing equals (TS scans `> madeAt`)
    e.add_change(20, "b2");
    assert_eq!(e.get_at_time(Some(20)), Some(&"b2"));
}
```

- [ ] **Step 2: Implement types.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "admin")] Admin,
    #[serde(rename = "manager")] Manager,
    #[serde(rename = "writer")] Writer,
    #[serde(rename = "reader")] Reader,
    #[serde(rename = "writeOnly")] WriteOnly,
    #[serde(rename = "revoked")] Revoked,
    #[serde(rename = "adminInvite")] AdminInvite,
    #[serde(rename = "managerInvite")] ManagerInvite,
    #[serde(rename = "writerInvite")] WriterInvite,
    #[serde(rename = "readerInvite")] ReaderInvite,
    #[serde(rename = "writeOnlyInvite")] WriteOnlyInvite,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> { /* match on the 11 strings */ }
    pub fn as_str(&self) -> &'static str { /* inverse */ }
    pub fn can_admin(role: Option<Role>) -> bool { matches!(role, Some(Role::Admin) | Some(Role::Manager)) }
    pub fn is_inheritable(role: Option<Role>) -> bool { /* revoked|admin|manager|writer|reader */ }
}

/// Validation-side comparator — permissions.ts:171-181. `a` higher than `b`?
pub fn is_higher_role(a: Role, b: Option<Role>) -> bool { /* port exactly: revoked never higher; admin > manager > writer-over-reader */ }

/// Read-side comparator — group.ts:1693-1727. NOTE: revoked parent role returns true.
pub fn is_more_permissive_and_should_inherit(role_in_parent: Role, role_in_child: Option<Role>) -> bool { /* port the 6-branch table exactly */ }

#[derive(Debug, Clone, PartialEq)]
pub enum ParentRoleMapping { Extend, Capped(Role), Revoked }
// parsed from the parent_<id> change value: "extend" | a role string | "revoked"

pub struct TimeBasedEntry<T> { changes: Vec<(u64, T)> }
impl<T> TimeBasedEntry<T> {
    pub fn new() -> Self { TimeBasedEntry { changes: Vec::new() } }
    pub fn add_change(&mut self, made_at: u64, value: T) {
        let mut idx = self.changes.len();
        while idx > 0 && self.changes[idx - 1].0 > made_at { idx -= 1; }
        self.changes.insert(idx, (made_at, value));
    }
    pub fn get_latest(&self) -> Option<&T> { self.changes.last().map(|(_, v)| v) }
    pub fn get_at_time(&self, at_time: Option<u64>) -> Option<&T> {
        match at_time {
            None => self.get_latest(),
            Some(t) => self.changes.iter().rev().find(|(m, _)| *m <= t).map(|(_, v)| v),
        }
    }
}
```

- [ ] **Step 3: Write failing tests + implement classify.rs**

Port the seven key classifiers with the EXACT TS string logic (`permissions.ts:583-642` — note `isKeyForAccountField`'s odd `||` grouping: `(starts key_ && (contains _for_sealer || _for_co)) || contains _for_everyone`), plus:

```rust
pub fn author_from_session_id(session_id: &str) -> &str {
    // substring before "_session" — accountOrAgentIDfromSessionID.ts
    match session_id.find("_session") { Some(i) => &session_id[..i], None => session_id }
}
pub fn parent_group_id_from_key(key: &str) -> &str { &key["parent_".len()..] }
```

Tests: one case per classifier true/false branch, mirroring the TS shapes (`writeKeyFor_co_z1`, `key_z1_for_key_z2`, `key_z1_for_sealer_z...`, `key_z1_for_everyone`, `key_z1_sealedFor_sealer_z...`, `parent_co_z1`, `child_co_z1`), plus `author_from_session_id("co_zA_session_z123") == "co_zA"`.

- [ ] **Step 4: Run and commit**

Run: `cd crates && cargo test -p cojson-core group_engine::` → green.

```bash
git add crates/cojson-core/src/core/group_engine crates/cojson-core/src/lib.rs
git commit -m "feat(cojson-core): group-engine foundation types and key classifiers"
```

---

### Task 3: Rust transaction view + validation ordering

**Files:**
- Create: `crates/cojson-core/src/core/group_engine/tx_view.rs` (add `pub mod tx_view;` to mod.rs)

- [ ] **Step 1: Write failing tests**

Load `data/group_engine/cross_session_ties.json` and `basic_roles.json` (serde structs for the fixture format defined here too — they'll be reused by later tasks; put them in `tx_view.rs` under `#[cfg(test)] pub(crate) mod fixtures`). Tests assert: transactions extracted per session in insertion order; ordering by the comparator below reproduces a hand-verified order for the ties fixture (derive the expected order once from the fixture's verdict list order semantics — validation state evolution depends on it, so if the order were wrong Task 4's fixtures would fail; here just pin: equal-madeAt cross-session preserves session-insertion order, same-session orders by txIndex, different madeAt orders ascending).

- [ ] **Step 2: Implement**

```rust
/// Extra per-tx info TS supplies (merge-meta-derived source times). Keyed lookup.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PendingTxIn {
    pub session_id: String,
    pub tx_index: u32,
    pub source_made_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct GroupTxView {
    pub session_id: String,
    pub tx_index: u32,
    pub author: String,            // author_from_session_id(session_id)
    pub current_made_at: u64,      // tx.madeAt — used for permission checks
    pub effective_made_at: u64,    // source_made_at.unwrap_or(current_made_at) — used for ORDERING
    pub privacy: Privacy,          // Private | Trusting
    pub changes: Option<Vec<serde_json::Value>>,  // parsed for trusting; None for private
}

/// Build views from a SessionMapImpl: iterate sessions in insertion order (the sessions
/// field is an IndexMap), within each session by tx index; parse each transaction JSON once.
pub fn collect_group_txs(sm: &SessionMapImpl, pending_info: &[PendingTxIn]) -> Vec<GroupTxView> { ... }

/// compareTransactions port (coValueCore.ts:1842-1855) + STABLE sort:
/// effective_made_at asc; equal → same session ? tx_index : keep relative order.
pub fn sort_for_validation(txs: &mut Vec<GroupTxView>) {
    txs.sort_by(|a, b| {
        match a.effective_made_at.cmp(&b.effective_made_at) {
            core::cmp::Ordering::Equal if a.session_id == b.session_id => a.tx_index.cmp(&b.tx_index),
            core::cmp::Ordering::Equal => core::cmp::Ordering::Equal,  // stable sort preserves insertion order
            other => other,
        }
    });
}
```

Use whatever accessor `SessionMapImpl` exposes for raw transactions (`get_session_transactions`/internal session iteration — read `session_map.rs` and use the least-copying path; adding a `pub(crate)` iterator to `SessionMapImpl` is allowed if none fits).

- [ ] **Step 3: Run and commit**

Run: `cd crates && cargo test -p cojson-core group_engine::` → green.

```bash
git add crates/cojson-core/src/core/group_engine
git commit -m "feat(cojson-core): group transaction views with validation ordering"
```

---

### Task 4: Rust GroupEngine — validation + read-side roles

This is the core port. It is one task because validation and role state are one algorithm (spec), but implement in the three internal phases below, running fixture subsets as you go.

**Files:**
- Create: `crates/cojson-core/src/core/group_engine/engine.rs` (add to mod.rs)
- Modify: `crates/cojson-core/src/core/node.rs` (engine storage + registry access)
- Modify: `crates/cojson-core/src/core/session_map.rs` (error variant)

- [ ] **Step 1: Add error variants**

On `SessionMapError` (session_map.rs), add:

```rust
    #[error("CoValue not loaded: {0}")]
    CoValueNotLoaded(String),
```

(`UnknownCoValue` stays for API misuse on the CoValue itself; `CoValueNotLoaded` is for a missing DEPENDENCY — parent group / owning account — and is what TS translates to its `expectCoValueLoaded` throw.)

- [ ] **Step 2: Define the engine structures**

```rust
pub struct Verdict {
    pub session_id: String,
    pub tx_index: u32,
    pub valid: bool,
    pub reason: Option<String>,      // verbatim TS reason string when invalid
}

/// Built by one full validation pass; cached per CoValue keyed by session tx-counts.
pub struct GroupEngineState {
    /// snapshot for cache validity: (session_id, tx_count) at build time
    pub session_counts: Vec<(String, u32)>,
    pub verdicts: Vec<Verdict>,
    /// READ state (time-indexed), built from VALIDATED set-role ops only:
    pub role_history: HashMap<String, TimeBasedEntry<Role>>,          // member -> role over time (madeAt = effective_made_at of the op, matching CoMap op indexing)
    pub parent_history: HashMap<String, TimeBasedEntry<ParentRoleMapping>>, // parent coId -> mapping over time
    /// header facts:
    pub initial_admin: Option<String>,
    pub is_account: bool,            // header meta type == "account" — mirror how TS distinguishes (check RawAccount creation: accountHeaderForInitialAgentSecret; verify against fixtures)
}
```

Validation state (function-local, NOT stored — mirrors `MemberRoleResolver` being rebuilt per call):

```rust
struct ResolverState {
    member_roles: HashMap<String, Role>,                 // plain, time-ignoring (permissions.ts:184-185)
    parent_groups: HashMap<String, ParentRoleMapping>,   // current mappings in validation order
    write_only_keys: HashMap<String, String>,            // member -> KeyID
    write_keys: HashSet<String>,                         // seen writeKeyFor_ change keys
}
```

- [ ] **Step 3: Port the validation loop (`validate_group_covalue`)**

Signature and flow:

```rust
/// Full recompute. `node` gives registry access for parents/accounts.
/// Returns the freshly built state. NEVER incremental (spec: recompute-don't-increment).
pub fn build_group_engine(
    node: &NodeCore,
    co_id: &str,
    pending_info: &[PendingTxIn],
    visited: &mut HashSet<String>,        // cycle guard across recursive builds
) -> Result<GroupEngineState, SessionMapError>
```

Port `determineValidTransactionsForGroup` (`permissions.ts:229-571`) branch by branch, in source order, preserving every reason string verbatim (see the normative list above). Structural mappings:

- `coValue.verifiedTransactions.sort(compareTransactions)` → `sort_for_validation` from Task 3.
- `transaction.author` → `GroupTxView.author`; the `getRoleAtTime(transactor, currentMadeAt)` call → `resolver_role_at(state, node, transactor, current_made_at, visited)?` which reads the PLAIN map for the direct role (time ignored) and does the time-based parent walk: for each `(parent_id, mapping)` in `parent_groups` (skip `Revoked`), `role = role_of_internal(node, parent_id, member, Some(time), visited)?`; if inheritable: resolved = mapping==Extend ? parent_role : capped; if `is_higher_role(resolved, current)` upgrade. (This is `MemberRoleResolver.getRoleAtTime`, `permissions.ts:207-226`.)
- `tx.privacy === "private"` branch: `is_group` = NOT `is_account` (verify against the `private_tx_in_group` fixture — TS `coValue.isGroup()` semantics; the fixture is authoritative).
- Parent-extension branch: `node.get(parent_id)` failing → return `Err(CoValueNotLoaded(parent_id))` (mirrors `expectCoValueLoaded` throwing). "Parent group is not a group" ← parent's header ruleset != group. Self-extension/cycle ← `visited` guard + direct self-reference (mirror `isSelfExtension` — read its TS impl in group.ts when porting).
- On every `markValid` of a set-role change: update BOTH the resolver's plain map AND `role_history.add_change(effective_made_at, role)`; parent set/revoke updates `parent_groups` AND `parent_history`.
- Verdicts pushed for EVERY transaction in validation order.

- [ ] **Step 4: Port read-side `role_of_internal`**

```rust
/// group.ts:451-488 + account.ts:68-75 overrides. at_time None = latest.
pub fn role_of_internal(
    node: &NodeCore,
    group_id: &str,
    member: &str,
    at_time: Option<u64>,
    visited: &mut HashSet<String>,
) -> Result<Option<Role>, SessionMapError>
```

- Ensures the group's engine is fresh (see Step 5) — building it recursively if needed.
- Account override first: if the engine `is_account` and `member == group_id` → `Some(Admin)`.
- Direct role: `role_history[member].get_at_time(at_time)`; `Revoked` → treated as none for `role_here` (but keep the raw value: the parent-walk result may still produce Revoked per `is_more_permissive_and_should_inherit`).
- Parent walk: for each parent in `parent_history`, mapping at `at_time`; skip none/Revoked mapping; recurse `role_of_internal(node, parent_id, member, at_time, visited)` (cycle guard: if parent already in `visited`, skip that edge); filter by `Role::is_inheritable`; `Extend` inherits parent role else capped; upgrade via `is_more_permissive_and_should_inherit`.
- Everyone fallback: only if no role resolved and `member != "everyone"`: `role_history["everyone"].get_at_time(at_time)` unless Revoked.
- Transactor-is-account resolution for validation (`agentInAccountOrMemberInGroup`, `permissions.ts:573-581`) — implemented where the VALIDATOR needs it: if transactor == the covalue's id and the covalue is an account → resolve to the account's static header agent (`initial_admin` from the header, which for accounts IS the agent id — `account.ts:44-62`).

- [ ] **Step 5: NodeCore integration + freshness**

In `node.rs`:

```rust
pub struct CoValueEntry {                 // refactor: HashMap<String, SessionMapImpl> becomes HashMap<String, CoValueEntry>
    pub session_map: SessionMapImpl,
    pub group_engine: Option<GroupEngineState>,
}
```

(Adjust `get`/`get_mut` to return `&CoValueEntry`/`&mut CoValueEntry` OR keep signatures returning the session map and add `entry`/`entry_mut` — pick whichever keeps the napi/binding diff smallest; the stage-1 binding calls `get(...)?.method(...)` on the session map.)

```rust
impl NodeCore {
    /// Rebuild engine iff session tx-counts changed since last build (full recompute).
    fn ensure_engine(&mut self, co_id: &str, pending: &[PendingTxIn], visited: &mut HashSet<String>) -> Result<(), SessionMapError> { ... }

    pub fn validate_group(&mut self, co_id: &str, pending: &[PendingTxIn]) -> Result<Vec<Verdict>, SessionMapError> {
        let mut visited = HashSet::new();
        self.ensure_engine(co_id, pending, &mut visited)?;
        Ok(self.entry(co_id)?.group_engine.as_ref().unwrap().verdicts.clone())
    }

    pub fn role_of(&mut self, group_id: &str, member: &str, at_time: Option<u64>) -> Result<Option<Role>, SessionMapError> {
        let mut visited = HashSet::new();
        role_of_internal(self, group_id, member, at_time, &mut visited).map(...)
    }
}
```

NOTE on borrows: recursive engine builds over `&mut self` won't borrow-check naively. Acceptable approaches (pick one, document it): (a) two-phase — collect the dependency closure first (walk parent ids from raw transactions), build engines bottom-up iteratively; (b) take the engine out of the entry during build (`Option::take`), put it back after. Do NOT clone entire session maps. Cycle guard applies in both.

- [ ] **Step 6: Fixture tests — the main gate**

One test per fixture file (all 18): load JSON, `NodeCore::new()`, `create_co_value(skip_verify=true)` + `add_transactions(skip_verify=true)` for every covalue/session, then:
- `validate_group(coId, pending=[])` for each verdict-bearing covalue → verdict list must equal the fixture's (order, valid flags, and reason strings EXACTLY).
- every `roleQuery` → `role_of` result string (or None) equals `expectedRole`.

Run: `cd crates && cargo test -p cojson-core group_engine::` → all 18 fixture tests green. Debug divergences by comparing against the TS oracle files — fixtures are authoritative; the TS source tells you WHY.

- [ ] **Step 7: Commit**

```bash
git add crates/cojson-core/src/core
git commit -m "feat(cojson-core): GroupEngine — group validation and role resolution over NodeCore"
```

---

### Task 5: Napi binding for validateGroup / roleOf

**Files:**
- Modify: `crates/cojson-core-napi/src/lib.rs`

- [ ] **Step 1: Add napi types + methods**

```rust
#[napi(object)]
pub struct PendingTx {
  pub session_id: String,
  pub tx_index: u32,
  pub source_made_at: Option<f64>,
}

#[napi(object)]
pub struct GroupVerdict {
  pub session_id: String,
  pub tx_index: u32,
  pub valid: bool,
  pub reason: Option<String>,
}

#[napi]
impl NodeCore {
  /// Validate a group/account CoValue; verdicts for ALL its transactions in validation order.
  #[napi]
  pub fn validate_group(&mut self, co_id: String, pending: Vec<PendingTx>) -> napi::Result<Vec<GroupVerdict>> { /* convert, delegate, map_err(to_napi_err) */ }

  /// Role of member in group at time (ms). Returns the role string or null.
  #[napi]
  pub fn role_of(&mut self, group_id: String, member: String, at_time: Option<f64>) -> napi::Result<Option<String>> { ... }
}
```

Error mapping note: `CoValueNotLoaded` must stay distinguishable in JS — it flows through `to_napi_err` as message `"CoValue not loaded: co_z..."`; TS matches on that prefix (Task 7). Keep the message format stable.

- [ ] **Step 2: Build + smoke test**

Run: `pnpm build:napi`. Then from `packages/cojson`:

```bash
node -e "
const { NodeCore } = require('cojson-core-napi');
const n = new NodeCore();
try { n.validateGroup('co_zNope', []); } catch (e) { console.log('unknown ok:', /Unknown CoValue/.test(e.message)); }
try { n.roleOf('co_zNope', 'co_zX'); } catch (e) { console.log('unknown ok2:', /Unknown CoValue/.test(e.message)); }
"
```

Expected: both `ok: true` lines. Confirm `index.d.ts` gained `validateGroup`, `roleOf`, `PendingTx`, `GroupVerdict`.

- [ ] **Step 3: Commit**

```bash
git add crates/cojson-core-napi
git commit -m "feat(cojson-core-napi): expose validateGroup and roleOf on NodeCore"
```

---

### Task 6: TS capability surface

**Files:**
- Modify: `packages/cojson/src/crypto/crypto.ts` (optional methods on `NodeCoreImpl`)
- Modify: `packages/cojson/src/crypto/NapiCrypto.ts` (adapter implements them)
- Test: `packages/cojson/src/tests/shimNodeCore.test.ts` (extend)

- [ ] **Step 1: Extend NodeCoreImpl (optional = capability detection)**

```ts
export type NodeCorePendingTx = {
  sessionId: string;
  txIndex: number;
  sourceMadeAt?: number;
};
export type NodeCoreGroupVerdict = {
  sessionId: string;
  txIndex: number;
  valid: boolean;
  reason?: string;
};

export interface NodeCoreImpl {
  // ...existing...
  /** Native group validation (stage 2). Absent on providers without a native NodeCore. */
  validateGroup?(coId: string, pending: NodeCorePendingTx[]): NodeCoreGroupVerdict[];
  /** Native role resolution (stage 2). Absent on providers without a native NodeCore. */
  roleOf?(groupId: string, member: string, atTime?: number): string | undefined;
}
```

`ShimNodeCore` intentionally does NOT implement them (TS fallback runs).

- [ ] **Step 2: Implement on NapiNodeCoreAdapter**

```ts
  validateGroup(coId: string, pending: NodeCorePendingTx[]): NodeCoreGroupVerdict[] {
    return this.nodeCore.validateGroup(coId, pending).map((v) => ({
      sessionId: v.sessionId,
      txIndex: v.txIndex,
      valid: v.valid,
      reason: v.reason ?? undefined,
    }));
  }

  roleOf(groupId: string, member: string, atTime?: number): string | undefined {
    return this.nodeCore.roleOf(groupId, member, atTime) ?? undefined;
  }
```

- [ ] **Step 3: Extend the registry tests**

In shimNodeCore.test.ts add to the parameterized suite: shim → `expect(nodeCore.validateGroup).toBeUndefined()`; native → `expect(typeof nodeCore.validateGroup).toBe("function")` and an unknown-coId throw assertion for both methods. Run: `pnpm test shimNodeCore` → green. `pnpm exec tsc --noEmit` → clean.

- [ ] **Step 4: Commit**

```bash
git add packages/cojson/src/crypto packages/cojson/src/tests/shimNodeCore.test.ts
git commit -m "feat(cojson): optional native validateGroup/roleOf on NodeCoreImpl"
```

---

### Task 7: TS delegation — permissions.ts group branch

**Files:**
- Modify: `packages/cojson/src/permissions.ts`

- [ ] **Step 1: Write the delegation**

In `determineValidTransactions` (`permissions.ts:73`), the `ruleset.type === "group"` branch becomes:

```ts
  if (coValue.verified.header.ruleset.type === "group") {
    const initialAdmin = coValue.verified.header.ruleset.initialAdmin;
    if (!initialAdmin) {
      throw new Error("Group must have initialAdmin");
    }

    const nodeCore = coValue.node.nodeCore;
    if (nodeCore.validateGroup && !nativeValidationDisabled()) {
      determineValidTransactionsForGroupNative(coValue, nodeCore);
    } else {
      determineValidTransactionsForGroup(coValue, initialAdmin);
    }
    return;
  }
```

Also add the kill switch helper (exported so group.ts and the differential
harness reuse it) — browser-safe (`process` may not exist in wasm/browser
environments):

```ts
/** Operational kill switch + differential-test escape hatch. */
export function nativeValidationDisabled(): boolean {
  return (
    (globalThis as { process?: { env?: Record<string, string> } }).process
      ?.env?.COJSON_DISABLE_NATIVE_VALIDATION === "1"
  );
}
```

```ts
function determineValidTransactionsForGroupNative(
  coValue: CoValueCore,
  nodeCore: NodeCoreImpl,
): void {
  const pending: NodeCorePendingTx[] = [];
  for (const tx of coValue.verifiedTransactions) {
    if (tx.sourceTxMadeAt !== undefined) {
      pending.push({
        sessionId: tx.currentTxID.sessionID,
        txIndex: tx.currentTxID.txIndex,
        sourceMadeAt: tx.sourceTxMadeAt,
      });
    }
  }
  const verdicts = nodeCore.validateGroup!(coValue.id, pending);

  const byKey = new Map<string, VerifiedTransaction>();
  for (const tx of coValue.verifiedTransactions) {
    byKey.set(`${tx.currentTxID.sessionID}/${tx.currentTxID.txIndex}`, tx);
  }
  // Apply IN THE ORDER RUST RETURNS (spec: dispatch order feeds downstream stable sorts)
  for (const v of verdicts) {
    const tx = byKey.get(`${v.sessionId}/${v.txIndex}`);
    if (!tx) continue; // verdict for a tx TS hasn't wrapped yet — next parseNewTransactions pass picks it up
    if (v.valid) {
      tx.markValid();
    } else {
      tx.markInvalid(v.reason ?? "Invalid group transaction", {
        transactor: tx.author,
      });
    }
  }
}
```

Error translation: wrap the `nodeCore.validateGroup` call in try/catch; if `e.message` starts with `"CoValue not loaded: "`, re-throw via the same path TS uses today — call `coValue.node.expectCoValueLoaded(extractedId, "Expected parent group to be loaded")` (which throws the canonical error). Otherwise rethrow.

- [ ] **Step 2: Run the oracle suites against the native path**

Run: `cd packages/cojson && pnpm test permissions && pnpm test group` (NapiCrypto default makes these exercise the Rust path).
Expected: green. Any failure is a Rust-port divergence — fix in Rust (fixtures should have caught it; add the failing case as a new fixture scenario first, then fix).

- [ ] **Step 3: Full suite + commit**

Run: `pnpm test` (full cojson) + `pnpm exec tsc --noEmit`.

```bash
git add packages/cojson/src/permissions.ts
git commit -m "feat(cojson): delegate group permission validation to native NodeCore"
```

---

### Task 8: TS delegation — group.ts roleOfInternal

**Files:**
- Modify: `packages/cojson/src/coValues/group.ts`

- [ ] **Step 1: Write the gated delegation**

In `RawGroup.roleOfInternal` (`group.ts:451`), add at the top:

```ts
    const nodeCore = this.core.node.nodeCore;
    if (
      nodeCore.roleOf &&
      !nativeValidationDisabled() &&                       // shared kill switch from permissions.ts (Task 7)
      this.core.verified.branchSourceId === undefined &&  // branch views keep TS semantics in stage 2
      !this.hasFrontierFilter()                            // any frontier/time-travel machinery beyond atTimeFilter — check what exists on RawCoMap; if only atTimeFilter exists, drop this condition
    ) {
      const role = nodeCore.roleOf(this.core.id, accountID, this.atTimeFilter);
      return role as Role | undefined;
    }
    // ...existing TS implementation unchanged (fallback)...
```

IMPORTANT gating caveats to resolve while implementing (read the actual RawCoMap/RawGroup view machinery):
- `atTime` views are prototype clones — `this.core` is shared, so `this.core.id` is correct on views.
- If `RawCoMap` has additional read filters beyond `atTimeFilter` (frontier/branch filters — grep for other filter fields on the class), the delegation must be skipped when they're active; enumerate them and gate on each.
- `RawAccount.roleOfInternal` override (self → admin) stays in TS and short-circuits BEFORE calling super — Rust implements it too, so either path is consistent.

- [ ] **Step 2: Verify against the read-side oracle suites**

Run: `cd packages/cojson && pnpm test group.roleOf && pnpm test group.inheritance && pnpm test group` → green.
Then FULL cojson suite + `tsc --noEmit` → green.

- [ ] **Step 3: Commit**

```bash
git add packages/cojson/src/coValues/group.ts
git commit -m "feat(cojson): delegate group role resolution to native NodeCore"
```

---

### Task 9: Randomized differential harness

**Files:**
- Create: `packages/cojson/src/tests/groupEngineDifferential.test.ts`

- [ ] **Step 1: Write the harness**

A seeded PRNG (e.g. mulberry32, seed logged on failure and overridable via `DIFF_SEED` env) drives N=50 random group scenarios: random member count (2-5 accounts), random operation sequences (addMember with random roles, removeMember, invites + acceptances, parent extensions incl. extend/capped, revocations, everyone roles), interleaved across members. For each scenario:

1. Build the scenario on a test node (native crypto).
2. Compute verdicts + a grid of role queries (every member × 3 random timestamps + latest) via the **TS path**: set `COJSON_DISABLE_NATIVE_VALIDATION=1` through the `nativeValidationDisabled()` kill switch already wired into both gates in Tasks 7-8 (in vitest, stub it via `vi.stubEnv` or set/unset `globalThis.process.env` around the TS-path run), forcing `determineValidTransactionsForGroup` and TS `roleOfInternal`.
3. Compute the same via the **native path** (gate enabled).
4. Assert deep equality of: every transaction's `(isValid, validationErrorMessage)` and every role query result.

- [ ] **Step 2: Run it**

Run: `cd packages/cojson && pnpm test groupEngineDifferential` → green, reasonable runtime (<60s; reduce N if slower).
Also run once with a different seed (`DIFF_SEED=1234`) to shake out seed-dependence.

- [ ] **Step 3: Commit**

```bash
git add packages/cojson/src/tests/groupEngineDifferential.test.ts packages/cojson/src/permissions.ts packages/cojson/src/coValues/group.ts
git commit -m "test(cojson): randomized differential harness for native group engine"
```

---

### Task 10: Cross-package verification + changeset + spec status

- [ ] **Step 1: Full verification**

- `pnpm build:packages` (repo root) → green (skip the RN NDK step if the environment lacks an Android NDK — known limitation).
- `pnpm exec turbo run test --filter=cojson --filter=jazz-tools` → green. jazz-tools runs the wasm/shim (fallback) path — proving the capability gate keeps non-native providers working.
- `cd crates && cargo test -p cojson-core` → green; `cargo clippy -p cojson-core -p cojson_core_napi` → no NEW warnings vs the branch base (pre-existing set documented in the stage-1 plan run: doc_lazy_continuation in docs, blake3.rs:55, session_map.rs make_new_private_transaction).

- [ ] **Step 2: Benchmarks (spec testing layer 4)**

Add `bench/cojson/groupEngine.bench.ts` (mirror the structure of existing files under `bench/`): (a) `roleOf` on a 3-level parent chain with 20 members, queried 1000×; (b) full validation of a 200-transaction group (invalidate + re-validate via `COJSON_DISABLE_NATIVE_VALIDATION` toggling for the TS baseline vs native). Run `pnpm bench:cojson` (or the repo's actual bench script — check bench/package.json) and record both numbers in the PR description. The kill switch makes the TS baseline measurable at any time, so no pre-landing baseline capture is needed.

- [ ] **Step 3: Changeset**

`.changeset/group-engine-native.md`:

```markdown
---
"cojson": patch
"cojson-core-napi": patch
---

Move group/account permission validation and role resolution into the native
NodeCore (napi), behind capability detection — wasm/RN keep the TypeScript
path until their native ports land. Adds a fixture corpus generated from the
TypeScript implementation and a randomized differential test harness.
```

- [ ] **Step 4: Update the spec status line**

In `docs/superpowers/specs/2026-07-03-cojson-rust-permissions-migration-design.md`, note under Stage 2 that it is implemented napi-first with the `COJSON_DISABLE_NATIVE_VALIDATION` kill switch and branch-view role queries still on the TS path.

- [ ] **Step 5: Commit**

```bash
git add .changeset docs/superpowers/specs bench
git commit -m "chore: changeset and spec status for native group engine"
```

---

## Explicitly out of scope (later plans)

- Stage 3 (`validateTransactions` for ownedByGroup/unsafeAllowAll, `resetValidation`, PendingTx meta plumbing) — next plan.
- Wasm/RN native `NodeCore` + group engine ports; deletion of the TS permissions logic and the differential harness — final cleanup after all bindings reach parity.
- Branch-view (`branchSourceId`) role-query delegation — kept on the TS path in stage 2; revisit in stage 3 with branch fixtures.

## Known risks to watch during execution

- **Account vs group semantics** (`isGroup()` in the private-tx branch, account header detection): resolved empirically by fixtures 15 and 18 — the fixture output is authoritative, don't guess.
- **Rust borrow structure for recursive engine builds** (Task 4 Step 5): decide the two-phase vs take-and-put-back approach early; it shapes the whole engine module.
- **`madeAt` used for role_history indexing** must be the same time base the TS CoMap op index uses (`madeAt` getter = effective time) — fixtures 10-13 with time-based queries pin this; if they fail, check effective vs current time first.
- **Verdict application order** feeds TS dispatch order (spec fidelity constraint 2) — the Task 7 code applies in Rust-returned order; don't "optimize" into map iteration.
