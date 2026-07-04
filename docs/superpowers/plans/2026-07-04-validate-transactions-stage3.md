# Unified validateTransactions (Stage 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the native permission engine: TypeScript delegates ALL ruleset branches (group, ownedByGroup, unsafeAllowAll) through one `validateTransactions(coId, pending)` entry point with decrypted-meta plumbing and the `validBranchPointerOnly` outcome, plus `resetValidation(coId)` wired into TS's dependant-revalidation walk.

**Architecture:** The Rust engine (stage 2) already dispatches all three rulesets internally — stage 3 (a) surfaces per-transaction decrypted meta and source txIDs through `PendingTxIn` so the reader branch-pointer case and merged-transaction tie-breaks become portable, (b) upgrades `Verdict` to a three-outcome enum, (c) renames the public entry to `validate_transactions` (subsuming `validate_group` per the spec) and adds `reset_validation`, and (d) moves the TS delegation gate up from the group branch to the top of `determineValidTransactions`, keeping the reader-branch trimming (`tx.changes = []`) in TS. The kill switch, capability detection, fixture corpus, and differential harness all extend rather than change shape.

**Tech Stack:** Rust (cojson-core), napi-rs (cojson-core-napi), TypeScript (packages/cojson), vitest, cargo test.

**Spec:** `docs/superpowers/specs/2026-07-03-cojson-rust-permissions-migration-design.md` — "Stage 3" section + "Fidelity constraints (normative)". REQUIRED READING for every task: `docs/superpowers/plans/2026-07-04-group-engine-porter-notes.md` (16 verified behavioral notes; notes 9, 12, 13, 14, 16 are stage-3-specific).

**Prerequisite:** Stage 2 landed (branch `cojson-group-engine`, PR #3532). Engine: `crates/cojson-core/src/core/group_engine/` (engine.rs dispatches group/ownedByGroup/unsafeAllowAll; reader branch-pointer intentionally unported at engine.rs ~762 with a stage-3 breadcrumb). TS: `permissions.ts` group-branch delegation + `nativeValidationDisabled()` kill switch; `NodeCoreImpl.validateGroup?/roleOf?`.

**Working notes:**
- Build napi: `pnpm build:napi` (repo root). Rust: `cargo test -p cojson-core` from `crates/` (baseline 137). TS: `pnpm test` in `packages/cojson` (baseline 1418/13 skipped).
- jazz-tools baseline: 2120 passed / 8 skipped. `pnpm build:packages` (RN NDK build unavailable in this env — skip).
- No Claude/AI mentions in commits.

## What stage 3 must preserve from TS (the remaining unported semantics)

| Behavior | TS source |
| --- | --- |
| Reader branch-pointer: reader with `tx.meta.branch` + `tx.meta.ownerId` → forced trim `tx.meta = {branch, ownerId}`, `tx.changes = []`, then VALID | `permissions.ts:124-137` |
| ownedByGroup checks use `currentMadeAt` (never effective) for the group role query | `permissions.ts:104-107` |
| Validation runs BEFORE decryption: freshly received private txs validate with `meta === undefined`; only locally-created (parsing cache) or re-validated txs carry meta | `coValueCore.ts:1581-1602`, spec Stage 3 contract |
| `resetParsedTransactions` re-validates everything (triggered by `invalidateDependants` when a group changes) | `coValueCore.ts:1317-1354` |
| Merged-tx tie-break identity: TS `compareTransactions` uses `txID = sourceTxID ?? currentTxID` for same-"session" ties | porter note 9; `coValueCore.ts:157-165` |

---

### Task 1: Stage-3 fixture scenarios (extend the exporter)

**Files:**
- Modify: `packages/cojson/src/tests/groupEngineFixtures.export.test.ts`
- Create: `crates/cojson-core/data/group_engine/owned_*.json`, `unsafe_allow_all.json`, `merged_tx_ties.json` (generated, committed)

- [ ] **Step 1: Add scenarios** (same exporter mechanics; verdicts read from `core.verifiedTransactions` after `getValidTransactions({})`; each scenario ALWAYS asserts internal consistency):

1. `owned_by_group_roles` — a map owned by a group; writes by admin/manager/writer/writeOnly (valid), reader (invalid: `Transactor has no write permissions`), non-member (invalid: check the exact TS reason — `Transactor not found in group` fires when `agentInAccountOrMemberInGroup` returns undefined; capture what TS actually produces).
2. `owned_by_group_role_change_over_time` — member demoted mid-history; their earlier writes stay valid (role at `currentMadeAt`), later writes invalid; include a roleQuery grid.
3. `owned_by_account` — a covalue owned by an ACCOUNT (account as ownedByGroup target): the account's own agent writes (exercises `agentInAccountOrMemberInGroup` account→agent resolution on the owned path).
4. `owned_reader_branch_pointer` — a reader posting a branch-pointer transaction (`meta.branch` + `meta.ownerId`): TS marks it VALID and trims changes/meta. Export the verdict AND a `trimmed: true` marker per affected tx (extend the fixture verdict schema with an optional `outcome` field: `"valid" | "invalid" | "validBranchPointerOnly"` — derive `validBranchPointerOnly` by detecting the TS trim: valid + reader role + branch meta). Study how branches are created in existing branch tests (grep `meta.branch` / `ownerId` in src/tests) and reuse that idiom; if a reader branch-pointer cannot be produced through public APIs, craft the raw transaction the way permissions.test.ts crafts hostile txs.
5. `owned_private_tx_meta_unavailable` — a RECEIVED private transaction on an owned covalue (meta undefined at validation): pin whatever TS produces (per the pipeline-order contract).
6. `unsafe_allow_all` — covalue with unsafeAllowAll ruleset: everything valid, including garbage changes.
7. `merged_tx_ties` — transactions carrying merge meta (`sourceTxMadeAt`, `sourceTxID`) such that effective-madeAt ordering and the sourceTxID tie-break MATTER (two txs, same effective madeAt, same SOURCE session, different current sessions — TS orders by source txIndex). Reuse how branch-merge tests construct merged transactions. If constructing a meaningful sourceTxID tie proves impractical through real APIs, document that in the fixture description and pin ordering-insensitive verdicts instead (multiset), noting the gap for the Rust test.

Fixture schema addition: verdict entries gain optional `"outcome"` (absent = derive from `valid`) and pending-relevant fields exported per tx where present: `"sourceMadeAt"`, `"sourceTxId": {"sessionID","txIndex"}`, `"metaJson"` (the DECRYPTED meta TS had at validation time, null when unavailable).

- [ ] **Step 2: Run without export (consistency green), with export (files written), spot-check `owned_reader_branch_pointer` by eye** (outcome field present, reason null, trimmed marker correct).

- [ ] **Step 3: Commit**

```bash
git add packages/cojson/src/tests/groupEngineFixtures.export.test.ts crates/cojson-core/data/group_engine
git commit -m "test(cojson): stage-3 fixture scenarios for ownedByGroup and merged transactions"
```

---

### Task 2: Rust — pending plumbing (meta, sourceTxId) + Verdict outcome enum

**Files:**
- Modify: `crates/cojson-core/src/core/group_engine/tx_view.rs`
- Modify: `crates/cojson-core/src/core/group_engine/engine.rs`

- [ ] **Step 1 (TDD):** extend `PendingTxIn` with `meta_json: Option<String>` and `source_tx_id: Option<(String, u32)>` (serde: `sourceTxId` object with `sessionID`/`txIndex`); `GroupTxView` gains `meta: Option<serde_json::Value>` — populated from pending's decrypted meta_json when present, else from the TRUSTING tx's own `meta` field (parse it — trusting meta is plaintext on the wire; check the Transaction serde type), else None. Also `source_session_id: Option<String>` + `source_tx_index: Option<u32>` for the tie-break.
- [ ] **Step 2:** `sort_for_validation` tie-break upgraded per porter note 9: same-"session" comparison uses the SOURCE identity when present (`txID = sourceTxID ?? currentTxID` semantics from coValueCore.ts:157-165 — two txs compare by txIndex when their effective session ids are equal, where effective session id = source session if present else current). Pin with a unit test constructing the tie synthetically.
- [ ] **Step 3:** `Verdict` gains `outcome: VerdictOutcome` (`Valid | Invalid | ValidBranchPointerOnly`) while KEEPING `valid: bool` in sync (valid = outcome != Invalid) so stage-2 fixture tests keep passing unchanged; reason only on Invalid.
- [ ] **Step 4:** `cargo test -p cojson-core` green (137 + new unit tests). Commit: `feat(cojson-core): pending meta and source-identity plumbing for stage 3`.

---

### Task 3: Rust — reader branch-pointer port + validate_transactions + reset_validation

**Files:**
- Modify: `crates/cojson-core/src/core/group_engine/engine.rs`, `crates/cojson-core/src/core/node.rs`

- [ ] **Step 1 (TDD with Task 1 fixtures):** port `permissions.ts:124-137` at the engine.rs stage-3 breadcrumb (~line 762): reader role + `meta.branch` + `meta.ownerId` present → `VerdictOutcome::ValidBranchPointerOnly` (classification only; trimming stays in TS). Confirm against `owned_reader_branch_pointer.json`.
- [ ] **Step 2:** `NodeCore::validate_transactions(co_id, pending)` = rename of `validate_group` (public surface; keep an inline comment noting the stage-2 name). Update the two stage-2 error-taxonomy tests and all fixture tests to the new name. `validate_group` REMOVED (spec: subsumed).
- [ ] **Step 3:** `NodeCore::reset_validation(co_id)` — drops the cached engine for that coValue (absent id = no-op, mirroring removeCoValue; UnknownCoValue would be hostile to the TS caller which fires it on dependants that may not be registered — decide: no-op, and document). Unit test: validate → reset → validate rebuilds (probe via a counter or by asserting cache-miss behavior with changed pending).
- [ ] **Step 4:** run ALL fixture tests (stage 2's 18 + stage 3's 7) green. Full crate green. Commit: `feat(cojson-core): unified validate_transactions with branch-pointer outcome and reset`.

---

### Task 4: Napi — validateTransactions/resetValidation, retire validateGroup

**Files:**
- Modify: `crates/cojson-core-napi/src/lib.rs` (+ regenerated index.d.ts)

- [ ] `PendingTx` gains `metaJson: Option<String>`, `sourceTxId: Option<SourceTxId>` (`#[napi(object)] SourceTxId { session_id, tx_index }`); `GroupVerdict` gains `outcome: String` ("valid"/"invalid"/"validBranchPointerOnly") keeping `valid: bool`. `validate_transactions` + `reset_validation` exposed; `validate_group` DELETED from the binding (grep packages/ for `validateGroup` usages first — the TS adapter (crypto.ts/NapiCrypto.ts) still references it and gets updated in Task 5; napi + TS must land in the SAME task sequence but different commits are fine since only this branch consumes the binding).
- [ ] `pnpm build:napi`; smoke test from packages/cojson (unknown primary → /Unknown CoValue/ for validateTransactions AND resetValidation no-op on unknown returns cleanly). Error-contract doc comments carried over. Commit: `feat(cojson-core-napi): unified validateTransactions and resetValidation`.

---

### Task 5: TS surface swap

**Files:**
- Modify: `packages/cojson/src/crypto/crypto.ts`, `packages/cojson/src/crypto/NapiCrypto.ts`, `packages/cojson/src/tests/shimNodeCore.test.ts`

- [ ] `NodeCoreImpl`: `validateGroup?` REPLACED by `validateTransactions?(coId, pending: NodeCorePendingTx[]): NodeCoreGroupVerdict[]` (PendingTx type gains `metaJson?`, `sourceTxId?`; verdict type gains `outcome`), plus `resetValidation?(coId): void`. Keep the capability/error-contract doc comments (never-stub warning). Adapter updated (outcome passthrough, `reason ?? undefined`). Capability tests updated: native has all three (validateTransactions/roleOf/resetValidation), shim none. tsc + shimNodeCore tests green. Commit: `feat(cojson): unified validateTransactions on NodeCoreImpl`.

---

### Task 6: TS delegation — full dispatch + trimming + resetValidation wiring

**Files:**
- Modify: `packages/cojson/src/permissions.ts`, `packages/cojson/src/coValueCore/coValueCore.ts`

- [ ] **Step 1:** in `determineValidTransactions`, hoist the native gate ABOVE the ruleset dispatch: when `nodeCore.validateTransactions && !nativeValidationDisabled()`, call `determineValidTransactionsNative(coValue, nodeCore)` for ALL three ruleset types; TS fallback dispatch unchanged below. The native helper (rename/extend the stage-2 one):
  - pending: for EVERY verifiedTransaction, include entry only when it has extras: `sourceMadeAt` (as before), `sourceTxId` (from `tx.sourceTxID` — check the exact field name on VerifiedTransaction), or decrypted meta available NOW (`tx.meta !== undefined` for private txs — pass `metaJson: JSON.stringify(tx.meta)`; trusting meta is wire-visible so Rust reads it itself — do NOT send it).
  - verdict application: `outcome === "validBranchPointerOnly"` → replicate `permissions.ts:124-137` trimming in TS (`tx.meta = {branch, ownerId}` from tx.meta, `tx.changes = []`) then `markValid()`; `"valid"` → markValid; `"invalid"` → markInvalid(reason). Keep returned-order application + skip-if-unwrapped + error translation (now the missing dependency can be the OWNING GROUP: translate with message `"Determining valid transaction in owned object but its group wasn't loaded"` — check the exact TS string at permissions.ts:95 and route through expectCoValueLoaded with THAT description for ownedByGroup covalues, keeping the parent-group description for group covalues; simplest faithful approach: pick the description by the covalue's ruleset type).
- [ ] **Step 2:** `resetParsedTransactions` (coValueCore.ts:1317) calls `this.node.nodeCore.resetValidation?.(this.id)` at its start (optional-chained — shim-safe).
- [ ] **Gates:** permissions + group + coValueCore + branch/merge suites native AND kill-switched; FULL suite; tsc. Native-only failure = divergence = BLOCKED with repro. Commit: `feat(cojson): delegate all permission validation to native NodeCore`.

---

### Task 7: Differential harness extension

**Files:**
- Modify: `packages/cojson/src/tests/groupEngineDifferential.test.ts`

- [ ] Add ownedByGroup ops to the generator: create 1-2 maps owned by the scenario group; random map writes by random members (valid and unauthorized); compare map verdicts too. Porter note 16 applies: scenarios must not generate meta-only/empty-changes txs, OR wrapper verdicts must be reset between passes — assert which. Keep N/runtime bounds; DIFF_SEED and default both green; note the final N. Commit: `test(cojson): extend differential harness to owned covalues`.

---

### Task 8: Verify + changeset + spec status

- [ ] `pnpm build:packages`; cojson full suite; `pnpm exec turbo run test --filter=jazz-tools` (baseline 2120/8 — regression triage vs merge-base if red); `cargo test -p cojson-core`; clippy no-new-warnings triage.
- [ ] Re-run `bench/cojson/groupEngine.bench.ts` (same runner convention) — validateTransactions path numbers into the report/PR.
- [ ] Changeset `.changeset/validate-transactions-native.md` (`cojson` + `cojson-core-napi` patch): unified native validateTransactions, branch-pointer outcome, resetValidation; wasm/RN still TS-path.
- [ ] Spec: Status note under Stage 3 (implemented napi-first; what remains for cleanup: wasm/RN ports, TS deletion, `validateGroup` gone).
- [ ] Commits: changeset+spec as one; bench numbers in report.

---

## Out of scope (final cleanup phase, after wasm/RN native ports)

Deleting the TS permission logic, `MemberRoleResolver`, `roleOfInternal` internals, the shim, kill switch, and the differential harness — the spec's "TypeScript deletion (end state)" section.

## Risks

- **Branch-pointer fixture construction** (Task 1.4) may require crafting raw transactions; the fixture is the contract for the Rust port — if TS's branch APIs can't produce the shape, escalate rather than approximate.
- **Merged-tx source-identity ties** (Tasks 1.7/2.2): if real APIs can't construct a meaningful tie, the Rust tie-break still ships (unit-tested synthetically) but fixture coverage is documented as synthetic-only.
- **Hoisting the gate above the dispatch** (Task 6) changes behavior for ownedByGroup covalues whose owning group isn't registered natively — the error-translation description must match per-ruleset; the full branch/merge suites are the gate.
