# Deletion inventory — Cleanup Phase Part C (Task C1)

> **Purpose:** authoritative decision on exactly what the deletion PR (C2) may
> remove. Every entry was verified by reading callers, not by assumption. A wrong
> DELETE here becomes a wrong deletion in C2.
>
> **HEAD when produced:** `be0c5203d` (Part B tip — RN NodeCore adapter merged).
> **Scope basis:** `docs/superpowers/plans/2026-07-04-cleanup-phase.md` Part C +
> `docs/superpowers/plans/2026-07-04-group-engine-porter-notes.md` (esp. note 17).

Classifications: **DELETE** (remove entirely), **KEEP** (survives, reason given),
**NARROW** (survives but a kill-switch/optionality/fallback branch inside it is removed).

## Ground truth established

- All three providers now `override createNodeCore()` returning a **native**
  adapter that wraps a native `NodeCore` (`WasmNodeCore`/`RNNodeCore`/napi) —
  `NapiCrypto.ts:238`, `WasmCrypto.ts:283`, `RNCrypto.ts:209`. None of these
  adapters touch `createSessionMap`/`SessionMapAdapter` (verified `WasmCrypto.ts:283-285`).
- The base `CryptoProvider.createNodeCore()` (`crypto.ts:307`) is the **only**
  remaining producer of `ShimNodeCore`, and `ShimNodeCore` is the **only**
  runtime consumer of `createSessionMap` / `SessionMapImpl` / `SessionMapAdapter`.
- `VerifiedState` addresses everything through `nodeCore.*` (verified
  `verifiedState.ts:83-669`), never `createSessionMap`. So once the shim dies,
  the entire per-CoValue `SessionMap` path is dead code.
- `SessionMapImpl.dispose?()` has exactly one caller family: the shim
  (`ShimNodeCore.ts:41,51`). Every other `.dispose(` hit in the tree is an
  unrelated scheduler (`storageAsync.ts:581`, `storageSync.ts:555`, eraser tests).

## Inventory table

| # | Item | Class | Evidence (file:line) | Notes |
|---|------|-------|----------------------|-------|
| **permissions.ts** |
| 1 | `determineValidTransactionsForGroup` | DELETE | def `permissions.ts:390`; only caller `permissions.ts:111` (the group fallback branch, itself deleted) | TS group engine; native path (`determineValidTransactionsNative`) subsumes it. |
| 2 | `MemberRoleResolver` (class) | DELETE | def `permissions.ts:209`; only use `permissions.ts:398` (inside #1) | Role-resolution helper for the TS group engine only. |
| 3 | `isHigherRole` | DELETE | def `permissions.ts:197`; only use `permissions.ts:246` (inside `MemberRoleResolver.getRoleAtTime`) | Dies with #2. |
| 4 | `canAdmin` (private) | DELETE | def `permissions.ts:75`; uses 454/462/470/478/507/569 — all inside #1 | The jazz-tools `canAdmin` hits are `Account.canAdmin`, unrelated. |
| 5 | `agentInAccountOrMemberInGroup` (private) | DELETE | def `permissions.ts:734`; only call `permissions.ts:134` (ownedByGroup fallback) | Test hits are comments only. |
| 6 | ownedByGroup fallback branch (`determineValidTransactions` body) | DELETE | `permissions.ts:116-181` | Reached only when `!validateTransactions \|\| killSwitch`. Native handles ownedByGroup (`determineValidTransactionsNative` + `validBranchPointerOnly`). |
| 7 | `unsafeAllowAll` fallback branch | DELETE | `permissions.ts:184-189` | Same gate; native marks all valid. |
| 8 | group fallback branch + `"Group must have initialAdmin"` throw | DELETE | `permissions.ts:105-113` | Native fails closed at deserialize (comment `permissions.ts:97-99`). |
| 9 | `nativeValidationDisabled` + its call site in the dispatch | DELETE | def `permissions.ts:80`; gate `permissions.ts:93` | Kill switch. See group.ts #18 for the second gate. |
| 10 | `determineValidTransactions` (exported wrapper) | KEEP/NARROW | body `permissions.ts:87`; callers `coValueCore.ts:1472,1594` | Live entry point. NARROW to: `isAvailable()` guard + `determineValidTransactionsNative(coValue, nodeCore)` unconditionally. |
| 11 | `determineValidTransactionsNative` | KEEP | `permissions.ts:271-388` | Becomes the sole body of #10. |
| 12 | `NodeCorePendingTx` / `NodeCoreGroupVerdict` build in #11 | KEEP | `permissions.ts:275-307`, `367-387` | Native path plumbing. |
| 13 | `isKeyForKeyField` (exported) | KEEP | def `permissions.ts:756`; imported `group.ts:33`, used `group.ts:369` | External import — MUST stay. |
| 14 | `isKeyForAccountField` (exported) | DELETE | def `permissions.ts:760`; uses only `permissions.ts:486-489` (inside #1) | Not re-exported publicly (`exports.ts` only re-exports `AccountRole`/`Role`/`isAccountRole`); no jazz-tools import. |
| 15 | `isKeySealedForGroupField` (exported) | DELETE | def `permissions.ts:770`; use `permissions.ts:488` (inside #1) | Same as #14. |
| 16 | `isWriteKeyForMember` (exported) | DELETE | def `permissions.ts:744`; use `permissions.ts:546` (inside #1) | Same as #14. |
| 17 | `getAccountOrAgentFromWriteKeyForMember` (exported) | DELETE | def `permissions.ts:750`; use `permissions.ts:547` (inside #1) | Same as #14. |
| 17b | `isParentExtension` / `isChildExtension` / `isOwnWriteKeyRevelation` (private) | DELETE | defs `permissions.ts:776/780/784`; uses 506/543/498 — all inside #1 | Private; die with #1. |
| **group.ts** |
| 18 | roleOf gate kill-switch condition | NARROW | `group.ts:463-472` — remove `!nativeValidationDisabled() &&` (line 466) and the import at `group.ts:34` | KEEP the branch/frontier carve-out (`branchSourceId === undefined && atFrontierFilter === undefined`, lines 467-468) and the TS body below (474-508). Rewrite the comment to "native unless branch/frontier view" (no kill switch). |
| 19 | `roleOfInternal` TS body (474-508) | KEEP | live callers: `coValueCore.ts:984`, `coList.ts:254`, `group.ts:443`(roleOf)/`488`(parent recursion)/`564`(myRole), `account.ts:68`(override) | Carve-out per plan — native models only `atTime`; branch/frontier views stay on TS. Non-fallback callers keep it live regardless. |
| 20 | `parentGroupsChanges` + `updateParentGroupCache` | KEEP | `group.ts:319/392`; used by **key-revelation** `getUncachedReadKey` `group.ts:974`, and by `getParentGroups` `group.ts:528` | Shared with NON-role machinery (key rotation/read-key resolution). Not role-only. |
| 21 | `TimeBasedEntry<T>` | KEEP | `group.ts:255`; backs `parentGroupsChanges` (#20) | Dies only if #20 dies — it doesn't. |
| 22 | `getParentGroup` | KEEP | `group.ts:510`; used `group.ts:487,533` + `getUncachedReadKey`/`findValidParentKeys` neighborhood | Shared key + role machinery. |
| **crypto.ts / ShimNodeCore.ts** |
| 23 | `ShimNodeCore` (whole file) | DELETE | `ShimNodeCore.ts:17`; instantiated only `crypto.ts:308` + test `shimNodeCore.test.ts:34,150` | No provider uses it — all override `createNodeCore` natively. |
| 24 | `CryptoProvider.createNodeCore()` base default | NARROW | `crypto.ts:307-311` → `abstract createNodeCore(): NodeCoreImpl;` | Removes the last shim producer + the `ShimNodeCore` import (`crypto.ts:14`). All three providers already override. |
| 25 | `validateTransactions?` / `roleOf?` / `resetValidation?` optionality | NARROW | interface `crypto.ts:547/556/571`; presence-check sites simplify: `permissions.ts:93` (`&&`→drop), `permissions.ts:319` (`!`→`.`), `group.ts:465` (`&&`→drop), `group.ts:470`, `coValueCore.ts:1324` (`?.`→`.`) | Make all three **required** on `NodeCoreImpl`. Only 5 presence-check sites total (grep-complete). |
| 26 | `SessionMapImpl.dispose?()` field + `SessionMapAdapter.dispose` impls | DELETE (with caveat) | field `crypto.ts:404`; impls `WasmCrypto.ts:294` etc.; sole caller shim `ShimNodeCore.ts:41,51` | Caller-less once shim dies. **See createSessionMap recommendation — bundle with #27, not standalone.** |
| 27 | `createSessionMap` + `SessionMapImpl` + `SessionMapAdapter` (×3) + binding `SessionMap` structs | DELETE — **DEFER to a dedicated follow-up PR** | `crypto.ts:295/332`; `WasmCrypto.ts:272/291`, `NapiCrypto.ts:227/246`, `RNCrypto.ts:198/291`; native structs in 3 crates | Provably dead after shim (only shim consumed it; VerifiedState uses `nodeCore`). Blast radius = 3 binding crates + wasm artifact rebuild (no CI gate). See recommendation below. |
| **Tests / bench** |
| 28 | `groupEngineDifferential.test.ts` (whole file) | DELETE | `groupEngineDifferential.test.ts:1-623`; kill-switch arm `:559` | Oracle (TS engine) gone; harness cannot run its pass-(b) TS comparison without the kill switch. Per plan C2. |
| 29 | `shimNodeCore.test.ts` — shim arms | NARROW | `makeShim`/`makeNodeCore` `:34`; `nodeCoreSuite("ShimNodeCore", …)` `:127`; `describe("ShimNodeCore" … dispose semantics)` `:145-end` | DELETE shim-specific arms + dispose-semantics block. KEEP the parameterized `nodeCoreSuite` for native providers (Napi/Wasm, add RN). Capability test `:103-123`: the `else`/`toBeUndefined` branch is now unreachable — assert presence on ALL arms. Consider renaming the file (no "shim" left). |
| 30 | `permissions.nativeGroupFlip.test.ts` | KEEP | single native test `:76`; NO `stubEnv` — the kill-switch mention is comment-only (`:25-26`) | Native late-revocation flip regression. NARROW: drop the stale "when run under COJSON_DISABLE_NATIVE_VALIDATION=1 … TS path (parity)" line from the header comment. |
| 31 | `groupEngineFixtures.export.test.ts` (the fixture exporter) | KEEP + NARROW | file; 7 dead `vi.stubEnv("COJSON_DISABLE_NATIVE_VALIDATION","1")` at `:1201,1290,1365,1408,1468,1527,1570`; stale gate comment `:1186-1197` | KEEP per plan (oracle-inversion decision). NARROW: the `stubEnv` calls become **no-ops** once the env gate is deleted — remove them and rewrite the block comment. **CRITICAL:** removing the forcing flips these 7 scenarios from TS-captured to native-captured; C2 MUST verify regenerated verdict CONTENT is unchanged (see exporter note). |
| 32 | `bench/cojson/groupEngine.bench.ts` — TS-fallback arms | NARROW | kill-switch arms `:165-205` (2 "(TS fallback)" cases) | The `COJSON_DISABLE_NATIVE_VALIDATION=1` arms can no longer force the TS path. DELETE the two "(TS fallback)" cases; keep the "(native)" cases. Update the file header comment `:7`. |

## Key findings that change C2's assumed scope

1. **Four exported classifiers are DELETE, not KEEP.** The plan text ("group.ts
   imports some — those stay") is true only for `isKeyForKeyField` (#13).
   `isKeyForAccountField`, `isKeySealedForGroupField`, `isWriteKeyForMember`,
   `getAccountOrAgentFromWriteKeyForMember` are exported but consumed **only**
   inside `determineValidTransactionsForGroup`, are **not** re-exported from
   `cojson`'s public `exports.ts`, and have **no** jazz-tools importers → safe DELETE.

2. **`parentGroupsChanges`/`TimeBasedEntry`/`getParentGroup` are unambiguously
   KEEP** — they are shared by the key-revelation/read-key path
   (`getUncachedReadKey` at `group.ts:974` iterates `parentGroupsChanges.keys()`),
   not just role resolution. Deleting them would break key decryption.

3. **`createSessionMap` and the entire per-CoValue `SessionMap` layer are dead
   after the shim** (finding above). The stage-1 plan's deferral was correct;
   recommendation is to keep deferring the *binding-struct* half (below).

4. **`permissions.nativeGroupFlip.test.ts` does NOT use the kill switch** despite
   its header comment — it is a native-only regression and simply survives.

5. **The exporter's kill-switch usage is load-bearing for fixture content.**
   Its 7 `stubEnv` calls currently pin specific ownedByGroup/stage-3 scenarios to
   TS-captured verdicts. Deleting the gate silently reroutes them through native.
   This is the oracle inversion in concrete form and is the single highest-risk
   item in C2.

6. **Only 5 optionality presence-check sites** exist for the three NodeCore
   methods (grep-complete), so flipping them to required is small and mechanical.

## C2 execution notes

### Ordering hazard: flip optionality LAST, after the shim is gone

`tsc` will break the moment `validateTransactions`/`roleOf`/`resetValidation`
become required (#25) if `ShimNodeCore` still exists — the shim does **not**
implement them, so it stops satisfying `NodeCoreImpl`. Correct order:

1. Delete `groupEngineDifferential.test.ts` (#28) and the bench TS arms (#32) —
   removes external kill-switch consumers first.
2. permissions.ts (#1-9, #14-17b): narrow `determineValidTransactions` to the
   native call; delete the TS engine + helpers + kill switch. Clean now-unused
   imports (`RawGroup`, `ParentGroupReferenceRole`, `EVERYONE`, `getParentGroupId`,
   `MapOpPayload`, `JsonValue`, etc. — let `tsc`/lint drive).
3. group.ts (#18): remove `!nativeValidationDisabled() &&` and the
   `nativeValidationDisabled` import; rewrite the gate comment.
4. Delete `ShimNodeCore.ts` (#23) and make base `createNodeCore` abstract (#24),
   dropping its import in `crypto.ts`.
5. **Only now** flip the three methods to required (#25) and simplify the 5
   presence-check sites. (Do it after step 4 so no non-native `NodeCoreImpl`
   implementer remains — otherwise `tsc` red mid-edit.)
6. Tests (#29-31): narrow `shimNodeCore.test.ts`, fix the two comment-only files.
7. Full gates: `pnpm test` (cojson) + jazz-tools + `tsc --noEmit` + cargo +
   **re-run Task A3 manual example-app verification** (wasm now has no fallback).

`dispose` (#26): its only caller vanishes at step 4. Because `dispose` lives on
the `createSessionMap`/`SessionMapImpl` layer that this inventory recommends
deferring (below), **leave `dispose?` in place in C2** and remove it together
with the rest of that layer in the follow-up PR — removing it alone buys nothing
and splits one coherent change across two PRs.

### Exporter oracle-inversion note (text to add to `groupEngineFixtures.export.test.ts`)

Replace the Stage-3 block comment (`:1183-1197`) and add a file-level note:

> **Oracle inversion (post Part C):** the `COJSON_DISABLE_NATIVE_VALIDATION`
> kill switch is gone, so this exporter no longer captures an INDEPENDENT TS
> oracle — it captures whatever the native NodeCore produces. The committed
> fixtures are **frozen golden files** originating from the TypeScript engine
> (commit `b84f15310`). They are now the authority; the exporter is only a
> *regenerator*. Regeneration MUST NOT change verdict CONTENT — only tx/session
> identities may churn. Any content diff on regeneration is a native-engine
> regression, not a fixture update. Before landing C2, regenerate once and diff
> the 7 previously-kill-switch-forced scenarios (owned_by_group_roles and the
> reader-branch-pointer / merged-tx cases) against the committed fixtures to
> confirm the native ownedByGroup engine reproduces `validBranchPointerOnly` and
> the "Transactor has no write permissions" verdicts byte-for-byte. If cheap,
> add a CI assertion that regenerated verdict content equals the committed
> fixtures (identities aside); else document the manual diff step here.

Porter-note cross-refs to preserve: note 12 (ownedByGroup reader branch-pointer
was the stage-2 unported case — verify stage-3 native now emits
`validBranchPointerOnly`), note 17 (the recompute-all vs drain-to-`[]` asymmetry
that made the differential harness need `resetParsedTransactions` — that harness
is being deleted, but the asymmetry still governs `determineValidTransactionsNative`'s
`applyTo` scoping in `permissions.ts:358-361`, which is KEEP).

### `createSessionMap` recommendation: DEFER to a dedicated follow-up PR

**Evidence:** after the shim (#23) and base `createNodeCore` (#24) are removed,
`createSessionMap` / `SessionMapImpl` / the three `SessionMapAdapter` classes /
`SessionMapImpl.dispose?` have **zero** remaining consumers — `VerifiedState`
uses `nodeCore.*` exclusively, and every native `createNodeCore` override wraps a
native `NodeCore`, never a `SessionMap`. So they are genuinely dead.

**Recommendation: DELETE them, but in a SEPARATE PR after C2 — do NOT fold into C2.**

Reasoning:
- **Blast radius / no-CI hazard.** A coherent removal deletes not just the TS
  layer but the three Rust binding structs (`WasmSessionMap`, napi
  `NativeSessionMap`, `RNSessionMap`). Deleting the Rust structs forces a
  **wasm artifact rebuild** whose only gate is manual browser testing (there is
  NO CI recompile gate for wasm — the checked-in `public/` binary IS the ship),
  plus an RN uniffi regen and a napi rebuild. That is precisely the risk profile
  C2 already carries once (the deletion re-verification); doubling it inside the
  same PR makes a bisect-hostile mega-diff across four crates.
- **Splitting TS-now / Rust-later is worse.** If C2 deleted only the TS wrappers
  it would orphan exported binding structs with no TS caller — an ugly interim
  state — while still not saving the wasm rebuild. Keep TS + Rust together in one
  focused PR where the wasm rebuild is verified exactly once.
- **The stage-1 plan already deferred this to "final cleanup."** Honoring that
  keeps C2 scoped to the validation-logic deletion, whose manual re-verification
  is the phase's highest-stakes gate. Adding a dead-code-removal that can't break
  runtime behavior to that PR only dilutes review attention on the part that can.
- **Cost of waiting is nil.** The dead layer compiles cleanly and `tsc` stays
  green; leaving it one PR longer costs nothing.

Name the follow-up e.g. `cojson-delete-sessionmap-layer`, base on C2, and treat it
with the same wasm manual-verification gate as Part A. Move `dispose?` (#26) into
that PR too.
