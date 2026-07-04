# Cleanup Phase Implementation Plan — wasm/RN NodeCore ports + TS deletion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the wasm and React Native bindings to native-`NodeCore` parity with napi, then delete the TypeScript permission-validation logic, the shim, and the kill switch — realizing the migration's "single cross-platform implementation" end state (with one honest carve-out, below).

**Architecture:** Three parts → three stacked PRs, each independently shippable: **A** (wasm port, verified by the full jazz-tools suite AND mandatory manual browser testing of example apps — wasm has NO CI recompile gate, its built artifacts are checked into the crate, so manual verification is the primary gate for the new binary), **B** (RN port; Android native build requires the NDK, absent locally — CI is the build/e2e gate), **C** (deletion, gated on A+B verified). All logic already lives in `cojson-core`; A and B are binding mirrors of the napi surface.

**Honest scope carve-out (C):** stage 2 deliberately keeps branch/frontier CoMap views on the TS `roleOfInternal` path (native models only `atTime`). Until native branch support exists, `roleOfInternal`'s TS body CANNOT be deleted — Part C deletes the validation logic, shim, kill switch, and harness, and narrows the roleOf gate to the branch/frontier condition only. The spec's "TypeScript deletion (end state)" section gets updated to record this.

**Spec:** `docs/superpowers/specs/2026-07-03-cojson-rust-permissions-migration-design.md` ("TypeScript deletion (end state)" + Stage statuses). **Porter notes:** `docs/superpowers/plans/2026-07-04-group-engine-porter-notes.md` (all 17). Both are required reading per task.

**Prerequisite:** Stage-3 branch (`cojson-validate-transactions`, PR #3533) is the base. All cleanup PRs stack on it.

## Templates (the ports are mirrors — copy these, do not redesign)

| What | Where |
| --- | --- |
| The Rust registry both ports wrap | `crates/cojson-core/src/core/node.rs` (NodeCore: create/has/remove/count/get/get_mut + validate_transactions/reset_validation/role_of) |
| Binding surface to mirror | `crates/cojson-core-napi/src/lib.rs` — `struct NodeCore` (~386), full `impl` (~390-801), object types `SourceTxId` (~351), `PendingTx` (~360), `GroupVerdict` (~371) |
| TS adapter to mirror | `packages/cojson/src/crypto/NapiCrypto.ts` — `NapiNodeCoreAdapter` (~414-end) + `override createNodeCore()` (~238) |
| wasm binding conventions | `crates/cojson-core-wasm/src/lib.rs` — `js_name` camelCase attrs, `CojsonCoreWasmError` → JsValue mapping (60-76), `serialize_js_value` for object returns (78-86), panic hook, NO Mutex |
| RN binding conventions | `crates/cojson-core-rn/rust/src/session_map.rs` — `uniffi::Object` + `Mutex<...>` (Send+Sync), `SessionMapError { Internal, LockError }`, `uniffi::Record` for object types |
| TS contract | `packages/cojson/src/crypto/crypto.ts` `NodeCoreImpl` (438-585) |
| Capability tests to extend | `packages/cojson/src/tests/shimNodeCore.test.ts` (parameterized nodeCoreSuite) |

---

## Part A — wasm NodeCore port (PR: `cojson-nodecore-wasm`, base `cojson-validate-transactions`)

### Task A1: Rust wasm `NodeCore`

**Files:** Modify `crates/cojson-core-wasm/src/lib.rs`.

- [ ] Mirror the napi `NodeCore` surface as a `#[wasm_bindgen]` struct wrapping `RustNodeCore` (no Mutex — wasm is single-threaded): constructor, registry methods (`createCoValue`/`hasCoValue`/`removeCoValue`/`coValueCount`), the full lifted SessionMap surface (copy method-by-method from the wasm `SessionMap` impl in the SAME file, adding `co_id` first — same transformation stage 1 did for napi; add the "parallel copy" breadcrumb comments both directions), and the stage-2/3 surface: `validateTransactions`, `roleOf`, `resetValidation`.
- [ ] Wire types: `pending` arrives as a `JsValue` (array) deserialized via `serde_wasm_bindgen::from_value::<Vec<PendingTxWire>>` where `PendingTxWire` is a serde struct whose renames MATCH THE TS-SIDE SHAPE EXACTLY (`sessionId`? NO — decide deliberately: define the wire as `{sessionId, txIndex, sourceMadeAt?, metaJson?, sourceTxId?: {sessionID, txIndex}}`... CHECK what NodeCorePendingTx uses (crypto.ts:~415-425: sessionId/txIndex/sourceMadeAt/metaJson camelCase, sourceTxId nested with sessionID capital-ID) and make the serde renames match so the TS adapter passes objects THROUGH with zero conversion — document this choice on the struct: "wire shape = NodeCorePendingTx verbatim, unlike napi which needs an adapter-side casing bridge"). Verdicts return via `serialize_js_value` of a serde struct with fields `sessionId/txIndex/valid/outcome/reason` (outcome from `VerdictOutcome::as_str`).
- [ ] Error mapping per the file's convention; the error MESSAGE must preserve the "Unknown CoValue: " / "CoValue not loaded: " prefixes (TS error translation matches on them).
- [ ] `cargo check -p cojson-core-wasm --target wasm32-unknown-unknown` (or the crate's test setup) green; `cargo clippy` no new warnings.
- [ ] Commit: `feat(cojson-core-wasm): NodeCore registry with unified validation surface`.

### Task A2: build + TS adapter

**Files:** regenerated `crates/cojson-core-wasm/public/*` + `pkg` artifacts per `build.js`; Modify `packages/cojson/src/crypto/WasmCrypto.ts`; Modify `packages/cojson/src/tests/shimNodeCore.test.ts`.

- [ ] `pnpm build:wasm` (root) — commit the regenerated checked-in artifacts (this is how wasm ships; verify `git status` shows the public/ updates and the `.d.ts` includes NodeCore).
- [ ] `WasmCrypto`: `override createNodeCore()` returning `new WasmNodeCoreAdapter(new WasmNodeCore())`; adapter mirrors `NapiNodeCoreAdapter` but with pass-through pending (if A1's wire-shape decision holds, no conversion; document either way) and JSON-string parsing exactly where the wasm SessionMap adapter does it. `dispose` semantics: the registry object exposes wasm-bindgen `free()`; wire the LocalNode-drop path the same way the shim's per-entry dispose worked — check what ShimNodeCore's wasm dispose relied on and ensure eviction still frees (removeCoValue frees Rust-side entries inside the registry; the registry object itself frees with the node).
- [ ] `WasmCryptoEdge` inherits automatically (same class) — verify by reading it; note in the commit message that edge-lite ships the same binary.
- [ ] Extend `nodeCoreSuite` with a WasmCrypto arm asserting the FULL capability trio present + unknown-coId throws. NOTE: the fixture exporter (`groupEngineFixtures.export.test.ts`) instantiates WasmCrypto — after this task its consistency assertions run through wasm-native validation, becoming a free wasm gate; run it and call that out.
- [ ] Gates: `cd packages/cojson && pnpm test` (full, 1425/13 baseline — some tests now route wasm-native); `pnpm exec tsc --noEmit`; jazz-tools full suite (`pnpm exec turbo run test --filter=jazz-tools`, 2120/8 baseline) — jazz-tools is wasm-heavy and now exercises the new binary end-to-end.
- [ ] Commit: `feat(cojson): native NodeCore adapter for WasmCrypto`.

### Task A3: MANDATORY manual example-app verification (user-required gate)

No commit; produces a written verification report + screenshots. Driven with the browser-automation tooling by the controller or a dedicated agent.

- [ ] Start a local sync server: `pnpm --filter jazz-run build-and-run` (or `jazz-run sync --in-memory --port 4200`). Temporarily point the example's `peer` at `ws://localhost:<port>` (edit `examples/chat/src/app.tsx:112` and the organization example's provider equivalently — DO NOT commit these edits; revert after).
- [ ] **Chat** (`pnpm --filter jazz-example-chat dev`): two tabs with `?user=Alice` / `?user=Bob` on the same `/#/chat/:id`. Verify: messages flow both directions live; reload persists; browser console has ZERO errors — specifically grep the console for `Unknown CoValue`, `CoValue not loaded`, `RuntimeError`, `unreachable` (wasm panic signatures), and the panic-hook output.
- [ ] **Organization** (`pnpm --filter organization dev`): richer permission surface. Create an organization (admin), create an invite link, accept it in a second tab/profile, verify the member sees role-appropriate UI; attempt writes as the lower role where the UI allows expressing them; verify no console errors as above.
- [ ] Negative check: with devtools open, exercise rapid create/switch/delete flows (the eviction/registry lifecycle) looking for the error signatures.
- [ ] Deliverable: a verification report (screenshots + console transcript summary + exact app/commit versions) attached to the PR description. Any error signature found = STOP, diagnose before the PR.

### Task A4: PR

- [ ] Changeset (`cojson` + note the wasm artifacts ship inside `cojson-core-wasm` — check whether that package is in the changeset fixed group and version it accordingly).
- [ ] Push `cojson-nodecore-wasm`, PR base `cojson-validate-transactions`, body includes the manual-verification report. Two-stage review before push per the standing process.

---

## Part B — RN NodeCore port (PR: `cojson-nodecore-rn`, base `cojson-nodecore-wasm`)

### Task B1: Rust uniffi `NodeCore`

**Files:** Create `crates/cojson-core-rn/rust/src/node_core.rs` (+ lib.rs module), mirroring session_map.rs conventions.

- [ ] `#[derive(uniffi::Object)] pub struct NodeCore { internal: Mutex<RustNodeCore> }`; every method locks with the `LockError` mapping; `#[uniffi::constructor] new()`; full mirrored surface incl. `validate_transactions`/`role_of`/`reset_validation`. `uniffi::Record`s: `PendingTx { session_id, tx_index, source_made_at: Option<f64>, meta_json: Option<String>, source_tx_id: Option<SourceTxId> }`, `SourceTxId { session_id, tx_index }`, `GroupVerdict { session_id, tx_index, valid, outcome: String, reason: Option<String> }` (outcome via `VerdictOutcome::as_str`). Error messages preserve the two prefixes.
- [ ] `cargo check`/`cargo test` on the rn rust crate (host target — no NDK needed for that) + clippy. Commit: `feat(cojson-core-rn): NodeCore registry with unified validation surface`.

### Task B2: bindings + TS adapter (env-limited — CI is the native gate)

- [ ] Attempt local regen: `pnpm --filter cojson-core-rn ubrn:ios` IF Xcode + iOS rust targets exist (`xcodebuild -version`; `rustup target list --installed | grep apple-ios`). If unavailable, check whether `ubrn` offers a generate-only invocation (`ubrn --help`; `ubrn generate` variants) that skips native compilation. If NEITHER works locally, hand-write the expected generated-TS delta is FORBIDDEN — instead mark the adapter work as compile-gated on CI and structure the PR so CI's `rn-build-reusable` job (which regenerates via `--and-generate`) produces the bindings; note this explicitly in the PR.
- [ ] `RNCrypto`: `override createNodeCore()` + `RNNodeCoreAdapter` mirroring the napi adapter (uniffi camelCases to the same names; verify against the generated `src/generated/cojson_core_rn.ts` once available; the SourceTxId casing question repeats here — match whatever uniffi generates and document the bridge or pass-through).
- [ ] Gates: everything runnable locally (cargo, tsc against generated types if regenerated, cojson suite — RN provider isn't exercised by the local suite) + **CI**: the PR must show `rn-build-reusable` android+ios builds green AND the `e2e-rn-test-cloud` Maestro run on `examples/chat-rn-expo` green. Those CI gates are the RN equivalent of Task A3.
- [ ] Commit: `feat(cojson): native NodeCore adapter for RNCrypto`; PR base `cojson-nodecore-wasm` with the CI-gating called out.

---

## Part C — deletion PR (PR: `cojson-delete-ts-permissions`, base `cojson-nodecore-rn`)

**Merge gate:** Parts A+B merged or verified green (incl. RN CI e2e). Do not start C's execution until then; its PLAN tasks can be prepared.

### Task C1: deletion inventory (investigation before any deletion)

- [ ] Enumerate every consumer of: `determineValidTransactionsForGroup`, `MemberRoleResolver`, `isHigherRole`, `roleOfInternal` (callers OUTSIDE the delegation gate — branch/frontier views, myRole, key rotation?), `parentGroupsChanges`/`TimeBasedEntry` (key-revelation machinery `keyRevelations`/`getUncachedReadKey` may share them — SHARED code must survive), `ShimNodeCore`, `nativeValidationDisabled` (both gates + harness + exporter + bench), the key-shape classifiers exported from permissions.ts (group.ts imports some — those stay).
- [ ] Produce the inventory as a table (delete / keep+why / narrow) committed to the plan directory. The roleOfInternal TS body is KEEP (branch/frontier carve-out) — the gate comment gets rewritten to reflect "native unless branch/frontier view" with no kill switch.

### Task C2: the deletion

- [ ] crypto.ts: `validateTransactions`/`roleOf`/`resetValidation` become REQUIRED on `NodeCoreImpl`; `createNodeCore()` becomes abstract; delete `ShimNodeCore.ts`; delete the `SessionMapImpl.dispose?` shim plumbing if now unused (check).
- [ ] permissions.ts: delete `nativeValidationDisabled` + the fallback dispatch + `determineValidTransactionsForGroup` + `MemberRoleResolver` + `isHigherRole` + the ownedByGroup/unsafeAllowAll TS branches; `determineValidTransactions` becomes: guards + `determineValidTransactionsNative` unconditionally. Keep exported classifiers per C1's inventory.
- [ ] group.ts: roleOf gate loses the kill-switch condition; keep branch/frontier condition + TS body.
- [ ] Delete `groupEngineDifferential.test.ts` (its oracle is gone). Fixture exporter DECISION (implement per C1 findings): post-deletion it captures NATIVE verdicts — keep it as a native-consistency regenerator with a doc note ("no longer an independent oracle; fixtures are frozen golden files from commit b84f15310's TS implementation — regeneration must not change verdict content, only identities"), and add a CI-value assertion that regenerated verdict CONTENT matches the committed fixtures (identity churn aside) if cheap, else document manual comparison.
- [ ] Tests: capability tests now assert presence on ALL providers; kill-switch test arms deleted.
- [ ] Gates: full cojson suite; jazz-tools; cargo; tsc; **re-run the Task A3 manual example-app verification** (wasm now has NO fallback — this is the highest-stakes smoke of the whole phase); changeset (consider whether removing the TS path warrants a minor bump — check repo convention); spec status update rewriting "TypeScript deletion (end state)" to reflect the roleOfInternal carve-out and what remains (native branch-view support as future work).
- [ ] PR base `cojson-nodecore-rn`, body with the deletion inventory table and the re-verification report.

---

## Risks

- **Wasm has no CI recompile gate** — the checked-in artifacts ARE the shipped binary; A2's rebuild must be committed, and A3's manual verification is the primary binary gate. Anyone later touching cojson-core Rust without rebuilding wasm ships a stale binary silently — worth flagging as follow-up CI work in the Part A PR.
- **RN Android is unverifiable locally** (no NDK); B's merge gate is CI. If CI's Maestro e2e is flaky/unavailable, escalate rather than merge unverified.
- **The exporter-oracle inversion** (C2): after deletion the exporter no longer independently checks Rust — the frozen fixtures carry the oracle role. Any future fixture regeneration must be reviewed against verdict-content stability.
- **Branch/frontier roleOf carve-out**: deleting the kill switch removes the only way to force the TS path for A/B comparisons; the harness goes with it. Acceptable per spec intent, but the carve-out means "single implementation" is true for validation and non-view role reads only.
