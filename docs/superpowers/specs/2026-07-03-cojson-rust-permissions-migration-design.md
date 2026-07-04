# Migrating cojson permissions & group state to Rust

**Date:** 2026-07-03
**Status:** Draft, revised after external review (GLM-5.2 findings verified against code and incorporated)

## Goal

Move the next layer of cojson logic into `crates/cojson-core`: permission
checking (`determineValidTransactions`) and group role resolution
(`roleOfInternal` and friends). Today Rust owns crypto primitives and the
per-CoValue verified session log (`SessionMapImpl`); every transaction is
verified in Rust, then serialized out as JSON so TypeScript can re-parse it to
decide validity and resolve roles. This migration removes that boundary tax on
the security-critical path and leaves a single cross-platform implementation
of role semantics.

Out of scope: general CRDT materialization (coMap/coList views), sync
protocol, storage, key management (read-key unsealing stays in TS).

## Decisions made

| Decision | Choice |
| --- | --- |
| Rollout | Direct replacement per stage; safety via fixture-based differential tests (no production shadow mode) |
| Registry shape | Full node-level API: one Rust `NodeCore` per `LocalNode`; `verifiedState.ts` rewritten against it (no per-CoValue facades) |
| Stage-3 surface | Verdicts **and** role queries: Rust exposes `roleOf` so `group.ts` role resolution delegates too |
| Binding order | Napi-first per stage; wasm and RN ports follow; TS fallback stays capability-gated until all bindings port |
| Execution model | Lazy, TS-orchestrated (approach A): Rust computes verdicts and maintains incremental group role indices; TS keeps validation timing, queues, and dependant revalidation |

## Architecture overview

```
TypeScript (packages/cojson)                 Rust (crates/cojson-core)
─────────────────────────────                ─────────────────────────
LocalNode ──────────────────── owns ───────► NodeCore (registry: CoID → CoValueEntry)
CoValueCore                                    ├─ SessionMapImpl   (existing: verified log)
  ├─ VerifiedState ─── calls (coId, …) ───►    ├─ GroupEngine      (stage 2: roles + group validation)
  ├─ tx state machine (unchanged)              └─ verdict cache    (stage 3, per-session watermarks)
  └─ parseNewTransactions ─ validateTransactions(coId, pending) ─► Verdict[]
RawGroup.roleOfInternal ─── roleOf(groupId, member, atTime) ────► Role
```

TS remains the orchestrator: it decides *when* to validate (lazy, on read,
via `parseNewTransactions`), owns the `to-validate`/`validated`/`processed`
state machine, decrypt queues, content rebuilds, and the
`invalidateDependants` walk. Rust owns *what is valid* and *who has which
role*.

A key structural fact discovered during design: group state materialization
and group self-validation are one algorithm. In TS,
`determineValidTransactionsForGroup` (`permissions.ts:229`) builds the
`MemberRoleResolver` *while* validating, transaction by transaction — role
state does not exist independently of verdicts. They therefore migrate
together (stage 2), and the registry they need migrates first (stage 1) as a
pure behavior-preserving refactor.

## Stage 1 — `NodeCore` registry (plumbing, no behavior change)

### Rust

New `core/node.rs` in `cojson-core`:

- `NodeCore { covalues: HashMap<CoId, SessionMapImpl> }` (plus, later,
  per-CoValue engine/verdict state).
- Methods: the existing `SessionMapImpl` surface lifted to take `co_id` as
  first parameter, plus `create_co_value(co_id, header_json, skip_verify)`,
  `has_co_value(co_id)`, `remove_co_value(co_id)`.

`cojson-core-napi` exposes `#[napi] NodeCore` with the same lifted surface
(camelCased). Wasm and RN ports mirror it in their follow-up PRs.

### TypeScript

- `crypto/crypto.ts`: the `SessionMapImpl` interface (currently
  `crypto.ts:320`) is replaced by `NodeCoreImpl` — same methods, coId-first —
  and `CryptoProvider` gains `createNodeCore(): NodeCoreImpl`.
- `coValueCore/verifiedState.ts`: keeps its class shape and its `SessionLog`
  / known-state caches; `this.impl.X(...)` becomes
  `this.nodeCore.X(this.id, ...)`. The `NodeCore` instance is created by
  `LocalNode` and passed to every `VerifiedState`.
- `NapiCrypto.ts`: implements `NodeCoreImpl` natively (the per-provider
  `SessionMapAdapter` becomes a `NodeCoreAdapter`; JSON parse/stringify at
  the boundary is unchanged).
- `WasmCrypto.ts` / `RNCrypto.ts`: a shared ~50-line TS shim class implements
  `NodeCoreImpl` over a `Map<coId, SessionMap>` of the existing per-CoValue
  native objects, until their native `NodeCore` ports land.
- Garbage collection: freeing a CoValue's Rust memory no longer rides on
  dropping a per-CoValue binding object (JS GC finalizers stop working as
  the cleanup mechanism). Every eviction path must call
  `nodeCore.removeCoValue(coId)` explicitly: the `GarbageCollector` unload
  path, `LocalNode` CoValue unmount/teardown, and node shutdown. The wasm
  shim's `Map` entry `free()`s the wrapped object on eviction.
  `removeCoValue` on an absent coId is a no-op (double-eviction safe).
  As implemented, delete/unmount eviction is **deferred one microtask**
  (with a skip-if-reloaded guard): `LocalTransactionsSyncQueue` flushes
  pending local transactions on a `queueMicrotask` that reads the registry,
  so synchronous eviction would break the final flush of a
  deleted-with-pending-tx CoValue; microtask FIFO guarantees the flush runs
  first. `nodeCore.hasCoValue(id)` therefore reads true until the next
  microtask turn after eviction. **Node shutdown does NOT evict**: a closing
  node must stay readable for in-flight handoff work (peer LOADs, final
  sync) after `gracefulShutdown` resolves — eagerly emptying the registry
  made those reads throw (found via a jazz-tools auth-flow regression). The
  registry, and every native session map it owns, is released when the
  `LocalNode` itself is dropped, so shutdown eviction is unnecessary for
  memory reclamation.

### Acceptance

Zero behavior change; the entire existing cojson + jazz-tools test suite
passing on all three providers (napi native, wasm/RN shimmed) is the gate.
Because the suite cannot detect native-memory leaks, stage 1 additionally
ships an explicit eviction test: create/unload CoValues through every
eviction path and assert `hasCoValue` is false and (napi) registry size
returns to baseline.

## Stage 2 — Group engine: validation + role resolution for groups/accounts

**Status:** Implemented, napi-first. Group/account validation and role
resolution delegate to the native `NodeCore` (`validateGroup`/`roleOf`) behind
capability detection, with the `COJSON_DISABLE_NATIVE_VALIDATION` kill switch
as an operational escape hatch and differential-test oracle; wasm and RN stay
on the TS path until their native ports land. Branch/frontier views — reading
CoMap keys other than roles off a time-travel view (e.g. branch pointers) —
remain on the TS path; only role resolution delegates, per the `atTime` view
semantics risk noted below.

### Rust

New `core/group_engine.rs`; one `GroupEngine` per group/account CoValue,
stored in the `NodeCore` entry, built incrementally in validation order.

The engine keeps **two distinct role structures** — validation state and
read state are *not* the same thing in TS and must not be merged (a single
time-indexed map would diverge from TS semantics for merged transactions
where `currentMadeAt != sourceTxMadeAt`):

- **Validation state (order-sensitive, deliberately not time-indexed):**
  `current_roles: HashMap<MemberId, Role>` — mirrors TS
  `MemberRoleResolver.memberRoles` (`permissions.ts:184-185`), a plain map
  mutated in validation order. During validation, a transactor's *direct*
  role is "resolver state after the previous transaction in effective-madeAt
  order" — `getRoleAtTime` ignores its time argument for direct roles
  (`permissions.ts:207-212`); the time argument only drives the
  parent-group walk. Plus `parent_groups_current: HashMap<CoId,
  ParentRoleMapping>`, `write_only_keys: HashMap<MemberId, KeyId>`, and
  `write_keys: HashSet<String>` (the writeOnly invite/override rules,
  `permissions.ts:385-418`), all evolving in validation order.
- **Read state (time-indexed):** `role_history: HashMap<MemberId,
  TimeBasedEntry<Role>>` and `parent_groups_history: HashMap<CoId,
  TimeBasedEntry<ParentRoleMapping>>` — built from the *validated* set-role
  ops; `TimeBasedEntry` = chronologically sorted `(made_at, value)` pairs,
  query = last entry with `made_at <= t` (semantics of `group.ts:254`
  `TimeBasedEntry` and the CoMap `atTime`/`getRaw` read). These serve
  `roleOf(_, _, atTime)`.

**Recompute, don't increment.** TS group validation constructs a fresh
`MemberRoleResolver` and re-derives every verdict from the full
`verifiedTransactions` set on every call (`permissions.ts:229-240`) —
necessarily so, because a newly arrived transaction can sort into the
*middle* of the effective-madeAt order (clock skew, merge source times) and
flip verdicts of transactions after it. The Rust engine replicates this:
when a group has new transactions since the last run, its engine and
verdicts are rebuilt from scratch over all transactions; the only caching is
"no new transactions since the last run → reuse the previous verdicts"
(keyed by per-session transaction counts). Append-only/watermark
incremental validation is explicitly ruled out for groups.

Algorithm: a direct port of `determineValidTransactionsForGroup`
(`permissions.ts:229-571`) — every rule branch preserved: initial-admin
self-promotion, self-revoke, admin/manager demotion and invite restrictions,
all invite kinds, `readKey`/`groupSealer`/`profile`/`root` admin-only sets,
key-revelation fields, parent-extension set/revoke with self-extension
(cycle) rejection, child-extension rejection, everyone-role restrictions,
"exactly one set change" shape rule, and privacy rules (private transactions
invalid in groups).

Read-side role resolution, a port of `RawGroup.roleOfInternal`
(`group.ts:451-488`) over the engine's validated state:

- direct role (revoked → none), recursive parent walk via the registry
  (mapping `extend` inherits parent role; otherwise the mapping caps it;
  only `isInheritableRole` parent roles count;
  `isMorePermissiveAndShouldInherit` decides upgrades), `everyone` fallback
  only when no role resolved and the query isn't `everyone` itself.
- Account→agent resolution (`agentInAccountOrMemberInGroup`,
  `permissions.ts:573`): when the transactor equals the owning account's id,
  resolve to the account's agent id — which is **static**: TS
  `currentAgentID()` returns the header's `initialAdmin`, cached, with no
  time component (`account.ts:44-62`). Rust must read it from the header,
  not time-resolve it from engine state.
- Account self-role override: `RawAccount.roleOfInternal(accountOwnId)`
  returns `"admin"` unconditionally (`account.ts:68-75`). The engine
  replicates this for account CoValues before falling through to group
  resolution.
- A visited-set cycle guard on the parent walk (defense in depth; validation
  already rejects self-extensions).

**Freshness and re-entrancy contract for `roleOf`.** Unlike TS — which
reads already-materialized CoMap content — `roleOf` answers from engine
state, so it must never answer from a stale or unbuilt engine. Contract:
`roleOf(groupId, …)` first ensures the group's engine is current (rebuild if
new transactions arrived since the last validation run), transitively doing
the same for parent groups and owning accounts encountered during the walk,
with the visited-set guarding re-entrancy. Engine build for group G may
itself query parents' engines; builds are therefore reentrant-by-recursion
with cycle detection, never concurrent (NodeCore is single-threaded per
node). Cross-CoValue *verdict* revalidation ordering (a group change
invalidating owned CoValues) remains TS-driven via `invalidateDependants` →
`resetValidation`, unchanged.

### Exposed API (napi first)

```
validateGroup(coId, pending: PendingTx[]) → Verdict[]   // groups & accounts
roleOf(groupId, member, atTimeMs?) → Role | undefined
```

`validateGroup` is the stage-2 interim entry point; stage 3's
`validateTransactions` subsumes it (group ruleset dispatches to the same
engine) and `validateGroup` is removed from the public surface then.

### TypeScript

- `permissions.ts`: the `ruleset.type === "group"` branch calls
  `nodeCore.validateGroup(...)` and maps verdicts onto the
  `toValidateTransactions` queue via the existing `markValid`/`markInvalid`,
  when `nodeCore.hasNativeValidation` is true; otherwise the current TS code
  runs (shim providers).
- `group.ts` `roleOfInternal`: delegates to `nodeCore.roleOf(this.id,
  member, this.atTimeFilter)` under the same capability flag. The TS
  implementation remains as fallback and as the differential-test oracle.

## Stage 3 — Unified `validateTransactions`

### Rust

```
validateTransactions(coId, pending: PendingTx[]) → Verdict[]
resetValidation(coId) → void
```

Dispatch on the CoValue's ruleset:

- `group` → stage-2 engine.
- `ownedByGroup` → for each pending transaction, resolve the effective
  transactor (account→agent resolution against the owning group when it is
  an account) and its role via the owning group's engine **at
  `currentMadeAt`** (the transaction's physical time — never the
  meta-derived source time; see `permissions.ts:104-107`). Writer-tier roles
  (admin/manager/writer/writeOnly) → `valid`; a `reader` whose decrypted
  meta carries `branch` + `ownerId` → `validBranchPointerOnly`; otherwise
  `invalid` with reason.
- `unsafeAllowAll` → all valid.

Caching follows the stage-2 rule: reuse verdicts only when a CoValue has no
new transactions since the last run (keyed by per-session transaction
counts); otherwise recompute in full. Because a recompute can *flip*
previously returned verdicts (mid-sequence insertion), `validateTransactions`
returns verdicts for the `pending` set **plus any previously reported
transaction whose verdict changed**; TS applies flips through the existing
`markValid`/`markInvalid`, whose processed-stage re-dispatch already handles
validity changes (`coValueCore.ts:182-218`). `pending` therefore means "the
transactions TS currently wants verdicts for", not "the only inputs" — for
groups, Rust always evaluates the full history internally, exactly like TS.
TS must apply returned verdicts in the order Rust returns them
(effective-madeAt sorted, stable), since dispatch order feeds
`toProcessTransactions` and downstream stable re-sorts
(`coValueCore.ts:1826-1840`). Cross-CoValue revalidation stays TS-triggered:
`resetParsedTransactions` (`coValueCore.ts:1317`) calls
`resetValidation(coId)` before re-running validation.

### Wire types

```ts
type PendingTx = {
  sessionId: SessionID;
  txIndex: number;
  metaJson?: string;      // decrypted meta, when TS has it (private txs)
  sourceMadeAt?: number;  // merge-meta-derived time, when TS has parsed it
};
type Verdict = {
  sessionId: SessionID;
  txIndex: number;
  outcome: "valid" | "invalid" | "validBranchPointerOnly";
  reason?: string;        // feeds markInvalid's log message
};
```

Contract points:

- TS passes decrypted private-transaction meta in **when it has it at the
  validation call point** — which, matching today's pipeline, is only for
  locally created transactions (via the parsing cache) or on revalidation
  passes: validation runs *before* the decrypt phase in
  `parseNewTransactions` (`coValueCore.ts:1581-1602`), so freshly received
  private transactions validate with `metaJson` absent, exactly as TS
  validates them with `meta === undefined` today. Key management and meta
  parsing (`parseMetaInformation`, source-time derivation and its tamper
  check) stay in TS. Rust reads trusting changes/meta directly from its own
  transaction store; nothing else crosses the boundary.
- `validBranchPointerOnly`: Rust only classifies; TS performs today's
  forced trimming of `tx.changes = []` / `tx.meta = {branch, ownerId}`
  (`permissions.ts:129-137`).
- TS calls `validateTransactions` from `parseNewTransactions` at exactly the
  point `determineValidTransactions` is called today; re-validation after
  meta decryption/parsing flows through the same existing re-dispatch
  mechanics, unchanged.

### TypeScript deletion (end state)

Once wasm and RN native ports pass the full suite: delete the rule logic in
`permissions.ts` (keep the thin dispatch + types), `MemberRoleResolver`, the
internals of `roleOfInternal` and its supporting indices in `group.ts`
(`parentGroupsChanges`, `TimeBasedEntry` where unused elsewhere), the
stage-1 wasm/RN shims, and the `hasNativeValidation` gate.

## Fidelity constraints (normative)

1. **Two time axes.** Permission checks use `currentMadeAt` (physical time in
   the session log). Group-transaction *ordering* for validation uses
   effective `madeAt` = `sourceTxMadeAt ?? currentMadeAt`
   (`coValueCore.ts:163`), where `sourceTxMadeAt` comes from merge meta and
   is supplied by TS via `PendingTx.sourceMadeAt`.
2. **Ordering quirk preserved.** `compareTransactions`
   (`coValueCore.ts:1842`): `madeAt` ascending; ties broken by `txIndex`
   only within the same session; cross-session ties compare equal and rely
   on stable sort. The Rust sort must be stable over the same input order TS
   produces (session-entry iteration order), and fixtures must include
   cross-session equal-timestamp cases.
3. **Validation-order state.** `writeOnlyKeys`/`writeKeys` and role state
   evolve in validation order; verdicts for a transaction depend only on
   state from transactions ordered before it. During validation, *direct*
   role lookups ignore the query time entirely — `MemberRoleResolver.
   getRoleAtTime` uses its time argument only for the parent-group walk
   (`permissions.ts:207-226`); replicating this asymmetry exactly is
   mandatory (do not "fix" it into a time-indexed lookup).
4. **Full recompute on change.** Group verdicts are a function of the whole
   sorted history; new transactions can insert mid-sequence and flip later
   verdicts. Verdict caches are only valid while per-session transaction
   counts are unchanged.
5. **Error-for-error parity.** Every `markInvalid` reason string in
   `permissions.ts` is preserved verbatim in Rust verdict reasons (tests
   assert on them).

## Error handling

- `coValueNotLoaded { coId }`: `validateTransactions`/`roleOf` needs a
  group/parent/account not in the registry. TS translates to the existing
  `expectCoValueLoaded` throw; load ordering remains a TS responsibility.
  Note: verdicts already applied before the error are not rolled back —
  this matches TS, where `markValid`/`markInvalid` dispatch has the same
  partial-application behavior when the throw interrupts the loop
  (`permissions.ts:355-358`). Rust should surface the error *before*
  returning any verdicts for the batch where practical (validate-then-
  return), narrowing but not eliminating this window.
- `unknownCoValue`: any coId-first call for an unregistered CoValue —
  programming error, throws.
- Malformed change payloads never throw: they classify the transaction
  `invalid` with a reason, as TS does today.
- Wasm panics already surface as JS errors via the existing panic hook.

## Testing

1. **Fixture differential corpus (safety backbone).** A TS export script
   replays the `permissions`/`group` test scenarios through the *current TS
   implementation* and writes transaction histories + expected
   verdicts/roles to `crates/cojson-core/src/core/data/` (extending the
   existing `singleTxSession*.json` pattern). Rust unit tests replay them.
   Required coverage: all invite flows; admin/manager demotion and
   promotion rules; writeOnly key revelation and override rules; parent
   extensions (`extend` and capped, revocation, deep chains); everyone
   fallback; account-agent resolution (static header agent, account
   self→admin); merged/branched transactions (source-time ordering, reader
   branch pointers, and merged group transactions where `currentMadeAt !=
   sourceTxMadeAt` exercises the validation-order vs time-indexed
   asymmetry); late-arriving transactions with earlier `madeAt` that flip
   previously computed verdicts; cross-session equal-timestamp ordering
   ties.
2. **Existing TS suite as acceptance.** CI already runs `packages/cojson`
   against napi; the unchanged suite passing after each stage's delegation
   is the regression gate.
3. **Test-only differential harness.** A vitest helper runs native and TS
   fallback implementations over randomized group histories and asserts
   identical verdicts and roles. Runs in CI until the TS path is deleted,
   then retires with it.
4. **Benchmarks.** Add `bench/` cases for `roleOf` on deep parent chains and
   bulk validation of owned CoValues; record baselines before stage 2 and
   compare after stage 3.

## Rollout

Per stage: (a) `cojson-core` + napi + TS wiring behind the capability gate,
(b) wasm port, (c) RN/uniffi port. Stage N+1 may start once stage N's napi
PR lands — the gate keeps wasm/RN on the TS path meanwhile. Final PR (after
all bindings pass): TS logic deletion. Changesets stay within the existing
fixed-version group; CI's `napi.yml`/`unit-test.yml` already build the
native core on `crates/` changes.

## Risks

- **Semantic drift in a security-critical port.** Mitigated by the fixture
  corpus, verbatim reason strings, the randomized differential harness, and
  keeping orchestration in TS (approach A) so only verdict computation
  changes per stage.
- **Registry lifetime bugs (stage 1).** CoValues freed on GC/unload must be
  evicted explicitly; missing eviction leaks Rust memory, double eviction
  must be a no-op. Covered by GC tests on all providers.
- **Napi-first window.** Wasm/RN run the TS shim + TS validation until
  ported; the capability gate must be exercised in CI for both code paths
  the whole window.
- **`atTime` view semantics.** TS role queries happen on prototype-cloned
  time-travel views; Rust replaces this with explicit `atTimeMs` parameters.
  Any TS call site that reads other keys off the time-view (not just roles)
  keeps using the TS CoMap view — only role resolution delegates.
