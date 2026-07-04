# CoValueCore in Rust — full CRDT materialization

**Date:** 2026-07-04
**Status:** Active. Successor to the permissions migration (spec 2026-07-03, shipped as PRs #3531-#3536).

## Goal — and the acceptance bar

Move CoValueCore's entire content pipeline and ALL CRDT materialization into
`cojson-core`: transaction parsing/decryption, meta/fww processing,
branch/merge semantics, and the view state for coMap, coList, coStream/coFeed,
coPlainText, and binary streams. TypeScript keeps sync orchestration, storage
adapters, and thin public API façades over Rust-resident views.

**The acceptance bar is performance, not architecture.** The migration is not
done until the benchmarked read/write paths are FASTER in Rust than the current
TypeScript implementation — on Node (napi) AND in the browser (wasm). "Single
implementation" is a side effect, not the goal. Every phase that ships behind a
gate must carry benchmark numbers; a phase that regresses performance does not
ship until fixed.

Lesson that dictates the architecture (measured in stage 2/3): FFI crossings
and JSON marshaling dominate — `roleOf` was ~20-25% slower and the
delegation-heavy validation path ~7x slower than in-process TS. Therefore:
**views live in Rust; the boundary carries snapshots and deltas, never
per-transaction or per-key chatter.** Fine-grained `get(coId, key)` FFI calls
are presumed disqualified until a benchmark proves otherwise.

## What already exists (built by the permissions migration)

- `NodeCore` registry (per-LocalNode), engine-cache freshness patterns,
  cross-CoValue access, `reset_validation`.
- `tx_view`: parsed transaction views, validation ordering, meta precedence,
  source-identity plumbing.
- Full permission engine: verdicts for every ruleset, `role_of`,
  `TimeBasedEntry` (the atTime read primitive — structurally identical to what
  coMap's `getRaw` needs).
- 25 frozen golden fixtures + the exporter (regenerator), 17 porter notes,
  three binding crates at surface parity.

## Phases — speed-first ordering

### R0 — Prove the payoff (prototype + benchmark gate) ← START HERE

Build the minimal Rust coMap materialization over TRUSTING transactions (no
key/decryption dependency): per-key op indices over the valid-transaction set
(reusing the engine's verdicts + `TimeBasedEntry` generalized to arbitrary
keys), `latest` + `atTime` reads, fww incorporated (port the TS fww overlay for
owned covalues — it decides key winners and cannot be approximated).

Implement THREE candidate read boundaries and benchmark all of them against
the TS `RawCoMap` baseline on realistic shapes (100-key map / 10k-op map /
hot-loop single-key reads / full-snapshot iteration), on napi AND wasm:

1. Per-key FFI accessor (expected loser — include to quantify).
2. Bulk snapshot export (whole materialized map as one crossing, JSON or
   napi/serde objects).
3. Rust-resident view + delta subscription: TS holds a version cursor; reads
   hit a TS-side cache that is invalidated/patched by compact deltas pulled
   after each ingest (one crossing per change-batch, zero crossings for
   repeated reads).

**Gate:** at least one boundary beats the TS baseline on the majority of the
bench shapes on BOTH runtimes. If none does, stop and redesign — do not
proceed to R1 on hope. The winning boundary becomes the pattern for every CRDT.

### R1 — Keys and decryption in Rust

Per-CoValue key store inside `NodeCore`: TS key management (unsealing,
rotation, revelation chains — which stays in TS) FEEDS secrets to Rust as it
learns them; Rust decrypts private transactions internally and adds them to
materialization. Design notes: secrets enter native memory (document the
security posture); key-miss behavior must mirror TS (undecryptable txs are
skipped from views, retried after `provide_key` + reset). This unlocks private
data in views and deletes the TS-side per-transaction decrypt loop.

### R2 — Pipeline completion

Native meta parsing (sourceTxMadeAt/sourceTxID derivation — currently supplied
via `pending`; Rust owns it outright), branch/merge semantics
(`branchSourceId`, merge application), and frontier filters. This deletes the
`pending` plumbing, the last `roleOfInternal` TS carve-out (branch views go
native), and the TS `VerifiedTransaction` decrypt/meta queues.

### R3 — coMap ships

Full coMap materialization (trusting + private + branches + fww) behind a
capability gate; `RawCoMap` becomes a façade over the R0-winning boundary.
Fixture corpus extended with content-materialization fixtures (ops → expected
view state, atTime grids, branch views, fww races) exported from the TS
implementation BEFORE its deletion — same frozen-golden-file discipline.
Benchmarks must show the R0 win holds on the real integration. Then the TS
coMap read path is deleted.

### R4 — The remaining CRDTs

coStream/coFeed (per-session append — simplest), coPlainText, binary streams,
and coList last (insertion-ordering semantics hardest; gets the largest
fixture corpus). Same per-type cycle: fixtures → port → gate → bench → delete
TS path.

### R5 — CoValueCore handle-ification

With views, validation, decryption, and pipeline all native, TS `CoValueCore`
reduces to: sync/storage orchestration + a handle. Delete the TS transaction
state machine, `getValidTransactions`, the parsing caches. Final benchmark
report against the pre-migration baseline closes the migration.

## Process (deliberately lighter than the permissions migration)

- No external model reviews of specs/plans; two-stage review stays for
  implementation tasks but tasks are cut LARGER. Fixtures and benchmarks are
  the safety net — they caught every real bug last time.
- Wasm artifacts: every phase that touches Rust rebuilds and re-verifies in
  the browser (example apps) before its PR. The manual browser pass is cheap
  and caught what CI structurally cannot (no wasm recompile gate yet — build
  that gate in R0).
- Stacked PRs continue on the existing stack until it merges; then base on
  main.
- The frozen golden fixtures rule stands: regeneration must never change
  verdict/content semantics.

## Known risks

- **R0 disproves the thesis** (no boundary beats TS): possible on wasm where
  crossings are cheapest to underestimate. That's why R0 is first and small.
- **Key secrets in native memory** (R1): needs an explicit security note;
  wasm memory is inspectable by the page anyway (same trust domain), napi is
  process memory — no worse than TS heap, but document it.
- **coList ordering fidelity** (R4): the TS insertion semantics have years of
  edge cases; the fixture corpus must be generated exhaustively before port.
- **Dual maintenance window**: every phase keeps the TS path alive until its
  gate+bench pass; the differential-style checks return per CRDT type.
