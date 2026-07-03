# NodeCore Registry (Stage 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-CoValue Rust `SessionMap` binding objects with a single per-`LocalNode` `NodeCore` registry (coId-keyed), natively in napi and via a TS shim for wasm/RN — zero behavior change.

**Architecture:** A `NodeCore` struct in `crates/cojson-core` owns all `SessionMapImpl`s keyed by CoID and exposes `create/has/remove/get/get_mut`. The napi binding lifts the existing `SessionMap` method surface onto a `#[napi] NodeCore` with `coId` as first parameter. On the TS side, a new `NodeCoreImpl` interface replaces `SessionMapImpl` as what `VerifiedState` talks to; `CryptoProvider.createNodeCore()` defaults to a TS shim over the existing per-CoValue `createSessionMap` (keeps wasm/RN working unchanged), and `NapiCrypto` overrides it with the native registry. `LocalNode` owns the instance and evicts CoValues explicitly.

**Tech Stack:** Rust (cojson-core), napi-rs v3 (cojson-core-napi), TypeScript (packages/cojson), vitest, cargo test.

**Spec:** `docs/superpowers/specs/2026-07-03-cojson-rust-permissions-migration-design.md` (Stage 1 section). Stages 2–3 get their own plans after this lands.

**Working notes for the implementer:**

- Build napi after Rust changes: `pnpm build:napi` (repo root; see CONTRIBUTING.md "cojson-core Setup"). Rust tests: `cargo test -p cojson-core` from `crates/`.
- TS tests: `pnpm test` inside `packages/cojson` (runs `vitest --run --root ../../ --project cojson`). Run single files with `pnpm test <path substring>`.
- Do NOT touch `crates/cojson-core-wasm` or `crates/cojson-core-rn` in this plan — the TS shim covers them; native ports are separate follow-up PRs per the spec's napi-first rollout.
- No Claude/AI mentions in commits.

---

### Task 1: Rust `NodeCore` registry in cojson-core

**Files:**
- Create: `crates/cojson-core/src/core/node.rs`
- Modify: `crates/cojson-core/src/lib.rs` (register module)
- Modify: `crates/cojson-core/src/core/session_map.rs` (new error variant)

Error-type note: `SessionMapImpl::new_with_skip_verify` returns
`Result<Self, SessionMapError>` (session_map.rs:339-345), and `SessionMapError`
has `#[from] CoJsonCoreError` (session_map.rs:270) — the reverse conversion
does NOT exist. All `NodeCore` fallible methods therefore use
`SessionMapError`, and the new variant goes on `SessionMapError`.

- [ ] **Step 1: Add the `UnknownCoValue` error variant**

In `crates/cojson-core/src/core/session_map.rs`, add to the `SessionMapError` enum (declared at line 247, alongside the existing variants):

```rust
    #[error("Unknown CoValue: {0}")]
    UnknownCoValue(String),
```

- [ ] **Step 2: Write failing tests for the registry (and register the module)**

Immediately register the module so the red step actually compiles the file: in `crates/cojson-core/src/lib.rs`, inside `pub mod core { ... }`, add after the `session_map` lines:

```rust
    pub mod node;
    pub use node::*;
```

Then create `crates/cojson-core/src/core/node.rs` containing only the test module for now (the tests reference `NodeCore`, which doesn't exist yet). Reuse the header-construction helper style from `session_map.rs`'s tests — look at how existing tests in that file build a valid `(co_id, header_json)` pair (they use fixtures / `compute_co_id_from_header`); copy the same helper into this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session_map::{SessionMapError, SessionMapImpl};

    // Build a valid header + matching co_id the same way session_map.rs tests do:
    // create a SessionMapImpl via an existing test fixture header, then reuse its
    // co_id/header. Simplest: copy the exact header JSON + co_id constants used by
    // an existing passing test in session_map.rs.
    fn valid_header() -> (String, String) {
        // (co_id, header_json) — copy the constants from a session_map.rs test
        // that constructs SessionMapImpl::new successfully.
        unimplemented!("copy from session_map.rs test constants")
    }

    #[test]
    fn create_has_remove_roundtrip() {
        let (co_id, header_json) = valid_header();
        let mut node = NodeCore::new();
        assert!(!node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 0);

        node.create_co_value(&co_id, &header_json, None, false).unwrap();
        assert!(node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 1);
        assert!(node.get(&co_id).is_ok());

        assert!(node.remove_co_value(&co_id));
        assert!(!node.has_co_value(&co_id));
        assert_eq!(node.co_value_count(), 0);
    }

    #[test]
    fn remove_absent_is_noop() {
        let mut node = NodeCore::new();
        assert!(!node.remove_co_value("co_zDoesNotExist"));
        // double-remove after create
        let (co_id, header_json) = valid_header();
        node.create_co_value(&co_id, &header_json, None, false).unwrap();
        assert!(node.remove_co_value(&co_id));
        assert!(!node.remove_co_value(&co_id));
    }

    #[test]
    fn get_unknown_covalue_errors() {
        let node = NodeCore::new();
        match node.get("co_zDoesNotExist") {
            Err(SessionMapError::UnknownCoValue(id)) => assert_eq!(id, "co_zDoesNotExist"),
            other => panic!("expected UnknownCoValue, got {other:?}"),
        }
    }

    #[test]
    fn create_replaces_existing_entry() {
        // Matches TS semantics: `new VerifiedState(sameId)` today creates a fresh
        // SessionMap; createCoValue must replace, not error.
        let (co_id, header_json) = valid_header();
        let mut node = NodeCore::new();
        node.create_co_value(&co_id, &header_json, None, false).unwrap();
        node.create_co_value(&co_id, &header_json, None, false).unwrap();
        assert_eq!(node.co_value_count(), 1);
    }

    #[test]
    fn invalid_header_does_not_insert() {
        let mut node = NodeCore::new();
        assert!(node.create_co_value("co_zBogus", "{not json", None, false).is_err());
        assert!(!node.has_co_value("co_zBogus"));
    }
}
```

Fill `valid_header()` with real constants copied from an existing green `session_map.rs` test before proceeding.

- [ ] **Step 3: Run tests to verify they fail to compile**

Run: `cd crates && cargo test -p cojson-core node::`
Expected: compile error — `NodeCore` not found.

- [ ] **Step 4: Implement `NodeCore`**

Add above the test module in `crates/cojson-core/src/core/node.rs`:

```rust
use std::collections::HashMap;

use crate::core::session_map::{SessionMapError, SessionMapImpl};

/// Node-level registry owning one SessionMapImpl per CoValue, keyed by CoID.
/// One instance per LocalNode. Stage 2+ builds cross-CoValue features
/// (group engine, permissions) on top of this registry.
pub struct NodeCore {
    covalues: HashMap<String, SessionMapImpl>,
}

impl NodeCore {
    pub fn new() -> Self {
        NodeCore {
            covalues: HashMap::new(),
        }
    }

    /// Create (or replace) the SessionMapImpl for a CoValue.
    /// Replace-on-existing matches current TS semantics, where constructing a
    /// new VerifiedState for an already-known id creates a fresh SessionMap.
    pub fn create_co_value(
        &mut self,
        co_id: &str,
        header_json: &str,
        max_tx_size: Option<u32>,
        skip_verify: bool,
    ) -> Result<(), SessionMapError> {
        let session_map =
            SessionMapImpl::new_with_skip_verify(co_id, header_json, max_tx_size, skip_verify)?;
        self.covalues.insert(co_id.to_string(), session_map);
        Ok(())
    }

    pub fn has_co_value(&self, co_id: &str) -> bool {
        self.covalues.contains_key(co_id)
    }

    /// Returns true if an entry was removed. Absent id is a no-op (false).
    pub fn remove_co_value(&mut self, co_id: &str) -> bool {
        self.covalues.remove(co_id).is_some()
    }

    pub fn co_value_count(&self) -> usize {
        self.covalues.len()
    }

    pub fn get(&self, co_id: &str) -> Result<&SessionMapImpl, SessionMapError> {
        self.covalues
            .get(co_id)
            .ok_or_else(|| SessionMapError::UnknownCoValue(co_id.to_string()))
    }

    pub fn get_mut(&mut self, co_id: &str) -> Result<&mut SessionMapImpl, SessionMapError> {
        self.covalues
            .get_mut(co_id)
            .ok_or_else(|| SessionMapError::UnknownCoValue(co_id.to_string()))
    }
}

impl Default for NodeCore {
    fn default() -> Self {
        Self::new()
    }
}
```

Note: bindings resolve the entry via `get`/`get_mut` and call `SessionMapImpl` methods directly — `NodeCore` does not re-wrap the whole per-CoValue surface (that double delegation would be ~300 lines of noise; stage 2 adds cross-CoValue logic here instead).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd crates && cargo test -p cojson-core`
Expected: all tests pass, including the 5 new `node::tests`.

- [ ] **Step 6: Commit**

```bash
git add crates/cojson-core/src/core/node.rs crates/cojson-core/src/core/session_map.rs crates/cojson-core/src/lib.rs
git commit -m "feat(cojson-core): NodeCore registry owning SessionMapImpls by CoID"
```

---

### Task 2: Napi `NodeCore` binding

**Files:**
- Modify: `crates/cojson-core-napi/src/lib.rs` (add `NodeCore` wrapper; keep the existing `SessionMap` wrapper untouched — wasm/RN parity and rollback both want it alive until the final cleanup PR)

- [ ] **Step 1: Add the `NodeCore` napi wrapper**

In `crates/cojson-core-napi/src/lib.rs`, add `NodeCore as RustNodeCore` to the existing `cojson_core::core::{...}` import, then append after the `SessionMap` impl block. The lifted methods are the existing `#[napi] impl SessionMap` bodies with (a) `co_id: String` prepended to the parameters, (b) `self.internal` replaced by the resolved entry. Error helper + registry methods + three fully worked examples:

```rust
fn to_napi_err<E: std::fmt::Display>(e: E) -> napi::Error {
  napi::Error::new(napi::Status::GenericFailure, e.to_string())
}

#[napi]
pub struct NodeCore {
  internal: RustNodeCore,
}

#[napi]
impl NodeCore {
  #[napi(constructor)]
  #[allow(clippy::new_without_default)]
  pub fn new() -> NodeCore {
    NodeCore {
      internal: RustNodeCore::new(),
    }
  }

  // === Registry ===

  #[napi]
  pub fn create_co_value(
    &mut self,
    co_id: String,
    header_json: String,
    max_tx_size: Option<u32>,
    skip_verify: Option<bool>,
  ) -> napi::Result<()> {
    self
      .internal
      .create_co_value(&co_id, &header_json, max_tx_size, skip_verify.unwrap_or(false))
      .map_err(to_napi_err)
  }

  #[napi]
  pub fn has_co_value(&self, co_id: String) -> bool {
    self.internal.has_co_value(&co_id)
  }

  #[napi]
  pub fn remove_co_value(&mut self, co_id: String) -> bool {
    self.internal.remove_co_value(&co_id)
  }

  #[napi]
  pub fn co_value_count(&self) -> u32 {
    self.internal.co_value_count() as u32
  }

  // === Lifted SessionMap surface (worked examples) ===

  #[napi]
  pub fn get_header(&self, co_id: String) -> napi::Result<String> {
    Ok(self.internal.get(&co_id).map_err(to_napi_err)?.get_header())
  }

  #[napi]
  pub fn add_transactions(
    &mut self,
    co_id: String,
    session_id: String,
    signer_id: Option<String>,
    transactions_json: String,
    signature: String,
    skip_verify: bool,
  ) -> napi::Result<()> {
    self
      .internal
      .get_mut(&co_id)
      .map_err(to_napi_err)?
      .add_transactions(
        &session_id,
        signer_id.as_deref(),
        &transactions_json,
        &signature,
        skip_verify,
      )
      .map_err(to_napi_err)
  }

  #[napi]
  pub fn get_transaction_count(&self, co_id: String, session_id: String) -> napi::Result<i32> {
    let sm = self.internal.get(&co_id).map_err(to_napi_err)?;
    // Same -1-if-absent convention as the SessionMap wrapper
    Ok(sm.get_transaction_count(&session_id).map(|c| c as i32).unwrap_or(-1))
  }

  // ... remaining methods
}
```

Now lift the REMAINING methods by the same two-step transformation (prepend `co_id: String`; replace `self.internal` with `self.internal.get(&co_id).map_err(to_napi_err)?` for `&self` methods or `self.internal.get_mut(&co_id).map_err(to_napi_err)?` for `&mut self` methods), copying each body from the existing `#[napi] impl SessionMap` block in this same file so every conversion (JSON strings, `KnownState::from`, `-1` conventions, `Option` → `null`) is preserved exactly:

`make_new_private_transaction`, `make_new_trusting_transaction`, `get_session_ids`, `get_transaction`, `get_session_transactions`, `get_last_signature`, `get_signature_after`, `get_last_signature_checkpoint`, `get_known_state`, `get_known_state_with_streaming`, `is_streaming`, `set_streaming_known_state`, `mark_as_deleted`, `is_deleted`, `decrypt_transaction`, `decrypt_transaction_meta`.

Cross-check afterward: `grep -c "pub fn" ` on the `impl SessionMap` block vs the new `impl NodeCore` block — NodeCore must have every SessionMap method plus the constructor and 4 registry methods.

- [ ] **Step 2: Build the napi package**

Run: `pnpm build:napi` (repo root)
Expected: build succeeds; `packages/cojson-core-napi` (the JS package wrapping the binary) regenerates its `.d.ts` including `export declare class NodeCore` with camelCased methods (`createCoValue`, `addTransactions`, …).

- [ ] **Step 3: Smoke-test from Node**

Run (repo root):

```bash
node -e "
const { NodeCore } = require('cojson-core-napi');
const n = new NodeCore();
console.log('count', n.coValueCount());
console.log('has', n.hasCoValue('co_zNope'));
console.log('remove', n.removeCoValue('co_zNope'));
try { n.getHeader('co_zNope'); } catch (e) { console.log('err ok:', /Unknown CoValue/.test(e.message)); }
"
```

Expected output: `count 0`, `has false`, `remove false`, `err ok: true`.
(If `require('cojson-core-napi')` fails from repo root, run inside `packages/cojson` where it is a dependency.)

- [ ] **Step 4: Commit**

```bash
git add crates/cojson-core-napi packages/cojson-core-napi
git commit -m "feat(cojson-core-napi): NodeCore registry binding with lifted SessionMap surface"
```

---

### Task 3: TS `NodeCoreImpl` interface + shim + provider default

**Files:**
- Modify: `packages/cojson/src/crypto/crypto.ts` (add `NodeCoreImpl`, `createNodeCore()`, `dispose?` on `SessionMapImpl`)
- Create: `packages/cojson/src/crypto/ShimNodeCore.ts`
- Modify: `packages/cojson/src/crypto/WasmCrypto.ts` (adapter `dispose()`)
- Test: `packages/cojson/src/tests/shimNodeCore.test.ts`

- [ ] **Step 1: Define `NodeCoreImpl` in crypto.ts**

Add after the `SessionMapImpl` interface (crypto.ts:390). It is the `SessionMapImpl` surface with `coId` as first parameter plus registry methods (`Transaction` is already imported in crypto.ts at line 13 — do NOT add a duplicate import):

```ts
/**
 * NodeCoreImpl - node-level registry of per-CoValue session state.
 * One instance per LocalNode; every method addresses a CoValue by its id.
 */
export interface NodeCoreImpl {
  // === Registry ===
  createCoValue(
    coId: string,
    headerJson: string,
    maxTxSize?: number,
    skipVerify?: boolean,
  ): void;
  hasCoValue(coId: string): boolean;
  /** No-op if absent. Frees the CoValue's native memory. */
  removeCoValue(coId: string): void;
  coValueCount(): number;

  // === Header ===
  getHeader(coId: string): string;

  // === Transaction Operations ===
  addTransactions(
    coId: string,
    sessionId: string,
    signerId: string | undefined,
    transactionsJson: string,
    signature: string,
    skipVerify: boolean,
  ): void;
  makeNewPrivateTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    keyId: string,
    keySecret: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string;
  makeNewTrustingTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string;

  // === Session Queries ===
  getSessionIds(coId: string): string[];
  getTransactionCount(coId: string, sessionId: string): number;
  getTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): Transaction | undefined;
  getSessionTransactions(
    coId: string,
    sessionId: string,
    fromIndex: number,
  ): Transaction[] | undefined;
  getLastSignature(coId: string, sessionId: string): string | undefined;
  getSignatureAfter(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): string | undefined;
  getLastSignatureCheckpoint(
    coId: string,
    sessionId: string,
  ): number | undefined;

  // === Known State ===
  getKnownState(coId: string): {
    id: string;
    header: boolean;
    sessions: Record<string, number>;
  };
  getKnownStateWithStreaming(
    coId: string,
  ):
    | { id: string; header: boolean; sessions: Record<string, number> }
    | undefined;
  isStreaming(coId: string): boolean;
  setStreamingKnownState(coId: string, streamingJson: string): void;

  // === Deletion ===
  markAsDeleted(coId: string): void;
  isDeleted(coId: string): boolean;

  // === Decryption ===
  decryptTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined;
  decryptTransactionMeta(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined;
}
```

Also add to the existing `SessionMapImpl` interface (used by the shim to free wasm memory):

```ts
  /** Optional: free native resources eagerly (wasm). */
  dispose?(): void;
```

And add to the `CryptoProvider` abstract class, next to `abstract createSessionMap`:

```ts
  /**
   * Node-level registry. Default: TS shim over per-CoValue session maps
   * (wasm/RN until their native NodeCore ports land). NapiCrypto overrides
   * this with the native registry.
   */
  createNodeCore(): NodeCoreImpl {
    return new ShimNodeCore((coId, headerJson, maxTxSize, skipVerify) =>
      this.createSessionMap(coId, headerJson, maxTxSize, skipVerify),
    );
  }
```

with `import { ShimNodeCore } from "./ShimNodeCore.js";` at the top of crypto.ts. (ShimNodeCore imports only *types* from crypto.ts, so the cycle is type-only and safe.)

- [ ] **Step 2: Write the failing shim test**

Create `packages/cojson/src/tests/shimNodeCore.test.ts`. Use whatever crypto provider the existing tests in `src/tests` use to get a working `createSessionMap` (grep a neighboring test for its crypto setup helper and reuse it — most use a `WasmCrypto.create()` or `NapiCrypto.create()` awaited in `beforeAll`):

```ts
import { beforeAll, describe, expect, test } from "vitest";
import { NapiCrypto } from "../crypto/NapiCrypto.js";
import { ShimNodeCore } from "../crypto/ShimNodeCore.js";
import type { CryptoProvider } from "../crypto/crypto.js";

let crypto: CryptoProvider;

beforeAll(async () => {
  crypto = await NapiCrypto.create();
});

function makeShim() {
  return new ShimNodeCore((coId, headerJson, maxTxSize, skipVerify) =>
    crypto.createSessionMap(coId, headerJson, maxTxSize, skipVerify),
  );
}

// Build a real header + coId the way VerifiedState does, so createCoValue
// passes native header validation.
function makeHeaderAndId() {
  const header = {
    type: "comap" as const,
    ruleset: { type: "unsafeAllowAll" as const },
    meta: null,
    createdAt: null,
    uniqueness: "test-uniqueness",
  };
  const coId = `co_z${crypto.shortHash(header).slice("shortHash_z".length)}`;
  return { coId, headerJson: JSON.stringify(header) };
}

describe("ShimNodeCore", () => {
  test("createCoValue / hasCoValue / removeCoValue roundtrip", () => {
    const shim = makeShim();
    const { coId, headerJson } = makeHeaderAndId();

    expect(shim.hasCoValue(coId)).toBe(false);
    expect(shim.coValueCount()).toBe(0);

    shim.createCoValue(coId, headerJson);
    expect(shim.hasCoValue(coId)).toBe(true);
    expect(shim.coValueCount()).toBe(1);
    expect(JSON.parse(shim.getHeader(coId))).toMatchObject({ type: "comap" });

    shim.removeCoValue(coId);
    expect(shim.hasCoValue(coId)).toBe(false);
    expect(shim.coValueCount()).toBe(0);
    // double remove is a no-op
    shim.removeCoValue(coId);
  });

  test("unknown coId throws with Unknown CoValue message", () => {
    const shim = makeShim();
    expect(() => shim.getHeader("co_zNope")).toThrow(/Unknown CoValue: co_zNope/);
    expect(() => shim.getSessionIds("co_zNope")).toThrow(/Unknown CoValue/);
  });

  test("delegates session queries to the underlying session map", () => {
    const shim = makeShim();
    const { coId, headerJson } = makeHeaderAndId();
    shim.createCoValue(coId, headerJson);
    expect(shim.getSessionIds(coId)).toEqual([]);
    expect(shim.getTransactionCount(coId, "co_zAnybody_session_z123")).toBe(-1);
    expect(shim.getKnownState(coId)).toMatchObject({ id: coId, header: true, sessions: {} });
  });
});
```

Adjust `makeHeaderAndId()` if native header validation rejects it: mirror exactly how `VerifiedState`/`CoValueCore` construct headers in existing tests (grep `createdAt: null` under `src/tests` for a working literal) — the assertion targets registry behavior, not header rules.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd packages/cojson && pnpm test shimNodeCore`
Expected: FAIL — `ShimNodeCore` module not found.

- [ ] **Step 4: Implement the shim**

Create `packages/cojson/src/crypto/ShimNodeCore.ts`:

```ts
import type { Transaction } from "../coValueCore/verifiedState.js";
import type { NodeCoreImpl, SessionMapImpl } from "./crypto.js";

type SessionMapFactory = (
  coId: string,
  headerJson: string,
  maxTxSize?: number,
  skipVerify?: boolean,
) => SessionMapImpl;

/**
 * NodeCoreImpl implemented over per-CoValue SessionMapImpl objects.
 * Used by providers without a native NodeCore (wasm, RN) until their
 * native ports land. Mirrors the native registry's semantics exactly:
 * replace-on-create, no-op remove, "Unknown CoValue: <id>" on misses.
 */
export class ShimNodeCore implements NodeCoreImpl {
  private readonly covalues = new Map<string, SessionMapImpl>();

  constructor(private readonly createSessionMap: SessionMapFactory) {}

  private get(coId: string): SessionMapImpl {
    const entry = this.covalues.get(coId);
    if (!entry) {
      throw new Error(`Unknown CoValue: ${coId}`);
    }
    return entry;
  }

  createCoValue(
    coId: string,
    headerJson: string,
    maxTxSize?: number,
    skipVerify?: boolean,
  ): void {
    const replaced = this.covalues.get(coId);
    this.covalues.set(
      coId,
      this.createSessionMap(coId, headerJson, maxTxSize, skipVerify),
    );
    replaced?.dispose?.();
  }

  hasCoValue(coId: string): boolean {
    return this.covalues.has(coId);
  }

  removeCoValue(coId: string): void {
    const entry = this.covalues.get(coId);
    this.covalues.delete(coId);
    entry?.dispose?.();
  }

  coValueCount(): number {
    return this.covalues.size;
  }

  getHeader(coId: string): string {
    return this.get(coId).getHeader();
  }

  addTransactions(
    coId: string,
    sessionId: string,
    signerId: string | undefined,
    transactionsJson: string,
    signature: string,
    skipVerify: boolean,
  ): void {
    this.get(coId).addTransactions(
      sessionId,
      signerId,
      transactionsJson,
      signature,
      skipVerify,
    );
  }

  makeNewPrivateTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    keyId: string,
    keySecret: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string {
    return this.get(coId).makeNewPrivateTransaction(
      sessionId,
      signerSecret,
      changesJson,
      keyId,
      keySecret,
      metaJson,
      madeAt,
    );
  }

  makeNewTrustingTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string {
    return this.get(coId).makeNewTrustingTransaction(
      sessionId,
      signerSecret,
      changesJson,
      metaJson,
      madeAt,
    );
  }

  getSessionIds(coId: string): string[] {
    return this.get(coId).getSessionIds();
  }

  getTransactionCount(coId: string, sessionId: string): number {
    return this.get(coId).getTransactionCount(sessionId);
  }

  getTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): Transaction | undefined {
    return this.get(coId).getTransaction(sessionId, txIndex);
  }

  getSessionTransactions(
    coId: string,
    sessionId: string,
    fromIndex: number,
  ): Transaction[] | undefined {
    return this.get(coId).getSessionTransactions(sessionId, fromIndex);
  }

  getLastSignature(coId: string, sessionId: string): string | undefined {
    return this.get(coId).getLastSignature(sessionId);
  }

  getSignatureAfter(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): string | undefined {
    return this.get(coId).getSignatureAfter(sessionId, txIndex);
  }

  getLastSignatureCheckpoint(
    coId: string,
    sessionId: string,
  ): number | undefined {
    return this.get(coId).getLastSignatureCheckpoint(sessionId);
  }

  getKnownState(coId: string): {
    id: string;
    header: boolean;
    sessions: Record<string, number>;
  } {
    return this.get(coId).getKnownState();
  }

  getKnownStateWithStreaming(
    coId: string,
  ):
    | { id: string; header: boolean; sessions: Record<string, number> }
    | undefined {
    return this.get(coId).getKnownStateWithStreaming();
  }

  isStreaming(coId: string): boolean {
    return this.get(coId).isStreaming();
  }

  setStreamingKnownState(coId: string, streamingJson: string): void {
    this.get(coId).setStreamingKnownState(streamingJson);
  }

  markAsDeleted(coId: string): void {
    this.get(coId).markAsDeleted();
  }

  isDeleted(coId: string): boolean {
    return this.get(coId).isDeleted();
  }

  decryptTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined {
    return this.get(coId).decryptTransaction(sessionId, txIndex, keySecret);
  }

  decryptTransactionMeta(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined {
    return this.get(coId).decryptTransactionMeta(sessionId, txIndex, keySecret);
  }
}
```

- [ ] **Step 5: Add `dispose()` to the wasm adapter**

In `packages/cojson/src/crypto/WasmCrypto.ts`, the `SessionMapAdapter` class (around line 283) wraps the wasm-bindgen `SessionMap` object, which has a `free()` method. Add to the adapter:

```ts
  dispose(): void {
    this.sessionMap.free();
  }
```

(Leave `RNCrypto.ts` alone: uniffi objects are collected by JS GC as today; `dispose` is optional.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd packages/cojson && pnpm test shimNodeCore`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add packages/cojson/src/crypto/crypto.ts packages/cojson/src/crypto/ShimNodeCore.ts packages/cojson/src/crypto/WasmCrypto.ts packages/cojson/src/tests/shimNodeCore.test.ts
git commit -m "feat(cojson): NodeCoreImpl interface with shim default over per-CoValue session maps"
```

---

### Task 4: Native `NodeCoreImpl` in NapiCrypto

**Files:**
- Modify: `packages/cojson/src/crypto/NapiCrypto.ts`
- Test: `packages/cojson/src/tests/shimNodeCore.test.ts` (extend to run the same suite against the native adapter)

- [ ] **Step 1: Extend the test to cover the native adapter**

In `packages/cojson/src/tests/shimNodeCore.test.ts`, refactor the `describe` block into a function parameterized by a `makeNodeCore(): NodeCoreImpl` factory and run it twice:

```ts
import type { NodeCoreImpl } from "../crypto/crypto.js";

function nodeCoreSuite(name: string, makeNodeCore: () => NodeCoreImpl) {
  describe(name, () => {
    // ...the three existing tests, using makeNodeCore() instead of makeShim()...
  });
}

nodeCoreSuite("ShimNodeCore", () =>
  new ShimNodeCore((coId, headerJson, maxTxSize, skipVerify) =>
    crypto.createSessionMap(coId, headerJson, maxTxSize, skipVerify),
  ),
);
nodeCoreSuite("NapiNodeCore (native)", () => crypto.createNodeCore());
```

- [ ] **Step 2: Run to verify the native suite fails**

Run: `cd packages/cojson && pnpm test shimNodeCore`
Expected: Shim suite PASSES; native suite FAILS or falls back to the shim (because `NapiCrypto` doesn't override `createNodeCore` yet — the default returns the shim, so it may spuriously pass; to make the red step real, assert the adapter class name):

```ts
test("NapiCrypto.createNodeCore returns the native adapter", () => {
  expect(crypto.createNodeCore().constructor.name).toBe("NapiNodeCoreAdapter");
});
```

Expected: FAIL (`ShimNodeCore` !== `NapiNodeCoreAdapter`).

- [ ] **Step 3: Implement the native adapter**

In `packages/cojson/src/crypto/NapiCrypto.ts`:

1. Add `NodeCore as NativeNodeCore` to the `cojson-core-napi` import list.
2. Add `NodeCoreImpl` to the `./crypto.js` import list.
3. Add to the `NapiCrypto` class:

```ts
  override createNodeCore(): NodeCoreImpl {
    return new NapiNodeCoreAdapter(new NativeNodeCore());
  }
```

4. Add the adapter class next to `SessionMapAdapter`. It is the same mechanical shape as `SessionMapAdapter` with `coId` threaded through — every method delegates to `this.nodeCore.<method>(coId, ...)` and applies the identical JSON-parse / `?? undefined` conversions. Worked examples plus the rule:

```ts
/**
 * Adapter wrapping the native NodeCore registry to implement NodeCoreImpl.
 */
class NapiNodeCoreAdapter implements NodeCoreImpl {
  constructor(private readonly nodeCore: NativeNodeCore) {}

  createCoValue(
    coId: string,
    headerJson: string,
    maxTxSize?: number,
    skipVerify?: boolean,
  ): void {
    this.nodeCore.createCoValue(coId, headerJson, maxTxSize, skipVerify);
  }

  hasCoValue(coId: string): boolean {
    return this.nodeCore.hasCoValue(coId);
  }

  removeCoValue(coId: string): void {
    this.nodeCore.removeCoValue(coId);
  }

  coValueCount(): number {
    return this.nodeCore.coValueCount();
  }

  getSessionTransactions(
    coId: string,
    sessionId: string,
    fromIndex: number,
  ): Transaction[] | undefined {
    const result = this.nodeCore.getSessionTransactions(coId, sessionId, fromIndex);
    if (!result) return undefined;
    return result.map((tx) => JSON.parse(tx) as Transaction);
  }

  getLastSignature(coId: string, sessionId: string): string | undefined {
    return this.nodeCore.getLastSignature(coId, sessionId) ?? undefined;
  }

  // ...remaining methods
}
```

Implement the remaining `NodeCoreImpl` methods (`getHeader`, `addTransactions`, `makeNewPrivateTransaction`, `makeNewTrustingTransaction`, `getSessionIds`, `getTransactionCount`, `getTransaction`, `getSignatureAfter`, `getLastSignatureCheckpoint`, `getKnownState`, `getKnownStateWithStreaming`, `isStreaming`, `setStreamingKnownState`, `markAsDeleted`, `isDeleted`, `decryptTransaction`, `decryptTransactionMeta`) by copying the corresponding `SessionMapAdapter` method body in this same file and inserting `coId` as the first argument to the native call. Keep conversions identical (`JSON.parse` for `getTransaction`/`getSessionTransactions`, `?? undefined` for nullable returns, direct object return for known state).

- [ ] **Step 4: Run tests to verify all pass**

Run: `cd packages/cojson && pnpm test shimNodeCore`
Expected: PASS — both suites plus the adapter-class assertion.

- [ ] **Step 5: Commit**

```bash
git add packages/cojson/src/crypto/NapiCrypto.ts packages/cojson/src/tests/shimNodeCore.test.ts
git commit -m "feat(cojson): native NodeCore adapter in NapiCrypto"
```

---

### Task 5: Rewire `VerifiedState` and `LocalNode` onto `NodeCoreImpl`

**Files:**
- Modify: `packages/cojson/src/localNode.ts` (own the NodeCore instance)
- Modify: `packages/cojson/src/coValueCore/verifiedState.ts` (talk to NodeCoreImpl)
- Modify: `packages/cojson/src/coValueCore/coValueCore.ts:591` (construction site)
- Modify: test files constructing `VerifiedState` directly (found by grep)

- [ ] **Step 1: LocalNode owns a NodeCore**

In `packages/cojson/src/localNode.ts`, add a public readonly field and initialize it in the constructor (constructor is at line 85; add after `this.crypto = crypto;` at line 98):

```ts
  readonly nodeCore: NodeCoreImpl;
```

```ts
    this.nodeCore = crypto.createNodeCore();
```

with `NodeCoreImpl` added to the existing `./crypto/crypto.js` type imports.

- [ ] **Step 2: Rewire VerifiedState**

In `packages/cojson/src/coValueCore/verifiedState.ts`:

1. Replace the field (line 83) `private readonly impl: SessionMapImpl;` with:

```ts
  private readonly nodeCore: NodeCoreImpl;
```

2. Change the constructor (lines 97–121) to accept the registry and register the CoValue:

```ts
  constructor(
    id: RawCoID,
    crypto: CryptoProvider,
    nodeCore: NodeCoreImpl,
    header: CoValueHeader,
    streamingKnownState?: KnownStateSessions,
    skipVerify?: boolean,
  ) {
    this.id = id;
    this.crypto = crypto;
    this.header = header;
    this.branchSourceId = header.meta?.source as RawCoID | undefined;
    this.branchName = header.meta?.branch as string | undefined;

    this.nodeCore = nodeCore;
    this.nodeCore.createCoValue(
      id,
      JSON.stringify(header),
      TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE,
      skipVerify,
    );

    if (streamingKnownState) {
      this.nodeCore.setStreamingKnownState(
        id,
        JSON.stringify(streamingKnownState),
      );
    }
  }
```

3. Mechanically rewrite every remaining `this.impl.<method>(<args>)` call in the file to `this.nodeCore.<method>(this.id, <args>)`. Find them all with `grep -n "this.impl" packages/cojson/src/coValueCore/verifiedState.ts` (they are concentrated in `updateSessionLogCache`, `getSessionLog`, `tryAddTransactions`, `makeNewPrivateTransaction`, `makeNewTrustingTransaction`, the signature/known-state/streaming getters, `markAsDeleted`, and the decrypt helpers). Example — line 145:

```ts
    const currentTxCount = this.impl.getTransactionCount(sessionID);
```

becomes

```ts
    const currentTxCount = this.nodeCore.getTransactionCount(this.id, sessionID);
```

After the rewrite, `grep -c "this.impl" verifiedState.ts` must be 0, and the `SessionMapImpl` import can be replaced with `NodeCoreImpl`.

4. If `VerifiedState` has a `clone`/branch helper that constructs `new VerifiedState(...)` internally (check with `grep -n "new VerifiedState" verifiedState.ts`), thread `this.nodeCore` through it.

- [ ] **Step 3: Update the construction site**

At `packages/cojson/src/coValueCore/coValueCore.ts:591`, add the registry argument (the surrounding CoValueCore has `this.node`):

```ts
      this._verified = new VerifiedState(
        // existing args...
      );
```

becomes the same call with `this.node.nodeCore` inserted as the third argument (after `crypto`), matching the new signature `(id, crypto, nodeCore, header, streamingKnownState?, skipVerify?)`.

- [ ] **Step 4: Update direct constructions in tests**

Run: `grep -rn "new VerifiedState" packages/cojson/src packages/jazz-tools/src 2>/dev/null`
Expected: exactly one hit — coValueCore.ts:591, already updated in Step 3. This step is a verification guard: if any other hits appear (e.g. tests added since this plan was written), insert a registry as the third argument (`node.nodeCore` where a LocalNode exists, else `crypto.createNodeCore()`).

- [ ] **Step 5: Typecheck and run the full cojson suite**

Run: `cd packages/cojson && pnpm exec tsc --noEmit && pnpm test`
Expected: typecheck clean; full suite PASSES (this is the stage's behavior-preservation gate — any failure here is a real regression, fix before proceeding).

- [ ] **Step 6: Commit**

```bash
git add packages/cojson/src
git commit -m "refactor(cojson): route VerifiedState through node-level NodeCore registry"
```

---

### Task 6: Eviction wiring + eviction test

**Files:**
- Modify: `packages/cojson/src/localNode.ts:199-250` (`internalDeleteCoValue`, `internalUnmountCoValue`)
- Test: `packages/cojson/src/tests/nodeCoreEviction.test.ts`

- [ ] **Step 1: Write the failing eviction test**

Create `packages/cojson/src/tests/nodeCoreEviction.test.ts`. Reuse the repo's standard test-node helper (grep `src/tests` for the helper used to create a connected `LocalNode` — e.g. `createTestNode`/`setupTestNode` in a `testUtils` module; use exactly that):

```ts
import { describe, expect, test } from "vitest";
// import the same node-creation helper neighboring tests use, e.g.:
// import { setupTestNode } from "./testUtils.js";

describe("NodeCore eviction", () => {
  test("internalDeleteCoValue removes the registry entry", () => {
    const { node } = setupTestNode();
    const group = node.createGroup();
    const map = group.createMap();

    expect(node.nodeCore.hasCoValue(map.id)).toBe(true);
    const before = node.nodeCore.coValueCount();

    node.internalDeleteCoValue(map.id);

    expect(node.nodeCore.hasCoValue(map.id)).toBe(false);
    expect(node.nodeCore.coValueCount()).toBe(before - 1);
    // double delete is a no-op
    node.internalDeleteCoValue(map.id);
  });

  test("internalUnmountCoValue removes the registry entry", async () => {
    // Unmount preconditions (no listeners, no in-memory dependants, synced):
    // mirror the EXACT setup of the existing unmount test at
    // src/tests/sync.concurrentLoad.test.ts:1074 (client/server pair, synced
    // map, then client.node.internalUnmountCoValue(map.id)). Copy its helpers.
    // ... setup copied from that test ...

    const unmounted = client.node.internalUnmountCoValue(map.id);
    expect(unmounted).toBe(true);
    expect(client.node.nodeCore.hasCoValue(map.id)).toBe(false);
    // The shell left in node.coValues must not resurrect a registry entry
    client.node.getCoValue(map.id);
    expect(client.node.nodeCore.hasCoValue(map.id)).toBe(false);
  });

  test("re-registration after unmount goes through VerifiedState creation", async () => {
    // Same setup as above, then reload the CoValue's content from the peer
    // the way the existing unmount test does (e.g. node.load(map.id) /
    // loadCoValueCore — copy the reload mechanism from
    // sync.concurrentLoad.test.ts's post-unmount assertions).
    // After the reload completes, the header was re-provided, a new
    // VerifiedState was constructed, and the registry entry must be back:
    // expect(client.node.nodeCore.hasCoValue(map.id)).toBe(true);
  });

  test("gracefulShutdown evicts all registry entries", async () => {
    const { node } = setupTestNode();
    const group = node.createGroup();
    group.createMap();
    expect(node.nodeCore.coValueCount()).toBeGreaterThan(0);

    await node.gracefulShutdown();

    expect(node.nodeCore.coValueCount()).toBe(0);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/cojson && pnpm test nodeCoreEviction`
Expected: FAIL — `hasCoValue` still true after delete/unmount (no eviction wired).

- [ ] **Step 3: Wire eviction into LocalNode**

In `packages/cojson/src/localNode.ts`:

`internalDeleteCoValue` (line 199):

```ts
  internalDeleteCoValue(id: RawCoID) {
    this.coValues.delete(id);
    this.nodeCore.removeCoValue(id);
    this.storage?.onCoValueUnmounted(id);
  }
```

`internalUnmountCoValue` (line 210) — add the removal right after the shell replacement (after `this.coValues.set(id, shell);` at line 244):

```ts
    this.coValues.set(id, shell);
    this.nodeCore.removeCoValue(id);
```

`gracefulShutdown` (line 999) — the spec lists node shutdown as an eviction
path; deterministic eviction also covers the wasm shim, whose per-entry
`free()` otherwise waits for GC. Add at the start of the method:

```ts
  async gracefulShutdown(): Promise<unknown> {
    for (const id of this.coValues.keys()) {
      this.nodeCore.removeCoValue(id);
    }
    this.garbageCollector?.stop();
    // ...existing body...
```

- [ ] **Step 4: Run the eviction test and the full suite**

Run: `cd packages/cojson && pnpm test nodeCoreEviction && pnpm test`
Expected: eviction tests PASS; full suite still green (the GC path in `GarbageCollector.collect()` calls `internalUnmountCoValue`, so it is covered by this wiring).

- [ ] **Step 5: Commit**

```bash
git add packages/cojson/src/localNode.ts packages/cojson/src/tests/nodeCoreEviction.test.ts
git commit -m "feat(cojson): evict CoValues from NodeCore registry on delete/unmount"
```

---

### Task 7: Cross-package verification + changeset

**Files:**
- Create: `.changeset/<generated-name>.md`

- [ ] **Step 1: Run the dependent-package suites**

Run from repo root: `pnpm build:all-packages && pnpm exec turbo run test --filter=cojson --filter=jazz-tools`
Expected: builds and tests green. jazz-tools exercises wasm (`WasmCrypto` + shim path) in its browser-targeted tests — this validates the shim under a real consumer.

- [ ] **Step 2: Rust + napi final check**

Run: `cd crates && cargo test -p cojson-core && cargo clippy -p cojson-core -p cojson-core-napi -- -D warnings`
Expected: green, no clippy warnings.

- [ ] **Step 3: Add a changeset**

Create a changeset covering `cojson`, `cojson-core-napi` (patch bumps, consistent with the repo's fixed-version group — check `.changeset/config.json` `fixed` entry to confirm package names):

```markdown
---
"cojson": patch
"cojson-core-napi": patch
---

Introduce a node-level NodeCore registry owning all per-CoValue session state
(native in napi; TS shim over per-CoValue session maps for wasm/RN). No
behavior change; groundwork for moving permissions and group state into the
Rust core.
```

- [ ] **Step 4: Commit**

```bash
git add .changeset
git commit -m "chore: changeset for NodeCore registry"
```

---

## Explicitly out of scope (follow-up plans)

- Native `NodeCore` in `cojson-core-wasm` and `cojson-core-rn` (napi-first rollout; the shim keeps those platforms shippable).
- Stage 2 (group engine: `validateGroup`, `roleOf`) and Stage 3 (`validateTransactions`, `resetValidation`) — separate plans, per the spec.
- Removing the per-CoValue `SessionMap` binding surface — happens in the final cleanup PR after wasm/RN native ports land.
