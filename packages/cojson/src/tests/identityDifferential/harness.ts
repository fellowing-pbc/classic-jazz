/**
 * Differential / golden-trace harness for PURE IDENTITY RESOLUTION.
 *
 * Phase 0 oracle for the (pure, synchronous, zero-mutation) identity-resolution
 * slice of `LocalNode`:
 *
 *   - `resolveAccountAgent(id)` — header/ruleset inspection: an agent-ID resolves
 *     to itself; an account CoValue resolves to its `ruleset.initialAdmin`; any
 *     other shape (not-loaded, not-a-group, non-account meta, non-agent admin)
 *     resolves to a classified error.
 *   - `accountOrAgentIDfromSessionID(sessionID)` — the pure string lens that
 *     `getCurrentAccountOrAgentID()` delegates to.
 *   - `internalCreateAccount(...)` — the deterministic account-bootstrap write
 *     sequence (golden-trace oracle, mirroring the `rotate_read_key` fixtures).
 *
 * This harness is TEST-ONLY and OBSERVATIONAL. It never modifies, wires into, or
 * imports mutably any production code path — it only calls the existing public
 * (`resolveAccountAgent`) / internal (`accountOrAgentIDfromSessionID`,
 * `internalCreateAccount`) surfaces and normalizes their outputs.
 *
 * Determinism strategy (mirroring the `rotateReadKey` fixtures): identities are
 * derived from FIXED secret seeds and the account bootstrap's single random
 * `newRandomKeySecret` is captured into the fixture, so two independent runs and
 * the committed golden are byte-identical and the goldens are self-describing.
 * The captured resolution outcomes and header shapes are consumed unchanged by
 * the native Rust replay (`crates/cojson-core/src/core/identity_resolution.rs`).
 */
import type { CoValueHeader } from "../../coValueCore/verifiedState.js";

/** The two error classes `resolveAccountAgent` can surface, normalized to a
 *  language-agnostic tag so TS and the native replay agree. */
export type ErrorKind = "unavailable" | "not_account";

/** Normalized outcome of `resolveAccountAgent`, derived from the REAL result. */
export type ResolveExpectation = {
  /** the resolved agent id, or null when an error was produced */
  value: string | null;
  /** null on success, else the classified error tag */
  errorKind: ErrorKind | null;
};

/** One `resolveAccountAgent` differential case + everything the native replay
 *  needs to reproduce it (the id, whether the covalue was loaded, its header). */
export type ResolutionCase = {
  description: string;
  /** id passed to `resolveAccountAgent` (an account id or an agent id) */
  id: string;
  /** whether the covalue was available/loaded at resolution time */
  available: boolean;
  /** the covalue header the resolution inspects (null for agent / unavailable) */
  header: CoValueHeader | null;
  /** normalized outcome derived from the REAL `resolveAccountAgent` */
  expected: ResolveExpectation;
};

/** One `accountOrAgentIDfromSessionID` differential case. */
export type SessionIdCase = {
  description: string;
  sessionId: string;
  /** the REAL `accountOrAgentIDfromSessionID(sessionId)` output */
  expected: string;
};

/** A single captured `(field, value)` write from the account bootstrap. */
export type BootstrapWrite = { field: string; value: string };

/** Golden trace of the deterministic `internalCreateAccount` bootstrap. */
export type BootstrapTrace = {
  description: string;
  /** hex of the fixed secret seed the agent secret was derived from */
  secretSeed: string;
  agentSecret: string;
  agentId: string;
  accountId: string;
  /** the fixed read key injected for the run (makes the golden self-describing) */
  readKey: { id: string; secret: string };
  /** the exact ordered `(field, value)` writes the bootstrap performed */
  writes: BootstrapWrite[];
};

/**
 * Classify a REAL `resolveAccountAgent` result into a normalized expectation.
 *
 * `resolveAccountAgent` returns `{ value, error }`. Both header-mismatch branches
 * (not-a-group / non-account meta / non-agent admin) throw the same
 * "Unexpectedly not account" message; the not-loaded branch surfaces the
 * `expectCoValueLoaded` "not yet loaded" error. We collapse to a stable tag.
 */
export function classifyResolution(result: {
  value: string | undefined;
  error: unknown;
}): ResolveExpectation {
  if (!result.error) {
    return { value: result.value ?? null, errorKind: null };
  }
  const message =
    result.error instanceof Error ? result.error.message : String(result.error);
  const errorKind: ErrorKind = /Unexpectedly not account/.test(message)
    ? "not_account"
    : "unavailable";
  return { value: null, errorKind };
}

/** Stable JSON serialization + trailing newline (matches the repo formatter). */
export function serializeGolden(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}
