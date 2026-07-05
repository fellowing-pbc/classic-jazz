/**
 * SHADOW-MODE content-decision comparison (Phase 2 of the sync-protocol port).
 *
 * This module runs the native Rust content decision (`content_to_send`)
 * ALONGSIDE the real TypeScript one (`VerifiedState.newContentSince`) purely to
 * observe whether they agree. It NEVER influences what is actually sent over the
 * wire, never mutates peer state, and is provably inert unless explicitly
 * enabled: the single entry point {@link maybeRunShadowContentCompare} short
 * circuits when {@link SHADOW_COMPARE_ENABLED} is false (the production
 * default), and even when enabled it only READS and records into
 * {@link shadowStats} — it can never throw into, or alter, the caller.
 *
 * Enable with `COJSON_SYNC_SHADOW_COMPARE=1` (read once at module load).
 */

import type { AvailableCoValueCore } from "./coValueCore/coValueCore.js";
import type { CoValueKnownState } from "./knownState.js";
import type { NewContentMessage } from "./sync.js";

/** Read once at module load; off by default. Only `"1"` enables the shadow. */
export const SHADOW_COMPARE_ENABLED: boolean =
  typeof process !== "undefined" &&
  process.env?.COJSON_SYNC_SHADOW_COMPARE === "1";

export type ShadowMismatch = {
  coValueId: string;
  /** Canonical JSON of the real (TS) content decision. */
  ts: string;
  /** Canonical JSON of the native (Rust) content decision. */
  native: string;
};

export type ShadowStats = {
  /** Comparisons where the native backend supports `contentToSend` and ran. */
  comparisons: number;
  matches: number;
  mismatches: number;
  /** Native computation threw (recorded, never propagated). */
  nativeErrors: number;
  /** Backend does not implement `contentToSend`; nothing compared. */
  skippedUnsupported: number;
  /** A bounded sample of mismatches for inspection/reporting. */
  mismatchExamples: ShadowMismatch[];
  /** A bounded sample of native errors for inspection/reporting. */
  errorExamples: { coValueId: string; error: string }[];
};

const MAX_EXAMPLES = 20;

export const shadowStats: ShadowStats = {
  comparisons: 0,
  matches: 0,
  mismatches: 0,
  nativeErrors: 0,
  skippedUnsupported: 0,
  mismatchExamples: [],
  errorExamples: [],
};

/** Reset all counters — for tests that want a clean slate. */
export function resetShadowStats(): void {
  shadowStats.comparisons = 0;
  shadowStats.matches = 0;
  shadowStats.mismatches = 0;
  shadowStats.nativeErrors = 0;
  shadowStats.skippedUnsupported = 0;
  shadowStats.mismatchExamples.length = 0;
  shadowStats.errorExamples.length = 0;
}

/**
 * Canonical structural serialization: object keys sorted, `undefined`-valued
 * keys dropped (so an omitted key and an explicit `undefined` compare equal),
 * arrays kept in order. Two structurally-equal content-message lists produce an
 * identical string; this is the equality oracle for the shadow comparison. It
 * absorbs benign differences (object key order, header field order) while
 * staying strict on transaction/piece/session ORDER, which is order-sensitive.
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue;
      out[key] = canonicalize(v);
    }
    return out;
  }
  return value;
}

function canonicalString(pieces: NewContentMessage[] | undefined): string {
  // `undefined` (nothing to send) and `null` both normalize to the same token.
  return JSON.stringify(canonicalize(pieces ?? null));
}

/**
 * SHADOW ENTRY POINT. When enabled, computes the native content decision for
 * the SAME CoValue + known state the caller just computed the real decision
 * for, and records whether they agree. Fully defensive: any error in the native
 * path or comparison is caught and counted, never rethrown, so a caller can
 * invoke this immediately after the real decision with zero risk to behavior.
 *
 * @param coValue the CoValue whose content the caller is deciding to send
 * @param knownState the SAME optimistic known state passed to `newContentSince`
 * @param realPieces the REAL result of `newContentSince` (used unconditionally
 *   by the caller; passed here only for comparison)
 */
export function maybeRunShadowContentCompare(
  coValue: AvailableCoValueCore,
  knownState: CoValueKnownState | undefined,
  realPieces: NewContentMessage[] | undefined,
): void {
  if (!SHADOW_COMPARE_ENABLED) return;

  try {
    const verified = coValue.verified;
    if (!verified.supportsNativeContentDecision()) {
      shadowStats.skippedUnsupported++;
      return;
    }

    let nativePieces: NewContentMessage[] | undefined;
    try {
      const result = verified.newContentSinceNative(knownState);
      if (!result.ok) {
        // The envelope now carries native failures in-band (an `error` kind);
        // `unsupported` is already handled above, so anything here is an error.
        throw new Error(
          result.kind === "error" ? result.message : "unsupported",
        );
      }
      nativePieces = result.value ?? undefined;
    } catch (error) {
      shadowStats.nativeErrors++;
      const message = error instanceof Error ? error.message : String(error);
      if (shadowStats.errorExamples.length < MAX_EXAMPLES) {
        shadowStats.errorExamples.push({
          coValueId: coValue.id,
          error: message,
        });
      }
      // Cross-file visibility (per-worker stats don't aggregate across test
      // files): surface each native error as a greppable structured line.
      // eslint-disable-next-line no-console
      console.error(
        `SHADOW_NATIVE_ERROR ${JSON.stringify({ coValueId: coValue.id, error: message })}`,
      );
      return;
    }

    shadowStats.comparisons++;

    const tsCanonical = canonicalString(realPieces);
    const nativeCanonical = canonicalString(nativePieces);

    if (tsCanonical === nativeCanonical) {
      shadowStats.matches++;
    } else {
      shadowStats.mismatches++;
      if (shadowStats.mismatchExamples.length < MAX_EXAMPLES) {
        shadowStats.mismatchExamples.push({
          coValueId: coValue.id,
          ts: tsCanonical,
          native: nativeCanonical,
        });
      }
      // Cross-file visibility (per-worker stats don't aggregate across test
      // files): surface each mismatch as a greppable structured line.
      // eslint-disable-next-line no-console
      console.error(
        `SHADOW_MISMATCH ${JSON.stringify({ coValueId: coValue.id, ts: tsCanonical, native: nativeCanonical })}`,
      );
    }
  } catch {
    // Defensive belt-and-braces: the shadow path must never disturb the caller.
    // A failure to even inspect state is silently ignored.
  }
}
