/**
 * SHADOW-MODE comparison report (Phase 2 of the sync-protocol port).
 *
 * Drives the full differential harness — every named scenario plus a seeded
 * property fuzz over many seeds — with the sync-layer shadow comparison ENABLED,
 * then reports how many native-vs-TS content decisions ran, matched, and
 * mismatched (with concrete examples). It asserts nothing about sync behavior
 * beyond convergence (the shadow path is inert); its job is to GATHER DATA on
 * how close the native `content_to_send` port is to TS `newContentSince`.
 *
 * Requires the flag: run with `COJSON_SYNC_SHADOW_COMPARE=1`. When the flag is
 * off (the default), the whole suite is skipped so this file is a no-op in the
 * normal test run.
 */
import { afterAll, describe, expect, test } from "vitest";
import {
  SHADOW_COMPARE_ENABLED,
  resetShadowStats,
  shadowStats,
} from "../syncShadowCompare.js";
import { captureScenario } from "./syncDifferential/harness.js";
import { makeSeedScenario } from "./syncDifferential/generator.js";
import { scenarios } from "./syncDifferential/scenarios.js";
import { SyncMessagesLog, TEST_NODE_CONFIG } from "./testUtils.js";

// Deterministic synchronous delivery, matching the golden-trace harness.
TEST_NODE_CONFIG.withAsyncPeers = false;

const SEED_COUNT = 100;

const suite = SHADOW_COMPARE_ENABLED ? describe : describe.skip;

suite("sync shadow-mode content-decision comparison", () => {
  afterAll(() => {
    // eslint-disable-next-line no-console
    console.log(
      "\n=== SYNC SHADOW COMPARE REPORT ===\n" +
        JSON.stringify(
          {
            comparisons: shadowStats.comparisons,
            matches: shadowStats.matches,
            mismatches: shadowStats.mismatches,
            nativeErrors: shadowStats.nativeErrors,
            skippedUnsupported: shadowStats.skippedUnsupported,
            mismatchExamples: shadowStats.mismatchExamples,
            errorExamples: shadowStats.errorExamples,
          },
          null,
          2,
        ) +
        "\n=== END REPORT ===\n",
    );
  });

  test("runs the shadow comparison across all named scenarios", async () => {
    resetShadowStats();
    for (const scenario of scenarios) {
      SyncMessagesLog.clear();
      const snapshot = await captureScenario(scenario);
      expect(snapshot.converged).toBe(true);
    }
    // eslint-disable-next-line no-console
    console.log(
      `[named scenarios] comparisons=${shadowStats.comparisons} matches=${shadowStats.matches} mismatches=${shadowStats.mismatches} nativeErrors=${shadowStats.nativeErrors} skipped=${shadowStats.skippedUnsupported}`,
    );
    // The shadow path must actually have run.
    expect(
      shadowStats.comparisons + shadowStats.skippedUnsupported,
    ).toBeGreaterThan(0);
  });

  test(`runs the shadow comparison across ${SEED_COUNT} fuzz seeds`, async () => {
    for (let seed = 1; seed <= SEED_COUNT; seed++) {
      SyncMessagesLog.clear();
      try {
        await captureScenario(makeSeedScenario(seed));
      } catch {
        // Convergence/data-loss is asserted by the golden-trace suite; here we
        // only care about exercising the shadow comparison, so swallow.
      }
    }
    // eslint-disable-next-line no-console
    console.log(
      `[after fuzz] comparisons=${shadowStats.comparisons} matches=${shadowStats.matches} mismatches=${shadowStats.mismatches} nativeErrors=${shadowStats.nativeErrors} skipped=${shadowStats.skippedUnsupported}`,
    );
  }, 600_000);
});
