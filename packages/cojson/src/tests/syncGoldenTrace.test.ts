/**
 * Differential / golden-trace harness driver.
 *
 * Phase 0 of the sync-protocol port. This suite:
 *
 *   1. Runs a representative set of multi-peer scenarios through the CURRENT
 *      all-TypeScript SyncManager and freezes each one's normalized golden
 *      snapshot (ordered wire trace + per-node confirmed/optimistic known-state +
 *      convergence verdict) as a committed JSON fixture. These fixtures are the
 *      ORACLE a future native-sync port will be diffed against; today there is no
 *      native sync to diff, so the job is only to ESTABLISH and freeze the oracle.
 *
 *   2. Proves the harness is DETERMINISTIC: every representative scenario is run
 *      twice and its normalized output must be byte-identical (this is the
 *      meta-test that makes the golden files trustworthy).
 *
 *   3. Runs a seeded, model-based property generator over >=100 seeds, asserting
 *      eventual CONVERGENCE and NO DATA LOSS on each — the mechanism that will
 *      catch the silent split-brain / optimistic-loss failure modes once there is
 *      native sync code to run through the same harness.
 *
 * Regenerate the golden fixtures with EXPORT_GOLDEN_TRACES=1.
 *
 * TEST-ONLY. Touches no production sync code path.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, test } from "vitest";
import {
  captureScenario,
  serializeGolden,
} from "./syncDifferential/harness.js";
import { makeSeedScenario } from "./syncDifferential/generator.js";
import { scenarios } from "./syncDifferential/scenarios.js";
import { SyncMessagesLog, TEST_NODE_CONFIG } from "./testUtils.js";

// Deterministic synchronous peer delivery.
//
// The live suite runs with `withAsyncPeers = true` (setTimeout(0) delivery) to
// mimic real network timing. That is deliberately NOT used here: under async
// delivery the ordered wire trace depends on wall-clock interleaving of the
// harness's `waitFor`/`stabilize` polls, so two runs of the same scenario are not
// byte-reproducible — which would defeat the determinism gate and make the golden
// files untrustworthy. Synchronous delivery preserves causal message order
// (including streaming chunk order, the property we care about) while removing the
// timing nondeterminism, so the trace becomes a stable oracle. A future native
// diff runs through the exact same synchronous transport.
TEST_NODE_CONFIG.withAsyncPeers = false;

const EXPORT = process.env.EXPORT_GOLDEN_TRACES === "1";
const GOLDEN_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "syncDifferential/golden",
);

beforeEach(() => {
  SyncMessagesLog.clear();
});

describe("sync golden-trace oracle", () => {
  for (const scenario of scenarios) {
    test(`golden: ${scenario.name}`, async () => {
      const snapshot = await captureScenario(scenario);
      const serialized = serializeGolden(snapshot);
      const path = join(GOLDEN_DIR, `${scenario.name}.json`);

      if (EXPORT) {
        mkdirSync(GOLDEN_DIR, { recursive: true });
        writeFileSync(path, serialized);
      }

      // The oracle must exist and match. On first-ever run, EXPORT writes it.
      expect(
        existsSync(path),
        `golden fixture missing for ${scenario.name}; run with EXPORT_GOLDEN_TRACES=1`,
      ).toBe(true);

      const committed = readFileSync(path, "utf8");
      expect(serialized).toBe(committed);

      // Every representative scenario must converge.
      expect(snapshot.converged).toBe(true);
    });
  }
});

describe("sync harness determinism (meta-test)", () => {
  for (const scenario of scenarios) {
    test(`deterministic: ${scenario.name}`, async () => {
      const first = serializeGolden(await captureScenario(scenario));
      SyncMessagesLog.clear();
      const second = serializeGolden(await captureScenario(scenario));
      // Same scenario, two independent runs (fresh random ids each time) ->
      // byte-identical normalized output.
      expect(second).toBe(first);
    });
  }
});

describe("sync convergence property (seeded model-based)", () => {
  const SEED_COUNT = 100;

  test(`converges + no data loss across ${SEED_COUNT} seeds`, async () => {
    const failures: string[] = [];

    for (let seed = 1; seed <= SEED_COUNT; seed++) {
      SyncMessagesLog.clear();
      try {
        // captureScenario runs the seed (whose run() throws on data loss) and
        // computes the convergence verdict.
        const snapshot = await captureScenario(makeSeedScenario(seed));
        if (!snapshot.converged) {
          failures.push(
            `seed ${seed}: did not converge: ${JSON.stringify(
              snapshot.convergence,
            )}`,
          );
        }
      } catch (e) {
        failures.push(`seed ${seed}: ${(e as Error).message}`);
      }
    }

    expect(failures, failures.slice(0, 10).join("\n")).toEqual([]);
  }, // Generous budget: 100 seeds x real async multi-peer sync (some streaming).
  600_000);
});
