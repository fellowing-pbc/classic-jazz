/**
 * Differential / golden-trace harness driver for the STORAGE layer.
 *
 * Phase 0 of the storage-layer port. This suite:
 *
 *   1. Runs a representative set of storage scenarios through the CURRENT
 *      all-TypeScript storage clients and freezes each one's normalized golden
 *      snapshot (ordered storage message trace + per-checkpoint DB row-state +
 *      durability-window / lock-decision captures) as a committed JSON fixture.
 *      These fixtures are the ORACLE a future native storage port would be
 *      diffed against; today there is no native storage to diff, so the job is
 *      only to ESTABLISH and freeze the oracle.
 *
 *   2. Proves the harness is DETERMINISTIC: every scenario is run twice and its
 *      normalized output must be byte-identical (the meta-test that makes the
 *      golden files trustworthy).
 *
 * The crash-window durability scenario is explicitly included — its
 * callback-timing sequence is the single highest-value capture given the team's
 * recent hardening work.
 *
 * Regenerate the golden fixtures with EXPORT_STORAGE_GOLDEN=1.
 *
 * TEST-ONLY. Touches no production storage read/write code path.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, test } from "vitest";
import {
  captureStorageScenario,
  serializeStorageGolden,
} from "./storageDifferential/harness.js";
import { storageScenarios } from "./storageDifferential/scenarios.js";
import { SyncMessagesLog, TEST_NODE_CONFIG } from "./testUtils.js";
import { registerStorageCleanupRunner } from "./testStorage.js";

// Deterministic synchronous peer delivery — same rationale as the sync harness:
// async delivery makes the observable ordering depend on wall-clock
// interleaving, which would defeat the determinism gate.
TEST_NODE_CONFIG.withAsyncPeers = false;

const EXPORT = process.env.EXPORT_STORAGE_GOLDEN === "1";
const GOLDEN_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "storageDifferential/golden",
);

beforeEach(() => {
  // Registered first so it runs last (after node/storage shutdown hooks).
  registerStorageCleanupRunner();
  SyncMessagesLog.clear();
});

describe("storage golden-trace oracle", () => {
  for (const scenario of storageScenarios) {
    test(`golden: ${scenario.name}`, async () => {
      const snapshot = await captureStorageScenario(scenario);
      const serialized = serializeStorageGolden(snapshot);
      const path = join(GOLDEN_DIR, `${scenario.name}.json`);

      if (EXPORT) {
        mkdirSync(GOLDEN_DIR, { recursive: true });
        writeFileSync(path, serialized);
      }

      expect(
        existsSync(path),
        `golden fixture missing for ${scenario.name}; run with EXPORT_STORAGE_GOLDEN=1`,
      ).toBe(true);

      const committed = readFileSync(path, "utf8");
      expect(serialized).toBe(committed);
    });
  }
});

describe("storage harness determinism (meta-test)", () => {
  for (const scenario of storageScenarios) {
    test(`deterministic: ${scenario.name}`, async () => {
      const first = serializeStorageGolden(
        await captureStorageScenario(scenario),
      );
      SyncMessagesLog.clear();
      const second = serializeStorageGolden(
        await captureStorageScenario(scenario),
      );
      // Same scenario, two independent runs (fresh random ids) → byte-identical
      // normalized output.
      expect(second).toBe(first);
    });
  }
});
