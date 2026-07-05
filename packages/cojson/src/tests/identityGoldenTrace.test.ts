/**
 * Differential / golden-trace harness driver for PURE IDENTITY RESOLUTION.
 *
 * Phase 0 oracle for the pure identity-resolution slice of `LocalNode`
 * (`resolveAccountAgent`, `accountOrAgentIDfromSessionID`) plus the deterministic
 * `internalCreateAccount` bootstrap. This suite:
 *
 *   1. Freezes each capture as a committed JSON fixture:
 *        - resolution cases + session-id cases -> the Rust data dir
 *          (`crates/cojson-core/data/identity_resolution/`), where the native
 *          replay (`identity_resolution.rs`) reads and reproduces them.
 *        - the account-bootstrap trace -> this package's golden dir (TS-only
 *          oracle; no native replay of the write path is in scope).
 *   2. Proves the harness is DETERMINISTIC: every capture is run twice and its
 *      normalized output must be byte-identical (the meta-test that makes the
 *      goldens trustworthy).
 *
 * Regenerate all fixtures with EXPORT_IDENTITY_GOLDEN=1.
 *
 * TEST-ONLY. Touches no production code path — only observes existing surfaces.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { serializeGolden } from "./identityDifferential/harness.js";
import {
  buildBootstrapTrace,
  buildResolutionCases,
  buildSessionIdCases,
} from "./identityDifferential/scenarios.js";

const EXPORT = process.env.EXPORT_IDENTITY_GOLDEN === "1";
const HERE = dirname(fileURLToPath(import.meta.url));

// Resolution + session-id fixtures live in the Rust data dir (like the
// rotateReadKey fixtures) so the native replay can read them directly.
const RUST_DATA_DIR = join(
  HERE,
  "../../../../crates/cojson-core/data/identity_resolution",
);
// The bootstrap trace is a TS-only oracle.
const GOLDEN_DIR = join(HERE, "identityDifferential/golden");

function checkGolden(dir: string, name: string, serialized: string) {
  const path = join(dir, `${name}.json`);
  if (EXPORT) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path, serialized);
  }
  expect(
    existsSync(path),
    `golden fixture missing for ${name}; run with EXPORT_IDENTITY_GOLDEN=1`,
  ).toBe(true);
  expect(serialized).toBe(readFileSync(path, "utf8"));
}

describe("identity resolution golden-trace oracle", () => {
  test("golden: resolution cases", async () => {
    checkGolden(
      RUST_DATA_DIR,
      "resolution",
      serializeGolden(await buildResolutionCases()),
    );
  });

  test("golden: session-id cases", () => {
    checkGolden(
      RUST_DATA_DIR,
      "session_ids",
      serializeGolden(buildSessionIdCases()),
    );
  });

  test("golden: internalCreateAccount bootstrap trace", async () => {
    checkGolden(
      GOLDEN_DIR,
      "internal_create_account",
      serializeGolden(await buildBootstrapTrace()),
    );
  });
});

describe("identity harness determinism (meta-test)", () => {
  test("deterministic: resolution cases", async () => {
    const first = serializeGolden(await buildResolutionCases());
    const second = serializeGolden(await buildResolutionCases());
    expect(second).toBe(first);
  });

  test("deterministic: session-id cases", () => {
    const first = serializeGolden(buildSessionIdCases());
    const second = serializeGolden(buildSessionIdCases());
    expect(second).toBe(first);
  });

  test("deterministic: internalCreateAccount bootstrap trace", async () => {
    const first = serializeGolden(await buildBootstrapTrace());
    const second = serializeGolden(await buildBootstrapTrace());
    expect(second).toBe(first);
  });
});
