// Stage-1 FFI round-trip verification for the storage per-session write decision,
// driving the REAL compiled wasm module (mirrors the napi test of the same name).
//
// Feeds each golden fixture *step*'s input through the JSON wire boundary
// (`planSessionWrite`) and asserts the returned `SessionWritePlan` matches the
// fixture's observed `expected` decision field-by-field. Since the pure-Rust
// fixture tests already lock the pure function's output to those same `expected`
// values (derived from OBSERVED real StorageApiSync behaviour), `wasm(step) ===
// expected` here proves the wasm wire format neither loses nor corrupts a byte,
// including the i64 byte-size / rolling-total values. Nothing in cojson
// production TS calls this yet (storage wiring is gated behind a later
// default-false flag).

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";

import { initialize, planSessionWrite } from "../index";

beforeAll(async () => {
  await initialize();
});

const FIXTURE_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../cojson-core/data/storage_write_plan",
);

type Step = {
  label: string;
  lastIdx: number;
  after: number;
  bytesSinceLastSignature: number;
  newTxSizes: number[];
  maxRecommendedTxSize: number;
  expected: {
    invalidGap: boolean;
    noOp: boolean;
    actuallyNewCount: number;
    newLastIdx: number;
    shouldWriteSignature: boolean;
    signatureIdx: number | null;
    newBytesSinceLastSignature: number;
  };
};

const fixtureNames = readdirSync(FIXTURE_DIR)
  .filter((n) => n.endsWith(".json"))
  .sort();

describe("storage write-plan FFI round-trip (wasm)", () => {
  test("11 golden fixtures present", () => {
    expect(fixtureNames.length).toBe(11);
  });

  for (const file of fixtureNames) {
    const fx = JSON.parse(
      readFileSync(resolve(FIXTURE_DIR, file), "utf8"),
    ) as { description: string; steps: Step[] };

    describe(file, () => {
      for (const step of fx.steps) {
        test(step.label, () => {
          // The response is the unified native-result envelope; plan is `value`.
          const env = JSON.parse(planSessionWrite(JSON.stringify(step)));
          expect(env.ok).toBe(true);
          const out = env.value;
          expect(out.invalidGap).toBe(step.expected.invalidGap);
          expect(out.noOp).toBe(step.expected.noOp);
          expect(out.actuallyNewCount).toBe(step.expected.actuallyNewCount);
          expect(out.newLastIdx).toBe(step.expected.newLastIdx);
          expect(out.shouldWriteSignature).toBe(
            step.expected.shouldWriteSignature,
          );
          expect(out.signatureIdx ?? null).toBe(step.expected.signatureIdx);
          expect(out.newBytesSinceLastSignature).toBe(
            step.expected.newBytesSinceLastSignature,
          );
        });
      }
    });
  }
});

describe("error propagation across the FFI boundary (wasm)", () => {
  test("malformed JSON yields an error-kind envelope (not a throw)", () => {
    const env = JSON.parse(planSessionWrite("{ not json"));
    expect(env.ok).toBe(false);
    expect(env.kind).toBe("error");
    expect(typeof env.message).toBe("string");
  });
});
