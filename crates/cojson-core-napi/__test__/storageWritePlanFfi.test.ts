// Stage-1 FFI round-trip verification for the storage per-session write decision.
//
// Drives the REAL compiled napi addon (`../index`) exactly as JS would, feeding
// each golden fixture *step*'s input through the JSON wire boundary
// (`planSessionWrite`) and asserting the returned `SessionWritePlan` matches the
// fixture's observed `expected` decision field-by-field.
//
// Why this proves the FFI boundary is lossless: the pure-Rust fixture tests
// (`cargo test -p cojson-core`) already lock the pure function's output to these
// same `expected` values, and were themselves derived from OBSERVED real
// `StorageApiSync` behaviour against real libsql. So `napi(step) === expected`
// here, combined with `pure(step) === expected` there, gives
// `napi(step) === pure(step)` — the napi wire format (JSON in / JSON out) neither
// loses nor corrupts a byte, INCLUDING the i64 byte-size / rolling-total values
// that a scalar-argument napi signature would otherwise marshal as BigInt.
// Nothing in cojson production TS calls this yet (storage wiring is gated behind
// a later default-false flag); this file imports the addon directly.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, test } from "vitest";

import { planSessionWrite } from "../index";

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

describe("storage write-plan FFI round-trip (napi)", () => {
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
          // Feed the step's exact input object straight through the wire (the
          // wrapper ignores the fixture-only `label`/`expected` keys). The
          // response is the unified native-result envelope; the plan is `value`.
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

describe("error propagation across the FFI boundary (napi)", () => {
  test("malformed JSON yields an error-kind envelope (not a throw)", () => {
    const env = JSON.parse(planSessionWrite("{ not json"));
    expect(env.ok).toBe(false);
    expect(env.kind).toBe("error");
    expect(typeof env.message).toBe("string");
  });
});
