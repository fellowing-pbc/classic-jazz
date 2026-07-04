/**
 * R6a wiring-gate benchmark (TypeScript side).
 *
 * Compares the incumbent pure-JS known-state combine against the UNAVOIDABLE
 * JSON-marshaling floor that any JSON-based native (NodeCore/FFI) combine must
 * pay on the JS side alone — before the FFI crossing and before Rust does any
 * work. If the marshal floor is already slower than the whole JS combine, a
 * native combine can never win on realistic (small) known-state sizes, which is
 * the R6a "do not wire" gate.
 *
 * Run: npx vitest --run --root . --project cojson knownStateCombine.bench
 * (It is a normal test that prints a table; assertions only sanity-check it ran.)
 */
import { describe, expect, test } from "vitest";
import type { RawCoID } from "../ids.js";
import {
  cloneKnownState,
  combineKnownStates,
  CoValueKnownState,
  KnownStateSessions,
} from "../knownState.js";

function makeState(n: number, base: number): CoValueKnownState {
  const sessions: Record<string, number> = {};
  for (let i = 0; i < n; i++) {
    // match the Rust bench's realistic long session-id strings
    sessions[
      `co_zGroup_session_z${String(i).padStart(4, "0")}AbCdEfGhIjKlMnOp`
    ] = base + i;
  }
  return {
    id: "co_zBenchKnownState" as RawCoID,
    header: true,
    sessions: sessions as KnownStateSessions,
  };
}

function opsPerSec(fn: () => void, seconds = 0.2): number {
  // warmup
  for (let i = 0; i < 1000; i++) fn();
  let count = 0;
  const start = performance.now();
  const end = start + seconds * 1000;
  while (performance.now() < end) {
    fn();
    count++;
  }
  const elapsed = (performance.now() - start) / 1000;
  return count / elapsed;
}

describe("known state combine bench", () => {
  test("combine vs FFI marshal floor", { timeout: 30_000 }, () => {
    const sizes = [5, 50, 500];
    const rows: string[] = [];
    rows.push(
      "size | jsCombine op/s | jsonRoundtrip(2x in) op/s | stringify(2x) op/s | parse(result) op/s",
    );

    for (const n of sizes) {
      const target = makeState(n, 100);
      const source = makeState(n, 100_000);
      const targetJson = JSON.stringify(target);
      const sourceJson = JSON.stringify(source);
      const combinedJson = JSON.stringify(
        combineKnownStates(cloneKnownState(target), source),
      );

      // (1) the incumbent: pure-JS combine (clone + merge), the real call shape
      const jsCombine = opsPerSec(() => {
        combineKnownStates(cloneKnownState(target), source);
      });

      // (2) the FFI-in floor: what JS must do just to hand two states across a
      // JSON boundary and read them back — stringify both args + parse both
      // (the Rust side would also parse, but this is already a JS-only lower
      // bound on a native call's cost).
      const jsonRoundtrip = opsPerSec(() => {
        JSON.parse(JSON.stringify(target));
        JSON.parse(JSON.stringify(source));
      });

      // (3) just stringify both args (what a NodeCore call must serialize to send)
      const stringify2x = opsPerSec(() => {
        JSON.stringify(target);
        JSON.stringify(source);
      });

      // (4) just parse the combined result (what JS must do to read the answer back)
      const parseResult = opsPerSec(() => {
        JSON.parse(combinedJson);
      });

      // sanity: the JSON forms are non-trivial
      expect(targetJson.length).toBeGreaterThan(0);
      expect(sourceJson.length).toBeGreaterThan(0);

      rows.push(
        `${String(n).padEnd(4)} | ${jsCombine.toFixed(0).padStart(14)} | ${jsonRoundtrip
          .toFixed(0)
          .padStart(
            25,
          )} | ${stringify2x.toFixed(0).padStart(18)} | ${parseResult
          .toFixed(0)
          .padStart(18)}`,
      );
    }

    // eslint-disable-next-line no-console
    console.log("\n" + rows.join("\n") + "\n");
    expect(rows.length).toBe(sizes.length + 1);
  });
});
