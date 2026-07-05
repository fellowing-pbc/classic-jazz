/**
 * PeerKnownState fixture exporter.
 *
 * Captures the CURRENT TypeScript behavior of the stateful `PeerKnownState`
 * wrapper (packages/cojson/src/coValueCore/PeerKnownState.ts) as executable
 * fixtures for the Rust port (crates/cojson-core/src/core/peer_known_state.rs).
 *
 * Unlike the pure `knownState.ts` algebra, `PeerKnownState` is STATEFUL: its
 * behavior depends on the sequence of operations applied (in particular the
 * lazy-clone-of-optimistic-from-confirmed and the reset-on-set / reset-on-clone
 * semantics). So each fixture drives a full operation SEQUENCE against a REAL
 * `PeerKnownState` instance and records, after every step, the resulting
 * confirmed (`value()`) and optimistic (`optimisticValue()`) states plus whether
 * an optimistic overlay currently exists.
 *
 * `hasOptimistic` is derived from the observable reference-identity contract:
 * with no overlay, `optimisticValue()` returns the very same object as
 * `value()`; with an overlay it returns a distinct object.
 *
 * When EXPORT_PEER_KNOWN_STATE_FIXTURES=1 the fixtures are written to
 * crates/cojson-core/data/peer_known_state/<scenario>.json. Regardless of export,
 * the suite always asserts internal invariants so it has value in CI. The Rust
 * replay (`replay_peer_known_state_fixtures`) reads the committed files and must
 * reproduce every step byte-for-byte.
 *
 * NOTE: this file only READS `PeerKnownState`; it never modifies the production
 * class.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { PeerKnownState } from "../coValueCore/PeerKnownState.js";
import type { RawCoID } from "../ids.js";
import { cloneKnownState, CoValueKnownState } from "../knownState.js";
import type { PeerID } from "../sync.js";

const EXPORT = process.env.EXPORT_PEER_KNOWN_STATE_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/peer_known_state",
);

const CO_ID = "co_zPeerKnownStateFixture" as RawCoID;
const PEER_ID = "peer_zFixture" as PeerID;

function ks(
  header: boolean,
  sessions: Record<string, number>,
): CoValueKnownState {
  return { id: CO_ID, header, sessions: { ...sessions } };
}

type Op =
  | { op: "combineWith"; value: CoValueKnownState }
  | { op: "combineOptimisticWith"; value: CoValueKnownState }
  | { op: "updateHeader"; header: boolean }
  | { op: "set"; payload: CoValueKnownState }
  | { op: "setEmpty" }
  | { op: "cloneWithoutOptimistic" };

type Step = {
  value: CoValueKnownState;
  optimisticValue: CoValueKnownState;
  hasOptimistic: boolean;
};

type Fixture = {
  description: string;
  id: RawCoID;
  peerId: PeerID;
  ops: Op[];
  steps: Step[];
};

function runScenario(name: string, description: string, ops: Op[]): Fixture {
  let pk = new PeerKnownState(CO_ID, PEER_ID);
  const steps: Step[] = [];

  for (const op of ops) {
    switch (op.op) {
      case "combineWith":
        pk.combineWith(op.value);
        break;
      case "combineOptimisticWith":
        pk.combineOptimisticWith(op.value);
        break;
      case "updateHeader":
        pk.updateHeader(op.header);
        break;
      case "set":
        pk.set(op.payload);
        break;
      case "setEmpty":
        pk.set("empty");
        break;
      case "cloneWithoutOptimistic":
        // Mirrors PeerState.newPeerStateFrom: the tracked state becomes the
        // reconnect clone (confirmed copied, optimistic dropped).
        pk = pk.cloneWithoutOptimistic();
        break;
    }

    // hasOptimistic via the observable reference-identity contract.
    const hasOptimistic = pk.optimisticValue() !== pk.value();

    steps.push({
      // Deep-copy: value()/optimisticValue() return the live mutable objects
      // which later ops mutate in place.
      value: cloneKnownState(pk.value()),
      optimisticValue: cloneKnownState(pk.optimisticValue()),
      hasOptimistic,
    });
  }

  const fixture: Fixture = {
    description,
    id: CO_ID,
    peerId: PEER_ID,
    ops,
    steps,
  };

  // --- ALWAYS-ON internal invariants (value in CI) ---
  expect(steps.length).toBe(ops.length);
  for (const step of steps) {
    // id is immutable across all operations.
    expect(step.value.id).toBe(CO_ID);
    expect(step.optimisticValue.id).toBe(CO_ID);
    // The optimistic overlay is always at least as advanced as confirmed on
    // every session it shares (it is confirmed + extra optimistic combines).
    for (const [s, c] of Object.entries(step.value.sessions)) {
      const o =
        (step.optimisticValue.sessions as Record<string, number>)[s] ?? 0;
      expect(o).toBeGreaterThanOrEqual(c);
    }
    // When no overlay exists the two states are byte-identical.
    if (!step.hasOptimistic) {
      expect(step.optimisticValue).toEqual(step.value);
    }
  }

  if (EXPORT) {
    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(
      join(OUT_DIR, `${name}.json`),
      JSON.stringify(fixture, null, 2),
    );
  }

  return fixture;
}

describe("peer known state fixtures", () => {
  test("fresh_combine_confirmed_only", () => {
    const f = runScenario(
      "fresh_combine_confirmed_only",
      "combineWith on a fresh state advances confirmed; no optimistic overlay ever created",
      [
        { op: "combineWith", value: ks(true, { s1: 2 }) },
        { op: "combineWith", value: ks(true, { s1: 5, s2: 1 }) },
      ],
    );
    expect(f.steps[1]!.value.sessions).toEqual({ s1: 5, s2: 1 });
    expect(f.steps[1]!.hasOptimistic).toBe(false);
  });

  test("optimistic_lazy_clone_from_confirmed", () => {
    // THE key scenario: confirm first, then an optimistic combine must start from
    // the confirmed baseline (s1:3), not from empty.
    const f = runScenario(
      "optimistic_lazy_clone_from_confirmed",
      "confirm s1:3, then combineOptimisticWith s2:7 -> optimistic carries s1:3 + s2:7 while confirmed stays s1:3",
      [
        { op: "combineWith", value: ks(true, { s1: 3 }) },
        { op: "combineOptimisticWith", value: ks(true, { s2: 7 }) },
      ],
    );
    expect(f.steps[1]!.value.sessions).toEqual({ s1: 3 });
    expect(f.steps[1]!.optimisticValue.sessions).toEqual({ s1: 3, s2: 7 });
    expect(f.steps[1]!.hasOptimistic).toBe(true);
  });

  test("optimistic_first_clones_from_empty", () => {
    const f = runScenario(
      "optimistic_first_clones_from_empty",
      "combineOptimisticWith before any confirm clones from the empty confirmed baseline",
      [{ op: "combineOptimisticWith", value: ks(true, { s1: 4 }) }],
    );
    expect(f.steps[0]!.value.sessions).toEqual({});
    expect(f.steps[0]!.value.header).toBe(false);
    expect(f.steps[0]!.optimisticValue.sessions).toEqual({ s1: 4 });
    expect(f.steps[0]!.optimisticValue.header).toBe(true);
    expect(f.steps[0]!.hasOptimistic).toBe(true);
  });

  test("confirmed_combine_advances_optimistic_too", () => {
    const f = runScenario(
      "confirmed_combine_advances_optimistic_too",
      "with an optimistic overlay present, combineWith advances BOTH confirmed and optimistic",
      [
        { op: "combineOptimisticWith", value: ks(true, { s1: 2 }) },
        { op: "combineWith", value: ks(true, { s1: 5, s2: 1 }) },
      ],
    );
    expect(f.steps[1]!.value.sessions).toEqual({ s1: 5, s2: 1 });
    expect(f.steps[1]!.optimisticValue.sessions).toEqual({ s1: 5, s2: 1 });
    expect(f.steps[1]!.hasOptimistic).toBe(true);
  });

  test("optimistic_ahead_confirmed_catches_up", () => {
    const f = runScenario(
      "optimistic_ahead_confirmed_catches_up",
      "optimistic runs ahead (s1:10) then confirmed catches up partially (s1:6); per-session max keeps optimistic at 10",
      [
        { op: "combineWith", value: ks(true, { s1: 4 }) },
        { op: "combineOptimisticWith", value: ks(true, { s1: 10 }) },
        { op: "combineWith", value: ks(true, { s1: 6 }) },
      ],
    );
    expect(f.steps[2]!.value.sessions).toEqual({ s1: 6 });
    // optimistic max(10, 6) = 10
    expect(f.steps[2]!.optimisticValue.sessions).toEqual({ s1: 10 });
  });

  test("set_overwrites_and_clears_optimistic", () => {
    const f = runScenario(
      "set_overwrites_and_clears_optimistic",
      "set is an OVERWRITE not a combine: prior confirmed sessions vanish and the optimistic overlay is dropped",
      [
        { op: "combineWith", value: ks(true, { s1: 9, s2: 3 }) },
        { op: "combineOptimisticWith", value: ks(true, { s3: 4 }) },
        { op: "set", payload: ks(true, { s4: 1 }) },
      ],
    );
    expect(f.steps[2]!.value.sessions).toEqual({ s4: 1 });
    expect(f.steps[2]!.hasOptimistic).toBe(false);
    expect(f.steps[2]!.optimisticValue.sessions).toEqual({ s4: 1 });
  });

  test("set_empty_clears_confirmed", () => {
    const f = runScenario(
      "set_empty_clears_confirmed",
      'set("empty") drops header + all sessions and clears the optimistic overlay, keeping the id',
      [
        { op: "combineWith", value: ks(true, { s1: 9 }) },
        { op: "combineOptimisticWith", value: ks(true, { s2: 2 }) },
        { op: "setEmpty" },
      ],
    );
    expect(f.steps[2]!.value.header).toBe(false);
    expect(f.steps[2]!.value.sessions).toEqual({});
    expect(f.steps[2]!.value.id).toBe(CO_ID);
    expect(f.steps[2]!.hasOptimistic).toBe(false);
  });

  test("update_header_confirmed_only", () => {
    const f = runScenario(
      "update_header_confirmed_only",
      "updateHeader with no optimistic overlay flips only the confirmed header",
      [
        { op: "combineWith", value: ks(false, { s1: 2 }) },
        { op: "updateHeader", header: true },
      ],
    );
    expect(f.steps[1]!.value.header).toBe(true);
    expect(f.steps[1]!.hasOptimistic).toBe(false);
  });

  test("update_header_with_optimistic", () => {
    const f = runScenario(
      "update_header_with_optimistic",
      "updateHeader flips the header on BOTH confirmed and optimistic layers when an overlay exists",
      [
        { op: "combineWith", value: ks(false, { s1: 2 }) },
        { op: "combineOptimisticWith", value: ks(false, { s2: 3 }) },
        { op: "updateHeader", header: true },
      ],
    );
    expect(f.steps[2]!.value.header).toBe(true);
    expect(f.steps[2]!.optimisticValue.header).toBe(true);
    expect(f.steps[2]!.hasOptimistic).toBe(true);
  });

  test("clone_without_optimistic_reconnect", () => {
    // The reconnect path: optimistic progress is speculative and must be reset to
    // the confirmed baseline when the connection is re-established.
    const f = runScenario(
      "clone_without_optimistic_reconnect",
      "build confirmed s1:3 + optimistic s2:8, then cloneWithoutOptimistic resets optimistic to the confirmed baseline",
      [
        { op: "combineWith", value: ks(true, { s1: 3 }) },
        { op: "combineOptimisticWith", value: ks(true, { s2: 8 }) },
        { op: "cloneWithoutOptimistic" },
      ],
    );
    expect(f.steps[1]!.optimisticValue.sessions).toEqual({ s1: 3, s2: 8 });
    // after clone: optimistic gone, confirmed preserved
    expect(f.steps[2]!.value.sessions).toEqual({ s1: 3 });
    expect(f.steps[2]!.optimisticValue.sessions).toEqual({ s1: 3 });
    expect(f.steps[2]!.hasOptimistic).toBe(false);
  });

  test("clone_then_reoptimize", () => {
    const f = runScenario(
      "clone_then_reoptimize",
      "after a reconnect clone, a new optimistic combine again lazily clones from the (preserved) confirmed baseline",
      [
        { op: "combineWith", value: ks(true, { s1: 3 }) },
        { op: "combineOptimisticWith", value: ks(true, { s2: 8 }) },
        { op: "cloneWithoutOptimistic" },
        { op: "combineOptimisticWith", value: ks(true, { s3: 1 }) },
      ],
    );
    // new overlay = confirmed baseline (s1:3) + s3:1, NOT the pre-reconnect s2:8
    expect(f.steps[3]!.optimisticValue.sessions).toEqual({ s1: 3, s3: 1 });
    expect(f.steps[3]!.value.sessions).toEqual({ s1: 3 });
    expect(f.steps[3]!.hasOptimistic).toBe(true);
  });

  test("combine_lower_is_ignored", () => {
    const f = runScenario(
      "combine_lower_is_ignored",
      "combineWith a strictly lower state is a no-op on both layers (per-session max)",
      [
        { op: "combineWith", value: ks(true, { s1: 5 }) },
        { op: "combineWith", value: ks(true, { s1: 2 }) },
      ],
    );
    expect(f.steps[1]!.value.sessions).toEqual({ s1: 5 });
  });

  test("interleaved_optimistic_and_confirmed_sequence", () => {
    const f = runScenario(
      "interleaved_optimistic_and_confirmed_sequence",
      "a realistic push sequence: optimistic ahead of confirmed, confirmed acks arriving, header flips, session fan-out",
      [
        { op: "updateHeader", header: true },
        { op: "combineOptimisticWith", value: ks(true, { s1: 3 }) },
        { op: "combineOptimisticWith", value: ks(true, { s1: 5, s2: 2 }) },
        { op: "combineWith", value: ks(true, { s1: 3 }) },
        { op: "combineWith", value: ks(true, { s1: 5, s2: 2 }) },
        { op: "combineOptimisticWith", value: ks(true, { s3: 9 }) },
      ],
    );
    const last = f.steps[5]!;
    expect(last.value.sessions).toEqual({ s1: 5, s2: 2 });
    expect(last.optimisticValue.sessions).toEqual({ s1: 5, s2: 2, s3: 9 });
    expect(last.hasOptimistic).toBe(true);
  });

  test("set_to_lower_then_combine_up", () => {
    const f = runScenario(
      "set_to_lower_then_combine_up",
      "set can move confirmed BACKWARD (overwrite), after which combineWith moves it forward again",
      [
        { op: "combineWith", value: ks(true, { s1: 10, s2: 4 }) },
        { op: "set", payload: ks(true, { s1: 2 }) },
        { op: "combineWith", value: ks(true, { s1: 5, s3: 1 }) },
      ],
    );
    // set overwrote to s1:2 (dropping s2), then combine raised s1 and added s3
    expect(f.steps[1]!.value.sessions).toEqual({ s1: 2 });
    expect(f.steps[2]!.value.sessions).toEqual({ s1: 5, s3: 1 });
  });
});
