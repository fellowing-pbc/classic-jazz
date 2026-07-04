/**
 * Known-state fixture exporter.
 *
 * This vitest suite captures the CURRENT TypeScript behavior of the known-state
 * combine algebra (packages/cojson/src/knownState.ts) as executable fixtures for
 * the Rust port (crates/cojson-core/src/core/known_state.rs).
 *
 * For every scenario it runs the REAL knownState.ts functions against a
 * `target`/`source` pair and records the full result surface:
 *   - combined            = combineKnownStates(clone(target), source)
 *   - combinedSessions    = combineKnownStateSessions(clone(target.sessions), source.sessions)
 *   - toSend              = getKnownStateToSend(target.sessions, source.sessions)
 *   - subsetOf            = isKnownStateSubsetOf(target.sessions, source.sessions)
 *   - inSync              = areCurrentSessionsInSyncWith(target.sessions, source.sessions)
 *   - peerHasAllContent   = peerHasAllContent(target, source)
 *
 * When EXPORT_KNOWN_STATE_FIXTURES=1 the fixtures are written to
 * crates/cojson-core/data/known_state/<scenario>.json. Regardless of export, the
 * suite always asserts internal consistency so it has value in CI. The Rust
 * replay (`replay_known_state_fixtures`) reads the committed files and must
 * reproduce every field byte-for-byte.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import type { RawCoID, SessionID } from "../ids.js";
import {
  areCurrentSessionsInSyncWith,
  cloneKnownState,
  combineKnownStates,
  combineKnownStateSessions,
  CoValueKnownState,
  getKnownStateToSend,
  isKnownStateSubsetOf,
  KnownStateSessions,
  peerHasAllContent,
} from "../knownState.js";

const EXPORT = process.env.EXPORT_KNOWN_STATE_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/known_state",
);

const CO_ID = "co_zKnownStateFixture" as RawCoID;

type Fixture = {
  description: string;
  target: CoValueKnownState;
  source: CoValueKnownState;
  expected: {
    combined: CoValueKnownState;
    combinedSessions: KnownStateSessions;
    toSend: KnownStateSessions;
    subsetOf: boolean;
    inSync: boolean;
    peerHasAllContent: boolean;
  };
};

function ks(
  header: boolean,
  sessions: Record<string, number>,
): CoValueKnownState {
  return { id: CO_ID, header, sessions: sessions as KnownStateSessions };
}

function exportScenario(
  name: string,
  description: string,
  target: CoValueKnownState,
  source: CoValueKnownState,
): Fixture {
  const combined = combineKnownStates(cloneKnownState(target), source);
  const combinedSessions = combineKnownStateSessions(
    { ...target.sessions },
    source.sessions,
  );
  const toSend = getKnownStateToSend(target.sessions, source.sessions);
  const subsetOf = isKnownStateSubsetOf(target.sessions, source.sessions);
  const inSync = areCurrentSessionsInSyncWith(target.sessions, source.sessions);
  const peerHas = peerHasAllContent(target, source);

  const fixture: Fixture = {
    description,
    target,
    source,
    expected: {
      combined,
      combinedSessions,
      toSend,
      subsetOf,
      inSync,
      peerHasAllContent: peerHas,
    },
  };

  // --- ALWAYS-ON internal consistency assertions (value in CI) ---
  // combine is a per-session max: every combined counter is >= both inputs.
  for (const [s, c] of Object.entries(combined.sessions)) {
    const t = (target.sessions as Record<string, number>)[s] ?? 0;
    const so = (source.sessions as Record<string, number>)[s] ?? 0;
    expect(c).toBe(Math.max(t, so));
  }
  // header is an OR.
  expect(combined.header).toBe(target.header || source.header);
  // combineKnownStates.sessions and combineKnownStateSessions agree.
  expect(combined.sessions).toEqual(combinedSessions);
  // subset + equal counts <=> inSync implies subset.
  if (inSync) {
    expect(subsetOf).toBe(true);
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

describe("known state fixtures", () => {
  test("empty_plus_empty", () => {
    const f = exportScenario(
      "empty_plus_empty",
      "two empty states combine to empty; peer trivially has all content",
      ks(false, {}),
      ks(false, {}),
    );
    expect(f.expected.combined.sessions).toEqual({});
    expect(f.expected.combined.header).toBe(false);
    expect(f.expected.peerHasAllContent).toBe(true);
    expect(f.expected.inSync).toBe(true);
  });

  test("empty_plus_partial", () => {
    const f = exportScenario(
      "empty_plus_partial",
      "empty target absorbs a source with a header and sessions",
      ks(false, {}),
      ks(true, { s1: 3, s2: 7 }),
    );
    expect(f.expected.combined.header).toBe(true);
    expect(f.expected.combined.sessions).toEqual({ s1: 3, s2: 7 });
    // target (empty) is trivially a subset of source
    expect(f.expected.subsetOf).toBe(true);
    // peer (=source) has header+all, but this asks peerHasAllContent(target,source)
    // where target is empty, so peer trivially has target's (nothing) content.
    expect(f.expected.peerHasAllContent).toBe(true);
  });

  test("partial_plus_empty", () => {
    const f = exportScenario(
      "partial_plus_empty",
      "target with content combined with an empty source is unchanged; source has no header",
      ks(true, { s1: 3 }),
      ks(false, {}),
    );
    expect(f.expected.combined.header).toBe(true);
    expect(f.expected.combined.sessions).toEqual({ s1: 3 });
    // target is NOT a subset of empty source, and source lacks header
    expect(f.expected.subsetOf).toBe(false);
    expect(f.expected.peerHasAllContent).toBe(false);
  });

  test("disjoint_sessions", () => {
    const f = exportScenario(
      "disjoint_sessions",
      "non-overlapping sessions are unioned; ordering appends source-only keys",
      ks(true, { a: 2, b: 4 }),
      ks(true, { c: 1, d: 9 }),
    );
    expect(f.expected.combined.sessions).toEqual({ a: 2, b: 4, c: 1, d: 9 });
    // key order: target keys first, then appended source keys
    expect(Object.keys(f.expected.combined.sessions)).toEqual([
      "a",
      "b",
      "c",
      "d",
    ]);
    expect(f.expected.toSend).toEqual({ a: 2, b: 4 });
  });

  test("overlap_source_higher", () => {
    const f = exportScenario(
      "overlap_source_higher",
      "source counters exceed target: combine takes the source values",
      ks(true, { s1: 2, s2: 3 }),
      ks(true, { s1: 5, s2: 8 }),
    );
    expect(f.expected.combined.sessions).toEqual({ s1: 5, s2: 8 });
    expect(f.expected.subsetOf).toBe(true);
    expect(f.expected.inSync).toBe(false);
    expect(f.expected.peerHasAllContent).toBe(true);
  });

  test("overlap_target_higher", () => {
    const f = exportScenario(
      "overlap_target_higher",
      "target counters exceed source: combine keeps the target values, source ignored",
      ks(true, { s1: 9, s2: 8 }),
      ks(true, { s1: 5, s2: 3 }),
    );
    expect(f.expected.combined.sessions).toEqual({ s1: 9, s2: 8 });
    expect(f.expected.subsetOf).toBe(false);
    expect(f.expected.toSend).toEqual({ s1: 9, s2: 8 });
  });

  test("overlap_equal", () => {
    const f = exportScenario(
      "overlap_equal",
      "identical states: combine is a no-op, states are in sync, nothing to send",
      ks(true, { s1: 4, s2: 6 }),
      ks(true, { s1: 4, s2: 6 }),
    );
    expect(f.expected.inSync).toBe(true);
    expect(f.expected.subsetOf).toBe(true);
    expect(f.expected.toSend).toEqual({});
    expect(f.expected.peerHasAllContent).toBe(true);
  });

  test("mixed_overlap", () => {
    const f = exportScenario(
      "mixed_overlap",
      "some sessions ahead in target, some in source, some disjoint",
      ks(true, { s1: 10, s2: 2, s3: 5 }),
      ks(true, { s1: 4, s2: 9, s4: 1 }),
    );
    expect(f.expected.combined.sessions).toEqual({
      s1: 10,
      s2: 9,
      s3: 5,
      s4: 1,
    });
    expect(f.expected.toSend).toEqual({ s1: 10, s3: 5 });
    expect(f.expected.subsetOf).toBe(false);
  });

  test("header_or_source_only", () => {
    const f = exportScenario(
      "header_or_source_only",
      "target lacks header, source has it: combined header becomes true",
      ks(false, { s1: 2 }),
      ks(true, { s1: 2 }),
    );
    expect(f.expected.combined.header).toBe(true);
    // sessions equal, so peer (source) has header + all -> true
    expect(f.expected.peerHasAllContent).toBe(true);
    expect(f.expected.inSync).toBe(true);
  });

  test("header_target_only", () => {
    const f = exportScenario(
      "header_target_only",
      "target has header, source does not: combined stays true; peer missing header",
      ks(true, { s1: 2 }),
      ks(false, { s1: 2 }),
    );
    expect(f.expected.combined.header).toBe(true);
    // peer (source) lacks the header while target has it -> false
    expect(f.expected.peerHasAllContent).toBe(false);
  });

  test("subset_true_strict", () => {
    const f = exportScenario(
      "subset_true_strict",
      "target strictly behind source on all sessions (peer ahead)",
      ks(true, { s1: 1, s2: 1 }),
      ks(true, { s1: 5, s2: 5, s3: 5 }),
    );
    expect(f.expected.subsetOf).toBe(true);
    expect(f.expected.peerHasAllContent).toBe(true);
    expect(f.expected.toSend).toEqual({});
  });

  test("subset_false_one_ahead", () => {
    const f = exportScenario(
      "subset_false_one_ahead",
      "target ahead on a single session breaks the subset relation",
      ks(true, { s1: 5, s2: 3 }),
      ks(true, { s1: 4, s2: 3 }),
    );
    expect(f.expected.subsetOf).toBe(false);
    expect(f.expected.toSend).toEqual({ s1: 5 });
    expect(f.expected.peerHasAllContent).toBe(false);
  });

  test("zero_count_session", () => {
    const f = exportScenario(
      "zero_count_session",
      "explicit zero counters: a missing target entry (default 0) equals an explicit 0",
      ks(true, { s1: 0, s2: 3 }),
      ks(true, { s2: 3 }),
    );
    // combine: source has no s1, so s1 stays 0; s2 equal
    expect(f.expected.combined.sessions).toEqual({ s1: 0, s2: 3 });
    // target has s1:0 which source lacks (default 0) -> 0<=0 subset holds
    expect(f.expected.subsetOf).toBe(true);
    // inSync: s1 0==0, s2 3==3 -> true
    expect(f.expected.inSync).toBe(true);
    // toSend: s1 0>0 false, s2 equal -> nothing
    expect(f.expected.toSend).toEqual({});
  });

  test("large_counts", () => {
    const f = exportScenario(
      "large_counts",
      "large per-session counters near u32 range exercise no overflow in the max",
      ks(true, { s1: 4_000_000_000, s2: 1 }),
      ks(true, { s1: 3_999_999_999, s2: 2_000_000_000 }),
    );
    expect(f.expected.combined.sessions).toEqual({
      s1: 4_000_000_000,
      s2: 2_000_000_000,
    });
  });

  test("many_sessions_realistic", () => {
    // ~8 sessions with a realistic mix, resembling an active shared group where
    // several members' sessions overlap and a couple are peer-only.
    const target: Record<string, number> = {};
    const source: Record<string, number> = {};
    for (let i = 0; i < 8; i++) {
      const s = `session_${i}` as SessionID;
      target[s] = i * 3 + 1;
      // source is ahead on even sessions, behind on odd
      source[s] = i % 2 === 0 ? i * 3 + 4 : i * 3;
    }
    // a peer-only session the target has never seen
    source["session_peer_only"] = 42;
    const f = exportScenario(
      "many_sessions_realistic",
      "8 overlapping sessions plus a peer-only session; realistic active-group merge",
      ks(true, target),
      ks(true, source),
    );
    // even sessions take source, odd keep target, peer-only appended
    const combinedSessions = f.expected.combined.sessions as Record<
      string,
      number
    >;
    expect(combinedSessions["session_0"]).toBe(4);
    expect(combinedSessions["session_1"]).toBe(4);
    expect(combinedSessions["session_peer_only"]).toBe(42);
  });
});
