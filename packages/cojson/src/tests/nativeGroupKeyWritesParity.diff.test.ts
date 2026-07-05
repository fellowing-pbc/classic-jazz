import { expect, test } from "vitest";
import {
  disableNativeGroupKeyWrites,
  enableNativeGroupKeyWrites,
} from "../coValueCore/coValueCore.js";
import type { CoValueUniqueness } from "../coValueCore/verifiedState.js";
import { WasmNode } from "../node/WasmNode.js";
import { LocalNode } from "../localNode.js";
import { expectGroup } from "../typeUtils/expectGroup.js";

const crypto = await WasmNode.create();

const ROTATIONS = 300;

type ScenarioResult = {
  snapshot: Record<string, string>;
  txCount: number;
  readKey: { id: string; secret: string | undefined };
  keyDraws: number;
};

/**
 * Run the SAME deterministic scenario (fixed agent, session, group uniqueness and
 * key-secret sequence) once with the native group-key-write path and once with
 * the pure-TS path, then diff the resulting materialized group state
 * byte-for-byte. `recordedKeys` is populated by the first (native) run and
 * replayed on the second (TS) run so both paths consume an identical random
 * key-secret stream — the only way two independent runs can be byte-comparable.
 */
function runScenario(
  agentSecret: ReturnType<typeof crypto.newRandomAgentSecret>,
  sessionID: ReturnType<typeof crypto.newRandomSessionID>,
  uniqueness: CoValueUniqueness,
  recordedKeys: { id: string; secret: string }[] | null,
): ScenarioResult {
  const node = new LocalNode(agentSecret, sessionID, crypto);

  // Record (native run) or replay (TS run) the key-secret stream.
  const original = crypto.newRandomKeySecret.bind(crypto);
  const drawn: { id: string; secret: string }[] = [];
  let replayIdx = 0;
  (
    crypto as unknown as { newRandomKeySecret: () => unknown }
  ).newRandomKeySecret = () => {
    if (recordedKeys) {
      const k = recordedKeys[replayIdx++];
      if (!k) throw new Error("replay key stream exhausted");
      return k;
    }
    const k = original() as { id: string; secret: string };
    drawn.push(k);
    return k;
  };

  let result: ScenarioResult;
  try {
    const group = expectGroup(node.createGroup(uniqueness));

    for (let i = 0; i < ROTATIONS; i++) {
      group.rotateReadKey();
    }
    group.addMember("everyone", "reader");

    const known = group.core.knownState();
    const txCount = Object.values(known.sessions ?? {}).reduce(
      (a, b) => a + (b as number),
      0,
    );

    const snapshot: Record<string, string> = {};
    for (const key of group.keys()) {
      const value = group.get(key);
      if (typeof value === "string") snapshot[key] = value;
    }

    const readKey = group.getCurrentReadKey();

    result = {
      snapshot,
      txCount,
      readKey: { id: readKey.id, secret: readKey.secret },
      keyDraws: recordedKeys ? replayIdx : drawn.length,
    };
  } finally {
    (
      crypto as unknown as { newRandomKeySecret: () => unknown }
    ).newRandomKeySecret = original;
  }

  if (!recordedKeys) recordedKeys = drawn;
  // Stash the drawn stream on the result path via closure return.
  (result as ScenarioResult & { _drawn?: typeof drawn })._drawn = drawn;
  return result;
}

test("native group-key-write path matches TS byte-for-byte over 300 rotations", () => {
  const agentSecret = crypto.newRandomAgentSecret();
  const sessionID = crypto.newRandomSessionID(crypto.getAgentID(agentSecret));
  const uniqueness = crypto.createdNowUnique();

  // 1. NATIVE path (flag ON) — records the random key stream.
  enableNativeGroupKeyWrites();
  const native = runScenario(
    agentSecret,
    sessionID,
    uniqueness,
    null,
  ) as ScenarioResult & { _drawn: { id: string; secret: string }[] };
  disableNativeGroupKeyWrites();

  // 2. TS path (flag OFF) — replays the identical key stream.
  const ts = runScenario(agentSecret, sessionID, uniqueness, native._drawn);

  // Re-enable for the rest of the (flag-on-by-default) suite.
  enableNativeGroupKeyWrites();

  expect(native.txCount).toBeGreaterThan(ROTATIONS); // sanity: real work happened
  expect(ts.txCount).toBe(native.txCount);
  expect(ts.readKey.secret).toBeDefined();
  expect(ts.readKey).toEqual(native.readKey);
  expect(JSON.stringify(ts.snapshot)).toBe(JSON.stringify(native.snapshot));
  // Both paths must have drawn the exact same number of random keys.
  expect(ts.keyDraws).toBe(native._drawn.length);
});
