/**
 * R4a coStream/coFeed materialization GATE benchmark (napi).
 *
 * Measures COLD-BUILD materialization of a per-session stream with N PRIVATE
 * entries — the realistic coStream shape (per-session encrypted feed items /
 * file chunks) — comparing:
 *
 *   (native) fresh `NodeCore` → replay ciphertext → provideKey →
 *            `streamMaterialize` (decrypt-and-bucket every tx in ONE native
 *            pass) → `streamDelta(0)` transfer + TS-side adopt.
 *   (TS)     per-tx `verified.decryptTransaction` (the primitive
 *            `decryptTransactionChangesAndMeta` uses — one FFI crossing per tx,
 *            no caching) → append into a per-session Map. TS's genuine
 *            per-tx-decrypt-then-append loop with a COLD decrypt cache.
 *
 * Both sides decrypt all N txs from scratch each measured iteration over
 * byte-identical ciphertext (see coStreamHarness fairness note). A TRUSTING
 * shape is included as the contrast where there is NO decrypt for Rust to
 * amortize (the coMap-style adverse case).
 *
 * THE GATE: native must BEAT the TS cold decrypt+append loop on the private
 * shape. If it does not, do NOT wire `RawCoStream`/`RawCoFeed` onto the native
 * path — report why and stop (the coMap precedent).
 *
 * Run FOREGROUND:
 *   node --experimental-strip-types --no-warnings bench/cojson/coStreamMaterialization.bench.ts
 */

import cronometro from "cronometro";
import {
  buildPrivateTsStream,
  extractSlices,
  generateItems,
  makeNativeStreamBuilder,
  tsColdBuildPrivate,
  type Extracted,
  type PrivateTsStream,
} from "./coStreamHarness.ts";

const benchOptions = {
  iterations: 50,
  warmup: true,
  print: { colors: true, compare: true },
  onTestError: (testName: string, error: unknown) => {
    console.error(`\nError in test "${testName}":`);
    console.error(error);
  },
};

let sink = 0;

// ---------------------------------------------------------------------------
// Shapes: single-session private streams at 500 and 2000 entries (the two
// entry counts the R4a task calls for), plus a 2000-entry TRUSTING contrast.
// ---------------------------------------------------------------------------
interface Shape {
  name: string;
  pts: PrivateTsStream;
  ext: Extracted;
  groupExt: Extracted;
  key?: { id: string; secret: string };
  count: number;
}

function makeShape(
  name: string,
  seed: number,
  count: number,
  privacy: "private" | "trusting",
): Shape {
  const pts = buildPrivateTsStream(generateItems(seed, count), privacy);
  const ext = extractSlices(pts.core);
  const groupExt = extractSlices(pts.group.core);
  return {
    name,
    pts,
    ext,
    groupExt,
    key:
      privacy === "private"
        ? { id: pts.readKeyId, secret: pts.readKeySecret }
        : undefined,
    count,
  };
}

function makePrivateShape(name: string, seed: number, count: number): Shape {
  return makeShape(name, seed, count, "private");
}

function makeTrustingShape(name: string, seed: number, count: number): Shape {
  return makeShape(name, seed, count, "trusting");
}

const PRIV_500 = makePrivateShape("private 500 / 1 session", 11, 500);
const PRIV_2000 = makePrivateShape("private 2000 / 1 session", 22, 2000);
const TRUST_2000 = makeTrustingShape("trusting 2000 / 1 session", 33, 2000);

const SHAPES = [PRIV_500, PRIV_2000, TRUST_2000];

// ---------------------------------------------------------------------------
// Correctness gate: native and TS agree on the materialized entry count AND the
// per-session values, over the same ciphertext, BEFORE timing.
// ---------------------------------------------------------------------------
import { NodeCore as NativeNodeCore } from "cojson-core-napi";
import { loadCore } from "./coStreamHarness.ts";
for (const s of SHAPES) {
  const nc = new NativeNodeCore();
  loadCore(nc, s.pts.group.id, s.groupExt);
  loadCore(nc, s.pts.coId, s.ext);
  if (s.key) nc.provideKeySecret(s.key.id, s.key.secret);
  nc.streamMaterialize(s.pts.coId, []);
  const nativeSnap = JSON.parse(nc.streamSnapshot(s.pts.coId)) as Record<
    string,
    unknown[]
  >;
  const tsSnap = s.pts.stream.toJSON() as Record<string, unknown[]>;
  const nativeTotal = Object.values(nativeSnap).reduce(
    (a, b) => a + b.length,
    0,
  );
  const tsTotal = Object.values(tsSnap).reduce((a, b) => a + b.length, 0);
  // Compare structurally (canonical: sort object keys) — JSON.stringify key
  // ORDER is not part of the contract (the fixtures test compares parsed JSON).
  const canon = (v: unknown): string =>
    JSON.stringify(v, (_k, val) =>
      val && typeof val === "object" && !Array.isArray(val)
        ? Object.fromEntries(
            Object.entries(val as Record<string, unknown>).sort(([a], [b]) =>
              a < b ? -1 : a > b ? 1 : 0,
            ),
          )
        : val,
    );
  const equal = canon(nativeSnap) === canon(tsSnap);
  if (nativeTotal !== s.count || !equal) {
    console.error(
      `MISMATCH [${s.name}] nativeTotal=${nativeTotal} tsTotal=${tsTotal} expected=${s.count} structurallyEqual=${equal}`,
    );
  } else {
    console.log(
      `ok [${s.name}] entries=${nativeTotal} (native snapshot === TS toJSON)`,
    );
  }
}

// ---------------------------------------------------------------------------
// The timed gate.
// ---------------------------------------------------------------------------
const tests: Record<string, { test: () => void }> = {};
for (const s of SHAPES) {
  const nativeBuild = makeNativeStreamBuilder(
    s.ext,
    s.pts.coId,
    s.groupExt,
    s.pts.group.id,
    s.key,
  );
  tests[`[${s.name}] native cold decrypt+bucket+transfer`] = {
    test() {
      sink += nativeBuild();
    },
  };
  tests[`[${s.name}] TS cold per-tx-decrypt+append`] = {
    test() {
      sink += tsColdBuildPrivate(s.pts, s.ext);
    },
  };
}

await cronometro(tests, benchOptions);

if (sink === -1) console.log("unreachable", sink);
