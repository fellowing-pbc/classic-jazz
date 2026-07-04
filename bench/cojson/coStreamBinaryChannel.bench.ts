/**
 * R4a investigation: WHERE does the native coStream-materialization cost go, and
 * can a BINARY transfer channel close the gap the JSON-string channel leaves?
 *
 * Two parts:
 *
 *  STEP 1 — a per-phase cost breakdown of the NATIVE cold-build pipeline for a
 *  private 2000-entry stream, bucketed into:
 *    (ingest)     createCoValue + replay ciphertext (re-parse+store all txs)
 *    (a) compute  streamMaterialize (validate + decrypt + bucket)
 *    (b) serialize  Rust serde delta -> String, length only (no FFI marshaling)
 *    (c) ffi-string  full streamDelta -> String minus (b) = napi string marshal
 *    (d) parse    JSON.parse of the delta string
 *    (e) apply    walk parsed sessions into a per-session Map (object adopt)
 *  Compared against the TS baseline's own per-tx-decrypt+append cost.
 *
 *  STEP 2 — a head-to-head of the SAME materialized view transferred two ways:
 *    JSON channel:   streamDelta (String) -> JSON.parse -> adopt
 *    BINARY channel: streamDeltaBinary (Buffer) -> DataView decode -> adopt
 *  plus the TS cold baseline, at the full-pipeline level (re-ingest each iter)
 *  AND at the transfer-only level (view pre-built; isolates the encoding win).
 *
 * Run FOREGROUND:
 *   node --experimental-strip-types --no-warnings bench/cojson/coStreamBinaryChannel.bench.ts
 */

import cronometro from "cronometro";
import { isMainThread } from "node:worker_threads";
import { NodeCore as NativeNodeCore } from "cojson-core-napi";
import {
  buildPrivateTsStream,
  extractSlices,
  generateItems,
  loadCore,
  replayInto,
  tsColdBuildPrivate,
  applyStreamDelta,
  type Extracted,
  type PrivateTsStream,
} from "./coStreamHarness.ts";

// ---------------------------------------------------------------------------
// Binary decoder for the coStream delta buffer produced by `streamDeltaBinary`.
// Layout (little-endian) — see CoStreamView::delta_binary in co_stream.rs:
//   u64 version; u8 reset; u32 sessionCount;
//   per session: u32 sidLen; sid utf8; u32 entryCount;
//     per entry: f64 madeAt; u32 txIndex; u8 tag; tag payload
//       1=f64 | 2=(u32 len + utf8) | 3=null | 4=true | 5=false | 0=(u32 len + json)
// Produces the SAME structure applyStreamDelta yields from the JSON channel:
// sessions[sid] = [{ value, tx:{sessionID, txIndex}, madeAt }, ...].
// ---------------------------------------------------------------------------
interface Entry {
  value: unknown;
  tx: { sessionID: string; txIndex: number };
  madeAt: number;
}

function decodeStreamBinary(buf: Buffer): {
  version: number;
  reset: boolean;
  sessions: Record<string, Entry[]>;
  total: number;
} {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let o = 0;
  const version = Number(dv.getBigUint64(o, true));
  o += 8;
  const reset = dv.getUint8(o) === 1;
  o += 1;
  const sessionCount = dv.getUint32(o, true);
  o += 4;
  const sessions: Record<string, Entry[]> = {};
  let total = 0;
  for (let s = 0; s < sessionCount; s++) {
    const sidLen = dv.getUint32(o, true);
    o += 4;
    const sid = buf.toString("utf8", o, o + sidLen);
    o += sidLen;
    const entryCount = dv.getUint32(o, true);
    o += 4;
    const entries: Entry[] = new Array(entryCount);
    for (let e = 0; e < entryCount; e++) {
      const madeAt = dv.getFloat64(o, true);
      o += 8;
      const txIndex = dv.getUint32(o, true);
      o += 4;
      const tag = dv.getUint8(o);
      o += 1;
      let value: unknown;
      switch (tag) {
        case 1:
          value = dv.getFloat64(o, true);
          o += 8;
          break;
        case 2: {
          const len = dv.getUint32(o, true);
          o += 4;
          value = buf.toString("utf8", o, o + len);
          o += len;
          break;
        }
        case 3:
          value = null;
          break;
        case 4:
          value = true;
          break;
        case 5:
          value = false;
          break;
        case 0: {
          const len = dv.getUint32(o, true);
          o += 4;
          value = JSON.parse(buf.toString("utf8", o, o + len));
          o += len;
          break;
        }
        default:
          throw new Error(`bad tag ${tag} @${o}`);
      }
      entries[e] = { value, tx: { sessionID: sid, txIndex }, madeAt };
    }
    sessions[sid] = entries;
    total += entryCount;
  }
  return { version, reset, sessions, total };
}

// ---------------------------------------------------------------------------
// Shapes.
// ---------------------------------------------------------------------------
interface Shape {
  name: string;
  pts: PrivateTsStream;
  ext: Extracted;
  groupExt: Extracted;
  key: { id: string; secret: string };
  count: number;
}

function makePrivateShape(name: string, seed: number, count: number): Shape {
  const pts = buildPrivateTsStream(generateItems(seed, count), "private");
  return {
    name,
    pts,
    ext: extractSlices(pts.core),
    groupExt: extractSlices(pts.group.core),
    key: { id: pts.readKeyId, secret: pts.readKeySecret },
    count,
  };
}

const PRIV_500 = makePrivateShape("private 500 / 1 session", 11, 500);
const PRIV_2000 = makePrivateShape("private 2000 / 1 session", 22, 2000);
const SHAPES = [PRIV_500, PRIV_2000];

// Persistent node with group warm + stream materialized ONCE (read-only after).
function makeWarmNode(s: Shape): NativeNodeCore {
  const nc = new NativeNodeCore();
  loadCore(nc, s.pts.group.id, s.groupExt);
  nc.provideKeySecret(s.key.id, s.key.secret);
  nc.createCoValue(s.pts.coId, s.ext.header, undefined, true);
  replayInto(nc, s.pts.coId, s.ext.slices);
  nc.streamMaterialize(s.pts.coId, []);
  return nc;
}

// ---------------------------------------------------------------------------
// Correctness gate: binary decode structurally equals the JSON channel equals
// TS toJSON, over the same ciphertext.
// ---------------------------------------------------------------------------
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

for (const s of isMainThread ? SHAPES : []) {
  const nc = makeWarmNode(s);
  const jsonStr = nc.streamDelta(s.pts.coId, 0);
  const bin = nc.streamDeltaBinary(s.pts.coId, 0);
  const jsonDelta = JSON.parse(jsonStr) as {
    sessions: Record<string, Entry[]>;
  };
  const binDelta = decodeStreamBinary(bin);
  // Snapshot-of-values comparison (order-preserving per session).
  const valuesOf = (sessions: Record<string, Entry[]>) => {
    const o: Record<string, unknown[]> = {};
    for (const sid in sessions) o[sid] = sessions[sid]!.map((e) => e.value);
    return o;
  };
  const tsSnap = s.pts.stream.toJSON() as Record<string, unknown[]>;
  const jsonEq = canon(valuesOf(jsonDelta.sessions)) === canon(tsSnap);
  const binEq = canon(valuesOf(binDelta.sessions)) === canon(tsSnap);
  // Full entry-shape equality between the two channels.
  const shapeEq = canon(jsonDelta.sessions) === canon(binDelta.sessions);
  console.log(
    `gate [${s.name}] jsonBytes=${Buffer.byteLength(jsonStr)} binBytes=${bin.length} ` +
      `binTotal=${binDelta.total} json==ts:${jsonEq} bin==ts:${binEq} bin==json:${shapeEq}`,
  );
  if (!jsonEq || !binEq || !shapeEq) console.error(`  !! MISMATCH [${s.name}]`);
}

// ---------------------------------------------------------------------------
// STEP 1: per-phase cost breakdown (median of many samples) for private 2000.
// ---------------------------------------------------------------------------
function median(xs: number[]): number {
  const a = [...xs].sort((x, y) => x - y);
  return a[a.length >> 1]!;
}

function profile(name: string, iters: number, fn: () => void): number {
  for (let i = 0; i < 200; i++) fn(); // warm
  const samples: number[] = [];
  for (let r = 0; r < 30; r++) {
    const t0 = performance.now();
    for (let i = 0; i < iters; i++) fn();
    samples.push((performance.now() - t0) / iters);
  }
  const med = median(samples);
  console.log(
    `  ${name.padEnd(26)} ${(med * 1000).toFixed(2).padStart(9)} us/op`,
  );
  return med;
}

function step1(s: Shape) {
  console.log(`\n=== STEP 1 breakdown [${s.name}] (median us/op) ===`);
  let sink = 0;

  // Fresh-node phases (ingest + compute) — must rebuild each iter.
  const gExt = s.groupExt,
    ext = s.ext,
    coId = s.pts.coId,
    gId = s.pts.group.id,
    key = s.key;
  const freshNode = () => {
    const nc = new NativeNodeCore();
    loadCore(nc, gId, gExt);
    nc.provideKeySecret(key.id, key.secret);
    return nc;
  };
  // (ingest): createCoValue + replay, on a warm-group node.
  {
    const nc = freshNode();
    profile("ingest(create+replay)", 200, () => {
      nc.createCoValue(coId, ext.header, undefined, true);
      replayInto(nc, coId, ext.slices);
    });
  }
  // (a) compute: materialize. Measured by subtraction — createCoValue drops the
  // cached view, so materialize alone cannot be timed without a preceding
  // ingest; time ingest+materialize and subtract ingest-only.
  const ingestOnly = (() => {
    const nc = freshNode();
    return profile("  ingest-only(ref)", 200, () => {
      nc.createCoValue(coId, ext.header, undefined, true);
      replayInto(nc, coId, ext.slices);
    });
  })();
  const ingestPlusMat = (() => {
    const nc = freshNode();
    return profile("  ingest+materialize", 200, () => {
      nc.createCoValue(coId, ext.header, undefined, true);
      replayInto(nc, coId, ext.slices);
      nc.streamMaterialize(coId, []);
    });
  })();
  console.log(
    `  => (a) materialize alone ~= ${((ingestPlusMat - ingestOnly) * 1000).toFixed(2)} us/op`,
  );

  // Read-only phases on a warm materialized view.
  const nc = makeWarmNode(s);
  const bSerialize = profile("b: serialize(bytelen)", 500, () => {
    sink += nc.streamDeltaByteLen(coId, 0);
  });
  const bcDeltaStr = profile("b+c: streamDelta(String)", 500, () => {
    sink += nc.streamDelta(coId, 0).length;
  });
  console.log(
    `  => (c) napi string-marshal ~= ${((bcDeltaStr - bSerialize) * 1000).toFixed(2)} us/op`,
  );
  const deltaBin = profile("   streamDeltaBinary(Buf)", 500, () => {
    sink += nc.streamDeltaBinary(coId, 0).length;
  });
  console.log(
    `  => (binary produce+marshal) ${(deltaBin * 1000).toFixed(2)} us/op`,
  );

  const jsonStr = nc.streamDelta(coId, 0);
  profile("d: JSON.parse", 500, () => {
    sink += (JSON.parse(jsonStr) as { reset: boolean }).reset ? 1 : 0;
  });
  const parseApply = profile("d+e: parse+adopt(JSON)", 500, () => {
    sink += applyStreamDelta(jsonStr);
  });
  const buf = nc.streamDeltaBinary(coId, 0);
  profile("bin decode+adopt", 500, () => {
    sink += decodeStreamBinary(buf).total;
  });
  void parseApply;

  // TS baseline phase reference.
  profile("TS per-tx decrypt+append", 200, () => {
    sink += tsColdBuildPrivate(s.pts, s.ext);
  });

  if (sink === -1) console.log("unreachable", sink);
}

if (isMainThread) step1(PRIV_2000);

// ---------------------------------------------------------------------------
// STEP 2: head-to-head channels.
// ---------------------------------------------------------------------------
console.log("\n=== STEP 2: channel head-to-head ===");
let sink = 0;

const tests: Record<string, { test: () => void }> = {};
for (const s of SHAPES) {
  const { ext, groupExt, key, pts } = s;
  const coId = pts.coId,
    gId = pts.group.id;
  const freshBuild = () => {
    const nc = new NativeNodeCore();
    loadCore(nc, gId, groupExt);
    nc.provideKeySecret(key.id, key.secret);
    nc.createCoValue(coId, ext.header, undefined, true);
    replayInto(nc, coId, ext.slices);
    nc.streamMaterialize(coId, []);
    return nc;
  };
  // Warm nodes for transfer-only comparison.
  const warm = makeWarmNode(s);

  // Full pipeline (re-ingest + materialize each iter), JSON vs binary vs TS.
  const ncJson = freshBuild();
  tests[`[${s.name}] FULL native JSON channel`] = {
    test() {
      ncJson.createCoValue(coId, ext.header, undefined, true);
      replayInto(ncJson, coId, ext.slices);
      ncJson.streamMaterialize(coId, []);
      sink += applyStreamDelta(ncJson.streamDelta(coId, 0));
    },
  };
  const ncBin = freshBuild();
  tests[`[${s.name}] FULL native BINARY channel`] = {
    test() {
      ncBin.createCoValue(coId, ext.header, undefined, true);
      replayInto(ncBin, coId, ext.slices);
      ncBin.streamMaterialize(coId, []);
      sink += decodeStreamBinary(ncBin.streamDeltaBinary(coId, 0)).total;
    },
  };
  tests[`[${s.name}] FULL TS baseline`] = {
    test() {
      sink += tsColdBuildPrivate(pts, ext);
    },
  };
  // Transfer-only (warm view): isolate the encoding+decode win.
  tests[`[${s.name}] XFER JSON (delta+parse+adopt)`] = {
    test() {
      sink += applyStreamDelta(warm.streamDelta(coId, 0));
    },
  };
  tests[`[${s.name}] XFER BINARY (delta+decode+adopt)`] = {
    test() {
      sink += decodeStreamBinary(warm.streamDeltaBinary(coId, 0)).total;
    },
  };
}

await cronometro(tests, {
  iterations: 50,
  warmup: true,
  print: { colors: true, compare: true },
  onTestError: (n: string, e: unknown) => console.error(`Error ${n}:`, e),
});

if (sink === -1) console.log("unreachable", sink);
