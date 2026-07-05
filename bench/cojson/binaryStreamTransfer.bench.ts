/**
 * binaryCoStream R? — STEP 1 (the FIRST gate): transfer-only cost of reading a
 * file's chunks BACK across the napi boundary, two ways, on realistic file
 * sizes. NO CRDT port yet — this exists purely to decide whether a native
 * raw-bytes channel is worth building for binaryCoStream.
 *
 * WHY binaryCoStream might differ from coMap/coStream (which both LOST): those
 * carry small SCALAR values, so JSON/FFI overhead is comparable to the value
 * and there is nothing to amortize. binaryCoStream chunks are large opaque byte
 * blobs. The current TS wire base64-encodes each chunk into a JSON string
 * (`binary_U<base64>`, ~+33% size), rides it across napi as a String, then
 * `JSON.parse`s and `base64URLtoBytes`-decodes it back to bytes. A native path
 * could hand raw bytes straight across as a napi Buffer — no base64, no JSON.
 *
 * Channels compared (read-back / transfer only; the encode is WRITE-time and is
 * precomputed once, off the clock, exactly as in the product):
 *   (a) CURRENT   probe.asBase64Json() [napi String]
 *                 -> JSON.parse -> per-chunk base64URLtoBytes -> Uint8Array[]
 *   (b) NATIVE    probe.asBuffer() [napi Buffer, near zero-copy]
 *                 -> subarray at 100KB boundaries -> Uint8Array[]
 * plus a "(b) merged" variant that returns the whole file as one Uint8Array
 * (the shape FileStream.toBlob / asBase64 ultimately concatenate to anyway).
 *
 * Chunk size is the product's real value: MAX_RECOMMENDED_TX_SIZE = 100KB
 * (FileStream.createFromArrayBuffer chunks at exactly this). Read-back contract
 * (RawBinaryCoStreamView.getBinaryChunks): returns Uint8Array[] — one per chunk.
 *
 * NOTE (generous to the current path): the product actually decrypts one tx PER
 * CHUNK — N separate napi crossings, not one String. Modeling (a) as a single
 * String crossing UNDERSTATES its real cost, so any (b) win here is a floor.
 *
 * Run FOREGROUND:
 *   node --experimental-strip-types --no-warnings bench/cojson/binaryStreamTransfer.bench.ts
 */

import cronometro from "cronometro";
import { BinaryTransferProbe } from "cojson-core-napi";
import { base64URLtoBytes, bytesToBase64url } from "cojson";

const CHUNK_SIZE = 100 * 1024; // MAX_RECOMMENDED_TX_SIZE
const PREFIX = "binary_U";

interface Shape {
  name: string;
  bytes: Uint8Array;
  probe: BinaryTransferProbe;
  chunkCount: number;
}

// Deterministic pseudo-random file content (incompressible-ish, so base64 has
// no easy structure to exploit).
function makeBytes(seed: number, size: number): Uint8Array {
  const b = new Uint8Array(size);
  let a = seed >>> 0;
  for (let i = 0; i < size; i++) {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    b[i] = (t ^ (t >>> 14)) & 0xff;
  }
  return b;
}

function chunkBoundaries(size: number): [number, number][] {
  const out: [number, number][] = [];
  for (let o = 0; o < size; o += CHUNK_SIZE)
    out.push([o, Math.min(o + CHUNK_SIZE, size)]);
  if (size === 0) out.push([0, 0]);
  return out;
}

function makeShape(name: string, seed: number, size: number): Shape {
  const bytes = makeBytes(seed, size);
  const bounds = chunkBoundaries(size);
  // The CURRENT wire: a JSON array of `binary_U<base64url>` chunk strings, built
  // ONCE with the product's real encoder (matches getBinaryChunks' inverse).
  const wire = bounds.map(
    ([s, e]) => PREFIX + bytesToBase64url(bytes.subarray(s, e)),
  );
  const base64Json = JSON.stringify(wire);
  const probe = new BinaryTransferProbe(Buffer.from(bytes), base64Json);
  return { name, bytes, probe, chunkCount: bounds.length };
}

const SIZES: [string, number, number][] = [
  ["64KB (1 chunk)", 1, 64 * 1024],
  ["1MB (~10 chunks)", 2, 1024 * 1024],
  ["10MB (~100 chunks)", 3, 10 * 1024 * 1024],
];
const SHAPES = SIZES.map(([n, seed, size]) => makeShape(n, seed, size));

// ---------------------------------------------------------------------------
// Read-back implementations.
// ---------------------------------------------------------------------------

/** (a) current: String -> JSON.parse -> per-chunk base64 decode -> Uint8Array[] */
function readCurrent(probe: BinaryTransferProbe): Uint8Array[] {
  const json = probe.asBase64Json();
  const arr = JSON.parse(json) as string[];
  const out: Uint8Array[] = new Array(arr.length);
  for (let i = 0; i < arr.length; i++)
    out[i] = base64URLtoBytes(arr[i]!.slice(PREFIX.length));
  return out;
}

/** (b) native chunked: Buffer -> zero-copy subarray per 100KB chunk -> Uint8Array[] */
function readNativeChunks(probe: BinaryTransferProbe): Uint8Array[] {
  const buf = probe.asBuffer();
  const out: Uint8Array[] = [];
  for (let o = 0; o < buf.length; o += CHUNK_SIZE)
    out.push(buf.subarray(o, Math.min(o + CHUNK_SIZE, buf.length)));
  if (buf.length === 0) out.push(buf.subarray(0, 0));
  return out;
}

/** (b) native merged: Buffer as one Uint8Array (toBlob/asBase64 merge anyway). */
function readNativeMerged(probe: BinaryTransferProbe): Uint8Array {
  return probe.asBuffer();
}

// ---------------------------------------------------------------------------
// Correctness gate: all three channels reconstruct the original bytes.
// ---------------------------------------------------------------------------
function concat(chunks: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

console.log("=== gate: channels reconstruct identical bytes ===");
for (const s of SHAPES) {
  const cur = concat(readCurrent(s.probe));
  const nat = concat(readNativeChunks(s.probe));
  const mrg = readNativeMerged(s.probe);
  const ok = eq(cur, s.bytes) && eq(nat, s.bytes) && eq(mrg, s.bytes);
  console.log(
    `  [${s.name}] chunks=${s.chunkCount} rawBytes=${s.probe.byteLen()} ` +
      `wireBytes=${s.probe.base64JsonLen()} (+${(
        (s.probe.base64JsonLen() / s.probe.byteLen() - 1) * 100
      ).toFixed(1)}%) ${ok ? "OK" : "!! MISMATCH"}`,
  );
}

// ---------------------------------------------------------------------------
// Timed gate.
// ---------------------------------------------------------------------------
let sink = 0;
const tests: Record<string, { test: () => void }> = {};
for (const s of SHAPES) {
  tests[`[${s.name}] (a) CURRENT base64+JSON String`] = {
    test() {
      sink += readCurrent(s.probe).length;
    },
  };
  tests[`[${s.name}] (b) NATIVE Buffer -> chunks`] = {
    test() {
      sink += readNativeChunks(s.probe).length;
    },
  };
  tests[`[${s.name}] (b) NATIVE Buffer -> merged`] = {
    test() {
      sink += readNativeMerged(s.probe).length;
    },
  };
}

await cronometro(tests, {
  iterations: 200,
  warmup: true,
  print: { colors: true, compare: true },
  onTestError: (n: string, e: unknown) => console.error(`Error ${n}:`, e),
});

if (sink === -1) console.log("unreachable", sink);
