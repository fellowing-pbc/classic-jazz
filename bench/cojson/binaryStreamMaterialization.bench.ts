/**
 * binaryCoStream — STEP 6 (the REAL gate): COLD full-materialize of a PRIVATE
 * (encrypted) file's chunks, read back to raw bytes, native vs TS, on realistic
 * file sizes. This is the actual wiring decision gate — Step 1
 * (binaryStreamTransfer.bench.ts) already proved the transfer-only delta; this
 * measures the whole read path including decrypt + base64-decode.
 *
 *   (native) fresh NodeCore -> replay ciphertext -> provideKey ->
 *            streamMaterialize (decrypt every chunk tx in ONE native pass) ->
 *            streamBinaryChunks (base64url-decode every chunk RUST-side and
 *            concatenate) -> napi Buffer (near-zero-copy) -> Uint8Array.
 *   (TS)     per-chunk verified.decryptTransaction (one FFI crossing per chunk,
 *            cold cache — the primitive getBinaryChunks' materialization uses)
 *            -> JSON.parse -> slice "binary_U" -> base64URLtoBytes -> Uint8Array[]
 *            -> merged (what FileStream.toBlob / asBase64 ultimately do).
 *
 * Both decrypt all chunks from scratch each iteration over byte-identical
 * ciphertext (the coStream harness fairness contract). Chunk size = the
 * product's real MAX_RECOMMENDED_TX_SIZE (100KB); FileStream chunks at exactly
 * this.
 *
 * Run FOREGROUND:
 *   node --experimental-strip-types --no-warnings bench/cojson/binaryStreamMaterialization.bench.ts
 */

import cronometro from "cronometro";
import { isMainThread } from "node:worker_threads";
import { NodeCore as NativeNodeCore } from "cojson-core-napi";
import { LocalNode } from "cojson";
import { base64URLtoBytes } from "cojson";
import { NapiCrypto } from "cojson/crypto/NapiCrypto";
import { extractSlices, loadCore, type Extracted } from "./coStreamHarness.ts";

const Crypto = await NapiCrypto.create();
const CHUNK_SIZE = 100 * 1024; // TRANSACTION_CONFIG.MAX_RECOMMENDED_TX_SIZE
const PREFIX = "binary_U";

function newNode(): LocalNode {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  return new LocalNode(agentSecret, sessionID, Crypto);
}

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

interface Shape {
  name: string;
  bytes: Uint8Array;
  core: any;
  coId: string;
  group: any;
  ext: Extracted;
  groupExt: Extracted;
  key: { id: string; secret: string };
  /** per-chunk (txIndex, sessionID) for the TS cold-decrypt loop */
  chunkTxs: { sessionID: string; txIndex: number }[];
}

function makeShape(name: string, seed: number, size: number): Shape {
  const node = newNode();
  const group = node.createGroup();
  const stream = group.createBinaryStream() as any;
  const bytes = makeBytes(seed, size);
  stream.startBinaryStream(
    { mimeType: "application/octet-stream", totalSizeBytes: size },
    "private",
  );
  for (let o = 0; o < bytes.length; o += CHUNK_SIZE) {
    stream.pushBinaryStreamChunk(bytes.subarray(o, o + CHUNK_SIZE), "private");
  }
  stream.endBinaryStream("private");

  const core = stream.core;
  const ext = extractSlices(core);
  const groupExt = extractSlices(group.core);
  const rk = group.getCurrentReadKey();

  // The cold-decrypt loop decrypts EVERY private tx (start/end included) and
  // keeps chunk payloads; index them from the extracted slices.
  const chunkTxs: { sessionID: string; txIndex: number }[] = [];
  for (const s of ext.slices) {
    for (const t of s.txs)
      chunkTxs.push({ sessionID: s.sessionID, txIndex: t.txIndex });
  }

  return {
    name,
    bytes,
    core,
    coId: stream.id,
    group,
    ext,
    groupExt,
    key: { id: rk.id, secret: rk.secret! },
    chunkTxs,
  };
}

// ---------------------------------------------------------------------------
// Native cold build: fresh stream covalue each call (group kept warm), replay
// ciphertext, materialize (decrypt), read raw bytes as a Buffer.
// ---------------------------------------------------------------------------
function makeNativeBuilder(s: Shape): () => number {
  const nc = new NativeNodeCore();
  loadCore(nc, s.group.id, s.groupExt);
  nc.provideKeySecret(s.key.id, s.key.secret);
  nc.createCoValue(s.coId, s.ext.header, undefined, true);
  for (const sl of s.ext.slices)
    nc.addTransactions(
      s.coId,
      sl.sessionID,
      undefined,
      sl.txsJson,
      sl.sig,
      true,
    );
  nc.streamMaterialize(s.coId, []);
  return () => {
    nc.createCoValue(s.coId, s.ext.header, undefined, true);
    for (const sl of s.ext.slices)
      nc.addTransactions(
        s.coId,
        sl.sessionID,
        undefined,
        sl.txsJson,
        sl.sig,
        true,
      );
    nc.streamMaterialize(s.coId, []);
    const buf = nc.streamBinaryChunks(s.coId); // raw bytes, near-zero-copy
    return buf.length;
  };
}

// ---------------------------------------------------------------------------
// TS cold build: per-chunk decrypt (cold cache) -> JSON.parse -> base64 decode
// -> merged Uint8Array (the getBinaryChunks + concat the product performs).
// ---------------------------------------------------------------------------
function tsColdBuild(s: Shape): number {
  const verified = s.core.verified;
  const secret = s.key.secret;
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (const { sessionID, txIndex } of s.chunkTxs) {
    const changes = verified.decryptTransaction(sessionID, txIndex, secret) as
      | any[]
      | undefined;
    if (!changes) continue;
    for (const item of changes) {
      if (item && item.type === "chunk") {
        const u8 = base64URLtoBytes(
          (item.chunk as string).slice(PREFIX.length),
        );
        chunks.push(u8);
        total += u8.length;
      }
    }
  }
  // Merge to a single Uint8Array (FileStream.toBlob/asBase64 shape).
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.length;
  }
  return merged.length;
}

// Warm re-read: the file is already loaded/decrypted; measure ONLY the
// read-back (base64 decode + assemble), the marginal cost of a repeat
// getBinaryChunks / toBlob. Native hands back a Rust-decoded Buffer; TS re-runs
// base64URLtoBytes in JS over its cached chunk strings each call.
function makeWarmNative(s: Shape): () => number {
  const nc = new NativeNodeCore();
  loadCore(nc, s.group.id, s.groupExt);
  nc.provideKeySecret(s.key.id, s.key.secret);
  loadCore(nc, s.coId, s.ext);
  nc.streamMaterialize(s.coId, []);
  return () => nc.streamBinaryChunks(s.coId).length;
}
function makeWarmTs(s: Shape): () => number {
  const content = s.core.getCurrentContent() as any; // RawBinaryCoStream
  content.getBinaryChunks(true); // warm the decrypt cache (this.chunks)
  return () => {
    const r = content.getBinaryChunks(true);
    let n = 0;
    for (const c of r.chunks) n += c.length;
    return n;
  };
}

const SIZES: [string, number, number][] = [
  ["64KB", 1, 64 * 1024],
  ["1MB", 2, 1024 * 1024],
  ["10MB", 3, 10 * 1024 * 1024],
];
// Built in every thread (cronometro re-imports the module per worker; each test
// closure needs its shape).
const SHAPES = SIZES.map(([n, seed, size]) => makeShape(n, seed, size));

// ---------------------------------------------------------------------------
// Correctness gate: native raw bytes === TS merged bytes === original.
// ---------------------------------------------------------------------------
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

if (isMainThread)
  console.log("=== gate: native raw bytes reconstruct the original file ===");
for (const s of isMainThread ? SHAPES : []) {
  const nc = new NativeNodeCore();
  loadCore(nc, s.group.id, s.groupExt);
  nc.provideKeySecret(s.key.id, s.key.secret);
  loadCore(nc, s.coId, s.ext);
  nc.streamMaterialize(s.coId, []);
  const native = nc.streamBinaryChunks(s.coId);
  const ok = eq(native, s.bytes) && nc.streamMissingKeyIds(s.coId).length === 0;
  console.log(
    `  [${s.name}] chunks=${s.chunkTxs.length} nativeBytes=${native.length} ` +
      `expected=${s.bytes.length} ${ok ? "OK" : "!! MISMATCH"}`,
  );
}

// ---------------------------------------------------------------------------
// Timed gate.
// ---------------------------------------------------------------------------
let sink = 0;
const tests: Record<string, { test: () => void }> = {};
for (const s of SHAPES) {
  const nativeBuild = makeNativeBuilder(s);
  tests[`[${s.name}] native decrypt+decode(Rust)+Buffer`] = {
    test() {
      sink += nativeBuild();
    },
  };
  tests[`[${s.name}] TS per-chunk decrypt+base64+merge`] = {
    test() {
      sink += tsColdBuild(s);
    },
  };
  const warmNative = makeWarmNative(s);
  const warmTs = makeWarmTs(s);
  tests[`[${s.name}] WARM re-read native Buffer`] = {
    test() {
      sink += warmNative();
    },
  };
  tests[`[${s.name}] WARM re-read TS getBinaryChunks`] = {
    test() {
      sink += warmTs();
    },
  };
}

await cronometro(tests, {
  iterations: 100,
  warmup: true,
  print: { colors: true, compare: true },
  onTestError: (n: string, e: unknown) => console.error(`Error ${n}:`, e),
});

if (sink === -1) console.log("unreachable", sink);
