/**
 * Shared harness for the R4a coStream/coFeed-materialization GATE benchmark and
 * its correctness spot-check.
 *
 * The thesis under test (see the R4a task): coStream data is very commonly
 * PRIVATE (per-session encrypted feed items / file chunks). Rust already
 * decrypts natively (R1 key store). When Rust decrypts AND buckets every entry
 * in ONE native pass — instead of TS decrypting each tx across a separate FFI
 * crossing (`verified.decryptTransaction` → napi, once per tx, exactly what
 * `decryptTransactionChangesAndMeta` does) and then appending — there is real
 * per-tx crossing cost to amortize. Unlike coMap's plaintext-heavy yardstick
 * shape (where native LOST), coStream's private shape is where native should win.
 *
 * Fairness contract (mirrors the coMap harness):
 *  - IDENTICAL DATA: the native side replays the EXACT signed+encrypted
 *    transactions the TS stream produced (extracted verbatim from
 *    `core.verified`), so both materialize the same valid set from the same
 *    ciphertext.
 *  - COLD DECRYPT on both sides per measured build: the native side rebuilds a
 *    FRESH `NodeCore` each iteration (create + add + provideKey + materialize),
 *    decrypting all N txs from scratch. The TS baseline decrypts each tx from
 *    scratch each iteration via `verified.decryptTransaction` (the primitive
 *    `decryptTransactionChangesAndMeta` calls — it crosses FFI per tx and does
 *    NOT cache), then appends — i.e. TS's genuine per-tx-decrypt-then-append
 *    loop with a cold cache. (A live `RawCoStream.rebuildFromCore()` would be
 *    UNFAIR here: TS caches the decrypted `changes` on each `VerifiedTransaction`
 *    after the first parse, so a second rebuild is warm-decrypt — it measures
 *    only the append loop, not the decrypt the yardstick pays once per tx at
 *    ingest.)
 *  - unsafeAllowAll / group-owned as appropriate; no kill switches.
 */

import { NodeCore as NativeNodeCore } from "cojson-core-napi";
import { LocalNode } from "cojson";
import { NapiCrypto } from "cojson/crypto/NapiCrypto";

const Crypto = await NapiCrypto.create();

export function newNode(): LocalNode {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  return new LocalNode(agentSecret, sessionID, Crypto);
}

// ---------------------------------------------------------------------------
// Seeded RNG (mulberry32) + item generation. Items model feed entries: a mix of
// small scalars and small objects (like binary-chunk metadata / feed payloads).
// ---------------------------------------------------------------------------
export function makeRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function generateItems(seed: number, count: number): unknown[] {
  const rng = makeRng(seed);
  const items: unknown[] = [];
  for (let i = 0; i < count; i++) {
    const r = rng();
    if (r < 0.5) items.push(Math.floor(rng() * 1e9));
    else if (r < 0.8)
      items.push(`item-${Math.floor(rng() * 1e6).toString(36)}`);
    else
      items.push({
        seq: i,
        tag: `t${Math.floor(rng() * 1000)}`,
        n: Math.floor(rng() * 1e6),
      });
  }
  return items;
}

// ---------------------------------------------------------------------------
// TS side: a group-owned RawCoStream with PRIVATE pushes (so materialization
// must decrypt), plus its owning group's read key.
// ---------------------------------------------------------------------------
export interface PrivateTsStream {
  node: LocalNode;
  core: any;
  stream: any;
  coId: string;
  group: any;
  readKeyId: string;
  readKeySecret: string;
}

export function buildPrivateTsStream(
  items: unknown[],
  privacy: "private" | "trusting" = "private",
): PrivateTsStream {
  const node = newNode();
  const group = node.createGroup();
  const stream = group.createStream([], "trusting") as any;
  for (const item of items) stream.push(item as any, privacy);
  const rk = group.getCurrentReadKey();
  return {
    node,
    core: stream.core,
    stream,
    coId: stream.id,
    group,
    readKeyId: rk.id,
    readKeySecret: rk.secret!,
  };
}

// ---------------------------------------------------------------------------
// Extract the signed transactions of a TS covalue so the native side (and the
// cold TS decrypt loop) replay byte-identical ciphertext — no re-signing.
// ---------------------------------------------------------------------------
export interface Slice {
  sessionID: string;
  txsJson: string;
  sig: string;
  /** Per-tx (privacy, txIndex) so the cold TS decrypt loop knows what to do. */
  txs: { txIndex: number; privacy: "private" | "trusting" }[];
}
export interface Extracted {
  header: string;
  slices: Slice[];
}

export function extractSlices(core: any): Extracted {
  const header = JSON.stringify(core.verified.header);
  const slices: Slice[] = [];
  for (const [sessionID, log] of core.verified.sessionEntries()) {
    if (log.transactions.length === 0) continue;
    const txs = log.transactions.map((tx: any, i: number) => ({
      txIndex: i,
      privacy: tx.privacy as "private" | "trusting",
    }));
    slices.push({
      sessionID,
      txsJson: JSON.stringify(log.transactions),
      sig: log.lastSignature,
      txs,
    });
  }
  return { header, slices };
}

export function replayInto(
  nc: NativeNodeCore,
  coId: string,
  slices: Slice[],
): void {
  for (const s of slices) {
    nc.addTransactions(coId, s.sessionID, undefined, s.txsJson, s.sig, true);
  }
}

// ---------------------------------------------------------------------------
// Native cold build: fresh NodeCore each call — create + replay ciphertext +
// provide the read key + materialize (decrypt-and-bucket in ONE native pass).
// Returns the applied TS-side view (adopt each session's entry list) so the
// transfer+apply cost is included, matching the coMap two-tier gate.
// ---------------------------------------------------------------------------
export interface StreamDelta {
  version: number;
  reset: boolean;
  sessions: Record<
    string,
    {
      value: unknown;
      tx: { sessionID: string; txIndex: number };
      madeAt: number;
    }[]
  >;
}

/** Adopt a stream delta into a fresh per-session Map (the work a TS RawCoStream
 * does in `consumeNativeDelta`: set `items[sid]` to the entry list). */
export function applyStreamDelta(deltaJson: string): number {
  const delta = JSON.parse(deltaJson) as StreamDelta;
  const items = new Map<string, unknown[]>();
  let total = 0;
  for (const sid in delta.sessions) {
    const entries = delta.sessions[sid]!;
    items.set(sid, entries);
    total += entries.length;
  }
  return total;
}

/** Register `coId` (header) and replay its ciphertext into `nc`. Used for both
 * the stream and its owning group (the group's transactions are needed for the
 * stream's permission validation). */
export function loadCore(
  nc: NativeNodeCore,
  coId: string,
  ext: Extracted,
): void {
  if (!nc.hasCoValue(coId)) {
    nc.createCoValue(coId, ext.header, undefined, true);
  }
  replayInto(nc, coId, ext.slices);
}

/**
 * A cold-STREAM-build closure over a persistent `NodeCore` whose owning GROUP is
 * loaded and validated ONCE (warm — matching reality, where a device validates a
 * group once and reuses it across every stream ingest). Each call re-creates the
 * STREAM covalue from scratch (create replaces + drops its cached view/engine),
 * replays its ciphertext, provides the read key, and materializes + transfers —
 * so the stream itself is genuinely cold per call, but the group is not
 * re-validated (which would be an artifact of the bench, not the workload).
 */
export function makeNativeStreamBuilder(
  streamExt: Extracted,
  coId: string,
  groupExt: Extracted,
  groupId: string,
  key?: { id: string; secret: string },
): () => number {
  const nc = new NativeNodeCore();
  loadCore(nc, groupId, groupExt);
  if (key) nc.provideKeySecret(key.id, key.secret);
  // Warm the group engine once (validate the owning group's transactions).
  nc.createCoValue(coId, streamExt.header, undefined, true);
  replayInto(nc, coId, streamExt.slices);
  nc.streamMaterialize(coId, []);
  return () => {
    // Fresh stream covalue: `createCoValue` replaces the entry and drops its
    // cached view + engine, so materialization below is a full cold build of
    // the stream (the group engine stays cached/warm).
    nc.createCoValue(coId, streamExt.header, undefined, true);
    replayInto(nc, coId, streamExt.slices);
    nc.streamMaterialize(coId, []);
    return applyStreamDelta(nc.streamDelta(coId, 0));
  };
}

// ---------------------------------------------------------------------------
// TS cold build baseline: per-tx decrypt via `verified.decryptTransaction` (the
// exact primitive `decryptTransactionChangesAndMeta` uses; it crosses FFI per
// tx and does NOT cache), then append into a per-session Map. This is TS's
// genuine per-tx-decrypt-then-append loop with a cold decrypt cache — the cost
// the yardstick pays once per tx as content arrives.
// ---------------------------------------------------------------------------
export function tsColdBuildPrivate(
  pts: PrivateTsStream,
  ext: Extracted,
): number {
  const verified = pts.core.verified;
  const secret = pts.readKeySecret;
  const items = new Map<string, unknown[]>();
  let total = 0;
  for (const s of ext.slices) {
    const bucket: unknown[] = [];
    for (const { txIndex, privacy } of s.txs) {
      let changes: unknown[];
      if (privacy === "trusting") {
        // A trusting tx's changes are plaintext on the wire; mirror TS's
        // already-decoded path (cheap parse, no crossing).
        changes = verified.getSession(s.sessionID)?.transactions[txIndex]
          ? JSON.parse(
              verified.getSession(s.sessionID).transactions[txIndex].changes,
            )
          : [];
      } else {
        changes =
          verified.decryptTransaction(s.sessionID, txIndex, secret) ?? [];
      }
      for (const item of changes) bucket.push(item);
    }
    items.set(s.sessionID, bucket);
    total += bucket.length;
  }
  return total;
}
