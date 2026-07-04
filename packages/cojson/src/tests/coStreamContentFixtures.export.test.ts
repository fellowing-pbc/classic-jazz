/**
 * coStream/coFeed CONTENT fixture exporter (R4a).
 *
 * Builds real coStream state through the public cojson API and captures, per
 * scenario, the CURRENT TS `RawCoStream` materialization as the frozen contract
 * the Rust port must reproduce byte-for-byte:
 *   - the raw wire form of every touched CoValue (header + sessions + txs +
 *     signerId + lastSignature) so a Rust `NodeCore` can ingest them via
 *     `addTransactions(..., skipVerify)`.
 *   - `snapshot`   — `stream.toJSON()` (per-session value arrays).
 *   - `sessions`   — the per-session ordered `CoStreamItem[]` (`stream.items`),
 *                    each `{value, tx, madeAt}` — the payload a native
 *                    `streamDelta` must reproduce.
 *   - `frontier`   — `stream.atFrontier(f).toJSON()` for several frontier cuts.
 *   - `provideKeys`— read-key secrets a private scenario needs so the Rust side
 *                    can decrypt natively.
 *
 * These freeze the coStream content contract. The Rust replay lives in
 * `crates/cojson-core/src/core/co_stream.rs` (`content_fixture_tests`).
 *
 * When `EXPORT_COSTREAM_CONTENT_FIXTURES=1` the fixtures are written to
 * `crates/cojson-core/data/co_stream_content/<scenario>.json`. Regardless of
 * export, the suite always asserts internal consistency so it has CI value.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { WasmCrypto } from "../crypto/WasmCrypto.js";
import type { RawCoID } from "../ids.js";
import { LocalNode } from "../localNode.js";

const Crypto = await WasmCrypto.create();

const EXPORT = process.env.EXPORT_COSTREAM_CONTENT_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/co_stream_content",
);

type SessionFixture = {
  sessionId: string;
  signerId: string;
  transactions: string[];
  lastSignature: string;
};
type CoValueFixture = {
  coId: string;
  headerJson: string;
  sessions: SessionFixture[];
};
type StreamEntry = {
  value: unknown;
  tx: { sessionID: string; txIndex: number };
  madeAt: number;
};
type FrontierExpect = {
  frontier: Record<string, number>;
  snapshot: Record<string, unknown[]>;
};
type ContentFixture = {
  description: string;
  covalues: CoValueFixture[];
  streamId: string;
  provideKeys: { keyId: string; keySecret: string }[];
  snapshot: Record<string, unknown[]>;
  sessions: Record<string, StreamEntry[]>;
  frontier: FrontierExpect[];
};

function makeRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function generateItems(seed: number, count: number): unknown[] {
  const rng = makeRng(seed);
  const items: unknown[] = [];
  for (let i = 0; i < count; i++) {
    const r = rng();
    if (r < 0.5) items.push(Math.floor(rng() * 1e6));
    else if (r < 0.8)
      items.push(`item-${Math.floor(rng() * 1e6).toString(36)}`);
    else items.push({ seq: i, tag: `t${Math.floor(rng() * 1000)}` });
  }
  return items;
}

function readCoValue(node: LocalNode, id: RawCoID): CoValueFixture {
  const core = node.getCoValue(id);
  if (!core.verified) throw new Error(`CoValue ${id} is not available`);
  core.getValidTransactions({ ignorePrivateTransactions: false });
  const nc = node.nodeCore;
  const headerJson = nc.getHeader(id);
  const sessions: SessionFixture[] = nc.getSessionIds(id).map((sessionId) => {
    const rawTxs = nc.getSessionTransactions(id, sessionId, 0) ?? [];
    const transactions = rawTxs.map((tx) => JSON.stringify(tx));
    const lastSignature = nc.getLastSignature(id, sessionId)!;
    const signerId = core.verified!.getSession(sessionId as any)?.signerID!;
    return { sessionId, signerId, transactions, lastSignature };
  });
  return { coId: id, headerJson, sessions };
}

function newNode(): LocalNode {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  return new LocalNode(agentSecret, sessionID, Crypto);
}

/** Capture the TS RawCoStream's content views as the frozen contract. */
function captureContent(
  node: LocalNode,
  stream: any,
  description: string,
  extraCovalueIds: RawCoID[] = [],
  provideKeys: { keyId: string; keySecret: string }[] = [],
): ContentFixture {
  const covalues = [
    ...extraCovalueIds.map((id) => readCoValue(node, id)),
    readCoValue(node, stream.id),
  ];

  const snapshot = stream.toJSON() as Record<string, unknown[]>;

  // Per-session ordered CoStreamItem[] straight off the live view.
  const sessions: Record<string, StreamEntry[]> = {};
  for (const sid of stream.sessions() as string[]) {
    sessions[sid] = (stream.items[sid] as any[]).map((it) => ({
      value: it.value,
      tx: { sessionID: it.tx.sessionID, txIndex: it.tx.txIndex },
      madeAt: it.madeAt,
    }));
  }

  // Frontier views: full frontier + per-session partial cuts.
  const fullFrontier = stream.core.frontier() as Record<string, number>;
  const frontierCuts: Record<string, number>[] = [{}, fullFrontier];
  for (const [sid, n] of Object.entries(fullFrontier)) {
    if (n > 1) frontierCuts.push({ [sid]: Math.floor(n / 2) });
    frontierCuts.push({ [sid]: n });
  }
  const frontier: FrontierExpect[] = frontierCuts.map((f) => ({
    frontier: f,
    snapshot: stream.atFrontier(f).toJSON(),
  }));

  const fixture: ContentFixture = {
    description,
    covalues,
    streamId: stream.id,
    provideKeys,
    snapshot,
    sessions,
    frontier,
  };

  // Always-on internal consistency (CI value even without EXPORT).
  expect(covalues.length).toBeGreaterThan(0);
  for (const c of covalues) {
    expect(c.headerJson.length).toBeGreaterThan(0);
    for (const s of c.sessions)
      expect(s.lastSignature.length).toBeGreaterThan(0);
  }
  // snapshot values must match each session's captured entry values in order.
  for (const sid of Object.keys(snapshot)) {
    expect(snapshot[sid]).toEqual(sessions[sid]!.map((e) => e.value));
  }
  return fixture;
}

function writeFixture(name: string, fixture: ContentFixture) {
  if (!EXPORT) return;
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(
    join(OUT_DIR, `${name}.json`),
    JSON.stringify(fixture, null, 2),
  );
}

describe("coStream content fixtures", () => {
  test("trusting_stream: single-session trusting pushes", () => {
    const node = newNode();
    const group = node.createGroup();
    const stream = group.createStream([], "trusting") as any;
    for (const item of generateItems(101, 60)) stream.push(item, "trusting");
    writeFixture(
      "trusting_stream",
      captureContent(node, stream, "single-session trusting stream", [
        group.id,
      ]),
    );
    expect(stream.sessions().length).toBeGreaterThan(0);
  });

  test("private_stream: group-owned stream with private pushes + read key", () => {
    const node = newNode();
    const group = node.createGroup();
    const stream = group.createStream([], "trusting") as any;
    const rk = group.getCurrentReadKey();
    for (const item of generateItems(202, 80)) stream.push(item, "private");
    const fixture = captureContent(
      node,
      stream,
      "group-owned private stream (native decrypt)",
      [group.id],
      [{ keyId: rk.id, keySecret: rk.secret! }],
    );
    writeFixture("private_stream", fixture);
    const total = Object.values(fixture.snapshot).reduce(
      (a, b) => a + b.length,
      0,
    );
    expect(total).toBe(80);
  });

  test("mixed_stream: mixed trusting + private pushes in one session", () => {
    const node = newNode();
    const group = node.createGroup();
    const stream = group.createStream([], "trusting") as any;
    const rk = group.getCurrentReadKey();
    const items = generateItems(303, 50);
    items.forEach((item, i) =>
      stream.push(item, i % 2 === 0 ? "private" : "trusting"),
    );
    writeFixture(
      "mixed_stream",
      captureContent(
        node,
        stream,
        "mixed private/trusting entries, single session",
        [group.id],
        [{ keyId: rk.id, keySecret: rk.secret! }],
      ),
    );
    expect(stream.sessions().length).toBeGreaterThan(0);
  });
});
