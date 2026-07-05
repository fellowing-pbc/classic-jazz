/**
 * coPlainText (grapheme text CRDT) CONTENT fixture exporter.
 *
 * `RawCoPlainText extends RawCoList<string, Meta>`: its entries are single
 * graphemes and it emits the SAME `pre`/`app`/`del` wire ops as a coList, so the
 * native (Rust-resident) RGA materializer — which never inspects the covalue's
 * header type — must reproduce its `asArray()` / `entries()` / `toString()`
 * byte-for-byte with no coPlainText-specific Rust code. This exporter freezes the
 * CURRENT TS `RawCoPlainText` materialization as the contract the Rust port
 * replays (`crates/cojson-core/src/core/co_list.rs`,
 * `coplaintext_content_fixture_tests`).
 *
 * Captured per scenario (superset of the coList content fixture, plus `text`):
 *   - the raw wire form of every touched CoValue (header + sessions + txs +
 *     signerId + lastSignature) so a Rust `NodeCore` can ingest them via
 *     `add_transactions(..., skipVerify)`.
 *   - `snapshot` — `text.asArray()` (ordered grapheme values).
 *   - `entries`  — `text.entries()`, each `{value, madeAt, opID}` (opID carries
 *                  `branch` for merged transactions).
 *   - `text`     — `text.toString()`; the Rust replay additionally asserts
 *                  `snapshot.join("") === text`, the coPlainText-specific
 *                  grapheme-join contract coList never had.
 *   - `provideKeys` — read-key secrets a private scenario needs so the Rust side
 *                  can decrypt natively.
 *
 * Scenarios deliberately cover the coPlainText-SPECIFIC risk (unicode graphemes:
 * combining marks, ZWJ emoji, regional-indicator flags, skin-tone modifiers,
 * mixed scripts — coList items are arbitrary JSON, never grapheme-segmented) AND
 * the hardest RGA semantics the port must preserve: insert-after-a-deleted
 * position, genuine concurrent same-anchor inserts from two DISTINCT sessions
 * (two connected nodes) resolved purely by the global sorted-transaction order,
 * and branch/merge (a branch that inserts/deletes merged back into a source that
 * also changed — the `${sessionID}_branch_${branchId}` opID namespacing).
 *
 * When `EXPORT_COPLAINTEXT_CONTENT_FIXTURES=1` the fixtures are written to
 * `crates/cojson-core/data/co_plain_text_content/<scenario>.json`. Regardless of
 * export, the suite always asserts internal consistency so it has CI value.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { expectPlainText } from "../coValue.js";
import { WasmNode } from "../node/WasmNode.js";
import type { RawCoID } from "../ids.js";
import { LocalNode } from "../localNode.js";
import { loadCoValueOrFail, setupTestNode, waitFor } from "./testUtils.js";

const Crypto = await WasmNode.create();

const EXPORT = process.env.EXPORT_COPLAINTEXT_CONTENT_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/co_plain_text_content",
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
type TextEntry = {
  value: unknown;
  madeAt: number;
  opID: unknown;
};
type ContentFixture = {
  description: string;
  covalues: CoValueFixture[];
  listId: string;
  provideKeys: { keyId: string; keySecret: string }[];
  snapshot: unknown[];
  entries: TextEntry[];
  text: string;
};

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

/** Capture the TS RawCoPlainText's content views as the frozen contract. */
function captureContent(
  node: LocalNode,
  text: any,
  description: string,
  extraCovalueIds: RawCoID[] = [],
  provideKeys: { keyId: string; keySecret: string }[] = [],
): ContentFixture {
  const covalues = [
    ...extraCovalueIds.map((id) => readCoValue(node, id)),
    readCoValue(node, text.id),
  ];

  const snapshot = text.asArray() as unknown[];
  const entries: TextEntry[] = text.entries().map((e: any) => ({
    value: e.value,
    madeAt: e.madeAt,
    opID: e.opID,
  }));
  const asString = text.toString() as string;

  const fixture: ContentFixture = {
    description,
    covalues,
    listId: text.id,
    provideKeys,
    snapshot,
    entries,
    text: asString,
  };

  // Always-on internal consistency (CI value even without EXPORT).
  expect(covalues.length).toBeGreaterThan(0);
  for (const c of covalues) {
    expect(c.headerJson.length).toBeGreaterThan(0);
    for (const s of c.sessions)
      expect(s.lastSignature.length).toBeGreaterThan(0);
  }
  // snapshot values must equal the captured entry values in order.
  expect(snapshot).toEqual(entries.map((e) => e.value));
  // the coPlainText grapheme-join contract: joined graphemes == toString().
  expect((snapshot as string[]).join("")).toEqual(asString);
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

function newUnsafeText(node: LocalNode) {
  const coValue = node.createCoValue({
    type: "coplaintext",
    ruleset: { type: "unsafeAllowAll" },
    meta: null,
    ...Crypto.createdNowUnique(),
  });
  return expectPlainText(coValue.getCurrentContent()) as any;
}

describe("coPlainText content fixtures", () => {
  test("sequential_text: inserts, deletes, insert-after-deleted (trusting)", () => {
    const client = setupTestNode();
    const text = newUnsafeText(client.node);

    // Grapheme-accurate sequential edits (mirrors the core coPlainText test).
    text.insertAfter(0, "hello", "trusting"); // "hello"
    text.insertAfter(4, " world", "trusting"); // "hello world"
    text.insertBefore(0, "Hello, ", "trusting"); // "Hello, hello world"
    text.deleteRange({ from: 6, to: 12 }, "trusting"); // "Hello, world"
    // insert-after-a-deleted-position: index 7 ("w") sits right after the
    // now-deleted run, so its anchor (the ", " region) spans deleted entries.
    text.insertBefore(7, "there ", "trusting"); // "Hello, there world"

    writeFixture(
      "sequential_text",
      captureContent(
        client.node,
        text,
        "single-session grapheme inserts, deletes, insert-after-deleted",
      ),
    );
    expect(text.toString()).toEqual("Hello, there world");
  });

  test("unicode_text: combining marks, ZWJ emoji, flags, skin tone", () => {
    const client = setupTestNode();
    const text = newUnsafeText(client.node);

    // Combining marks — 3 graphemes: [a̐][é][ö̲]
    text.insertAfter(0, "a̐éö̲", "trusting");
    // ZWJ family (1 grapheme), regional-indicator flag (1), skin-tone (1).
    text.insertAfter(3, "👨‍👩‍👧‍👦", "trusting"); // append family
    text.insertAfter(4, "🇺🇸", "trusting"); // append flag
    text.insertBefore(0, "👍🏽", "trusting"); // prepend skin-tone thumbs-up
    // Mixed script + emoji, then delete a multi-codepoint grapheme mid-string.
    text.insertAfter(text.entries().length, " 안녕!", "trusting");
    // Delete the ZWJ family grapheme (verify grapheme-unit deletion).
    const familyIdx = text.asArray().indexOf("👨‍👩‍👧‍👦");
    text.deleteRange({ from: familyIdx, to: familyIdx + 1 }, "trusting");

    writeFixture(
      "unicode_text",
      captureContent(
        client.node,
        text,
        "multi-codepoint graphemes: combining, ZWJ, flag, skin tone, mixed script",
      ),
    );
    // Freeze whatever the grapheme-segmented RGA resolves to.
    expect(text.asArray()).not.toContain("👨‍👩‍👧‍👦");
    expect(text.toString()).toEqual(text.asArray().join(""));
  });

  test("concurrent_same_anchor_text: two DISTINCT sessions insert at one anchor", async () => {
    const client = setupTestNode({ isSyncServer: true, connected: true });
    const other = setupTestNode({});
    const otherConn = other.connectToSyncServer();

    const coValue = client.node.createCoValue({
      type: "coplaintext",
      ruleset: { type: "unsafeAllowAll" },
      meta: null,
      ...Crypto.createdNowUnique(),
    });
    const text = expectPlainText(coValue.getCurrentContent()) as any;
    text.insertAfter(0, "root", "trusting"); // "root"

    const textOnOther = expectPlainText(
      await loadCoValueOrFail(other.node, text.id),
    ) as any;

    // Partition the two nodes, then edit concurrently at the SAME anchor
    // (after the final "t", index 4). Distinct SessionIDs, real distinct madeAt.
    otherConn.peerState.gracefulShutdown();

    text.insertAfter(4, "-A", "trusting");
    await new Promise((r) => setTimeout(r, 20));
    textOnOther.insertAfter(4, "-B", "trusting");
    await new Promise((r) => setTimeout(r, 20));
    text.insertAfter(4, "-C", "trusting");

    // Heal the partition; both converge to the RGA-resolved order.
    other.connectToSyncServer();
    await waitFor(() => {
      expect(textOnOther.toString()).toEqual(text.toString());
      expect(text.asArray().length).toBe(10); // "root"(4) + "-A"/"-B"/"-C"(2 each)
    });

    writeFixture(
      "concurrent_same_anchor_text",
      captureContent(
        client.node,
        text,
        "genuine two-session concurrent same-anchor inserts, global sort order",
      ),
    );
    expect(text.toString().startsWith("root")).toBe(true);
  });

  test("branch_merge_text: branch inserts/deletes merged into a changed source", async () => {
    const client = setupTestNode();
    const group = client.node.createGroup();
    const text = group.createPlainText("bread") as any; // private init
    text.insertAfter(text.entries().length, " milk"); // "bread milk"
    // delete the "d" grapheme in "bread"
    text.deleteRange({ from: 4, to: 5 }); // "brea milk"

    const branch = expectPlainText(
      text.core.createBranch("feature-branch", group.id).getCurrentContent(),
    ) as any;
    branch.insertAfter(branch.entries().length, " eggs"); // branch adds
    branch.deleteRange({ from: 0, to: 1 }); // branch deletes first grapheme

    // Meanwhile the source also changes after the branch point. Advance the
    // clock so the source edit has a DISTINCT madeAt from the branch edits: a
    // same-millisecond tie across two sessions (branch-namespaced vs source)
    // is a genuine `compareTransactions === 0` tie that cojson resolves by
    // per-node ARRIVAL order — which is not encoded in the serialized fixture,
    // so it must not be relied on for a byte-for-byte replay contract (the
    // coList `branch_merge_list` fixture likewise keeps the madeAts distinct).
    await new Promise((r) => setTimeout(r, 5));
    text.insertAfter(text.entries().length, "!");

    const merged = expectPlainText(
      branch.core.mergeBranch().getCurrentContent(),
    ) as any;

    writeFixture(
      "branch_merge_text",
      captureContent(
        client.node,
        merged,
        "branch inserts/deletes merged into a source that also changed",
        [group.id],
        [
          {
            keyId: group.getCurrentReadKey().id,
            keySecret: group.getCurrentReadKey().secret!,
          },
        ],
      ),
    );
    // Freeze whatever the TS RGA resolves to (asserted equal to Rust replay).
    expect(merged.toString().length).toBeGreaterThan(0);
    expect(merged.asArray().join("")).toEqual(merged.toString());
  });
});
