/**
 * coList (RGA list CRDT) CONTENT fixture exporter.
 *
 * Builds real coList state through the public cojson API and captures, per
 * scenario, the CURRENT TS `RawCoList` materialization as the frozen contract
 * the Rust port must reproduce byte-for-byte:
 *   - the raw wire form of every touched CoValue (header + sessions + txs +
 *     signerId + lastSignature) so a Rust `NodeCore` can ingest them via
 *     `addTransactions(..., skipVerify)`.
 *   - `snapshot` — `list.asArray()` (ordered values).
 *   - `entries`  — `list.entries()`, each `{value, madeAt, opID}` — the payload
 *                  a native `listDelta` / `listEntries` must reproduce (opID
 *                  carries `branch` for merged transactions).
 *   - `provideKeys` — read-key secrets a private scenario needs so the Rust side
 *                  can decrypt natively.
 *
 * Scenarios deliberately cover the hardest coList semantics: concurrent inserts
 * at the SAME anchor resolved purely by the global sorted-transaction order, and
 * branch/merge (a branch that inserts/deletes merged back into a source that
 * also changed — the shape of the coStream branch-merge regression) which
 * exercises the `${sessionID}_branch_${branchId}` opID namespacing.
 *
 * The Rust replay lives in `crates/cojson-core/src/core/co_list.rs`
 * (`content_fixture_tests`).
 *
 * When `EXPORT_COLIST_CONTENT_FIXTURES=1` the fixtures are written to
 * `crates/cojson-core/data/co_list_content/<scenario>.json`. Regardless of
 * export, the suite always asserts internal consistency so it has CI value.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { expectList } from "../coValue.js";
import { WasmNode } from "../node/WasmNode.js";
import type { RawCoID } from "../ids.js";
import { LocalNode } from "../localNode.js";

const Crypto = await WasmNode.create();

const EXPORT = process.env.EXPORT_COLIST_CONTENT_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/co_list_content",
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
type ListEntry = {
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
  entries: ListEntry[];
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

function newNode(): LocalNode {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  return new LocalNode(agentSecret, sessionID, Crypto);
}

/** Capture the TS RawCoList's content views as the frozen contract. */
function captureContent(
  node: LocalNode,
  list: any,
  description: string,
  extraCovalueIds: RawCoID[] = [],
  provideKeys: { keyId: string; keySecret: string }[] = [],
): ContentFixture {
  const covalues = [
    ...extraCovalueIds.map((id) => readCoValue(node, id)),
    readCoValue(node, list.id),
  ];

  const snapshot = list.asArray() as unknown[];
  const entries: ListEntry[] = list.entries().map((e: any) => ({
    value: e.value,
    madeAt: e.madeAt,
    opID: e.opID,
  }));

  const fixture: ContentFixture = {
    description,
    covalues,
    listId: list.id,
    provideKeys,
    snapshot,
    entries,
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

describe("coList content fixtures", () => {
  test("sequential_list: appends, prepends, deletes, replace (trusting)", () => {
    const node = newNode();
    const group = node.createGroup();
    const list = group.createList([], null, "trusting") as any;

    list.appendItems(["a", "b", "c", "d"], undefined, "trusting");
    list.prepend("z", 0, "trusting"); // -> z a b c d
    list.append("e", 4, "trusting"); // after "d" -> z a b c d e
    list.delete(list.asArray().indexOf("b"), "trusting"); // -> z a c d e
    list.replace(list.asArray().indexOf("c"), "C", "trusting"); // -> z a C d e

    writeFixture(
      "sequential_list",
      captureContent(node, list, "single-session sequential edits", [group.id]),
    );
    expect(list.asArray()).toEqual(["z", "a", "C", "d", "e"]);
  });

  test("private_list: group-owned list with private edits + read key", () => {
    const node = newNode();
    const group = node.createGroup();
    const list = group.createList([], null, "trusting") as any;
    const rk = group.getCurrentReadKey();

    list.appendItems(["one", "two", "three", "four"], undefined, "private");
    list.delete(list.asArray().indexOf("two"), "private");
    list.append("five", list.asArray().indexOf("four"), "private");

    writeFixture(
      "private_list",
      captureContent(
        node,
        list,
        "group-owned private list (native decrypt)",
        [group.id],
        [{ keyId: rk.id, keySecret: rk.secret! }],
      ),
    );
    expect(list.asArray()).toEqual(["one", "three", "four", "five"]);
  });

  test("branch_merge_list: branch inserts/deletes merged into a changed source", () => {
    const node = newNode();
    const group = node.createGroup();
    const list = group.createList() as any;

    list.appendItems(["bread", "milk", "eggs"]);
    list.delete(list.asArray().indexOf("milk")); // -> bread, eggs

    const branch = expectList(
      list.core.createBranch("feature-branch", group.id).getCurrentContent(),
    ) as any;

    branch.appendItems(["cheese", "yogurt", "bananas"]);
    branch.delete(branch.asArray().indexOf("yogurt"));

    // Meanwhile the source also changes after the branch point.
    list.append("apples", list.asArray().indexOf("eggs"));

    const merged = expectList(
      branch.core.mergeBranch().getCurrentContent(),
    ) as any;

    writeFixture(
      "branch_merge_list",
      captureContent(
        node,
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
    expect(merged.asArray().length).toBeGreaterThan(0);
  });

  test("concurrent_branches_list: two branches off one list, both merged", () => {
    const node = newNode();
    const group = node.createGroup();
    const list = group.createList() as any;

    list.appendItems(["root-1", "root-2"]);

    const alice = expectList(
      list.core.createBranch("alice-branch", group.id).getCurrentContent(),
    ) as any;
    const bob = expectList(
      list.core.createBranch("bob-branch", group.id).getCurrentContent(),
    ) as any;

    // Both branches insert after the SAME anchor ("root-1") — concurrent
    // inserts resolved purely by the global sorted-transaction order.
    alice.append("alice-x", alice.asArray().indexOf("root-1"));
    alice.append("alice-y", alice.asArray().indexOf("alice-x"));
    bob.append("bob-x", bob.asArray().indexOf("root-1"));
    bob.delete(bob.asArray().indexOf("root-2"));

    alice.core.mergeBranch();
    bob.core.mergeBranch();

    const merged = expectList(list.core.getCurrentContent()) as any;

    writeFixture(
      "concurrent_branches_list",
      captureContent(
        node,
        merged,
        "two concurrent branches merged into the same source",
        [group.id],
        [
          {
            keyId: group.getCurrentReadKey().id,
            keySecret: group.getCurrentReadKey().secret!,
          },
        ],
      ),
    );
    expect(merged.asArray().length).toBeGreaterThan(0);
  });
});
