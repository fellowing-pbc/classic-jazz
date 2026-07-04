/**
 * Benchmark: fetch (import content) + processing (build view) of a large CoList.
 *
 * Simulates a client receiving a large CoList over sync/storage:
 *  1. Node A creates a group + CoList with N items.
 *  2. Content messages are exported (what a peer would send).
 *  3. A fresh Node B imports them and reads the list.
 *
 * Run: pnpm exec tsx bench/colist.load.bench.ts [items] [itemsPerTx]
 */
import { LocalNode, ControlledAgent } from "cojson";
import { WasmCrypto } from "cojson/crypto/WasmCrypto";
import type { RawCoList } from "cojson";

const ITEMS = Number(process.argv[2] ?? 100_000);
const ITEMS_PER_TX = Number(process.argv[3] ?? 100);
const PRIVACY = (process.env.PRIVACY ?? "private") as "private" | "trusting";

const crypto = await WasmCrypto.create();

function ms(n: number) {
  return `${n.toFixed(1)}ms`;
}

function createNode(agentSecret = crypto.newRandomAgentSecret()) {
  const agent = new ControlledAgent(agentSecret, crypto);
  const node = new LocalNode(
    agentSecret,
    crypto.newRandomSessionID(agent.id),
    crypto,
  );
  return { node, agentSecret };
}

// --- Node A: create the list ---------------------------------------------
const { node: nodeA, agentSecret } = createNode();
const group = nodeA.createGroup();

const tCreate0 = performance.now();
const list = group.createList<RawCoList<string>>();
const batch: string[] = [];
for (let i = 0; i < ITEMS_PER_TX; i++) {
  batch.push(`item-with-some-payload-${i}-abcdefghijklmnopqrstuvwxyz`);
}
for (let i = 0; i < ITEMS / ITEMS_PER_TX; i++) {
  list.appendItems(batch, undefined, PRIVACY);
}
const tCreate1 = performance.now();

console.log(
  `create: ${ITEMS} items in ${ITEMS / ITEMS_PER_TX} txs -> ${ms(tCreate1 - tCreate0)}`,
);

// --- Export content messages (what a sync peer would send) ----------------
const groupContent = nodeA.getCoValue(group.id).newContentSince(undefined)!;
const listContent = nodeA.getCoValue(list.id).newContentSince(undefined)!;
console.log(
  `content chunks: group=${groupContent.length} list=${listContent.length}`,
);

// --- Node B: import + read -------------------------------------------------
const SUBSCRIBED = Boolean(process.env.SUBSCRIBED);

async function loadOnFreshNode() {
  const { node: nodeB } = createNode(agentSecret);
  if (process.env.SKIP_VERIFY) {
    nodeB.syncManager.disableTransactionVerification();
  }

  // Simulate an app subscription (jazz-tools always loads through one):
  // the listener reads the list contents on every update.
  let listenerReads = 0;
  if (SUBSCRIBED) {
    nodeB.getCoValue(list.id).subscribe((core) => {
      if (core.isAvailable()) {
        (core.getCurrentContent() as RawCoList<string>).length();
        listenerReads++;
      }
    }, false);
  }

  const tImport0 = performance.now();
  for (const chunk of groupContent) {
    nodeB.syncManager.handleNewContent(chunk, "import");
  }
  for (const chunk of listContent) {
    nodeB.syncManager.handleNewContent(chunk, "import");
    if (SUBSCRIBED) {
      // let the microtask-batched notifications fire per chunk,
      // like websocket messages arriving one per macrotask
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  const tImport1 = performance.now();

  const listB = nodeB
    .getCoValue(list.id)
    .getCurrentContent() as RawCoList<string>;
  const entries = listB.entries();
  const tRead1 = performance.now();

  if (entries.length !== ITEMS) {
    throw new Error(`expected ${ITEMS} entries, got ${entries.length}`);
  }
  if (process.env.VERIFY) {
    for (let i = 0; i < entries.length; i++) {
      if (entries[i]!.value !== batch[i % ITEMS_PER_TX]) {
        throw new Error(
          `order mismatch at ${i}: ${entries[i]!.value} != ${batch[i % ITEMS_PER_TX]}`,
        );
      }
    }
    // also verify against a fresh full traversal (no incremental cache)
    const fresh = listB.entriesUncached();
    if (
      fresh.length !== entries.length ||
      fresh.some((e, i) => e.value !== entries[i]!.value)
    ) {
      throw new Error("incremental cache diverges from full traversal");
    }
  }

  nodeB.gracefulShutdown();

  return {
    import: tImport1 - tImport0,
    read: tRead1 - tImport1,
    total: tRead1 - tImport0,
    listenerReads,
  };
}

// warmup
await loadOnFreshNode();

let stopProfiler: (() => Promise<void>) | undefined;
if (process.env.PROFILE) {
  const inspector = await import("node:inspector");
  const fs = await import("node:fs");
  const session = new inspector.Session();
  session.connect();
  const post = (method: string, params?: object) =>
    new Promise<any>((resolve, reject) =>
      session.post(method, params, (err, res) =>
        err ? reject(err) : resolve(res),
      ),
    );
  await post("Profiler.enable");
  await post("Profiler.start");
  stopProfiler = async () => {
    const { profile } = await post("Profiler.stop");
    fs.writeFileSync(process.env.PROFILE!, JSON.stringify(profile));
    console.log(`profile written to ${process.env.PROFILE}`);
  };
}

const runs: Awaited<ReturnType<typeof loadOnFreshNode>>[] = [];
for (let i = 0; i < 5; i++) {
  runs.push(await loadOnFreshNode());
}

await stopProfiler?.();

const best = runs.reduce((a, b) => (a.total < b.total ? a : b));
const median = [...runs].sort((a, b) => a.total - b.total)[
  Math.floor(runs.length / 2)
]!;

console.log(
  `load (import+read) best:   import=${ms(best.import)} read=${ms(best.read)} total=${ms(best.total)}`,
);
console.log(
  `load (import+read) median: import=${ms(median.import)} read=${ms(median.read)} total=${ms(median.total)}`,
);
