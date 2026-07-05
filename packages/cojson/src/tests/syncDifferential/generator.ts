/**
 * Seeded, model-based scenario generator for the differential harness.
 *
 * Each seed deterministically drives a randomized multi-peer session: a random
 * CoValue DAG (group + maps, optionally an extended parent group), randomized
 * transaction interleavings across clients, and randomized
 * connect/disconnect/reconnect/stream/delete/correction sequences. After the run
 * every client is reconnected and the session is settled; the generator then
 * asserts NO DATA LOSS (every recorded write is still readable on every client)
 * and returns the named cores/nodes so the harness can assert EVENTUAL
 * CONVERGENCE.
 *
 * The op mix intentionally over-weights the exact paths the scoping pass flagged
 * as silent-failure-prone — reconnect (optimistic-state loss), streaming
 * (chunk-ordering), deletion (tombstone divergence), and correction
 * (assumed-invalid-state) — rather than happy-path writes only.
 *
 * TEST-ONLY. No production import.
 */
import type { RawCoMap } from "../../coValues/coMap.js";
import type { JsonValue } from "../../jsonValue.js";
import { fillCoMapWithLargeData, waitFor } from "../testUtils.js";
import type { Scenario } from "./harness.js";
import {
  connect,
  disconnect,
  makeNode,
  stabilize,
  type MeshNode,
} from "./mesh.js";

/** mulberry32: tiny, fast, fully deterministic seeded PRNG. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise<void>((resolve) => queueMicrotask(resolve));
  }
}

async function settle(...nodes: MeshNode[]): Promise<void> {
  await flush();
  await Promise.all(
    nodes.map((n) =>
      n.node.syncManager.waitForAllCoValuesSync(15_000).catch(() => {}),
    ),
  );
  await flush();
}

export type SeedResult = {
  scenario: Scenario;
};

export function makeSeedScenario(seed: number): Scenario {
  const rng = mulberry32(seed);
  const pick = <T>(arr: T[]): T => arr[Math.floor(rng() * arr.length)]!;
  const chance = (p: number) => rng() < p;

  return {
    name: `seed_${seed}`,
    run: async () => {
      const server = makeNode("server");
      const clientCount = 2 + Math.floor(rng() * 2); // 2..3 clients
      const clients: MeshNode[] = Array.from({ length: clientCount }, (_, i) =>
        makeNode(`client${i}`),
      );
      const all = [server, ...clients];
      const connected = new Set<MeshNode>();
      for (const c of clients) {
        connect(server, c);
        connected.add(c);
      }

      // --- random CoValue DAG ---
      const owner = clients[0]!;
      let group = owner.node.createGroup();
      group.addMember("everyone", "writer");
      if (chance(0.5)) {
        // Extend with a parent group to exercise dependency sync.
        const parent = owner.node.createGroup();
        group.extend(parent);
      }
      const primary = group.createMap();
      const secondary = chance(0.5) ? group.createMap() : undefined;

      // Data-loss oracle: recorded writes to the (never-deleted) primary map.
      const expected: Record<string, JsonValue> = {};
      let counter = 0;
      let secondaryDeleted = false;
      let streamed = false;

      const contentFor = async (
        client: MeshNode,
        mapCore = primary.core,
      ): Promise<RawCoMap | undefined> => {
        const core = await client.node.loadCoValueCore(mapCore.id);
        if (!core.isAvailable()) return undefined;
        return core.getCurrentContent() as unknown as RawCoMap;
      };

      const writeOn = async (client: MeshNode) => {
        const map = await contentFor(client);
        if (!map) return;
        const key = `k${counter++}`;
        const value = `s${seed}_${key}`;
        map.set(key, value, "trusting");
        expected[key] = value;
      };

      await settle(...all);
      // Ensure every client has the primary map before interleaving writes.
      for (const c of clients) {
        await waitFor(async () => {
          const core = await c.node.loadCoValueCore(primary.core.id);
          if (!core.isAvailable()) throw new Error("primary not loaded");
        });
      }

      const rounds = 5 + Math.floor(rng() * 8); // 5..12 rounds
      for (let r = 0; r < rounds; r++) {
        const op = pick([
          "write",
          "write",
          "write",
          "reconnect",
          "reconnect",
          "stream",
          "delete",
          "correction",
        ]);

        if (op === "write") {
          const c = pick([...connected]);
          if (c) await writeOn(c);
        } else if (op === "reconnect") {
          const c = pick(clients);
          if (connected.has(c)) {
            // Offline write then reconnect: the classic optimistic-reset path.
            disconnect(server, c);
            connected.delete(c);
            await flush();
            const map = await contentFor(c);
            if (map) {
              const key = `k${counter++}`;
              const value = `s${seed}_${key}`;
              map.set(key, value, "trusting");
              expected[key] = value;
            }
            connect(server, c);
            connected.add(c);
            await flush();
          } else {
            connect(server, c);
            connected.add(c);
            await flush();
          }
        } else if (op === "stream" && secondary && !streamed) {
          fillCoMapWithLargeData(secondary as unknown as RawCoMap);
          streamed = true;
        } else if (op === "delete" && secondary && !secondaryDeleted) {
          secondary.core.deleteCoValue();
          secondaryDeleted = true;
        } else if (op === "correction") {
          // Server-side data loss on the primary, then a client rewrite forces a
          // KNOWN CORRECTION and recovery.
          if (server.node.getCoValue(primary.core.id).isAvailable()) {
            server.node.internalDeleteCoValue(primary.core.id);
            const c = pick([...connected]) ?? clients[0]!;
            await writeOn(c);
            await flush();
          }
        }
      }

      // Reconnect everyone and let the whole mesh quiesce.
      for (const c of clients) {
        if (!connected.has(c)) {
          connect(server, c);
          connected.add(c);
        }
      }
      const trackedIds = [group.core.id, primary.core.id];
      if (secondary && !secondaryDeleted) trackedIds.push(secondary.core.id);
      await stabilize(all, trackedIds);

      // --- NO DATA LOSS oracle ---
      for (const c of clients) {
        const map = await contentFor(c);
        if (!map) {
          throw new Error(
            `seed ${seed}: client ${c.name} lost the primary map entirely`,
          );
        }
        for (const [key, value] of Object.entries(expected)) {
          const got = map.get(key);
          if (got !== value) {
            throw new Error(
              `seed ${seed}: data loss on ${c.name} key ${key}: expected ${JSON.stringify(
                value,
              )} got ${JSON.stringify(got)}`,
            );
          }
        }
      }

      const coValues: Record<string, (typeof primary)["core"]> = {
        Group: group.core,
        Primary: primary.core,
      };
      if (secondary) coValues.Secondary = secondary.core;

      return {
        coValues,
        nodes: Object.fromEntries(all.map((n) => [n.name, n.node])),
      };
    },
  };
}
