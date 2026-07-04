/**
 * Randomized differential harness: TS group-permission engine vs native NodeCore.
 *
 * Builds N random group scenarios (native crypto, native validation enabled by
 * default), snapshots verdicts + role queries, then flips the
 * `COJSON_DISABLE_NATIVE_VALIDATION` kill switch on and forces a second
 * validation pass over the SAME already-ingested transactions, and asserts the
 * two passes agree.
 *
 * For the GROUP ruleset, `determineValidTransactions` and
 * `RawGroup#roleOfInternal` recompute from scratch on every call (see
 * permissions.ts/group.ts), so no extra plumbing is needed to force a
 * revalidation. The OWNED-COVALUE (ownedByGroup) ruleset is different: its TS
 * fallback iterates `coValue.toValidateTransactions`, which the
 * `determineValidTransactions` wrapper DRAINS to `[]` after every call
 * (coValueCore.ts). So after pass 1 (native) runs, that list is already empty
 * and, without intervention, pass 2 (TS-forced) would iterate nothing and
 * silently retain pass 1's verdicts for every owned-map transaction — a
 * self-comparison that would make the whole owned-covalue extension a no-op
 * (verified experimentally: native-call spying showed 0 native calls but
 * `isValid` unchanged when reset was skipped). The fix (and the "reset
 * wrappers between passes" mitigation from the stage-3 porter notes) is to
 * call `core.resetParsedTransactions()` on each owned map's core AFTER
 * stubbing the kill switch on: that repopulates `toValidateTransactions` and,
 * as a side effect, immediately re-runs `determineValidTransactions` under the
 * TS path (confirmed via the same native-call spy: 0 native calls, verdicts
 * recomputed). Order matters — reset before stubbing would just re-run the
 * native path again.
 *
 * Seed is logged on failure and overridable via DIFF_SEED so a divergence can
 * be reproduced deterministically. Reproduction is STRUCTURAL, not bitwise:
 * the seed drives op structure and time ordering, but account/session IDs come
 * from real crypto randomness — fine because the harness deliberately avoids
 * ID-ordering-sensitive constructions (see tick()).
 */
import { expect, test, vi } from "vitest";
import { expectMap } from "../coValue.js";
import {
  ControlledAccount,
  ControlledAgent,
  type RawAccountID,
} from "../coValues/account.js";
import type { RawCoMap } from "../coValues/coMap.js";
import { EVERYONE, type Everyone, type RawGroup } from "../coValues/group.js";
import type { CoValueCore } from "../coValueCore/coValueCore.js";
import { NapiCrypto } from "../crypto/NapiCrypto.js";
import type { AgentID } from "../ids.js";
import { LocalNode } from "../localNode.js";
import type { AccountRole, Role } from "../permissions.js";
import { expectGroup } from "../typeUtils/expectGroup.js";

const Crypto = await NapiCrypto.create();

// ---------------------------------------------------------------------------
// PRNG
// ---------------------------------------------------------------------------

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function rng() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, maxInclusive: number) {
  return min + Math.floor(rng() * (maxInclusive - min + 1));
}

function pick<T>(rng: () => number, arr: readonly T[]): T {
  return arr[randInt(rng, 0, arr.length - 1)]!;
}

// ---------------------------------------------------------------------------
// Node/account helpers (bound to a native-crypto instance, so both the
// native and TS group-engine paths are actually reachable via the kill
// switch - a WasmCrypto/ShimNodeCore node has no validateTransactions/roleOf at all).
// ---------------------------------------------------------------------------

function freshAgent() {
  const secret = Crypto.newRandomAgentSecret();
  const id = Crypto.getAgentID(secret);
  return { secret, id, controlled: new ControlledAgent(secret, Crypto) };
}

function newGroupHighLevelNative() {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  const node = new LocalNode(agentSecret, sessionID, Crypto);
  const group = node.createGroup();
  return { node, group };
}

function createAccountInNodeNative(node: LocalNode) {
  const accountOnTempNode = LocalNode.internalCreateAccount({
    crypto: node.crypto,
  });
  const accountCoreEntry = node.getCoValue(accountOnTempNode.id);
  const content = accountOnTempNode.core.newContentSince(undefined)?.[0]!;
  node.syncManager.handleNewContent(content, "import");
  return new ControlledAccount(
    accountCoreEntry.getCurrentContent() as any,
    accountOnTempNode.core.node.agentSecret,
  );
}

/**
 * Runs `fn` against the group content as authored by `account` (a different
 * account/agent), then imports the resulting session(s) back into `node`.
 * Mirrors the idiom from groupEngineFixtures.export.test.ts.
 */
async function actAs(
  node: LocalNode,
  coId: RawGroup["id"],
  account: ControlledAccount | ControlledAgent,
  fn: (group: RawGroup) => void,
) {
  const core = node.getCoValue(coId);
  const content = await core.contentInClonedNodeWithDifferentAccount(account);
  const group = expectGroup(content);
  fn(group);
  const newContent = group.core.newContentSince(undefined);
  if (newContent) {
    for (const chunk of newContent) {
      node.syncManager.handleNewContent(chunk, "import");
    }
  }
}

/**
 * Same idiom as {@link actAs}, but for an owned RawCoMap rather than a group:
 * runs `fn` against the map's content as authored by `account`, then imports
 * the resulting session(s) back into `node`.
 */
async function actAsOnMap(
  node: LocalNode,
  coId: RawCoMap["id"],
  account: ControlledAccount | ControlledAgent,
  fn: (map: RawCoMap) => void,
) {
  const core = node.getCoValue(coId);
  const content = await core.contentInClonedNodeWithDifferentAccount(account);
  const map = expectMap(content);
  fn(map);
  const newContent = map.core.newContentSince(undefined);
  if (newContent) {
    for (const chunk of newContent) {
      node.syncManager.handleNewContent(chunk, "import");
    }
  }
}

// ---------------------------------------------------------------------------
// Scenario op script: generated up-front from the seeded PRNG so it can be
// logged verbatim as a minimal repro on divergence.
// ---------------------------------------------------------------------------

const ACCOUNT_ROLES: readonly AccountRole[] = [
  "admin",
  "manager",
  "writer",
  "reader",
  "writeOnly",
];
const SETTABLE_ROLES: readonly Role[] = [...ACCOUNT_ROLES, "revoked"];
const CAP_ROLES = ["inherit", "reader", "writer", "manager", "admin"] as const;

type TargetRef = { kind: "member"; idx: number } | { kind: "everyone" };
type AuthorRef = { kind: "admin" } | { kind: "member"; idx: number };
// Owned-map writes additionally allow a "nonMember" author: a fresh agent
// never added to the scenario group, exercising the unauthorized-write path.
type MapAuthorRef = AuthorRef | { kind: "nonMember" };

type OpEntry =
  | { kind: "setRole"; author: AuthorRef; target: TargetRef; role: Role }
  | {
      kind: "invite";
      inviteRole: AccountRole;
      targetIdx: number;
      acceptRole: Role;
    }
  | { kind: "extend"; cap: (typeof CAP_ROLES)[number] }
  | { kind: "revokeExtend" }
  | { kind: "parentSetRole"; targetIdx: number; role: Role }
  // ownedByGroup coverage: create a RawCoMap owned by the scenario's main
  // group (created early, before the random op mix below runs).
  | { kind: "createMap" }
  // A random write to one of the previously-created owned maps, authored by
  // the admin, a random member (whatever role they hold at that point in the
  // script), or a non-member agent. Always a plain `set` — RawCoMap.set()
  // always emits a single non-empty "set" change, so this can never hit the
  // ownedByGroup ruleset's "unmarked" edges (there is no !changes skip in
  // that ruleset, and we never construct tx.meta.branch/ownerId, so the
  // reader branch-pointer trim path is also never exercised here).
  | {
      kind: "mapWrite";
      mapIdx: number;
      author: MapAuthorRef;
      key: string;
      value: number;
    };

function genOpScript(rng: () => number, memberCount: number): OpEntry[] {
  const ops: OpEntry[] = [];

  // Seed every member with an initial role, authored by the top admin.
  for (let idx = 0; idx < memberCount; idx++) {
    ops.push({
      kind: "setRole",
      author: { kind: "admin" },
      target: { kind: "member", idx },
      role: pick(rng, ACCOUNT_ROLES),
    });
  }

  // Create 1-2 owned maps early, before the random op mix below runs, so
  // every mapWrite op below has a guaranteed-existing target.
  const mapCount = randInt(rng, 1, 2);
  for (let i = 0; i < mapCount; i++) {
    ops.push({ kind: "createMap" });
  }

  const extraOps = randInt(rng, 6, 11);
  for (let i = 0; i < extraOps; i++) {
    const r = rng();
    if (r < 0.35) {
      const author: AuthorRef =
        rng() < 0.55
          ? { kind: "admin" }
          : { kind: "member", idx: randInt(rng, 0, memberCount - 1) };
      const target: TargetRef =
        rng() < 0.25
          ? { kind: "everyone" }
          : { kind: "member", idx: randInt(rng, 0, memberCount - 1) };
      ops.push({
        kind: "setRole",
        author,
        target,
        role: pick(rng, SETTABLE_ROLES),
      });
    } else if (r < 0.5) {
      const inviteRole = pick(rng, ACCOUNT_ROLES);
      const mismatch = rng() < 0.3;
      ops.push({
        kind: "invite",
        inviteRole,
        targetIdx: randInt(rng, 0, memberCount - 1),
        acceptRole: mismatch ? pick(rng, ACCOUNT_ROLES) : inviteRole,
      });
    } else if (r < 0.62) {
      ops.push({ kind: "extend", cap: pick(rng, CAP_ROLES) });
    } else if (r < 0.7) {
      ops.push({ kind: "revokeExtend" });
    } else if (r < 0.78) {
      ops.push({
        kind: "parentSetRole",
        targetIdx: randInt(rng, 0, memberCount - 1),
        role: pick(rng, SETTABLE_ROLES),
      });
    } else {
      const authorRoll = rng();
      const author: MapAuthorRef =
        authorRoll < 0.15
          ? { kind: "nonMember" }
          : authorRoll < 0.35
            ? { kind: "admin" }
            : { kind: "member", idx: randInt(rng, 0, memberCount - 1) };
      ops.push({
        kind: "mapWrite",
        mapIdx: randInt(rng, 0, mapCount - 1),
        author,
        key: `k${randInt(rng, 0, 999_999)}`,
        value: randInt(rng, 0, 1000),
      });
    }
  }

  return ops;
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

type Member = { account: ControlledAccount };

type OpScriptResult = { timestamps: number[]; maps: RawCoMap[] };

async function executeOpScript(
  node: LocalNode,
  mainGroup: RawGroup,
  parentGroup: RawGroup,
  members: Member[],
  ops: OpEntry[],
  tick: () => number,
): Promise<OpScriptResult> {
  const timestamps: number[] = [];
  const maps: RawCoMap[] = [];
  let extended = false;

  for (const op of ops) {
    timestamps.push(tick());

    switch (op.kind) {
      case "setRole": {
        const key =
          op.target.kind === "everyone"
            ? EVERYONE
            : members[op.target.idx]!.account.id;
        if (op.author.kind === "admin") {
          (mainGroup.set as any)(key, op.role, "trusting");
        } else {
          await actAs(
            node,
            mainGroup.id,
            members[op.author.idx]!.account,
            (g) => {
              (g.set as any)(key, op.role, "trusting");
            },
          );
        }
        break;
      }
      case "invite": {
        const invite = freshAgent();
        (mainGroup.set as any)(invite.id, `${op.inviteRole}Invite`, "trusting");
        timestamps.push(tick());
        const targetKey = members[op.targetIdx]!.account.id;
        await actAs(node, mainGroup.id, invite.controlled, (g) => {
          (g.set as any)(targetKey, op.acceptRole, "trusting");
        });
        break;
      }
      case "extend": {
        if (op.cap === "inherit") {
          mainGroup.extend(parentGroup);
        } else {
          mainGroup.extend(parentGroup, op.cap);
        }
        extended = true;
        break;
      }
      case "revokeExtend": {
        if (extended) {
          mainGroup.revokeExtend(parentGroup);
          extended = false;
        }
        break;
      }
      case "parentSetRole": {
        const key = members[op.targetIdx]!.account.id;
        (parentGroup.set as any)(key, op.role, "trusting");
        break;
      }
      case "createMap": {
        maps.push(mainGroup.createMap());
        break;
      }
      case "mapWrite": {
        const map = maps[op.mapIdx]!;
        if (op.author.kind === "admin") {
          map.set(op.key, op.value, "trusting");
        } else if (op.author.kind === "member") {
          await actAsOnMap(
            node,
            map.id,
            members[op.author.idx]!.account,
            (m) => {
              m.set(op.key, op.value, "trusting");
            },
          );
        } else {
          const nonMember = freshAgent();
          await actAsOnMap(node, map.id, nonMember.controlled, (m) => {
            m.set(op.key, op.value, "trusting");
          });
        }
        break;
      }
    }
  }

  return { timestamps, maps };
}

// ---------------------------------------------------------------------------
// Snapshotting (verdicts + role-query grid)
// ---------------------------------------------------------------------------

type VerdictSnapshot = { valid: boolean; reason: string | null };

function snapshotVerdicts(
  core: CoValueCore,
  into: Map<string, VerdictSnapshot>,
) {
  core.getValidTransactions({ ignorePrivateTransactions: false });
  for (const t of core.verifiedTransactions) {
    into.set(`${core.id}/${t.currentTxID.sessionID}/${t.currentTxID.txIndex}`, {
      valid: t.isValid,
      reason: t.validationErrorMessage ?? null,
    });
  }
}

function snapshotRoles(
  mainGroup: RawGroup,
  parentGroup: RawGroup,
  subjects: (RawAccountID | AgentID | Everyone)[],
  timestampSamples: number[],
  into: Map<string, Role | null>,
) {
  const atTimes: (number | null)[] = [...timestampSamples, null];
  for (const [label, group] of [
    ["main", mainGroup],
    ["parent", parentGroup],
  ] as const) {
    for (const subject of subjects) {
      for (const atTime of atTimes) {
        // NEVER synthesize atTime=0: TS/native diverge on falsy-0 internally.
        if (atTime === 0) {
          throw new Error("Refusing to query atTime=0 (falsy-0 divergence)");
        }
        const view = atTime === null ? group : group.atTime(atTime);
        into.set(
          `${label}/${subject}/${atTime ?? "latest"}`,
          view.roleOfInternal(subject) ?? null,
        );
      }
    }
  }
}

function snapshotPass(
  mainGroup: RawGroup,
  parentGroup: RawGroup,
  maps: RawCoMap[],
  subjects: (RawAccountID | AgentID | Everyone)[],
  timestampSamples: number[],
) {
  const verdicts = new Map<string, VerdictSnapshot>();
  snapshotVerdicts(mainGroup.core, verdicts);
  snapshotVerdicts(parentGroup.core, verdicts);
  for (const map of maps) {
    snapshotVerdicts(map.core, verdicts);
  }

  const roles = new Map<string, Role | null>();
  snapshotRoles(mainGroup, parentGroup, subjects, timestampSamples, roles);

  return { verdicts, roles };
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

// ~350ms total at N=50 (well under the 60s timeout, ~170x headroom). NOTE if
// you raise N substantially: scenario nodes are not gracefully shut down
// (deliberate — short-lived process), so very large N grows memory.
const N = 50;
const SEED = process.env.DIFF_SEED ? Number(process.env.DIFF_SEED) : 424242;

test(`randomized differential harness: TS vs native group engine (N=${N}, seed=${SEED})`, async () => {
  const rng = mulberry32(SEED);
  let simTime = 1_700_000_000_000;

  // Canary counts across the whole run: proves the owned-map extension
  // genuinely exercises both the authorized and unauthorized write paths
  // (reader/writeOnly-elsewhere/non-member writes), rather than only ever
  // generating trivially-valid ops.
  let totalMapValidVerdicts = 0;
  let totalMapInvalidVerdicts = 0;

  vi.useFakeTimers();
  try {
    for (let scenario = 0; scenario < N; scenario++) {
      const memberCount = randInt(rng, 2, 5);
      const ops = genOpScript(rng, memberCount);

      try {
        const { node, group: mainGroup } = newGroupHighLevelNative();
        const parentGroup = node.createGroup();

        const members: Member[] = [];
        for (let i = 0; i < memberCount; i++) {
          members.push({ account: createAccountInNodeNative(node) });
        }

        const tick = () => {
          // Advance the clock at least 1ms before every operation so we
          // never construct exact cross-session equal-madeAt ties (TS's
          // own tie behavior is arrival-order-dependent and not
          // reproducible across the native/TS split).
          simTime += randInt(rng, 1, 5);
          vi.setSystemTime(simTime);
          return Date.now();
        };

        const { timestamps, maps } = await executeOpScript(
          node,
          mainGroup,
          parentGroup,
          members,
          ops,
          tick,
        );

        const subjects: (RawAccountID | AgentID | Everyone)[] = [
          ...members.map((m) => m.account.id),
          EVERYONE,
        ];
        const timestampSamples = [
          pick(rng, timestamps),
          pick(rng, timestamps),
          pick(rng, timestamps),
        ];

        // (a) native path (default: switch unset)
        const nativePass = snapshotPass(
          mainGroup,
          parentGroup,
          maps,
          subjects,
          timestampSamples,
        );

        const mapIds = new Set(maps.map((m) => m.id as string));
        for (const [key, v] of nativePass.verdicts) {
          if (mapIds.has(key.slice(0, key.indexOf("/")))) {
            if (v.valid) {
              totalMapValidVerdicts++;
            } else {
              totalMapInvalidVerdicts++;
            }
          }
        }

        // (b) TS path: re-validate the SAME already-ingested transactions
        // with the kill switch stubbed on.
        //
        // For the group ruleset, determineValidTransactions and
        // roleOfInternal both recompute from scratch on every call, so no
        // extra revalidation plumbing is needed - just force another pass.
        //
        // For owned maps (ownedByGroup), that is NOT true: the TS fallback
        // iterates coValue.toValidateTransactions, which the wrapper drains
        // to [] after pass (a) ran. Left alone, pass (b) would iterate
        // nothing and silently keep pass (a)'s verdicts for every owned-map
        // tx (see file header). So each map's core must be explicitly reset
        // AFTER stubbing the kill switch on - resetParsedTransactions()
        // repopulates toValidateTransactions and, as a side effect,
        // immediately re-runs determineValidTransactions under the
        // now-active TS path.
        vi.stubEnv("COJSON_DISABLE_NATIVE_VALIDATION", "1");
        let tsPass: typeof nativePass;
        try {
          for (const map of maps) {
            map.core.resetParsedTransactions();
          }
          tsPass = snapshotPass(
            mainGroup,
            parentGroup,
            maps,
            subjects,
            timestampSamples,
          );
        } finally {
          vi.unstubAllEnvs();
        }

        expect(tsPass.verdicts.size).toBe(nativePass.verdicts.size);
        for (const [key, nativeVerdict] of nativePass.verdicts) {
          const tsVerdict = tsPass.verdicts.get(key);
          if (
            !tsVerdict ||
            tsVerdict.valid !== nativeVerdict.valid ||
            tsVerdict.reason !== nativeVerdict.reason
          ) {
            throw new Error(
              `Verdict divergence at key ${key}: native=${JSON.stringify(
                nativeVerdict,
              )} ts=${JSON.stringify(tsVerdict ?? null)}`,
            );
          }
        }

        expect(tsPass.roles.size).toBe(nativePass.roles.size);
        for (const [key, nativeRole] of nativePass.roles) {
          const tsRole = tsPass.roles.get(key);
          if (tsRole !== nativeRole) {
            throw new Error(
              `Role-query divergence at key ${key}: native=${JSON.stringify(
                nativeRole,
              )} ts=${JSON.stringify(tsRole)}`,
            );
          }
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        throw new Error(
          `[groupEngineDifferential] divergence in scenario #${scenario} ` +
            `(seed=${SEED}, memberCount=${memberCount}). ` +
            `Repro: DIFF_SEED=${SEED} pnpm test groupEngineDifferential\n` +
            `opScript=${JSON.stringify(ops)}\n${message}`,
        );
      }
    }
  } finally {
    vi.useRealTimers();
  }

  // Canary: make sure the owned-map extension actually generated both valid
  // and invalid map writes across the run (not just always-valid admin
  // writes) - otherwise the verdict-equality checks above would be trivially
  // satisfied without exercising the unauthorized-write path at all.
  expect(totalMapValidVerdicts).toBeGreaterThan(0);
  expect(totalMapInvalidVerdicts).toBeGreaterThan(0);
}, 60_000);
