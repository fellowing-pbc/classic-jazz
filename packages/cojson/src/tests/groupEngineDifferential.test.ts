/**
 * Randomized differential harness: TS group-permission engine vs native NodeCore.
 *
 * Builds N random group scenarios (native crypto, native validation enabled by
 * default), snapshots verdicts + role queries, then flips the
 * `COJSON_DISABLE_NATIVE_VALIDATION` kill switch on and forces a second
 * validation pass over the SAME already-ingested transactions (both
 * `determineValidTransactions` and `RawGroup#roleOfInternal` recompute from
 * scratch on every call - see permissions.ts/group.ts - so no extra plumbing
 * is needed to force a revalidation), and asserts the two passes agree.
 *
 * Seed is logged on failure and overridable via DIFF_SEED so a divergence can
 * be reproduced deterministically. Reproduction is STRUCTURAL, not bitwise:
 * the seed drives op structure and time ordering, but account/session IDs come
 * from real crypto randomness — fine because the harness deliberately avoids
 * ID-ordering-sensitive constructions (see tick()).
 */
import { expect, test, vi } from "vitest";
import {
  ControlledAccount,
  ControlledAgent,
  type RawAccountID,
} from "../coValues/account.js";
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
  | { kind: "parentSetRole"; targetIdx: number; role: Role };

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

  const extraOps = randInt(rng, 6, 11);
  for (let i = 0; i < extraOps; i++) {
    const r = rng();
    if (r < 0.45) {
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
    } else if (r < 0.65) {
      const inviteRole = pick(rng, ACCOUNT_ROLES);
      const mismatch = rng() < 0.3;
      ops.push({
        kind: "invite",
        inviteRole,
        targetIdx: randInt(rng, 0, memberCount - 1),
        acceptRole: mismatch ? pick(rng, ACCOUNT_ROLES) : inviteRole,
      });
    } else if (r < 0.8) {
      ops.push({ kind: "extend", cap: pick(rng, CAP_ROLES) });
    } else if (r < 0.9) {
      ops.push({ kind: "revokeExtend" });
    } else {
      ops.push({
        kind: "parentSetRole",
        targetIdx: randInt(rng, 0, memberCount - 1),
        role: pick(rng, SETTABLE_ROLES),
      });
    }
  }

  return ops;
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

type Member = { account: ControlledAccount };

async function executeOpScript(
  node: LocalNode,
  mainGroup: RawGroup,
  parentGroup: RawGroup,
  members: Member[],
  ops: OpEntry[],
  tick: () => number,
): Promise<number[]> {
  const timestamps: number[] = [];
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
    }
  }

  return timestamps;
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
  subjects: (RawAccountID | AgentID | Everyone)[],
  timestampSamples: number[],
) {
  const verdicts = new Map<string, VerdictSnapshot>();
  snapshotVerdicts(mainGroup.core, verdicts);
  snapshotVerdicts(parentGroup.core, verdicts);

  const roles = new Map<string, Role | null>();
  snapshotRoles(mainGroup, parentGroup, subjects, timestampSamples, roles);

  return { verdicts, roles };
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

// ~270ms total at N=50 (well under the 60s timeout, ~200x headroom). NOTE if
// you raise N substantially: scenario nodes are not gracefully shut down
// (deliberate — short-lived process), so very large N grows memory.
const N = 50;
const SEED = process.env.DIFF_SEED ? Number(process.env.DIFF_SEED) : 424242;

test(`randomized differential harness: TS vs native group engine (N=${N}, seed=${SEED})`, async () => {
  const rng = mulberry32(SEED);
  let simTime = 1_700_000_000_000;

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

        const timestamps = await executeOpScript(
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
          subjects,
          timestampSamples,
        );

        // (b) TS path: re-validate the SAME already-ingested transactions
        // with the kill switch stubbed on. determineValidTransactions and
        // roleOfInternal both recompute from scratch on every call, so no
        // extra revalidation plumbing is needed - just force another pass.
        vi.stubEnv("COJSON_DISABLE_NATIVE_VALIDATION", "1");
        let tsPass: typeof nativePass;
        try {
          tsPass = snapshotPass(
            mainGroup,
            parentGroup,
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
}, 60_000);
