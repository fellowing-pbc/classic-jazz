/**
 * Representative, hand-built scenarios for the identity-resolution harness.
 *
 * Everything is derived from FIXED secret seeds so two runs (and the committed
 * golden) are byte-identical. No production code path is modified — the builders
 * only call `resolveAccountAgent`, `accountOrAgentIDfromSessionID`,
 * `internalCreateAccount`, and `createCoValue` (to materialize crafted headers),
 * then normalize the REAL outputs.
 *
 * Coverage:
 *   resolution cases —
 *     1. agent-ID session: `resolveAccountAgent(agentID)` short-circuits to itself
 *     2. account session: `resolveAccountAgent(accountID)` -> `ruleset.initialAdmin`
 *     3. plain group (meta not "account") -> not_account
 *     4. ownedByGroup comap (ruleset not "group") -> not_account
 *     5. malformed admin (account-shaped, initialAdmin not an agent) -> not_account
 *     6. unavailable (id never loaded) -> unavailable
 *   session-id cases — account / agent / delete-session string shapes
 *   bootstrap trace — the deterministic `internalCreateAccount` write sequence
 */
import { base58 } from "@scure/base";
import { RawCoMap } from "../../coValues/coMap.js";
import {
  accountHeaderForInitialAgentSecret,
  type RawAccount,
  type RawAccountID,
} from "../../coValues/account.js";
import { idforHeader } from "../../coValueCore/coValueCore.js";
import type { CoValueHeader } from "../../coValueCore/verifiedState.js";
import type { AgentID } from "../../ids.js";
import { LocalNode } from "../../localNode.js";
import { WasmCrypto } from "../../crypto/WasmCrypto.js";
import {
  type BootstrapTrace,
  type BootstrapWrite,
  classifyResolution,
  type ResolutionCase,
  type SessionIdCase,
} from "./harness.js";

const Crypto = await WasmCrypto.create();

/** A 32-byte fixed secret seed filled with `byte` (deterministic identities). */
function fixedSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

function seedHex(seed: Uint8Array): string {
  return Array.from(seed, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A throwaway node used only to materialize crafted headers and resolve ids.
 *  Its own (random) agent never appears in any captured output. */
function throwawayNode(): LocalNode {
  const agentSecret = Crypto.newRandomAgentSecret();
  const sessionID = Crypto.newRandomSessionID(Crypto.getAgentID(agentSecret));
  return new LocalNode(agentSecret, sessionID, Crypto);
}

const ACCOUNT_SEED = fixedSeed(7);
const AGENT_SEED = fixedSeed(19);
const UNAVAILABLE_SEED = fixedSeed(31);

/** Build the six `resolveAccountAgent` differential cases. */
export async function buildResolutionCases(): Promise<ResolutionCase[]> {
  const node = throwawayNode();
  try {
    const cases: ResolutionCase[] = [];

    // 1. agent-ID session: resolveAccountAgent(agentID) short-circuits.
    const agentSecret = Crypto.agentSecretFromSecretSeed(AGENT_SEED);
    const agentId = Crypto.getAgentID(agentSecret);
    cases.push({
      description:
        "agent-ID session: resolveAccountAgent(agentID) returns the agent id " +
        "itself with no covalue lookup",
      id: agentId,
      available: false,
      header: null,
      expected: classifyResolution(node.resolveAccountAgent(agentId, "agent")),
    });

    // 2. account session: resolveAccountAgent(accountID) -> ruleset.initialAdmin.
    const accountAgentSecret = Crypto.agentSecretFromSecretSeed(ACCOUNT_SEED);
    const accountHeader = accountHeaderForInitialAgentSecret(
      accountAgentSecret,
      Crypto,
    );
    const accountCore = node.createCoValue(accountHeader);
    cases.push({
      description:
        "account session: resolveAccountAgent(accountID) reads the account " +
        "header's ruleset.initialAdmin and returns that agent id",
      id: accountCore.id,
      available: true,
      header: accountCore.verified.header,
      expected: classifyResolution(
        node.resolveAccountAgent(accountCore.id as RawAccountID, "account"),
      ),
    });

    // 3. plain group (meta not "account") -> not_account.
    const plainGroupHeader: CoValueHeader = {
      type: "comap",
      ruleset: { type: "group", initialAdmin: agentId },
      meta: null,
      createdAt: null,
      uniqueness: null,
    };
    const plainGroupCore = node.createCoValue(plainGroupHeader);
    cases.push({
      description:
        "plain group (valid group ruleset but meta is not { type: 'account' }) " +
        "-> not_account",
      id: plainGroupCore.id,
      available: true,
      header: plainGroupCore.verified.header,
      expected: classifyResolution(
        node.resolveAccountAgent(
          plainGroupCore.id as RawAccountID,
          "plain group",
        ),
      ),
    });

    // 4. ownedByGroup comap (ruleset not "group") -> not_account.
    const ownedHeader: CoValueHeader = {
      type: "comap",
      ruleset: {
        type: "ownedByGroup",
        group: plainGroupCore.id,
      },
      meta: { type: "account" },
      createdAt: null,
      uniqueness: null,
    };
    const ownedCore = node.createCoValue(ownedHeader);
    cases.push({
      description:
        "ownedByGroup comap (account-looking meta but ruleset.type is not " +
        "'group') -> not_account",
      id: ownedCore.id,
      available: true,
      header: ownedCore.verified.header,
      expected: classifyResolution(
        node.resolveAccountAgent(
          ownedCore.id as RawAccountID,
          "owned by group",
        ),
      ),
    });

    // 5. malformed admin: account-shaped, but initialAdmin is not an agent id.
    const malformedHeader: CoValueHeader = {
      type: "comap",
      ruleset: {
        type: "group",
        initialAdmin: plainGroupCore.id as unknown as AgentID,
      },
      meta: { type: "account" },
      createdAt: null,
      uniqueness: null,
    };
    const malformedCore = node.createCoValue(malformedHeader);
    cases.push({
      description:
        "malformed admin: comap + group ruleset + account meta, but " +
        "ruleset.initialAdmin is a co id (not an agent id) -> not_account",
      id: malformedCore.id,
      available: true,
      header: malformedCore.verified.header,
      expected: classifyResolution(
        node.resolveAccountAgent(
          malformedCore.id as RawAccountID,
          "malformed admin",
        ),
      ),
    });

    // 6. unavailable: a well-formed account id that was never loaded.
    const unavailableSecret =
      Crypto.agentSecretFromSecretSeed(UNAVAILABLE_SEED);
    const unavailableId = idforHeader(
      accountHeaderForInitialAgentSecret(unavailableSecret, Crypto),
      Crypto,
    );
    cases.push({
      description:
        "unavailable: resolveAccountAgent on an account id that was never " +
        "loaded surfaces expectCoValueLoaded's error -> unavailable",
      id: unavailableId,
      available: false,
      header: null,
      expected: classifyResolution(
        node.resolveAccountAgent(unavailableId as RawAccountID, "unavailable"),
      ),
    });

    return cases;
  } finally {
    await node.gracefulShutdown();
  }
}

/** Build the `accountOrAgentIDfromSessionID` string-lens differential cases. */
export function buildSessionIdCases(): SessionIdCase[] {
  const accountAgentSecret = Crypto.agentSecretFromSecretSeed(ACCOUNT_SEED);
  const accountId = idforHeader(
    accountHeaderForInitialAgentSecret(accountAgentSecret, Crypto),
    Crypto,
  );
  const agentSecret = Crypto.agentSecretFromSecretSeed(AGENT_SEED);
  const agentId = Crypto.getAgentID(agentSecret);

  // Deterministic session ids (fixed random-part suffixes) covering the three
  // shapes `accountOrAgentIDfromSessionID` must slice: account session, agent
  // session, and delete session (whose "_session_d…$" still contains "_session").
  const specs: { description: string; sessionId: string }[] = [
    {
      description: "account session id -> account id",
      sessionId: `${accountId}_session_zFIXEDSESSION1`,
    },
    {
      description:
        "agent session id (agent id contains a '/') -> agent id, sliced " +
        "at the first '_session'",
      sessionId: `${agentId}_session_zFIXEDSESSION2`,
    },
    {
      description:
        "delete session id ('_session_d…$') -> account id (still contains " +
        "'_session')",
      sessionId: `${accountId}_session_dFIXEDDELETE$`,
    },
  ];

  // Derive expected by REPLICATING the exact production slice logic so the
  // fixture's `expected` is the ground truth the native replay must reproduce.
  return specs.map(({ description, sessionId }) => {
    const until = sessionId.indexOf("_session");
    return { description, sessionId, expected: sessionId.slice(0, until) };
  });
}

/**
 * Capture the deterministic `internalCreateAccount` bootstrap as an ordered
 * `(field, value)` write trace.
 *
 * The single source of randomness inside the bootstrap is `newRandomKeySecret`
 * (the read key); we inject a fixed key (captured into the fixture) exactly as
 * the `rotateReadKey` oracle does, and intercept `RawCoMap.prototype.set` for the
 * duration to record the ordered writes. `seal` is deterministic given fixed
 * inputs, so the sealed read-key write is stable too. The temp node is shut down
 * afterwards.
 */
export async function buildBootstrapTrace(): Promise<BootstrapTrace> {
  const agentSecret = Crypto.agentSecretFromSecretSeed(ACCOUNT_SEED);
  const agentId = Crypto.getAgentID(agentSecret);
  const accountId = idforHeader(
    accountHeaderForInitialAgentSecret(agentSecret, Crypto),
    Crypto,
  );

  // A FIXED read key (deterministic bytes) in the exact shape `newRandomKeySecret`
  // produces (`keySecret_z` + base58(32), `key_z` + base58(12)). Injecting a fixed
  // key — rather than the random one — is what makes the bootstrap trace (and its
  // deterministic sealed write) reproducible across runs; the key is captured into
  // the fixture so the golden stays self-describing.
  const fixedKey = {
    secret: `keySecret_z${base58.encode(new Uint8Array(32).fill(3))}`,
    id: `key_z${base58.encode(new Uint8Array(12).fill(5))}`,
  } as ReturnType<typeof Crypto.newRandomKeySecret>;
  const writes: BootstrapWrite[] = [];

  const origNewRandomKeySecret = Crypto.newRandomKeySecret.bind(Crypto);
  const origNewRandomSessionID = Crypto.newRandomSessionID.bind(Crypto);
  const origSet = RawCoMap.prototype.set;
  let account: RawAccount;
  try {
    (
      Crypto as { newRandomKeySecret: () => typeof fixedKey }
    ).newRandomKeySecret = () => fixedKey;
    // Pin the session id: the sealed read-key write's nonce is derived from the
    // account's next TransactionID, which embeds the session id — a random one
    // would make the sealed value differ run-to-run. accountId is deterministic.
    (
      Crypto as {
        newRandomSessionID: typeof origNewRandomSessionID;
      }
    ).newRandomSessionID = ((
      id: Parameters<typeof origNewRandomSessionID>[0],
    ) => `${id}_session_zFIXEDBOOTSTRAP`) as typeof origNewRandomSessionID;
    RawCoMap.prototype.set = function patchedSet(
      this: RawCoMap,
      key: string,
      value: unknown,
      privacy?: "private" | "trusting",
    ) {
      // The bootstrap only ever writes to the account map it just created.
      writes.push({ field: String(key), value: value as string });
      return (origSet as (...a: unknown[]) => void).call(
        this,
        key,
        value,
        privacy,
      );
    } as typeof RawCoMap.prototype.set;

    account = LocalNode.internalCreateAccount({
      crypto: Crypto,
      initialAgentSecret: agentSecret,
    });
  } finally {
    RawCoMap.prototype.set = origSet;
    (
      Crypto as { newRandomKeySecret: typeof origNewRandomKeySecret }
    ).newRandomKeySecret = origNewRandomKeySecret;
    (
      Crypto as { newRandomSessionID: typeof origNewRandomSessionID }
    ).newRandomSessionID = origNewRandomSessionID;
  }

  try {
    return {
      description:
        "internalCreateAccount bootstrap: set(agentID, 'admin') -> " +
        "set(<readKeyId>_for_<agentID>, sealed) -> set('readKey', <readKeyId>)",
      secretSeed: seedHex(ACCOUNT_SEED),
      agentSecret,
      agentId,
      accountId,
      readKey: { id: fixedKey.id, secret: fixedKey.secret },
      writes,
    };
  } finally {
    await account.core.node.gracefulShutdown();
  }
}
