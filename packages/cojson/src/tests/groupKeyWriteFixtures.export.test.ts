/**
 * addMemberInternal / createInvite / extend / removeMember fixture exporter.
 *
 * Builds real cojson groups via the public API, then drives the group membership /
 * extend / remove write paths with `newRandomKeySecret` stubbed to fixed (but valid)
 * keys and every `group.set` captured, producing a golden record of the EXACT ordered
 * `(field, value)` writes TS performs. The native `add_member_internal`, `extend` and
 * `remove_member` (crates/cojson-core) are replayed against the captured inputs and
 * must reproduce these writes byte-for-byte.
 *
 * When `EXPORT_GROUP_KEY_WRITE_FIXTURES=1` the fixtures are written under
 * `crates/cojson-core/data/group_key_membership/` and `.../group_key_extend/`.
 * Regardless of export, the suite asserts internal consistency so it has CI value.
 *
 * The branches the native port handles are captured here (see the module scope
 * note in group_key_membership.rs): reader-class adds, fresh writeOnly adds, invite
 * adds, everyone->reader, the writeOnly demotion of a reader (which rotates the read
 * key first), the everyone->writeOnly path (which rotates then deletes the plaintext
 * reveal), standard-path extend, and admin removeMember.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import type { KeyID, KeySecret } from "../crypto/crypto.js";
import type { RawGroup } from "../coValues/group.js";
import { createAccountInNode, newGroupHighLevel } from "./testUtils.js";

const EXPORT = process.env.EXPORT_GROUP_KEY_WRITE_FIXTURES === "1";
const CRATE_DATA = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data",
);
const MEMBERSHIP_DIR = join(CRATE_DATA, "group_key_membership");
const EXTEND_DIR = join(CRATE_DATA, "group_key_extend");

type KeyPairFixture = { id: string; secret: string };
type MemberFixture = { memberKey: string; agentSealerId: string };
type ParentFixture = { readKeyId: string; readKeySecret: string };
type WriteFixture = { field: string; value: string };
/** A set OR delete op, in program order. `op` defaults to "set". */
type MutationFixture = { field: string; value?: string; op?: "set" | "del" };

/** Resolve every member key (getMemberKeys order) to its sealer id. */
function resolveMembers(group: RawGroup): MemberFixture[] {
  const node = group.core.node;
  const crypto = node.crypto;
  return group.getMemberKeys().map((mk) => {
    const agent = node.resolveAccountAgent(mk, "member").value;
    if (!agent) throw new Error(`could not resolve agent for ${mk}`);
    return { memberKey: mk, agentSealerId: crypto.getAgentSealerID(agent) };
  });
}

/** Resolve every parent group (getParentGroups order) to its current read key. */
function resolveParents(group: RawGroup): ParentFixture[] {
  return group.getParentGroups().map((p) => {
    const { id, secret } = p.getCurrentReadKey();
    if (!secret) throw new Error(`no read key secret for parent ${p.id}`);
    return { readKeyId: id, readKeySecret: secret };
  });
}

/** getWriteOnlyKeys() (ops insertion order) resolved to (id, secret). */
function resolveWriteOnlyKeys(group: RawGroup): KeyPairFixture[] {
  const out: KeyPairFixture[] = [];
  for (const key of group.keys()) {
    if (key.startsWith("writeKeyFor_")) {
      const id = group.get(key) as KeyID;
      const secret = group.core.getReadKey(id);
      if (!secret) throw new Error(`no secret for writeOnly key ${id}`);
      out.push({ id, secret });
    }
  }
  return out;
}

// --------------------------------------------------------------------------
// addMemberInternal / createInvite capture
// --------------------------------------------------------------------------

type AddFixture = {
  description: string;
  groupId: string;
  sessionId: string;
  startTxIndex: number;
  memberKey: string;
  memberAgentSealerId: string;
  role: string;
  fromSealerSecret: string;
  currentReadKey: KeyPairFixture;
  existingWriteOnlyKeys: KeyPairFixture[];
  freshWriteOnlyKey: KeyPairFixture | null;
  /** Present only for a writeOnly demotion of a reader-class member (the preceding
   * rotateReadKey's fresh read key + any rotation writeOnly keys). */
  rotationNewReadKey?: KeyPairFixture | null;
  rotationWriteOnlyFreshKeys?: KeyPairFixture[];
  members: MemberFixture[];
  parents: ParentFixture[];
  snapshot: Record<string, unknown>;
  expectedWrites: WriteFixture[];
};

function captureAdd(
  description: string,
  group: RawGroup,
  account: any,
  memberKey: string,
  memberAgentSealerId: string,
  role: string,
  expectedFreshKeys: number,
): AddFixture {
  const node = group.core.node;
  const crypto = node.crypto;

  const members = resolveMembers(group);
  const parents = resolveParents(group);
  const existingWriteOnlyKeys = resolveWriteOnlyKeys(group);
  const cur = group.getCurrentReadKey();
  if (!cur.secret) throw new Error("no current read key secret");
  const currentReadKey = { id: cur.id, secret: cur.secret };

  const injected: { id: KeyID; secret: KeySecret }[] = [];
  for (let i = 0; i < expectedFreshKeys; i++) {
    injected.push(crypto.newRandomKeySecret());
  }
  const freshWriteOnlyKey =
    injected.length > 0
      ? { id: injected[0]!.id, secret: injected[0]!.secret }
      : null;

  const snapshot = group.asObject() as Record<string, unknown>;
  const fromSealerSecret = node.getCurrentAgent().currentSealerSecret();
  const groupId = group.id;
  const sessionId = node.currentSessionID;
  const startTxIndex = group.core.nextTransactionID().txIndex;

  let injIdx = 0;
  const origNewRandomKeySecret = crypto.newRandomKeySecret.bind(crypto);
  (crypto as any).newRandomKeySecret = () => {
    const k = injected[injIdx++];
    if (!k) throw new Error("more newRandomKeySecret calls than expected");
    return k;
  };

  const expectedWrites: WriteFixture[] = [];
  const origSet = group.set.bind(group);
  (group as any).set = (key: string, value: unknown, privacy: unknown) => {
    expectedWrites.push({ field: String(key), value: value as string });
    return (origSet as any)(key, value, privacy);
  };

  try {
    group.addMemberInternal(account as any, role as any);
  } finally {
    (crypto as any).newRandomKeySecret = origNewRandomKeySecret;
    delete (group as any).set;
  }

  return {
    description,
    groupId,
    sessionId,
    startTxIndex,
    memberKey,
    memberAgentSealerId,
    role,
    fromSealerSecret,
    currentReadKey,
    existingWriteOnlyKeys,
    freshWriteOnlyKey,
    members,
    parents,
    snapshot,
    expectedWrites,
  };
}

function writeAddFixture(name: string, fx: AddFixture) {
  // A non-no-op add always writes the member's role first.
  expect(fx.expectedWrites.length).toBeGreaterThan(0);
  expect(fx.expectedWrites[0]!.field).toBe(fx.memberKey);
  if (EXPORT) {
    mkdirSync(MEMBERSHIP_DIR, { recursive: true });
    writeFileSync(
      join(MEMBERSHIP_DIR, `${name}.json`),
      JSON.stringify(fx, null, 2),
    );
  }
}

function writeDemotionFixture(name: string, fx: AddFixture) {
  // A demotion rotates FIRST, so the member's own role set is NOT the first write;
  // it appears later with value "writeOnly", and the first write is a rotation reveal.
  expect(fx.expectedWrites[0]!.field).not.toBe(fx.memberKey);
  expect(fx.expectedWrites[0]!.field).toContain("_for_");
  expect(
    fx.expectedWrites.some(
      (w) => w.field === fx.memberKey && w.value === "writeOnly",
    ),
  ).toBe(true);
  // Rotation must have produced the standard tail.
  const fieldSet = new Set(fx.expectedWrites.map((w) => w.field));
  expect(fieldSet.has("readKey")).toBe(true);
  expect(fieldSet.has("groupSealer")).toBe(true);
  if (EXPORT) {
    mkdirSync(MEMBERSHIP_DIR, { recursive: true });
    writeFileSync(
      join(MEMBERSHIP_DIR, `${name}.json`),
      JSON.stringify(fx, null, 2),
    );
  }
}

/**
 * Capture the writeOnly *demotion of a reader-class member*: TS first calls
 * `rotateReadKey(memberKey)` (excluding the member), THEN `set(memberKey,writeOnly)`
 * + the writeOnly-grant. The injected keys are, in order,
 * `[rotationNewReadKey, ...rotationWriteOnlyFreshKeys, demotedMemberFreshKey]`.
 */
function captureDemotion(
  description: string,
  group: RawGroup,
  account: any,
  memberKey: string,
  memberAgentSealerId: string,
): AddFixture {
  const node = group.core.node;
  const crypto = node.crypto;

  const members = resolveMembers(group);
  const parents = resolveParents(group);
  const existingWriteOnlyKeys = resolveWriteOnlyKeys(group);
  const cur = group.getCurrentReadKey();
  if (!cur.secret) throw new Error("no current read key secret");
  const currentReadKey = { id: cur.id, secret: cur.secret };

  // The preceding rotation re-keys every OTHER writeOnly member.
  const rotationWriteOnlyCount = group
    .getMemberKeys()
    .filter((mk) => mk !== memberKey && isWriteOnlyRole(group.get(mk))).length;

  // injected = [newReadKey, ...rotationWriteOnlyKeys, demotedFreshKey]
  const injected: { id: KeyID; secret: KeySecret }[] = [];
  for (let i = 0; i < 1 + rotationWriteOnlyCount + 1; i++) {
    injected.push(crypto.newRandomKeySecret());
  }
  const rotationNewReadKey = {
    id: injected[0]!.id,
    secret: injected[0]!.secret,
  };
  const rotationWriteOnlyFreshKeys = injected
    .slice(1, 1 + rotationWriteOnlyCount)
    .map((k) => ({ id: k.id, secret: k.secret }));
  const demoted = injected[1 + rotationWriteOnlyCount]!;
  const freshWriteOnlyKey = { id: demoted.id, secret: demoted.secret };

  const snapshot = group.asObject() as Record<string, unknown>;
  const fromSealerSecret = node.getCurrentAgent().currentSealerSecret();
  const groupId = group.id;
  const sessionId = node.currentSessionID;
  const startTxIndex = group.core.nextTransactionID().txIndex;

  let injIdx = 0;
  const origNewRandomKeySecret = crypto.newRandomKeySecret.bind(crypto);
  (crypto as any).newRandomKeySecret = () => {
    const k = injected[injIdx++];
    if (!k) throw new Error("more newRandomKeySecret calls than expected");
    return k;
  };

  const expectedWrites: WriteFixture[] = [];
  const origSet = group.set.bind(group);
  (group as any).set = (key: string, value: unknown, privacy: unknown) => {
    expectedWrites.push({ field: String(key), value: value as string });
    return (origSet as any)(key, value, privacy);
  };

  try {
    group.addMemberInternal(account as any, "writeOnly" as any);
  } finally {
    (crypto as any).newRandomKeySecret = origNewRandomKeySecret;
    delete (group as any).set;
  }

  return {
    description,
    groupId,
    sessionId,
    startTxIndex,
    memberKey,
    memberAgentSealerId,
    role: "writeOnly",
    fromSealerSecret,
    currentReadKey,
    existingWriteOnlyKeys,
    freshWriteOnlyKey,
    rotationNewReadKey,
    rotationWriteOnlyFreshKeys,
    members,
    parents,
    snapshot,
    expectedWrites,
  };
}

// --------------------------------------------------------------------------
// everyone -> writeOnly capture (rotate then delete; captures set AND del ops)
// --------------------------------------------------------------------------

type EveryoneWriteOnlyFixture = {
  description: string;
  groupId: string;
  sessionId: string;
  startTxIndex: number;
  fromSealerSecret: string;
  currentReadKey: KeyPairFixture;
  rotationNewReadKey: KeyPairFixture | null;
  rotationWriteOnlyFreshKeys: KeyPairFixture[];
  members: MemberFixture[];
  parents: ParentFixture[];
  snapshot: Record<string, unknown>;
  /** ordered set/del ops */
  expectedWrites: MutationFixture[];
};

function captureEveryoneWriteOnly(
  description: string,
  group: RawGroup,
): EveryoneWriteOnlyFixture {
  const node = group.core.node;
  const crypto = node.crypto;

  const members = resolveMembers(group);
  const parents = resolveParents(group);
  const cur = group.getCurrentReadKey();
  if (!cur.secret) throw new Error("no current read key secret");
  const currentReadKey = { id: cur.id, secret: cur.secret };

  // Demoting everyone (reader/writer) rotates: newReadKey + one key per writeOnly
  // member. everyone->writeOnly does NOT mint a per-member writeOnly key.
  const rotationWriteOnlyCount = group
    .getMemberKeys()
    .filter((mk) => isWriteOnlyRole(group.get(mk))).length;

  const injected: { id: KeyID; secret: KeySecret }[] = [];
  for (let i = 0; i < 1 + rotationWriteOnlyCount; i++) {
    injected.push(crypto.newRandomKeySecret());
  }
  const rotationNewReadKey = {
    id: injected[0]!.id,
    secret: injected[0]!.secret,
  };
  const rotationWriteOnlyFreshKeys = injected
    .slice(1)
    .map((k) => ({ id: k.id, secret: k.secret }));

  const snapshot = group.asObject() as Record<string, unknown>;
  const fromSealerSecret = node.getCurrentAgent().currentSealerSecret();
  const groupId = group.id;
  const sessionId = node.currentSessionID;
  const startTxIndex = group.core.nextTransactionID().txIndex;

  let injIdx = 0;
  const origNewRandomKeySecret = crypto.newRandomKeySecret.bind(crypto);
  (crypto as any).newRandomKeySecret = () => {
    const k = injected[injIdx++];
    if (!k) throw new Error("more newRandomKeySecret calls than expected");
    return k;
  };

  const expectedWrites: MutationFixture[] = [];
  const origSet = group.set.bind(group);
  (group as any).set = (key: string, value: unknown, privacy: unknown) => {
    expectedWrites.push({
      field: String(key),
      value: value as string,
      op: "set",
    });
    return (origSet as any)(key, value, privacy);
  };
  const origDelete = group.delete.bind(group);
  (group as any).delete = (key: string, privacy: unknown) => {
    expectedWrites.push({ field: String(key), op: "del" });
    return (origDelete as any)(key, privacy);
  };

  try {
    group.addMemberInternal("everyone" as any, "writeOnly" as any);
  } finally {
    (crypto as any).newRandomKeySecret = origNewRandomKeySecret;
    delete (group as any).set;
    delete (group as any).delete;
  }

  return {
    description,
    groupId,
    sessionId,
    startTxIndex,
    fromSealerSecret,
    currentReadKey,
    rotationNewReadKey,
    rotationWriteOnlyFreshKeys,
    members,
    parents,
    snapshot,
    expectedWrites,
  };
}

function writeEveryoneWriteOnlyFixture(
  name: string,
  fx: EveryoneWriteOnlyFixture,
) {
  // set(everyone,writeOnly) is first; a del of `${readKey}_for_everyone` is last.
  expect(fx.expectedWrites[0]).toEqual({
    field: "everyone",
    value: "writeOnly",
    op: "set",
  });
  const last = fx.expectedWrites[fx.expectedWrites.length - 1]!;
  expect(last.op).toBe("del");
  expect(last.field).toBe(`${fx.currentReadKey.id}_for_everyone`);
  if (EXPORT) {
    mkdirSync(MEMBERSHIP_DIR, { recursive: true });
    writeFileSync(
      join(MEMBERSHIP_DIR, `${name}.json`),
      JSON.stringify(fx, null, 2),
    );
  }
}

// --------------------------------------------------------------------------
// extend capture
// --------------------------------------------------------------------------

type ExtendFixture = {
  description: string;
  parentId: string;
  parentRefValue: string;
  parent: ParentFixture;
  childReadKey: KeyPairFixture;
  writeOnlyKeys: KeyPairFixture[];
  expectedWrites: WriteFixture[];
};

function captureExtend(
  description: string,
  child: RawGroup,
  parent: RawGroup,
  parentRefValue: string,
): ExtendFixture {
  const p = parent.getCurrentReadKey();
  if (!p.secret) throw new Error("no parent read key secret");
  const cur = child.getCurrentReadKey();
  if (!cur.secret) throw new Error("no child read key secret");
  const writeOnlyKeys = resolveWriteOnlyKeys(child);

  const expectedWrites: WriteFixture[] = [];
  const origSet = child.set.bind(child);
  (child as any).set = (key: string, value: unknown, privacy: unknown) => {
    expectedWrites.push({ field: String(key), value: value as string });
    return (origSet as any)(key, value, privacy);
  };
  try {
    child.extend(parent);
  } finally {
    delete (child as any).set;
  }

  return {
    description,
    parentId: parent.id,
    parentRefValue,
    parent: { readKeyId: p.id, readKeySecret: p.secret },
    childReadKey: { id: cur.id, secret: cur.secret },
    writeOnlyKeys,
    expectedWrites,
  };
}

function writeExtendFixture(name: string, fx: ExtendFixture) {
  expect(fx.expectedWrites[0]!.field).toBe(`parent_${fx.parentId}`);
  expect(fx.expectedWrites.some((w) => w.field.includes("_for_"))).toBe(true);
  if (EXPORT) {
    mkdirSync(EXTEND_DIR, { recursive: true });
    writeFileSync(
      join(EXTEND_DIR, `${name}.json`),
      JSON.stringify(fx, null, 2),
    );
  }
}

// --------------------------------------------------------------------------
// removeMember capture (rotation inputs + trailing revoked write)
// --------------------------------------------------------------------------

type RemoveFixture = {
  description: string;
  memberKey: string;
  callerIsAdminOrManager: boolean;
  groupId: string;
  sessionId: string;
  startTxIndex: number;
  fromSealerSecret: string;
  currentReadKey: KeyPairFixture;
  newReadKey: KeyPairFixture;
  members: MemberFixture[];
  writeOnlyFreshKeys: KeyPairFixture[];
  parents: ParentFixture[];
  snapshot: Record<string, unknown>;
  expectedWrites: WriteFixture[];
};

function isWriteOnlyRole(role: unknown): boolean {
  return role === "writeOnly" || role === "writeOnlyInvite";
}

function captureRemove(
  description: string,
  group: RawGroup,
  memberKey: string,
): RemoveFixture {
  const node = group.core.node;
  const crypto = node.crypto;

  const members = resolveMembers(group);
  const parents = resolveParents(group);
  const cur = group.getCurrentReadKey();
  if (!cur.secret) throw new Error("no current read key secret");
  const currentReadKey = { id: cur.id, secret: cur.secret };

  const writeOnlyCount = group
    .getMemberKeys()
    .filter((mk) => mk !== memberKey && isWriteOnlyRole(group.get(mk))).length;

  const injected: { id: KeyID; secret: KeySecret }[] = [];
  for (let i = 0; i < 1 + writeOnlyCount; i++) {
    injected.push(crypto.newRandomKeySecret());
  }
  const newReadKey = { id: injected[0]!.id, secret: injected[0]!.secret };
  const writeOnlyFreshKeys = injected
    .slice(1)
    .map((k) => ({ id: k.id, secret: k.secret }));

  const snapshot = group.asObject() as Record<string, unknown>;
  const fromSealerSecret = node.getCurrentAgent().currentSealerSecret();
  const groupId = group.id;
  const sessionId = node.currentSessionID;
  const startTxIndex = group.core.nextTransactionID().txIndex;

  let injIdx = 0;
  const origNewRandomKeySecret = crypto.newRandomKeySecret.bind(crypto);
  (crypto as any).newRandomKeySecret = () => {
    const k = injected[injIdx++];
    if (!k) throw new Error("more newRandomKeySecret calls than expected");
    return k;
  };

  const expectedWrites: WriteFixture[] = [];
  const origSet = group.set.bind(group);
  (group as any).set = (key: string, value: unknown, privacy: unknown) => {
    expectedWrites.push({ field: String(key), value: value as string });
    return (origSet as any)(key, value, privacy);
  };

  try {
    group.removeMember(memberKey as any);
  } finally {
    (crypto as any).newRandomKeySecret = origNewRandomKeySecret;
    delete (group as any).set;
  }

  return {
    description,
    memberKey,
    callerIsAdminOrManager: true,
    groupId,
    sessionId,
    startTxIndex,
    fromSealerSecret,
    currentReadKey,
    newReadKey,
    members,
    writeOnlyFreshKeys,
    parents,
    snapshot,
    expectedWrites,
  };
}

function writeRemoveFixture(name: string, fx: RemoveFixture) {
  const last = fx.expectedWrites[fx.expectedWrites.length - 1]!;
  expect(last.field).toBe(fx.memberKey);
  expect(last.value).toBe("revoked");
  if (EXPORT) {
    mkdirSync(MEMBERSHIP_DIR, { recursive: true });
    writeFileSync(
      join(MEMBERSHIP_DIR, `${name}.json`),
      JSON.stringify(fx, null, 2),
    );
  }
}

// --------------------------------------------------------------------------
// scenarios
// --------------------------------------------------------------------------

describe("group key write fixtures", () => {
  test("add_reader: fresh reader gets the read key revealed", () => {
    const { node, group } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    const sealerId = node.crypto.getAgentSealerID(
      node.resolveAccountAgent(reader.id, "reader").value!,
    );
    const fx = captureAdd(
      "Add a fresh reader: set role then reveal the current read key to them.",
      group,
      reader,
      reader.id,
      sealerId,
      "reader",
      0,
    );
    writeAddFixture("add_reader", fx);
  });

  test("add_writer_with_existing_writeonly: writer also gets existing writeOnly keys", () => {
    const { node, group } = newGroupHighLevel();
    const writeOnly = createAccountInNode(node);
    group.addMember(writeOnly, "writeOnly" as any);
    const writer = createAccountInNode(node);
    const sealerId = node.crypto.getAgentSealerID(
      node.resolveAccountAgent(writer.id, "writer").value!,
    );
    const fx = captureAdd(
      "Add a writer to a group that already has a writeOnly member: the writer is " +
        "revealed the read key AND every existing writeOnly key.",
      group,
      writer,
      writer.id,
      sealerId,
      "writer",
      0,
    );
    writeAddFixture("add_writer_with_existing_writeonly", fx);
  });

  test("add_write_only: fresh writeOnly member gets a dedicated key", () => {
    const { node, group } = newGroupHighLevel();
    const writeOnly = createAccountInNode(node);
    const sealerId = node.crypto.getAgentSealerID(
      node.resolveAccountAgent(writeOnly.id, "writeOnly").value!,
    );
    const fx = captureAdd(
      "Add a fresh writeOnly member: set role, create writeKeyFor_, reveal the " +
        "dedicated key to self and to the admin reader.",
      group,
      writeOnly,
      writeOnly.id,
      sealerId,
      "writeOnly",
      1,
    );
    writeAddFixture("add_write_only", fx);
  });

  test("create_invite_reader: readerInvite for an agent id", () => {
    const { node, group } = newGroupHighLevel();
    const secretSeed = node.crypto.newRandomSecretSeed();
    const inviteSecret = node.crypto.agentSecretFromSecretSeed(secretSeed);
    const inviteID = node.crypto.getAgentID(inviteSecret);
    const sealerId = node.crypto.getAgentSealerID(inviteID);
    const fx = captureAdd(
      "createInvite('reader') delegates to addMemberInternal(inviteAgentID, " +
        "'readerInvite'): set role + reveal the read key to the invite agent.",
      group,
      inviteID,
      inviteID,
      sealerId,
      "readerInvite",
      0,
    );
    writeAddFixture("create_invite_reader", fx);
  });

  test("everyone_reader: read key revealed to everyone in plaintext", () => {
    const { group } = newGroupHighLevel();
    const fx = captureAdd(
      "addMember(everyone, 'reader'): set everyone=reader then store the read key " +
        "secret in plaintext under `${readKey}_for_everyone`.",
      group,
      "everyone",
      "everyone",
      "",
      "reader",
      0,
    );
    writeAddFixture("everyone_reader", fx);
  });

  test("write_only_demotion: reader demoted to writeOnly rotates then grants", () => {
    const { node, group } = newGroupHighLevel();
    const member = createAccountInNode(node);
    group.addMember(member, "reader" as any);
    const sealerId = node.crypto.getAgentSealerID(
      node.resolveAccountAgent(member.id, "member").value!,
    );
    const fx = captureDemotion(
      "Demote an existing reader to writeOnly: rotateReadKey(member) re-reveals the " +
        "new read key to the remaining readers (member excluded), then set(member," +
        "writeOnly) + writeKeyFor_ + reveal the fresh writeOnly key to self and readers.",
      group,
      member,
      member.id,
      sealerId,
    );
    writeDemotionFixture("write_only_demotion", fx);
  });

  test("everyone_write_only: demote everyone from reader rotates then deletes", () => {
    const { group } = newGroupHighLevel();
    group.addMember("everyone" as any, "reader" as any);
    const fx = captureEveryoneWriteOnly(
      "addMember(everyone,'writeOnly') after everyone was a reader: set everyone=" +
        "writeOnly, rotateReadKey('everyone') (RemoveEveryone bypasses the guard), " +
        "then delete `${readKey}_for_everyone` (the plaintext reveal).",
      group,
    );
    writeEveryoneWriteOnlyFixture("everyone_write_only", fx);
  });

  test("extend_basic: child extended to a parent reveals its read key", () => {
    const { node, group: child } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    child.addMember(reader, "reader" as any);
    const parent = node.createGroup();
    const fx = captureExtend(
      "extend(parent): set parent_<id>='extend' then reveal the child read key to " +
        "the parent read key via encryptKeySecret (standard/account-member path).",
      child,
      parent,
      "extend",
    );
    writeExtendFixture("extend_basic", fx);
  });

  test("extend_with_writeonly: extend also reveals writeOnly keys to the parent", () => {
    const { node, group: child } = newGroupHighLevel();
    const writeOnly = createAccountInNode(node);
    child.addMember(writeOnly, "writeOnly" as any);
    const parent = node.createGroup();
    const fx = captureExtend(
      "extend(parent) with a writeOnly member: revealAllWriteOnlyKeys reveals the " +
        "child read key AND each writeOnly key to the parent read key.",
      child,
      parent,
      "extend",
    );
    writeExtendFixture("extend_with_writeonly", fx);
  });

  test("remove_reader: rotate excluding the member, then revoke", () => {
    const { node, group } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    const writer = createAccountInNode(node);
    group.addMember(reader, "reader" as any);
    group.addMember(writer, "writer" as any);
    const fx = captureRemove(
      "removeMember(reader): admin rotates the read key (reader excluded from " +
        "re-reveal), then sets the reader's role to 'revoked'.",
      group,
      reader.id,
    );
    writeRemoveFixture("remove_reader", fx);
  });
});
