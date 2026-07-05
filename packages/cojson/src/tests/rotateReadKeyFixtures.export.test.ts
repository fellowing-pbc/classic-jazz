/**
 * rotateReadKey fixture exporter.
 *
 * Builds real cojson groups via the public API, then calls `RawGroup.rotateReadKey`
 * with `newRandomKeySecret` stubbed to fixed (but valid) keys and every `group.set`
 * captured, producing a golden record of the EXACT ordered `(field, value)` writes
 * TS's rotation performs. The native `rotate_read_key` (crates/cojson-core) is
 * replayed against the captured inputs and must reproduce these writes byte-for-byte.
 *
 * When `EXPORT_ROTATE_READ_KEY_FIXTURES=1` the fixtures are written to
 * `crates/cojson-core/data/group_key_rotation/<scenario>.json`. Regardless of
 * export, the suite asserts internal consistency so it has value in CI.
 *
 * Determinism note: the injected key secrets are captured into the fixture, so the
 * committed golden files are self-describing — Rust replays whatever keys TS used.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import type { KeyID, KeySecret } from "../crypto/crypto.js";
import { RawGroup } from "../coValues/group.js";
import { createAccountInNode, newGroupHighLevel } from "./testUtils.js";

const EXPORT = process.env.EXPORT_ROTATE_READ_KEY_FIXTURES === "1";
const OUT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/cojson-core/data/group_key_rotation",
);

type KeyPairFixture = { id: string; secret: string };
type MemberFixture = { memberKey: string; agentSealerId: string };
type ParentFixture = { readKeyId: string; readKeySecret: string };
type WriteFixture = { field: string; value: string };

type TriggerFixture =
  | { kind: "rotate" }
  | { kind: "removeEveryone" }
  | { kind: "removeMember"; member: string };

type RotateFixture = {
  description: string;
  trigger: TriggerFixture;
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

/** roles that `rotateReadKey` treats as fresh-writeOnly-key recipients. */
function isWriteOnlyRole(role: unknown): boolean {
  return role === "writeOnly" || role === "writeOnlyInvite";
}

/**
 * Capture a rotateReadKey run into a fixture.
 *
 * `removedMemberKey` mirrors the optional arg of rotateReadKey. The group's
 * snapshot / member resolution / start-tx-index are all taken immediately before
 * the rotation, so the fixture reflects the exact state the write path reads.
 */
function captureRotation(
  description: string,
  group: RawGroup,
  removedMemberKey: string | undefined,
  trigger: TriggerFixture,
): RotateFixture {
  const node = group.core.node;
  const crypto = node.crypto;

  // --- resolve members (getMemberKeys order) + their sealer ids -----------
  const memberKeys = group.getMemberKeys();
  const members: MemberFixture[] = memberKeys.map((mk) => {
    const agent = node.resolveAccountAgent(mk, "member").value;
    if (!agent) throw new Error(`could not resolve agent for ${mk}`);
    return { memberKey: mk, agentSealerId: crypto.getAgentSealerID(agent) };
  });

  // --- resolve parents (getParentGroups order) with their read keys -------
  const parents: ParentFixture[] = group.getParentGroups().map((p) => {
    const { id, secret } = p.getCurrentReadKey();
    if (!secret) throw new Error(`no read key secret for parent ${p.id}`);
    return { readKeyId: id, readKeySecret: secret };
  });

  // --- current read key ----------------------------------------------------
  const cur = group.getCurrentReadKey();
  if (!cur.secret) throw new Error("no current read key secret");
  const currentReadKey = { id: cur.id, secret: cur.secret };

  // --- how many writeOnly members will get a fresh key --------------------
  const writeOnlyCount = memberKeys.filter(
    (mk) => mk !== removedMemberKey && isWriteOnlyRole(group.get(mk)),
  ).length;

  // --- pre-generate fixed keys: [newReadKey, ...writeOnlyKeys] -------------
  const injected: { id: KeyID; secret: KeySecret }[] = [];
  for (let i = 0; i < 1 + writeOnlyCount; i++) {
    injected.push(crypto.newRandomKeySecret());
  }
  const newReadKey = { id: injected[0]!.id, secret: injected[0]!.secret };
  const writeOnlyFreshKeys: KeyPairFixture[] = injected
    .slice(1)
    .map((k) => ({ id: k.id, secret: k.secret }));

  // --- snapshot the group state BEFORE rotation ---------------------------
  const snapshot = group.asObject() as Record<string, unknown>;

  const fromSealerSecret = node.getCurrentAgent().currentSealerSecret();
  const groupId = group.id;
  const sessionId = node.currentSessionID;
  const startTxIndex = group.core.nextTransactionID().txIndex;

  // --- install stubs: fixed keys + capture every set ----------------------
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
    group.rotateReadKey(removedMemberKey as any);
  } finally {
    (crypto as any).newRandomKeySecret = origNewRandomKeySecret;
    delete (group as any).set;
  }

  return {
    description,
    trigger,
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

function writeFixture(name: string, fixture: RotateFixture) {
  // Internal consistency: rotation always writes readKey + groupSealer + old_for_new.
  const fieldSet = new Set(fixture.expectedWrites.map((w) => w.field));
  expect(fieldSet.has("readKey")).toBe(true);
  expect(fieldSet.has("groupSealer")).toBe(true);
  expect(fixture.expectedWrites.some((w) => w.field.includes("_for_"))).toBe(
    true,
  );
  // Every writeOnly fresh key must be paired with a writeKeyFor_ write.
  expect(
    fixture.expectedWrites.filter((w) => w.field.startsWith("writeKeyFor_"))
      .length,
  ).toBe(fixture.writeOnlyFreshKeys.length);

  if (EXPORT) {
    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(
      join(OUT_DIR, `${name}.json`),
      JSON.stringify(fixture, null, 2),
    );
  }
}

describe("rotateReadKey fixtures", () => {
  test("readers_only: admin + reader + writer", () => {
    const { node, group } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    const writer = createAccountInNode(node);
    group.addMember(reader, "reader" as any);
    group.addMember(writer, "writer" as any);

    const fixture = captureRotation(
      "Plain rotation of a group with admin(self) + reader + writer members; " +
        "all three re-revealed to, then old_for_new + readKey + groupSealer.",
      group,
      undefined,
      { kind: "rotate" },
    );
    writeFixture("readers_only", fixture);
  });

  test("remove_member: reader removed is excluded from re-reveal", () => {
    const { node, group } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    const writer = createAccountInNode(node);
    group.addMember(reader, "reader" as any);
    group.addMember(writer, "writer" as any);

    const fixture = captureRotation(
      "rotateReadKey(reader): the removed reader still carries its 'reader' role " +
        "in the pre-rotate snapshot but must NOT be re-revealed to.",
      group,
      reader.id,
      { kind: "removeMember", member: reader.id },
    );
    writeFixture("remove_member", fixture);
  });

  test("write_only: admin + writeOnly member", () => {
    const { node, group } = newGroupHighLevel();
    const writeOnly = createAccountInNode(node);
    group.addMember(writeOnly, "writeOnly" as any);

    const fixture = captureRotation(
      "Rotation with a writeOnly member: the member gets a fresh writeOnly key " +
        "(revealed to self + writeKeyFor_ + revealed to the admin reader).",
      group,
      undefined,
      { kind: "rotate" },
    );
    writeFixture("write_only", fixture);
  });

  test("with_parent: child rotation reveals new key to parent", () => {
    const { node, group: child } = newGroupHighLevel();
    const reader = createAccountInNode(node);
    child.addMember(reader, "reader" as any);

    // Parent group in the SAME node → current account is admin of both, so the
    // standard (account-member) parent-reveal path is taken.
    const parent = node.createGroup();
    child.extend(parent);

    const fixture = captureRotation(
      "Rotation of a child group extended to a parent: the new read key is " +
        "re-revealed to the parent read key via encryptKeySecret (standard path).",
      child,
      undefined,
      { kind: "rotate" },
    );
    writeFixture("with_parent", fixture);
  });
});
