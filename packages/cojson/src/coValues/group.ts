import { base58 } from "@scure/base";
import type { CoID } from "../coValue.js";
import type {
  AvailableCoValueCore,
  CoValueCore,
  DecryptedTransaction,
} from "../coValueCore/coValueCore.js";
import {
  isNativeCoMapMaterializationEnabled,
  isNativeGroupKeyWritesEnabled,
} from "../coValueCore/coValueCore.js";
import type { CoValueUniqueness } from "../coValueCore/verifiedState.js";
import type {
  CryptoProvider,
  Encrypted,
  KeyID,
  KeySecret,
  Sealed,
  SealedForGroup,
  SealerID,
  SealerSecret,
} from "../crypto/crypto.js";
import {
  AgentID,
  ChildGroupReference,
  ParentGroupReference,
  getParentGroupId,
  isAgentID,
  isParentGroupReference,
} from "../ids.js";
import { JsonObject, JsonValue } from "../jsonValue.js";
import { logger } from "../logger.js";
import {
  AccountRole,
  Role,
  isAccountRole,
  isKeyForKeyField,
} from "../permissions.js";
import { accountOrAgentIDfromSessionID } from "../typeUtils/accountOrAgentIDfromSessionID.js";
import { expectGroup } from "../typeUtils/expectGroup.js";
import { isAccountID } from "../typeUtils/isAccountID.js";
import {
  ControlledAccountOrAgent,
  RawAccount,
  RawAccountID,
} from "./account.js";
import { RawCoList } from "./coList.js";
import { RawCoMap } from "./coMap.js";
import { RawCoPlainText } from "./coPlainText.js";
import { RawBinaryCoStream } from "./binaryCoStream.js";
import { RawCoStream } from "./coStream.js";

export const EVERYONE = "everyone" as const;
export type Everyone = "everyone";

/**
 * Format a composite groupSealer value that includes the readKeyID.
 * New format: "readKeyID@sealerID" - explicitly associates the sealer with
 * the readKey it was derived from. This prevents inconsistency when different
 * admins concurrently rotate keys and migrate the groupSealer.
 *
 * @internal
 */
export function formatGroupSealerValue(readKeyID: KeyID, sealerID: SealerID) {
  return `${readKeyID}@${sealerID}` as const;
}

/**
 * Extract the SealerID from a groupSealer field value.
 * Handles both new format ("readKeyID@sealerID") and legacy format ("sealer_z...").
 *
 * @internal
 */
function extractSealerID(groupSealerValue: string): SealerID {
  const idx = groupSealerValue.indexOf("@");
  if (idx > 0) {
    return groupSealerValue.substring(idx + 1) as SealerID;
  }
  return groupSealerValue as SealerID;
}

/**
 * Extract the readKeyID from a groupSealer field value.
 * Returns undefined for legacy format values that don't include the readKeyID.
 *
 * @internal
 */
function extractReadKeyID(groupSealerValue: string): KeyID | undefined {
  const idx = groupSealerValue.indexOf("@");
  if (idx > 0) {
    return groupSealerValue.substring(0, idx) as KeyID;
  }
  return undefined;
}

export type ParentGroupReferenceRole =
  | "revoked"
  | "extend"
  | "reader"
  | "writer"
  | "manager"
  | "admin";

export type GroupShape = {
  profile: CoID<RawCoMap> | null;
  root: CoID<RawCoMap> | null;
  [key: RawAccountID | AgentID]: Role;
  [EVERYONE]?: Role;
  readKey?: KeyID;
  // Group-level asymmetric encryption key (public portion only)
  // Private key is derived from readKey, not stored
  groupSealer?: `${KeyID}@${SealerID}`;
  [writeKeyFor: `writeKeyFor_${RawAccountID | AgentID}`]: KeyID;
  [revelationFor: `${KeyID}_for_${RawAccountID | AgentID}`]: Sealed<KeySecret>;
  [revelationFor: `${KeyID}_for_${Everyone}`]: KeySecret;
  [oldKeyForNewKey: `${KeyID}_for_${KeyID}`]: Encrypted<
    KeySecret,
    { encryptedID: KeyID; encryptingID: KeyID }
  >;
  // Key revelations encrypted to group sealer (from non-members extending child groups)
  // Using _sealedFor_ prefix to distinguish from _for_ patterns used for member/key revelations
  [keyForSealer: `${KeyID}_sealedFor_${SealerID}`]: SealedForGroup<KeySecret>;
  [parent: ParentGroupReference]: ParentGroupReferenceRole;
  [child: ChildGroupReference]: "revoked" | "extend";
};

// We had a bug on key rotation, where the new read key was not revealed to everyone
// TODO: remove this when we hit the 0.18.0 release (either the groups are healed or they are not used often, it's a minor issue anyway)
function healMissingKeyForEveryone(group: RawGroup) {
  const readKeyId = group.get("readKey");

  if (
    !readKeyId ||
    !canRead(group, EVERYONE) ||
    group.get(`${readKeyId}_for_${EVERYONE}`)
  ) {
    return;
  }

  const hasAccessToReadKey = canRead(
    group,
    group.core.node.getCurrentAgent().id,
  );

  // If the current account has access to the read key, we can fix the group
  if (hasAccessToReadKey) {
    const secret = group.getReadKey(readKeyId);
    if (secret) {
      group.set(`${readKeyId}_for_${EVERYONE}`, secret, "trusting");
    }
    return;
  }

  // Fallback to the latest readable key for everyone
  const keys = group
    .keys()
    .filter((key) => key.startsWith("key_") && key.endsWith("_for_everyone"));

  let latestKey = keys[0];

  for (const key of keys) {
    if (!latestKey) {
      latestKey = key;
      continue;
    }

    const keyEntry = group.getRaw(key);
    const latestKeyEntry = group.getRaw(latestKey);

    if (keyEntry && latestKeyEntry && keyEntry.madeAt > latestKeyEntry.madeAt) {
      latestKey = key;
    }
  }

  if (latestKey) {
    group._lastReadableKeyId = latestKey.replace("_for_everyone", "") as KeyID;
  }
}

/**
 * Backfill the groupSealer field for groups created before the feature was introduced.
 * Since the groupSealer is derived deterministically from the readKey, parallel migrations
 * from different accounts will always produce the same value.
 *
 * Only admins/managers can set the groupSealer field.
 */
function healMissingGroupSealer(group: RawGroup) {
  if (group.get("groupSealer")) {
    return;
  }

  // Check direct membership only (not inherited roles via parent groups)
  // to avoid accessing parentGroupsChanges which may not be initialized during early construction
  const currentAccountOrAgent = group.core.node.getCurrentAccountOrAgentID();
  const directRole = group.get(currentAccountOrAgent);
  if (directRole !== "admin" && directRole !== "manager") {
    return;
  }

  const readKeyId = group.get("readKey");
  if (!readKeyId) {
    return;
  }

  const readKeySecret = group.getReadKey(readKeyId);
  if (!readKeySecret) {
    return;
  }

  const groupSealer =
    group.core.node.crypto.groupSealerFromReadKey(readKeySecret);
  group.set(
    "groupSealer",
    formatGroupSealerValue(readKeyId, groupSealer.publicKey),
    "trusting",
  );
}

function needsKeyRotation(group: RawGroup) {
  const myRole = group.myRole();

  // Checking only direct membership because inside the migrations we can't navigate the parent groups
  if (myRole !== "admin" && myRole !== "manager") {
    return false;
  }

  const currentReadKeyId = group.get("readKey");

  if (!currentReadKeyId) {
    return false;
  }

  for (const parentGroup of group.getParentGroups()) {
    const parentReadKeyId = parentGroup.get("readKey");

    if (!parentReadKeyId) {
      continue;
    }

    const hasKeyRevelation = group.get(
      `${currentReadKeyId}_for_${parentReadKeyId}`,
    );

    if (!hasKeyRevelation) {
      return true;
    }
  }

  return false;
}

function rotateReadKeyIfNeeded(group: RawGroup) {
  if (needsKeyRotation(group)) {
    group.rotateReadKey();
  }
}

class TimeBasedEntry<T> {
  changes: { madeAt: number; value: T }[] = [];

  addChange(madeAt: number, value: T) {
    const changes = this.changes;
    const newChange = { madeAt, value };
    // Insert the change in chronological order
    // Find the correct position by searching backwards from the end
    let insertIndex = changes.length;
    while (insertIndex > 0 && changes[insertIndex - 1]!.madeAt > madeAt) {
      insertIndex--;
    }

    // Insert at the correct position to maintain chronological order
    if (insertIndex === changes.length) {
      changes.push(newChange);
    } else {
      changes.splice(insertIndex, 0, newChange);
    }
  }

  getLatest() {
    return this.changes[this.changes.length - 1]?.value;
  }

  getAtTime(atTime?: number) {
    if (atTime === undefined) {
      return this.getLatest();
    }

    return this.changes.findLast((change) => change.madeAt <= atTime)?.value;
  }
}

/** A `Group` is a scope for permissions of its members (`"reader" | "writer" | "admin"`), applying to objects owned by that group.
 *
 *  A `Group` object exposes methods for permission management and allows you to create new CoValues owned by that group.
 *
 *  (Internally, a `Group` is also just a `CoMap`, mapping member accounts to roles and containing some
 *  state management for making cryptographic keys available to current members)
 *
 *  @example
 *  You typically get a group from a CoValue that you already have loaded:
 *
 *  ```typescript
 *  const group = coMap.group;
 *  ```
 *
 *  @example
 *  Or, you can create a new group with a `LocalNode`:
 *
 *  ```typescript
 *  const localNode.createGroup();
 *  ```
 * */
export class RawGroup<
  Meta extends JsonObject | null = JsonObject | null,
> extends RawCoMap<GroupShape, Meta> {
  protected readonly crypto: CryptoProvider;

  _lastReadableKeyId?: KeyID;

  // Not using class field initializers because they run after that the CoMap constructor
  // calls processNewTransactions, which would reset the parentGroupsChanges map
  private declare parentGroupsChanges: Map<
    CoID<RawGroup>,
    TimeBasedEntry<ParentGroupReferenceRole>
  >;

  // Cache for key-for-key revelations: maps encrypted keyID to set of encrypting keyIDs
  // This avoids iterating through all keys in getUncachedReadKey and findValidParentKeys
  private declare keyRevelations: Map<KeyID, Set<KeyID>>;

  protected resetInternalState() {
    super.resetInternalState();
    this.parentGroupsChanges = new Map();
    this.keyRevelations = new Map();
    this._lastReadableKeyId = undefined;
  }

  constructor(
    core: AvailableCoValueCore,
    options?: {
      ignorePrivateTransactions: boolean;
    },
  ) {
    super(core, options);
    this.crypto = core.node.crypto;
    this.migrate();
  }

  // We override the handleNewTransaction hook from CoMap to build the parent group cache
  // and key revelations cache
  override handleNewTransaction(transaction: DecryptedTransaction): void {
    if (!this.parentGroupsChanges) {
      this.parentGroupsChanges = new Map();
    }
    if (!this.keyRevelations) {
      this.keyRevelations = new Map();
    }
    // Build caches incrementally
    for (const changeValue of transaction.changes) {
      const change = changeValue as {
        op: "set" | "del";
        key: string;
        value?: any;
      };
      if (change.op === "set") {
        if (isParentGroupReference(change.key)) {
          this.updateParentGroupCache(
            change.key,
            change.value as ParentGroupReferenceRole,
            transaction.madeAt,
          );
        } else if (isKeyForKeyField(change.key)) {
          this.updateKeyRevelationsCache(change.key);
        }
      }
    }
  }

  private updateKeyRevelationsCache(key: string): void {
    // Key format: key_encryptedID_for_key_encryptingID
    const parts = key.split("_for_");
    if (parts.length === 2) {
      const encryptedKeyID = parts[0] as KeyID;
      const encryptingKeyID = parts[1] as KeyID;

      let revelations = this.keyRevelations.get(encryptedKeyID);
      if (!revelations) {
        revelations = new Set();
        this.keyRevelations.set(encryptedKeyID, revelations);
      }
      revelations.add(encryptingKeyID);
    }
  }

  private updateParentGroupCache(
    key: string,
    value: any,
    timestamp: number,
  ): void {
    const parentGroupId = key.substring(7) as CoID<RawGroup>; // Remove 'parent_' prefix

    let entry = this.parentGroupsChanges.get(parentGroupId);
    if (!entry) {
      entry = new TimeBasedEntry<ParentGroupReferenceRole>();
      this.parentGroupsChanges.set(parentGroupId, entry);
    }

    entry.addChange(timestamp, value as ParentGroupReferenceRole);
  }

  migrate() {
    if (!this.core.isGroup()) {
      return;
    }

    const runMigrations = () => {
      // rotateReadKeyIfNeeded(this);
      healMissingKeyForEveryone(this);
      healMissingGroupSealer(this);
    };

    // We need the group and their parents to be completely downloaded to correctly handle the migrations
    if (!this.core.isCompletelyDownloaded()) {
      this.core.waitFor({
        predicate: (core) => core.isCompletelyDownloaded(),
        onSuccess: runMigrations,
      });
    } else {
      runMigrations();
    }
  }

  /**
   * Optional display name set at group creation. Immutable; stored in plaintext in header meta.
   */
  get name(): string | undefined {
    return (this.headerMeta as { name?: string } | null)?.name;
  }

  /**
   * Returns the current role of a given account.
   *
   * @category 1. Role reading
   */
  roleOf(accountID: RawAccountID | typeof EVERYONE): Role | undefined {
    return this.roleOfInternal(accountID);
  }

  /**
   *  This is a performance-critical function, micro-optimizing it is important
   *
   *  Avoid to add objects/array allocations in this function
   */
  /** @internal */
  roleOfInternal(
    accountID: RawAccountID | AgentID | typeof EVERYONE,
  ): Role | undefined {
    // Delegate read-side role resolution to the native NodeCore. The native
    // implementation covers the full read semantics (direct role, parent-group
    // inheritance, everyone fallback, RawAccount self→admin) and only models an
    // `atTime` view, so this TS body survives ONLY for branch/frontier views
    // that the native side has no equivalent of (stage 2 keeps those on the TS
    // path). Do NOT collapse the two view checks into `!this.isTimeTravelEntity()`:
    // that would also block plain `atTime` views — which native DOES support
    // (passed as the third arg below) — and it doesn't cover branchSourceId.
    const nodeCore = this.core.node.nodeCore;
    if (
      this.core.verified.branchSourceId === undefined &&
      this.atFrontierFilter === undefined
    ) {
      const role = nodeCore.roleOf(this.core.id, accountID, this.atTimeFilter);
      return role as Role | undefined;
    }

    let roleHere = this.get(accountID);

    if (roleHere === "revoked") {
      roleHere = undefined;
    }

    let roleInfo: Role | undefined = roleHere;

    for (const [parentGroupId, entry] of this.parentGroupsChanges.entries()) {
      const role = entry.getAtTime(this.atTimeFilter);

      if (!role || role === "revoked") continue;

      const parentGroup = this.getParentGroup(parentGroupId, this.atTimeFilter);
      const parentRole = parentGroup.roleOfInternal(accountID);

      if (!isInheritableRole(parentRole)) {
        continue;
      }

      const roleToInherit = role !== "extend" ? role : parentRole;

      if (isMorePermissiveAndShouldInherit(roleToInherit, roleInfo)) {
        roleInfo = roleToInherit;
      }
    }

    if (!roleInfo && accountID !== "everyone") {
      const everyoneRole = this.get("everyone");

      if (everyoneRole && everyoneRole !== "revoked") return everyoneRole;
    }

    return roleInfo;
  }

  getParentGroup(id: CoID<RawGroup>, atTime?: number) {
    const parent = this.core.node.expectCoValueLoaded(
      id,
      "Expected parent group to be loaded",
    );

    const group = expectGroup(parent.getCurrentContent());

    if (atTime) {
      return group.atTime(atTime);
    } else {
      return group;
    }
  }

  getParentGroups() {
    const groups: RawGroup[] = [];

    for (const [parentGroupId, entry] of this.parentGroupsChanges.entries()) {
      const role = entry.getAtTime(this.atTimeFilter);

      if (!role || role === "revoked") continue;

      groups.push(this.getParentGroup(parentGroupId, this.atTimeFilter));
    }

    return groups;
  }

  forEachChildGroup(callback: (child: RawGroup) => void) {
    // When rotating the parent key, all the child groups loaded in memory rotate their key.
    // The unloaded child groups will be rotated when they are loaded, by checking if their key has been revealed to the latest parent readKey.
    for (const id of this.core.dependant) {
      const dependant = this.core.node.getCoValue(id);

      if (!dependant.isGroup()) {
        continue;
      }

      const childGroup = expectGroup(dependant.getCurrentContent());
      const reference = childGroup.get(`parent_${this.id}`);

      if (reference && reference !== "revoked") {
        callback(childGroup);
      }
    }
  }

  /**
   * Returns the role of the current account in the group.
   *
   * @category 1. Role reading
   */
  myRole(): Role | undefined {
    return this.roleOfInternal(this.core.node.getCurrentAccountOrAgentID());
  }

  /**
   * Directly grants a new member a role in the group. The current account must be an
   * admin to be able to do so. Throws otherwise.
   *
   * @category 2. Role changing
   */
  addMember(
    account: RawAccount | ControlledAccountOrAgent | Everyone,
    role: Role,
  ) {
    this.addMemberInternal(account, role);
  }

  /** @internal */
  addMemberInternal(
    account: RawAccount | ControlledAccountOrAgent | AgentID | Everyone,
    role: Role,
  ) {
    const memberKey = typeof account === "string" ? account : account.id;
    const previousRole = this.get(memberKey);

    // if the role is the same, we don't need to do anything
    if (previousRole === role) {
      return;
    }

    if (
      this.useNativeGroupKeyWrites() &&
      this.tryAddMemberInternalNative(account, role, memberKey, previousRole)
    ) {
      return;
    }

    if (memberKey === EVERYONE) {
      if (!(role === "reader" || role === "writer" || role === "writeOnly")) {
        throw new Error(
          "Can't make everyone something other than reader, writer or writeOnly",
        );
      }
      const currentReadKey = this.getCurrentReadKey();

      if (!currentReadKey.secret) {
        throw new Error("Can't add member without read key secret");
      }

      const previousRole = this.get(memberKey);

      this.set(memberKey, role, "trusting");

      if (this.get(memberKey) !== role) {
        throw new Error(
          `Failed to set role ${role} to ${memberKey} (role of current account is ${this.myRole()})`,
        );
      }

      if (role === "writeOnly") {
        if (previousRole === "reader" || previousRole === "writer") {
          this.rotateReadKey("everyone");
        }

        this.delete(`${currentReadKey.id}_for_${EVERYONE}`);
      } else {
        this.set(
          `${currentReadKey.id}_for_${EVERYONE}`,
          currentReadKey.secret,
          "trusting",
        );
      }

      return;
    }

    const agent =
      typeof account === "string" ? account : account.currentAgentID();

    if (agent === EVERYONE) {
      throw new Error("Agent should not be everyone");
    }

    /**
     * WriteOnly members can only see their own changes.
     *
     * We don't want to reveal the readKey to them so we create a new one specifically for them
     * and also reveal it to everyone else with a reader or higher-capability role
     * (but crucially not to other writer-only members).
     *
     * To never reveal the readKey to writeOnly members we also create a dedicated writeKey for the
     * invite.
     */
    if (role === "writeOnly" || role === "writeOnlyInvite") {
      if (
        previousRole === "reader" ||
        previousRole === "writer" ||
        previousRole === "manager" ||
        previousRole === "admin"
      ) {
        this.rotateReadKey(memberKey);
      }

      this.set(memberKey, role, "trusting");

      if (this.get(memberKey) !== role) {
        throw new Error(
          `Failed to set role ${role} to ${memberKey} (role of current account is ${this.myRole()})`,
        );
      }

      this.internalCreateWriteOnlyKeyForMember(memberKey, agent);
    } else {
      const currentReadKey = this.getCurrentReadKey();

      if (!currentReadKey.secret) {
        throw new Error("Can't add member without read key secret");
      }

      this.set(memberKey, role, "trusting");

      if (this.get(memberKey) !== role) {
        throw new Error(
          `Failed to set role ${role} to ${memberKey} (role of current account is ${this.myRole()})`,
        );
      }

      this.storeKeyRevelationForMember(
        memberKey,
        agent,
        currentReadKey.id,
        currentReadKey.secret,
      );

      for (const keyID of this.getWriteOnlyKeys()) {
        const secret = this.core.getReadKey(keyID);

        if (!secret) {
          logger.error("Can't find key " + keyID);
          continue;
        }

        this.storeKeyRevelationForMember(memberKey, agent, keyID, secret);
      }
    }
  }

  private internalCreateWriteOnlyKeyForMember(
    memberKey: RawAccountID | AgentID,
    agent: AgentID,
  ): KeyID {
    const writeKeyForNewMember = this.crypto.newRandomKeySecret();

    this.set(`writeKeyFor_${memberKey}`, writeKeyForNewMember.id, "trusting");

    this.storeKeyRevelationForMember(
      memberKey,
      agent,
      writeKeyForNewMember.id,
      writeKeyForNewMember.secret,
    );

    // Reveal the new writeOnly key to Account members
    for (const otherMemberKey of this.getMemberKeys()) {
      const memberRole = this.get(otherMemberKey);

      if (
        memberRole === "reader" ||
        memberRole === "writer" ||
        memberRole === "admin" ||
        memberRole === "manager" ||
        memberRole === "readerInvite" ||
        memberRole === "writerInvite" ||
        memberRole === "adminInvite"
      ) {
        const otherMemberAgent = this.core.node.resolveAccountAgent(
          otherMemberKey,
          "Expected member agent to be loaded",
        ).value;

        if (!otherMemberAgent) {
          throw new Error("Expected member agent to be loaded");
        }

        this.storeKeyRevelationForMember(
          otherMemberKey,
          otherMemberAgent,
          writeKeyForNewMember.id,
          writeKeyForNewMember.secret,
        );
      }
    }

    // Reveal the new writeOnly key to parent groups
    for (const parentGroup of this.getParentGroups()) {
      this.revealReadKeyToParentGroup(
        parentGroup,
        writeKeyForNewMember.id,
        writeKeyForNewMember.secret,
        { revealAllWriteOnlyKeys: false },
      );
    }

    return writeKeyForNewMember.id;
  }

  private storeKeyRevelationForMember(
    memberKey: RawAccountID | AgentID,
    agent: AgentID,
    keyID: KeyID,
    secret: KeySecret,
  ) {
    this.set(
      `${keyID}_for_${memberKey}`,
      this.crypto.seal({
        message: secret,
        from: this.core.node.getCurrentAgent().currentSealerSecret(),
        to: this.crypto.getAgentSealerID(agent),
        nOnceMaterial: {
          in: this.id,
          tx: this.core.nextTransactionID(),
        },
      }),
      "trusting",
    );
  }

  private storeKeyRevelationForParentGroup(
    parentReadKeyID: KeyID,
    parentReadKeySecret: KeySecret,
    childReadKeyID: KeyID,
    childReadKeySecret: KeySecret,
  ) {
    this.set(
      `${childReadKeyID}_for_${parentReadKeyID}`,
      this.crypto.encryptKeySecret({
        encrypting: {
          id: parentReadKeyID,
          secret: parentReadKeySecret,
        },
        toEncrypt: {
          id: childReadKeyID,
          secret: childReadKeySecret,
        },
      }).encrypted,
      "trusting",
    );
  }

  private getWriteOnlyKeys() {
    const keys: KeyID[] = [];

    for (const key of this.keys()) {
      if (key.startsWith("writeKeyFor_")) {
        keys.push(
          this.get(key as `writeKeyFor_${RawAccountID | AgentID}`) as KeyID,
        );
      }
    }

    return keys;
  }

  getCurrentReadKeyId() {
    if (this._lastReadableKeyId) {
      return this._lastReadableKeyId;
    }

    const myRole = this.myRole();

    if (myRole === "writeOnly") {
      const accountId = this.core.node.getCurrentAgent().id;

      const key = this.get(`writeKeyFor_${accountId}`) as KeyID;

      // When everyone is writeOnly, we need to create a writeOnly key for the current account if missing
      if (!key && this.get("everyone") === "writeOnly") {
        this.internalCreateWriteOnlyKeyForMember(
          accountId,
          this.core.node.getCurrentAgent().currentAgentID(),
        );

        return this.get(`writeKeyFor_${accountId}`) as KeyID;
      }

      return key;
    }

    if (!myRole) {
      const accountId = this.core.node.getCurrentAgent().id;

      const key = this.get(`writeKeyFor_${accountId}`) as KeyID;

      if (key) {
        return key;
      }
    }

    return this.get("readKey");
  }

  getMemberKeys(): (RawAccountID | AgentID)[] {
    return this.keys().filter((key): key is RawAccountID | AgentID => {
      return key.startsWith("co_") || isAgentID(key);
    });
  }

  getAllMemberKeysSet(): Set<RawAccountID | AgentID> {
    const memberKeys = new Set(this.getMemberKeys());

    for (const group of this.getParentGroups()) {
      for (const key of group.getAllMemberKeysSet()) {
        memberKeys.add(key);
      }
    }

    return memberKeys;
  }

  getReadKey(keyID: KeyID): KeySecret | undefined {
    const cache = this.core.readKeyCache;

    let key = cache.get(keyID);
    if (!key) {
      key = this.getUncachedReadKey(keyID);
      if (key) {
        cache.set(keyID, key);
      }
    }
    return key;
  }

  getUncachedReadKey(keyID: KeyID) {
    const core = this.core;

    const keyForEveryone = this.get(`${keyID}_for_everyone`);
    if (keyForEveryone) {
      return keyForEveryone;
    }

    // Try to find key revelation for us
    const currentAgentOrAccountID = accountOrAgentIDfromSessionID(
      core.node.currentSessionID,
    );

    // being careful here to avoid recursion
    const lookupAccountOrAgentID = isAccountID(currentAgentOrAccountID)
      ? core.id === currentAgentOrAccountID
        ? core.node.crypto.getAgentID(core.node.agentSecret) // in accounts, the read key is revealed for the primitive agent
        : currentAgentOrAccountID // current account ID
      : currentAgentOrAccountID; // current agent ID

    const lastReadyKeyEdit = this.lastEditAt(
      `${keyID}_for_${lookupAccountOrAgentID}`,
    );

    if (lastReadyKeyEdit?.value) {
      const revealer = lastReadyKeyEdit.by;
      const revealerAgent = core.node.resolveAccountAgent(
        revealer,
        "Expected to know revealer",
      ).value;

      if (!revealerAgent) {
        throw new Error("Expected to know revealer");
      }

      const secret = this.crypto.unseal(
        lastReadyKeyEdit.value,
        this.crypto.getAgentSealerSecret(core.node.agentSecret), // being careful here to avoid recursion
        this.crypto.getAgentSealerID(revealerAgent),
        {
          in: this.id,
          tx: lastReadyKeyEdit.tx,
        },
      );

      if (secret) {
        return secret as KeySecret;
      }
    }

    // Try to find indirect revelation through previousKeys
    // Use keyRevelations cache instead of iterating through all keys
    const revelationsForKey = this.keyRevelations.get(keyID);
    if (revelationsForKey) {
      for (const encryptingKeyID of revelationsForKey) {
        const encryptingKeySecret = this.getReadKey(encryptingKeyID);

        if (!encryptingKeySecret) {
          continue;
        }

        const encryptedPreviousKey = this.get(
          `${keyID}_for_${encryptingKeyID}`,
        )!;

        const secret = this.crypto.decryptKeySecret(
          {
            encryptedID: keyID,
            encryptingID: encryptingKeyID,
            encrypted: encryptedPreviousKey,
          },
          encryptingKeySecret,
        );

        if (secret) {
          return secret as KeySecret;
        } else {
          logger.warn(
            `Encrypting ${encryptingKeyID} key didn't decrypt ${keyID}`,
          );
        }
      }
    }

    // try to find revelation to parent group read keys
    // Use parentGroupsChanges cache instead of iterating through all keys
    for (const parentGroupID of this.parentGroupsChanges.keys()) {
      const parentGroup = core.node.expectCoValueLoaded(
        parentGroupID,
        "Expected parent group to be loaded",
      );

      const parentKeys = this.findValidParentKeys(keyID, parentGroup);

      for (const parentKey of parentKeys) {
        const revelationForParentKey = this.get(`${keyID}_for_${parentKey.id}`);

        if (revelationForParentKey) {
          const secret = parentGroup.node.crypto.decryptKeySecret(
            {
              encryptedID: keyID,
              encryptingID: parentKey.id,
              encrypted: revelationForParentKey,
            },
            parentKey.secret,
          );

          if (secret) {
            return secret as KeySecret;
          } else {
            logger.warn(
              `Encrypting parent ${parentKey.id} key didn't decrypt ${keyID}`,
            );
          }
        }
      }

      // Try to find revelation via parent group sealer (anonymous box)
      const parentContent = expectGroup(parentGroup.getCurrentContent());
      const secret = this.tryDecryptWithGroupSealer(keyID, parentContent);
      if (secret) {
        return secret;
      }
    }

    return undefined;
  }

  /**
   * Try to decrypt a key that was revealed via a parent group's sealer.
   * Walks the parent group's groupSealer history backwards (newest first)
   * and tries to unseal the key revelation for each historical sealer value.
   *
   * New format groupSealer values embed the readKeyID directly (e.g., "key_z..._sealer_z...")
   * so we can deterministically find the correct readKey without time-based correlation.
   * Legacy format values (just "sealer_z...") fall back to time-based readKey lookup.
   */
  private tryDecryptWithGroupSealer(
    keyID: KeyID,
    parentGroup: RawGroup,
  ): KeySecret | undefined {
    const sealerEntries = parentGroup.ops["groupSealer"];
    if (!sealerEntries) return undefined;

    // Iterate backwards (newest sealer first) to try the most recent one first
    for (let i = sealerEntries.length - 1; i >= 0; i--) {
      const sealerEntry = sealerEntries[i]!;
      if (sealerEntry.change.op !== "set") continue;
      const groupSealerValue = sealerEntry.change.value as string | undefined;
      if (!groupSealerValue) continue;

      // Extract the SealerID (handles both new composite and legacy formats)
      const sealerID = extractSealerID(groupSealerValue);

      const sealedKeyEdit = this.lastEditAt(`${keyID}_sealedFor_${sealerID}`);
      if (!sealedKeyEdit?.value) continue;

      // Try to get the readKeyID directly from the composite value (new format)
      const readKeyID = extractReadKeyID(groupSealerValue);
      if (!readKeyID) continue;

      const readKeySecret = parentGroup.getReadKey(readKeyID);
      if (!readKeySecret) continue;

      const { secret: sealerSecret } =
        this.crypto.groupSealerFromReadKey(readKeySecret);

      const secret = this.crypto.unsealForGroup(
        sealedKeyEdit.value as SealedForGroup<KeySecret>,
        sealerSecret,
        {
          in: this.id,
          tx: sealedKeyEdit.tx,
        },
      );

      if (secret) {
        return secret;
      }
    }

    return undefined;
  }

  private findValidParentKeys(keyID: KeyID, parentGroup: CoValueCore) {
    const validParentKeys: { id: KeyID; secret: KeySecret }[] = [];

    // Use keyRevelations cache instead of iterating through all keys
    const revelationsForKey = this.keyRevelations.get(keyID);
    if (revelationsForKey) {
      for (const encryptingKeyID of revelationsForKey) {
        const encryptingKeySecret = parentGroup.getReadKey(encryptingKeyID);

        if (!encryptingKeySecret) {
          continue;
        }

        validParentKeys.push({
          id: encryptingKeyID,
          secret: encryptingKeySecret,
        });
      }
    }

    return validParentKeys;
  }

  // =========================================================================
  // Native group key-management write path (behind `nativeGroupKeyWrites`).
  //
  // Each `try*Native` gathers the non-native inputs TS already resolves (fresh
  // random keys, resolved agent sealer ids, resolved read-key secrets,
  // `startTxIndex`), calls the matching JSON FFI wrapper to get the exact
  // ordered write list the corresponding TS write path would emit, and applies
  // it via `group.set` / `group.delete`. It returns `true` when it fully handled
  // the operation, or `false` to fall back to the TS body — for deferred branches
  // (non-account-member parent group-sealer/legacy paths, unresolvable inputs)
  // and, conservatively, any rotation of a group with loaded child groups (whose
  // recursive `forEachChildGroup` rotation is TS-only).
  //
  // Transaction-index invariant: a member seal's nonce embeds
  // `nextTransactionID().txIndex`, so `startTxIndex` is captured AFTER all
  // incidental resolution (which itself never writes here) and immediately
  // before applying, and each native write is applied as exactly one `group.set`
  // (one transaction) with nothing interleaved — so write i lands at
  // `startTxIndex + i`, matching the tx index its seal was built with.
  // =========================================================================

  /** Whether the native key-management write path is enabled AND the current
   *  crypto backend exposes it. */
  private useNativeGroupKeyWrites(): boolean {
    return (
      isNativeGroupKeyWritesEnabled() &&
      this.core.node.nodeCore.supportsNativeGroupKeyWrites()
    );
  }

  /** Materialize the current group CoMap as a `{field: value}` object of
   *  string-valued fields — the `snapshot` `GroupKeyState::from_snapshot`
   *  consumes (it keeps only string values, exactly as this does). */
  private nativeGroupSnapshot(): Record<string, string> {
    const snapshot: Record<string, string> = {};
    for (const key of this.keys()) {
      const value = this.get(key as keyof GroupShape & string);
      if (typeof value === "string") {
        snapshot[key] = value;
      }
    }
    return snapshot;
  }

  /** The `snapshot` fragment to merge into a native group key-write FFI input.
   *
   *  When native coMap materialization is enabled the FFI is dispatched through
   *  the NodeCore methods (see `crypto`'s `groupRotateReadKey` etc.), which source
   *  the group's key state from the node's OWN materialized coMap view — so we
   *  OMIT the snapshot entirely rather than re-serialize the whole group CoMap and
   *  marshal it across the FFI boundary on every write (an O(fields) cost per
   *  write, O(n^2) over a long rotation run). When it is disabled we fall back to
   *  embedding the TS-materialized snapshot, which the native side then honors
   *  as-is. */
  private nativeGroupSnapshotInput(): { snapshot?: Record<string, string> } {
    if (
      isNativeCoMapMaterializationEnabled() &&
      this.core.node.nodeCore.supportsNativeCoMapMaterialization()
    ) {
      return {};
    }
    return { snapshot: this.nativeGroupSnapshot() };
  }

  /** Resolve a member key to the sealer id revelations are sealed *to*
   *  (`getAgentSealerID(resolveAccountAgent(...))`), or undefined if the
   *  member's agent can't be resolved. */
  private tryResolveMemberSealerID(
    memberKey: RawAccountID | AgentID,
  ): SealerID | undefined {
    try {
      const agent = this.core.node.resolveAccountAgent(memberKey).value;
      if (!agent) return undefined;
      return this.crypto.getAgentSealerID(agent);
    } catch {
      return undefined;
    }
  }

  /** getMemberKeys() order, each with its resolved agent sealer id (`""` when
   *  unresolvable — only the members the native fn actually seals to require a
   *  real id, which the caller checks separately). */
  private nativeMembers(): { memberKey: string; agentSealerId: string }[] {
    return this.getMemberKeys().map((memberKey) => ({
      memberKey,
      agentSealerId: this.tryResolveMemberSealerID(memberKey) ?? "",
    }));
  }

  /** Whether a member (by its current direct role) is one the rotation
   *  re-reveals a key to — a reader-class member, or a writeOnly member. */
  private nativeSealsToMember(memberKey: string): boolean {
    const key = memberKey as RawAccountID | AgentID;
    const role = this.get(key);
    return (
      canRead(this, key) || role === "writeOnly" || role === "writeOnlyInvite"
    );
  }

  /** Count of writeOnly members (getMemberKeys order) excluding `excluded`. */
  private nativeWriteOnlyMemberCount(
    members: { memberKey: string }[],
    excluded?: string,
  ): number {
    return members.filter((m) => {
      if (m.memberKey === excluded) return false;
      const role = this.get(m.memberKey as RawAccountID | AgentID);
      return role === "writeOnly" || role === "writeOnlyInvite";
    }).length;
  }

  /** Resolve every parent group (getParentGroups() order) to its
   *  `(readKeyId, readKeySecret)` for the STANDARD account-member reveal path.
   *  Returns undefined (→ caller falls back to full TS) if any parent needs the
   *  non-account-member group-sealer/legacy path or we lack its read key secret. */
  private tryResolveStandardParents():
    | { readKeyId: string; readKeySecret: string }[]
    | undefined {
    const resolved: { readKeyId: string; readKeySecret: string }[] = [];
    for (const parent of this.getParentGroups()) {
      if (!isAccountRole(parent.myRole())) {
        return undefined; // group-sealer / legacy path is TS-only
      }
      const { id, secret } = parent.getCurrentReadKey();
      if (!secret) {
        return undefined; // TS warns+skips; defer to keep byte parity
      }
      resolved.push({ readKeyId: id, readKeySecret: secret });
    }
    return resolved;
  }

  /** Whether any loaded child group currently extends this group — rotations
   *  recurse into them (forEachChildGroup), which the native functions do not
   *  cover, so the caller conservatively falls back to TS when this is true. */
  private hasLoadedChildGroup(): boolean {
    let has = false;
    this.forEachChildGroup(() => {
      has = true;
    });
    return has;
  }

  private setTrusting(field: string, value: JsonValue) {
    (this.set as unknown as (k: string, v: JsonValue, p: "trusting") => void)(
      field,
      value,
      "trusting",
    );
  }

  private deleteTrusting(field: string) {
    (this.delete as unknown as (k: string, p: "trusting") => void)(
      field,
      "trusting",
    );
  }

  /** Apply an ordered native write list as contiguous trusting sets (see the
   *  transaction-index invariant above). */
  private applyNativeWrites(writes: { field: string; value: string }[]) {
    for (const w of writes) {
      this.setTrusting(w.field, w.value);
    }
  }

  /** Mirror `addMemberInternal`'s post-`set` role assertion (group.ts:606/658/674):
   *  if the role write didn't land (e.g. the current account isn't authorized),
   *  surface the same error TS does. */
  private assertNativeMemberRole(
    memberKey: RawAccountID | AgentID | Everyone,
    role: Role,
  ) {
    if (this.get(memberKey as RawAccountID | AgentID) !== role) {
      throw new Error(
        `Failed to set role ${role} to ${memberKey} (role of current account is ${this.myRole()})`,
      );
    }
  }

  /** Reproduce `rotateReadKey` via the native FFI. Returns false to fall back. */
  private tryRotateReadKeyNative(
    removedMemberKey?: RawAccountID | AgentID | "everyone",
  ): boolean {
    // Top guard mirrors rotateReadKey's early return (and avoids any incidental
    // getCurrentReadKey writes when rotation is a no-op).
    if (removedMemberKey !== EVERYONE && canRead(this, EVERYONE)) {
      return true; // nothing to do, exactly as TS
    }

    // Child groups recurse (forEachChildGroup) — TS-only; defer whole rotation.
    if (this.hasLoadedChildGroup()) {
      return false;
    }

    const parents = this.tryResolveStandardParents();
    if (parents === undefined) {
      return false;
    }

    const maybeCurrentReadKey = this.getCurrentReadKey();
    if (!maybeCurrentReadKey.secret) {
      throw new NoReadKeyAccessError(
        "Can't rotate read key secret we don't have access to",
      );
    }
    const currentReadKey = {
      id: maybeCurrentReadKey.id,
      secret: maybeCurrentReadKey.secret,
    };

    const members = this.nativeMembers();
    // Every member the rotation actually seals to must have a resolvable sealer
    // id; if not, defer to the (proven) TS path rather than emit a bad seal.
    for (const m of members) {
      if (m.memberKey === removedMemberKey) continue;
      if (this.nativeSealsToMember(m.memberKey) && !m.agentSealerId) {
        return false;
      }
    }

    const writeOnlyFreshKeys = Array.from(
      { length: this.nativeWriteOnlyMemberCount(members, removedMemberKey) },
      () => this.crypto.newRandomKeySecret(),
    );
    const newReadKey = this.crypto.newRandomKeySecret();

    const trigger =
      removedMemberKey === EVERYONE
        ? { kind: "removeEveryone" }
        : removedMemberKey !== undefined
          ? { kind: "removeMember", member: removedMemberKey }
          : { kind: "rotate" };

    // Capture start tx index AFTER all incidental resolution above.
    const { sessionID, txIndex } = this.core.nextTransactionID();
    const input = {
      trigger,
      groupId: this.id,
      sessionId: sessionID,
      startTxIndex: txIndex,
      fromSealerSecret: this.core.node.getCurrentAgent().currentSealerSecret(),
      currentReadKey,
      newReadKey,
      members,
      writeOnlyFreshKeys,
      parents,
      ...this.nativeGroupSnapshotInput(),
    };

    let out: { skipped: boolean; writes: { field: string; value: string }[] };
    try {
      out = JSON.parse(
        this.core.node.nodeCore.groupRotateReadKey!(JSON.stringify(input)),
      );
    } catch {
      return false;
    }
    if (out.skipped) {
      return true;
    }
    this.applyNativeWrites(out.writes);
    return true;
  }

  /** Invoke the native `add_member_internal` FFI; undefined on a deferred branch. */
  private callAddMemberInternal(
    input: unknown,
  ): { field: string; value: string }[] | undefined {
    try {
      return JSON.parse(
        this.core.node.nodeCore.groupAddMemberInternal!(JSON.stringify(input)),
      );
    } catch {
      // Deferred/unsupported branch (e.g. everyone -> writeOnly) or any native
      // error → fall back to the TS write path (nothing has been applied yet).
      return undefined;
    }
  }

  /** Reproduce `addMemberInternal` via the native FFI. Returns false to fall back. */
  private tryAddMemberInternalNative(
    account: RawAccount | ControlledAccountOrAgent | AgentID | Everyone,
    role: Role,
    memberKey: RawAccountID | AgentID | Everyone,
    previousRole: Role | undefined,
  ): boolean {
    const fromSealerSecret = this.core.node
      .getCurrentAgent()
      .currentSealerSecret();

    if (memberKey === EVERYONE) {
      if (role !== "reader" && role !== "writer" && role !== "writeOnly") {
        return false; // invalid everyone role → let TS throw
      }
      if (role === "writeOnly") {
        return this.tryAddEveryoneWriteOnlyNative(
          previousRole,
          fromSealerSecret,
        );
      }
      // everyone → reader/writer: plaintext read-key reveal, no rotation.
      const maybeCurrentReadKey = this.getCurrentReadKey();
      if (!maybeCurrentReadKey.secret) {
        return false; // TS throws "Can't add member without read key secret"
      }
      const { sessionID, txIndex } = this.core.nextTransactionID();
      const writes = this.callAddMemberInternal({
        groupId: this.id,
        sessionId: sessionID,
        startTxIndex: txIndex,
        memberKey: EVERYONE,
        memberAgentSealerId: "",
        role,
        fromSealerSecret,
        currentReadKey: {
          id: maybeCurrentReadKey.id,
          secret: maybeCurrentReadKey.secret,
        },
        existingWriteOnlyKeys: [],
        members: [],
        parents: [],
        ...this.nativeGroupSnapshotInput(),
      });
      if (writes === undefined) return false;
      this.applyNativeWrites(writes);
      this.assertNativeMemberRole(EVERYONE, role);
      return true;
    }

    const agent =
      typeof account === "string" ? account : account.currentAgentID();
    if (agent === EVERYONE) {
      return false; // TS throws "Agent should not be everyone"
    }
    let memberAgentSealerId: SealerID;
    try {
      memberAgentSealerId = this.crypto.getAgentSealerID(agent);
    } catch {
      return false;
    }

    if (role === "writeOnly" || role === "writeOnlyInvite") {
      const isDemotion =
        previousRole === "reader" ||
        previousRole === "writer" ||
        previousRole === "manager" ||
        previousRole === "admin";
      // A demotion first rotates the read key (recurses into child groups).
      if (isDemotion && this.hasLoadedChildGroup()) {
        return false;
      }
      const parents = this.tryResolveStandardParents();
      if (parents === undefined) return false;

      const members = this.nativeMembers();
      // The fresh writeOnly key is revealed to every reader-class member (except
      // the one being demoted); those recipients need resolvable sealer ids.
      for (const m of members) {
        if (m.memberKey === memberKey) continue;
        if (
          canRead(this, m.memberKey as RawAccountID | AgentID) &&
          !m.agentSealerId
        ) {
          return false;
        }
      }

      const maybeCurrentReadKey = this.getCurrentReadKey();
      if (isDemotion && !maybeCurrentReadKey.secret) return false;
      const currentReadKey = {
        id: maybeCurrentReadKey.id,
        secret: maybeCurrentReadKey.secret ?? "",
      };

      const freshWriteOnlyKey = this.crypto.newRandomKeySecret();
      let rotationNewReadKey: { id: KeyID; secret: KeySecret } | undefined;
      let rotationWriteOnlyFreshKeys: { id: KeyID; secret: KeySecret }[] = [];
      if (isDemotion) {
        rotationNewReadKey = this.crypto.newRandomKeySecret();
        rotationWriteOnlyFreshKeys = Array.from(
          { length: this.nativeWriteOnlyMemberCount(members, memberKey) },
          () => this.crypto.newRandomKeySecret(),
        );
      }

      const { sessionID, txIndex } = this.core.nextTransactionID();
      const writes = this.callAddMemberInternal({
        groupId: this.id,
        sessionId: sessionID,
        startTxIndex: txIndex,
        memberKey,
        memberAgentSealerId,
        role,
        fromSealerSecret,
        currentReadKey,
        existingWriteOnlyKeys: [],
        freshWriteOnlyKey,
        rotationNewReadKey,
        rotationWriteOnlyFreshKeys,
        members,
        parents,
        ...this.nativeGroupSnapshotInput(),
      });
      if (writes === undefined) return false;
      this.applyNativeWrites(writes);
      this.assertNativeMemberRole(memberKey, role);
      return true;
    }

    // reader-class branch (reader/writer/manager/admin + *Invite).
    const maybeCurrentReadKey = this.getCurrentReadKey();
    if (!maybeCurrentReadKey.secret) {
      return false; // TS throws "Can't add member without read key secret"
    }
    const existingWriteOnlyKeys: { id: KeyID; secret: KeySecret }[] = [];
    for (const keyID of this.getWriteOnlyKeys()) {
      const secret = this.core.getReadKey(keyID);
      if (!secret) return false; // TS logs+continues; defer to keep parity
      existingWriteOnlyKeys.push({ id: keyID, secret });
    }

    const { sessionID, txIndex } = this.core.nextTransactionID();
    const writes = this.callAddMemberInternal({
      groupId: this.id,
      sessionId: sessionID,
      startTxIndex: txIndex,
      memberKey,
      memberAgentSealerId,
      role,
      fromSealerSecret,
      currentReadKey: {
        id: maybeCurrentReadKey.id,
        secret: maybeCurrentReadKey.secret,
      },
      existingWriteOnlyKeys,
      members: [],
      parents: [],
      ...this.nativeGroupSnapshotInput(),
    });
    if (writes === undefined) return false;
    this.applyNativeWrites(writes);
    this.assertNativeMemberRole(memberKey, role);
    return true;
  }

  /** Reproduce `addMember(everyone, "writeOnly")` via the native FFI. */
  private tryAddEveryoneWriteOnlyNative(
    previousRole: Role | undefined,
    fromSealerSecret: SealerSecret,
  ): boolean {
    const willRotate = previousRole === "reader" || previousRole === "writer";
    // The preceding rotateReadKey("everyone") recurses into child groups.
    if (willRotate && this.hasLoadedChildGroup()) {
      return false;
    }
    const maybeCurrentReadKey = this.getCurrentReadKey();
    if (!maybeCurrentReadKey.secret) {
      return false; // needed for the rotation and the deleted field name
    }
    const currentReadKey = {
      id: maybeCurrentReadKey.id,
      secret: maybeCurrentReadKey.secret,
    };

    let rotationNewReadKey: { id: KeyID; secret: KeySecret } | undefined;
    let rotationWriteOnlyFreshKeys: { id: KeyID; secret: KeySecret }[] = [];
    let members: { memberKey: string; agentSealerId: string }[] = [];
    let parents: { readKeyId: string; readKeySecret: string }[] = [];
    if (willRotate) {
      const resolvedParents = this.tryResolveStandardParents();
      if (resolvedParents === undefined) return false;
      parents = resolvedParents;
      members = this.nativeMembers();
      for (const m of members) {
        if (
          canRead(this, m.memberKey as RawAccountID | AgentID) &&
          !m.agentSealerId
        ) {
          return false;
        }
      }
      rotationNewReadKey = this.crypto.newRandomKeySecret();
      rotationWriteOnlyFreshKeys = Array.from(
        { length: this.nativeWriteOnlyMemberCount(members) },
        () => this.crypto.newRandomKeySecret(),
      );
    }

    const { sessionID, txIndex } = this.core.nextTransactionID();
    const input = {
      groupId: this.id,
      sessionId: sessionID,
      startTxIndex: txIndex,
      fromSealerSecret,
      currentReadKey,
      rotationNewReadKey,
      rotationWriteOnlyFreshKeys,
      members,
      parents,
      ...this.nativeGroupSnapshotInput(),
    };
    let muts: { op: "set" | "del"; field: string; value?: string }[];
    try {
      muts = JSON.parse(
        this.core.node.nodeCore.groupAddEveryoneWriteOnly!(
          JSON.stringify(input),
        ),
      );
    } catch {
      return false;
    }
    for (const m of muts) {
      if (m.op === "del") {
        this.deleteTrusting(m.field);
      } else {
        this.setTrusting(m.field, m.value!);
      }
    }
    this.assertNativeMemberRole(EVERYONE, "writeOnly");
    return true;
  }

  /** Reproduce `removeMember` via the native FFI. Returns false to fall back. */
  private tryRemoveMemberNative(
    memberKey: RawAccountID | AgentID | Everyone,
  ): boolean {
    // removeMember(everyone) → rotateReadKey("everyone"), whose trigger semantics
    // (RemoveEveryone, guard bypassed) differ from native remove_member's
    // RemoveMember(everyone). Keep that on the TS path.
    if (memberKey === EVERYONE) {
      return false;
    }

    const myRole = this.myRole();
    const callerIsAdminOrManager = myRole === "admin" || myRole === "manager";

    let members: { memberKey: string; agentSealerId: string }[] = [];
    let parents: { readKeyId: string; readKeySecret: string }[] = [];
    let writeOnlyFreshKeys: { id: KeyID; secret: KeySecret }[] = [];
    let currentReadKey = { id: "", secret: "" };
    let newReadKey = { id: "", secret: "" };

    if (callerIsAdminOrManager) {
      // rotateReadKey(memberKey) runs first: it recurses into child groups and
      // can take the group-sealer / legacy parent path — defer those to TS.
      if (this.hasLoadedChildGroup()) return false;

      const resolvedParents = this.tryResolveStandardParents();
      if (resolvedParents === undefined) return false;
      parents = resolvedParents;

      const maybeCurrentReadKey = this.getCurrentReadKey();
      // The internal rotation only runs (and thus only needs the read key) when
      // everyone can't already read; otherwise it skips and only the revoked set
      // is emitted.
      if (!maybeCurrentReadKey.secret && !canRead(this, EVERYONE)) {
        return false; // TS rotateReadKey would throw NoReadKeyAccessError
      }
      currentReadKey = {
        id: maybeCurrentReadKey.id,
        secret: maybeCurrentReadKey.secret ?? "",
      };

      members = this.nativeMembers();
      for (const m of members) {
        if (m.memberKey === memberKey) continue;
        if (this.nativeSealsToMember(m.memberKey) && !m.agentSealerId) {
          return false;
        }
      }
      writeOnlyFreshKeys = Array.from(
        { length: this.nativeWriteOnlyMemberCount(members, memberKey) },
        () => this.crypto.newRandomKeySecret(),
      );
      newReadKey = this.crypto.newRandomKeySecret();
    }

    const { sessionID, txIndex } = this.core.nextTransactionID();
    const input = {
      memberKey,
      callerIsAdminOrManager,
      groupId: this.id,
      sessionId: sessionID,
      startTxIndex: txIndex,
      fromSealerSecret: this.core.node.getCurrentAgent().currentSealerSecret(),
      currentReadKey,
      newReadKey,
      members,
      writeOnlyFreshKeys,
      parents,
      ...this.nativeGroupSnapshotInput(),
    };
    let writes: { field: string; value: string }[];
    try {
      writes = JSON.parse(
        this.core.node.nodeCore.groupRemoveMember!(JSON.stringify(input)),
      );
    } catch {
      return false;
    }
    this.applyNativeWrites(writes);
    // Mirror removeMember's post-write assertion (group.ts:1494-1498).
    if (this.get(memberKey as RawAccountID | AgentID) !== "revoked") {
      throw new Error(
        `Failed to revoke role to ${memberKey} (role of current account is ${this.myRole()})`,
      );
    }
    return true;
  }

  /** Reproduce `extend` (standard account-member parent) via the native FFI. */
  private tryExtendNative(
    parent: RawGroup,
    role: "reader" | "writer" | "manager" | "admin" | "inherit",
  ): boolean {
    const value = role === "inherit" ? "extend" : role;

    const { id: childReadKeyID, secret: childReadKeySecret } =
      this.getCurrentReadKey();
    if (childReadKeySecret === undefined) {
      return false; // TS throws "Can't extend group without child read key secret"
    }

    // Only the standard account-member parent path is native; the group-sealer /
    // legacy paths stay in TS (revealReadKeyToParentGroup).
    if (!isAccountRole(parent.myRole())) {
      return false;
    }
    const { id: parentReadKeyID, secret: parentReadKeySecret } =
      parent.getCurrentReadKey();
    if (!parentReadKeySecret) {
      return false; // TS throws "Can't extend group without parent read key secret"
    }

    // extend reveals ALL writeOnly keys to the parent (revealAllWriteOnlyKeys: true).
    const writeOnlyKeys: { id: KeyID; secret: KeySecret }[] = [];
    for (const keyID of this.getWriteOnlyKeys()) {
      const secret = this.core.getReadKey(keyID);
      if (!secret) return false; // TS logs+continues; defer to keep parity
      writeOnlyKeys.push({ id: keyID, secret });
    }

    let writes: { field: string; value: string }[];
    try {
      writes = JSON.parse(
        this.core.node.nodeCore.groupExtend!(
          JSON.stringify({
            parentId: parent.id,
            parentRefValue: value,
            parent: {
              readKeyId: parentReadKeyID,
              readKeySecret: parentReadKeySecret,
            },
            childReadKey: { id: childReadKeyID, secret: childReadKeySecret },
            writeOnlyKeys,
          }),
        ),
      );
    } catch {
      return false;
    }
    this.applyNativeWrites(writes);
    return true;
  }

  /** @internal */
  rotateReadKey(removedMemberKey?: RawAccountID | AgentID | "everyone") {
    if (
      this.useNativeGroupKeyWrites() &&
      this.tryRotateReadKeyNative(removedMemberKey)
    ) {
      return;
    }

    if (removedMemberKey !== EVERYONE && canRead(this, EVERYONE)) {
      // When everyone has access to the group, rotating the key is useless
      // because it would be stored unencrypted and available to everyone
      return;
    }

    const memberKeys = this.getMemberKeys().filter(
      (key) => key !== removedMemberKey,
    );

    const currentlyPermittedReaders = memberKeys.filter((key) =>
      canRead(this, key),
    );

    const writeOnlyMembers = memberKeys.filter((key) => {
      const role = this.get(key);
      return role === "writeOnly" || role === "writeOnlyInvite";
    });

    // Get these early, so we fail fast if they are unavailable
    const parentGroups = this.getParentGroups();
    const maybeCurrentReadKey = this.getCurrentReadKey();

    if (!maybeCurrentReadKey.secret) {
      throw new NoReadKeyAccessError(
        "Can't rotate read key secret we don't have access to",
      );
    }

    const currentReadKey = {
      id: maybeCurrentReadKey.id,
      secret: maybeCurrentReadKey.secret,
    };

    const newReadKey = this.crypto.newRandomKeySecret();

    for (const readerID of currentlyPermittedReaders) {
      const agent = this.core.node.resolveAccountAgent(
        readerID,
        "Expected to know currently permitted reader",
      ).value;

      if (!agent) {
        throw new Error("Expected to know currently permitted reader");
      }

      this.storeKeyRevelationForMember(
        readerID,
        agent,
        newReadKey.id,
        newReadKey.secret,
      );
    }

    /**
     * If there are some writeOnly members we need to rotate their keys
     * and reveal them to the other non-writeOnly members
     */
    for (const writeOnlyMemberID of writeOnlyMembers) {
      const agent = this.core.node.resolveAccountAgent(
        writeOnlyMemberID,
        "Expected to know writeOnly member",
      ).value;

      if (!agent) {
        throw new Error("Expected to know writeOnly member");
      }

      const writeOnlyKey = this.crypto.newRandomKeySecret();

      this.storeKeyRevelationForMember(
        writeOnlyMemberID,
        agent,
        writeOnlyKey.id,
        writeOnlyKey.secret,
      );
      this.set(`writeKeyFor_${writeOnlyMemberID}`, writeOnlyKey.id, "trusting");

      for (const readerID of currentlyPermittedReaders) {
        const agent = this.core.node.resolveAccountAgent(
          readerID,
          "Expected to know currently permitted reader",
        ).value;

        if (!agent) {
          throw new Error("Expected to know currently permitted reader");
        }

        this.storeKeyRevelationForMember(
          readerID,
          agent,
          writeOnlyKey.id,
          writeOnlyKey.secret,
        );
      }

      for (const parentGroup of this.getParentGroups()) {
        this.revealReadKeyToParentGroup(
          parentGroup,
          writeOnlyKey.id,
          writeOnlyKey.secret,
          { revealAllWriteOnlyKeys: false },
        );
      }
    }

    this.set(
      `${currentReadKey.id}_for_${newReadKey.id}`,
      this.crypto.encryptKeySecret({
        encrypting: newReadKey,
        toEncrypt: currentReadKey,
      }).encrypted,
      "trusting",
    );

    this.set("readKey", newReadKey.id, "trusting");

    // Update the group sealer (derived deterministically from the new read key)
    // Store composite value with readKeyID to prevent race conditions between
    // concurrent key rotations and groupSealer migrations
    const newGroupSealer = this.crypto.groupSealerFromReadKey(
      newReadKey.secret,
    );
    this.set(
      "groupSealer",
      formatGroupSealerValue(newReadKey.id, newGroupSealer.publicKey),
      "trusting",
    );

    /**
     * The new read key needs to be revealed to the parent groups
     *
     * This way the members from the parent groups can still have access to this group
     */
    for (const parent of parentGroups) {
      const { id: parentReadKeyID, secret: parentReadKeySecret } =
        parent.getCurrentReadKey();

      if (!parentReadKeySecret) {
        // We can't reveal the new child key to the parent group where we don't have access to the parent read key
        // TODO: This will be fixed with: https://github.com/garden-co/jazz/issues/1979
        logger.warn(
          "Can't reveal new child key to parent where we don't have access to the parent read key",
        );
        continue;
      }

      this.storeKeyRevelationForParentGroup(
        parentReadKeyID,
        parentReadKeySecret,
        newReadKey.id,
        newReadKey.secret,
      );
    }

    this.forEachChildGroup((child) => {
      // Since child references are mantained only for the key rotation,
      // circular references are skipped here because it's more performant
      // than always checking for circular references in childs inside the permission checks
      if (child.isSelfExtension(this)) {
        return;
      }

      try {
        child.rotateReadKey(removedMemberKey);
      } catch (error) {
        if (error instanceof NoReadKeyAccessError) {
          logger.warn(
            `Can't rotate read key on child ${child.id} because we don't have access to the read key`,
          );
        } else {
          throw error;
        }
      }
    });
  }

  /** Detect circular references in group inheritance */
  isSelfExtension(parent: RawGroup) {
    return isSelfExtension(this.core, parent);
  }

  getCurrentReadKey() {
    const keyId = this.getCurrentReadKeyId();

    if (!keyId) {
      throw new Error("No readKey set");
    }

    return {
      secret: this.getReadKey(keyId),
      id: keyId,
    };
  }

  /**
   * Get the group sealer secret by deriving it from the associated read key.
   * Uses the readKeyID embedded in the composite groupSealer value (new format),
   * or falls back to the current read key (legacy format).
   * Returns undefined if we don't have access to the read key.
   */
  getGroupSealerSecret(): SealerSecret | undefined {
    const groupSealerValue = this.get("groupSealer");
    if (!groupSealerValue) return undefined;

    const readKeyID = extractReadKeyID(groupSealerValue as string);
    const readKeySecret = readKeyID
      ? this.getReadKey(readKeyID)
      : this.getCurrentReadKey().secret;

    if (!readKeySecret) return undefined;

    return this.crypto.groupSealerFromReadKey(readKeySecret).secret;
  }

  extend(
    parent: RawGroup,
    role: "reader" | "writer" | "manager" | "admin" | "inherit" = "inherit",
  ) {
    if (this.isSelfExtension(parent)) {
      return;
    }

    if (this.myRole() !== "admin") {
      throw new Error(
        "To extend a group, the current account must be an admin in the child group",
      );
    }

    if (this.useNativeGroupKeyWrites() && this.tryExtendNative(parent, role)) {
      return;
    }

    const value = role === "inherit" ? "extend" : role;

    this.set(`parent_${parent.id}`, value, "trusting");

    const { id: childReadKeyID, secret: childReadKeySecret } =
      this.getCurrentReadKey();
    if (childReadKeySecret === undefined) {
      throw new Error("Can't extend group without child read key secret");
    }

    this.revealReadKeyToParentGroup(
      parent,
      childReadKeyID,
      childReadKeySecret,
      { revealAllWriteOnlyKeys: true },
    );
  }

  private revealReadKeyToParentGroup(
    parent: RawGroup,
    readKeyId: KeyID,
    readKeySecret: KeySecret,
    { revealAllWriteOnlyKeys }: { revealAllWriteOnlyKeys: boolean },
  ) {
    const parentGroupSealerValue = parent.get("groupSealer");

    // If we're not a member of the parent group, we need to use an alternative mechanism
    if (!isAccountRole(parent.myRole())) {
      if (parentGroupSealerValue) {
        // Extract the pure SealerID from the composite value (or legacy format)
        const parentSealerID = extractSealerID(
          parentGroupSealerValue as string,
        );

        // NEW PATH: Use group sealer (anonymous box) instead of writeOnly key
        this.storeKeyRevelationForGroupSealer(
          parentSealerID,
          readKeyId,
          readKeySecret,
        );

        // Also reveal all writeOnly keys if requested
        if (revealAllWriteOnlyKeys) {
          for (const keyID of this.getWriteOnlyKeys()) {
            const secret = this.core.getReadKey(keyID);
            if (!secret) {
              logger.error("Can't find key " + keyID);
              continue;
            }
            this.storeKeyRevelationForGroupSealer(
              parentSealerID,
              keyID,
              secret,
            );
          }
        }
        return;
      } else {
        // LEGACY FALLBACK: Create a writeOnly key in the parent group
        parent.internalCreateWriteOnlyKeyForMember(
          this.core.node.getCurrentAgent().id,
          this.core.node.getCurrentAgent().currentAgentID(),
        );
      }
    }

    // Standard path: we have access to the parent's read key
    const { id: parentReadKeyID, secret: parentReadKeySecret } =
      parent.getCurrentReadKey();

    if (!parentReadKeySecret) {
      throw new Error("Can't extend group without parent read key secret");
    }

    this.storeKeyRevelationForParentGroup(
      parentReadKeyID,
      parentReadKeySecret,
      readKeyId,
      readKeySecret,
    );

    if (revealAllWriteOnlyKeys) {
      for (const keyID of this.getWriteOnlyKeys()) {
        const secret = this.core.getReadKey(keyID);

        if (!secret) {
          logger.error("Can't find key " + keyID);
          continue;
        }

        this.storeKeyRevelationForParentGroup(
          parentReadKeyID,
          parentReadKeySecret,
          keyID,
          secret,
        );
      }
    }
  }

  /**
   * Store a key revelation encrypted to a parent group's sealer (anonymous box).
   * Used when extending a child group to a parent group we don't have access to.
   */
  private storeKeyRevelationForGroupSealer(
    groupSealer: SealerID,
    childKeyID: KeyID,
    childKeySecret: KeySecret,
  ) {
    this.set(
      `${childKeyID}_sealedFor_${groupSealer}`,
      this.crypto.sealForGroup({
        message: childKeySecret,
        to: groupSealer,
        nOnceMaterial: {
          in: this.id,
          tx: this.core.nextTransactionID(),
        },
      }),
      "trusting",
    );
  }

  revokeExtend(parent: RawGroup) {
    if (this.myRole() !== "admin") {
      throw new Error(
        "To unextend a group, the current account must be an admin in the child group",
      );
    }

    if (!isAccountRole(parent.myRole())) {
      throw new Error(
        "To unextend a group, the current account must be a member of the parent group",
      );
    }

    if (
      !this.get(`parent_${parent.id}`) ||
      this.get(`parent_${parent.id}`) === "revoked"
    ) {
      return;
    }

    // Set the parent key on the child group to `revoked`
    this.set(`parent_${parent.id}`, "revoked", "trusting");

    // Set the child key on the parent group to `revoked`
    if (parent.get(`child_${this.id}`)) {
      parent.set(`child_${this.id}`, "revoked", "trusting");
    }

    // Rotate the keys on the child group
    this.rotateReadKey();
  }

  /**
   * Strips the specified member of all roles (preventing future writes in
   *  the group and owned values) and rotates the read encryption key for that group
   * (preventing reads of new content in the group and owned values)
   *
   * @category 2. Role changing
   */
  removeMember(account: RawAccount | ControlledAccountOrAgent | Everyone) {
    const memberKey = typeof account === "string" ? account : account.id;

    if (
      this.useNativeGroupKeyWrites() &&
      this.tryRemoveMemberNative(memberKey)
    ) {
      return;
    }

    if (this.myRole() === "admin" || this.myRole() === "manager") {
      this.rotateReadKey(memberKey);
    }

    this.set(memberKey, "revoked", "trusting");

    if (this.get(memberKey) !== "revoked") {
      throw new Error(
        `Failed to revoke role to ${memberKey} (role of current account is ${this.myRole()})`,
      );
    }
  }

  /**
   * Creates an invite for new members to indirectly join the group,
   * allowing them to grant themselves the specified role with the InviteSecret
   * (a string starting with "inviteSecret_") - use `LocalNode.acceptInvite()` for this purpose.
   *
   * @category 2. Role changing
   */
  createInvite(role: AccountRole): InviteSecret {
    const secretSeed = this.crypto.newRandomSecretSeed();

    const inviteSecret = this.crypto.agentSecretFromSecretSeed(secretSeed);
    const inviteID = this.crypto.getAgentID(inviteSecret);

    this.addMemberInternal(inviteID, `${role}Invite` as Role);

    return inviteSecretFromSecretSeed(secretSeed);
  }

  private assertCanWrite(): void {
    const role = this.myRole();
    if (role === undefined || role === "reader" || role === "revoked") {
      throw new Error(
        `Cannot create content: current user does not have write permissions`,
      );
    }
  }

  /**
   * Creates a new `CoMap` within this group, with the specified specialized
   * `CoMap` type `M` and optional static metadata.
   *
   * @category 3. Value creation
   */
  createMap<M extends RawCoMap>(
    init?: M["_shape"],
    meta?: M["headerMeta"],
    initPrivacy: "trusting" | "private" = "private",
    uniqueness: CoValueUniqueness = this.crypto.createdNowUnique(),
    initMeta?: JsonObject,
  ): M {
    this.assertCanWrite();
    const map = this.core.node
      .createCoValue({
        type: "comap",
        ruleset: {
          type: "ownedByGroup",
          group: this.id,
        },
        meta: meta || null,
        ...(uniqueness.createdAt !== undefined
          ? { createdAt: uniqueness.createdAt }
          : {}),
        uniqueness: uniqueness.uniqueness,
      })
      .getCurrentContent() as M;

    if (init) {
      map.assign(init, initPrivacy, initMeta);
    } else if (!uniqueness.createdAt) {
      // If the createdAt is not set, we need to make a trusting transaction to set the createdAt
      map.core.makeTransaction([], "trusting", initMeta);
    }

    return map;
  }

  /**
   * Creates a new `CoList` within this group, with the specified specialized
   * `CoList` type `L` and optional static metadata.
   *
   * @category 3. Value creation
   */
  createList<L extends RawCoList>(
    init?: L["_item"][],
    meta?: L["headerMeta"],
    initPrivacy: "trusting" | "private" = "private",
    uniqueness: CoValueUniqueness = this.crypto.createdNowUnique(),
    initMeta?: JsonObject,
    options?: { restrictDeletion?: boolean },
  ): L {
    this.assertCanWrite();
    const list = this.core.node
      .createCoValue({
        type: "colist",
        ruleset: {
          type: "ownedByGroup",
          group: this.id,
          ...(options?.restrictDeletion === true
            ? { restrictDeletion: true }
            : {}),
        },
        meta: meta || null,
        ...(uniqueness.createdAt !== undefined
          ? { createdAt: uniqueness.createdAt }
          : {}),
        uniqueness: uniqueness.uniqueness,
      })
      .getCurrentContent() as L;

    if (init?.length) {
      list.appendItems(init, undefined, initPrivacy, initMeta);
    } else if (!uniqueness.createdAt) {
      // If the createdAt is not set, we need to make a trusting transaction to set the createdAt
      list.core.makeTransaction([], "trusting", initMeta);
    }

    return list;
  }

  /**
   * Creates a new `CoPlainText` within this group, with the specified specialized
   * `CoPlainText` type `T` and optional static metadata.
   *
   * @category 3. Value creation
   */
  createPlainText<T extends RawCoPlainText>(
    init?: string,
    meta?: T["headerMeta"],
    initPrivacy: "trusting" | "private" = "private",
  ): T {
    this.assertCanWrite();
    const text = this.core.node
      .createCoValue({
        type: "coplaintext",
        ruleset: {
          type: "ownedByGroup",
          group: this.id,
        },
        meta: meta || null,
        ...this.crypto.createdNowUnique(),
      })
      .getCurrentContent() as T;

    if (init) {
      text.insertAfter(0, init, initPrivacy);
    }

    return text;
  }

  /** @category 3. Value creation */
  createStream<C extends RawCoStream>(
    init?: JsonValue[],
    initPrivacy: "trusting" | "private" = "private",
    meta?: C["headerMeta"],
    uniqueness: CoValueUniqueness = this.crypto.createdNowUnique(),
    initMeta?: JsonObject,
  ): C {
    this.assertCanWrite();
    const stream = this.core.node
      .createCoValue({
        type: "costream",
        ruleset: {
          type: "ownedByGroup",
          group: this.id,
        },
        meta: meta || null,
        ...(uniqueness.createdAt !== undefined
          ? { createdAt: uniqueness.createdAt }
          : {}),
        uniqueness: uniqueness.uniqueness,
      })
      .getCurrentContent() as C;

    if (init?.length) {
      stream.core.makeTransaction(init, initPrivacy, initMeta);
    } else if (!uniqueness.createdAt) {
      // If the createdAt is not set, we need to make a trusting transaction to set the createdAt
      stream.core.makeTransaction([], "trusting", initMeta);
    }

    return stream;
  }

  /** @category 3. Value creation */
  createBinaryStream<C extends RawBinaryCoStream>(
    meta: C["headerMeta"] = { type: "binary" },
    uniqueness: CoValueUniqueness = this.crypto.createdNowUnique(),
  ): C {
    this.assertCanWrite();
    return this.core.node
      .createCoValue({
        type: "costream",
        ruleset: {
          type: "ownedByGroup",
          group: this.id,
        },
        meta: meta,
        ...(uniqueness.createdAt !== undefined
          ? { createdAt: uniqueness.createdAt }
          : {}),
        uniqueness: uniqueness.uniqueness,
      })
      .getCurrentContent() as C;
  }
}

export function isInheritableRole(
  roleInParent: Role | undefined,
): roleInParent is "revoked" | "admin" | "manager" | "writer" | "reader" {
  return (
    roleInParent === "revoked" ||
    roleInParent === "admin" ||
    roleInParent === "manager" ||
    roleInParent === "writer" ||
    roleInParent === "reader"
  );
}

function isMorePermissiveAndShouldInherit(
  roleInParent: "revoked" | "admin" | "manager" | "writer" | "reader",
  roleInChild: Role | undefined,
) {
  if (roleInParent === "revoked") {
    return true;
  }

  if (roleInParent === "manager") {
    return (
      !roleInChild || (roleInChild !== "manager" && roleInChild !== "admin")
    );
  }

  if (roleInParent === "admin") {
    return !roleInChild || roleInChild !== "admin";
  }

  if (roleInParent === "writer") {
    return (
      !roleInChild || roleInChild === "reader" || roleInChild === "writeOnly"
    );
  }

  if (roleInParent === "reader") {
    return !roleInChild;
  }

  // writeOnly can't be inherited
  if (roleInParent === "writeOnly") {
    return false;
  }

  return false;
}

export type InviteSecret = `inviteSecret_z${string}`;

function inviteSecretFromSecretSeed(secretSeed: Uint8Array): InviteSecret {
  return `inviteSecret_z${base58.encode(secretSeed)}`;
}

export function secretSeedFromInviteSecret(inviteSecret: InviteSecret) {
  if (!inviteSecret.startsWith("inviteSecret_z")) {
    throw new Error("Invalid invite secret");
  }

  return base58.decode(inviteSecret.slice("inviteSecret_z".length));
}

const canRead = (
  group: RawGroup,
  key: RawAccountID | AgentID | "everyone",
): boolean => {
  const role = group.get(key);
  return (
    role === "admin" ||
    role === "manager" ||
    role === "writer" ||
    role === "reader" ||
    role === "adminInvite" ||
    role === "writerInvite" ||
    role === "readerInvite"
  );
};

class NoReadKeyAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoReadKeyAccessError";
  }
}

export function isSelfExtension(coValue: CoValueCore, parent: RawGroup) {
  const checkedGroups = new Set<string>();
  const queue = [parent];

  while (true) {
    const current = queue.pop();

    if (!current) {
      return false;
    }

    if (current.id === coValue.id) {
      return true;
    }

    checkedGroups.add(current.id);

    const parentGroups = current.getParentGroups();

    for (const parent of parentGroups) {
      if (!checkedGroups.has(parent.id)) {
        queue.push(parent);
      }
    }
  }
}
