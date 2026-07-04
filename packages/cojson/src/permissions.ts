import { CoID } from "./coValue.js";
import { CoValueCore, VerifiedTransaction } from "./coValueCore/coValueCore.js";
import { RawAccount, RawAccountID, RawProfile } from "./coValues/account.js";
import { MapOpPayload, RawCoMap } from "./coValues/coMap.js";
import {
  EVERYONE,
  Everyone,
  ParentGroupReferenceRole,
  RawGroup,
  isInheritableRole,
  isSelfExtension,
} from "./coValues/group.js";
import {
  KeyID,
  NodeCoreGroupVerdict,
  NodeCoreImpl,
  NodeCorePendingTx,
  SealerID,
} from "./crypto/crypto.js";
import {
  AgentID,
  ParentGroupReference,
  RawCoID,
  getParentGroupId,
} from "./ids.js";
import { JsonValue } from "./jsonValue.js";
import { expectGroup } from "./typeUtils/expectGroup.js";

export type PermissionsDef =
  | { type: "group"; initialAdmin: RawAccountID | AgentID }
  | { type: "ownedByGroup"; group: RawCoID; restrictDeletion?: boolean }
  | { type: "unsafeAllowAll" };

export type AccountRole =
  /**
   * Can read the group's CoValues
   */
  | "reader"
  /**
   * Can read and write to the group's CoValues
   */
  | "writer"
  /**
   * Can read and write to the group, and change group member roles
   */
  | "admin"
  /**
   * Can read and write, invite and revoke members except admin
   */
  | "manager"
  /**
   * Can only write to the group's CoValues and read their own changes
   */
  | "writeOnly";

export type Role =
  | AccountRole
  | "revoked"
  | "managerInvite"
  | "adminInvite"
  | "writerInvite"
  | "readerInvite"
  | "writeOnlyInvite";

export function isAccountRole(role?: Role): role is AccountRole {
  return (
    role === "manager" ||
    role === "admin" ||
    role === "writer" ||
    role === "reader" ||
    role === "writeOnly"
  );
}

function canAdmin(role: Role | undefined): boolean {
  return role === "admin" || role === "manager";
}

/** Operational kill switch + differential-test escape hatch. */
export function nativeValidationDisabled(): boolean {
  return (
    (globalThis as { process?: { env?: Record<string, string> } }).process?.env
      ?.COJSON_DISABLE_NATIVE_VALIDATION === "1"
  );
}

export function determineValidTransactions(coValue: CoValueCore): void {
  if (!coValue.isAvailable()) {
    throw new Error("determineValidTransactions CoValue is not available");
  }

  const nodeCore = coValue.node.nodeCore;
  if (nodeCore.validateTransactions && !nativeValidationDisabled()) {
    // Native NodeCore validates ALL rulesets (group, ownedByGroup,
    // unsafeAllowAll). The TS dispatch below remains a byte-identical fallback
    // for providers without a native NodeCore, or when the kill switch is set.
    // Per-ruleset guards there (incl. the "Group must have initialAdmin"
    // throw) apply on the fallback path only — natively, a header missing
    // initialAdmin cannot even deserialize/register (fail-closed).
    determineValidTransactionsNative(coValue, nodeCore);
    return;
  }

  // The CoValue is a group
  if (coValue.verified.header.ruleset.type === "group") {
    const initialAdmin = coValue.verified.header.ruleset.initialAdmin;
    if (!initialAdmin) {
      throw new Error("Group must have initialAdmin");
    }

    determineValidTransactionsForGroup(coValue, initialAdmin);
    return;
  }

  // The CoValue is owned by a group
  if (coValue.verified.header.ruleset.type === "ownedByGroup") {
    const groupContent = expectGroup(
      coValue.node
        .expectCoValueLoaded(
          coValue.verified.header.ruleset.group,
          "Determining valid transaction in owned object but its group wasn't loaded",
        )
        .getCurrentContent(),
    );

    if (groupContent.type !== "comap") {
      throw new Error("Group must be a map");
    }

    for (const tx of coValue.toValidateTransactions) {
      // We use the original made at to get the group at the original time when the transaction was made
      // madeAt might be changed by the meta field (e.g. merged transactions), and so can't be used for permissions checks
      const groupAtTime = groupContent.atTime(tx.currentMadeAt);
      const effectiveTransactor = agentInAccountOrMemberInGroup(
        tx.author,
        groupAtTime,
      );

      if (!effectiveTransactor) {
        tx.markInvalid("Transactor not found in group", {
          transactor: tx.author,
          group: groupAtTime.toJSON(),
        });
        continue;
      }

      const transactorRoleAtTxTime =
        groupAtTime.roleOfInternal(effectiveTransactor);

      if (
        transactorRoleAtTxTime === "reader" &&
        tx.meta?.branch &&
        tx.meta?.ownerId
      ) {
        // Force the changes and meta to only contain the branch pointer information
        tx.meta = {
          branch: tx.meta.branch,
          ownerId: tx.meta.ownerId,
        };
        tx.changes = [];
        tx.markValid();
        continue;
      }

      if (
        transactorRoleAtTxTime !== "admin" &&
        transactorRoleAtTxTime !== "manager" &&
        transactorRoleAtTxTime !== "writer" &&
        transactorRoleAtTxTime !== "writeOnly"
      ) {
        tx.markInvalid("Transactor has no write permissions", {
          transactor: tx.author,
          transactorRole: transactorRoleAtTxTime ?? "undefined",
        });
        continue;
      }

      tx.markValid();
    }
    return;
  }

  // The CoValue has unsafeAllowAll ruleset
  if (coValue.verified.header.ruleset.type === "unsafeAllowAll") {
    for (const tx of coValue.toValidateTransactions) {
      tx.markValid();
    }
    return;
  }

  throw new Error(
    "Unknown ruleset type " +
      (coValue.verified.header.ruleset as { type: string }).type,
  );
}

function isHigherRole(a: Role, b: Role | undefined) {
  if (a === undefined || a === "revoked") return false;
  if (b === undefined || b === "revoked") return true;
  if (b === "admin") return false;
  if (a === "admin") return true;

  if (b === "manager") return false;
  if (a === "manager") return true;

  return a === "writer" && b === "reader";
}

class MemberRoleResolver {
  private parentGroups = new Map<RawGroup, ParentGroupReferenceRole>();
  private memberRoles = new Map<RawAccountID | AgentID | Everyone, Role>();

  setDirectRole(member: RawAccountID | AgentID | Everyone, role: Role) {
    this.memberRoles.set(member, role);
  }

  removeMember(member: RawAccountID | AgentID | Everyone) {
    this.memberRoles.delete(member);
  }

  addParentGroup(parentGroup: RawGroup, roleMapping: ParentGroupReferenceRole) {
    this.parentGroups.set(parentGroup, roleMapping);
  }

  removeParentGroup(parentGroup: RawGroup) {
    this.parentGroups.delete(parentGroup);
  }

  getDirectRole(member: RawAccountID | AgentID | Everyone) {
    return this.memberRoles.get(member);
  }

  getRoleAtTime(member: RawAccountID | AgentID | Everyone, time: number) {
    let role = this.memberRoles.get(member);

    for (const [parentGroup, roleMapping] of this.parentGroups.entries()) {
      const parentRole = parentGroup.atTime(time).roleOfInternal(member);

      if (!parentRole || !isInheritableRole(parentRole)) {
        continue;
      }

      const resolvedParentRole =
        roleMapping === "extend" ? parentRole : roleMapping;

      if (isHigherRole(resolvedParentRole, role)) {
        role = resolvedParentRole;
      }
    }

    return role;
  }
}

/**
 * Native counterpart of the whole {@link determineValidTransactions} dispatch:
 * NodeCore validates EVERY ruleset (group, ownedByGroup, unsafeAllowAll). The
 * registry already holds every transaction (ingested via addTransactions), so
 * `pending` carries ONLY the per-transaction extras native cannot recompute
 * itself:
 *   - `sourceMadeAt`: the TS-derived ordering override for merged/branch
 *     transactions (computed from merge meta in parseMetaInformation).
 *   - `sourceTxId`: the merged transaction's source identity in its branch.
 *   - `metaJson`: decrypted PRIVATE meta available NOW (private meta is not on
 *     the wire, so native can't read it; trusting meta IS wire-visible and must
 *     NOT be sent — native reads it itself).
 * A transaction contributes a pending entry only when it has at least one such
 * extra. Verdicts come back for ALL transactions in validation order and MUST
 * be applied in that order.
 */
function determineValidTransactionsNative(
  coValue: CoValueCore,
  nodeCore: NodeCoreImpl,
): void {
  const pending: NodeCorePendingTx[] = [];
  for (const tx of coValue.verifiedTransactions) {
    const entry: NodeCorePendingTx = {
      sessionId: tx.currentTxID.sessionID,
      txIndex: tx.currentTxID.txIndex,
    };
    let hasExtra = false;

    if (tx.sourceTxMadeAt !== undefined) {
      entry.sourceMadeAt = tx.sourceTxMadeAt;
      hasExtra = true;
    }

    if (tx.sourceTxID !== undefined) {
      entry.sourceTxId = {
        sessionID: tx.sourceTxID.sessionID,
        txIndex: tx.sourceTxID.txIndex,
      };
      hasExtra = true;
    }

    // Only PRIVATE meta is passed: it is not on the wire so native cannot read
    // it. `tx.meta` is populated for a private tx only once decrypted; trusting
    // meta is wire-visible and native reads it itself, so it must not be sent.
    if (tx.tx.privacy === "private" && tx.meta !== undefined) {
      entry.metaJson = JSON.stringify(tx.meta);
      hasExtra = true;
    }

    if (hasExtra) {
      pending.push(entry);
    }
  }

  // Missing-dependency error description differs per ruleset, matching the TS
  // fallback: an owned object throws about its owning group, everything else
  // (group parent extensions / owning account) about the parent group.
  const missingDependencyDescription =
    coValue.verified?.header.ruleset.type === "ownedByGroup"
      ? "Determining valid transaction in owned object but its group wasn't loaded"
      : "Expected parent group to be loaded";

  let verdicts: NodeCoreGroupVerdict[];
  try {
    verdicts = nodeCore.validateTransactions!(coValue.id, pending);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (message.startsWith("CoValue not loaded: ")) {
      // Dependency (parent group / owning group / owning account) missing from
      // the native registry — route through the canonical TS error path so
      // consumers see the same message the TS implementation produces.
      const missingId = message.slice("CoValue not loaded: ".length) as RawCoID;
      coValue.node.expectCoValueLoaded(missingId, missingDependencyDescription);
    }
    throw e;
  }

  // Apply verdicts ONLY to `toValidateTransactions` (the delta this pass is
  // responsible for) — mirroring the TS fallback's contract exactly (every
  // ruleset branch above iterates `coValue.toValidateTransactions`, never the
  // full `coValue.verifiedTransactions`). `pending` above still walks the full
  // history because Rust needs it for internal engine consistency, but
  // APPLYING a verdict to an already-settled transaction here would silently
  // overwrite TS-only, post-permission overlays that run after this function
  // returns (e.g. `parseMetaInformation`'s `fww` winner tracking, which calls
  // `markInvalid` on a previously-valid transaction the next time a
  // competing transaction arrives). Since native has no notion of `fww`, a
  // permission-only "valid" verdict for that transaction would erase the
  // overlay's invalidation on every subsequent pass. Restricting to the delta
  // makes native and TS agree: only freshly-arrived transactions get a
  // verdict applied here.
  const byKey = new Map<string, VerifiedTransaction>();
  for (const tx of coValue.toValidateTransactions) {
    byKey.set(`${tx.currentTxID.sessionID}/${tx.currentTxID.txIndex}`, tx);
  }
  // Apply IN THE ORDER RUST RETURNS (spec: dispatch order feeds downstream stable sorts)
  for (const v of verdicts) {
    const tx = byKey.get(`${v.sessionId}/${v.txIndex}`);
    if (!tx) continue; // verdict for a tx outside this pass's delta (already settled, or TS hasn't wrapped it yet)

    if (v.outcome === "validBranchPointerOnly") {
      // Mirror the reader branch-pointer trim in the TS ownedByGroup path:
      // force changes and meta to only contain the branch pointer information.
      tx.meta = {
        branch: tx.meta?.branch,
        ownerId: tx.meta?.ownerId,
      };
      tx.changes = [];
      tx.markValid();
    } else if (v.outcome === "invalid") {
      tx.markInvalid(v.reason ?? "Invalid transaction", {
        transactor: tx.author,
      });
    } else {
      tx.markValid();
    }
  }
}

function determineValidTransactionsForGroup(
  coValue: CoValueCore,
  initialAdmin: RawAccountID | AgentID,
): void {
  coValue.verifiedTransactions.sort(coValue.compareTransactions);

  const writeOnlyKeys: Record<RawAccountID | AgentID, KeyID> = {};
  const writeKeys = new Set<string>();
  const memberRoleResolver = new MemberRoleResolver();
  const isGroup = coValue.isGroup();

  for (const transaction of coValue.verifiedTransactions) {
    const transactor = transaction.author;

    const transactorRole = memberRoleResolver.getRoleAtTime(
      transactor,
      transaction.currentMadeAt,
    );

    const tx = transaction.tx;

    if (tx.privacy === "private") {
      if (isGroup) {
        transaction.markInvalid("Can't make private transactions in groups");
        continue;
      }

      if (transactorRole === "admin") {
        transaction.markValid();
        continue;
      } else {
        transaction.markInvalid(
          "Only admins can make private transactions in groups",
        );
        continue;
      }
    }

    const changes = transaction.changes;

    if (!changes) {
      continue;
    }

    const change = changes[0] as
      | MapOpPayload<RawAccountID | AgentID | Everyone, Role>
      | MapOpPayload<"readKey", JsonValue>
      | MapOpPayload<"groupSealer", SealerID>
      | MapOpPayload<"profile", CoID<RawProfile>>
      | MapOpPayload<"root", CoID<RawCoMap>>
      | MapOpPayload<`parent_${CoID<RawGroup>}`, CoID<RawGroup>>
      | MapOpPayload<`child_${CoID<RawGroup>}`, CoID<RawGroup>>;

    if (changes.length !== 1) {
      transaction.markInvalid("Group transaction must have exactly one change");
      continue;
    }

    if (change.op !== "set") {
      transaction.markInvalid("Group transaction must set a role or readKey");
      continue;
    }

    if (change.key === "readKey") {
      if (!canAdmin(transactorRole)) {
        transaction.markInvalid("Only admins can set readKeys");
        continue;
      }

      transaction.markValid();
      continue;
    } else if (change.key === "groupSealer") {
      if (!canAdmin(transactorRole)) {
        transaction.markInvalid("Only admins can set groupSealer");
        continue;
      }

      transaction.markValid();
      continue;
    } else if (change.key === "profile") {
      if (!canAdmin(transactorRole)) {
        transaction.markInvalid("Only admins can set profile");
        continue;
      }

      transaction.markValid();
      continue;
    } else if (change.key === "root") {
      if (!canAdmin(transactorRole)) {
        transaction.markInvalid("Only admins can set root");
        continue;
      }

      transaction.markValid();
      continue;
    } else if (
      isKeyForKeyField(change.key) ||
      isKeyForAccountField(change.key) ||
      isKeySealedForGroupField(change.key)
    ) {
      if (
        transactorRole !== "admin" &&
        transactorRole !== "adminInvite" &&
        transactorRole !== "manager" &&
        transactorRole !== "managerInvite" &&
        transactorRole !== "writerInvite" &&
        transactorRole !== "readerInvite" &&
        transactorRole !== "writeOnlyInvite" &&
        !isOwnWriteKeyRevelation(change.key, transactor, writeOnlyKeys)
      ) {
        transaction.markInvalid("Only admins and managers can reveal keys");
        continue;
      }

      transaction.markValid();
      continue;
    } else if (isParentExtension(change.key)) {
      if (!canAdmin(transactorRole)) {
        transaction.markInvalid(
          "Only admins and managers can set parent extensions",
        );
        continue;
      }

      const parentGroupId = getParentGroupId(change.key);

      const parentGroupCore = coValue.node.expectCoValueLoaded(
        parentGroupId,
        "Expected parent group to be loaded",
      );

      if (!parentGroupCore.isGroup()) {
        transaction.markInvalid("Parent group is not a group");
        continue;
      }

      const parentGroup = expectGroup(parentGroupCore.getCurrentContent());

      if (isSelfExtension(coValue, parentGroup)) {
        transaction.markInvalid("Parent group is a circular dependency");
        continue;
      }

      const value = change.value as ParentGroupReferenceRole;

      if (value === "revoked") {
        memberRoleResolver.removeParentGroup(parentGroup);
      } else {
        memberRoleResolver.addParentGroup(parentGroup, value);
      }

      transaction.markValid();
      continue;
    } else if (isChildExtension(change.key)) {
      transaction.markInvalid("Child extensions are not allowed anymore");
      continue;
    } else if (isWriteKeyForMember(change.key)) {
      const memberKey = getAccountOrAgentFromWriteKeyForMember(change.key);

      if (
        transactorRole !== "admin" &&
        transactorRole !== "manager" &&
        transactorRole !== "writeOnlyInvite" &&
        memberKey !== transactor
      ) {
        transaction.markInvalid("Only admins and managers can set writeKeys");
        continue;
      }

      writeOnlyKeys[memberKey] = change.value as KeyID;

      /**
       * writeOnlyInvite need to be able to set writeKeys because every new writeOnly
       * member comes with their own write key.
       *
       * We don't want to give the ability to invite members to override
       * write keys, otherwise they could hide a write key to other writeOnly users
       * blocking them from accessing the group.ß
       */
      if (writeKeys.has(change.key) && !canAdmin(transactorRole)) {
        transaction.markInvalid(
          "Write key already exists and can't be overridden by invite",
        );
        continue;
      }

      writeKeys.add(change.key);

      transaction.markValid();
      continue;
    }

    const affectedMember = change.key;
    const assignedRole = change.value;

    if (
      assignedRole !== "admin" &&
      assignedRole !== "manager" &&
      assignedRole !== "writer" &&
      assignedRole !== "reader" &&
      assignedRole !== "writeOnly" &&
      assignedRole !== "revoked" &&
      assignedRole !== "managerInvite" &&
      assignedRole !== "adminInvite" &&
      assignedRole !== "writerInvite" &&
      assignedRole !== "readerInvite" &&
      assignedRole !== "writeOnlyInvite"
    ) {
      transaction.markInvalid("Group transaction must set a valid role");
      continue;
    }

    if (
      affectedMember === EVERYONE &&
      !(
        assignedRole === "reader" ||
        assignedRole === "writer" ||
        assignedRole === "writeOnly" ||
        assignedRole === "revoked"
      )
    ) {
      transaction.markInvalid(
        "Everyone can only be set to reader, writer, writeOnly or revoked",
      );
      continue;
    }

    function markTransactionSetRoleAsValid(
      change: MapOpPayload<RawAccountID | AgentID | Everyone, Role>,
    ) {
      if (change.op !== "set") {
        throw new Error("Expected set operation");
      }

      memberRoleResolver.setDirectRole(change.key, change.value);
      transaction.markValid();
    }

    // is first self promotion to admin
    if (
      transactorRole === undefined &&
      transactor === initialAdmin &&
      affectedMember === transactor &&
      assignedRole === "admin"
    ) {
      markTransactionSetRoleAsValid(change);
      continue;
    }

    // if I'm self revoking, it is always valid
    if (transactor === change.key && change.value === "revoked") {
      markTransactionSetRoleAsValid(change);
      continue;
    }

    const affectedMemberRole = memberRoleResolver.getRoleAtTime(
      affectedMember,
      transaction.currentMadeAt,
    );

    /**
     * Admins can't:
     * - demote other admins
     */
    if (transactorRole === "admin") {
      if (
        affectedMemberRole === "admin" &&
        assignedRole !== "admin" &&
        affectedMember !== transactor
      ) {
        transaction.markInvalid("Admins can't demote admins.");
        continue;
      }

      markTransactionSetRoleAsValid(change);
      continue;
    }

    /**
     * Managers can't:
     * - demote other admins
     * - invite new admins
     * - promote to admin
     */
    if (transactorRole === "manager") {
      if (affectedMemberRole === "admin") {
        transaction.markInvalid("Managers can't demote admins.");
        continue;
      }
      if (change.value === "admin") {
        transaction.markInvalid("Managers can't promote to admin.");
        continue;
      }

      if (change.value === "adminInvite") {
        transaction.markInvalid("Managers can't invite admins.");
        continue;
      }
      if (change.value === "managerInvite") {
        transaction.markInvalid("Managers can't invite managers.");
        continue;
      }

      markTransactionSetRoleAsValid(change);
      continue;
    }

    if (transactorRole === "adminInvite") {
      if (change.value !== "admin") {
        transaction.markInvalid("AdminInvites can only create admins.");
        continue;
      }
    } else if (transactorRole === "managerInvite") {
      if (change.value !== "manager") {
        transaction.markInvalid("managerInvite can only create managers.");
        continue;
      }
    } else if (transactorRole === "writerInvite") {
      if (change.value !== "writer") {
        transaction.markInvalid("WriterInvites can only create writers.");
        continue;
      }
    } else if (transactorRole === "readerInvite") {
      if (change.value !== "reader") {
        transaction.markInvalid("ReaderInvites can only create reader.");
        continue;
      }
    } else if (transactorRole === "writeOnlyInvite") {
      if (change.value !== "writeOnly") {
        transaction.markInvalid("WriteOnlyInvites can only create writeOnly.");
        continue;
      }
    } else {
      transaction.markInvalid(
        "Group transaction must be made by current admin, manager, or invite",
      );
      continue;
    }

    memberRoleResolver.setDirectRole(affectedMember, change.value);
    transaction.markValid();
  }
}

function agentInAccountOrMemberInGroup(
  transactor: RawAccountID | AgentID,
  groupAtTime: RawGroup,
): RawAccountID | AgentID | undefined {
  if (transactor === groupAtTime.id && groupAtTime instanceof RawAccount) {
    return groupAtTime.currentAgentID();
  }
  return transactor;
}

export function isWriteKeyForMember(
  co: string,
): co is `writeKeyFor_${RawAccountID | AgentID}` {
  return co.startsWith("writeKeyFor_");
}

export function getAccountOrAgentFromWriteKeyForMember(
  co: `writeKeyFor_${RawAccountID | AgentID}`,
): RawAccountID | AgentID {
  return co.slice("writeKeyFor_".length) as RawAccountID | AgentID;
}

export function isKeyForKeyField(co: string): co is `${KeyID}_for_${KeyID}` {
  return co.startsWith("key_") && co.includes("_for_key");
}

export function isKeyForAccountField(
  co: string,
): co is `${KeyID}_for_${RawAccountID | AgentID}` {
  return (
    (co.startsWith("key_") &&
      (co.includes("_for_sealer") || co.includes("_for_co"))) ||
    co.includes("_for_everyone")
  );
}

export function isKeySealedForGroupField(
  co: string,
): co is `${KeyID}_sealedFor_${SealerID}` {
  return co.startsWith("key_") && co.includes("_sealedFor_sealer");
}

function isParentExtension(key: string): key is `parent_${CoID<RawGroup>}` {
  return key.startsWith("parent_");
}

function isChildExtension(key: string): key is `child_${CoID<RawGroup>}` {
  return key.startsWith("child_");
}

function isOwnWriteKeyRevelation(
  key: `${KeyID}_for_${string}` | `${KeyID}_sealedFor_${SealerID}`,
  memberKey: RawAccountID | AgentID,
  writeOnlyKeys: Record<RawAccountID | AgentID, KeyID>,
): key is
  | `${KeyID}_for_${RawAccountID | AgentID}`
  | `${KeyID}_sealedFor_${SealerID}` {
  let i = key.indexOf("_for_");
  if (i === -1) {
    i = key.indexOf("_sealedFor_");
  }

  const keyID = key.slice(0, i);

  if (!keyID) {
    return false;
  }

  return writeOnlyKeys[memberKey] === keyID;
}
