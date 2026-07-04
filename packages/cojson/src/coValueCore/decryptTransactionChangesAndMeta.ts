import { KeySecret } from "../crypto/crypto.js";
import { SessionID } from "../ids.js";
import { AvailableCoValueCore, VerifiedTransaction } from "./coValueCore.js";

export function decryptTransactionChangesAndMeta(
  coValue: AvailableCoValueCore,
  transaction: VerifiedTransaction,
) {
  if (
    !transaction.isValid ||
    transaction.tx.privacy === "trusting" // Trusting transactions are already decrypted
  ) {
    return;
  }

  const needsChagesParsing = !transaction.changes;
  const needsMetaParsing = !transaction.meta && transaction.tx.meta;

  if (!needsChagesParsing && !needsMetaParsing) {
    return;
  }

  const readKey = coValue.getReadKey(transaction.tx.keyUsed);

  if (!readKey) {
    return;
  }

  if (needsChagesParsing) {
    const changes = coValue.verified.decryptTransaction(
      transaction.txID.sessionID,
      transaction.txID.txIndex,
      readKey,
    );

    if (changes) {
      transaction.changes = changes;
    }
  }

  if (needsMetaParsing) {
    const meta = coValue.verified.decryptTransactionMeta(
      transaction.txID.sessionID,
      transaction.txID.txIndex,
      readKey,
    );

    if (meta) {
      transaction.meta = meta;
    }
  }
}

/**
 * Batched equivalent of running `decryptTransactionChangesAndMeta` over a list
 * of transactions. Changes decryption is grouped by (sessionID, readKey) and
 * dispatched to the native batch fast path with a single FFI call per group;
 * meta decryption stays per-transaction (meta is rare).
 *
 * Preserves the exact per-transaction semantics of
 * `decryptTransactionChangesAndMeta`: transactions are skipped when invalid,
 * trusting, or already parsed; a missing read key leaves them undecrypted; and
 * a per-transaction decrypt failure leaves `changes` unset. When the native
 * batch method is unavailable it transparently falls back to the
 * per-transaction path.
 */
export function batchDecryptTransactionChangesAndMeta(
  coValue: AvailableCoValueCore,
  transactions: VerifiedTransaction[],
) {
  type Group = {
    sessionID: SessionID;
    keySecret: KeySecret;
    transactions: VerifiedTransaction[];
    indices: number[];
  };

  // Groups of changes-needing transactions, keyed by (sessionID, readKey id),
  // in first-seen order so the batch preserves the original ordering.
  const groups = new Map<string, Group>();

  for (const transaction of transactions) {
    if (!transaction.isValid || transaction.tx.privacy === "trusting") {
      continue;
    }

    const needsChangesParsing = !transaction.changes;
    const needsMetaParsing = !transaction.meta && transaction.tx.meta;

    if (!needsChangesParsing && !needsMetaParsing) {
      continue;
    }

    const readKey = coValue.getReadKey(transaction.tx.keyUsed);

    if (!readKey) {
      continue;
    }

    if (needsChangesParsing) {
      const sessionID = transaction.txID.sessionID;
      const keyID = transaction.tx.keyUsed;
      const groupKey = `${sessionID}\n${keyID}`;
      let group = groups.get(groupKey);
      if (!group) {
        group = {
          sessionID,
          keySecret: readKey,
          transactions: [],
          indices: [],
        };
        groups.set(groupKey, group);
      }
      group.transactions.push(transaction);
      group.indices.push(transaction.txID.txIndex);
    }

    // Meta is rare, so keep it on the per-transaction path.
    if (needsMetaParsing) {
      const meta = coValue.verified.decryptTransactionMeta(
        transaction.txID.sessionID,
        transaction.txID.txIndex,
        readKey,
      );

      if (meta) {
        transaction.meta = meta;
      }
    }
  }

  for (const group of groups.values()) {
    const results = coValue.verified.decryptTransactionsBatch(
      group.sessionID,
      group.indices,
      group.keySecret,
    );

    if (!results) {
      // No native batch support: fall back to the per-transaction path.
      // Meta was already handled above, so this only decrypts changes.
      for (const transaction of group.transactions) {
        decryptTransactionChangesAndMeta(coValue, transaction);
      }
      continue;
    }

    for (let i = 0; i < group.transactions.length; i++) {
      const changes = results[i];
      if (changes) {
        group.transactions[i]!.changes = changes;
      }
    }
  }
}
