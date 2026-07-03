import type { Transaction } from "../coValueCore/verifiedState.js";
import type { NodeCoreImpl, SessionMapImpl } from "./crypto.js";

type SessionMapFactory = (
  coId: string,
  headerJson: string,
  maxTxSize?: number,
  skipVerify?: boolean,
) => SessionMapImpl;

/**
 * NodeCoreImpl implemented over per-CoValue SessionMapImpl objects.
 * Used by providers without a native NodeCore (wasm, RN) until their
 * native ports land. Mirrors the native registry's semantics exactly:
 * replace-on-create, no-op remove, "Unknown CoValue: <id>" on misses.
 */
export class ShimNodeCore implements NodeCoreImpl {
  private readonly covalues = new Map<string, SessionMapImpl>();

  constructor(private readonly createSessionMap: SessionMapFactory) {}

  private get(coId: string): SessionMapImpl {
    const entry = this.covalues.get(coId);
    if (!entry) {
      throw new Error(`Unknown CoValue: ${coId}`);
    }
    return entry;
  }

  createCoValue(
    coId: string,
    headerJson: string,
    maxTxSize?: number,
    skipVerify?: boolean,
  ): void {
    const replaced = this.covalues.get(coId);
    this.covalues.set(
      coId,
      this.createSessionMap(coId, headerJson, maxTxSize, skipVerify),
    );
    replaced?.dispose?.();
  }

  hasCoValue(coId: string): boolean {
    return this.covalues.has(coId);
  }

  removeCoValue(coId: string): void {
    const entry = this.covalues.get(coId);
    this.covalues.delete(coId);
    entry?.dispose?.();
  }

  coValueCount(): number {
    return this.covalues.size;
  }

  getHeader(coId: string): string {
    return this.get(coId).getHeader();
  }

  addTransactions(
    coId: string,
    sessionId: string,
    signerId: string | undefined,
    transactionsJson: string,
    signature: string,
    skipVerify: boolean,
  ): void {
    this.get(coId).addTransactions(
      sessionId,
      signerId,
      transactionsJson,
      signature,
      skipVerify,
    );
  }

  makeNewPrivateTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    keyId: string,
    keySecret: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string {
    return this.get(coId).makeNewPrivateTransaction(
      sessionId,
      signerSecret,
      changesJson,
      keyId,
      keySecret,
      metaJson,
      madeAt,
    );
  }

  makeNewTrustingTransaction(
    coId: string,
    sessionId: string,
    signerSecret: string,
    changesJson: string,
    metaJson: string | undefined,
    madeAt: number,
  ): string {
    return this.get(coId).makeNewTrustingTransaction(
      sessionId,
      signerSecret,
      changesJson,
      metaJson,
      madeAt,
    );
  }

  getSessionIds(coId: string): string[] {
    return this.get(coId).getSessionIds();
  }

  getTransactionCount(coId: string, sessionId: string): number {
    return this.get(coId).getTransactionCount(sessionId);
  }

  getTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): Transaction | undefined {
    return this.get(coId).getTransaction(sessionId, txIndex);
  }

  getSessionTransactions(
    coId: string,
    sessionId: string,
    fromIndex: number,
  ): Transaction[] | undefined {
    return this.get(coId).getSessionTransactions(sessionId, fromIndex);
  }

  getLastSignature(coId: string, sessionId: string): string | undefined {
    return this.get(coId).getLastSignature(sessionId);
  }

  getSignatureAfter(
    coId: string,
    sessionId: string,
    txIndex: number,
  ): string | undefined {
    return this.get(coId).getSignatureAfter(sessionId, txIndex);
  }

  getLastSignatureCheckpoint(
    coId: string,
    sessionId: string,
  ): number | undefined {
    return this.get(coId).getLastSignatureCheckpoint(sessionId);
  }

  getKnownState(coId: string): {
    id: string;
    header: boolean;
    sessions: Record<string, number>;
  } {
    return this.get(coId).getKnownState();
  }

  getKnownStateWithStreaming(
    coId: string,
  ):
    | { id: string; header: boolean; sessions: Record<string, number> }
    | undefined {
    return this.get(coId).getKnownStateWithStreaming();
  }

  isStreaming(coId: string): boolean {
    return this.get(coId).isStreaming();
  }

  setStreamingKnownState(coId: string, streamingJson: string): void {
    this.get(coId).setStreamingKnownState(streamingJson);
  }

  markAsDeleted(coId: string): void {
    this.get(coId).markAsDeleted();
  }

  isDeleted(coId: string): boolean {
    return this.get(coId).isDeleted();
  }

  decryptTransaction(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined {
    return this.get(coId).decryptTransaction(sessionId, txIndex, keySecret);
  }

  decryptTransactionMeta(
    coId: string,
    sessionId: string,
    txIndex: number,
    keySecret: string,
  ): string | undefined {
    return this.get(coId).decryptTransactionMeta(sessionId, txIndex, keySecret);
  }
}
