/* @ts-self-types="./cojson_core_wasm.d.ts" */
import { dumpWasmPanic } from './snippets/cojson-core-wasm-130f84f2109aae70/inline0.js';


export class Blake3Hasher {
    static __wrap(ptr) {
        const obj = Object.create(Blake3Hasher.prototype);
        obj.__wbg_ptr = ptr;
        Blake3HasherFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Blake3HasherFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_blake3hasher_free(ptr, 0);
    }
    /**
     * @returns {Blake3Hasher}
     */
    clone() {
        const ret = wasm.blake3hasher_clone(this.__wbg_ptr);
        return Blake3Hasher.__wrap(ret);
    }
    /**
     * @returns {Uint8Array}
     */
    finalize() {
        const ret = wasm.blake3hasher_finalize(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    constructor() {
        const ret = wasm.blake3hasher_new();
        this.__wbg_ptr = ret;
        Blake3HasherFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array | number[]} data
     */
    update(data) {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.blake3hasher_update(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) Blake3Hasher.prototype[Symbol.dispose] = Blake3Hasher.prototype.free;

export class SessionMap {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SessionMapFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_sessionmap_free(ptr, 0);
    }
    /**
     * Add transactions to a session
     * @param {string} session_id
     * @param {string | null | undefined} signer_id
     * @param {string} transactions_json
     * @param {string} signature
     * @param {boolean} skip_verify
     */
    addTransactions(session_id, signer_id, transactions_json, signature, skip_verify) {
        const val5 = +skip_verify;
        let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
        try {
            ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = isLikeNone(signer_id) ? 0 : passStringToWasm0(signer_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len1 = WASM_VECTOR_LEN;
            ptr2 = passStringToWasm0(transactions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len2 = WASM_VECTOR_LEN;
            ptr3 = passStringToWasm0(signature, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len3 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
            if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.sessionmap_addTransactions(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, val5);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Decrypt transaction meta
     * @param {string} session_id
     * @param {number} tx_index
     * @param {string} key_secret
     * @returns {string | undefined}
     */
    decryptTransactionMeta(session_id, tx_index, key_secret) {
        const val3 = +tx_index;
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passStringToWasm0(key_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.sessionmap_decryptTransactionMeta(this.__wbg_ptr, ptr0, len0, val3, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v4;
        if (ret[0] !== 0) {
            v4 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v4;
    }
    /**
     * Decrypt transaction changes
     * @param {string} session_id
     * @param {number} tx_index
     * @param {string} key_secret
     * @returns {string | undefined}
     */
    decryptTransaction(session_id, tx_index, key_secret) {
        const val3 = +tx_index;
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passStringToWasm0(key_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.sessionmap_decryptTransaction(this.__wbg_ptr, ptr0, len0, val3, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v4;
        if (ret[0] !== 0) {
            v4 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v4;
    }
    /**
     * Get the header as JSON
     * @returns {string}
     */
    getHeader() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.sessionmap_getHeader(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the known state with streaming as a native JavaScript object
     * @returns {any}
     */
    getKnownStateWithStreaming() {
        const ret = wasm.sessionmap_getKnownStateWithStreaming(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the known state as a native JavaScript object
     * @returns {any}
     */
    getKnownState() {
        const ret = wasm.sessionmap_getKnownState(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the last signature checkpoint index (-1 if no checkpoints, undefined if session not found)
     * @param {string} session_id
     * @returns {number | undefined}
     */
    getLastSignatureCheckpoint(session_id) {
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getLastSignatureCheckpoint(this.__wbg_ptr, ptr0, len0);
        return ret === Number.MAX_SAFE_INTEGER ? undefined : ret;
    }
    /**
     * Get last signature for a session (returns undefined if session not found)
     * @param {string} session_id
     * @returns {string | undefined}
     */
    getLastSignature(session_id) {
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getLastSignature(this.__wbg_ptr, ptr0, len0);
        let v2;
        if (ret[0] !== 0) {
            v2 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v2;
    }
    /**
     * Get all session IDs as native array
     * @returns {string[]}
     */
    getSessionIds() {
        const ret = wasm.sessionmap_getSessionIds(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]);
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * Get transactions for a session from index as JSON strings (returns undefined if session not found)
     * @param {string} session_id
     * @param {number} from_index
     * @returns {string[] | undefined}
     */
    getSessionTransactions(session_id, from_index) {
        const val2 = +from_index;
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getSessionTransactions(this.__wbg_ptr, ptr0, len0, val2);
        let v3;
        if (ret[0] !== 0) {
            v3 = getArrayJsValueFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        }
        return v3;
    }
    /**
     * Get signature after specific transaction index
     * @param {string} session_id
     * @param {number} tx_index
     * @returns {string | undefined}
     */
    getSignatureAfter(session_id, tx_index) {
        const val2 = +tx_index;
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getSignatureAfter(this.__wbg_ptr, ptr0, len0, val2);
        let v3;
        if (ret[0] !== 0) {
            v3 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v3;
    }
    /**
     * Get transaction count for a session (returns -1 if session not found)
     * @param {string} session_id
     * @returns {number}
     */
    getTransactionCount(session_id) {
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getTransactionCount(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Get single transaction by index as JSON string (returns undefined if not found)
     * @param {string} session_id
     * @param {number} tx_index
     * @returns {string | undefined}
     */
    getTransaction(session_id, tx_index) {
        const val2 = +tx_index;
        const ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_getTransaction(this.__wbg_ptr, ptr0, len0, val2);
        let v3;
        if (ret[0] !== 0) {
            v3 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v3;
    }
    /**
     * Check if this CoValue is deleted
     * @returns {boolean}
     */
    isDeleted() {
        const ret = wasm.sessionmap_isDeleted(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Check whether the CoValue still has pending streaming content.
     * @returns {boolean}
     */
    isStreaming() {
        const ret = wasm.sessionmap_isStreaming(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Create new private transaction (for local writes)
     * Returns JSON: { signature: string, transaction: Transaction }
     * @param {string} session_id
     * @param {string} signer_secret
     * @param {string} changes_json
     * @param {string} key_id
     * @param {string} key_secret
     * @param {string | null | undefined} meta_json
     * @param {number} made_at
     * @returns {string}
     */
    makeNewPrivateTransaction(session_id, signer_secret, changes_json, key_id, key_secret, meta_json, made_at) {
        let deferred9_0;
        let deferred9_1;
        try {
            const val7 = +made_at;
            let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5;
            try {
                ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len0 = WASM_VECTOR_LEN;
                ptr1 = passStringToWasm0(signer_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len1 = WASM_VECTOR_LEN;
                ptr2 = passStringToWasm0(changes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len2 = WASM_VECTOR_LEN;
                ptr3 = passStringToWasm0(key_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len3 = WASM_VECTOR_LEN;
                ptr4 = passStringToWasm0(key_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len4 = WASM_VECTOR_LEN;
                ptr5 = isLikeNone(meta_json) ? 0 : passStringToWasm0(meta_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len5 = WASM_VECTOR_LEN;
            } catch (e) {
                if (ptr5) { wasm.__wbindgen_free(ptr5, len5 * 1, 1); }
                if (ptr4) { wasm.__wbindgen_free(ptr4, len4 * 1, 1); }
                if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
                if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
                if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
                if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
                throw e;
            }
            const ret = wasm.sessionmap_makeNewPrivateTransaction(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, val7);
            var ptr8 = ret[0];
            var len8 = ret[1];
            if (ret[3]) {
                ptr8 = 0; len8 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred9_0 = ptr8;
            deferred9_1 = len8;
            return getStringFromWasm0(ptr8, len8);
        } finally {
            wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
        }
    }
    /**
     * Create new trusting transaction (for local writes)
     * Returns JSON: { signature: string, transaction: Transaction }
     * @param {string} session_id
     * @param {string} signer_secret
     * @param {string} changes_json
     * @param {string | null | undefined} meta_json
     * @param {number} made_at
     * @returns {string}
     */
    makeNewTrustingTransaction(session_id, signer_secret, changes_json, meta_json, made_at) {
        let deferred7_0;
        let deferred7_1;
        try {
            const val5 = +made_at;
            let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
            try {
                ptr0 = passStringToWasm0(session_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len0 = WASM_VECTOR_LEN;
                ptr1 = passStringToWasm0(signer_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len1 = WASM_VECTOR_LEN;
                ptr2 = passStringToWasm0(changes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len2 = WASM_VECTOR_LEN;
                ptr3 = isLikeNone(meta_json) ? 0 : passStringToWasm0(meta_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
                len3 = WASM_VECTOR_LEN;
            } catch (e) {
                if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
                if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
                if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
                if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
                throw e;
            }
            const ret = wasm.sessionmap_makeNewTrustingTransaction(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, val5);
            var ptr6 = ret[0];
            var len6 = ret[1];
            if (ret[3]) {
                ptr6 = 0; len6 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred7_0 = ptr6;
            deferred7_1 = len6;
            return getStringFromWasm0(ptr6, len6);
        } finally {
            wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
        }
    }
    /**
     * Mark this CoValue as deleted
     */
    markAsDeleted() {
        wasm.sessionmap_markAsDeleted(this.__wbg_ptr);
    }
    /**
     * Create a new SessionMap for a CoValue
     * `max_tx_size` is the threshold for recording in-between signatures (default: 100KB)
     * Create a new SessionMap for a CoValue.
     * Validates the header and verifies that `co_id` matches the hash of the header.
     * `max_tx_size` is the threshold for recording in-between signatures (default: 100KB)
     * `skip_verify` if true, skips uniqueness and ID validation (for trusted storage shards)
     * @param {string} co_id
     * @param {string} header_json
     * @param {number | null} [max_tx_size]
     * @param {boolean | null} [skip_verify]
     */
    constructor(co_id, header_json, max_tx_size, skip_verify) {
        const val3 = +(isLikeNone(max_tx_size) ? Number.MAX_SAFE_INTEGER : (max_tx_size) >>> 0);
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passStringToWasm0(co_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passStringToWasm0(header_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.sessionmap_new(ptr0, len0, ptr1, len1, val3, isLikeNone(skip_verify) ? 0xFFFFFF : skip_verify ? 1 : 0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        SessionMapFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Set streaming known state
     * @param {string} streaming_json
     */
    setStreamingKnownState(streaming_json) {
        const ptr0 = passStringToWasm0(streaming_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sessionmap_setStreamingKnownState(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) SessionMap.prototype[Symbol.dispose] = SessionMap.prototype.free;

/**
 * Hash data once using BLAKE3.
 * - `data`: Raw bytes to hash
 * Returns 32 bytes of hash output.
 * This is the simplest way to compute a BLAKE3 hash of a single piece of data.
 * @param {Uint8Array | number[]} data
 * @returns {Uint8Array}
 */
export function blake3HashOnce(data) {
    const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.blake3HashOnce(ptr0, len0);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Hash data once using BLAKE3 with a context prefix.
 * - `data`: Raw bytes to hash
 * - `context`: Context bytes to prefix to the data
 * Returns 32 bytes of hash output.
 * This is useful for domain separation - the same data hashed with different contexts will produce different outputs.
 * @param {Uint8Array | number[]} data
 * @param {Uint8Array | number[]} context
 * @returns {Uint8Array}
 */
export function blake3HashOnceWithContext(data, context) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.blake3HashOnceWithContext(ptr0, len0, ptr1, len1);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * WASM-exposed function to decrypt bytes with a key secret and nonce material.
 * - `ciphertext`: The encrypted bytes to decrypt
 * - `key_secret`: A base58-encoded key secret with "keySecret_z" prefix
 * - `nonce_material`: Raw bytes used to generate the nonce (must match encryption)
 * Returns the decrypted bytes or throws a JsError if decryption fails.
 * @param {Uint8Array | number[]} ciphertext
 * @param {string} key_secret
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function decrypt(ciphertext, key_secret, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(key_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decrypt(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * WASM-exposed function for XSalsa20 decryption without authentication.
 * - `key`: 32-byte key for decryption (must match encryption key)
 * - `nonce_material`: Raw bytes used to generate a 24-byte nonce (must match encryption)
 * - `ciphertext`: Encrypted bytes to decrypt
 * Returns the decrypted bytes or throws a JsError if decryption fails.
 * Note: This function does not provide authentication. Use decrypt_xsalsa20_poly1305 for authenticated decryption.
 * @param {Uint8Array | number[]} key
 * @param {Uint8Array | number[]} nonce_material
 * @param {Uint8Array | number[]} ciphertext
 * @returns {Uint8Array}
 */
export function decryptXsalsa20(key, nonce_material, ciphertext) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decryptXsalsa20(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * WASM-exposed function to sign a message using Ed25519.
 * - `signing_key`: 32 bytes of signing key material
 * - `message`: Raw bytes to sign
 * Returns 64 bytes of signature material or throws JsError if signing fails.
 * @param {Uint8Array | number[]} signing_key
 * @param {Uint8Array | number[]} message
 * @returns {Uint8Array}
 */
export function ed25519Sign(signing_key, message) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(signing_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.ed25519Sign(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * WASM-exposed function to validate and copy Ed25519 signature bytes.
 * - `bytes`: 64 bytes of signature material to validate
 * Returns the same 64 bytes if valid or throws JsError if invalid.
 * @param {Uint8Array | number[]} bytes
 * @returns {Uint8Array}
 */
export function ed25519SignatureFromBytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519SignatureFromBytes(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to validate and copy Ed25519 signing key bytes.
 * - `bytes`: 32 bytes of signing key material to validate
 * Returns the same 32 bytes if valid or throws JsError if invalid.
 * @param {Uint8Array | number[]} bytes
 * @returns {Uint8Array}
 */
export function ed25519SigningKeyFromBytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519SigningKeyFromBytes(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to sign a message with an Ed25519 signing key.
 * - `signing_key`: 32 bytes of signing key material
 * - `message`: Raw bytes to sign
 * Returns 64 bytes of signature material or throws JsError if signing fails.
 * @param {Uint8Array | number[]} signing_key
 * @param {Uint8Array | number[]} message
 * @returns {Uint8Array}
 */
export function ed25519SigningKeySign(signing_key, message) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(signing_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.ed25519SigningKeySign(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * WASM-exposed function to derive the public key from an Ed25519 signing key.
 * - `signing_key`: 32 bytes of signing key material
 * Returns 32 bytes of public key material or throws JsError if key is invalid.
 * @param {Uint8Array | number[]} signing_key
 * @returns {Uint8Array}
 */
export function ed25519SigningKeyToPublic(signing_key) {
    const ptr0 = passArray8ToWasm0(signing_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519SigningKeyToPublic(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to verify an Ed25519 signature.
 * - `verifying_key`: 32 bytes of verifying key material
 * - `message`: Raw bytes that were signed
 * - `signature`: 64 bytes of signature material
 * Returns true if signature is valid, false otherwise, or throws JsError if verification fails.
 * @param {Uint8Array | number[]} verifying_key
 * @param {Uint8Array | number[]} message
 * @param {Uint8Array | number[]} signature
 * @returns {boolean}
 */
export function ed25519Verify(verifying_key, message, signature) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(verifying_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.ed25519Verify(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * WASM-exposed function to derive an Ed25519 verifying key from a signing key.
 * - `signing_key`: 32 bytes of signing key material
 * Returns 32 bytes of verifying key material or throws JsError if key is invalid.
 * @param {Uint8Array | number[]} signing_key
 * @returns {Uint8Array}
 */
export function ed25519VerifyingKey(signing_key) {
    const ptr0 = passArray8ToWasm0(signing_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519VerifyingKey(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to validate and copy Ed25519 verifying key bytes.
 * - `bytes`: 32 bytes of verifying key material to validate
 * Returns the same 32 bytes if valid or throws JsError if invalid.
 * @param {Uint8Array | number[]} bytes
 * @returns {Uint8Array}
 */
export function ed25519VerifyingKeyFromBytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ed25519VerifyingKeyFromBytes(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to encrypt bytes with a key secret and nonce material.
 * - `value`: The raw bytes to encrypt
 * - `key_secret`: A base58-encoded key secret with "keySecret_z" prefix
 * - `nonce_material`: Raw bytes used to generate the nonce
 * Returns the encrypted bytes or throws a JsError if encryption fails.
 * @param {Uint8Array | number[]} value
 * @param {string} key_secret
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function encrypt(value, key_secret, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(value, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(key_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encrypt(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * WASM-exposed function for XSalsa20 encryption without authentication.
 * - `key`: 32-byte key for encryption
 * - `nonce_material`: Raw bytes used to generate a 24-byte nonce via BLAKE3
 * - `plaintext`: Raw bytes to encrypt
 * Returns the encrypted bytes or throws a JsError if encryption fails.
 * Note: This function does not provide authentication. Use encrypt_xsalsa20_poly1305 for authenticated encryption.
 * @param {Uint8Array | number[]} key
 * @param {Uint8Array | number[]} nonce_material
 * @param {Uint8Array | number[]} plaintext
 * @returns {Uint8Array}
 */
export function encryptXsalsa20(key, nonce_material, plaintext) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encryptXsalsa20(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Generate a 24-byte nonce from input material using BLAKE3.
 * - `nonce_material`: Raw bytes to derive the nonce from
 * Returns 24 bytes suitable for use as a nonce in cryptographic operations.
 * This function is deterministic - the same input will produce the same nonce.
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function generateNonce(nonce_material) {
    const ptr0 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generateNonce(ptr0, len0);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * WASM-exposed function to derive a sealer ID from a sealer secret.
 * - `secret`: Raw bytes of the sealer secret
 * Returns a base58-encoded sealer ID with "sealer_z" prefix or throws JsError if derivation fails.
 * @param {Uint8Array | number[]} secret
 * @returns {string}
 */
export function getSealerId(secret) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.getSealerId(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * WASM-exposed function to derive a signer ID from a signing key.
 * - `secret`: Raw Ed25519 signing key bytes
 * Returns base58-encoded verifying key with "signer_z" prefix or throws JsError if derivation fails.
 * @param {Uint8Array | number[]} secret
 * @returns {string}
 */
export function getSignerId(secret) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.getSignerId(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

export function init() {
    wasm.init();
}

/**
 * Generate a new Ed25519 signing key using secure random number generation.
 * Returns 32 bytes of raw key material suitable for use with other Ed25519 functions.
 * @returns {Uint8Array}
 */
export function newEd25519SigningKey() {
    const ret = wasm.newEd25519SigningKey();
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Generate a new X25519 private key using secure random number generation.
 * Returns 32 bytes of raw key material suitable for use with other X25519 functions.
 * This key can be reused for multiple Diffie-Hellman exchanges.
 * @returns {Uint8Array}
 */
export function newX25519PrivateKey() {
    const ret = wasm.newX25519PrivateKey();
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * WASM-exposed function for sealing a message using X25519 + XSalsa20-Poly1305.
 * Provides authenticated encryption with perfect forward secrecy.
 * - `message`: Raw bytes to seal
 * - `sender_secret`: Base58-encoded sender's private key with "sealerSecret_z" prefix
 * - `recipient_id`: Base58-encoded recipient's public key with "sealer_z" prefix
 * - `nonce_material`: Raw bytes used to generate the nonce
 * Returns sealed bytes or throws JsError if sealing fails.
 * @param {Uint8Array | number[]} message
 * @param {string} sender_secret
 * @param {string} recipient_id
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function seal(message, sender_secret, recipient_id, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(sender_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(recipient_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.seal(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * WASM-exposed function for sealing a message for a group (anonymous box pattern).
 * Uses an ephemeral key pair, so no sender authentication is provided.
 * - `message`: Raw bytes to seal
 * - `recipient_id`: Base58-encoded recipient's public key with "sealer_z" prefix (the group's sealer)
 * - `nonce_material`: Raw bytes used to generate the nonce
 * Returns ephemeral_public_key (32 bytes) || ciphertext, or throws JsError if sealing fails.
 * @param {Uint8Array | number[]} message
 * @param {string} recipient_id
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function sealForGroup(message, recipient_id, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(recipient_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.sealForGroup(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Compute a short hash of a stable-stringified JSON value.
 * The input should already be serialized using stableStringify on the JS side.
 * Returns a string prefixed with "shortHash_z" followed by base58-encoded hash.
 * @param {string} value
 * @returns {string}
 */
export function shortHash(value) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.shortHash(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * WASM-exposed function to sign a message using Ed25519.
 * - `message`: Raw bytes to sign
 * - `secret`: Raw Ed25519 signing key bytes
 * Returns base58-encoded signature with "signature_z" prefix or throws JsError if signing fails.
 * @param {Uint8Array | number[]} message
 * @param {Uint8Array | number[]} secret
 * @returns {string}
 */
export function sign(message, secret) {
    let deferred4_0;
    let deferred4_1;
    try {
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.sign(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * WASM-exposed function for unsealing a message using X25519 + XSalsa20-Poly1305.
 * Provides authenticated decryption with perfect forward secrecy.
 * - `sealed_message`: The sealed bytes to decrypt
 * - `recipient_secret`: Base58-encoded recipient's private key with "sealerSecret_z" prefix
 * - `sender_id`: Base58-encoded sender's public key with "sealer_z" prefix
 * - `nonce_material`: Raw bytes used to generate the nonce (must match sealing)
 * Returns unsealed bytes or throws JsError if unsealing fails.
 * @param {Uint8Array | number[]} sealed_message
 * @param {string} recipient_secret
 * @param {string} sender_id
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function unseal(sealed_message, recipient_secret, sender_id, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(sealed_message, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(recipient_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(sender_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.unseal(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * WASM-exposed function for unsealing a message sealed for a group (anonymous box pattern).
 * Extracts the ephemeral public key and decrypts the message.
 * - `sealed_message`: ephemeral_public_key (32 bytes) || ciphertext
 * - `recipient_secret`: Base58-encoded recipient's private key with "sealerSecret_z" prefix
 * - `nonce_material`: Raw bytes used to generate the nonce (must match sealing)
 * Returns unsealed bytes or throws JsError if unsealing fails.
 * @param {Uint8Array | number[]} sealed_message
 * @param {string} recipient_secret
 * @param {Uint8Array | number[]} nonce_material
 * @returns {Uint8Array}
 */
export function unsealForGroup(sealed_message, recipient_secret, nonce_material) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(sealed_message, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(recipient_secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(nonce_material, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.unsealForGroup(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * WASM-exposed function to verify an Ed25519 signature.
 * - `signature`: Raw signature bytes
 * - `message`: Raw bytes that were signed
 * - `id`: Raw Ed25519 verifying key bytes
 * Returns true if signature is valid, false otherwise, or throws JsError if verification fails.
 * @param {Uint8Array | number[]} signature
 * @param {Uint8Array | number[]} message
 * @param {Uint8Array | number[]} id
 * @returns {boolean}
 */
export function verify(signature, message, id) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(id, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.verify(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * WASM-exposed function to perform X25519 Diffie-Hellman key exchange.
 * - `private_key`: 32 bytes of private key material
 * - `public_key`: 32 bytes of public key material
 * Returns 32 bytes of shared secret material or throws JsError if key exchange fails.
 * @param {Uint8Array | number[]} private_key
 * @param {Uint8Array | number[]} public_key
 * @returns {Uint8Array}
 */
export function x25519DiffieHellman(private_key, public_key) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.x25519DiffieHellman(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * WASM-exposed function to derive an X25519 public key from a private key.
 * - `private_key`: 32 bytes of private key material
 * Returns 32 bytes of public key material or throws JsError if key is invalid.
 * @param {Uint8Array | number[]} private_key
 * @returns {Uint8Array}
 */
export function x25519PublicKey(private_key) {
    const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.x25519PublicKey(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_208446807d0d1e30: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 1, len1, true);
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_debug_string_f249a2a76caa9a55: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 1, len1, true);
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_741ff2bb612836f5: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_8b968c3ab8e96595: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_fc456fee5d3317de: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_be5b34249ff1fc15: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_4c88d8bf264fd984: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_a410eb4b59ed5965: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_631eea7dbeef47f0: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_dumpWasmPanic_1813313d03ad909f: function(arg0, arg1) {
            dumpWasmPanic(getStringFromWasm0(arg0, arg1));
        },
        __wbg_error_757e9472f8410341: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_6f30f3c706426ebc: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_186163212ffe79c3: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_d857fa672421ff36: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_7075786089b89c5e: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_bb74001155cb8ca8: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_cd4348290afae586: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_with_length_01b143a7e5dd5a3e: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_ac74ca8a6c82c88b: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_a5257baeeee95a4a: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_13162965d1fe7aa3: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_d5f99df0cf6ef00b: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_15af88864162fe05: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_set_8282f7e0d2d01336: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_e4b9a833d288759a: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_stack_575c4e0918581b9c: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 1, len1, true);
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_003ee833af9699fc: function() {
            const ret = typeof globalThis === 'undefined' ? undefined : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_e4293fb22cbe77da: function() {
            const ret = typeof global === 'undefined' ? undefined : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_53bb20457401453d: function() {
            const ret = typeof self === 'undefined' ? undefined : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_b5e0810bfecb7feb: function() {
            const ret = typeof window === 'undefined' ? undefined : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_58f388a9247ac0bb: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_cb104e72dd1aa377: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_generic_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_generic_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_generic_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            table.set(0, undefined);
            table.set(1024, undefined);
            table.set(1025, null);
            table.set(1026, true);
            table.set(1027, false);
        },
    };
    return {
        __proto__: null,
        "./cojson_core_wasm_bg.js": import0,
    };
}

const Blake3HasherFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_blake3hasher_free(ptr, 1));
const SessionMapFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_sessionmap_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function debugString(val) {
    switch (typeof val) {
        // primitive types
        case 'number':
        case 'boolean':
        case 'undefined':
        return `${val}`;
        case 'string':
        return JSON.stringify(val);
        case 'bigint':
        return `${val}n`;
        case 'symbol':
        return val.description !== undefined
            ? `Symbol(${val.description})`
            : 'Symbol';
        case 'function':
        return typeof val.name === 'string' && val.name !== ''
            ? `Function(${val.name})`
            : 'Function';
        case 'object': {
            if (val === null) {
                return 'null';
            }
            // objects
            if (Array.isArray(val)) {
                return '[' + Array.from(val, debugString).join(', ') + ']';
            }
            // errors
            if (val instanceof Error) {
                return `${val.name}: ${val.message}\n${val.stack}`;
            }

            const toStringOutput = toString.call(val);
            // Test for built-in
            const className = /\[object ([^\]]+)\]/.exec(toStringOutput)?.[1];

            // Failed to match the standard '[object ClassName]'
            if (className === undefined) {
                return toStringOutput;
            }
            if (className === 'Object') {
                // we're a user defined class or Object
                // JSON.stringify avoids problems with cycles, and is generally much
                // easier than looping through ownProperties of `val`.
                try {
                    return 'Object(' + JSON.stringify(val) + ')';
                } catch (_) {
                    return 'Object';
                }
            }
            // TODO we could test for more things here, like `Set`s and `Map`s.
            return className;
        }
        // Per MDN: 'This list of values is exhaustive.'
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/typeof#description
    }
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(bytes) {
    numBytesDecoded += bytes.length;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
        cachedTextDecoder.decode();
        numBytesDecoded = bytes.length;
    }
    return cachedTextDecoder.decode(bytes);
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

let __wbg_init_promise;
async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;
    if (__wbg_init_promise === undefined) {
        __wbg_init_promise = __wbg_init_once(module_or_path);
        __wbg_init_promise.catch(() => { __wbg_init_promise = undefined; });
    }
    return __wbg_init_promise;
}

async function __wbg_init_once(module_or_path) {

    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        throw new Error();
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
