import { beforeAll, describe, expect, test } from "vitest";
import { NapiCrypto } from "../crypto/NapiCrypto.js";
import { ShimNodeCore } from "../crypto/ShimNodeCore.js";
import { WasmCrypto } from "../crypto/WasmCrypto.js";
import type {
  CryptoProvider,
  NodeCoreImpl,
  SessionMapImpl,
} from "../crypto/crypto.js";
import type { RawCoID } from "../ids.js";

// RNCrypto now has a native NodeCore adapter (RNNodeCoreAdapter, mirroring
// NapiNodeCoreAdapter's casing bridge) — see Part B of the cleanup-phase
// plan. It can't be added to nodeCoreSuite here: `RNCrypto.create()` loads
// `cojson-core-rn`'s generated bindings, which register a React Native
// TurboModule (`NativeCojsonCoreRn` via `TurboModuleRegistry.getEnforcing`)
// at import time — that requires the RN runtime and cannot be instantiated
// under vitest/node. RN NodeCore capability is exercised by CI/e2e only
// (rn-build-reusable + the Maestro e2e run); `tsc --noEmit` covers
// RNNodeCoreAdapter's `NodeCoreImpl` conformance in the meantime. ShimNodeCore
// no longer has any production consumer (Napi/Wasm/RN all override
// `createNodeCore()`), but it's kept until Part C's deletion pass — its
// dispose-semantics tests below still exercise real behavior via a fake
// SessionMapImpl.
let crypto: CryptoProvider;
let wasmCrypto: CryptoProvider;

beforeAll(async () => {
  crypto = await NapiCrypto.create();
  wasmCrypto = await WasmCrypto.create();
});

function makeShim() {
  return new ShimNodeCore((coId, headerJson, maxTxSize, skipVerify) =>
    crypto.createSessionMap(coId as RawCoID, headerJson, maxTxSize, skipVerify),
  );
}

// Build a real header + coId the way VerifiedState does, so createCoValue
// passes native header validation.
function makeHeaderAndId(cryptoProvider: CryptoProvider = crypto) {
  const header = {
    type: "comap" as const,
    ruleset: { type: "unsafeAllowAll" as const },
    meta: null,
    createdAt: null,
    uniqueness: "test-uniqueness",
  };
  const coId = `co_z${cryptoProvider.shortHash(header).slice("shortHash_z".length)}`;
  return { coId, headerJson: JSON.stringify(header) };
}

function nodeCoreSuite(
  name: string,
  makeNodeCore: () => NodeCoreImpl,
  getCryptoProvider: () => CryptoProvider = () => crypto,
) {
  describe(name, () => {
    test("createCoValue / hasCoValue / removeCoValue roundtrip", () => {
      const shim = makeNodeCore();
      const { coId, headerJson } = makeHeaderAndId(getCryptoProvider());

      expect(shim.hasCoValue(coId)).toBe(false);
      expect(shim.coValueCount()).toBe(0);

      shim.createCoValue(coId, headerJson);
      expect(shim.hasCoValue(coId)).toBe(true);
      expect(shim.coValueCount()).toBe(1);
      expect(JSON.parse(shim.getHeader(coId))).toMatchObject({
        type: "comap",
      });

      shim.removeCoValue(coId);
      expect(shim.hasCoValue(coId)).toBe(false);
      expect(shim.coValueCount()).toBe(0);
      // double remove is a no-op
      shim.removeCoValue(coId);
    });

    test("unknown coId throws with Unknown CoValue message", () => {
      const shim = makeNodeCore();
      expect(() => shim.getHeader("co_zNope")).toThrow(
        /Unknown CoValue: co_zNope/,
      );
      expect(() => shim.getSessionIds("co_zNope")).toThrow(/Unknown CoValue/);
    });

    test("delegates session queries to the underlying session map", () => {
      const shim = makeNodeCore();
      const { coId, headerJson } = makeHeaderAndId(getCryptoProvider());
      shim.createCoValue(coId, headerJson);
      expect(shim.getSessionIds(coId)).toEqual([]);
      expect(shim.getTransactionCount(coId, "co_zAnybody_session_z123")).toBe(
        -1,
      );
      expect(shim.getKnownState(coId)).toMatchObject({
        id: coId,
        header: true,
        sessions: {},
      });
    });

    test("validateTransactions/resetValidation/roleOf capability signal", () => {
      const nodeCore = makeNodeCore();

      if (nodeCore.validateTransactions) {
        expect(typeof nodeCore.validateTransactions).toBe("function");
        expect(typeof nodeCore.resetValidation).toBe("function");
        expect(typeof nodeCore.roleOf).toBe("function");
        expect(() => nodeCore.validateTransactions!("co_zNope", [])).toThrow(
          /Unknown CoValue/,
        );
        expect(() => nodeCore.roleOf!("co_zNope", "someone")).toThrow(
          /Unknown CoValue/,
        );
        // resetValidation on an unregistered coId is a no-op, not an error.
        expect(() => nodeCore.resetValidation!("co_zNope")).not.toThrow();
      } else {
        expect(nodeCore.validateTransactions).toBeUndefined();
        expect(nodeCore.resetValidation).toBeUndefined();
        expect(nodeCore.roleOf).toBeUndefined();
      }
    });
  });
}

nodeCoreSuite("ShimNodeCore", () => makeShim());
nodeCoreSuite("NapiNodeCore (native)", () => crypto.createNodeCore());
nodeCoreSuite(
  "WasmNodeCore (native)",
  () => wasmCrypto.createNodeCore(),
  () => wasmCrypto,
);

test("NapiCrypto.createNodeCore returns the native adapter", () => {
  expect(crypto.createNodeCore().constructor.name).toBe("NapiNodeCoreAdapter");
});

test("WasmCrypto.createNodeCore returns the native adapter", () => {
  expect(wasmCrypto.createNodeCore().constructor.name).toBe(
    "WasmNodeCoreAdapter",
  );
});

describe("ShimNodeCore", () => {
  describe("dispose semantics", () => {
    function makeFakeShim() {
      let disposed = 0;
      let shouldThrow = false;
      const shim = new ShimNodeCore(() => {
        if (shouldThrow) {
          throw new Error("factory failed");
        }
        return {
          dispose: () => {
            disposed++;
          },
        } as unknown as SessionMapImpl;
      });
      return {
        shim,
        getDisposedCount: () => disposed,
        setShouldThrow: (value: boolean) => {
          shouldThrow = value;
        },
      };
    }

    test("dispose-once-on-remove: removeCoValue disposes exactly once, double-remove is a no-op", () => {
      const { shim, getDisposedCount } = makeFakeShim();
      const { coId, headerJson } = makeHeaderAndId();

      shim.createCoValue(coId, headerJson);
      expect(getDisposedCount()).toBe(0);

      shim.removeCoValue(coId);
      expect(getDisposedCount()).toBe(1);

      // Second remove must not double-dispose.
      shim.removeCoValue(coId);
      expect(getDisposedCount()).toBe(1);
    });

    test("dispose-of-replaced-on-recreate: recreating the same coId disposes only the replaced entry", () => {
      const { shim, getDisposedCount } = makeFakeShim();
      const { coId, headerJson } = makeHeaderAndId();

      shim.createCoValue(coId, headerJson);
      expect(getDisposedCount()).toBe(0);

      shim.createCoValue(coId, headerJson);
      expect(getDisposedCount()).toBe(1);
      expect(shim.hasCoValue(coId)).toBe(true);
    });

    test("no-dispose-when-factory-throws: throwing factory leaves the existing entry undisposed", () => {
      const { shim, getDisposedCount, setShouldThrow } = makeFakeShim();
      const { coId, headerJson } = makeHeaderAndId();

      shim.createCoValue(coId, headerJson);
      expect(getDisposedCount()).toBe(0);

      setShouldThrow(true);
      expect(() => shim.createCoValue(coId, headerJson)).toThrow(
        "factory failed",
      );

      expect(getDisposedCount()).toBe(0);
      expect(shim.hasCoValue(coId)).toBe(true);
    });
  });
});
