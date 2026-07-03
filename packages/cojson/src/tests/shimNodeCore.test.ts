import { beforeAll, describe, expect, test } from "vitest";
import { NapiCrypto } from "../crypto/NapiCrypto.js";
import { ShimNodeCore } from "../crypto/ShimNodeCore.js";
import type { CryptoProvider, SessionMapImpl } from "../crypto/crypto.js";
import type { RawCoID } from "../ids.js";

let crypto: CryptoProvider;

beforeAll(async () => {
  crypto = await NapiCrypto.create();
});

function makeShim() {
  return new ShimNodeCore((coId, headerJson, maxTxSize, skipVerify) =>
    crypto.createSessionMap(coId as RawCoID, headerJson, maxTxSize, skipVerify),
  );
}

// Build a real header + coId the way VerifiedState does, so createCoValue
// passes native header validation.
function makeHeaderAndId() {
  const header = {
    type: "comap" as const,
    ruleset: { type: "unsafeAllowAll" as const },
    meta: null,
    createdAt: null,
    uniqueness: "test-uniqueness",
  };
  const coId = `co_z${crypto.shortHash(header).slice("shortHash_z".length)}`;
  return { coId, headerJson: JSON.stringify(header) };
}

describe("ShimNodeCore", () => {
  test("createCoValue / hasCoValue / removeCoValue roundtrip", () => {
    const shim = makeShim();
    const { coId, headerJson } = makeHeaderAndId();

    expect(shim.hasCoValue(coId)).toBe(false);
    expect(shim.coValueCount()).toBe(0);

    shim.createCoValue(coId, headerJson);
    expect(shim.hasCoValue(coId)).toBe(true);
    expect(shim.coValueCount()).toBe(1);
    expect(JSON.parse(shim.getHeader(coId))).toMatchObject({ type: "comap" });

    shim.removeCoValue(coId);
    expect(shim.hasCoValue(coId)).toBe(false);
    expect(shim.coValueCount()).toBe(0);
    // double remove is a no-op
    shim.removeCoValue(coId);
  });

  test("unknown coId throws with Unknown CoValue message", () => {
    const shim = makeShim();
    expect(() => shim.getHeader("co_zNope")).toThrow(
      /Unknown CoValue: co_zNope/,
    );
    expect(() => shim.getSessionIds("co_zNope")).toThrow(/Unknown CoValue/);
  });

  test("delegates session queries to the underlying session map", () => {
    const shim = makeShim();
    const { coId, headerJson } = makeHeaderAndId();
    shim.createCoValue(coId, headerJson);
    expect(shim.getSessionIds(coId)).toEqual([]);
    expect(shim.getTransactionCount(coId, "co_zAnybody_session_z123")).toBe(-1);
    expect(shim.getKnownState(coId)).toMatchObject({
      id: coId,
      header: true,
      sessions: {},
    });
  });

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
