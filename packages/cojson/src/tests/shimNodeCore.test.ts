import { beforeAll, describe, expect, test } from "vitest";
import { NapiCrypto } from "../crypto/NapiCrypto.js";
import { ShimNodeCore } from "../crypto/ShimNodeCore.js";
import type { CryptoProvider } from "../crypto/crypto.js";
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
});
