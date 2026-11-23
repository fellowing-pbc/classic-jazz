import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { decodeBase58, encodeBase58 } from "../subscribe/cursorBase58.js";

const randomBytes = (length: number) =>
  Uint8Array.from({ length }, () => Math.floor(Math.random() * 256));

const withLeadingZeros = (zeros: number, bytes: Uint8Array) => {
  const result = new Uint8Array(zeros + bytes.length);
  result.set(bytes, zeros);
  return result;
};

describe("cursor base58", () => {
  const inputs = [
    new Uint8Array(0),
    new Uint8Array(1),
    new Uint8Array(3),
    Uint8Array.of(255),
    withLeadingZeros(2, Uint8Array.of(0, 1, 2)),
    ...[1, 7, 8, 9, 10, 32, 100, 1000, 2048].map(randomBytes),
    withLeadingZeros(5, randomBytes(500)),
  ];

  it.each(inputs.map((bytes) => [bytes.length, bytes] as const))(
    "writes the same text as @scure/base for %i bytes",
    (_, bytes) => {
      const text = encodeBase58(bytes);

      expect(text).toBe(base58.encode(bytes));
      expect(decodeBase58(text)).toEqual(bytes);
    },
  );

  it("roundtrips input larger than @scure/base accepts", () => {
    const bytes = withLeadingZeros(3, randomBytes(20_000));

    expect(decodeBase58(encodeBase58(bytes))).toEqual(bytes);
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => decodeBase58("abc0")).toThrow();
  });
});
