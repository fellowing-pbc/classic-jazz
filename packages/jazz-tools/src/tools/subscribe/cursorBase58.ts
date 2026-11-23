// Cursors hold a frontier for every resolved CoValue, so they grow with the
// query. `base58` from @scure/base 2.x refuses inputs over 2048 bytes, so
// cursors use this codec instead. It writes the same base58 as @scure/base.

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DIGITS_PER_CHUNK = 10;
const CHUNK = 58n ** BigInt(DIGITS_PER_CHUNK);

const leadingCount = <T>(items: ArrayLike<T>, zero: T) => {
  let count = 0;
  while (count < items.length && items[count] === zero) count++;
  return count;
};

export const encodeBase58 = (bytes: Uint8Array): string => {
  const zeros = leadingCount(bytes, 0);
  const rest = bytes.subarray(zeros);
  if (rest.length === 0) return ALPHABET[0]!.repeat(zeros);

  const hex = Array.from(rest, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  let value = BigInt(`0x${hex}`);

  const chunks: string[] = [];
  while (value > 0n) {
    let chunk = value % CHUNK;
    value /= CHUNK;
    let digits = "";
    for (let i = 0; i < DIGITS_PER_CHUNK; i++) {
      digits = ALPHABET[Number(chunk % 58n)] + digits;
      chunk /= 58n;
    }
    chunks.push(digits);
  }
  const digits = chunks.reverse().join("");

  return ALPHABET[0]!.repeat(zeros) + digits.slice(leadingCount(digits, "1"));
};

export const decodeBase58 = (text: string): Uint8Array => {
  const zeros = leadingCount(text, ALPHABET[0]);
  const rest = text.slice(zeros);

  let value = 0n;
  for (let start = 0; start < rest.length; start += DIGITS_PER_CHUNK) {
    const digits = rest.slice(start, start + DIGITS_PER_CHUNK);
    let chunk = 0n;
    for (const digit of digits) {
      const index = ALPHABET.indexOf(digit);
      if (index === -1) throw new Error(`Invalid base58 character: ${digit}`);
      chunk = chunk * 58n + BigInt(index);
    }
    value = value * 58n ** BigInt(digits.length) + chunk;
  }

  if (value === 0n) return new Uint8Array(zeros);

  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const bytes = new Uint8Array(zeros + hex.length / 2);
  for (let i = 0; i < hex.length / 2; i++) {
    bytes[zeros + i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
};
