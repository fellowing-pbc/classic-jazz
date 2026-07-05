/**
 * Unified result envelope for the native-decision FFI surface.
 *
 * Three native-decision families cross the napi/wasm boundary as a JSON string:
 * the sync content decision (`contentToSend`), the storage write-plan
 * (`planSessionWrite`) and the five group-key writes. They all now emit ONE wire
 * shape, produced by `crates/cojson-core/src/core/native_result.rs`:
 *
 * ```text
 * success:  {"ok":true,"value":<T>}
 * error:    {"ok":false,"kind":"error","message":"<msg>"}
 * ```
 *
 * `parseNativeResult` normalizes that into a {@link NativeResult}, adding a
 * third, TS-side-only case: `unsupported`, for when the native method is absent
 * on the backend (the string is `undefined`). Rust never emits `unsupported`.
 *
 * The point of the envelope is to make a genuine Rust-side failure (`error`)
 * distinguishable from "this backend doesn't have the method" (`unsupported`) —
 * so callers can LOG real errors before falling back to the TS path instead of
 * silently swallowing them (the old bare `try/catch { fall back }` conflated the
 * two).
 */
export type NativeResult<T> =
  | { ok: true; value: T }
  | { ok: false; kind: "unsupported" }
  | { ok: false; kind: "error"; message: string };

/**
 * Parse a native-decision FFI response string into a {@link NativeResult}.
 *
 * - `undefined` input (the native method is not present on this backend) =>
 *   `{ ok: false, kind: "unsupported" }`.
 * - `JSON.parse` throwing, a `{"ok":false,…}` envelope, or a bare
 *   `{"error":"…"}` payload from Rust => `{ ok: false, kind: "error", message }`.
 * - a `{"ok":true,"value":…}` envelope => `{ ok: true, value }`.
 */
export function parseNativeResult<T>(
  json: string | undefined | null,
): NativeResult<T> {
  if (json === undefined || json === null) {
    return { ok: false, kind: "unsupported" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    return {
      ok: false,
      kind: "error",
      message: `native result was not valid JSON: ${String(e)}`,
    };
  }

  if (typeof parsed === "object" && parsed !== null) {
    const obj = parsed as {
      ok?: unknown;
      value?: unknown;
      message?: unknown;
      error?: unknown;
    };

    if (obj.ok === true) {
      return { ok: true, value: obj.value as T };
    }

    if (obj.ok === false) {
      return {
        ok: false,
        kind: "error",
        message:
          typeof obj.message === "string"
            ? obj.message
            : "unknown native error",
      };
    }

    // Defensive: a well-formed bare `{"error":"…"}` payload from Rust.
    if (typeof obj.error === "string") {
      return { ok: false, kind: "error", message: obj.error };
    }
  }

  return {
    ok: false,
    kind: "error",
    message: "malformed native result envelope",
  };
}
