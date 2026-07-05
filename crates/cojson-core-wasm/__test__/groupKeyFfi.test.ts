// Stage-1 FFI round-trip verification for the group key-management write paths,
// driving the REAL compiled wasm module (mirrors the napi test of the same name).
//
// Feeds each golden fixture's input through the JSON wire boundary and asserts
// the returned write list is byte-identical to the fixture's `expectedWrites`.
// Since the pure-Rust fixture tests already lock each pure function's output to
// those same `expectedWrites`, `wasm(input) === expectedWrites` here proves the
// wasm wire format neither loses nor corrupts a byte of the secret-material-heavy
// sealed values. Nothing in cojson production TS calls these yet (stage 2).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { beforeAll, describe, expect, test } from "vitest";

import {
  groupAddEveryoneWriteOnly,
  groupAddMemberInternal,
  groupExtend,
  groupRemoveMember,
  groupRotateReadKey,
  initialize,
} from "../index";

beforeAll(async () => {
  await initialize();
});

const DATA_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../cojson-core/data",
);

function loadFixture(category: string, name: string): any {
  const path = resolve(DATA_DIR, category, `${name}.json`);
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("group key FFI round-trip (wasm)", () => {
  describe("groupRotateReadKey", () => {
    for (const name of [
      "readers_only",
      "remove_member",
      "write_only",
      "with_parent",
    ]) {
      test(name, () => {
        const fx = loadFixture("group_key_rotation", name);
        const out = JSON.parse(groupRotateReadKey(JSON.stringify(fx)));
        expect(out.skipped).toBe(false);
        expect(out.writes).toEqual(fx.expectedWrites);
      });
    }
  });

  describe("groupAddMemberInternal", () => {
    for (const name of [
      "add_reader",
      "add_writer_with_existing_writeonly",
      "add_write_only",
      "create_invite_reader",
      "everyone_reader",
      "write_only_demotion",
    ]) {
      test(name, () => {
        const fx = loadFixture("group_key_membership", name);
        const out = JSON.parse(groupAddMemberInternal(JSON.stringify(fx)));
        expect(out).toEqual(fx.expectedWrites);
      });
    }
  });

  describe("groupAddEveryoneWriteOnly", () => {
    test("everyone_write_only (set + del mutations)", () => {
      const fx = loadFixture("group_key_membership", "everyone_write_only");
      const out = JSON.parse(groupAddEveryoneWriteOnly(JSON.stringify(fx)));
      const expected = (fx.expectedWrites as any[]).map((w) =>
        (w.op ?? "set") === "del"
          ? { op: "del", field: w.field }
          : { op: "set", field: w.field, value: w.value },
      );
      expect(out).toEqual(expected);
    });
  });

  describe("groupRemoveMember", () => {
    test("remove_reader", () => {
      const fx = loadFixture("group_key_membership", "remove_reader");
      const out = JSON.parse(groupRemoveMember(JSON.stringify(fx)));
      expect(out).toEqual(fx.expectedWrites);
    });
  });

  describe("groupExtend", () => {
    for (const name of ["extend_basic", "extend_with_writeonly"]) {
      test(name, () => {
        const fx = loadFixture("group_key_extend", name);
        const out = JSON.parse(groupExtend(JSON.stringify(fx)));
        expect(out).toEqual(fx.expectedWrites);
      });
    }
  });

  describe("error propagation across the FFI boundary", () => {
    test("unknown rotation trigger kind throws", () => {
      const fx = loadFixture("group_key_rotation", "readers_only");
      const bad = { ...fx, trigger: { kind: "bogus" } };
      expect(() => groupRotateReadKey(JSON.stringify(bad))).toThrow();
    });

    test("malformed JSON throws", () => {
      expect(() => groupExtend("{ not json")).toThrow();
    });
  });
});
