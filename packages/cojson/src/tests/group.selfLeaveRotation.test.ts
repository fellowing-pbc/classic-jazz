import { beforeEach, describe, expect, test } from "vitest";
import { setCoValueLoadingRetryDelay } from "../config.js";
import { RawCoMap } from "../coValues/coMap.js";
import type { RawGroup } from "../coValues/group.js";
import {
  SyncMessagesLog,
  loadCoValueOrFail,
  setupTestAccount,
  setupTestNode,
  waitFor,
} from "./testUtils.js";

setCoValueLoadingRetryDelay(10);

beforeEach(async () => {
  SyncMessagesLog.clear();
  setupTestNode({ isSyncServer: true });
});

async function setupGroupWithWriter() {
  const admin = await setupTestAccount({ connected: true });
  const writer = await setupTestAccount({ connected: true });

  const group = admin.node.createGroup();
  group.addMember(
    await loadCoValueOrFail(admin.node, writer.accountID),
    "writer",
  );
  const map = group.createMap();
  map.set("before", "written before the leave", "private");
  await map.core.waitForSync();

  return { admin, writer, group, map };
}

async function leave(
  writer: Awaited<ReturnType<typeof setupTestAccount>>,
  groupId: RawGroup["id"],
) {
  const groupOnWriter = await loadCoValueOrFail(writer.node, groupId);
  groupOnWriter.removeMember(writer.node.expectCurrentAccount("writer"));
  await groupOnWriter.core.waitForSync();
}

describe("a writer who leaves a group", () => {
  test("can't read what the group writes after the leave", async () => {
    const { admin, writer, group, map } = await setupGroupWithWriter();
    const keyBeforeLeave = group.get("readKey");

    await leave(writer, group.id);
    await waitFor(() => {
      expect(group.get(writer.accountID)).toEqual("revoked");
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    map.set("after", "written after the leave", "private");
    await map.core.waitForSync();

    const leaverSession = await writer.spawnNewSession();
    const mapOnLeaver = await loadCoValueOrFail<RawCoMap>(
      leaverSession.node,
      map.id,
    );
    expect(mapOnLeaver.get("before")).toEqual("written before the leave");
    expect(mapOnLeaver.get("after")).toBeUndefined();
    expect(group.get("readKey")).not.toEqual(keyBeforeLeave);

    expect(
      (await loadCoValueOrFail<RawCoMap>(admin.node, map.id)).get("after"),
    ).toEqual("written after the leave");
  });

  test("loses the key when an admin who was offline loads the group", async () => {
    const { admin, writer, group } = await setupGroupWithWriter();
    const keyBeforeLeave = group.get("readKey");
    await group.core.waitForSync();
    admin.disconnect();

    await leave(writer, group.id);

    const adminSession = await admin.spawnNewSession();
    const groupOnAdmin = await loadCoValueOrFail(adminSession.node, group.id);
    expect(groupOnAdmin.get(writer.accountID)).toEqual("revoked");

    await waitFor(() => {
      expect(groupOnAdmin.get("readKey")).not.toEqual(keyBeforeLeave);
    });
    expect(groupOnAdmin.myRole()).toEqual("admin");
    expect(groupOnAdmin.getCurrentReadKey().secret).toBeDefined();
  });
});
