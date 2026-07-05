import type { SessionID } from "cojson";
import { WasmNode } from "cojson/node/WasmNode";
import { LocalNode } from "cojson";
import { afterEach, describe, expect, test, vi } from "vitest";
import { makeDurabilityMarkerListener } from "../implementation/sessionDurabilityMarker.js";
import {
  Credentials,
  InMemoryKVStore,
  KvStoreContext,
  MockSessionProvider,
  createJazzContextFromExistingCredentials,
} from "../exports.js";
import {
  createJazzTestAccount,
  getPeerConnectedToTestSyncServer,
  setupJazzTestSync,
} from "../testing.js";

const sessionID = "co_ztest_session_ztest" as SessionID;

function mockMarker() {
  return { set: vi.fn(), clear: vi.fn(), isSet: vi.fn(() => false) };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("makeDurabilityMarkerListener", () => {
  test("sets the marker synchronously when the window opens", () => {
    const marker = mockMarker();
    const listener = makeDurabilityMarkerListener(marker);

    listener(true, sessionID);

    expect(marker.set).toHaveBeenCalledWith(sessionID);
    expect(marker.clear).not.toHaveBeenCalled();
  });

  test("clears the marker only after the debounce delay", () => {
    vi.useFakeTimers();
    const marker = mockMarker();
    const listener = makeDurabilityMarkerListener(marker, 200);

    listener(true, sessionID);
    listener(false, sessionID);
    expect(marker.clear).not.toHaveBeenCalled();

    vi.advanceTimersByTime(200);
    expect(marker.clear).toHaveBeenCalledWith(sessionID);
  });

  test("a new pending window cancels a scheduled clear", () => {
    vi.useFakeTimers();
    const marker = mockMarker();
    const listener = makeDurabilityMarkerListener(marker, 200);

    listener(true, sessionID);
    listener(false, sessionID);
    listener(true, sessionID); // window re-opens within the debounce
    vi.advanceTimersByTime(500);

    expect(marker.clear).not.toHaveBeenCalled();
  });

  test("consecutive clears don't leave an orphaned timer that clears a fresh set", () => {
    vi.useFakeTimers();
    const marker = mockMarker();
    const listener = makeDurabilityMarkerListener(marker, 200);

    listener(true, sessionID);
    listener(false, sessionID);
    listener(false, sessionID); // must supersede (not orphan) the first timer
    listener(true, sessionID); // window re-opens: no clear may fire anymore
    vi.advanceTimersByTime(500);

    expect(marker.clear).not.toHaveBeenCalled();
  });

  test("a reopen within the debounce doesn't rewrite the still-set marker", () => {
    vi.useFakeTimers();
    const marker = mockMarker();
    const listener = makeDurabilityMarkerListener(marker, 200);

    listener(true, sessionID);
    listener(false, sessionID);
    listener(true, sessionID); // marker was never cleared: no write needed

    expect(marker.set).toHaveBeenCalledTimes(1);

    // ...but after an actual clear, the next window writes again
    listener(false, sessionID);
    vi.advanceTimersByTime(200);
    listener(true, sessionID);

    expect(marker.clear).toHaveBeenCalledTimes(1);
    expect(marker.set).toHaveBeenCalledTimes(2);
  });

  test("returns undefined when no marker is provided", () => {
    expect(makeDurabilityMarkerListener(undefined)).toBeUndefined();
  });

  test("marker errors are swallowed with a warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const marker = mockMarker();
    marker.set.mockImplementation(() => {
      throw new Error("quota exceeded");
    });
    const listener = makeDurabilityMarkerListener(marker);

    expect(() => listener(true, sessionID)).not.toThrow();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });
});

const Crypto = await WasmNode.create();
KvStoreContext.getInstance().initialize(new InMemoryKVStore());

describe("createContext wiring", () => {
  test("passes a durability listener to LocalNode when the provider has a marker", async () => {
    await setupJazzTestSync();
    const account = await createJazzTestAccount({
      isCurrentActiveAccount: true,
    });

    const credentials: Credentials = {
      accountID: account.$jazz.id,
      secret: account.$jazz.localNode.getCurrentAgent().agentSecret,
    };

    const spy = vi.spyOn(LocalNode, "withLoadedAccount");

    const provider = new MockSessionProvider();
    provider.durabilityMarker = mockMarker();

    const context = await createJazzContextFromExistingCredentials({
      credentials,
      peers: [getPeerConnectedToTestSyncServer()],
      crypto: Crypto,
      sessionProvider: provider,
      asActiveAccount: false,
    });
    context.done();

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        onLocalStoreDurabilityChange: expect.any(Function),
      }),
    );
  });

  test("passes no listener when the provider has no marker", async () => {
    await setupJazzTestSync();
    const account = await createJazzTestAccount({
      isCurrentActiveAccount: true,
    });

    const credentials: Credentials = {
      accountID: account.$jazz.id,
      secret: account.$jazz.localNode.getCurrentAgent().agentSecret,
    };

    const spy = vi.spyOn(LocalNode, "withLoadedAccount");

    const context = await createJazzContextFromExistingCredentials({
      credentials,
      peers: [getPeerConnectedToTestSyncServer()],
      crypto: Crypto,
      sessionProvider: new MockSessionProvider(),
      asActiveAccount: false,
    });
    context.done();

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        onLocalStoreDurabilityChange: undefined,
      }),
    );
  });
});
