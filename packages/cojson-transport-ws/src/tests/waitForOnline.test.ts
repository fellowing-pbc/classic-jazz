import { describe, expect, test, vi } from "vitest";
import { WebSocketPeerWithReconnection } from "../WebSocketPeerWithReconnection";

/**
 * The reconnection backoff is the only thing standing between a peer that
 * cannot connect and a loop that dials as fast as the network allows, so these
 * tests pin its two failure modes: resolving on a replayed state instead of a
 * real change, and growing without bound.
 */

type NetworkCallback = (connected: boolean) => void;

class TestPeer extends WebSocketPeerWithReconnection {
  /** State replayed synchronously to each new subscriber, NetInfo-style. */
  replayState: boolean | undefined = undefined;
  /** Synchronously known connectivity, browser-style (`navigator.onLine`). */
  syncConnectivity: boolean | undefined = undefined;
  callbacks: NetworkCallback[] = [];
  unsubscribeCount = 0;

  protected currentConnectivity(): boolean | undefined {
    return this.syncConnectivity;
  }

  onNetworkChange(callback: NetworkCallback): () => void {
    this.callbacks.push(callback);
    if (this.replayState !== undefined) callback(this.replayState);
    return () => {
      this.unsubscribeCount++;
      this.callbacks = this.callbacks.filter((c) => c !== callback);
    };
  }

  emitNetwork(connected: boolean) {
    for (const callback of [...this.callbacks]) callback(connected);
  }

  /** `waitForOnline` is private; these tests are about its contract. */
  wait(timeout: number): Promise<void> {
    return (
      this as unknown as { waitForOnline(t: number): Promise<void> }
    ).waitForOnline(timeout);
  }
}

function makePeer(reconnectionTimeout = 500): TestPeer {
  return new TestPeer({
    peer: "wss://example.invalid",
    reconnectionTimeout,
    addPeer: vi.fn(),
    removePeer: vi.fn(),
  });
}

/** Resolves to true if `promise` settles before the microtask queue drains. */
async function settledImmediately(promise: Promise<void>): Promise<boolean> {
  let settled = false;
  void promise.then(() => {
    settled = true;
  });
  await Promise.resolve();
  await Promise.resolve();
  return settled;
}

describe("waitForOnline", () => {
  test("does not resolve on a replayed 'connected' state", async () => {
    vi.useFakeTimers();
    const peer = makePeer();
    // The common case: the device has a working connection and the SERVER
    // dropped the socket. A listener that replays `true` describes the state we
    // are already in, so honouring it would collapse the backoff to zero and
    // reconnect in a tight loop.
    peer.replayState = true;

    const promise = peer.wait(5_000);
    expect(await settledImmediately(promise)).toBe(false);

    await vi.advanceTimersByTimeAsync(5_000);
    await expect(promise).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  test("resolves early on a real offline → online edge", async () => {
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = false;

    const promise = peer.wait(60_000);
    expect(await settledImmediately(promise)).toBe(false);

    peer.emitNetwork(true);
    await expect(promise).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  test("resolves early on a real edge when the platform reports connectivity synchronously but never replays it (browser)", async () => {
    // Browser case: DOM `online`/`offline` events do not replay state, and the
    // peer was already offline when the backoff began. The baseline comes from
    // `currentConnectivity()` (navigator.onLine === false), so the first
    // `online` event is a real false → true edge and must cut the backoff short
    // rather than waiting out the whole timeout.
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = undefined;
    peer.syncConnectivity = false;

    const promise = peer.wait(60_000);
    expect(await settledImmediately(promise)).toBe(false);

    peer.emitNetwork(true);
    await expect(promise).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  test("ignores repeated 'connected' events with no intervening drop", async () => {
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = true;

    const promise = peer.wait(5_000);
    peer.emitNetwork(true);
    peer.emitNetwork(true);
    expect(await settledImmediately(promise)).toBe(false);

    await vi.advanceTimersByTimeAsync(5_000);
    await expect(promise).resolves.toBeUndefined();
    vi.useRealTimers();
  });

  test("survives a listener that fires synchronously during subscription", async () => {
    // Regression: `handleTimeoutOrOnline` used to close over `timer` and
    // `unsubscribeNetworkChange` before either was initialized, so a
    // synchronous callback ran inside their temporal dead zone.
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = false;

    expect(() => peer.wait(1_000)).not.toThrow();
    await vi.advanceTimersByTimeAsync(1_000);
    vi.useRealTimers();
  });

  test("unsubscribes exactly once, whether it resolves by timer or by edge", async () => {
    vi.useFakeTimers();

    const byTimer = makePeer();
    byTimer.replayState = true;
    const timerPromise = byTimer.wait(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await timerPromise;
    expect(byTimer.unsubscribeCount).toBe(1);
    expect(byTimer.callbacks).toHaveLength(0);

    const byEdge = makePeer();
    byEdge.replayState = false;
    const edgePromise = byEdge.wait(60_000);
    byEdge.emitNetwork(true);
    await edgePromise;
    expect(byEdge.unsubscribeCount).toBe(1);
    expect(byEdge.callbacks).toHaveLength(0);

    // A late event after settling must not resolve or unsubscribe again.
    byEdge.emitNetwork(true);
    expect(byEdge.unsubscribeCount).toBe(1);

    vi.useRealTimers();
  });
});

describe("reconnection backoff", () => {
  test("grows linearly, then caps", async () => {
    const peer = makePeer(500);
    const waits: number[] = [];
    vi.spyOn(
      peer as unknown as { waitForOnline(t: number): Promise<void> },
      "waitForOnline",
    ).mockImplementation(async (timeout: number) => {
      waits.push(timeout);
      // Abort before the dial so no socket is constructed.
      peer.enabled = false;
    });

    peer.enabled = true;
    for (const attempts of [1, 9, 60, 500]) {
      peer.reconnectionAttempts = attempts - 1;
      peer.currentPeer = {
        outgoing: { close: vi.fn() },
      } as unknown as typeof peer.currentPeer;
      peer.enabled = true;
      await peer.startConnection();
    }

    // 500ms × attempts, capped at 30s — without the cap the last two would be
    // 30s and 250s, and a peer that never reconnects would drift to hours.
    expect(waits).toEqual([500, 4_500, 30_000, 30_000]);
  });
});
