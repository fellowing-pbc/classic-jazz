import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocketPeerWithReconnection } from "../WebSocketPeerWithReconnection";
import type { AnyWebSocketConstructor } from "../types";

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

/** Inert socket standing in for the real thing when a dial must not go out. */
class FakeWebSocket {
  readyState = 0;
  bufferedAmount = 0;
  addEventListener() {}
  removeEventListener() {}
  send() {}
  close() {}
}

function makePeer(
  reconnectionTimeout = 500,
  WebSocketConstructor?: AnyWebSocketConstructor,
): TestPeer {
  return new TestPeer({
    peer: "wss://example.invalid",
    reconnectionTimeout,
    addPeer: vi.fn(),
    removePeer: vi.fn(),
    WebSocketConstructor,
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

afterEach(() => {
  // Restore on the failure path too — a mid-test assertion throw must not
  // leave fake timers installed for the rest of the worker.
  vi.useRealTimers();
});

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
  });

  test("resolves early on a real offline → online edge", async () => {
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = false;

    const promise = peer.wait(60_000);
    expect(await settledImmediately(promise)).toBe(false);

    peer.emitNetwork(true);
    await expect(promise).resolves.toBeUndefined();
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
  });

  test("settles synchronously when the baseline is offline and the subscription replays 'connected'", async () => {
    // Two generations of regression pinned by one input. The pre-rewrite code
    // closed over `timer` and `unsubscribeNetworkChange` from inside a
    // synchronous 'connected' callback before either initializer had run — a
    // temporal-dead-zone ReferenceError inside the promise executor, which
    // surfaces as a REJECTED promise (never a synchronous throw). And the
    // first rewrite settled before the unsubscribe function was assigned,
    // leaking the subscription. Baseline false + synchronous replay of true
    // exercises both: the promise must resolve, and the listener must be gone.
    const peer = makePeer();
    peer.syncConnectivity = false;
    peer.replayState = true;

    await expect(peer.wait(60_000)).resolves.toBeUndefined();
    expect(peer.unsubscribeCount).toBe(1);
    expect(peer.callbacks).toHaveLength(0);
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
  });

  test("disable() settles a pending wait and tears down its timer and subscription", async () => {
    vi.useFakeTimers();
    const peer = makePeer();
    peer.replayState = true;
    peer.enabled = true;

    const promise = peer.wait(30_000);
    expect(peer.callbacks).toHaveLength(1);

    peer.disable();
    await expect(promise).resolves.toBeUndefined();
    expect(peer.unsubscribeCount).toBe(1);
    expect(peer.callbacks).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("startConnection lifecycle", () => {
  test("a dial suspended in the backoff across disable()/enable() does not dial a second socket", async () => {
    // The backgrounding race: socket drops, the reconnect loop suspends in its
    // backoff wait, the app backgrounds (disable) and foregrounds (enable)
    // before the wait is over. enable() dials immediately; the suspended
    // continuation must then bail instead of dialing a second socket that
    // overwrites `currentPeer` and leaks the first.
    vi.useFakeTimers();
    const dialed: FakeWebSocket[] = [];
    class CountingWebSocket extends FakeWebSocket {
      constructor(_url: string) {
        super();
        dialed.push(this);
      }
    }
    const peer = makePeer(
      500,
      CountingWebSocket as unknown as AnyWebSocketConstructor,
    );

    peer.enabled = true;
    peer.reconnectionAttempts = 0;
    peer.currentPeer = {
      outgoing: { close: vi.fn() },
    } as unknown as typeof peer.currentPeer;

    // Runs synchronously up to `await waitForOnline(500)` and suspends there.
    const suspended = peer.startConnection();
    expect(dialed).toHaveLength(0);

    peer.disable();
    peer.enable();
    expect(dialed).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(60_000);
    await suspended;

    expect(dialed).toHaveLength(1);
    peer.disable();
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

  test("a base interval above the cap is honoured, not clamped below itself", async () => {
    const peer = makePeer(60_000);
    const waits: number[] = [];
    vi.spyOn(
      peer as unknown as { waitForOnline(t: number): Promise<void> },
      "waitForOnline",
    ).mockImplementation(async (timeout: number) => {
      waits.push(timeout);
      peer.enabled = false;
    });

    for (const attempts of [1, 3]) {
      peer.reconnectionAttempts = attempts - 1;
      peer.currentPeer = {
        outgoing: { close: vi.fn() },
      } as unknown as typeof peer.currentPeer;
      peer.enabled = true;
      await peer.startConnection();
    }

    // A caller asking for a 60s base gets a fixed 60s interval — the 30s cap
    // exists to bound linear growth, not to override an explicit choice.
    expect(waits).toEqual([60_000, 60_000]);
  });
});
