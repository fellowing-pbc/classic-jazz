import { type Peer, logger } from "cojson";
import { createWebSocketPeer } from "./createWebSocketPeer.js";
import type { AnyWebSocketConstructor } from "./types.js";

/** Ceiling for the linear reconnection backoff. */
const MAX_RECONNECTION_TIMEOUT = 30_000;

export class WebSocketPeerWithReconnection {
  private peer: string;
  private reconnectionTimeout: number;
  private addPeer: (peer: Peer) => void;
  private removePeer: (peer: Peer) => void;
  private WebSocketConstructor: AnyWebSocketConstructor;
  private pingTimeout: number;
  private onPingReceived?: (sample: {
    serverTime: number;
    localReceiveTime: number;
  }) => void;

  constructor(opts: {
    peer: string;
    reconnectionTimeout: number | undefined;
    addPeer: (peer: Peer) => void;
    removePeer: (peer: Peer) => void;
    WebSocketConstructor?: AnyWebSocketConstructor;
    pingTimeout?: number;
    onPingReceived?: (sample: {
      serverTime: number;
      localReceiveTime: number;
    }) => void;
  }) {
    this.peer = opts.peer;
    this.reconnectionTimeout = opts.reconnectionTimeout || 500;
    this.addPeer = opts.addPeer;
    this.removePeer = opts.removePeer;
    this.WebSocketConstructor = opts.WebSocketConstructor || WebSocket;
    this.pingTimeout = opts.pingTimeout || 10_000;
    this.onPingReceived = opts.onPingReceived;
  }

  enabled = false;
  closed = true;

  // We use this state to feed the Connection Status hooks
  connected = false;

  currentPeer: Peer | undefined = undefined;

  /**
   * Settles the network wait of the currently suspended `startConnection`, if
   * any. `disable()` calls it so that no backoff timer or platform network
   * listener outlives the peer being switched off.
   */
  private cancelWaitForOnline: (() => void) | undefined = undefined;

  /**
   * Incremented on every `disable()`. A `startConnection` that was suspended
   * in `waitForOnline` across a disable()/enable() cycle must not dial when it
   * resumes — the enable() already dialed, and a stale continuation would
   * create a second socket that nothing ever closes.
   */
  private dialGeneration = 0;

  // Basic implementation for environments that don't support network change events (e.g. Node.js)
  // Needs to be extended to handle platform specific APIs
  onNetworkChange(callback: (connected: boolean) => void): () => void {
    callback;
    return () => {};
  }

  /**
   * Synchronously known current connectivity, if the platform exposes it
   * (the browser does, via `navigator.onLine`). This seeds the online-edge
   * baseline in `waitForOnline`, so a platform whose listener does NOT replay
   * state — DOM `online`/`offline` events, unlike NetInfo — still catches a
   * genuine offline → online transition instead of waiting out the whole
   * backoff. Return `undefined` when connectivity is only known
   * asynchronously (NetInfo); the baseline is then taken from the first
   * replayed callback.
   */
  protected currentConnectivity(): boolean | undefined {
    return undefined;
  }

  /**
   * Wait out the reconnection backoff, cutting it short if the device comes
   * back online.
   *
   * Two hazards this has to avoid, both of which turn the backoff into a hot
   * reconnect loop that dials as fast as the network allows:
   *
   * 1. `handleTimeoutOrOnline` used to be declared before `timer` and
   *    `unsubscribeNetworkChange` were initialized. A network callback that
   *    fires synchronously during subscription therefore ran while both were
   *    still in their temporal dead zone — either resolving immediately with an
   *    uncancelled timer, or throwing a ReferenceError inside the promise
   *    executor (which rejects `startConnection` and silently kills sync for
   *    the rest of the session, depending on whether the runtime enforces TDZ).
   *
   * 2. Platform listeners commonly replay their cached state to a new
   *    subscriber, synchronously. React Native's NetInfo does exactly this. That
   *    first callback describes the state we are already in, not a change, so
   *    treating it as "back online" collapses every backoff to zero on any
   *    device that has a working connection — which is the normal case when the
   *    server, not the network, dropped the socket.
   *
   * So: settle exactly once, and only on a real offline → online edge. The
   * baseline is seeded from `currentConnectivity()` where the platform reports
   * it synchronously (the browser), and otherwise from the first replayed
   * callback (NetInfo). A platform that neither replays state nor exposes it
   * synchronously waits out the (capped) timeout instead of reconnecting early
   * — slow in a rare case, rather than a dial loop in a common one.
   */
  private waitForOnline(timeout: number) {
    return new Promise<void>((resolve) => {
      // `timer` and `unsubscribeNetworkChange` are declared up front, on
      // purpose. `settle` closes over both, and `onNetworkChange` can invoke
      // its callback — and therefore `settle` — synchronously, before either
      // has a value. Declaring them here makes that read `undefined` instead of
      // a temporal-dead-zone ReferenceError. The `biome-ignore`s below are load
      // bearing: useConst's autofix collapses each to `const x = <init>` at the
      // assignment site, moving the declaration below `settle` and reintroducing
      // the exact TDZ this function was written to avoid.
      let settled = false;
      // biome-ignore lint/style/useConst: must be declared before `settle` closes over it; autofix reintroduces a TDZ.
      let timer: ReturnType<typeof setTimeout> | undefined;
      let unsubscribeNetworkChange: (() => void) | undefined;
      let lastConnected: boolean | undefined = this.currentConnectivity();

      const settle = () => {
        if (settled) return;
        settled = true;
        if (this.cancelWaitForOnline === settle) {
          this.cancelWaitForOnline = undefined;
        }
        if (timer !== undefined) clearTimeout(timer);
        unsubscribeNetworkChange?.();
        resolve();
      };

      unsubscribeNetworkChange = this.onNetworkChange((connected) => {
        const previous = lastConnected;
        lastConnected = connected;
        if (previous === false && connected) settle();
      });

      // `settle` may already have run if a listener fired synchronously with an
      // edge. It ran before `unsubscribeNetworkChange` was assigned, so it
      // could not unsubscribe — do that here, and don't arm a timer nobody
      // will clear.
      if (settled) {
        unsubscribeNetworkChange();
        return;
      }
      this.cancelWaitForOnline = settle;
      timer = setTimeout(settle, timeout);
    });
  }

  reconnectionAttempts = 0;

  onConnectionChangeListeners = new Set<(connected: boolean) => void>();

  waitUntilConnected = async () => {
    if (this.closed) {
      return new Promise<void>((resolve) => {
        const listener = (connected: boolean) => {
          if (connected) {
            resolve();
            this.onConnectionChangeListeners.delete(listener);
          }
        };

        this.onConnectionChangeListeners.add(listener);
      });
    }
  };

  subscribe = (listener: (connected: boolean) => void) => {
    this.onConnectionChangeListeners.add(listener);
    listener(!this.closed);
  };

  unsubscribe = (listener: (connected: boolean) => void) => {
    this.onConnectionChangeListeners.delete(listener);
  };

  startConnection = async () => {
    if (!this.enabled) return;

    const generation = this.dialGeneration;

    if (this.currentPeer) {
      this.removePeer(this.currentPeer);
      this.currentPeer.outgoing.close();

      this.reconnectionAttempts++;

      // Linear growth, capped. Uncapped, a peer that stays unreachable for a
      // long session (or one whose `onSuccess` never fires — a server that
      // accepts and then closes with an auth code does exactly that, so
      // `reconnectionAttempts` never resets) would eventually wait for hours.
      // A configured base above the cap is honoured as a fixed interval rather
      // than being clamped below what the caller explicitly asked for.
      const timeout = Math.min(
        this.reconnectionTimeout * this.reconnectionAttempts,
        Math.max(MAX_RECONNECTION_TIMEOUT, this.reconnectionTimeout),
      );

      logger.debug(
        `Websocket disconnected, trying to reconnect in ${timeout}ms`,
      );

      await this.waitForOnline(timeout);
    }

    // The generation check catches a disable()/enable() cycle that happened
    // while we were suspended above: enable() already dialed, and dialing here
    // too would overwrite `currentPeer` and leak a live socket.
    if (!this.enabled || generation !== this.dialGeneration) return;

    this.currentPeer = createWebSocketPeer({
      websocket: new this.WebSocketConstructor(this.peer),
      pingTimeout: this.pingTimeout,
      id: this.peer,
      role: "server",
      onPingReceived: this.onPingReceived,
      onClose: () => {
        this.closed = true;
        this.connected = false;
        for (const listener of this.onConnectionChangeListeners) {
          listener(false);
        }
        this.startConnection();
      },
      onSuccess: () => {
        this.closed = false;
        this.connected = true;
        for (const listener of this.onConnectionChangeListeners) {
          listener(true);
        }
        logger.debug("Websocket connection successful");

        this.reconnectionAttempts = 0;
      },
    });

    this.addPeer(this.currentPeer);
  };

  enable = () => {
    if (this.enabled) return;

    // Optimistically set the connected state to true
    this.connected = true;
    this.enabled = true;
    this.startConnection();
  };

  disable = () => {
    if (!this.enabled) return;

    this.enabled = false;
    this.dialGeneration++;

    this.reconnectionAttempts = 0;
    // Settle any suspended backoff wait now, so its timer and platform network
    // listener don't outlive the disable. Its continuation re-checks `enabled`
    // and the generation, so it won't dial.
    this.cancelWaitForOnline?.();

    if (this.currentPeer) {
      this.removePeer(this.currentPeer);
      this.currentPeer.outgoing.close();
      this.currentPeer = undefined;
    }
  };
}
