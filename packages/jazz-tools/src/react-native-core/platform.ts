import NetInfo from "@react-native-community/netinfo";
import { LocalNode, Peer, getSqliteStorageAsync } from "cojson";
import {
  Account,
  AccountClass,
  AnyAccountSchema,
  AuthCredentials,
  AuthSecretStorage,
  CoValue,
  CoValueFromRaw,
  NewAccountProps,
  SyncConfig,
  createInviteLink as baseCreateInviteLink,
  createAnonymousJazzContext,
  createJazzContext,
} from "jazz-tools";
import { KvStore, KvStoreContext } from "./storage/kv-store-context.js";
import { ReactNativeSessionProvider } from "./ReactNativeSessionProvider.js";

import { SQLiteDatabaseDriverAsync } from "cojson";
import {
  AnyWebSocketConstructor,
  WebSocketPeerWithReconnection,
} from "cojson-transport-ws";
import { RNCrypto } from "cojson/crypto/RNCrypto";

export type BaseReactNativeContextOptions = {
  sync: SyncConfig;
  reconnectionTimeout?: number;
  /**
   * How long to wait for any inbound frame before treating the socket as dead
   * and reconnecting (default 10s).
   *
   * This is the ceiling on the sync server's keepalive cadence, and on a mobile
   * client that cadence is a battery cost: every keepalive frame wakes the JS
   * thread and keeps the cellular modem out of its idle state. Raising this
   * lets the server ping less often, at the price of taking longer to notice a
   * genuinely dead socket.
   */
  pingTimeout?: number;
  storage?: SQLiteDatabaseDriverAsync | "disabled";
  authSecretStorage: AuthSecretStorage;
  experimental_clockSyncFromServerPings?: boolean;
};

class ReactNativeWebSocketPeerWithReconnection extends WebSocketPeerWithReconnection {
  onNetworkChange(callback: (connected: boolean) => void): () => void {
    return NetInfo.addEventListener((state) => {
      // `isConnected: null` means NetInfo doesn't know yet — it re-resolves
      // reachability after foregrounding and on connection-type changes.
      // Reporting it as `false` would fabricate an offline baseline in
      // `waitForOnline`, making the next `true` look like a reconnect edge and
      // collapsing the backoff on a device that was connected all along.
      // Unknown states establish no baseline.
      if (state.isConnected != null) callback(state.isConnected);
    });
  }
}

let syncWebSocketConstructor: AnyWebSocketConstructor | undefined;

/**
 * Inject the WebSocket constructor used for the sync connection (e.g. to add
 * auth headers per dial). Call before the Jazz context is created — same
 * contract as setPasskeyModule.
 */
export function setSyncWebSocketConstructor(
  constructor: AnyWebSocketConstructor | undefined,
): void {
  syncWebSocketConstructor = constructor;
}

/**
 * App-level gate on the sync connection, independent of the context/auth
 * lifecycle. Both must want the network on for the socket to be dialed.
 */
let appWantsNetwork = true;
const networkAppliers = new Set<() => void>();

/**
 * Enable or disable the sync connection at runtime, from outside the Jazz
 * context.
 *
 * The motivating case is mobile backgrounding. When the OS suspends the app the
 * socket stays open, so the server keeps sending keepalive frames, the kernel
 * keeps ACKing them, and the radio keeps waking — for the whole time the app is
 * suspended, with no JS running to benefit from it. Closing the socket on the
 * way to the background removes that entirely; the app re-enables on resume and
 * the reconnection layer dials again.
 *
 * Composes with `sync.when` rather than overriding it: this is an AND, so
 * disabling here suspends the socket even under `when: "always"`, and enabling
 * here does not force a connection that auth (`when: "signedUp"`) has gated
 * off. Safe to call before any context exists — the state is remembered and
 * applied when one is created.
 */
export function setSyncNetworkEnabled(enabled: boolean): void {
  if (appWantsNetwork === enabled) return;
  appWantsNetwork = enabled;
  for (const apply of networkAppliers) apply();
}

async function setupPeers(options: BaseReactNativeContextOptions) {
  const crypto = await RNCrypto.create();
  let node: LocalNode | undefined = undefined;

  const peers: Peer[] = [];

  const storage =
    options.storage && options.storage !== "disabled"
      ? await getSqliteStorageAsync(options.storage)
      : undefined;

  if (options.sync.when === "never") {
    return {
      toggleNetwork: () => {},
      disposeNetwork: () => {},
      addConnectionListener: () => () => {},
      connected: () => false,
      peers,
      syncWhen: options.sync.when,
      setNode: () => {},
      crypto,
      storage,
    };
  }

  const wsPeer = new ReactNativeWebSocketPeerWithReconnection({
    peer: options.sync.peer,
    reconnectionTimeout: options.reconnectionTimeout,
    pingTimeout: options.pingTimeout,
    WebSocketConstructor: syncWebSocketConstructor,
    addPeer: (peer) => {
      if (node) {
        node.syncManager.addPeer(peer);
      } else {
        peers.push(peer);
      }
    },
    removePeer: (peer) => {
      peers.splice(peers.indexOf(peer), 1);
    },
    onPingReceived: (sample) => {
      node?.clockOffset.addSample(sample);
    },
  });

  // What the context/auth lifecycle wants, gated against what the app wants
  // (see setSyncNetworkEnabled). The socket is dialed only if both agree.
  let contextWantsNetwork = false;

  function applyNetwork() {
    if (contextWantsNetwork && appWantsNetwork) {
      wsPeer.enable();
    } else {
      wsPeer.disable();
    }
  }

  function toggleNetwork(enabled: boolean) {
    contextWantsNetwork = enabled;
    applyNetwork();
  }

  networkAppliers.add(applyNetwork);
  function disposeNetwork() {
    networkAppliers.delete(applyNetwork);
  }

  function setNode(value: LocalNode) {
    node = value;
  }

  if (options.sync.when === "always" || !options.sync.when) {
    toggleNetwork(true);
  }

  return {
    toggleNetwork,
    disposeNetwork,
    addConnectionListener(listener: (connected: boolean) => void) {
      wsPeer.subscribe(listener);

      return () => {
        wsPeer.unsubscribe(listener);
      };
    },
    connected: () => wsPeer.connected,
    peers,
    syncWhen: options.sync.when,
    setNode,
    crypto,
    storage,
  };
}

export async function createJazzReactNativeGuestContext(
  options: BaseReactNativeContextOptions,
) {
  const {
    toggleNetwork,
    disposeNetwork,
    peers,
    syncWhen,
    setNode,
    crypto,
    storage,
    addConnectionListener,
    connected,
  } = await setupPeers(options);

  try {
    const context = createAnonymousJazzContext({
      crypto,
      peers,
      syncWhen,
      storage,
      experimental_clockSyncFromServerPings:
        options.experimental_clockSyncFromServerPings,
    });

    setNode(context.agent.node);

    options.authSecretStorage.emitUpdate(null);

    return {
      guest: context.agent,
      node: context.agent.node,
      done: () => {
        // TODO: Sync all the covalues before closing the connection & context
        toggleNetwork(false);
        disposeNetwork();
        context.done();
      },
      logOut: () => {
        return context.logOut();
      },
      addConnectionListener,
      connected,
    };
  } catch (error) {
    // setupPeers registered this context's applier in the module-level set and
    // may already have enabled the socket. Without this cleanup a failed
    // context creation leaves an orphaned, enabled peer behind that every
    // later setSyncNetworkEnabled(true) would re-dial — and retries stack one
    // more per failure.
    toggleNetwork(false);
    disposeNetwork();
    throw error;
  }
}

export type ReactNativeContextOptions<
  S extends
    | (AccountClass<Account> & CoValueFromRaw<Account>)
    | AnyAccountSchema,
> = {
  credentials?: AuthCredentials;
  AccountSchema?: S;
  newAccountProps?: NewAccountProps;
  defaultProfileName?: string;
} & BaseReactNativeContextOptions;

export async function createJazzReactNativeContext<
  S extends
    | (AccountClass<Account> & CoValueFromRaw<Account>)
    | AnyAccountSchema,
>(options: ReactNativeContextOptions<S>) {
  const {
    toggleNetwork,
    disposeNetwork,
    peers,
    syncWhen,
    setNode,
    crypto,
    storage,
    addConnectionListener,
    connected,
  } = await setupPeers(options);

  let unsubscribeAuthUpdate = () => {};

  try {
    if (options.sync.when === "signedUp") {
      const authSecretStorage = options.authSecretStorage;
      const credentials =
        options.credentials ?? (await authSecretStorage.get());

      // To update the internal state with the current credentials
      authSecretStorage.emitUpdate(credentials);

      function handleAuthUpdate(isAuthenticated: boolean) {
        if (isAuthenticated) {
          toggleNetwork(true);
        } else {
          toggleNetwork(false);
        }
      }

      unsubscribeAuthUpdate = authSecretStorage.onUpdate(handleAuthUpdate);
      handleAuthUpdate(authSecretStorage.isAuthenticated);
    }

    const sessionProvider = new ReactNativeSessionProvider();

    const context = await createJazzContext({
      credentials: options.credentials,
      newAccountProps: options.newAccountProps,
      peers,
      syncWhen,
      crypto,
      defaultProfileName: options.defaultProfileName,
      AccountSchema: options.AccountSchema,
      sessionProvider,
      authSecretStorage: options.authSecretStorage,
      storage,
      experimental_clockSyncFromServerPings:
        options.experimental_clockSyncFromServerPings,
    });

    setNode(context.node);

    return {
      me: context.account,
      node: context.node,
      authSecretStorage: context.authSecretStorage,
      done: () => {
        // TODO: Sync all the covalues before closing the connection & context
        toggleNetwork(false);
        disposeNetwork();
        unsubscribeAuthUpdate();
        context.done();
      },
      logOut: () => {
        unsubscribeAuthUpdate();
        return context.logOut();
      },
      addConnectionListener,
      connected,
    };
  } catch (error) {
    // setupPeers registered this context's applier in the module-level set,
    // and the auth wiring above may already have enabled the socket (`when:
    // "always"` enables inside setupPeers itself). Without this cleanup a
    // failed context creation — offline first launch, storage or auth errors —
    // leaves an orphaned, enabled peer behind that every later
    // setSyncNetworkEnabled(true) would re-dial, and manager retries stack one
    // more per failure.
    toggleNetwork(false);
    disposeNetwork();
    unsubscribeAuthUpdate();
    throw error;
  }
}

/** @category Invite Links */
export function createInviteLink<C extends CoValue>(
  value: C,
  role: "reader" | "writer" | "admin",
  { baseURL, valueHint }: { baseURL?: string; valueHint?: string } = {},
): string {
  return baseCreateInviteLink(value, role, {
    baseURL: baseURL ?? "",
    valueHint,
  });
}

export function setupKvStore(
  kvStore: KvStore | undefined,
): KvStore | undefined {
  if (!kvStore) {
    return undefined;
  }
  KvStoreContext.getInstance().initialize(kvStore);
  return kvStore;
}
