import {
  CHAIN_NAMESPACES,
  CONNECTOR_EVENTS,
  MFA_LEVELS,
  WALLET_CONNECTORS,
  WEB3AUTH_NETWORK,
  Web3Auth,
  type CustomChainConfig,
  type IProvider,
  type WEB3AUTH_NETWORK_TYPE,
} from "@web3auth/modal";
import type { WalletPhaseListener } from "./index";

/**
 * ─── Web3Auth tKey — key reconstruction, inside the boundary ──────────────────
 * The only file importing the Web3Auth SDK, reached only via `await import()`
 * (enforced by ESLint's wallet wall and the 512 KB entry-chunk budget).
 */

// ── Configuration ────────────────────────────────────────────────────────────

/** Required build-time value; throwing beats a default. `sapphire_devnet` and
 *  `sapphire_mainnet` derive DIFFERENT addresses for the same user, so a wrong
 *  default is a different person signing. */
function required(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `${name} is not set. Design A's wallet needs it at build time — see .env.a.example.`,
    );
  }
  return value;
}

/** NOT a secret (Stripe-publishable class): it ships in this bundle by design. */
const CLIENT_ID = (): string =>
  required("VITE_WEB3AUTH_CLIENT_ID", import.meta.env.VITE_WEB3AUTH_CLIENT_ID);

const NETWORK = (): WEB3AUTH_NETWORK_TYPE => {
  const raw = required("VITE_WEB3AUTH_NETWORK", import.meta.env.VITE_WEB3AUTH_NETWORK);
  const known = Object.values(WEB3AUTH_NETWORK) as string[];
  if (!known.includes(raw)) {
    throw new Error(`VITE_WEB3AUTH_NETWORK "${raw}" is not a Web3Auth network (${known.join(", ")}).`);
  }
  return raw as WEB3AUTH_NETWORK_TYPE;
};

/** The chain as a hex chain id. Must equal the backend's `CHAIN_ID` — the DID is
 *  `did:ethr:0x<chainIdHex>:<address>`, and the same address on two chains is two
 *  different owners. */
function chainConfig(): CustomChainConfig {
  const chainId = Number(required("VITE_CHAIN_ID", import.meta.env.VITE_CHAIN_ID));
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error(`VITE_CHAIN_ID must be a positive integer chain id (got "${import.meta.env.VITE_CHAIN_ID}").`);
  }
  const rpcTarget = required("VITE_RPC_URL", import.meta.env.VITE_RPC_URL);
  return {
    chainNamespace: CHAIN_NAMESPACES.EIP155,
    chainId: `0x${chainId.toString(16)}`,
    rpcTarget,
    displayName: import.meta.env.VITE_CHAIN_NAME ?? `chain ${chainId}`,
    blockExplorerUrl: import.meta.env.VITE_BLOCK_EXPLORER_URL ?? "",
    ticker: import.meta.env.VITE_CHAIN_TICKER ?? "ETH",
    tickerName: import.meta.env.VITE_CHAIN_TICKER_NAME ?? "Ether",
    logo: "",
  };
}

/** The SDK's storage-adapter shape, written out rather than imported: this
 *  directory depends on the shape, not on a nominal type a version bump can
 *  rename. If the shape changes, the `storage:` option stops typechecking. */
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

/**
 * Storage that forgets — for the part of the SDK that honours it.
 */
function memoryStorage(): StorageAdapter {
  const store = new Map<string, string>();
  return {
    get: (key: string) => Promise.resolve(store.get(key) ?? null),
    set: (key: string, value: string) => {
      store.set(key, value);
      return Promise.resolve();
    },
    remove: (key: string) => {
      store.delete(key);
      return Promise.resolve();
    },
  };
}

// ── The instance ─────────────────────────────────────────────────────────────

/** Live only between `connect()` and `disconnect()`. Module-scoped rather than
 *  per-call so a stray second `connect()` cannot leave an orphaned instance
 *  holding a reconstructed key with nobody left to tear it down. */
let instance: Web3Auth | null = null;

/** Phase sink for callers that pass none. Keeps every emit site unconditional —
 *  a `?.()` at six call sites is six chances to forget one. */
const NO_PHASES: WalletPhaseListener = () => {};

/**
 * Connect, with one retry for a first-login-only provider race.
 */
async function connect(
  onPhase: WalletPhaseListener,
): Promise<{ web3auth: Web3Auth; provider: IProvider; address: string }> {
  try {
    return await connectOnce(onPhase);
  } catch (err) {
    if (!isRetryableProviderFailure(err)) throw err;
    console.warn("Web3Auth connect failed on a retryable provider error; retrying once.", err);
    /* Announced, not silent: the retry re-renders the login modal, and an
     * unexplained repeat of a question the user just answered reads as failure.
     * (They pressed X, turning a recoverable hiccup into a real cancellation.) */
    onPhase("reopening");
    return await connectOnce(onPhase);
  }
}

/**
 * Their backend failing mid-connect, vs. the user declining or our own refusals.
 *
 * The Response branch is the one that fires: the SDK rejects with a bare fetch
 * Response, so `String(err)` is "[object Response]" and every text needle missed.
 * Host-scoped — a 404 from OUR api is a real answer, not a wobble.
 */
function isRetryableProviderFailure(err: unknown): boolean {
  // 1 — A bare Response. The observed shape, and the only one that matters.
  if (typeof Response !== "undefined" && err instanceof Response) {
    const provider = /(^|\.)web3auth\.io$/i.test(safeHost(err.url));
    return provider && (err.status === 404 || err.status >= 500);
  }

  // 2 — Everything else, by text. Errors carry `.message`; some SDK paths reject
  //     with a plain `{ message }` object, so read that rather than stringify it
  //     into uselessness.
  const text = messageOf(err).toLowerCase();
  if (!text) return false;

  // Cancellation first: these can also mention "connect", and a retry here would
  // reopen a window the user just closed.
  if (/closed|cancel|blocked|denied|rejected/.test(text)) return false;

  // Our own refusals must never be retried — a "1/1" key stays "1/1", and
  // reopening the modal would make a deliberate, explained refusal look like a
  // flaky connection. See assertThresholdKey / assertAuthConnector.
  if (/threshold|2-of-n|refusing to sign|design a requires/.test(text)) return false;

  return (
    text.includes("failed to login with auth") ||
    text.includes("failed to connect with auth provider") ||
    text.includes("body stream already read")
  );
}

/** What `connectOnce` actually needs out of a connect. Narrower than the SDK's
 *  `Connection` on purpose: the salvage path below can produce these two fields
 *  from the connector alone, and cannot honestly produce the rest. */
interface ConnectResult {
  connectorName: string;
  ethereumProvider: IProvider | null;
}

/**
 * `connect()`, but trusting the SDK's STATE over its EVENT.
 */
async function connectTrustingState(web3auth: Web3Auth): Promise<ConnectResult | null> {
  try {
    return await web3auth.connect();
  } catch (err) {
    const connector = web3auth.getConnector(WALLET_CONNECTORS.AUTH);
    const provider = connector?.provider ?? null;
    const hasKey = Boolean((connector as unknown as AuthConnectorShape | null)?.authInstance?.privKey);

    if (provider && hasKey) {
      console.warn(
        "Web3Auth rejected the connect promise but the auth connector holds a live key and provider; " +
          "treating the rejection as spurious and continuing.",
        err,
      );
      closeLoginModal(web3auth);
      return { connectorName: WALLET_CONNECTORS.AUTH, ethereumProvider: provider };
    }

    console.warn("Web3Auth connect failed and nothing could be salvaged.", {
      hasConnector: Boolean(connector),
      hasProvider: Boolean(provider),
      hasKey,
      connected: web3auth.connected,
      status: web3auth.status,
      err,
    });
    throw err;
  }
}

/**
 * Dismiss the SDK's own login modal after a salvaged connection — its SUCCESS
 * path normally does this, and a salvaged connect never takes that path, so the
 * first rescued supplier landed in their portal with the login modal still over
 * it. `loginModal.closeModal()` is the SDK's own public door, but this is
 * cosmetic cleanup on a rescue path:
 */
function closeLoginModal(web3auth: Web3Auth): void {
  try {
    (web3auth as unknown as { loginModal?: { closeModal?: () => void } }).loginModal?.closeModal?.();
  } catch (err) {
    console.warn("Could not close the Web3Auth modal after a salvaged connect.", err);
  }
}

/** Host of a URL, or "" if it will not parse. Never throws — this runs on a
 *  string that came out of a failed request. */
function safeHost(url: unknown): string {
  if (typeof url !== "string" || !url) return "";
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** The message of an Error, or of a `{ message }` / `{ error }` rejection.
 *  Deliberately NOT `String(err)`: that is what produced "[object Response]". */
function messageOf(err: unknown): string {
  if (err instanceof Error) return `${err.name} ${err.message}`;
  if (err && typeof err === "object") {
    const o = err as { message?: unknown; error?: unknown };
    if (typeof o.message === "string") return o.message;
    if (typeof o.error === "string") return o.error;
    return "";
  }
  return typeof err === "string" ? err : "";
}

async function connectOnce(
  onPhase: WalletPhaseListener,
): Promise<{ web3auth: Web3Auth; provider: IProvider; address: string }> {
  if (instance) await disconnect();

  const web3auth = new Web3Auth({
    clientId: CLIENT_ID(),
    web3AuthNetwork: NETWORK(),
    chains: [chainConfig()],
    defaultChainId: chainConfig().chainId,
    // See memoryStorage(): this reaches the SDK's own `Web3Auth-state` key and
    // external-wallet sessions. It does NOT reach the AUTH connector's session
    // tokens — that comment says exactly why, and what does bound them instead.
    storage: {
      sessionId: memoryStorage(),
      accessToken: memoryStorage(),
      refreshToken: memoryStorage(),
      idToken: memoryStorage(),
    },
    /* MFA is required, not offered — the PnP dashboard has no dependable toggle,
     * so this is the code half of the decision. Only a REQUEST, though:
     * `assertThresholdKey()` checks what actually came back, and asking without
     * checking is how a 1/1 key gets minted quietly.
     *
     * `mfaSettings` is deliberately unset: it ranks individual factors (a paid
     * feature) rather than answering "must there be MFA at all". */
    mfaLevel: MFA_LEVELS.MANDATORY,
    /* No third-party telemetry. Left on, `no-modal`'s analytics would identify
     * the clientId to Segment and ship connection events including
     * `is_mfa_enabled` per actor — which a thesis about removing custody has no
     * business exporting. The flag disables it at the source, better than
     * widening the CSP. */
    disableAnalytics: true,
    /*
     * The AUTH entry is not decoration: modalConfig REPLACES the SDK's default
     * wholesale, so omitting it deletes the only login connector and
     * filterConnectors() throws inside an unawaited listener — the modal then opens
     * with no buttons and closing it reports "User closed the modal". External
     * wallets stay listed-but-hidden because filterConnectors() re-adds
     */
    modalConfig: {
      // Injected/discovered wallets would otherwise appear in their own section,
      // below the connectors list and unaffected by the flags above.
      hideWalletDiscovery: true,
      connectors: {
        [WALLET_CONNECTORS.AUTH]: { label: "Auth", showOnModal: true },
        [WALLET_CONNECTORS.METAMASK]: { label: "MetaMask", showOnModal: false },
        [WALLET_CONNECTORS.COINBASE]: { label: "Coinbase", showOnModal: false },
        [WALLET_CONNECTORS.WALLET_CONNECT_V2]: { label: "WalletConnect", showOnModal: false },
        [WALLET_CONNECTORS.BASE_ACCOUNT]: { label: "Base Account", showOnModal: false },
      },
    },
    // Injected-provider discovery exists to surface browser extension wallets,
    // which this flow refuses anyway. Off: fewer moving parts, and nothing
    // enumerates the user's installed extensions.
    multiInjectedProviderDiscovery: false,
  });
  instance = web3auth;

  /* The honest boundary between "a popup is open" and "your key is being
   * rebuilt": CONNECTING fires when the user has picked a method and share
   * retrieval starts. Read off the SDK, not guessed on a timer. The listener
   * dies with the instance in disconnect(). */
  web3auth.on(CONNECTOR_EVENTS.CONNECTING, () => onPhase("reconstructing"));

  // `init()` fetches project config over the network and `connect()` renders the
  // modal; from the user's side both are "the wallet is opening", so one phase
  // spans them. A popup blocker, if there is one, bites inside connect().
  onPhase("opening");
  await web3auth.init();
  const connection = await connectTrustingState(web3auth);
  // Typed `Promise<Connection | null>`, but modal v11's cancellation paths all
  // REJECT and never resolve null — so this branch is an SDK invariant failure,
  // not a cancellation. Kept only because the declared type demands it.
  if (!connection) throw new Error("Web3Auth reported a connection with no connection data.");
  assertAuthConnector(connection.connectorName);
  assertThresholdKey(web3auth);

  const provider = connection.ethereumProvider;
  if (!provider) throw new Error("Wallet did not expose an Ethereum provider.");

  return { web3auth, provider, address: await readAddress(provider) };
}

/** Refuse anything but the tKey connector. `modalConfig` hides the others, but
 *  hiding is a UI decision and this is a trust-model invariant. */
function assertAuthConnector(connectorName: string): void {
  if (connectorName !== WALLET_CONNECTORS.AUTH) {
    throw new Error(
      `Design A requires a Web3Auth tKey account (2-of-3 shares); this connection came from ` +
        `"${connectorName}". Sign in with a social or passwordless account instead.`,
    );
  }
}

/**
 * The SHAPE of the auth connector this file reads, written out rather than
 * imported.
 */
interface AuthConnectorShape {
  authInstance?: {
    privKey?: string;
    state?: { keyMode?: string; userInfo?: { isMfaEnabled?: boolean } };
  } | null;
}

/** `AuthSessionData["keyMode"]` for a threshold key: 2 of n shares, none of
 *  which any single party holds enough of. `"1/1"` and `"v1"` are not this. */
const THRESHOLD_KEY_MODE = "2/n";

/**
 * Refuse anything that is not a 2-of-n threshold key.
 */
function assertThresholdKey(web3auth: Web3Auth): void {
  const connector = web3auth.getConnector(WALLET_CONNECTORS.AUTH) as unknown as AuthConnectorShape | null;
  const state = connector?.authInstance?.state;
  const keyMode = state?.keyMode;

  // 1 — The STRUCTURAL signal, when the server sends it. A mode of "1/1" is an
  //     explicit statement that one share exists and Web3Auth holds it, so it is
  //     refused even though MFA might separately be flagged on.
  if (keyMode === THRESHOLD_KEY_MODE) return;
  if (keyMode) throw notThreshold(keyMode);

  // 2 — The signal this SDK actually populates. Measured on @web3auth/auth 11.8.2:
  // after a completed MFA setup the session carries `userInfo.isMfaEnabled ===
  // true` while BOTH `keyMode` and `tKey` are absent from `authInstance.state` —
  // the key arrives as `privKey` / `coreKitKey` and the tKey internals are not
  // exposed.
  if (state?.userInfo?.isMfaEnabled === true) return;

  // 3 — Neither signal. Refuse: "cannot tell" is not a claim.
  throw notThreshold(keyMode);
}

/** The refusal, shared by both branches so the two paths cannot drift apart. */
function notThreshold(keyMode: string | undefined): Error {
  return new Error(
    keyMode
      ? `This Web3Auth account reconstructed a "${keyMode}" key, not the 2-of-n threshold key ` +
          `Design A requires — at "${keyMode}" the Web3Auth network can reconstruct it alone, so ` +
          `signing here would relocate custody rather than remove it. Refusing to sign.`
      : `This Web3Auth account could not be shown to hold a multi-factor key, which Design A ` +
          `requires: without a second factor the Web3Auth network can reconstruct the key alone. ` +
          `Refusing to sign rather than assert a custody property that has not been verified. ` +
          `If multi-factor is set up on this account, that is a configuration problem with this ` +
          `deployment — please report it.`,
  );
}

/** The EOA the shares reconstruct to. The address is derivable from the key, so
 *  ask for the derivative — even the credential ceremony reads the address from
 *  here and CHECKS the key against it, rather than the other way round. */
async function readAddress(provider: IProvider): Promise<string> {
  const accounts = (await provider.request({ method: "eth_accounts" })) as string[] | null;
  const address = accounts?.[0];
  if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error("Wallet did not return an Ethereum address.");
  }
  // Lower case, always: EIP-55 checksums are a display encoding, and the backend
  // compares addresses as strings (`designA/chainTypes.ts` → `asAddress`).
  return address.toLowerCase();
}

/** Tear down: disconnect the connector, drop the instance, drop the in-memory
 *  session with it. Safe to call when nothing is connected. */
export async function disconnect(): Promise<void> {
  const web3auth = instance;
  instance = null;
  if (!web3auth) return;
  try {
    await web3auth.logout({ cleanup: true });
  } catch {
    // A logout that fails (popup closed, network gone) must not leave the caller
    // stuck: the instance reference is already dropped, the memory storage goes
    // with it, and the next connect() builds a fresh one.
  }
}

// ── The one operation the rest of the app performs ───────────────────────────

/** The two provider-backed signing surfaces, over one live connection. */
function buildSigner(provider: IProvider, address: string, onPhase: WalletPhaseListener): WalletSigner {
  return {
    address,
    /**
     * EIP-191 `personal_sign` — the login/binding surface.
     */
    signMessage: async (message: string) => {
      // Emitted here rather than by the caller: this is the line the user is
      // actually blocked on, reading the message in the wallet.
      onPhase("signing");
      const signature = (await provider.request({
        method: "personal_sign",
        // personal_sign's parameter order is (message, address).
        params: [message, address],
      })) as string;
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        throw new Error("Wallet returned a malformed signature.");
      }
      return signature;
    },

    /**
     * EIP-712 `eth_signTypedData_v4` — the ceremony surface.
     */
    signTypedData: async (payload: unknown) => {
      onPhase("signing");
      const signature = (await provider.request({
        method: "eth_signTypedData_v4",
        // (address, typedData) — the reverse of personal_sign's order.
        params: [address, JSON.stringify(payload)],
      })) as string;
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        throw new Error("Wallet returned a malformed signature.");
      }
      return signature;
    },
  };
}

/**
 * Connect, run `fn` with a live signer, and disconnect — always.
 */
export async function withWallet<T>(
  fn: (signer: WalletSigner) => Promise<T>,
  onPhase: WalletPhaseListener = NO_PHASES,
): Promise<T> {
  const { provider, address } = await connect(onPhase);
  try {
    return await fn(buildSigner(provider, address, onPhase));
  } finally {
    await disconnect();
  }
}

/**
 * One wallet session for a WHOLE ceremony — typed-data signatures and raw-key
 * credential signatures, without a second connect between them.
 *
 * The publish ceremony needs both surfaces (approvals/plan/anchor are EIP-712,
 * the operator's own credentials are ES256K-R over the raw key), and opening a
 * fresh session per surface showed the login window several times for what the
 * user was told is one action. This holds ONE connection for the ceremony's
 * lifetime instead.
 *
 * The key-lifetime rules do not relax: `useKey` reconstructs the key bytes per
 * call and zeroes them in a `finally`, exactly as `withSigningKey` does — what
 * is held across the ceremony is the SESSION (the provider connection), never
 * key material. `disconnect()` in the outer `finally` tears the session down on
 * every path out.
 */
export interface CeremonySession {
  signer: WalletSigner;
  useKey<T>(fn: (key: SigningKey) => T | Promise<T>): Promise<T>;
}

export async function withCeremonySession<T>(
  fn: (session: CeremonySession) => Promise<T>,
  onPhase: WalletPhaseListener = NO_PHASES,
): Promise<T> {
  const { web3auth, provider, address } = await connect(onPhase);
  try {
    return await fn({
      signer: buildSigner(provider, address, onPhase),
      useKey: async (kfn) => {
        let bytes: Uint8Array | null = null;
        try {
          bytes = hexToKeyBytes(await readPrivateKeyHex(web3auth, provider));
          return await kfn({ address, bytes });
        } finally {
          bytes?.fill(0);
        }
      },
    });
  } finally {
    await disconnect();
  }
}

/** What a caller gets inside `withWallet`. Never stored, never returned. */
export interface WalletSigner {
  address: string;
  signMessage(message: string): Promise<string>;
  /** EIP-712. Takes the payload the server built — see the implementation for
   *  why this one goes through the provider while a credential cannot. */
  signTypedData(payload: unknown): Promise<string>;
}

// ── The raw key, for the ONE thing `personal_sign` cannot do ─────────────────

/**
 * The reconstructed key, for the length of one callback.
 */
export interface SigningKey {
  /** The EOA `eth_accounts` reports, lower case — the key's own claim about
   *  itself must be checked against THIS, not assumed to match. */
  address: string;
  /** The 32-byte secp256k1 scalar. Zeroed as soon as `fn` returns or throws. */
  bytes: Uint8Array;
}

export async function withSigningKey<T>(
  fn: (key: SigningKey) => T | Promise<T>,
  onPhase: WalletPhaseListener = NO_PHASES,
): Promise<T> {
  const { web3auth, provider, address } = await connect(onPhase);
  let bytes: Uint8Array | null = null;
  try {
    bytes = hexToKeyBytes(await readPrivateKeyHex(web3auth, provider));
    return await fn({ address, bytes });
  } finally {
    bytes?.fill(0);
    await disconnect();
  }
}

/**
 * The reconstructed key, hex.
 */
async function readPrivateKeyHex(web3auth: Web3Auth, provider: IProvider): Promise<string> {
  const connector = web3auth.getConnector(WALLET_CONNECTORS.AUTH) as unknown as AuthConnectorShape | null;
  const reconstructed = connector?.authInstance?.privKey;
  if (typeof reconstructed === "string" && reconstructed.trim()) return reconstructed.trim();

  for (const method of ["eth_privateKey", "private_key", "eth_private_key"]) {
    try {
      const value = (await provider.request({ method })) as string | null;
      if (typeof value === "string" && value.trim()) return value.trim();
    } catch {
      // `rpcErrors.methodNotSupported()` from a provider that does not implement
      // this one. Try the next spelling; the throw below is the real answer.
    }
  }

  throw new Error(
    "This Web3Auth account did not expose its reconstructed key to the page, so no credential " +
      "signature can be produced here. Design A signs credentials in your browser with your own " +
      "key — the platform holds no share and cannot sign for you.",
  );
}

/** 64 hex chars → 32 bytes, strictly.
 *
 *  Strict because everything downstream trusts the length: a short key silently
 *  left-padded is a DIFFERENT key, and a different key is a different issuer.
 *  The all-zero scalar is refused explicitly — it is not a valid secp256k1
 *  private key, and letting it reach `sign()` turns a wallet misconfiguration
 *  into a curve-library stack trace. */
function hexToKeyBytes(hex: string): Uint8Array {
  const raw = (hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(raw)) {
    throw new Error("The wallet returned a key that is not 32 bytes — refusing to sign with it.");
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) bytes[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  if (bytes.every((b) => b === 0)) {
    throw new Error("The wallet returned an empty key — refusing to sign with it.");
  }
  return bytes;
}

/**
 * `did:ethr:0x<chainIdHex>:<address>` — the identifier this address becomes.
 */
export function didForAddress(address: string): string {
  return `did:ethr:${chainConfig().chainId}:${address.toLowerCase()}`;
}
