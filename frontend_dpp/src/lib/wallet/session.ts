import { API_BASE } from "@/api/base";
import { setSession } from "@/api/session";
import type { User } from "@/types";
import type { WalletCeremonyOptions, WalletPhaseListener, WalletSession } from "./index";

/**
 * ─── challenge → sign → platform session ──────────────────────────────────────
 * The three-step exchange that turns "I control this key" into an ordinary
 * TrustDPP session. It lives inside the wallet boundary because step 2 needs a
 * signer, and it is the only place the two halves meet.
 */

/** `fetch` for the auth surface: credentialed (the refresh cookie is set on the
 *  response) and never routed through the app's 401-retry client, which would
 *  try to refresh a session that does not exist yet. */
async function authFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let body: { error?: string } | null = null;
    try {
      body = (await res.json()) as { error?: string };
    } catch {
      /* non-JSON error body */
    }
    const err = new Error(body?.error ?? `Request failed (${res.status})`) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

/** What the challenge endpoint hands back. The nonce is inside `message` — it is
 *  not returned separately, precisely so a client cannot assemble its own. */
interface Challenge {
  message: string;
  expiresAt: string;
}

const challenge = (address: string, purpose: "login" | "bind"): Promise<Challenge> =>
  authFetch<Challenge>(
    `/api/auth/challenge?address=${encodeURIComponent(address)}&purpose=${purpose}`,
  );

/** Phase sink for callers that pass none — see `web3auth.ts`. */
const NO_PHASES: WalletPhaseListener = () => {};

/**
 * Load this directory's other half.
 *
 * Split out so the ~3.5 MB chunk fetch gets its OWN phase. On a phone on mobile
 * data that download is seconds of nothing happening, and it is the one part of
 * the ceremony where a spinner with no label reads as a broken button.
 */
async function loadWallet(onPhase: WalletPhaseListener) {
  onPhase("loading-wallet");
  return import("./web3auth");
}

interface WalletLoginResponse {
  user: User;
  token: string;
  tab: string;
  address: string;
  /** True when this login created the organization (first sight of this wallet). */
  provisioned: boolean;
}

/**
 * Sign in with the org's non-custodial wallet.
 */
export async function signInWithWallet(
  opts: WalletCeremonyOptions & {
    company?: string;
    /* Accepting a supplier invitation with a wallet instead of a password.
     *
     * Passed straight through to `/wallet-login`, which forks on it: with a
     * token the server consumes the invite, provisions a SUPPLIER org and
     * inherits the operator's node bindings; without one it self-registers a
     * producer. The browser does not need to know that difference — it proves
     * the same address the same way either way. */
    inviteToken?: string;
    /** True only from the register card. Sign-in must not create organizations —
     *  see the server's own note on `loginWithWallet`. */
    register?: boolean;
  } = {},
): Promise<WalletSession & { user: User; provisioned: boolean }> {
  const onPhase = opts.onPhase ?? NO_PHASES;
  const { withWallet } = await loadWallet(onPhase);

  const result = await withWallet(async (signer) => {
    onPhase("challenging");
    const { message } = await challenge(signer.address, "login");
    const signature = await signer.signMessage(message);
    onPhase("verifying");
    const login = await authFetch<WalletLoginResponse>("/api/auth/wallet-login", {
      method: "POST",
      body: JSON.stringify({
        address: signer.address,
        message,
        signature,
        ...(opts.company ? { company: opts.company } : {}),
        ...(opts.inviteToken ? { inviteToken: opts.inviteToken } : {}),
        ...(opts.register ? { register: true } : {}),
      }),
    });

    /*
     * Binding used to be a second, manual trip: sign in, find a Settings page, press
     * a button, sign again — for a decision the user had already made by choosing
     * which account to sign in with. Safe to fold in silently because the server
     * permits REBINDING until the org has issued its first credential, so the
     * wrong-account mistake is recoverable by signing in with the right one.
     */
    if (!login.user.did) {
      try {
        const bound = await bindWithSigner(signer, login.token, onPhase);
        // The server minted the DID in this same request cycle — reflect it so
        // the caller (and the session store below) see the bound identity
        // rather than a pre-bind snapshot.
        login.user = { ...login.user, did: bound.did, didShort: bound.didShort ?? login.user.didShort };
      } catch (err) {
        console.warn("[trustdpp] automatic binding after sign-in did not complete", err);
      }
    }
    return login;
  }, onPhase);

  // Join the shared session plane. Identical to what `api.login` does after a
  // password login — same store, same subscribers, same refresh behaviour.
  setSession(result.token, result.user);

  return {
    address: result.address,
    // The org's `did:ethr` only exists once the wallet is BOUND (see below), so
    // a freshly provisioned account legitimately has none yet. `user.did` is the
    // server's answer; an empty string here would be a fabricated identifier.
    did: result.user.did ?? "",
    user: result.user,
    // Surfaced, not swallowed: a first-ever login has an org with NO issuer
    // identity, and the only useful next screen is the binding one. Without this
    // flag the UI cannot tell "welcome back" from "your org exists but cannot
    // issue anything yet" and would drop a new operator on an empty dashboard.
    provisioned: result.provisioned,
  };
}

/**
 * Which address the user controls, and the `did:ethr` it would become — without
 * binding anything.
 */
export async function previewWalletBinding(
  opts: WalletCeremonyOptions = {},
): Promise<WalletSession> {
  const onPhase = opts.onPhase ?? NO_PHASES;
  const { withWallet, didForAddress } = await loadWallet(onPhase);
  return withWallet(
    (signer) => Promise.resolve({ address: signer.address, did: didForAddress(signer.address) }),
    onPhase,
  );
}

interface WalletBinding {
  orgId: string;
  address: string;
  did: string;
  didShort: string | null;
  boundAt: string;
  alreadyBound: boolean;
}

/**
 * Bind this wallet as the organization's issuer identity.
 */
export async function bindWallet(
  accessToken: string,
  opts: WalletCeremonyOptions = {},
): Promise<WalletBinding> {
  const onPhase = opts.onPhase ?? NO_PHASES;
  const { withWallet } = await loadWallet(onPhase);
  return withWallet((signer) => bindWithSigner(signer, accessToken, onPhase), onPhase);
}

/** The bind ceremony against an ALREADY-OPEN wallet.
 *
 *  Split out of {@link bindWallet} so sign-in can run it inside its own wallet
 *  session instead of opening a second one. `withWallet` tears the session down
 *  in its `finally` and Web3Auth state is deliberately memory-only, so "call
 *  bindWallet after signing in" does not reuse anything — it re-opens the full
 *  provider chooser. That is exactly the popup-after-login this split removes. */
async function bindWithSigner(
  signer: { address: string; signMessage(message: string): Promise<string> },
  accessToken: string,
  onPhase: WalletPhaseListener,
): Promise<WalletBinding> {
  onPhase("challenging");
  const { message } = await challenge(signer.address, "bind");
  const signature = await signer.signMessage(message);
  onPhase("verifying");
  return authFetch<WalletBinding>("/api/auth/wallet/bind", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ address: signer.address, message, signature }),
  });
}
