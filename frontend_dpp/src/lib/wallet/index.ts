/**
 * ─── The client-side key boundary (R4) ────────────────────────────────────────
 *
 * ALL Web3Auth / tKey / EVM-signing code lives under `src/lib/wallet/`, and this
 * directory is ONLY ever reached through a dynamic `import()`:
 *
 *     const { signInWithWallet } = await import("@/lib/wallet/session");  // correct
 *     import { signInWithWallet } from "@/lib/wallet/session";            // WRONG
 *
 * A static import links the whole Web3Auth tree into the entry chunk, which
 * every anonymous QR scan then downloads before it can see a passport — a page
 * that needs no wallet at all. Two things enforce it: the ESLint wallet wall
 * (R6, `frontend_dpp/eslint.config.js`) makes the static form a build error, and
 * CI's 512 KB entry budget catches anything that slips past. See README.md here
 * for the full rule.
 *
 * `import type` from this directory is always fine — types are erased, so they
 * cost no bytes and pull in no code. Callers should depend on THESE types and
 * never on a Web3Auth one, so the SDK stays swappable.
 *
 * ## What lives where
 *
 * | File          | Responsibility                                              |
 * |---------------|-------------------------------------------------------------|
 * | `web3auth.ts` | tKey login, key lifetime, address derivation, `personal_sign`, `eth_signTypedData_v4`, `withSigningKey` |
 * | `session.ts`  | challenge → sign → platform session; wallet binding           |
 * | `signer.ts`   | credential values → ES256K-R JWS. THE only key-touching module |
 * | `typedData.ts`| EIP-712 approval / checkpoint / anchor / authorization signing |
 * | `CSP.md`      | the enumerated origins Design A's CSP must allow (ADR-001)    |
 *
 * The same key signs all three, which is why `session.ts` goes to such lengths to
 * keep them structurally distinguishable: `personal_sign` is `0x19 0x45 …` with
 * recovery 27/28, EIP-712 is `0x19 0x01 …`, and a credential is a bare SHA-256
 * digest with recovery 0/1. Note that only `signer.ts` reads the raw key —
 * `typedData.ts` goes through the provider, because a provider CAN produce an
 * EIP-712 signature and cannot produce an ES256K-R one.
 *
 * Verification steps are deliberately NOT here: they read public data, need no
 * key, and belong to the trust adapter in `src/lib/trust/steps.ts`.
 */

/**
 * ─── Progress, as reported from where it actually happens ─────────────────────
 * tKey reconstruction is not fast — three shares are fetched and recombined over
 * the network while a popup the user has to interact with sits in front of them.
 * A button that says "Signing in…" for eight seconds is indistinguishable from a
 * button that has hung, and a user who cannot tell reaches for the close box.
 */
export type WalletPhase =
  /** Fetching this directory's chunk — ~3.5 MB of SDK, on a phone, once. */
  | "loading-wallet"
  /** SDK booting and the Web3Auth modal opening. The popup appears in here. */
  | "opening"
  /**
   * The provider failed its own first connect and we are opening its window a
   * SECOND time. A phase of its own because the user is about to be asked to pick
   * a login method again, seconds after already picking one — and without a label
   * saying so, that reads as the app having lost their sign-in. It fires only on
   * the retry path in `web3auth.ts`; a normal ceremony never emits it.
   */
  | "reopening"
  /** The user picked a login method; 2-of-3 shares are being combined. */
  | "reconstructing"
  /** Asking the server for the EIP-4361 message to sign. */
  | "challenging"
  /** `personal_sign` is pending — the user is reading the message in the wallet. */
  | "signing"
  /** The signed message is with the server, which is recovering the signer. */
  | "verifying";

/** Where to send phase changes. Optional everywhere: a caller that does not care
 *  passes nothing and the ceremony behaves exactly as it did before. */
export type WalletPhaseListener = (phase: WalletPhase) => void;

/** Options every ceremony in `session.ts` accepts. */
export interface WalletCeremonyOptions {
  onPhase?: WalletPhaseListener;
}

/** A wallet session: who signed in, and which key the browser reconstructed. */
export interface WalletSession {
  /** The EOA the tKey shares reconstruct to — lower case, always. */
  address: string;
  /**
   * `did:ethr:<chainIdHex>:<address>`, as the resolver will resolve it — or the
   * empty string when the org has not BOUND this wallet yet. Login and binding
   * are separate steps: an address can sign in before it is the org's issuer.
   */
  did: string;
}
