# `src/lib/wallet/` — the client-side key boundary

Design A's non-custodial signing key is reconstructed **in this browser**, from
2-of-3 Web3Auth tKey shares (device / network / recovery). The platform holds no
share and cannot sign. Everything that touches that key lives in this directory
and nowhere else. Read `index.ts` for the contract callers may depend on.

## The rule

1. **All Web3Auth / tKey / EVM / JOSE / curve code lives in this directory.**
   (`@noble/*` included — it is what actually touches the private key.)
   No other file in `src/` may import those packages. The rest of the app talks
   to a wallet through the small surface in `session.ts`, never to a library.
2. **This directory is only ever reached through a dynamic `import()`.**
   A static `import { … } from "@/lib/wallet/…"` anywhere outside this directory
   is a bug, even if it type-checks: it links the whole Web3Auth tree into the
   entry chunk, which every anonymous QR scan then downloads before it can see a
   passport.

```ts
// correct — the chunk is fetched when a user actually signs in
const { signInWithWallet } = await import("@/lib/wallet/session");
const session = await signInWithWallet();

// wrong — this lands Web3Auth in the entry chunk
import { signInWithWallet } from "@/lib/wallet/session";
```

`import type` is always fine: types are erased, so they cost no bytes and pull in
no code.

## Why the boundary is drawn here and not somewhere else

Key handling should be auditable by reading one directory. The narrower the
surface that ever touches a private key, the shorter the list of files a reviewer
has to trust — and under D7 (WYSIWYS) that list *is* the security argument.

The bundle argument reinforces the same line. The consumer passport page is the
platform's highest-traffic, lowest-trust surface — an anonymous phone scan. It
needs no wallet at all. Design B users never need one either. Only a producer or
supplier signing in does.

**The numbers, measured on `@web3auth/modal@11.3.0`:** the SDK is ~3.5 MB of
JavaScript across ~44 lazily-loaded chunks. Behind the dynamic import it costs the
entry chunk **169 bytes** (the import stub). A single static import would move all
3.5 MB onto the critical path of every QR scan.

## Enforcement

- **ESLint wallet wall — R6**, in `frontend_dpp/eslint.config.js`. Forbids
  `ethers` / `@web3auth/*` / `@tkey/*` / `@toruslabs/*` / `@noble/*` / `jose` / … outside
  `src/lib/wallet/**`, and forbids the STATIC form of importing this directory
  (ESLint sees import declarations but not `import()` expressions, so banning the
  path permits exactly the lazy form). `allowTypeImports: true`. **Build error.**
- **CI entry-chunk budget — 512 KB**, in `.github/workflows/ci.yml`. The lint
  catches the cause; the budget catches the consequence.
  ⚠ The budget now reads the entry from `dist/index.html`. It used to glob
  `dist/assets/index-*.js | head -1`, which stopped working the moment Web3Auth
  was installed: Rollup names a vendor chunk after its source file, and this SDK
  emits ~20 chunks called `index-<hash>.js`. The glob picked an arbitrary 1 KB
  vendor chunk, so the budget silently measured nothing.

## Contents

| File | Responsibility |
|---|---|
| `index.ts` | the types callers may depend on (`WalletSession`, `WalletPhase`) — never a library type |
| `web3auth.ts` | tKey login, key lifetime, address derivation, `personal_sign`, `eth_signTypedData_v4`, `withSigningKey`, `did:ethr` derivation |
| `session.ts` | challenge → sign → platform session; binding, and the pre-binding preview |
| `signer.ts` | credential values → ES256K-R JWS. **The only module that reads a private key** |
| `typedData.ts` | EIP-712 approval / checkpoint / anchor / issuer-authorization signing |
| `env.d.ts` | the build-time `VITE_*` inputs, typed and documented |
| `CSP.md` | the enumerated Torus/Web3Auth origins for ADR-001's policy |

The three ceremonies a caller may run, all from `session.ts`:

| Function | Signs? | Changes state? |
|---|---|---|
| `signInWithWallet({ company?, onPhase? })` | login challenge | provisions an org on first sight of an address |
| `previewWalletBinding({ onPhase? })` | **no** | **no** — connect, read the address, derive its DID, disconnect |
| `bindWallet(token, { onPhase? })` | bind challenge | mints the org's `did:ethr`; irreversible |

`previewWalletBinding` exists because binding is the one action with no undo:
the confirmation screen has to name the exact address AND the exact `did:ethr`
before the user agrees, and only a live connection knows the address. The cost is
that binding opens the wallet twice.

## Progress, reported from inside

`WalletPhase` (in `index.ts`) is the small, SDK-free vocabulary a caller renders
while a ceremony runs: `loading-wallet → opening → reconstructing → challenging →
signing → verifying`. Every phase is emitted at the line that starts the work,
and `reconstructing` comes off the SDK's own `CONNECTOR_EVENTS.CONNECTING` — so
it means shares really are being combined, not that a timer elapsed.

This matters more than it looks: the ceremony is comfortably ten seconds on a
phone, and two of its waits are for the USER. A button that says "Signing in…"
for all of them gives someone no way to tell that the popup behind their browser
is what everything is waiting on. Callers pass `onPhase`; passing nothing is
supported and changes no behaviour.

The UI-side copy for these phases — and for every failure mode — lives OUTSIDE
this directory, in `src/lib/trust/walletAuth.ts`. Two reasons: a login screen must
decide whether to offer wallet sign-in *before* loading 3.5 MB of SDK, and error
copy that lives behind the failing import cannot render "the wallet couldn't be
downloaded".

A fourth ceremony, from `signer.ts`:

| Function | Signs? | Changes state? |
|---|---|---|
| `signAttestation(claim, { onPhase? })` | the credential JWS (ES256K-R) | no — the caller uploads the result |

`claim` is the decomposed VALUES, never a pre-built document: the browser
assembles the credential from exactly what it displayed (D7). The display side
lives in `src/lib/trust/attestation.ts` and `components/supplier/AttestationPanel.tsx`.

And two more from `typedData.ts` — EIP-712 through the provider, never the raw
key (a provider *can* produce an EIP-712 signature and *cannot* produce an
ES256K-R one, which is the exact inverse of `signer.ts`'s constraint):

| Function | Signs? | Changes state? |
|---|---|---|
| `signTypedData(payload, expectedAddress, { onPhase? })` | one EIP-712 payload — approval, checkpoint, anchor, `setIssuer` | no — the caller posts the result, or the relayer submits it |
| `signTypedDataBatch(items, expectedAddress, { onPhase? })` | several, in order, in **one** wallet opening | no — all-or-nothing: the first refusal aborts and nothing is uploaded |

Both take `expectedAddress` and refuse locally when the reconstructed wallet is
not the one the org's `did:ethr` names — otherwise the failure would arrive from
the server as "your approval was signed by somebody else".

Verification steps are **not** here: they read public data, need no key, and
belong to the trust adapter in `src/lib/trust/steps.ts`.

## Key lifetime

`withWallet(fn)` in `web3auth.ts` is the only way in. It connects, runs one
operation, and disconnects in a `finally` — so every path out of a ceremony,
including a thrown error or a closed popup, ends with the key gone.

Three things bound how long a key is reachable:

- **login and binding never see key bytes at all** — they go through
  `personal_sign` on the EIP-1193 provider, as does every EIP-712 signature;
- the bytes `withSigningKey` does read live in one `Uint8Array`, zeroed in a
  `finally`;
- the instance is torn down after every use, and that teardown (`disconnect()` →
  `logout()`) is what clears the SDK's session token.

### What "persisted" actually means here

This section used to claim that replacing Web3Auth's storage adapters with
in-memory `Map`s meant *nothing* was persisted. That was **wrong**, and the
correction is worth stating precisely because the difference is a live session
token.

`coreOptions.storage` reaches exactly two places in `@web3auth/modal@11.3.0`:
`noModal.js`'s `getStorageMethod()` (which reads only `storage.sessionId`, for
the SDK's own `Web3Auth-state` key) and `baseConnector.js` (external-wallet SIWE
sessions, which this app refuses anyway). It does **not** reach the AUTH
connector: `authConnector.js` constructs its `Auth` without a `storage` option,
so `AuthSessionManager.resolveStorage()` falls back to `LocalStorageAdapter` for
`sessionId` / `accessToken` / `idToken` and `CookieStorage` for `refreshToken`.
Those survive a reload, and `Auth.init()` reads them and repopulates
`state.privKey` **before any user interaction**.

There is no supported way to inject storage into that connector on 11.3.0:
`loadConnectors()` is explicit ("always add auth connector") and appends its own
`authConnector()` unconditionally, so passing a configured one via
`coreOptions.connectors` yields two.

So the true guarantees are narrower than the old ones, and they are these:

- **no private key is ever written to `localStorage`, a cookie, or anywhere else
  durable** — the key bytes exist only inside `withSigningKey`;
- a **session token** can persist, and it is enough to re-derive the key;
- `disconnect()` → `logout()` clears it, and every ceremony runs `disconnect()`
  in a `finally` — but `logout()` throws when nothing is connected (we swallow
  that), and a tab closed mid-ceremony never reaches the `finally` at all.

Net: an XSS payload landing after a **completed** ceremony finds nothing; one
landing after an **abandoned** ceremony may find a session token. The teardown
is the mitigation, not the storage option.

The cost is accepted: signing is a deliberate ceremony with a login each time,
not an ambient capability. A key that is always ready to sign is a key the page
can always be tricked into using.

## MFA is required, and the result is checked

The key must be a **2-of-n threshold key**, and `web3auth.ts` does two things to
make sure it is:

1. `mfaLevel: MFA_LEVELS.MANDATORY` on the core options — the Plug-and-Play
   dashboard has no dependable toggle, so this is a code decision. It rides
   `coreOptions.mfaLevel` → the auth connector's `loginSettings` →
   `authInstance.login()`.
2. `assertThresholdKey()` inside `connect()` — after connecting, it reads
   `authInstance.state.keyMode` and **refuses anything but `"2/n"`**.

The second is not belt-and-braces. `keyMode === "1/1"` means a single share held
by the Web3Auth network, which the network alone can reconstruct: at `1/1` the
design has not removed custody, it has *relocated* it from the platform to
Web3Auth, and the evaluation's independent variable is gone while every screen
still says the key is the actor's. An absent `keyMode` fails the same way — the
check exists to support a claim, and "cannot tell" is not a claim.

`connect()` is the single choke point for **every** ceremony (login, binding,
credential JWS, EIP-712), so there is no path around it. The failure renders as
an operator/configuration fault via `lib/trust/walletAuth.ts`, never as a user
mistake.

Analytics are off (`disableAnalytics: true`). The SDK otherwise loads
`@segment/analytics-next` on any non-localhost `https://` origin and reports
`dapp_url`, connection events and **`is_mfa_enabled`** per actor, plus a
`web3auth_ajs_user_id` cookie. `noModal.js`'s constructor honours the flag and
every `init`/`identify`/`track` returns early once disabled — which is also why
`CSP.md` need not allow `cdn.segment.com` / `api.segment.io`.

## The one operation that does read the key: `withSigningKey`

A credential JWS is **ES256K-R over plain `SHA-256(header.payload)` with no
EIP-191 prefix** (see `backend_dpp/src/domain/trust/designA/jose.ts`).
`personal_sign` cannot produce it: it prefixes unconditionally, hashes with
keccak256, and returns recovery id 27/28. A `personal_sign` signature over a JWS
signing input recovers a *different* public key, so the failure presents as "the
issuer's own credential was issued by a stranger" with nothing pointing at a
prefix. No provider method signs a bare digest, so the digest is signed with the
key.

That is the trust model working, not a hole in it: the key is the *actor's*,
reconstructed from 2-of-3 tKey shares in the actor's own browser, and this code
runs on the actor's machine. `withSigningKey` obtains it from
`connector.authInstance.privKey` — a public field of `AuthConnector` holding a
public getter of `Auth`, i.e. the SDK's documented non-custodial contract —
falling back to the provider's key-export methods.

Those are `eth_privateKey` and `private_key`, in that order. On an EIP155 chain
the auth connector never assigns `privateKeyProvider`; it builds a `WsEmbed`, and
its `provider` getter returns the ws-embed in-page provider, whose method table
(`@web3auth/ws-embed/.../constants.js`) spells them exactly those two ways. The
snake-case `eth_private_key` is tried last as a hedge only — it exists in the
tree, but solely in `WalletConnectV2Provider`'s middleware (a connector we
refuse) and the account-abstraction provider's (we configure none), so it never
fires today. Export is permitted at the project level: dashboard **Enable Key
Export: ON**.

Guarantees, all in `web3auth.ts` and `signer.ts`:

- the bytes live in one `Uint8Array`, passed to **one** callback, zeroed in a
  `finally` on every path out;
- they are never returned, never stored, never logged, never sent anywhere;
- `signer.ts` derives the address from the key and refuses to sign unless it
  matches both `eth_accounts` and the organization's `did:ethr`;
- the document, header and signing input are assembled **before** the wallet
  opens, so the key-reachable window is one address derivation, two comparisons
  and one ECDSA operation.

Honest limit: the SDK hands the key out as a hex *string*, and JS strings are
immutable — that one string can only be dropped for the GC, not wiped. It is
never bound to anything that outlives the call.
