# Design A CSP — the enumerated origins

**Fills in the table ADR-001 §2 deliberately left blank.** That ADR was written
*before* `npm install @web3auth/modal` so the policy could not be reverse-engineered
from console errors; this file is the other half of the deal — the origins, read out
of the SDK's own network configuration rather than out of a browser devtools tab.

**Scope: `web3.trustdpp.co` only.** Do **not** apply any of this to
`frontend_dpp/nginx.conf`, which is Design B's live production config for
`app.trustdpp.co` and must stay exactly as it is.

**Measured against** `@web3auth/modal@11.3.0` (→ `@web3auth/no-modal@11.3.0`,
`@web3auth/auth@11.8.2`, `@web3auth/ws-embed`, `@toruslabs/*`), with
`WEB3AUTH_NETWORK = sapphire_mainnet`. Re-derive on any SDK major bump: this is a
list of hosts a compromised page may send key material to, and it ages with the
dependency, not with the calendar.

---

## Where each origin comes from

Every host below was read from a constant inside an installed package. Nothing is
guessed and nothing is a wildcard — `https://*.web3auth.io` would make any subdomain
an attacker can obtain a legal exfiltration target for share material, which is the
one thing this policy exists to prevent.

| Origin | Source in `node_modules` | What it is |
|---|---|---|
| `https://api.web3auth.io` | `@toruslabs/constants` → `SIGNER_MAP`, `METADATA_MAP`, `FND_SERVER`, `SESSION_SERVER` | signer, metadata, node-details and session services (`/signer-service`, `/metadata-service`, `/fnd-service`, `/session-service`, `/citadel-service`) |
| `https://session.web3auth.io` | `@toruslabs/constants`, `@toruslabs/broadcast-channel` | session/pub-sub server the login popup talks back through |
| `https://node-1.node.web3auth.io` … `https://node-5.node.web3auth.io` | `@toruslabs/fnd-base` (`SAPPHIRE_MAINNET` node list), `@toruslabs/torus.js` | **the Sapphire share network** — the 5 nodes that hold the *network* share of the 2-of-3 |
| `https://auth.web3auth.io` | `@web3auth/auth` (`BUILD_ENV.PRODUCTION`) | the OAuth/login **popup** origin — needs `frame-src`, not just `connect-src` |
| `https://account.web3auth.io` | `@web3auth/auth` | account / MFA management screens |
| `https://wallet.web3auth.io` | `@web3auth/ws-embed` | wallet-services iframe |
| `https://assets.web3auth.io`, `https://images.web3auth.io` | `@web3auth/modal` UI | modal logos and wallet-registry icons (`img-src` only) |
| `https://metadata.tor.us` | `@toruslabs/metadata-helpers`, `@toruslabs/customauth` | legacy Torus metadata host, still reached on some share-migration paths |
| *(the configured RPC endpoint)* | our own `VITE_RPC_URL` / backend `RPC_URL` | the EVM JSON-RPC the provider calls |

**Deliberately excluded**, though they appear in the packages:

- `api-develop.web3auth.io`, `develop-*`, `staging-*` — the `BUILD_ENV.DEVELOPMENT`
  and `.STAGING` variants. Production runs `BUILD_ENV.PRODUCTION`, so allowing them
  would widen the policy for endpoints this build never calls.
- `node-N.dev-node.web3auth.io` — the **`sapphire_devnet`** share network. Devnet and
  mainnet derive *different addresses for the same user*; a stack pinned to
  `sapphire_mainnet` must never reach these, and the CSP is a good place to say so.
  A devnet stack swaps this block, it does not add to it.
- `accounts.google.com`, `www.facebook.com`, `discord.com`, `id.twitch.tv`, … — the
  social IdPs. The OAuth redirect happens **inside the `auth.web3auth.io` popup**,
  which is a separate browsing context with its own policy. Our page never navigates
  to or fetches from an IdP, so allowing them here would be pure over-permission.
- `api.mainnet-beta.solana.com` and the other chain RPCs bundled in the SDK's default
  chain list — Design A is EVM-only and passes its own `chains`.

---

## The policy

```
default-src 'self';

script-src 'self';

connect-src 'self'
  https://api.web3auth.io
  https://assets.web3auth.io
  https://session.web3auth.io
  https://node-1.node.web3auth.io
  https://node-2.node.web3auth.io
  https://node-3.node.web3auth.io
  https://node-4.node.web3auth.io
  https://node-5.node.web3auth.io
  https://auth.web3auth.io
  https://metadata.tor.us
  <RPC_URL>
  <RPC_URL_FALLBACK>;

frame-src
  https://auth.web3auth.io
  https://account.web3auth.io
  https://wallet.web3auth.io;

worker-src 'self' blob:;

style-src 'self' 'unsafe-inline';

img-src 'self' data: blob:
  https://assets.web3auth.io  # also in connect-src: the SDK FETCHES
                             # wallet-registry.json from here, it is not only an image host
  https://images.web3auth.io;

font-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
object-src 'none';
```

Substitute the two `<RPC_URL…>` placeholders with the exact origins from the A
stack's `.env.a` (they are already required there with no defaults). Ship it as
`Content-Security-Policy-Report-Only` first, per ADR-001 §4.

---

## Findings against ADR-001

### 1. `'unsafe-eval'` is NOT required — ✅

ADR-001 §3 said a library demanding full `'unsafe-eval'` would be a **blocking
finding**. It does not arise. `script-src 'self'` — with neither `'unsafe-eval'` nor
`'unsafe-inline'` — is sufficient for `@web3auth/modal@11.3.0`.

The check was run on the **emitted bundle**, not on `node_modules`, because that is
what a browser actually evaluates: a `node_modules` grep is dominated by the SDK's own
nested dev dependencies (`vite`, `vitest`, `es-module-lexer` all use `eval` and never
ship). Built with the wallet reachable, the whole `dist/assets/*.js` set contains:

- **no `eval(`** and **no `new Function(`** — anywhere;
- **no `WebAssembly.*` call.** The single textual hit is the string literal
  `"[object WebAssembly.Exception]"` inside `@toruslabs/loglevel-sentry`'s
  error-type switch — a comparison against a tag name, not a use of WASM;
- **no `.wasm` asset** emitted, and none present in `@web3auth/**` or `@toruslabs/**`;
- **no `new Worker(`**.

`@toruslabs/ffjavascript@6.0.0` was checked specifically, since it is the one
dependency in this tree that *can* compile WASM at runtime and is therefore the
reason to look. Its `dist/` contains no `new Function`, no `eval(` and no
`WebAssembly`; it arrives transitively via `@web3auth/auth` and stays pure JS on the
paths this SDK takes.

So **`'wasm-unsafe-eval'` is not needed either**, and should not be added
"pre-emptively": ADR-001's method is that a directive appears only when a named thing
needs it.

⚠ **Re-check on every SDK bump**, do not assume. Web3Auth's MPC/TSS line
(`@web3auth/mpc-core-kit`) *does* ship WASM, so a move from PnP tKey to core-kit would
legitimately introduce `'wasm-unsafe-eval'` — permitted by ADR-001 §3, unlike full
`'unsafe-eval'`. Re-run it against the build, not the tree:

```sh
# with a dynamic import of src/lib/wallet reachable from the entry
npm run build
grep -olE "(new Function\(|[^a-zA-Z_.\"']eval\(|WebAssembly\.|new Worker\()" dist/assets/*.js
find dist -name '*.wasm'
```

### 2. `worker-src 'self' blob:` is provisional — and may be droppable

ADR-001 §2 lists it because "some SDKs spawn workers from blobs". **No `new Worker(`
appears in the emitted bundle at all.** It is kept only because
`@toruslabs/broadcast-channel` picks a transport at runtime and a worker fallback is
within its documented behaviour. It is the one directive here not backed by a located
constant, so it is the first thing to drop if the report-only phase records no worker
violations.

### 3. `style-src 'unsafe-inline'` is inherited, and the modal needs it

Carried over from Design B unchanged. The Web3Auth login modal injects inline
styles, so removing it would break the popup. Worth stating plainly rather than
leaving implicit: it is the weakest directive in this policy and it is the one
Design A did not introduce.

### 4. SRI (ADR-001 §5) is not addressed here

Subresource-integrity pinning of the wallet bundle is a build/deploy concern, not a
CSP one, and is still outstanding. Note that the wallet chunk is now ~3.5 MB across
~44 lazily-loaded files, so "SRI-pin the wallet bundle" means pinning a *chunk graph*
— worth designing before promising it in the thesis.
