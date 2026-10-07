# `designA/` — the Design A trust implementation

Design A is the thesis architecture: **`did:ethr`** identities, **non-custodial**
Web3Auth tKey keys (2-of-3 shares; the platform holds **no** share and cannot
sign), **VC-JOSE-COSE ES256K-R** credentials, and on-chain anchoring to
`TrustAnchorRegistry` on **Polygon Amoy (chainId 80002)**.

Design B (live in production) is untouched by everything in this folder.

## The containment rule

Every EVM and JOSE library is confined here, enforced by
`backend_dpp/eslint.config.js` — a bypass is a build error, not a review note:

- **`ethers` has exactly ONE importer: `chainGateway.ts`.** Not "mostly one".
  The gateway is what makes the entire provider testable against a fake and what
  keeps a chain swap from reaching business logic. Verify with:
  `grep -rn 'from "ethers"' src/ | grep -v designA` → must be empty.
- `@web3auth/*`, `@tkey/*`, `jose`, `did-jwt*`, `ethr-did*`, `viem`, `web3` may
  not be imported anywhere outside `src/domain/trust/designA/**`.
- Deleting this folder plus `contracts/` must remove Design A entirely.
  Deletability is the debt ceiling, and it is measurable.

## What is here

| File | Role |
|---|---|
| `chainTypes.ts` | Chain-facing vocabulary: `ProductId`, `Address`, `SignedCall`, `AnchorRecord`, and `normalizeSignedCall` — which **both** gateways run, so both reject the same bytes. |
| `chainGateway.ts` | The `ChainGateway` interface + `EthersChainGateway`. The only file importing `ethers`. Minimal hand-written ABI fragments rather than generated artifacts, because the backend consumes `contracts/deployments/<network>.json` for **addresses and nothing else**. |
| `fakeChainGateway.ts` | `FakeChainGateway` — in-memory, deterministic, zero network. Reproduces the contract's *semantics*, including its failure modes. |
| `typedData.ts` | EIP-712 payload construction for `claimProduct` / `setIssuer` / `anchor`. **Builds and validates payloads; never signs one** — signing happens in the actor's browser. Domain read from the contract via ERC-5267, not transcribed. |

## Two invariants worth stating plainly

**1. "Chain unreachable" is never "not authorized."**
`isAuthorized` returning `false` because an RPC was down would be a security
failure dressed as a degraded read — it would silently authorize nobody, or
worse, be caught and defaulted. Unavailability **throws**; `null`/`false` mean
the chain genuinely said so. Both gateways behave identically here, and the fake
can simulate outages (`setUnavailable`, `failNextRead`) so callers are forced to
confront it.

**2. The relayer pays gas and holds no authority.**
`TrustAnchorRegistry` authorizes on `ecrecover` over an EIP-712 payload and
ignores `msg.sender` — the deployed runtime bytecode provably never executes the
`CALLER` opcode. `submitSignedCall` therefore forwards a **pre-signed** payload
and cannot construct one; a payload recovering to the relayer's own address is
refused outright. A hostile relayer can delay or refuse to submit (the modelled
censoring-relayer threat) but can never forge, authorize, or anchor.

## What is attested, and what deliberately is not

Three layers get conflated easily, so they are named separately here.

| Layer | Covers | Attested by |
|---|---|---|
| **Authentication** | everyone who logs in | the actor's own key (SIWE-style challenge) |
| **Audit trail** | every mutation, 29 action types, hash-chained | the platform *(it writes the rows)* |
| **Attestation** | claims that leave the platform, and decisions the regulation makes substantive | the actor's own key |

**Signed by the actor:**

- **Credentials** — each contributor signs their own slice at contribution time (`PendingAttestation`).
- **Publish** — indirectly but really: the anchor payload is operator-signed and commits to the version's Merkle root.
- **Approval** — the operator accepting or rejecting a supplier's contribution (`ApprovalAttestation`). Substantive under ESPR Art. 9(1): this is where responsibility for the passport transfers.
- **Authorization / revocation** — `setIssuer`, controller-signed EIP-712.
- **Chain-head checkpoint** — the operator's periodic commitment to their own audit log (`ChainHeadCheckpoint`).

**NOT signed, on purpose:**

- **Draft editing** (`passport.fields.save`, packaging, tier CRUD). A wallet prompt per keystroke is unusable — tKey reconstruction takes seconds — and a draft edit needs no third-party verifiability. It is internal bookkeeping until publish, and publish *is* attested.
- **Session and account events** (login, logout, password change). Authentication already proves these; a signature would be circular.

This boundary is a decision, not an oversight, and the line is: **does the claim leave the platform, or does the regulation make the decision substantive?** Anything inside that line is signed by an actor; everything else is recorded in the audit chain, which remains hash-linked and tamper-*evident* but is platform-written and says so.

The honest residual: a compromised platform can still fabricate *draft-editing* history. It cannot fabricate a credential, an approval, a publication, an authorization, or a chain-head checkpoint.

## Status

All of it landed. `index.ts` (`DesignATrust implements TrustProvider`),
`didEthr.ts`, `jose.ts` (ES256K-R), `authRoot.ts`, `anchor.ts`, `relayer.ts`
(the `AnchorTx` outbox drain), `outbox.ts`, `decisions.ts`, `chainGateway.ts`,
`chainTypes.ts`, `typedData.ts` and `designARoutes.ts` are all present, and the
contracts are deployed and verified on Amoy (`contracts/deployments/amoy.json`).

Two notes on what is NOT here:

- **`ceremony.ts` lives in the browser**, at `frontend_dpp/src/lib/trust/ceremony.ts`.
  That is the point of Design A: the envelope is assembled and signed where the
  values are displayed, not on the server (D7 / WYSIWYS).
- **`fakeChainGateway.ts` is not wired to anything** and there are no Design A
  unit tests. See its header for what injecting it would take.
