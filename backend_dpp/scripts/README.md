# `backend_dpp/scripts` — the independent verifiers

Standalone tools that check the platform's claims **without using the
platform's code**. All are thesis artifacts: their value is entirely in their
independence, so the rule for this directory is absolute.

> **Nothing in this directory may import from `backend_dpp/src/`, `packages/`,
> or npm.** Node's standard library only.
>
> A verifier that shares a hash function, a canonicalization routine or a
> parser with the thing it verifies proves nothing — a bug or a lie in the
> shared code is reproduced identically on both sides and cancels out. The two
> `.ts` files in here (`rewrap-signing-keys.ts`, `seed-design-a.ts`) are
> operations scripts, not verifiers, and are exempt — one rewraps custodied
> keys, the other *drives* the platform rather than judging it, and its output
> is judged by `verify-passport.mjs`, which keeps the rule.
> `tamper-passport.mjs` is exempt on the same ground: it *attacks* rather than
> judges, every verdict in its report is copied out of a `verify-passport.mjs`
> subprocess, and it needs the one thing the verifier deliberately lacks — a
> signing function.

| file | verifies / measures | needs |
| --- | --- | --- |
| `verify-chain.mjs` | an organization's audit chain: every event hash recomputes, and the signed chain head matches the export's tip | the platform (HTTP) |
| `verify-passport.mjs` | a published passport export: credential signatures, issuer DID resolution, on-chain authorization, and the Merkle anchor | an export file + an EVM JSON-RPC endpoint |
| `tamper-passport.mjs` | *attacks* rather than verifies: mutates a real export sixteen ways and records what `verify-passport.mjs` catches, offline and against the chain | an export file (+ an endpoint for the online half) |
| `measure-rq3.mjs` | *measures* rather than verifies: produces RQ3's quantitative table — verification latency, gas, time-to-anchor, onboarding and signing latency, A against B | the above, plus a database or a running platform |
| `seed-design-a.ts` | *drives* rather than verifies: runs the whole Design A ceremony end to end and produces a real published, anchored passport plus the timings measure-rq3 consumes | a Design A stack, Redis, and a funded relayer on Amoy |

---

## `verify-passport.mjs`

```
node scripts/verify-passport.mjs <bundle.json> [options]
node scripts/verify-passport.mjs --inspect <0x…productId | did:…> --rpc <url>
node scripts/verify-passport.mjs --self-test
node scripts/verify-passport.mjs --help
```

This is the tool that produces both columns of the thesis's headline
comparison. Run it against a **Design B** export with the platform stopped and
`did:web` cannot resolve — the DID document is served *by* the platform, so the
issuer's key is unobtainable and nothing verifies. Run it against a **Design A**
export with the platform stopped and issuer DIDs still resolve from the ERC-1056
registry on chain, signatures still verify, and the anchor still checks out.

### Exit codes

| code | meaning |
| --- | --- |
| `0` | `VERIFIED` — every check ran and passed |
| `1` | `FAILED` — at least one check ran and failed |
| `2` | usage error, unreadable bundle, or a failed crypto self-test |
| `3` | `INCOMPLETE` — nothing failed, but something could not be checked |

**Exit 3 is not a pass.** `SKIP` is printed differently from `PASS`, counted
separately, and downgrades the verdict. That is the whole point: a reader has to
be able to trust the tool's ✗, which is only possible if it never dresses a
skipped check as a passed one.

### What goes in

`GET /api/public/passports/:id/export` now serves shape 1 directly (it did not
when this tool was written, and it is **not yet deployed to production** — the
`app.` instance still 404s it, so the production baseline has to come from the
public passport route or straight from the database). The tool therefore still
accepts either shape:

1. **A `PassportVersion` row** — `{ version, snapshot, credentials, hash }`,
   plus `productDid`. Everything is checkable. This is the shape you want.
2. **The public passport JSON** (`GET /api/public/passports/:id`) — it serves a
   *flattened* projection of the frozen snapshot, so the Merkle pre-image is
   gone. Signatures and issuer resolution are still checkable; `merkle-root` and
   `anchor` report `SKIP` with that reason rather than hashing the wrong bytes.

Either shape is also accepted under a `passportVersion`, `bundle` or `payload`
key. Optional `anchorTxHash` (or `--anchor-tx`) points at the anchoring
transaction — a **hint only**: it says where to look, and the log found there is
still checked against the configured registry address, the `Anchored` topic, the
productId, the version, and the locally recomputed root. A wrong hint can cause
a miss, never a false match.

Producing shape 1 straight from a database, with no platform code:

```sh
docker exec trustdpp-db-dev psql -U trustdpp -d trustdpp -tAc "
select jsonb_build_object(
  'passportId', v.\"passportId\", 'version', v.version, 'hash', v.hash,
  'productDid', pr.did, 'snapshot', v.snapshot::jsonb, 'credentials', v.credentials::jsonb
)::text
from \"PassportVersion\" v
join \"Passport\" p on p.id = v.\"passportId\"
join \"Product\"  pr on pr.id = p.\"productId\"
where v.\"passportId\"='dpp_denim_003' and v.version=56;" > export.json
```

### Chain arguments

Defaults come from `contracts/deployments/amoy.json`, but they are **arguments**
— a verifier that hardcodes a deployment cannot check any other one:

```
--chain-id 80002
--registry      0x03dd7e09263a24e5e6aBACA533EeE9d992b85479
--did-registry  0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65
--from-block    44629028          # the registry's deployment block
--rpc <url>                       # or $RPC_URL. Never printed: it carries an API key.
```

`--offline` uses no network at all and reports every network-dependent step as
`SKIP`. Note that "the chain is unreachable" and "`--offline`" are **different**
states: a dead RPC endpoint must never silence `did:web` resolution over HTTPS,
because that would hide the single most important finding this tool produces.

### Endpoint range caps

Free-tier endpoints cap `eth_getLogs` (Alchemy's Amoy free tier: **ten blocks**).
The anchor scan therefore runs **backwards** from the newest block in windows
that shrink on refusal, under a request budget (`--max-log-requests`, default
200). If the budget runs out without finding an anchor, the result is `SKIP`
with the blocks actually covered — *inconclusive*, never "absent". Supplying
`--anchor-tx` skips the sweep entirely: one `eth_getTransactionReceipt`.

### `--inspect`

Not part of verification. It dumps what the chain says about one product —
controller, nonce, the derived selectors and event topics, and every decoded
registry log — so the chain-reading code can be pointed at known-good on-chain
state and checked by eye. That is how its selector derivation, ABI encoding and
event-topic hashing were confirmed against the deployed Amoy contracts rather
than against themselves.

### What it does **not** prove

Stated at length in the file header; in brief:

- **Design B signatures are never verified.** `eddsa-rdfc-2022` signs the
  URDNA2015 canonicalization of the JSON-LD, which needs a JSON-LD processor and
  the `@context` documents — themselves served by the platform under audit. The
  `signature` check reports `SKIP` with that reason. It will not guess.
- It does not prove a passport is **true**, only who signed which bytes.
- A matching `version-hash` proves **nothing against the platform**: the platform
  chose the bytes *and* computed the digest. Only the on-chain anchor is
  evidence a third party can weigh — which is the substance of A vs B.
- Revocation is not checked, in either design.
- Chain state is only as trustworthy as the RPC endpoint.

### Self-test

keccak-256 and secp256k1 recovery are implemented here from their
specifications, so they are checked against frozen vectors on **every run**
before any credential is examined; a failure exits 2 rather than producing
confident wrong answers. The ES256K-R vector was signed once, out of band, by
the private key `1` (address `0x7e5f…95bdf`). There is deliberately **no signing
function** in the verifier — only the constant.

The independent implementation has been cross-checked against the platform's
own: for both a real Design B export and a Design A fixture, the credential
digests, snapshot digest and Merkle root come out byte-identical, computed by
two unrelated keccak implementations and two unrelated canonical serializers.

---

## `tamper-passport.mjs`

```
node scripts/tamper-passport.mjs <bundle.json> --rpc <url> [--anchor-tx 0x…]
                                 [--out-dir <dir>] [--only id,id] [--offline-only]
```

The ✗ half of `verify-passport.mjs`. That file says the entire value of the tool
is that a reader can trust its ✗ — but until this one existed, nothing in the
repository had ever made it produce one, so a verifier that agrees was
indistinguishable from a verifier that always agrees.

It takes a real published, anchored export, mutates it sixteen ways, runs the
**untouched** verifier against each as a subprocess, and reports what was caught,
by which check, at which exit code. It never edits the verifier: a mutation that
is not caught is reported as a finding.

Every mutation is verified twice — `--offline` (bytes only: `version-hash`,
`merkle-root`, ES256K-R recovery) and against the chain (adds ERC-1056
resolution, the authorization root, the anchor). The two columns answer one
question: which mutations does the chain catch that the bytes cannot? (Thesis
Sec. 7.2 (RQ1) and Table 7.1.)

Mutations ending `-rehashed` also recompute the platform's own `hash`, because a
platform altering its own database would. Five mutations are invisible offline
once it does, and only the anchor refuses: a matching `version-hash` proves
nothing against the platform.

Exit `0` every mutation behaved as catalogued · `1` one diverged, in either
direction · `2` usage. The archived runs, with their verbatim transcripts, are
in `evidence/` (`*_designA-tamper-suite*.json` / `.txt`).

**Two mutations are not caught**, and both are re-signed with a genuinely
authorized supplier key: a credential whose `credentialSubject.id` names a
*different product*, and one whose validity window closed in 2020. The verifier
binds neither the subject to the passport's product nor evaluates
`validFrom`/`validUntil`. Their `anchor` FAIL is not a catch — the anchor only
says the bytes moved, and a passport *published* with either would anchor
faithfully.

---

## `measure-rq3.mjs`

```
node scripts/measure-rq3.mjs                      # human table
node scripts/measure-rq3.mjs --json --out rq3.json
node scripts/measure-rq3.mjs --markdown           # paste into the thesis
node scripts/measure-rq3.mjs --latex
node scripts/measure-rq3.mjs --help
```

The quantitative half of the evaluation. RQ3 asks what the decentralised
architecture costs against the baseline. This is the instrument that measures it
(thesis Sec. 4.4 and 7.4).

It is a **measurement** tool, not a verifier — but it keeps the directory's
zero-import rule anyway. Two things fall out of that: the verification-latency
number is the wall time of a genuinely independent verifier rather than of a
runtime this harness dragged in, and the harness still runs when the platform's
dependency tree does not, which is the scenario the thesis is about. Database
reads go through `docker exec … psql`; chain reads go through `fetch`.

### The rule

**A number that was not measured is `null`.** Never `0`, never an estimate.
`verify-passport.mjs` exits 3 on INCOMPLETE so a skip can never read as a pass;
this harness inherits that exactly.

| code | meaning |
| --- | --- |
| `0` | `COMPLETE` — every measurement in scope was taken |
| `1` | `FAILED` — a measurement was attempted and errored |
| `2` | usage error |
| `3` | `INCOMPLETE` — nothing failed, but something could not be measured |

### Four states, not two

Collapsing "could not measure" into "does not exist" would manufacture a false
equivalence, so every row carries one of:

| state | meaning |
| --- | --- |
| `measured` | a timer or a receipt produced it; carries a distribution |
| `unavailable` | takeable in principle, not today; **carries the precondition** |
| `n/a` | the category does not exist in this design; **carries the reason** |
| `structural` | known exactly from the design, not from a timer — e.g. gas per actor DID is `0` because `did:ethr` is address-derived |

Design B has no gas cost and no anchor; Design A has no platform-side signing.
Those are `n/a`, not `0`. Printing `0` would read as "Design B does the same
thing for free" rather than "Design B does not do this".

### Distributions

The thesis commits to **N ≥ 30, median + IQR** (Sec. 4.4), so `--n` defaults to 30
and every latency reports n / min / p25 / median / p75 / IQR / p95 / max / mean /
stddev. Percentiles use method R-7 (linear interpolation, the NumPy/Excel
default), stated in the JSON so it is reproducible. `--warmup` (default 3) runs
are executed and discarded: cold JIT and a cold TCP path are costs of starting
to measure, not costs of the architecture.

Network-bound rows default to `min(n, 10)` (`--n-network`) — 30 live round trips
measure the link as much as the design — and the reduced `n` is reported in the
row itself, so it can never be mistaken for the headline `n`.

### What is measured independently, and what through the platform

Recorded per row in `provenance` and printed in the table:
`independent` (a `verify-passport.mjs` subprocess) · `chain` (JSON-RPC receipts
and gas price) · `artifact` (Foundry's gas snapshot, `deployments/amoy.json`) ·
`platform` (the platform's own HTTP API — necessarily true of onboarding and
publish latency, and kept visibly separate because a number the platform timed
about itself is weaker evidence) · `structural`.

### Gas is read, not timed

Gas *units* are deterministic; gas *price* is volatile. They are separate rows
and the price carries a timestamp. Three sources are kept apart rather than
reconciled, because their agreement is itself evidence: the committed Foundry
snapshot (execution gas only — **not** what a relayer pays), a live
`forge test --match-test test_Gas_PerOperation` parsed for the TOTAL TX column,
and real `gasUsed` from Amoy receipts. The deployment receipts currently agree
with `contracts/README.md` to the gas.

`--pol-usd` is **required** for the dollar column and is never fetched: a rate
scraped from a price API at run time is unciteable and irreproducible in a
thesis. Same for `--web3auth-usd-per-maw`, an RQ3 row that is a published list price to be cited, not a quantity anything can observe.

### Time-to-anchor comes free

`AnchorTx` already carries `createdAt` and `confirmedAt`, so this is a database
read. Re-measuring it by polling would produce a *worse* number — it would
measure the harness's poll interval.

### Mutating measurements are opt-in

Timing a publish means performing one, which freezes a new `PassportVersion`.
`--publish-runs` and `--onboarding-runs` default to `0`, require `--api-base`,
and **refuse a non-localhost target** unless `--allow-remote-mutation`.

### The honesty gate you will actually hit

The dev database's Design B passports carry `did:web` issuers on a domain that
no longer resolves. Timing a verification against them measures a DNS *failure*,
which is systematically faster than a success — so if no issuer resolves, the
"with network" row is **downgraded to `null`** and the observed timings are
parked under `detail.observedButRejected`. Take that baseline against production
with `--b-prod-url`.

### The production Design B baseline (`--b-prod-url`)

```
node scripts/measure-rq3.mjs --n 30 --n-network 30 \
  --b-prod-url https://app.trustdpp.co/api/public/passports/dpp_806e2c79e92bb84e
```

The thesis scopes the empirical comparison to the **deployed** status quo (Sec. 4.2), so the
baseline has to come from deployed infrastructure. What production serves today
is the flattened public projection, **not** a full evidence bundle — `/export`
exists in the working tree but is not deployed. That matters and is stamped on
every row: without the frozen snapshot, `version-hash`, `merkle-root` and
`anchor` all SKIP, so **this is not an end-to-end verification time.** It is
parse + real `did:web` resolution.

Three rows, because one number hides what matters:

| row | what it is |
| --- | --- |
| `prod.compute` | `--offline` over the same bytes. The computational floor. |
| `prod.full` | with the network: compute + real `did:web` resolution |
| `prod.didwebOnly` | the resolution alone — a fresh subprocess fetches the distinct `did.json` documents and exits |

**Network conditions are part of `prod.full`.** It is taken over the public
internet from the machine in `provenance.machine`; the link is not a property of
Design B. Quote it with the other two beside it, never alone.

**The two network estimates do not agree, and should not.**
`prod.full − prod.compute` ≈ 512 ms; `prod.didwebOnly − nodeStartup` ≈ 275 ms.
Both are correct and they count different things, for two compounding reasons:

1. **Fetch count.** `verify-passport.mjs` does not cache DID resolution, so it
   fetches once per *credential* (5) while the isolated row fetches once per
   *distinct issuer* (2).
2. **Connection reuse.** Within one process the first fetch pays DNS plus a TLS
   handshake (~140 ms measured) and every later fetch to the same host reuses
   the connection (~35 ms measured). Cost is **not** linear in fetch count.

Use the normalised `networkPerResolution` (~102 ms) and `networkPerFetch`
(~138 ms) for comparison, and treat neither raw figure as "the" network cost.
The redundant fetches are an implementation property of the verifier, not an
architectural property of Design B.

### Current state (2026-08-05)

`INCOMPLETE`, exit 3, and correctly so: Phase 5 is being built, no Design A
passport has been published or anchored, so every Design A latency is `null`
with its precondition. That gap is the honest output and the thesis should
report it as one.

Measurable today — 10 measured, 1 structural, 11 `null`, 3 `n/a`:

| row | n | median | IQR |
| --- | --: | --: | --- |
| `designB.local` (dev bundle, compute only) | 30 | 105.2 ms | 101.9–109.9 |
| `designB.prod.compute` (prod projection, compute only) | 30 | 86.4 ms | 83.1–105.0 |
| `designB.prod.full` (prod, real `did:web` resolution) | 30 | 598.7 ms | 574.9–623.6 |
| `designB.prod.didwebOnly` (resolution alone) | 30 | 313.3 ms | 297.4–324.2 |
| `nodeStartup` (subtractable floor) | 30 | 38.2 ms | 36.7–42.4 |

Gas: execution 14 633 / 51 805 / 36 767 (`anchor` / `claimProduct` / `setIssuer`),
total tx 38 445 / 75 321 / 60 435, real Amoy deployment receipts 1 406 231 and
1 398 848 gas — the receipts match `contracts/README.md` to the gas, which is a
cross-check on the instrument. Gas per actor DID is `0`, `structural`.

`issuer-key-current` SKIPs even against production, and **not** because of the
projection shape: `did:web` publishes no rotation or revocation history, so the
document only says what the platform says *today*. That is a property of the
method and belongs in the thesis's Design B column as a finding, not a gap.

---

## `seed-design-a.ts`

```sh
npx tsx scripts/seed-design-a.ts                 # the whole ceremony, end to end
npx tsx scripts/seed-design-a.ts --fresh-actors  # a new cast of five organisations
npx tsx scripts/seed-design-a.ts --help
```

The only thing in this directory that **writes**. Every step of Design A was
built and individually verified long before anything had run as one sequence;
this is that sequence:

```
5 actors exist with their own keys (1 operator + 4 suppliers)
  → operator claims the product on chain
  → operator authorises each supplier (setIssuer)
  → each supplier signs their own credential slice (ES256K-R JWS)
  → operator signs an approval per role (EIP-712, zero gas)
  → publish assembles the pre-signed envelopes (CeremonyAssembly)
  → operator signs the chain-head checkpoint and the anchor
  → relayer submits → confirmed on Amoy
  → export the bundle → verify with verify-passport.mjs
```

### Running it against a local Design A stack

The dev compose stack is **Design B** — `/api/trust/design-a/*` is absent there,
not disabled, and the script's preflight refuses rather than guessing. Bring up a
second backend in Design A mode beside it. It shares the dev Postgres and needs a
Redis with a *published* port (SIWE nonces are single-use and Redis-only;
`trustdpp-redis-dev` publishes none):

```sh
docker run -d --rm --name trustdpp-redis-designa -p 6390:6379 \
  redis:7-alpine redis-server --save '' --appendonly no

cd backend_dpp
PORT=3011 NODE_ENV=development TRUST_MODE=design-a \
DATABASE_URL="postgresql://trustdpp:trustdpp@localhost:5433/trustdpp?schema=public" \
DIRECT_URL="postgresql://trustdpp:trustdpp@localhost:5433/trustdpp?schema=public" \
REDIS_URL="redis://localhost:6390" JWT_SECRET="dev-only-change-me-0123456789012345" \
APP_URL="http://localhost:3011" CHAIN_ID=80002 CHAIN_NAME=amoy \
DID_REGISTRY_ADDRESS=0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65 \
ANCHOR_REGISTRY_ADDRESS=0x03dd7e09263a24e5e6aBACA533EeE9d992b85479 \
RPC_URL="<AMOY_RPC_URL from contracts/.env>" \
RPC_URL_FALLBACK="https://polygon-amoy-bor-rpc.publicnode.com" \
RELAYER_PRIVATE_KEY="<the funded key>" \
WEB3AUTH_CLIENT_ID=dev-placeholder WEB3AUTH_NETWORK=sapphire_devnet \
npx tsx src/server.ts
```

`WEB3AUTH_*` are required by `config.resolveDesignA` and are never read
server-side — they ship in the frontend bundle. The relayer key is the only real
secret and it pays gas only: the registry authorises on `ecrecover` and never
reads `msg.sender`.

**Rate limits bind this ceremony.** Per IP: `wallet-challenge` 10 / 15 min,
`wallet-login` 10 / 15 min, `wallet-bind` **5 / hour**. A five-actor first run
consumes exactly 10 challenges and exactly 5 binds — it fits with zero headroom,
and a sixth actor cannot be onboarded from the same address within the hour.
Re-runs skip the bind (the actor file records it), so they need 5 + 5.

### The honesty constraint

**The script holds five private keys.** That is legitimate only because in this
scenario the script *is* the five actors — it is not the platform signing on
their behalf, and the distinction is the whole thesis. So:

- every organisation it creates is named `[DEMONSTRATION ACCOUNT] …`, which is
  what a reader sees as the credential issuer on the published passport;
- it drives **only the real HTTP routes** the browser drives, in the same order,
  with the same payload shapes. It opens no database connection for any ceremony
  step and imports no route handler;
- it adds **no server-side signing capability**. `DesignATrust.signCredential`
  still throws, and this run produced six signed credentials without the server
  ever holding key material;
- the relayer key is not in the process. Gas is paid by the platform's relayer,
  which holds no authority (`TrustAnchorRegistry` authorises on `ecrecover` and
  ignores `msg.sender`).

The one function to read against its browser counterpart is
`signAttestationJws`, a deliberate re-implementation of
`frontend_dpp/src/lib/wallet/signer.ts` (a browser module Node cannot load).
What is **not** re-implemented is the credential document: that comes from
`dpp-core/vc/envelope.buildAttestationBody`, the same pure function the browser
and the server both run. Three checks catch any divergence — local signature
recovery, the browser's own "does my assembly reproduce the server's reference"
guard, and the upload route's byte comparison against a document rebuilt from
the database.

### Re-runnability

**Actors persist, the product is fresh every run.** Keys live in
`scripts/.design-a-actors.json` (git-ignored), so re-running reuses one stable
cast instead of accumulating organisations. A product DID can be claimed exactly
once and for ever — the registry is first-claim-wins — so each run mints a new
product, which is the only shape under which "claim the product on chain" is a
step that can run twice. Nothing is deleted; earlier runs stay published and
anchored.

### What it costs

Six transactions: 1 × `claimProduct`, 4 × `setIssuer`, 1 × `anchor`.
Everything else — five `did:ethr` identities, six ES256K-R credentials, five
EIP-712 approvals, one chain-head checkpoint — is free, which is itself an RQ3
finding.

### What it emits

`scripts/out/design-a-run-<timestamp>.json` carries the run: per-step wall
times, the actors, the credentials, the outbox rows, the verifier's verdict,
the findings, and a `measurements` array in **`measure-rq3.mjs`'s own row
shape** (same ids, same four states, same R-7 percentiles) so no second format
exists. `scripts/out/design-a-export-<id>-v<n>.json` is the export bundle, with
the anchoring transaction hash attached from the chain so it verifies directly:

```sh
node scripts/verify-passport.mjs scripts/out/design-a-export-<id>-v1.json --rpc <url>
```

Two measurement ids are deliberately **not** the ones the RQ3 metrics name —
`onboarding.designA.headless` and `signing.designA.ceremony.headless`. Both of
those metrics begin at a human action in a browser ("Google-Login bis did:ethr
registriert", "Sign-Button → VC auf dem Server"); this script has no browser, no
OAuth redirect and no tKey reconstruction, so what it measures is the protocol
and platform component of those spans — a strict lower bound. Publishing it
under the metric's own id would answer it with a number that
excludes the part the metric exists to question.
