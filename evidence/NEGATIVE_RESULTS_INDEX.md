# Negative results — index

Run date **2026-08-06**. Repository at `88fabf4362307f4c590b15634c55617ee7cd8005`,
node `v25.1.0`, Polygon Amoy `chainId 80002`.

Everything here was judged by `backend_dpp/scripts/verify-passport.mjs`
**unmodified**. That is the whole point of the exercise: the file's own docblock
says *"the entire value of this tool is that a reader can trust its ✗"*, and
until this run nothing in the repository had ever made it produce one. Every
prior run was against bytes the platform itself had just written, which cannot
distinguish a verifier that agrees from a verifier that always agrees.

The rule for the run was that a mutation the tool misses is a **finding**, not a
bug to repair. Nothing was changed to make anything pass or fail.

> **Reproducing this after 2026-08-11.** `TrustAnchorRegistry` was redeployed to
> `0x03dd7e09263a24e5e6aBACA533EeE9d992b85479` on **2026-08-11** to add batch
> issuer authorization (`setIssuers`); the registry is immutable, so a new
> capability is a new deployment. `verify-passport.mjs`'s DEFAULTS now point
> there, and this run's anchor is not at that address — running the suite with
> the current defaults reports the anchor `absent`, which would look like a
> failure and is not one.
>
> The addresses below are the ones this run used and are left as they were. To
> reproduce it, pass them explicitly:
>
> ```
> --registry 0xf4e0Ab431a2F5df241fa0E9c6A87DBa86b0E0d93 --from-block 44055315
> ```
>
> Nothing else changes: `EthereumDIDRegistry` did **not** move, so every
> `did:ethr` in this bundle resolves exactly as it did on 2026-08-06, and the
> credential bytes are untouched.

> **Amended later the same day.** Parts 1–3 below are the record of the verifier
> **as it stood at `88fabf4`** and are left exactly as they were written — that
> is what makes them evidence. Acting on their findings afterwards is a separate
> event, recorded separately in **Part 4**, which re-runs the identical suite
> against a changed verifier and reports both columns. Read Parts 1–3 as the
> measurement and Part 4 as the response; do not read either as amending the
> other. Three passages below are stale as *present-tense statements about the
> code* and are marked **[superseded → Part 4]** where they occur.

## Subject

| | |
| --- | --- |
| passport | `dpp_b48b5bd5525d679a` v1 |
| product DID | `did:web:trustdpp.co:prod_b48b5bd5525d679a` |
| productId | `0xebdca24465ff87fccbc7f1923308fee2eb45eff3d63c208af60bec6eb2954792` |
| credentials | 6, from 5 distinct `did:ethr` issuers |
| anchor | `0x131426ac6fc6e0b5c19a6522da26e1cd631705559c0993a4d8981e2807d5be5b`, block 44139201 |
| `TrustAnchorRegistry` | `0xf4e0Ab431a2F5df241fa0E9c6A87DBa86b0E0d93` |
| ERC-1056 `EthereumDIDRegistry` | `0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65` |
| baseline verdict | **40 passed · 0 failed · 0 skipped · VERIFIED**, exit 0 |

The bundle was exported straight from Postgres by the `docker exec … psql`
technique documented in `backend_dpp/scripts/README.md` — no platform code took
part in producing the bytes that were then verified.

## Files

| file | what it demonstrates | answers |
| --- | --- | --- |
| `2026-08-06_designA-export-dpp_b48b5bd5525d679a-v1.json` | the input bundle, verbatim from the database. Everything else in this index is reproducible from it. | provenance |
| `2026-08-06_designA-tamper-suite.txt` | verbatim `verify-passport.mjs` output for the untouched export and for 16 mutations, each verified twice (`--offline` and against the chain) | §13 RQ1 rows 1–2 · §13 RQ2 „Manipulationserkennung" and „Fälschungserkennung" · §16 `Manipulationserkennung` · §14 threat table |
| `2026-08-06_designA-tamper-suite.json` | the same run, machine-readable: per mutation the change made, the checks that failed, the exit codes, and the addresses of the keys minted for the run | — |
| `2026-08-06_designA-revocation-onchain.txt` | Mechanism 4 in its **refusing** direction, end to end on Amoy: VERIFIED → `authorization` FAIL with the signature still valid → VERIFIED again | §13 RQ1 row 2 · §9 Mechanismus 4 · §10 Widerruf · §14 „Schlüsseldieb", „Nicht-autorisierter Dritter" |
| `2026-08-06_designA-revocation-onchain.json` | the same run, machine-readable, with tx hashes, block numbers and relayer balances | — |
| `2026-08-06_designB-tamper-uncheckable.txt` | the same class of tamper against the **Design B baseline**: the verifier's report is byte-for-byte identical before and after | §15 · §16 „Signaturverifikation" row · §16.1 |
| `2026-08-06_designA-tamper-suite-after-hardening.txt` | **Part 4.** The identical 16 mutations re-run against the verifier *after* the two checks of §4.1 were added — the before/after that shows two findings closed and nothing else moved | §13 RQ2 · §16 |
| `2026-08-06_designA-tamper-suite-after-hardening.json` | the same re-run, machine-readable | — |

---

## Part 1 — Tamper suite

16 mutations, each verified twice. `offline` is the bytes alone; `online` adds
ERC-1056 resolution, the on-chain authorisation root and the Merkle anchor.
Exit `1` = FAILED, `3` = INCOMPLETE (nothing failed, something could not be
checked — **not** a pass). `c1` is `credential[1]`, the cotton-farming credential.

Mutations marked `-rehashed` also recompute the platform's own
`hash = sha256(stableStringify({snapshot, credentials, version}))`. That costs
nothing and is what a platform altering its own database would do; §15 says a
matching `version-hash` proves nothing against the platform, and these rows are
that sentence made empirical.

| mutation | caught offline by | exit | caught online by | exit |
| --- | --- | --: | --- | --: |
| `payload-byte-flip` | version-hash, c1.signature | 1 | version-hash, c1.signature, c1.issuer-key-current, anchor | 1 |
| `credential-reorder` | version-hash | 1 | version-hash, anchor | 1 |
| `credential-reorder-rehashed` | — none | 3 | anchor | 1 |
| `credential-delete` | version-hash | 1 | version-hash, anchor | 1 |
| `credential-delete-rehashed` | — none | 3 | anchor | 1 |
| `snapshot-attribution-swap-rehashed` | — none | 3 | anchor | 1 |
| `platform-signs-as-supplier` | c1.signature | 1 | c1.signature, c1.issuer-key-current, anchor | 1 |
| `issuer-did-swap-rehashed` | c1.signature | 1 | c1.signature, c1.issuer-key-current, anchor | 1 |
| `unauthorized-issuer-rehashed` | — none | 3 | **c1.authorization**, anchor | 1 |
| `alg-none-rehashed` | c1.signature | 1 | c1.signature, anchor | 1 |
| `alg-none-empty-signature-rehashed` | c1.parse, c1.issuer-did | 1 | c1.parse, c1.issuer-did, anchor | 1 |
| `typ-cross-protocol-rehashed` | c1.signature | 1 | c1.signature, anchor | 1 |
| `login-token-replay-rehashed` | c1.signature | 1 | c1.signature, anchor | 1 |
| `high-s-malleability-rehashed` | c1.signature | 1 | c1.signature, anchor | 1 |
| `cross-product-transplant-rehashed` | — none | 3 | anchor | 1 |
| `expired-credential-rehashed` | — none | 3 | anchor | 1 |

**No mutation produced a false ✓.** Every one exits non-zero online. The tool
never once reported VERIFIED over bytes that had been altered.

### The four rows §13 promised

1. *„Fälschungsversuch: Plattform versucht als Lieferant zu signieren →
   Verifikation muss fehlschlagen"* — `platform-signs-as-supplier`. A key minted
   for the run re-signs the farm's credential and leaves `issuer` claiming to be
   the farm. The platform can mint keys freely; what it cannot do is hold the
   supplier's. Result: *"signature recovers to 0x436b8199…, but the issuer DID
   names 0xa79046e8…"*, plus `issuer-key-current` — the resolved ERC-1056
   document does not authorise that address to assert.
2. *„Nicht-autorisierter Akteur stellt VC für GTIN X aus → Autorisierungsprüfung
   muss fehlschlagen (Mech. 4)"* — `unauthorized-issuer-rehashed`. This is the
   sharpest row in the table, because it separates *who signed* from *who was
   entitled to sign*:

   ```
   [ ✓ PASS ]  signature          ES256K-R recovers to 0xdb7e7c24…, which is what the issuer DID names
   [ ✓ PASS ]  issuer-did         did:ethr address form, chain 80002 → 0xdb7e7c24…
   [ ✓ PASS ]  issuer-resolution  resolved from ERC-1056 … address-derived default document
   [ ✓ PASS ]  issuer-key-current the resolved document still authorizes 0xdb7e7c24… to assert
   [ ✗ FAIL ]  authorization      the chain says NO: authorized[][0xdb7e7c24…] is false …
   ```

   A real key, a real signature, a real resolvable DID, and the chain still says
   no. Nothing but the on-chain authorisation root produces this ✗.
3. *„Manipulationserkennung: VC-Inhalt modifizieren → Hash-Mismatch"* —
   `payload-byte-flip`. One character of the base64url payload; the signature
   recovers to a different address entirely.
4. *„Fälschungserkennung: Falsche/nicht-autorisierte VC einfügen"* — rows 1, 2
   and `issuer-did-swap-rehashed` together.

### What only the chain catches

Five mutations are invisible offline once the platform recomputes its own digest
— `credential-reorder-rehashed`, `credential-delete-rehashed`,
`snapshot-attribution-swap-rehashed`, `cross-product-transplant-rehashed`,
`expired-credential-rehashed`. In each the offline pass reports **0 failures**
and exit 3, and only the Merkle anchor refuses. That is §15's claim, empirically:
the platform-defined digest is worthless as evidence against the platform, and
the anchor is the only line a third party can weigh.

`snapshot-attribution-swap-rehashed` deserves separate mention. It re-credits the
cotton claim in `snapshot.tiers[0]` from *Karimov Cotton Farm* to *Anatolia Denim
Mill* while leaving every credential byte-identical. The passport's
human-readable attribution and its cryptographic attribution are **different
surfaces**, and nothing in the verifier binds them — see §7.4, WYSIWYS.

### What is NOT caught — the finding  **[superseded → Part 4]**

Two mutations survive every check the verifier has. Both are re-signed with the
**real, on-chain-authorised** supplier key, so nothing about them is a forgery:

| mutation | what it does | why nothing catches it |
| --- | --- | --- |
| `cross-product-transplant-rehashed` | `credentialSubject.id` points at `did:web:trustdpp.co:prod_730b0c113be89275` — a **different product** — while sitting inside this passport's bundle | the verifier never compares a credential's subject with the bundle's `productDid`. Its `authorization` check asks whether the issuer is authorised for *this product*; it never asks whether the credential is *about* it. |
| `expired-credential-rehashed` | `validFrom` / `validUntil` moved to 2019-01-01 … 2020-01-01, six years expired | `verify-passport.mjs` contains no reference to `validFrom`, `validUntil` or expiry at all. A credential's validity window is never evaluated. |

Both show `anchor` FAIL in the online column, and that must not be read as a
catch. The anchor fails only because the bytes moved; it says *"these are not the
bytes that were committed to"*, never *"this credential is wrong"*. The platform
computes the root over whatever it assembles at publish time, so a passport
published **with** a transplanted or expired credential would anchor exactly as
faithfully as a valid one, and then nothing in the tool would object. The
`--offline` column is the honest measure here: **0 failures, exit 3.**

Neither is a soundness bug — the tool never claims to check subject binding or
temporal validity, and §14's *„Lügnender Lieferant"* row already concedes the
oracle problem. But both are checks a reader would reasonably assume were
happening, and `verify-passport.mjs`'s *"What it does not prove"* section names
neither. Two candidate additions:

- bind `credentialSubject.id` to the bundle's `productDid` — cheap, offline, and
  it closes a genuine transplant attack;
- report `validFrom` / `validUntil` against a stated verification time — §10 of
  the thesis („war gültig" vs. „ist gültig") argues this distinction at length
  and the instrument does not implement it.

### Two smaller observations

- **`alg: none` is refused twice, at different layers.** With the signature
  segment kept, the `alg` allow-list refuses it: *"refused `alg: none` — an
  unsecured JWS is not a credential"*. In RFC 7515's canonical form (empty third
  segment) the token is not a compact JWS at all, so the envelope parser declines
  it first and the credential falls through to the embedded-proof branch, which
  reports *"embedded-proof credential with NO `proof` — honestly unsigned"*. Both
  refuse; only the first exercises the guard that was written for it.
- **`issuer-key-current`'s wording over-diagnoses.** **[superseded → Part 4]** When a signature is forged,
  the recovered address is legitimately not in the DID document's assertion set,
  so the check fails correctly — but its text reads *"the key was rotated away or
  revoked"*, which names the ordinary cause rather than this one. The verdict is
  right; the explanation would mislead a reader of the transcript.

---

## Part 2 — Revocation on the real chain

The same bytes, three times. Not one byte of the passport changes; the only thing
that moves is `authorized[productId][issuer]` on Amoy.

| state | on-chain | verdict | counts | exit |
| --- | --- | --- | --- | --: |
| 1 — before | `authorized[…][farm] == true` | **VERIFIED** | 40 · 0 · 0 | 0 |
| 2 — revoked | `setIssuer(allowed=false)` confirmed | **FAILED** | 39 · **1** · 0 | 1 |
| 3 — restored | `setIssuer(allowed=true)` confirmed | **VERIFIED** | 40 · 0 · 0 | 0 |

State 2, the whole result in two lines:

```
credential[1]  role=cotton-farming  issuer=did:ethr:0x13882:0xa79046e8…
  [ ✓ PASS ]  signature       ES256K-R recovers to 0xa79046e8…, which is what the issuer DID names
  [ ✗ FAIL ]  authorization   the chain says NO: authorized[][0xa79046e8…] is false and the
                              product's controller is 0xb147280b…
```

Revocation under Design A **removes entitlement without invalidating the
signature**. The credential is still provably the farm's; the farm is simply no
longer permitted to speak for this product. A third party with an RPC endpoint
and no access to the platform sees the change — which is precisely what §16's
`Autorisierungsprüfung` row claims and what Design B, where the same fact lives
in the platform's database, cannot offer.

| | |
| --- | --- |
| revoked issuer | Karimov Cotton Farm, `did:ethr:0x13882:0xa79046e84dac70b21540c3c96d6ad42e82d1bd0b` |
| controller | `0xB147280bCDC2dE966e8E2131Bedb1D02a1997360`, EIP-712 `SetIssuer` |
| relayer | `0xd1b3849ba046fc85175211a14d064e743e9bd6ca` — pays gas, holds no authority |
| `setIssuer(false)` | `0x8e0f9e6f90eaedccf42aae6f727dc5cff198e537995b38d663ea90d5f1e38893`, block 44222458 |
| `setIssuer(true)` | `0x86c77b4bad12eba3ea4d43afc68c321465e91af52064fb0e887117718dd03c83`, block 44222487 |
| relayer balance | 0.086858454909107023 → 0.083335674901709185 POL |
| cost | 0.003522780007397835 POL for both transactions |
| artefact state | **restored — `dpp_b48b5bd5525d679a` v1 verifies VERIFIED, 40 · 0 · 0, exit 0** |

### A platform bug this run uncovered

`GET /api/trust/design-a/passports/:id/authorizations/payload?allowed=false`
**returns a payload for `allowed = true`.** The route parses its query string
with `z.coerce.boolean()` (`designARoutes.ts`, the
`/passports/:id/authorizations/payload` handler), and `Boolean("false") === true`
in JavaScript, so the revoking direction of Mechanism 4 cannot be expressed
through the one endpoint that exists to express it.

The first attempt of this run did exactly what a browser would: fetched the
payload with `?allowed=false`, signed it, and POSTed `{allowed: false}`. The
controller had signed the digest for the *other* value, so `ecrecover` returned
a different address and the transaction reverted **`NotController`** — recorded
in `AnchorTx` as `status='failed'` (a terminal state; the relayer retries only
`pending` and `sent`).

Two things follow:

1. The POST route is correct — it parses a JSON body with `z.boolean()` and
   rebuilds the payload faithfully. Only the GET is wrong. The run therefore
   corrected `payload.message.allowed` locally before signing, which is exactly
   what the server rebuilds on POST, and the transaction then confirmed.
2. This is why the brief's observation held: **every `setIssuer` in the
   repository passes `allowed: true`.** The permissive direction masks the bug
   completely. Mechanism 4's refusing direction was, until this run, unreachable
   through the browser-drivable API surface — for a mechanism the thesis presents
   as one of its four.

The fix is one call (`z.enum(["true","false"]).transform(v => v === "true")`, or
`z.coerce.boolean()` replaced by an explicit string comparison), but it lives in
`backend_dpp/src/`, which this run was not permitted to touch. **It is not
fixed.** **[superseded → Part 4: fixed with the first of those two forms.]**

---

## Part 3 — Design B, the same tamper

`credentials[1].issuer` swapped from one organisation to another on a Design B
passport, `proof.proofValue` left untouched, platform digest recomputed.

```
untouched   14 passed · 0 failed · 26 skipped   exit 3 INCOMPLETE
mutated     14 passed · 0 failed · 26 skipped   exit 3 INCOMPLETE
```

The two reports are identical. Under Design A the corresponding mutation
(`issuer-did-swap-rehashed`) is refused by `signature` and `issuer-key-current`.
Under Design B the `signature` check is `SKIP` for every credential —
`eddsa-rdfc-2022` signs the URDNA2015 canonicalisation of the JSON-LD, which
requires a JSON-LD processor and the `@context` documents, themselves served by
the platform under audit. The swapped issuer is therefore not merely undetected;
it is **uncheckable by an independent party**, and the verifier says so rather
than guessing. That distinction — *not caught* versus *not checkable* — is the
Design B column of §16 stated as a measurement rather than as an argument.

---

## Reproducing

```sh
# 1 — export the bundle (no platform code)
docker exec trustdpp-db-dev psql -U trustdpp -d trustdpp -tAc "…"  # scripts/README.md

# 2 — the tamper suite
cd backend_dpp
node scripts/tamper-passport.mjs <bundle.json> \
  --rpc <amoy-endpoint> \
  --anchor-tx 0x131426ac6fc6e0b5c19a6522da26e1cd631705559c0993a4d8981e2807d5be5b
```

`scripts/tamper-passport.mjs` is kept because it is free, offline-capable and
re-runnable against any future export. The Part 2 driver is **not** kept: it
spends real gas and mutates the authorisation state of the thesis's
demonstration artefact, and a script that does that should not be one keystroke
away. Its exact sequence is recorded verbatim in
`2026-08-06_designA-revocation-onchain.txt`, and `scripts/seed-design-a.ts`
already documents the `setIssuer` flow it drove.

The two keys minted for the tamper run (`0x436b8199…` platform forgery,
`0xdb7e7c24…` unauthorised third party) are random per run, so those two
mutations are not byte-reproducible; their addresses are recorded in the JSON so
the transcript can be read against them.

---

## Part 4 — What was changed in response

**Same day, after Parts 1–3 were archived.** Parts 1–3 measured the verifier and
found three defects. This part records fixing them, and re-running the *identical*
suite so the change is visible as a before/after rather than asserted.

The separation matters and is the reason this is a distinct section: the rule for
the original run was *"a mutation the tool misses is a finding, not a bug to
repair"*. That rule protected the measurement. It does not oblige the codebase to
stay broken afterwards.

### Caveat on the strength of this evidence

The two new checks were written **by the same session that wrote the mutations
they catch**. Catching an attack you authored is weaker evidence than catching
one you did not, and no claim here should be read as "the verifier is now
complete". What Part 4 does establish is narrower and still worth stating: two
specific, previously-unchecked properties are now checked, the baseline did not
have to move to accommodate them, and no other row of the table changed.

### 4.1 — Two checks added to `verify-passport.mjs`

Exactly the two additions Part 1 proposed, no more:

| check | what it asks | scope |
| --- | --- | --- |
| `subject-binding` | is `credentialSubject.id` the bundle's `productDid`? | offline; both designs |
| `validity` | was the credential in force at the judging instant? | offline; both designs |

Both are **offline** checks — each compares two values already inside the bundle,
so neither adds a network dependency to a tool whose ✗ has to be trustworthy
without one. Under Design A the subject sits *inside the signed bytes*, so a
transplanted credential cannot be retargeted without breaking its signature.

Three details worth recording:

- **`validity` skips rather than fails when no window is asserted.**
  `validFrom`/`validUntil` are optional in VCDM 2.0, so their absence is not a
  violation and must not be reported as one.
- **A new `--as-of <date-time>` flag.** Without it, re-running an archived bundle
  after its `validUntil` would turn a recorded VERIFIED into a FAILED, and this
  archive would appear to contradict itself. The flag pins the judging instant so
  a stored report stays reproducible; the transcript prints which instant was
  used and whether it was explicit.
- **Neither check runs on a credential that failed to parse.** The first
  implementation did, and `alg-none-empty-signature-rehashed` — an unparseable
  blob — began reporting *"the credential names NO subject"* alongside its real
  `parse` failure. True, but it points a reader at the wrong finding. Both checks
  now emit an explicit **skip** in that case, rather than a misleading ✗ or (worse)
  silence, since an absent row reads as "fine".

### 4.2 — The `z.coerce.boolean()` bug: fixed

`designARoutes.ts`, the `/passports/:id/authorizations/payload` handler:

```js
allowed: z.enum(["true", "false"]).default("true").transform((s) => s === "true"),
```

`Boolean("false") === true`, so `?allowed=false` had been building an **allow**
payload — which is why signing it reverted `NotController` on chain. `grep`
confirms this was the **only** `z.coerce.boolean()` in `src/` and `scripts/`, so
the class of bug is not present elsewhere. Mechanism 4's refusing direction is now
reachable through the browser-drivable API, which Part 2 established it was not.

### 4.3 — `issuer-key-current`'s wording: corrected

It read *"the key was rotated away or revoked"*, naming the ordinary cause even
when the actual cause was a forgery. It now states the fact and points at the row
that distinguishes the two cases, instead of guessing between them:

> *"either that key was rotated away or revoked, or it was never the issuer's at
> all; the `signature` row above distinguishes the two"*

### 4.4 — Re-run: the baseline did not move

The point of a regression check on a verifier is that closing a gap must not be
achieved by loosening anything else.

| | before (Parts 1–3) | after |
| --- | --- | --- |
| baseline, online | 40 passed · 0 failed · 0 skipped · **VERIFIED**, exit 0 | **52 passed · 0 failed · 0 skipped · VERIFIED**, exit 0 |
| baseline, offline | — | 32 passed · 0 failed · 20 skipped, exit 3 |
| backend test suite | 105/105 | **105/105**, no test file modified |

The twelve additional passing checks are the two new rows across all six
credentials. **Zero failures on the untouched export**: every real credential in
the demonstration passport names this product as its subject and was in force
when judged.

### 4.5 — Re-run: the two findings, offline

The `--offline` column is the honest measure for these two mutations — Part 1
explains why the online `anchor` FAIL is not a catch.

| mutation | before (offline) | after (offline) | after (online) |
| --- | --- | --- | --- |
| `cross-product-transplant-rehashed` | — none, exit **3** | **`c1.subject-binding`**, exit **1** | `c1.subject-binding`, anchor, exit 1 |
| `expired-credential-rehashed` | — none, exit **3** | **`c1.validity`**, exit **1** | `c1.validity`, anchor, exit 1 |

Both are now refused **on the bytes alone**. That is the material change: before,
a reader with no RPC endpoint got `0 failures, exit 3` on a transplanted or
expired credential; now they get a named ✗. The online `anchor` row still appears
beside them and still is not the catch — but it is no longer the *only* thing
that objects, which was the actual defect.

The full 16-mutation suite was re-run against the chain to confirm this. The
tamper harness compares each result to its catalogued expectation and reports
`as catalogued` or `DIVERGES`: **fourteen rows read `as catalogued`, and the only
two that diverge are the two intended above.** Summary line:
`16 mutations · 2 diverging · 0 not caught at all`.

The other fourteen rows are **unchanged**, including the three that remain
offline-invisible by design (`credential-reorder-rehashed`,
`credential-delete-rehashed`, `snapshot-attribution-swap-rehashed`) — those are
§15's claim about the platform-defined digest and closing them is not possible
offline, which is the point.

`snapshot-attribution-swap-rehashed` is still uncaught offline, and that remains
the most interesting open finding in this archive: the passport's human-readable
attribution and its cryptographic attribution are different surfaces, and nothing
binds them. See §7.4 (WYSIWYS).
