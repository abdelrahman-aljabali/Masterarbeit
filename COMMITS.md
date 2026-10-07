# Commit map

The thesis cites commits of the private development repository in which the prototype was built.
This repository is a **snapshot** of the files the thesis refers to, taken at development commit
`3001964` (2026-10-07), without that repository's history.

For each cited commit the table states what it produced, whether the run's provenance header
marked the working tree as dirty (uncommitted changes present), and which files of this snapshot
differ from their state at that commit. A file not listed is identical to the version at that
commit. The files in `evidence/` are unchanged copies of the artifacts.

| Commit | Date | Working tree | Produced | Files of this snapshot changed since |
|---|---|---|---|---|
| `88fabf4` | 2026-08-04 | no flag recorded | 6 August: first tamper suite (16 mutations), suite after hardening, on-chain revocation, Design B issuer swap | 71 files, listed below |
| `0b7df64` | 2026-08-24 | dirty | 24 August: ceremony runs (per issuer, batched); export bundle `dpp_f3bea69cca545292` | 56 files, listed below |
| `7a7f396` | 2026-08-24 | dirty | 24 August: second tamper suite (19 mutations); measurement-harness run | 56 files, listed below |
| `5d84f5d` | 2026-09-17 | dirty | 17 September: did-jwt cross-check, Slither, receipts, latency series, scaling series | `backend_dpp/scripts/verify-passport.mjs`<br>`contracts/README.md`<br>`contracts/deployments/polygon.json`<br>`contracts/foundry.toml` |
| `f8d7902` | 2026-09-19 | dirty | 19 September: bytecode equality, actor balances, Design B transcript, forge test output | `backend_dpp/scripts/verify-passport.mjs`<br>`contracts/README.md`<br>`contracts/deployments/polygon.json`<br>`contracts/foundry.toml` |
| `489a358` | 2026-09-19 | dirty | 23 September: main-network replication on Polygon PoS | `backend_dpp/scripts/verify-passport.mjs`<br>`contracts/README.md`<br>`contracts/deployments/polygon.json`<br>`contracts/foundry.toml` |
| `9051cf9` | 2026-10-07 | clean (committed) | 7 October: verifier options (anchor-time authorization, expected controller, pruned endpoint) and their runs | `contracts/README.md`<br>`contracts/foundry.toml` |

## Notes

- **Contracts and the 6 August runs.** The registry those runs used (`0xf4e0…0d93`, now superseded)
  was deployed to Polygon Amoy on 4 August 2026 (block 44 055 315, 20:02 UTC); the contract source
  was first committed on 7 August (`e44e731`). The 6 August runs therefore record `88fabf4`, the last
  commit before that, with the contract present as uncommitted work. The registry every later run
  uses (`0x03dd…5479`) is compared byte for byte with this snapshot's build in
  `evidence/2026-09-19_bytecode-equality.json`.
- **`b397781`.** Three online scaling points (`2026-09-17_scaling-online-{20,50,100}.json`) record
  `b397781`, a thesis-text commit made 50 minutes after `5d84f5d`; no script changed between the two.
- **Dirty working trees.** Most runs were taken with uncommitted edits present (typically thesis
  text and notes). The instruments' state at each run is the one in the table plus those edits.
- **The August trust layer.** Between the August runs and the snapshot the trust layer and the
  browser wallet were refactored (provider seam tightened, one-click publish, MFA fallback, logout
  after every ceremony). The August-era sources remain in the development repository.

## Changed files per commit

### `88fabf4`

```
backend_dpp/eslint.config.js                             |  146 ++-
 backend_dpp/scripts/README.md                            |  515 +++++++++++
 backend_dpp/scripts/measure-rq3.mjs                      | 2048 ++++++++++++++++++++++++++++++++++++++++++
 backend_dpp/scripts/seed-design-a.ts                     | 1753 ++++++++++++++++++++++++++++++++++++
 backend_dpp/scripts/tamper-passport.mjs                  |  712 +++++++++++++++
 backend_dpp/scripts/verify-chain.mjs                     |   15 +-
 backend_dpp/scripts/verify-passport.mjs                  | 2111 ++++++++++++++++++++++++++++++++++++++++++++
 backend_dpp/src/domain/integrity/canonical.ts            |   21 +-
 backend_dpp/src/domain/integrity/golden.test.ts          |   32 +-
 backend_dpp/src/domain/integrity/hash.ts                 |   17 +-
 backend_dpp/src/domain/integrity/keccak.ts               |  109 +++
 backend_dpp/src/domain/integrity/merkle.ts               |  216 +++++
 backend_dpp/src/domain/integrity/stageAlignment.test.ts  |    8 -
 backend_dpp/src/domain/integrity/uuid.ts                 |    5 +-
 backend_dpp/src/domain/trust/TrustProvider.ts            |  113 ++-
 backend_dpp/src/domain/trust/chainExport.ts              |   10 +-
 backend_dpp/src/domain/trust/contextV3.test.ts           |   23 +-
 backend_dpp/src/domain/trust/credentialLifecycle.test.ts |    8 -
 backend_dpp/src/domain/trust/credentialSchema.ts         |    5 +-
 backend_dpp/src/domain/trust/designA/README.md           |   92 ++
 backend_dpp/src/domain/trust/designA/anchor.ts           |  201 +++++
 backend_dpp/src/domain/trust/designA/authRoot.ts         |  111 +++
 backend_dpp/src/domain/trust/designA/chainGateway.ts     |  977 ++++++++++++++++++++
 backend_dpp/src/domain/trust/designA/chainTypes.ts       |  512 +++++++++++
 backend_dpp/src/domain/trust/designA/decisions.ts        |  546 ++++++++++++
 backend_dpp/src/domain/trust/designA/designARoutes.ts    | 1691 +++++++++++++++++++++++++++++++++++
 backend_dpp/src/domain/trust/designA/didEthr.ts          |  241 +++++
 backend_dpp/src/domain/trust/designA/fakeChainGateway.ts |  402 +++++++++
 backend_dpp/src/domain/trust/designA/index.ts            |  332 +++++++
 backend_dpp/src/domain/trust/designA/jose.ts             |  466 ++++++++++
 backend_dpp/src/domain/trust/designA/outbox.ts           |  144 +++
 backend_dpp/src/domain/trust/designA/relayer.ts          |  557 ++++++++++++
 backend_dpp/src/domain/trust/designA/setIssuers.test.ts  |  150 ++++
 backend_dpp/src/domain/trust/designA/typedData.ts        |  465 ++++++++++
 backend_dpp/src/domain/trust/designB.ts                  |   61 +-
 backend_dpp/src/domain/trust/designBRoutes.ts            |   16 +-
 backend_dpp/src/domain/trust/did.ts                      |   36 +-
 backend_dpp/src/domain/trust/index.ts                    |   63 +-
 backend_dpp/src/domain/trust/originCheck.ts              |   24 +-
 backend_dpp/src/domain/trust/rewrap.ts                   |   24 +-
 backend_dpp/src/domain/trust/schemaConformance.test.ts   |   10 +-
 backend_dpp/src/domain/trust/sign.ts                     |   65 +-
 backend_dpp/src/domain/trust/signingKeys.ts              |   66 +-
 backend_dpp/src/domain/trust/statusList.test.ts          |   13 -
 backend_dpp/src/domain/trust/statusList.ts               |   59 +-
 backend_dpp/src/domain/trust/trustUrls.ts                |   81 +-
 backend_dpp/src/domain/trust/types.ts                    |  181 ++++
 backend_dpp/src/domain/trust/vc.ts                       |  123 ++-
 backend_dpp/src/domain/trust/vcContext.ts                |   30 -
 backend_dpp/src/domain/trust/verdictCache.ts             |   12 +-
 contracts/README.md                                      |  252 ++++++
 contracts/deployments/README.md                          |   95 ++
 contracts/deployments/amoy.json                          |   29 +
 contracts/deployments/polygon.json                       |   22 +
 contracts/foundry.toml                                   |   78 ++
 contracts/script/Deploy.s.sol                            |  133 +++
 contracts/script/finalize-deployment.sh                  |   47 +
 contracts/src/TrustAnchorRegistry.sol                    |  487 ++++++++++
 contracts/src/vendor/EthereumDIDRegistry.sol             |  186 ++++
 contracts/test/TrustAnchorRegistry.t.sol                 | 1347 ++++++++++++++++++++++++++++
 frontend_dpp/eslint.config.js                            |   65 +-
 frontend_dpp/src/lib/wallet/CSP.md                       |  168 ++++
 frontend_dpp/src/lib/wallet/README.md                    |  260 ++++++
 frontend_dpp/src/lib/wallet/env.d.ts                     |   29 +
 frontend_dpp/src/lib/wallet/index.ts                     |   90 ++
 frontend_dpp/src/lib/wallet/session.ts                   |  208 +++++
 frontend_dpp/src/lib/wallet/signer.ts                    |  317 +++++++
 frontend_dpp/src/lib/wallet/typedData.ts                 |   96 ++
 frontend_dpp/src/lib/wallet/web3auth.ts                  |  608 +++++++++++++
 packages/dpp-core/index.ts                               |    6 +
 packages/dpp-core/vc/envelope.ts                         |  273 ++++++
 71 files changed, 19834 insertions(+), 580 deletions(-)
```

### `0b7df64`

```
backend_dpp/scripts/measure-rq3.mjs                      | 430 +++-------------------------
 backend_dpp/scripts/seed-design-a.ts                     | 418 +++++++--------------------
 backend_dpp/scripts/tamper-passport.mjs                  | 152 +++++-----
 backend_dpp/scripts/verify-chain.mjs                     |  15 +-
 backend_dpp/scripts/verify-passport.mjs                  | 619 ++++++++++++---------------------------
 backend_dpp/src/domain/integrity/canonical.ts            |  21 +-
 backend_dpp/src/domain/integrity/golden.test.ts          |  32 +--
 backend_dpp/src/domain/integrity/hash.ts                 |  17 +-
 backend_dpp/src/domain/integrity/keccak.ts               |  27 --
 backend_dpp/src/domain/integrity/merkle.ts               | 103 +------
 backend_dpp/src/domain/integrity/stageAlignment.test.ts  |   8 -
 backend_dpp/src/domain/integrity/uuid.ts                 |   5 +-
 backend_dpp/src/domain/trust/TrustProvider.ts            | 111 +------
 backend_dpp/src/domain/trust/chainExport.ts              |  10 +-
 backend_dpp/src/domain/trust/contextV3.test.ts           |  14 +-
 backend_dpp/src/domain/trust/credentialLifecycle.test.ts |   8 -
 backend_dpp/src/domain/trust/credentialSchema.ts         |   5 +-
 backend_dpp/src/domain/trust/designA/anchor.ts           |  73 +----
 backend_dpp/src/domain/trust/designA/authRoot.ts         |  50 ----
 backend_dpp/src/domain/trust/designA/chainGateway.ts     | 170 +----------
 backend_dpp/src/domain/trust/designA/chainTypes.ts       | 135 +--------
 backend_dpp/src/domain/trust/designA/decisions.ts        | 302 +-------------------
 backend_dpp/src/domain/trust/designA/designARoutes.ts    | 400 +++-----------------------
 backend_dpp/src/domain/trust/designA/didEthr.ts          | 173 +----------
 backend_dpp/src/domain/trust/designA/fakeChainGateway.ts |  64 -----
 backend_dpp/src/domain/trust/designA/index.ts            | 124 +-------
 backend_dpp/src/domain/trust/designA/jose.ts             | 165 -----------
 backend_dpp/src/domain/trust/designA/outbox.ts           |  39 ---
 backend_dpp/src/domain/trust/designA/relayer.ts          | 203 +------------
 backend_dpp/src/domain/trust/designA/setIssuers.test.ts  |  20 --
 backend_dpp/src/domain/trust/designA/typedData.ts        |  74 +----
 backend_dpp/src/domain/trust/designB.ts                  |  17 +-
 backend_dpp/src/domain/trust/designBRoutes.ts            |  12 +-
 backend_dpp/src/domain/trust/did.ts                      |  34 +--
 backend_dpp/src/domain/trust/index.ts                    |  23 +-
 backend_dpp/src/domain/trust/originCheck.ts              |  24 +-
 backend_dpp/src/domain/trust/rewrap.ts                   |   8 -
 backend_dpp/src/domain/trust/schemaConformance.test.ts   |  10 +-
 backend_dpp/src/domain/trust/sign.ts                     |  13 +-
 backend_dpp/src/domain/trust/signingKeys.ts              |  44 +--
 backend_dpp/src/domain/trust/statusList.test.ts          |  13 -
 backend_dpp/src/domain/trust/statusList.ts               |  50 +---
 backend_dpp/src/domain/trust/trustUrls.ts                |   9 -
 backend_dpp/src/domain/trust/types.ts                    |  76 +----
 backend_dpp/src/domain/trust/vc.ts                       |  38 ---
 backend_dpp/src/domain/trust/vcContext.ts                |  30 --
 backend_dpp/src/domain/trust/verdictCache.ts             |  12 +-
 contracts/README.md                                      |   2 +-
 contracts/deployments/polygon.json                       |  22 ++
 contracts/foundry.toml                                   |   4 +-
 frontend_dpp/src/lib/wallet/env.d.ts                     |  15 -
 frontend_dpp/src/lib/wallet/index.ts                     |  22 +-
 frontend_dpp/src/lib/wallet/session.ts                   |  71 +----
 frontend_dpp/src/lib/wallet/signer.ts                    | 177 ++----------
 frontend_dpp/src/lib/wallet/typedData.ts                 | 106 +++----
 frontend_dpp/src/lib/wallet/web3auth.ts                  | 699 +++++++++------------------------------------
 56 files changed, 781 insertions(+), 4737 deletions(-)
```

### `7a7f396`

```
backend_dpp/scripts/measure-rq3.mjs                      | 430 +++-------------------------
 backend_dpp/scripts/seed-design-a.ts                     | 330 ++-------------------
 backend_dpp/scripts/tamper-passport.mjs                  | 152 +++++-----
 backend_dpp/scripts/verify-chain.mjs                     |  15 +-
 backend_dpp/scripts/verify-passport.mjs                  | 619 ++++++++++++---------------------------
 backend_dpp/src/domain/integrity/canonical.ts            |  21 +-
 backend_dpp/src/domain/integrity/golden.test.ts          |  32 +--
 backend_dpp/src/domain/integrity/hash.ts                 |  17 +-
 backend_dpp/src/domain/integrity/keccak.ts               |  27 --
 backend_dpp/src/domain/integrity/merkle.ts               | 103 +------
 backend_dpp/src/domain/integrity/stageAlignment.test.ts  |   8 -
 backend_dpp/src/domain/integrity/uuid.ts                 |   5 +-
 backend_dpp/src/domain/trust/TrustProvider.ts            | 111 +------
 backend_dpp/src/domain/trust/chainExport.ts              |  10 +-
 backend_dpp/src/domain/trust/contextV3.test.ts           |  14 +-
 backend_dpp/src/domain/trust/credentialLifecycle.test.ts |   8 -
 backend_dpp/src/domain/trust/credentialSchema.ts         |   5 +-
 backend_dpp/src/domain/trust/designA/anchor.ts           |  73 +----
 backend_dpp/src/domain/trust/designA/authRoot.ts         |  50 ----
 backend_dpp/src/domain/trust/designA/chainGateway.ts     | 170 +----------
 backend_dpp/src/domain/trust/designA/chainTypes.ts       | 135 +--------
 backend_dpp/src/domain/trust/designA/decisions.ts        | 302 +-------------------
 backend_dpp/src/domain/trust/designA/designARoutes.ts    | 400 +++-----------------------
 backend_dpp/src/domain/trust/designA/didEthr.ts          | 173 +----------
 backend_dpp/src/domain/trust/designA/fakeChainGateway.ts |  64 -----
 backend_dpp/src/domain/trust/designA/index.ts            | 124 +-------
 backend_dpp/src/domain/trust/designA/jose.ts             | 165 -----------
 backend_dpp/src/domain/trust/designA/outbox.ts           |  39 ---
 backend_dpp/src/domain/trust/designA/relayer.ts          | 203 +------------
 backend_dpp/src/domain/trust/designA/setIssuers.test.ts  |  20 --
 backend_dpp/src/domain/trust/designA/typedData.ts        |  74 +----
 backend_dpp/src/domain/trust/designB.ts                  |  17 +-
 backend_dpp/src/domain/trust/designBRoutes.ts            |  12 +-
 backend_dpp/src/domain/trust/did.ts                      |  34 +--
 backend_dpp/src/domain/trust/index.ts                    |  23 +-
 backend_dpp/src/domain/trust/originCheck.ts              |  24 +-
 backend_dpp/src/domain/trust/rewrap.ts                   |   8 -
 backend_dpp/src/domain/trust/schemaConformance.test.ts   |  10 +-
 backend_dpp/src/domain/trust/sign.ts                     |  13 +-
 backend_dpp/src/domain/trust/signingKeys.ts              |  44 +--
 backend_dpp/src/domain/trust/statusList.test.ts          |  13 -
 backend_dpp/src/domain/trust/statusList.ts               |  50 +---
 backend_dpp/src/domain/trust/trustUrls.ts                |   9 -
 backend_dpp/src/domain/trust/types.ts                    |  76 +----
 backend_dpp/src/domain/trust/vc.ts                       |  38 ---
 backend_dpp/src/domain/trust/vcContext.ts                |  30 --
 backend_dpp/src/domain/trust/verdictCache.ts             |  12 +-
 contracts/README.md                                      |   2 +-
 contracts/deployments/polygon.json                       |  22 ++
 contracts/foundry.toml                                   |   4 +-
 frontend_dpp/src/lib/wallet/env.d.ts                     |  15 -
 frontend_dpp/src/lib/wallet/index.ts                     |  22 +-
 frontend_dpp/src/lib/wallet/session.ts                   |  71 +----
 frontend_dpp/src/lib/wallet/signer.ts                    | 177 ++----------
 frontend_dpp/src/lib/wallet/typedData.ts                 | 106 +++----
 frontend_dpp/src/lib/wallet/web3auth.ts                  | 699 +++++++++------------------------------------
 56 files changed, 706 insertions(+), 4724 deletions(-)
```
