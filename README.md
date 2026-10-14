# TrustDPP — thesis artifact

Code and evidence for the Master's thesis

> **Decentralized Per-Actor Attribution for EU Digital Product Passports — A Manifest-Graph
> Architecture with Comparative Prototype Evaluation**
> Abdelrahman Aljabali, M.Sc. Blockchain & Distributed Ledger Technologies,
> Hochschule Mittweida, 2026.

This repository holds the parts of the prototype the thesis makes claims about: the smart
contract, the trust layer with both designs, the browser wallet boundary, the shared credential
core, the evaluation instruments and every dated evidence file. It is a **reading and
reproduction artifact**, not a deployable platform. The passport editor, supplier portal,
dashboards, authentication, database and deployment configuration are part of the product the
prototype was built in and are not included (thesis, Chapter 6).

The final PDF is in [`thesis/`](thesis/), with its LaTeX sources in [`thesis/latex/`](thesis/latex/).

## What you can reproduce

Requirements: Node.js ≥ 20, [Foundry](https://getfoundry.sh) 1.7.1 for the contracts, git.

```bash
git clone --recurse-submodules https://github.com/abdelrahman-aljabali/Masterarbeit.git
cd Masterarbeit
```

| What | Command | Result on 10 October 2026 (`evidence/2026-10-10_repository-reproduction.txt`) |
|---|---|---|
| Contract build and tests (Sec. 7.6) | `cd contracts && forge test` | 66 passed, 0 failed |
| Reproducible bytecode (Sec. 7.6) | `cd contracts && forge build` | the same runtime bytecode as the build compared with the deployed contract in `evidence/2026-09-19_bytecode-equality.json` (and `.py`) |
| Verifier self-test (Sec. 6.3) | `node backend_dpp/scripts/verify-passport.mjs --self-test` | PASS |
| Verifier, offline (RQ2) | `node backend_dpp/scripts/verify-passport.mjs evidence/2026-08-24_designA-export-dpp_f3bea69cca545292-v1.json --offline --as-of 2026-08-24T12:00:00Z` | 32 passed, 20 skipped (the chain checks), INCOMPLETE by design |
| Verifier, online on Polygon Amoy (RQ1, RQ2) | `node backend_dpp/scripts/verify-passport.mjs evidence/2026-08-24_designA-export-dpp_f3bea69cca545292-v1.json --rpc https://polygon-amoy.drpc.org` | 52 passed, VERIFIED |
| Verifier, Polygon main network (Sec. 7.5) | see below | 52 passed, VERIFIED |
| Verifier on the browser-signed passport (Sec. 7.3) | `node backend_dpp/scripts/verify-passport.mjs evidence/2026-10-10_designA-browser-export-dpp_38e8491ab51db46c-v8.json --rpc https://polygon-amoy.drpc.org` | 52 passed, VERIFIED (two of its six credentials were signed through the key infrastructure in the browser on 6 October 2026) |
| Tamper suite (RQ1) | `npm install`, then `node backend_dpp/scripts/tamper-passport.mjs evidence/2026-08-24_designA-export-dpp_f3bea69cca545292-v1.json --rpc https://polygon-amoy.drpc.org --out-dir /tmp/tamper` | 15 mutations, none accepted (see note) |

Main-network verification of the replicated passport:

```bash
node backend_dpp/scripts/verify-passport.mjs \
  evidence/2026-09-23_polygon-export-dpp_39a431d1543b4252-v1.json \
  --rpc https://polygon.drpc.org --chain-id 137 --chain-name polygon \
  --registry 0x8c7F06eDe1C36FDc7d36AAb77D2Ac5bfB0aABb65 \
  --did-registry 0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B --from-block 94303476
```

Notes:

- **Public endpoints time out now and then.** A chain read that times out is reported as a
  skip and the verdict becomes INCOMPLETE, never VERIFIED. Re-run, or use another endpoint.
  `polygon-amoy.drpc.org` and `polygon.drpc.org` gave complete runs on 7 October 2026; pruned
  endpoints that drop old receipts are handled by a log scan (Sec. 6.3).
- **Tamper suite: 15 of 19.** Four mutations (cross-protocol replay, login-token replay,
  cross-product transplant, expired credential) re-sign with a real, authorized demonstration
  supplier key. Those keys are not published, so the script omits the four and says so. The
  full run of 24 August 2026 with all 19 is `evidence/2026-08-24_designA-tamper-suite-v2.{json,txt}`.
- The verifier has **no dependencies**; it implements keccak-256, secp256k1 recovery and the
  Merkle convention itself (Sec. 6.3). The tamper suite needs `@noble/curves` and `@noble/hashes`
  only to mint its forgeries.
- Running the ceremony driver (`seed-design-a.ts`) or the measurement harness requires the full
  platform and is not reproducible from this repository; their outputs are in `evidence/`.

## Where each claim lives

| Thesis | Claim | Files |
|---|---|---|
| Sec. 5.3.4, 6.2, 7.6 | The authorization root and anchor log; authorization by EIP-712 signature, never by sender; 66 tests | [`contracts/src/TrustAnchorRegistry.sol`](contracts/src/TrustAnchorRegistry.sol), [`contracts/test/`](contracts/test/), [`contracts/script/Deploy.s.sol`](contracts/script/Deploy.s.sol) |
| Sec. 5.3.1, Table A.2 | Self-deployed ERC-1056 on Amoy, canonical one on Polygon; deployment records | [`contracts/src/vendor/`](contracts/src/vendor/), [`contracts/deployments/`](contracts/deployments/) |
| Sec. 6.1 | One trust-provider interface, fifteen methods, two implementations | [`backend_dpp/src/domain/trust/TrustProvider.ts`](backend_dpp/src/domain/trust/TrustProvider.ts), [`designA/`](backend_dpp/src/domain/trust/designA/), [`designB.ts`](backend_dpp/src/domain/trust/designB.ts) |
| Sec. 6.1 | Design A's provider holds no key and refuses to sign | [`backend_dpp/src/domain/trust/designA/index.ts`](backend_dpp/src/domain/trust/designA/index.ts) |
| Sec. 6.1 | Lint rules confine EVM/JOSE libraries and key-touching code | [`backend_dpp/eslint.config.js`](backend_dpp/eslint.config.js), [`frontend_dpp/eslint.config.js`](frontend_dpp/eslint.config.js) |
| Sec. 5.3.2, 6.2 | The browser wallet boundary: key reconstruction, ES256K-R signing, EIP-712, logout after every ceremony | [`frontend_dpp/src/lib/wallet/`](frontend_dpp/src/lib/wallet/) |
| Sec. 6.2, Table 6.2 | EIP-712 structures, relayer, outbox, chain gateway | [`backend_dpp/src/domain/trust/designA/`](backend_dpp/src/domain/trust/designA/) |
| Sec. 5.3.3 | Merkle convention, canonical JSON, digests | [`backend_dpp/src/domain/integrity/`](backend_dpp/src/domain/integrity/) |
| Sec. 5.3.3, 6.2 | The credential builder shared by browser and server; field catalogue; JSON-LD contexts | [`packages/dpp-core/`](packages/dpp-core/) |
| Sec. 5.6 | Design B baseline: did:web, Ed25519, eddsa-rdfc-2022, Bitstring Status List | [`backend_dpp/src/domain/trust/designB.ts`](backend_dpp/src/domain/trust/designB.ts), [`vc.ts`](backend_dpp/src/domain/trust/vc.ts), [`statusList.ts`](backend_dpp/src/domain/trust/statusList.ts) |
| Sec. 4.4, 6.3, App. C | The independent verifier and its 14 kinds of check | [`backend_dpp/scripts/verify-passport.mjs`](backend_dpp/scripts/verify-passport.mjs) |
| Sec. 4.4, 7.2 | The tamper suite | [`backend_dpp/scripts/tamper-passport.mjs`](backend_dpp/scripts/tamper-passport.mjs) |
| Sec. 4.4, 7.4 | The ceremony driver and the measurement harness | [`backend_dpp/scripts/seed-design-a.ts`](backend_dpp/scripts/seed-design-a.ts), [`backend_dpp/scripts/measure-rq3.mjs`](backend_dpp/scripts/measure-rq3.mjs) |
| Ch. 7, App. A | Every dated artifact | [`evidence/`](evidence/) |

## Provenance

This repository reflects the state of 10 October 2026. Commit identifiers inside the evidence
headers refer to the prototype's development history.

## What is not here

- The application around the trust layer (editor, portals, dashboards, authentication, e-mail,
  database schema, Docker Compose, Caddy, monitoring).
- Environment files, API keys, the relayer key and the demonstration actors' private keys. No
  file here contains a private key; the only key-like constant is the public self-test vector
  for private key 1 in the verifier.
- The two screen recordings of the browser session of 6 October 2026 (684 MB); the step-by-step
  count is `evidence/2026-10-06_r4-browser-session.md`.

The e-mail addresses that appear in `evidence/` belong to demonstration organizations and are
part of signed, published credentials; changing them would break the signatures under study.

## License

See [LICENSE](LICENSE).
