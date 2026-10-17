# TrustDPP — Design A contracts

The on-chain layer of **Design A** of the TrustDPP thesis platform: the `did:ethr` variant, in which
every **attesting organization** holds its own **non-custodial** secp256k1 key (Web3Auth tKey, 2-of-3
shares — **the platform holds no share and cannot sign**) and signs its own W3C Verifiable
Credentials as a `did:ethr` issuer.

"Attesting organization" is the precise set, and it is neither "everyone on the platform" nor
"the suppliers":

- **The operator holds the most important key of all.** Its address is the on-chain
  `productController`, and only that address may authorize an issuer via `setIssuer`. The
  authorization root hangs off it.
- **Suppliers and certifiers hold keys** when they are bound to a node and issue their own slice.
- **Other members of those organizations do not.** Signing capability and login are separate
  layers: only the wallet-bound owner can attest, while colleagues keep password logins and may
  view and edit. An invited-but-unbound node has no key either — it has no organization yet.
- **Consumers and verifiers hold none.** Verification is public chain reads; needing a wallet to
  check a passport would defeat the point.
- **The platform holds none.** Its relayer pays gas and signs nothing. That absence is the
  measured claim, not an omission.

The predicate is *"does this party issue a signed claim?"* — not *"is this party in the supply
chain?"*. A certifier is not a supply-chain actor in the material-flow sense and still holds a key.

Two contracts are deployed:

| Contract                             | Role                                                                                         |
| ------------------------------------ | -------------------------------------------------------------------------------------------- |
| `src/TrustAnchorRegistry.sol`        | Authorization root and anchor log. Written for this thesis.                                    |
| `src/vendor/EthereumDIDRegistry.sol` | The **unmodified** ERC-1056 reference registry that `did:ethr` resolves against. Vendored.     |

---

## ⚠ The rule everything else depends on: `msg.sender` is never authorization

**Every state transition in `TrustAnchorRegistry` is authorized by an EIP-712 payload signature
recovered with `ecrecover`. `msg.sender` is never read, never compared, never stored, never
emitted.** There is no owner, no admin, no proxy, no upgrade path.

This is not stylistic. The platform runs a funded **relayer** that submits every transaction so that
attesting organizations never have to hold MATIC. Therefore `msg.sender` is *always* the platform
relayer. If any state transition were authorized on `msg.sender`, the platform would silently become
the controller of every product on the system and the entire "the platform cannot forge" claim would
collapse.

The relayer must be able to **pay gas and nothing else**. It can submit what an actor has already
signed, or refuse to submit it — censorship, a modelled and accepted threat — but it can never forge
or authorize.

A literal, testable consequence: because every call carries the complete pre-signed payload, **any
address on earth can submit any of these transactions and the outcome is identical**. That is
asserted by `test_AnyRelayerCanSubmitTheSamePreSignedPayload` (same calldata, five different
senders, identical resulting state) and by
`test_RelayerIsNeverAuthorization_AttributionFollowsTheSigner`, the load-bearing test of the suite.
`test_RuntimeBytecodeNeverExecutesCALLER` goes further and walks the deployed runtime bytecode as an
opcode stream, asserting that the `CALLER` (`0x33`) opcode does not appear in it at all.

Any change to this repo that introduces `msg.sender` into an authorization path is a bug, however
convenient it looks.

---

## What the registry answers

1. *Was this issuer authorized by the product's controller to make claims about this product?*
   → `productController[productId]` and `authorized[productId][issuer]`.
2. *Did this exact set of credentials exist at this block?*
   → the `Anchored(productId, merkleRoot, version, by)` event log.

```solidity
mapping(bytes32 => address) public productController;           // productId → controller
mapping(bytes32 => mapping(address => bool)) public authorized; // productId → issuer → allowed
mapping(address => uint256) public nonces;                      // replay protection, per signer

function claimProduct(bytes32 productId, address controller, uint256 nonce, bytes calldata sig) external;
function setIssuer(bytes32 productId, address issuer, bool ok, uint256 nonce, bytes calldata sig) external;
function anchor(bytes32 productId, bytes32 merkleRoot, uint64 version, uint256 nonce, bytes calldata sig) external;
```

### Design decisions

- **`productId = keccak256(productDid)`.** No GTIN, no product name, no company name, no URL. Only a
  digest of a public DID ever reaches the chain.
- **A Merkle root, not a flat hash.** The root commits to the ordered credential digests plus the
  snapshot digest, built off-chain per passport version. That buys **selective proof**: a verifier
  can prove one credential was in the anchored set without holding the whole bundle. The contract
  stores/emits the root and exposes `hashLeaf` / `hashNode` / `verifyInclusion` as `pure` functions —
  free to call, and a normative, executable specification the off-chain TypeScript builder must
  match byte for byte (see the NatSpec on `hashLeaf` for the exact convention, including the
  odd-node promotion rule and the `0x00` / `0x01` domain-separation tags).
- **Events over storage for anchors.** No `anchors` mapping exists. An offline verifier reads
  anchors from logs via `eth_getLogs` filtered on the indexed `productId`, roughly an order of
  magnitude cheaper than an `SSTORE` per anchor. The consequence — no on-chain monotonicity check on
  `version` — is deliberate; ordering comes from block/log index plus the off-chain snapshot.
- **Immutable.** No upgradeability, no proxy, no admin key, no owner. A thesis artifact has to be
  maximally auditable, so it deploys immutable and is redeployed if wrong. The registry is tiny
  (8,074 bytes runtime).
- **Custom errors, not revert strings.** Cheaper, and gas is a measured quantity here.

### Security decisions

| Concern                | Decision |
| ---------------------- | -------- |
| **Domain separator**   | OpenZeppelin `EIP712`: the separator is cached at construction along with the `chainid` and address it was built from, and **rebuilt on the fly whenever `block.chainid` or `address(this)` no longer matches**. Chosen over an unconditional per-call recompute (which every non-forked call would pay for, forever) and over a plain `immutable` (which is *wrong across a chain fork* — both forks would accept the same signature). Also gives ERC-5267 `eip712Domain()`, so the off-chain signer can read the domain off the contract instead of hard-coding it. `chainId` and `verifyingContract` are both in the domain, so a signature binds to one chain and one deployment. |
| **Malleability**       | Signature recovery goes through OpenZeppelin's `ECDSA`, which rejects high-`s` (`s > N/2`, the EIP-2 canonical form) with `ECDSAInvalidSignatureS` *before* touching `ecrecover`, rejects non-65-byte input, and — critically — converts `ecrecover`'s `address(0)` failure return into an explicit `ECDSAInvalidSignature` revert. That last point matters more than it looks: `address(0)` is exactly the controller value of an unclaimed product, so a silent zero recovery would be an impersonation primitive. |
| **Nonces**             | Per **signer**, strictly `nonce == nonces[signer]` then increment. Per-signer, not per-product, because the key is the principal a replay targets; because `claimProduct` can transfer control and a per-product counter would be shared mutable state across two different keys; and because one controller holds many products. The accepted cost is that a signer's operations are strictly serialized. |
| **`claimProduct`**     | **First-claim-wins, then controller-only transfer.** Unclaimed → the signature must be by `controller` itself (self-claim), so nobody can install a third party as controller without that party's key participating. Already claimed → only the **current** controller may reassign, and the nonce consumed is the *incumbent's*. Transfer to `address(0)` is rejected, because unclaiming would re-open the product to squatting. |
| **Squatting**          | **Known limitation, tested rather than hidden** (`test_KnownLimitation_DidSquattingIsPossibleBeforeTheBrandClaims`). `productId` derives from a public DID, so an adversary who learns a DID before the brand claims it can claim it first and permanently become its controller — there is no admin key and no recovery. Mitigation is operational: the brand claims at product creation, in the same workflow step that mints the DID, before the DID is published anywhere. The residual risk is a relayer that delays the claim transaction, which is the same censoring-relayer threat already modelled everywhere else. |
| **Sanity guards**      | `productId == 0`, `controller == 0`, `issuer == 0` and `merkleRoot == 0` are all rejected — each would be an uninitialised value off-chain with an irreversible on-chain effect. |

---

## The vendored ERC-1056 registry

Design A targets **Polygon Amoy (chainId 80002)**, and the canonical `EthereumDIDRegistry` is
**not deployed there**. It exists on Ethereum mainnet, Sepolia, Gnosis and Polygon *mainnet*;
`ethr-did-resolver` ships no Amoy entry in its built-in address table. So Design A deploys the
unmodified reference contract itself.

`src/vendor/EthereumDIDRegistry.sol` is upstream commit `0ab4f151` of
`uport-project/ethr-did-registry`, byte for byte from line 55 onwards, with only a provenance header
added. Verify:

```sh
tail -n +55 src/vendor/EthereumDIDRegistry.sol | shasum -a 256
# 996a83c78cc60e03b8406cf2d6768bae929a0f3a387c8a45e9df813065ae7a5c
```

It is excluded from `forge fmt` (`[fmt] ignore` in `foundry.toml`) precisely so formatting can never
silently diverge it. Its pragma is `^0.8.6`, satisfied by the project-wide pinned `0.8.28`, so it
compiles in the default profile — no separate compilation profile and **no edit to the vendored
logic** were needed.

Because the address is not canonical, a third-party verifier must be told it explicitly:

```ts
getResolver({ networks: [{ name: "amoy", chainId: 80002, registry: "0x…", rpcUrl: "…" }] });
```

---

## Build, test, deploy

Foundry v1.7.1. Binaries are used from `~/.foundry/bin/` directly, so nothing depends on shell
profile changes having taken effect.

```sh
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup
```

Dependencies. `lib/` is git-ignored and the deps are installed as **plain clones, not git
submodules**, so that nothing in this directory writes to the parent repository's `.gitmodules`.
Restore them with these exact pinned commands (they are the reproducibility contract — there is no
lockfile, because Foundry only maintains one for submodule installs):

```sh
forge install --no-git foundry-rs/forge-std@v1.9.7
forge install --no-git OpenZeppelin/openzeppelin-contracts@v5.4.0
```

```sh
forge build            # compile
forge test -vv         # 66 tests, all green
forge fmt --check      # formatting gate (skips src/vendor/)
forge snapshot         # writes .gas-snapshot + snapshots/TrustAnchorRegistry.json
forge coverage
```

Deploy (env: `PRIVATE_KEY`, `AMOY_RPC_URL`, `POLYGONSCAN_API_KEY`; see `.env.example`):

```sh
forge script script/Deploy.s.sol:Deploy --rpc-url amoy                       # dry run
forge script script/Deploy.s.sol:Deploy --rpc-url amoy --broadcast --verify  # for real
./script/finalize-deployment.sh 80002 amoy                                   # stamp tx hashes
```

`deployments/<network>.json` is a **committed artifact and the only thing the backend config
consumes** — see `deployments/README.md`. On Polygon mainnet, where the canonical ERC-1056 exists,
set `SKIP_DID_REGISTRY=true` and `DID_REGISTRY_ADDRESS=0x…` to reference it instead of deploying a
second copy.

### Pinned toolchain

| | |
| --- | --- |
| foundry | v1.7.1 (`4072e48705`, 2026-05-08) |
| solc | 0.8.28 (pinned in `foundry.toml`) |
| EVM target | `shanghai` |
| optimizer | on, 20 000 runs |
| metadata | `bytecode_hash = "none"`, `cbor_metadata = false` — byte-identical builds across machines |
| forge-std | v1.9.7 (`77041d2ce690e692d6e03cc812b57d1ddaa4d505`) |
| openzeppelin-contracts | v5.4.0 (`c64a1edb67b6e3f4a15cca8909c9482ad33a02b0`) |

---

## Gas (thesis measurement)

The thesis reports gas from real transaction receipts, not from in-test estimates (thesis
Table 7.5). The receipts are recorded in `../evidence/`:

| Figure | Gas | Source |
| ------ | --: | ------ |
| `TrustAnchorRegistry` deployment (Polygon main network, 23 September 2026) | 1 802 590 | `evidence/2026-09-23_polygon-receipts-gas.json` |
| One publication, batched path (`claimProduct` + `setIssuers` + `anchor`) | 267 008 | `evidence/2026-09-17_receipts-gas.json` (`paths.batched`) |
| One publication, per-issuer path (`claimProduct` + 4 × `setIssuer` + `anchor`) | 405 053 | `evidence/2026-09-17_receipts-gas.json` (`paths.perIssuer`) |

The per-transaction receipts behind each total are listed in the same files. The recurring
per-publication cost is `anchor` (44 324 to 44 336 gas on these receipts); anchors are events, not storage,
so a publication writes no anchor slot.

`forge test --match-test test_Gas -vv` runs the in-test gas checks (`test_Gas_PerOperation`,
`test_Gas_SetIssuersVersusFourSetIssuerCalls`).

Contract size: `TrustAnchorRegistry` 8 074 B runtime, byte-equal to the deployed Amoy instance
modulo immutables (`evidence/2026-09-19_bytecode-equality.json`).

---

## Test suite

66 tests in `test/TrustAnchorRegistry.t.sol`. EIP-712 digests are reconstructed in the test from
literals rather than read off the contract, so an encoding bug cannot hide by being mirrored.

Coverage highlights:

- **Core property** — `test_RelayerIsNeverAuthorization_AttributionFollowsTheSigner`,
  `test_AnyRelayerCanSubmitTheSamePreSignedPayload`, `test_RuntimeBytecodeNeverExecutesCALLER`.
- **Replay** — same signature twice (all three functions), stale nonce, nonce too high, per-signer
  nonce independence, cross-**chain** replay (Amoy signature rejected on Polygon, and *then* a
  Polygon-domain signature accepted, proving the separator is rebuilt correctly and not merely
  broken), cross-**contract** replay, and cross-**payload-type** replay.
- **Authorization** — non-controller `setIssuer` / `anchor`, operations on unclaimed products, an
  *authorized issuer* correctly being unable to touch the registry, relayer tampering with the
  arguments of a payload it is forwarding.
- **Signatures** — malleable high-`s`, all-zero, invalid `v`, wrong length, garbage, and an explicit
  test that a zero recovery cannot impersonate an unclaimed product's `address(0)` controller.
- **Fuzz** (512 runs each) — both state transitions (`testFuzz_ClaimProduct`, `testFuzz_SetIssuer`)
  plus their negative cases, anchor attribution, wrong nonces, cross-chain replay, and Merkle
  inclusion over odd-sized trees.
