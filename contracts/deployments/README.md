# `contracts/deployments/`

**These `<network>.json` files are committed build artifacts, and they are the *only* artifact the
backend configuration consumes.**

Nothing else in `contracts/` — not `out/`, not `broadcast/`, not the Foundry cache — is read by the
running platform. `out/` and `broadcast/` are git-ignored precisely so that no part of the stack can
come to depend on them. If an address is not in this directory, the backend does not know about it.

The chain of custody is:

```
forge script script/Deploy.s.sol --broadcast   ->  deployments/amoy.json   (committed)
                                                          |
                                                          v
                                        .env  DID_REGISTRY_ADDRESS
                                              ANCHOR_REGISTRY_ADDRESS
```

`.env.a.example` at the repo root names both variables and points here for their values. Copying the
address by hand out of a terminal scrollback is the failure mode this directory exists to prevent:
an anchor written against the wrong registry address is indistinguishable from no anchor at all, and
a `did:ethr` minted against the wrong ERC-1056 registry resolves to a document nobody else can
verify.

## Files

| File            | Chain                       | Status                                             |
| --------------- | --------------------------- | -------------------------------------------------- |
| `amoy.json`     | Polygon Amoy (80002)        | Design A target. Written by `script/Deploy.s.sol`. |
| `polygon.json`  | Polygon mainnet (137)       | Deployed 23 September 2026 (block 94303476), verified on Polygonscan. Reuses the *canonical* ERC-1056, so `ethereumDidRegistryTx` is empty. |
| `anvil.json`    | Local anvil (31337)         | Throwaway; regenerate freely, do not commit.        |

## Shape

```json
{
  "network": "amoy",
  "chainId": 80002,
  "blockNumber": 12345678,
  "deployer": "0x0000000000000000000000000000000000000000",

  "trustAnchorRegistry": "0x0000000000000000000000000000000000000000",
  "trustAnchorRegistryTx": "0x0000000000000000000000000000000000000000000000000000000000000000",

  "ethereumDidRegistry": "0x0000000000000000000000000000000000000000",
  "ethereumDidRegistryTx": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "ethereumDidRegistryIsCanonical": false,

  "eip712Name": "TrustAnchorRegistry",
  "eip712Version": "1",
  "solcVersion": "0.8.28",
  "evmVersion": "shanghai"
}
```

### Field notes

- **`chainId`** — must match `CHAIN_ID` in the backend `.env`. It is baked into every
  `did:ethr:80002:0x…` the moment one is minted, and into the EIP-712 domain separator, so it cannot
  be changed after the first passport is published without invalidating everything already issued.
- **`trustAnchorRegistry`** — the `verifyingContract` in the EIP-712 domain. Change it and every
  previously produced signature stops verifying. It is not upgradeable and has no admin key; a fix
  means a new deployment and a new address, and the backend must then treat pre-existing anchors as
  belonging to the old registry.
- **`ethereumDidRegistry`** — on Amoy this is *our own* deployment of the unmodified ERC-1056
  reference contract, because no canonical one exists on Amoy (see
  `src/vendor/EthereumDIDRegistry.sol` for the full rationale). A third-party verifier must be told
  this address explicitly, because `ethr-did-resolver` has no built-in entry for chain 80002:

  ```ts
  getResolver({
    networks: [{ name: "amoy", chainId: 80002, registry: "0x…", rpcUrl: "…" }],
  });
  ```

- **`ethereumDidRegistryIsCanonical`** — `false` on Amoy, `true` wherever the upstream deployment is
  used. This flag is what tells a verifier whether it needs the explicit `networks` override above.
- **`eip712Name` / `eip712Version`** — the domain the off-chain signer must use. Also readable from
  the contract at runtime via ERC-5267 `eip712Domain()`; the JSON copy exists so a config check can
  fail fast without an RPC round trip.
- **`*Tx`** — the deploy transaction hashes. Foundry scripts cannot know these (the broadcast runs
  after `run()` returns), so `Deploy.s.sol` writes them as `""` and
  `script/finalize-deployment.sh` fills them in from
  `broadcast/Deploy.s.sol/<chainId>/run-latest.json`.

## Regenerating

```sh
forge script script/Deploy.s.sol:Deploy --rpc-url amoy --broadcast --verify
./script/finalize-deployment.sh 80002 amoy
git add deployments/amoy.json && git commit -m "chore(contracts): record amoy deployment"
```

Do not hand-edit these files except to fill a field the tooling could not.
