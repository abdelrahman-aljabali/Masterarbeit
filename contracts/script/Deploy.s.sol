// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {TrustAnchorRegistry} from "../src/TrustAnchorRegistry.sol";
import {EthereumDIDRegistry} from "../src/vendor/EthereumDIDRegistry.sol";

/// @title Deploy — TrustDPP Design A on-chain layer
///
/// @notice Deploys, in one broadcast:
///   1. `EthereumDIDRegistry` — the **unmodified** ERC-1056 reference contract.
///   2. `TrustAnchorRegistry` — the authorization root and anchor log.
///
/// @dev **Why the ERC-1056 registry is deployed here rather than referenced.**
/// Design A targets Polygon Amoy (chainId 80002). The canonical `EthereumDIDRegistry` is deployed
/// on Ethereum mainnet, Sepolia, Gnosis and Polygon *mainnet* — but **not on Amoy**, and
/// `ethr-did-resolver` ships no Amoy entry in its built-in address table. So Amoy gets our own
/// deployment of the unmodified reference source (see src/vendor/EthereumDIDRegistry.sol for full
/// provenance). Production on Polygon mainnet would use the canonical deployment instead, and this
/// script's step 1 would be skipped — set `SKIP_DID_REGISTRY=true` and `DID_REGISTRY_ADDRESS=0x…`.
///
/// Both contracts are immutable: no proxy, no admin key, no owner. Redeploy to change anything.
///
/// Usage:
///
/// ```sh
/// # dry run
/// forge script script/Deploy.s.sol:Deploy --rpc-url amoy
///
/// # broadcast + verify
/// forge script script/Deploy.s.sol:Deploy --rpc-url amoy --broadcast --verify
///
/// # then stamp the tx hashes into deployments/amoy.json
/// ./script/finalize-deployment.sh 80002 amoy
/// ```
///
/// Required env: `PRIVATE_KEY` (deployer; needs a little MATIC), `AMOY_RPC_URL`.
/// Optional env: `DEPLOYMENT_NAME` (defaults to a name derived from chainId),
///               `SKIP_DID_REGISTRY` + `DID_REGISTRY_ADDRESS` (use a canonical registry instead).
contract Deploy is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        bool skipDidRegistry = vm.envOr("SKIP_DID_REGISTRY", false);
        address preexistingDidRegistry = vm.envOr("DID_REGISTRY_ADDRESS", address(0));

        if (skipDidRegistry) {
            require(preexistingDidRegistry != address(0), "SKIP_DID_REGISTRY set but DID_REGISTRY_ADDRESS empty");
            require(preexistingDidRegistry.code.length > 0, "DID_REGISTRY_ADDRESS has no code on this chain");
        }

        console2.log("chainId ", block.chainid);
        console2.log("deployer", deployer);

        vm.startBroadcast(deployerPk);

        address didRegistry;
        if (skipDidRegistry) {
            didRegistry = preexistingDidRegistry;
            console2.log("EthereumDIDRegistry (pre-existing, canonical)", didRegistry);
        } else {
            didRegistry = address(new EthereumDIDRegistry());
            console2.log("EthereumDIDRegistry (self-deployed reference) ", didRegistry);
        }

        TrustAnchorRegistry anchorRegistry = new TrustAnchorRegistry();
        console2.log("TrustAnchorRegistry                           ", address(anchorRegistry));

        vm.stopBroadcast();

        // Sanity: the domain separator must bind THIS chain and THIS address. A mismatch here
        // means every signature the backend produces would be rejected.
        require(
            anchorRegistry.domainSeparator()
                == keccak256(
                    abi.encode(
                        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                        keccak256(bytes("TrustAnchorRegistry")),
                        keccak256(bytes("1")),
                        block.chainid,
                        address(anchorRegistry)
                    )
                ),
            "domain separator mismatch"
        );

        // NOT `skipDidRegistry`. "We reused an existing deployment" and "that deployment is the
        // CANONICAL upstream one" are different claims, and conflating them wrote
        // `ethereumDidRegistryIsCanonical: true` into the Amoy record for an address that is our
        // own deployment of the reference source — a false provenance claim in the one file the
        // thesis and every verifier read to learn what this deployment is. The script cannot
        // determine it, so the operator states it, and the default is the safe answer.
        bool didRegistryIsCanonical = vm.envOr("DID_REGISTRY_IS_CANONICAL", false);
        _write(didRegistry, address(anchorRegistry), deployer, didRegistryIsCanonical);
    }

    /// @dev Writes `deployments/<name>.json`. Transaction hashes are not knowable from inside a
    /// script (the broadcast is executed after `run()` returns), so they are emitted as empty
    /// strings and filled in by script/finalize-deployment.sh from the broadcast artifact.
    function _write(address didRegistry, address anchorRegistry, address deployer, bool didRegistryIsCanonical)
        internal
    {
        string memory name = vm.envOr("DEPLOYMENT_NAME", _defaultName(block.chainid));

        string memory obj = "deployment";
        vm.serializeString(obj, "network", name);
        vm.serializeUint(obj, "chainId", block.chainid);
        vm.serializeUint(obj, "blockNumber", block.number);
        vm.serializeAddress(obj, "deployer", deployer);
        vm.serializeAddress(obj, "trustAnchorRegistry", anchorRegistry);
        vm.serializeAddress(obj, "ethereumDidRegistry", didRegistry);
        vm.serializeBool(obj, "ethereumDidRegistryIsCanonical", didRegistryIsCanonical);
        vm.serializeString(obj, "trustAnchorRegistryTx", "");
        vm.serializeString(obj, "ethereumDidRegistryTx", "");
        vm.serializeString(obj, "eip712Name", "TrustAnchorRegistry");
        vm.serializeString(obj, "eip712Version", "1");
        vm.serializeString(obj, "solcVersion", "0.8.28");
        string memory json = vm.serializeString(obj, "evmVersion", "shanghai");

        string memory path = string.concat("deployments/", name, ".json");
        vm.writeJson(json, path);
        console2.log("wrote", path);
    }

    function _defaultName(uint256 chainId) internal pure returns (string memory) {
        if (chainId == 80002) return "amoy";
        if (chainId == 137) return "polygon";
        if (chainId == 11155111) return "sepolia";
        if (chainId == 31337) return "anvil";
        return "unknown";
    }
}
