// ─────────────────────────────────────────────────────────────────────────────
// VENDORED — DO NOT EDIT THE LOGIC BELOW.
//
// Contract : EthereumDIDRegistry (the ERC-1056 "Ethereum Lightweight Identity"
//            reference implementation; the registry that `did:ethr` resolves
//            against and that `ethr-did-resolver` reads).
// Source   : https://github.com/uport-project/ethr-did-registry
//            contracts/EthereumDIDRegistry.sol
// Commit   : 0ab4f151ddde5b7739b97827c4fb901289f57892 (2022-01-11)
// Retrieved: 2026-08-04
// License  : MIT (as upstream)
//
// PROVENANCE / INTEGRITY
// ----------------------
// Everything from the upstream SPDX line onwards (line 55) is the upstream file
// byte for byte. Only this header comment was added. Verify with:
//
//   tail -n +55 src/vendor/EthereumDIDRegistry.sol | shasum -a 256
//   # => 996a83c78cc60e03b8406cf2d6768bae929a0f3a387c8a45e9df813065ae7a5c
//
// This file is excluded from `forge fmt` (see `[fmt] ignore` in foundry.toml)
// precisely so that formatting never silently diverges it from upstream.
//
// WHY A SELF-DEPLOYED COPY
// ------------------------
// Design A targets **Polygon Amoy (chainId 80002)**, and the canonical
// EthereumDIDRegistry is **not deployed there**. `ethr-did-resolver` ships a
// built-in address table covering Ethereum mainnet, Sepolia, Gnosis and Polygon
// *mainnet*, and Amoy has no entry. Design A therefore deploys this unmodified
// reference contract itself (see script/Deploy.s.sol) and records the resulting
// address in deployments/amoy.json.
//
// Consequences a verifier must be told about, and which the thesis records as a
// known deviation from "canonical registry only":
//
//  1. The address differs from the canonical one, so a third-party verifier must
//     be configured with it explicitly:
//       new Resolver(getResolver({ networks: [
//         { name: "amoy", chainId: 80002, registry: "0x…", rpcUrl: "…" }
//       ]}))
//     Production on Polygon mainnet would use the canonical deployment and need
//     no such configuration.
//  2. The bytecode is not identical to the canonical mainnet deployment, because
//     that one was compiled with an older solc. The *source* and therefore the
//     ABI and the storage/event semantics are identical. The only behavioural
//     difference introduced by compiling under ^0.8 is that the arithmetic in
//     `block.timestamp + validity` reverts on overflow instead of wrapping —
//     strictly a hardening, and unreachable for any sane `validity`.
//  3. Upstream's pragma is `^0.8.6`, which the project-wide pinned `0.8.28`
//     satisfies, so this file compiles in the default profile alongside
//     TrustAnchorRegistry. No separate compilation profile or pragma edit was
//     needed — and none was made.
// ─────────────────────────────────────────────────────────────────────────────

/* SPDX-License-Identifier: MIT */

pragma solidity ^0.8.6;

contract EthereumDIDRegistry {

  mapping(address => address) public owners;
  mapping(address => mapping(bytes32 => mapping(address => uint))) public delegates;
  mapping(address => uint) public changed;
  mapping(address => uint) public nonce;

  modifier onlyOwner(address identity, address actor) {
    require (actor == identityOwner(identity), "bad_actor");
    _;
  }

  event DIDOwnerChanged(
    address indexed identity,
    address owner,
    uint previousChange
  );

  event DIDDelegateChanged(
    address indexed identity,
    bytes32 delegateType,
    address delegate,
    uint validTo,
    uint previousChange
  );

  event DIDAttributeChanged(
    address indexed identity,
    bytes32 name,
    bytes value,
    uint validTo,
    uint previousChange
  );

  function identityOwner(address identity) public view returns(address) {
     address owner = owners[identity];
     if (owner != address(0x00)) {
       return owner;
     }
     return identity;
  }

  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == identityOwner(identity), "bad_signature");
    nonce[signer]++;
    return signer;
  }

  function validDelegate(address identity, bytes32 delegateType, address delegate) public view returns(bool) {
    uint validity = delegates[identity][keccak256(abi.encode(delegateType))][delegate];
    return (validity > block.timestamp);
  }

  function changeOwner(address identity, address actor, address newOwner) internal onlyOwner(identity, actor) {
    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }

  function changeOwner(address identity, address newOwner) public {
    changeOwner(identity, msg.sender, newOwner);
  }

  function changeOwnerSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "changeOwner", newOwner));
    changeOwner(identity, checkSignature(identity, sigV, sigR, sigS, hash), newOwner);
  }

  function addDelegate(address identity, address actor, bytes32 delegateType, address delegate, uint validity) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp + validity;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function addDelegate(address identity, bytes32 delegateType, address delegate, uint validity) public {
    addDelegate(identity, msg.sender, delegateType, delegate, validity);
  }

  function addDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate, uint validity) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "addDelegate", delegateType, delegate, validity));
    addDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate, validity);
  }

  function revokeDelegate(address identity, address actor, bytes32 delegateType, address delegate) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeDelegate(address identity, bytes32 delegateType, address delegate) public {
    revokeDelegate(identity, msg.sender, delegateType, delegate);
  }

  function revokeDelegateSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 delegateType, address delegate) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "revokeDelegate", delegateType, delegate));
    revokeDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hash), delegateType, delegate);
  }

  function setAttribute(address identity, address actor, bytes32 name, bytes memory value, uint validity ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function setAttribute(address identity, bytes32 name, bytes memory value, uint validity) public {
    setAttribute(identity, msg.sender, name, value, validity);
  }

  function setAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value, uint validity) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "setAttribute", name, value, validity));
    setAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value, validity);
  }

  function revokeAttribute(address identity, address actor, bytes32 name, bytes memory value ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeAttribute(address identity, bytes32 name, bytes memory value) public {
    revokeAttribute(identity, msg.sender, name, value);
  }

  function revokeAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes memory value) public {
    bytes32 hash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), this, nonce[identityOwner(identity)], identity, "revokeAttribute", name, value));
    revokeAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value);
  }

}
