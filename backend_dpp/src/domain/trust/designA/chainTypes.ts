/**
 * ─── Design A chain vocabulary — the half with no chain client in it ──────────
 * Everything in this file is a TYPE, a VALIDATOR, an ERROR or a PURE FUNCTION
 * over strings. It imports nothing — not `ethers`, not `config`, not Prisma. Two
 * structural reasons, both load-bearing:
 */

// ── Primitive aliases ────────────────────────────────────────────────────────
// Deliberately plain `string` aliases rather than branded types: these values
// come out of JSON columns and HTTP bodies, where the compiler's word is not
// evidence, so the guarantee has to be a runtime check (`asAddress` and friends)
// that BOTH gateways run — not a cast that only looks like one.

/** `0x` + 20 bytes, lower case. */
export type Address = string;
/** `0x` + 32 bytes. */
export type Bytes32 = string;
/** `keccak256(productDid)` — the contract's `productId`. See TrustAnchorRegistry. */
export type ProductId = Bytes32;
/** `0x` + 65 bytes: an EIP-712 `(r,s,v)` signature as the contract expects it. */
export type Signature65 = string;

export const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";
export const ZERO_BYTES32: Bytes32 = `0x${"0".repeat(64)}`;

// ── Errors ───────────────────────────────────────────────────────────────────

/**
 * Base for everything this layer throws. The taxonomy matters more than the
 * classes: a caller MUST be able to tell "the chain says no" from "I could not
 * ask the chain", because collapsing the second into the first is how a down
 * RPC silently becomes a negative authorization answer.
 */
export class ChainGatewayError extends Error {
  readonly detail: Record<string, unknown>;
  constructor(message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = new.target.name;
    this.detail = detail;
  }
}

/**
 * **The chain could not be read.** Transport failure, timeout, both endpoints
 * exhausted, or a read that could not be completed to the end (a change-log walk
 * that ran out of hops). NEVER carries a value — that is the entire point. Any
 * caller that turns this into `false`, `null` or "unverified but fine" has
 * reintroduced the bug this class exists to prevent.
 */
export class ChainUnavailableError extends ChainGatewayError {}

/**
 * The endpoint answered, but not for the chain we were configured for (or the
 * configuration is internally inconsistent). Not retryable and NOT failed over:
 * a second endpoint cannot fix a wrong `CHAIN_ID`, and an RPC that lies about
 * its chain id is precisely the "lying RPC" the threat model refuses to model
 * away.
 */
export class ChainMisconfiguredError extends ChainGatewayError {}

/**
 * The contract itself refused — `InvalidNonce`, `NotController`,
 * `ClaimMustBeSelfSigned`, a zero guard. A deterministic answer from the chain,
 * identical on every endpoint, so it is never retried and never failed over.
 */
export class ChainCallRevertedError extends ChainGatewayError {
  /** Decoded custom-error name where the node returned revert data. */
  readonly reason: string | null;
  constructor(message: string, reason: string | null, detail: Record<string, unknown> = {}) {
    super(message, detail);
    this.reason = reason;
  }
}

/** A malformed argument reached the gateway. Programmer error, never a chain answer. */
export class InvalidChainArgumentError extends ChainGatewayError {}

/**
 * The signer recovered from a submitted payload is the RELAYER. Refused before
 * it can reach the chain.
 */
export class RelayerMayNotAuthorizeError extends ChainGatewayError {}

// ── Validators ───────────────────────────────────────────────────────────────

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/;

export function asAddress(value: unknown, what: string): Address {
  if (typeof value !== "string" || !ADDRESS_RE.test(value)) {
    throw new InvalidChainArgumentError(`${what} must be a 0x-prefixed 20-byte address`, { what, value });
  }
  return value.toLowerCase();
}

export function asBytes32(value: unknown, what: string): Bytes32 {
  if (typeof value !== "string" || !BYTES32_RE.test(value)) {
    throw new InvalidChainArgumentError(`${what} must be 0x-prefixed 32 bytes`, { what, value });
  }
  return value.toLowerCase();
}

/**
 * A 65-byte signature. Length and alphabet only — validity is decided by
 * `ecrecover`, on-chain and (as a pre-flight) locally in the real gateway. This
 * check exists so an obviously-wrong payload dies before it costs gas.
 */
export function asSignature65(value: unknown, what: string): Signature65 {
  if (typeof value !== "string" || !SIGNATURE_RE.test(value)) {
    throw new InvalidChainArgumentError(`${what} must be a 0x-prefixed 65-byte signature`, { what });
  }
  return value.toLowerCase();
}

/** A non-negative integer as `bigint`, from `number | bigint | string`. */
export function asUint(value: unknown, what: string): bigint {
  let out: bigint;
  try {
    out = typeof value === "bigint" ? value : BigInt(value as number | string);
  } catch {
    throw new InvalidChainArgumentError(`${what} must be an integer`, { what, value: String(value) });
  }
  if (out < 0n) throw new InvalidChainArgumentError(`${what} must not be negative`, { what, value: out.toString() });
  return out;
}

// ── did:ethr grammar ─────────────────────────────────────────────────────────

/**
 * `did:ethr:[<network>:]<address>`.
 */
const DID_ETHR_RE = /^did:ethr:(?:([^:\s]+):)?(0x[0-9a-fA-F]{40})$/;

export interface ParsedDidEthr {
  /** The network segment as written, or `null` when omitted (= mainnet, per the method spec). */
  network: string | null;
  address: Address;
}

export function parseDidEthr(did: unknown): ParsedDidEthr | null {
  if (typeof did !== "string") return null;
  const m = DID_ETHR_RE.exec(did.trim());
  if (!m) return null;
  return { network: m[1] ?? null, address: m[2]!.toLowerCase() };
}

/**
 * The canonical form this platform MINTS: `did:ethr:0x<chainIdHex>:0x<address>`.
 */
export function formatDidEthr(address: Address, chainId: number): string {
  return `did:ethr:0x${chainId.toString(16)}:${asAddress(address, "address")}`;
}

/**
 * Does a DID's network segment name the chain this stack is configured for?
 */
export function networkMatchesChain(network: string | null, chainId: number, chainName: string): boolean {
  // Omitted network segment means mainnet in the did:ethr method spec. It is
  // NOT a wildcard, and treating it as one would resolve a mainnet DID against
  // an Amoy registry — a different key, silently.
  if (network === null) return chainId === 1;
  const n = network.trim().toLowerCase();
  if (n === chainName.trim().toLowerCase()) return true;
  if (n === String(chainId)) return true;
  if (/^0x[0-9a-f]+$/.test(n)) {
    try {
      return BigInt(n) === BigInt(chainId);
    } catch {
      return false;
    }
  }
  return false;
}

// ── DID documents ────────────────────────────────────────────────────────────

export interface DidVerificationMethod {
  id: string;
  /** The suite `blockchainAccountId` keys use — ES256K-R verification by address recovery. */
  type: "EcdsaSecp256k1RecoveryMethod2020";
  controller: string;
  /** CAIP-10: `eip155:<chainId>:<address>`. */
  blockchainAccountId: string;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: DidVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

const DID_CONTEXT = "https://www.w3.org/ns/did/v1";
const SECP256K1_RECOVERY_CONTEXT = "https://w3id.org/security/suites/secp256k1recovery-2020/v2";

/**
 * Shape an ERC-1056 identity into a DID document.
 */
export function buildDidDocument(args: { did: string; owner: Address; chainId: number }): DidDocument {
  const { did, chainId } = args;
  const owner = asAddress(args.owner, "owner");
  const base: DidDocument = {
    "@context": [DID_CONTEXT, SECP256K1_RECOVERY_CONTEXT],
    id: did,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
  };
  if (owner === ZERO_ADDRESS) return base;

  const vmId = `${did}#controller`;
  base.verificationMethod = [
    {
      id: vmId,
      type: "EcdsaSecp256k1RecoveryMethod2020",
      controller: did,
      blockchainAccountId: `eip155:${chainId}:${owner}`,
    },
  ];
  base.authentication = [vmId];
  base.assertionMethod = [vmId];
  return base;
}

// ── Anchors ──────────────────────────────────────────────────────────────────

/**
 * One `Anchored(productId, merkleRoot, version, by)` log entry.
 */
export interface AnchorRecord {
  productId: ProductId;
  merkleRoot: Bytes32;
  version: bigint;
  /** The RECOVERED signer the contract emitted — the controller, never the relayer. */
  by: Address;
  txHash: string;
  blockNumber: number;
  logIndex: number;
  /**
   * How many `Anchored` logs matched this `(productId, version)` pair. Normally
   * 1. The contract deliberately enforces no monotonicity on `version`
   * (anchors are logs, not storage), so a controller CAN anchor the same version
   * twice; the record returned is the latest by (block, logIndex) and this field
   * is how a caller notices the ambiguity instead of inheriting it.
   */
  occurrences: number;
}

/**
 * Newest-by-(block, logIndex) of a set of matching anchors, with `occurrences`
 * filled in. Shared by both gateways so "which anchor counts" cannot drift
 * between the fake and the real one.
 */
export function latestAnchor(matches: readonly AnchorRecord[]): AnchorRecord | null {
  let best: AnchorRecord | null = null;
  for (const record of matches) {
    if (
      !best ||
      record.blockNumber > best.blockNumber ||
      (record.blockNumber === best.blockNumber && record.logIndex > best.logIndex)
    ) {
      best = record;
    }
  }
  return best ? { ...best, occurrences: matches.length } : null;
}

/**
 * ── The result of SEARCHING for an anchor, which is not the same thing as an
 * An anchor lives in an event LOG, and reading logs on a public endpoint is a
 * bounded, best-effort operation: every provider caps `eth_getLogs` (Alchemy's
 * Amoy free tier at TEN blocks, publicnode and dRPC at 10 000), so a search that
 * has to sweep a chain's history can run out of budget before it runs out of
 * blocks. A bare `AnchorRecord | null` cannot express that:
 */
export interface AnchorLookup {
  /** The newest matching `Anchored` log SEEN, or null if none was seen. */
  anchor: AnchorRecord | null;
  /**
   * Did the search cover the entire range it set out to cover?
   *
   * `complete: false` with `anchor: null` is INCONCLUSIVE — the blocks in
   * `scannedFrom..scannedTo` contained no anchor, and the rest was never read.
   */
  complete: boolean;
  /** First block actually read (inclusive). Scans run backwards, so this moves down. */
  scannedFrom: number;
  /** Last block actually read (inclusive) — the chain head at the time of the search. */
  scannedTo: number;
  /** RPC round trips spent. Bounded by the gateway's per-search budget. */
  requests: number;
  /** The `eth_getLogs` window the search ended on, in blocks. */
  window: number;
  /** True when an endpoint refused a range and the window had to shrink. */
  capped: boolean;
  /**
   * How the answer was obtained. `receipt` is the one-request fast path taken
   * when the caller supplied a transaction HINT; `log-scan` is the sweep that
   * needs no hint and is what an independent verifier does.
   */
  via: "receipt" | "log-scan";
}

/** Anchored, provably not anchored, or not established. Never two of these. */
export type AnchorPresence = "anchored" | "absent" | "inconclusive";

export function anchorPresence(lookup: AnchorLookup): AnchorPresence {
  if (lookup.anchor) return "anchored";
  // Absence is a CLAIM, and it may only be made about blocks that were read.
  return lookup.complete ? "absent" : "inconclusive";
}

/**
 * Where to look first — a HINT, never evidence.
 */
export interface AnchorHint {
  txHash?: string | null;
}

// ── Pre-signed calls ─────────────────────────────────────────────────────────

/**
 * A transaction some ACTOR has already authorized, for the relayer to forward.
 */
export type SignedCall =
  | {
      kind: "claimProduct";
      productId: ProductId;
      controller: Address;
      nonce: bigint;
      signature: Signature65;
    }
  | {
      kind: "setIssuer";
      productId: ProductId;
      issuer: Address;
      allowed: boolean;
      nonce: bigint;
      signature: Signature65;
    }
  | {
      /**
       * The BATCH grant/revoke. A distinct kind rather than `setIssuer` with an array,
       * because it is a distinct EIP-712 type on chain (`SetIssuers`, with `address[]
       * issuers`) — the type string is inside the struct hash, so a signature for one
       * can never be replayed as the other.
       */
      kind: "setIssuers";
      productId: ProductId;
      issuers: readonly Address[];
      allowed: boolean;
      nonce: bigint;
      signature: Signature65;
    }
  | {
      kind: "anchor";
      productId: ProductId;
      merkleRoot: Bytes32;
      version: bigint;
      nonce: bigint;
      signature: Signature65;
    };

export type SignedCallKind = SignedCall["kind"];

/** Validate and normalise a call. Both gateways run THIS, so both reject the same bytes. */
export function normalizeSignedCall(call: SignedCall): SignedCall {
  const nonce = asUint(call.nonce, "nonce");
  const signature = asSignature65(call.signature, "signature");
  switch (call.kind) {
    case "claimProduct": {
      const productId = asBytes32(call.productId, "productId");
      const controller = asAddress(call.controller, "controller");
      // Mirrors the contract's own guards, so the fake reverts where the chain
      // would and the real gateway never pays gas to be told the same thing.
      if (productId === ZERO_BYTES32) throw new ChainCallRevertedError("ZeroProductId", "ZeroProductId");
      if (controller === ZERO_ADDRESS) throw new ChainCallRevertedError("ZeroController", "ZeroController");
      return { kind: "claimProduct", productId, controller, nonce, signature };
    }
    case "setIssuer": {
      const productId = asBytes32(call.productId, "productId");
      const issuer = asAddress(call.issuer, "issuer");
      if (issuer === ZERO_ADDRESS) throw new ChainCallRevertedError("ZeroIssuer", "ZeroIssuer");
      return { kind: "setIssuer", productId, issuer, allowed: call.allowed === true, nonce, signature };
    }
    case "setIssuers": {
      const productId = asBytes32(call.productId, "productId");
      // Same guards the contract applies, in the same order, so the fake gateway
      // reverts where the chain would and the real one never pays gas to be told.
      if (!Array.isArray(call.issuers) || call.issuers.length === 0) {
        throw new ChainCallRevertedError("EmptyIssuerSet", "EmptyIssuerSet");
      }
      const issuers = call.issuers.map((a, i) => {
        const issuer = asAddress(a, `issuers[${i}]`);
        if (issuer === ZERO_ADDRESS) throw new ChainCallRevertedError("ZeroIssuer", "ZeroIssuer");
        return issuer;
      });
      // NOT de-duplicated and NOT sorted. The array is inside the signed digest,
      // so any reordering here would produce a payload the signature no longer
      // covers — a "helpful" normalisation that guarantees a revert.
      return { kind: "setIssuers", productId, issuers, allowed: call.allowed === true, nonce, signature };
    }
    case "anchor": {
      const productId = asBytes32(call.productId, "productId");
      const merkleRoot = asBytes32(call.merkleRoot, "merkleRoot");
      const version = asUint(call.version, "version");
      if (merkleRoot === ZERO_BYTES32) throw new ChainCallRevertedError("ZeroMerkleRoot", "ZeroMerkleRoot");
      if (version > 0xffff_ffff_ffff_ffffn) {
        throw new InvalidChainArgumentError("version must fit in uint64", { version: version.toString() });
      }
      return { kind: "anchor", productId, merkleRoot, version, nonce, signature };
    }
  }
}

/** Log-safe summary — never the signature, never a URL, never a key. */
export function signedCallSummary(call: SignedCall): Record<string, unknown> {
  switch (call.kind) {
    case "claimProduct":
      return { kind: call.kind, productId: call.productId, controller: call.controller, nonce: call.nonce.toString() };
    case "setIssuer":
      return { kind: call.kind, productId: call.productId, issuer: call.issuer, allowed: call.allowed, nonce: call.nonce.toString() };
    case "setIssuers":
      return { kind: call.kind, productId: call.productId, issuers: call.issuers, allowed: call.allowed, nonce: call.nonce.toString() };
    case "anchor":
      return { kind: call.kind, productId: call.productId, version: call.version.toString(), nonce: call.nonce.toString() };
  }
}

// ── EIP-712 typed data (the contract's own definitions) ──────────────────────

/**
 * Domain name/version are `constructor() EIP712("TrustAnchorRegistry", "1")` in
 * TrustAnchorRegistry.sol, and are repeated in
 * `contracts/deployments/<network>.json` as `eip712Name` / `eip712Version` so a
 * config check can fail fast without an RPC round trip.
 */
export const EIP712_DOMAIN_NAME = "TrustAnchorRegistry";
export const EIP712_DOMAIN_VERSION = "1";

/**
 * The three typed-data structs, byte-for-byte as the contract's TYPEHASH
 * constants declare them. Field ORDER is part of the hash — reordering anything
 * here silently produces signatures the contract rejects.
 */
export const EIP712_TYPES: Record<SignedCallKind, { name: string; type: string }[]> = {
  claimProduct: [
    { name: "productId", type: "bytes32" },
    { name: "controller", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
  setIssuer: [
    { name: "productId", type: "bytes32" },
    { name: "issuer", type: "address" },
    { name: "allowed", type: "bool" },
    { name: "nonce", type: "uint256" },
  ],
  // `address[]`, and ethers hashes it per EIP-712: the concatenation of each
  // element's 32-byte encoding, hashed. The contract widens each address to a
  // word before packing for exactly this reason — `hashSetIssuers` exists so the
  // agreement can be checked rather than assumed.
  setIssuers: [
    { name: "productId", type: "bytes32" },
    { name: "issuers", type: "address[]" },
    { name: "allowed", type: "bool" },
    { name: "nonce", type: "uint256" },
  ],
  anchor: [
    { name: "productId", type: "bytes32" },
    { name: "merkleRoot", type: "bytes32" },
    { name: "version", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};

/** The struct name inside the typed data — `SetIssuer`, not `setIssuer`. */
export const EIP712_PRIMARY_TYPE: Record<SignedCallKind, string> = {
  claimProduct: "ClaimProduct",
  setIssuer: "SetIssuer",
  setIssuers: "SetIssuers",
  anchor: "Anchor",
};

/** The signed struct's field values, in the order `EIP712_TYPES` declares them. */
export function eip712Message(call: SignedCall): Record<string, unknown> {
  switch (call.kind) {
    case "claimProduct":
      return { productId: call.productId, controller: call.controller, nonce: call.nonce };
    case "setIssuer":
      return { productId: call.productId, issuer: call.issuer, allowed: call.allowed, nonce: call.nonce };
    case "setIssuers":
      // A mutable copy: ethers reads the array, and handing it the frozen
      // `readonly` one the call carries is a type lie waiting to be a bug.
      return { productId: call.productId, issuers: [...call.issuers], allowed: call.allowed, nonce: call.nonce };
    case "anchor":
      return { productId: call.productId, merkleRoot: call.merkleRoot, version: call.version, nonce: call.nonce };
  }
}

// ── Transactions ─────────────────────────────────────────────────────────────

/**
 * `unknown` is a fourth state on purpose, against the three-state sketch.
 */
export type TxState = "pending" | "confirmed" | "failed" | "unknown";

export interface TxStatus {
  status: TxState;
  blockNumber?: number;
}
