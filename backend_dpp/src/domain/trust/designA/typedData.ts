import {
  bytesToHex,
  hexToBytes,
  isZeroBytes32,
  keccak256Concat,
  keccak256Utf8,
  toAddress,
  toBytes32,
  ZERO_BYTES32,
  type Address,
  type Bytes32,
} from "../../integrity/keccak.js";

/**
 * ─── EIP-712 payloads for `TrustAnchorRegistry` ───────────────────────────────
 * The three payloads the registry authorizes on, built and validated here and
 * signed NOWHERE here.
 */

/* ────────────────────────────────────────────────────────────────────────────
 *  Domain
 * ──────────────────────────────────────────────────────────────────────────── */

/** The EIP-712 domain, exactly the four members `TrustAnchorRegistry` uses. */
export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

/** What `constructor() EIP712("TrustAnchorRegistry", "1")` fixes forever. Used
 *  only to CHECK a domain read off-chain — never to construct one. */
export const REGISTRY_DOMAIN_NAME = "TrustAnchorRegistry";
export const REGISTRY_DOMAIN_VERSION = "1";

/** `bytes4(keccak256("eip712Domain()"))` — ERC-5267. Computed, not transcribed. */
export const EIP712_DOMAIN_SELECTOR: `0x${string}` = keccak256Utf8("eip712Domain()").slice(0, 10) as `0x${string}`;

/**
 * ERC-5267 `fields` bitmap for a domain using exactly
 * `(name, version, chainId, verifyingContract)` — bits 0-3, no `salt`, no
 * extensions. Asserted rather than ignored: a domain that grew a `salt` would
 * have a different `EIP712Domain` type string and therefore a different
 * separator, and every signature this module built would be silently unverifiable.
 */
export const EXPECTED_DOMAIN_FIELDS = 0x0f;

const EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/** Decode the return data of `eip712Domain()` — pure hex arithmetic, no ABI
 *  library. Rejects anything that is not the 4-member domain shape. */
export function decodeEip712Domain(returnData: string): Eip712Domain & { fields: number } {
  const data = hexToBytes(returnData, { label: "eip712Domain() return data" });
  // 7 head words: fields, offset(name), offset(version), chainId,
  // verifyingContract, salt, offset(extensions).
  if (data.length < 7 * 32) {
    throw new RangeError(`eip712Domain(): return data too short (${data.length} bytes, need ≥ 224)`);
  }
  const word = (i: number): Uint8Array => data.subarray(i * 32, i * 32 + 32);
  const uint = (i: number): bigint => BigInt(bytesToHex(word(i)));

  const fields = Number(uint(0) >> 248n); // bytes1 is LEFT-aligned in its word
  const chainId = uint(3);
  const verifyingContract = toAddress(bytesToHex(word(4).subarray(12)), "verifyingContract");
  const salt = bytesToHex(word(5));

  const str = (offsetWord: number): string => {
    const at = Number(uint(offsetWord));
    if (at + 32 > data.length) throw new RangeError("eip712Domain(): string offset out of bounds");
    const len = Number(BigInt(bytesToHex(data.subarray(at, at + 32))));
    if (at + 32 + len > data.length) throw new RangeError("eip712Domain(): string length out of bounds");
    return new TextDecoder().decode(data.subarray(at + 32, at + 32 + len));
  };

  if (salt !== ZERO_BYTES32) throw new Error("eip712Domain(): a non-zero salt is not part of this domain");
  if (chainId > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("eip712Domain(): chainId exceeds Number range");

  return { fields, name: str(1), version: str(2), chainId: Number(chainId), verifyingContract };
}

/**
 * Refuse a domain that is not this registry's.
 *
 * The name/version check is what turns "read the domain off-chain" from a
 * convenience into a safety property: reading blindly would let a wrong (or
 * hostile) contract address dictate the bytes an actor is asked to sign.
 */
export function assertRegistryDomain(
  domain: Eip712Domain & { fields?: number },
  expected?: { chainId?: number; verifyingContract?: string },
): asserts domain is Eip712Domain {
  if (domain.fields !== undefined && domain.fields !== EXPECTED_DOMAIN_FIELDS) {
    throw new Error(
      `EIP-712 domain: unexpected ERC-5267 fields 0x${domain.fields.toString(16)} ` +
        `(expected 0x${EXPECTED_DOMAIN_FIELDS.toString(16)} — name, version, chainId, verifyingContract)`,
    );
  }
  if (domain.name !== REGISTRY_DOMAIN_NAME || domain.version !== REGISTRY_DOMAIN_VERSION) {
    throw new Error(
      `EIP-712 domain: this is not a TrustAnchorRegistry ` +
        `(name "${domain.name}", version "${domain.version}")`,
    );
  }
  if (!Number.isInteger(domain.chainId) || domain.chainId <= 0) {
    throw new RangeError(`EIP-712 domain: invalid chainId ${domain.chainId}`);
  }
  toAddress(domain.verifyingContract, "EIP-712 domain: verifyingContract");
  if (expected?.chainId !== undefined && expected.chainId !== domain.chainId) {
    throw new Error(`EIP-712 domain: chainId ${domain.chainId} is not the configured ${expected.chainId}`);
  }
  if (
    expected?.verifyingContract !== undefined &&
    toAddress(expected.verifyingContract) !== toAddress(domain.verifyingContract)
  ) {
    throw new Error(
      `EIP-712 domain: verifyingContract ${domain.verifyingContract} is not the configured ` +
        `${expected.verifyingContract}`,
    );
  }
}

/** `keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256(name), keccak256(version), chainId, verifyingContract))`
 *  — OpenZeppelin's `_domainSeparatorV4()`, off-chain. */
export function domainSeparator(domain: Eip712Domain): Bytes32 {
  return keccak256Concat(
    b32(keccak256Utf8(EIP712_DOMAIN_TYPE)),
    b32(keccak256Utf8(domain.name)),
    b32(keccak256Utf8(domain.version)),
    uintWord(BigInt(domain.chainId)),
    addressWord(domain.verifyingContract),
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 *  The three payload types
 * ──────────────────────────────────────────────────────────────────────────── */

/** One member of an EIP-712 struct, as a wallet's `types` table spells it. */
export interface TypedDataField {
  name: string;
  type: string;
}

/** The ABI types these three structs are made of — the exhaustive set
 *  {@link hashStruct} knows how to encode. */
type RegistryFieldType = "bytes32" | "address" | "uint256" | "uint64" | "bool" | "address[]";

/**
 * The single source of truth for each struct: this table drives the wallet's
 * `types` (what the user is shown), the `encodeType` string, the type hash AND
 * the member encoding. They cannot drift apart, because there is only one of
 * them.
 */
export const REGISTRY_TYPES = {
  ClaimProduct: [
    { name: "productId", type: "bytes32" },
    { name: "controller", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
  SetIssuer: [
    { name: "productId", type: "bytes32" },
    { name: "issuer", type: "address" },
    { name: "allowed", type: "bool" },
    { name: "nonce", type: "uint256" },
  ],
  SetIssuers: [
    { name: "productId", type: "bytes32" },
    { name: "issuers", type: "address[]" },
    { name: "allowed", type: "bool" },
    { name: "nonce", type: "uint256" },
  ],
  Anchor: [
    { name: "productId", type: "bytes32" },
    { name: "merkleRoot", type: "bytes32" },
    { name: "version", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
} as const satisfies Record<string, readonly { name: string; type: RegistryFieldType }[]>;

export type RegistryPrimaryType = keyof typeof REGISTRY_TYPES;

/** `ClaimProduct(bytes32 productId,address controller,uint256 nonce)` — EIP-712
 *  `encodeType`. No referenced structs here, so no recursion is needed. */
export function encodeType(primaryType: RegistryPrimaryType): string {
  const members = REGISTRY_TYPES[primaryType].map((f) => `${f.type} ${f.name}`).join(",");
  return `${primaryType}(${members})`;
}

/** `keccak256(encodeType(primaryType))`. Cross-checked against the contract's
 *  public `*_TYPEHASH` constants by the on-chain verification run. */
export function typeHash(primaryType: RegistryPrimaryType): Bytes32 {
  return keccak256Utf8(encodeType(primaryType));
}

/**
 * Message values, as a wallet receives them.
 *
 * `uint256`/`uint64` are DECIMAL STRINGS, not JS numbers: a nonce is a `uint256`
 * and `Number` silently loses precision past 2^53. Every wallet accepts the
 * string form for integer types; not every value survives the number form.
 */
export interface ClaimProductMessage {
  productId: Bytes32;
  controller: Address;
  nonce: string;
}
export interface SetIssuerMessage {
  productId: Bytes32;
  issuer: Address;
  allowed: boolean;
  nonce: string;
}
export interface SetIssuersMessage {
  productId: Bytes32;
  /** ORDER IS PART OF THE DIGEST. EIP-712 hashes an array as the concatenation
   *  of its elements' encodings, so sorting or de-duplicating this list after it
   *  was signed produces a payload the signature does not cover. */
  issuers: Address[];
  allowed: boolean;
  nonce: string;
}
export interface AnchorMessage {
  productId: Bytes32;
  merkleRoot: Bytes32;
  version: string;
  nonce: string;
}

export interface RegistryMessages {
  ClaimProduct: ClaimProductMessage;
  SetIssuer: SetIssuerMessage;
  SetIssuers: SetIssuersMessage;
  Anchor: AnchorMessage;
}

/** Exactly the object `eth_signTypedData_v4` / `signer.signTypedData` takes. */
export interface TypedDataPayload<P extends RegistryPrimaryType = RegistryPrimaryType> {
  domain: Eip712Domain;
  types: Record<string, readonly TypedDataField[]>;
  primaryType: P;
  message: RegistryMessages[P];
}

const EIP712_DOMAIN_FIELDS: readonly TypedDataField[] = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
];

function payload<P extends RegistryPrimaryType>(
  domain: Eip712Domain,
  primaryType: P,
  message: RegistryMessages[P],
): TypedDataPayload<P> {
  assertRegistryDomain(domain);
  return {
    domain,
    // `EIP712Domain` is included because `eth_signTypedData_v4` requires it in
    // `types`; ethers' `signTypedData` ignores/strips it. Shipping it suits both.
    types: { EIP712Domain: EIP712_DOMAIN_FIELDS, [primaryType]: REGISTRY_TYPES[primaryType] },
    primaryType,
    message,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Builders — one per state transition
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * `claimProduct` — claim an unclaimed product, or transfer a claimed one.
 */
export function buildClaimProduct(
  domain: Eip712Domain,
  args: { productId: string; controller: string; nonce: bigint | number | string },
): TypedDataPayload<"ClaimProduct"> {
  const productId = requireNonZeroBytes32(args.productId, "productId");
  const controller = requireNonZeroAddress(args.controller, "controller");
  return payload(domain, "ClaimProduct", { productId, controller, nonce: uint(args.nonce, 256, "nonce") });
}

/** `setIssuer` — grant or revoke an issuer's authority over one product. Only
 *  the product's current controller may sign it. */
export function buildSetIssuer(
  domain: Eip712Domain,
  args: { productId: string; issuer: string; allowed: boolean; nonce: bigint | number | string },
): TypedDataPayload<"SetIssuer"> {
  const productId = requireNonZeroBytes32(args.productId, "productId");
  const issuer = requireNonZeroAddress(args.issuer, "issuer");
  if (typeof args.allowed !== "boolean") throw new TypeError("allowed: expected a boolean");
  return payload(domain, "SetIssuer", {
    productId,
    issuer,
    allowed: args.allowed,
    nonce: uint(args.nonce, 256, "nonce"),
  });
}

/**
 * `setIssuers` — grant or revoke SEVERAL issuers over one product, in one
 * transaction and against ONE nonce. Same authority rule as {@link
 * buildSetIssuer}.
 */
export function buildSetIssuers(
  domain: Eip712Domain,
  args: { productId: string; issuers: readonly string[]; allowed: boolean; nonce: bigint | number | string },
): TypedDataPayload<"SetIssuers"> {
  const productId = requireNonZeroBytes32(args.productId, "productId");
  if (!Array.isArray(args.issuers) || args.issuers.length === 0) {
    throw new TypeError("issuers: expected at least one address — the contract reverts EmptyIssuerSet");
  }
  const issuers = args.issuers.map((a, i) => requireNonZeroAddress(a, `issuers[${i}]`));
  if (typeof args.allowed !== "boolean") throw new TypeError("allowed: expected a boolean");
  return payload(domain, "SetIssuers", {
    productId,
    issuers,
    allowed: args.allowed,
    nonce: uint(args.nonce, 256, "nonce"),
  });
}

/** `anchor` — publish a passport version's Merkle root to the log. `merkleRoot`
 *  is what {@link ../../integrity/merkle.versionMerkleRoot} returned. */
export function buildAnchor(
  domain: Eip712Domain,
  args: {
    productId: string;
    merkleRoot: string;
    version: bigint | number | string;
    nonce: bigint | number | string;
  },
): TypedDataPayload<"Anchor"> {
  const productId = requireNonZeroBytes32(args.productId, "productId");
  const merkleRoot = requireNonZeroBytes32(args.merkleRoot, "merkleRoot");
  return payload(domain, "Anchor", {
    productId,
    merkleRoot,
    version: uint(args.version, 64, "version"),
    nonce: uint(args.nonce, 256, "nonce"),
  });
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Hashing — what the wallet actually signs
 * ──────────────────────────────────────────────────────────────────────────── */

/** `keccak256(typeHash ‖ encoded members)` — EIP-712 `hashStruct`. */
export function hashStruct<P extends RegistryPrimaryType>(primaryType: P, message: RegistryMessages[P]): Bytes32 {
  const words = REGISTRY_TYPES[primaryType].map((field) => {
    const value = (message as unknown as Record<string, unknown>)[field.name];
    if (value === undefined) throw new TypeError(`${primaryType}.${field.name}: missing`);
    switch (field.type) {
      case "bytes32":
        return b32(toBytes32(String(value), `${primaryType}.${field.name}`));
      case "address":
        return addressWord(String(value));
      // EIP-712 "Definition of encodeData": a dynamic array encodes to the
      // keccak256 of its elements' concatenated encodings — so the array
      // occupies ONE word in the parent struct, and that word is a hash.
      case "address[]": {
        if (!Array.isArray(value)) throw new TypeError(`${primaryType}.${field.name}: expected an array`);
        if (value.length === 0) throw new TypeError(`${primaryType}.${field.name}: must not be empty`);
        return b32(keccak256Concat(...value.map((a) => addressWord(String(a)))));
      }
      case "bool":
        if (typeof value !== "boolean") throw new TypeError(`${primaryType}.${field.name}: expected a boolean`);
        return uintWord(value ? 1n : 0n);
      case "uint64":
      case "uint256":
        return uintWord(BigInt(uint(value as string, field.type === "uint64" ? 64 : 256, field.name)));
    }
  });
  return keccak256Concat(b32(typeHash(primaryType)), ...words);
}

/**
 * The 32-byte digest an actor's key signs: `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`.
 *
 * Identical by construction to the contract's `hashClaimProduct` /
 * `hashSetIssuer` / `hashAnchor` views, which exist so this equality can be
 * asserted against a live deployment rather than assumed.
 */
export function hashTypedData<P extends RegistryPrimaryType>(p: TypedDataPayload<P>): Bytes32 {
  return keccak256Concat(
    Uint8Array.of(0x19, 0x01),
    b32(domainSeparator(p.domain)),
    b32(hashStruct(p.primaryType, p.message)),
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 *  productId
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * `productId = keccak256(productDid)` — the on-chain product key.
 */
export function productIdFromDid(productDid: string): Bytes32 {
  if (typeof productDid !== "string" || productDid.trim() === "") {
    throw new TypeError("productIdFromDid: empty product DID");
  }
  if (!productDid.startsWith("did:")) {
    throw new TypeError(`productIdFromDid: not a DID ("${productDid}")`);
  }
  return keccak256Utf8(productDid);
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Encoding helpers
 * ──────────────────────────────────────────────────────────────────────────── */

const b32 = (hex: Bytes32): Uint8Array => hexToBytes(hex, { bytes: 32 });

/** ABI word for a `uintN`: big-endian, left-padded to 32 bytes. */
function uintWord(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** ABI word for an `address`: 12 zero bytes then the 20 address bytes. */
function addressWord(value: string): Uint8Array {
  const out = new Uint8Array(32);
  out.set(hexToBytes(toAddress(value), { bytes: 20 }), 12);
  return out;
}

/** Normalize an unsigned integer to its decimal string, bounded to `bits`.
 *  Rejects negatives, non-integers and overflow — each of which the contract
 *  would either revert on or silently wrap. */
function uint(value: bigint | number | string, bits: 64 | 256, label: string): string {
  let v: bigint;
  if (typeof value === "bigint") v = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError(`${label}: ${value} is not a safe integer — pass a bigint`);
    v = BigInt(value);
  } else if (typeof value === "string" && /^\d+$/.test(value.trim())) v = BigInt(value.trim());
  else throw new TypeError(`${label}: expected a non-negative integer, got ${JSON.stringify(value)}`);

  if (v < 0n) throw new RangeError(`${label}: must be non-negative`);
  if (v >= 1n << BigInt(bits)) throw new RangeError(`${label}: exceeds uint${bits}`);
  return v.toString(10);
}

function requireNonZeroBytes32(value: string, label: string): Bytes32 {
  const b = toBytes32(value, label);
  // Mirrors `ZeroProductId` / `ZeroMerkleRoot`: an all-zero word is always an
  // uninitialised value off-chain, never a real digest. Caught here so the
  // failure names the field, instead of surfacing as a reverted relayer tx.
  if (isZeroBytes32(b)) throw new RangeError(`${label}: must not be the zero word`);
  return b;
}

function requireNonZeroAddress(value: string, label: string): Address {
  const a = toAddress(value, label);
  // Mirrors `ZeroController` / `ZeroIssuer`.
  if (a === `0x${"0".repeat(40)}`) throw new RangeError(`${label}: must not be the zero address`);
  return a;
}
