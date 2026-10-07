import { secp256k1 } from "@noble/curves/secp256k1";
import { config } from "../../../config.js";
import {
  hexToBytes,
  isZeroBytes32,
  keccak256,
  keccak256Concat,
  keccak256Utf8,
  toBytes32,
  type Bytes32,
} from "../../integrity/keccak.js";
import { asAddress, ZERO_ADDRESS, type Address } from "./chainTypes.js";
import { didMatchesAddress, type ChainBinding } from "./didEthr.js";
import type { VerificationCheck } from "./jose.js";
import type { TypedDataField } from "./typedData.js";

/**
 * ─── Off-chain EIP-712 decision attestations ──────────────────────────────────
 * Two workflow decisions an ACTOR signs in their own browser, with a key this
 * platform does not hold. Neither reaches a contract; neither costs gas.
 */

/* ────────────────────────────────────────────────────────────────────────────
 *  Domain
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * The EIP-712 domain for off-chain decisions. **Three members, and the absence
 * of the fourth is the point** — see the header.
 */
export interface DecisionDomain {
  name: string;
  version: string;
  chainId: number;
}

/** Frozen. Changing either value invalidates every stored decision signature,
 *  so they are constants and not configuration. */
export const DECISION_DOMAIN_NAME = "TrustDPP Decision";
export const DECISION_DOMAIN_VERSION = "1";

/**
 * ERC-5267 `fields` bitmap for `(name, version, chainId)` — bits 0-2.
 */
export const DECISION_DOMAIN_FIELDS = 0x07;

/**
 * The `EIP712Domain` type string for a domain WITHOUT `verifyingContract`.
 */
const DECISION_EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId)";

/**
 * The decision domain for THIS deployment.
 */
export function decisionDomain(): DecisionDomain {
  const a = config.designA;
  if (!a) {
    throw new Error("decisionDomain: Design A config is absent — this code is unreachable under Design B.");
  }
  return { name: DECISION_DOMAIN_NAME, version: DECISION_DOMAIN_VERSION, chainId: a.chainId };
}

/**
 * Refuse a domain that is not this one.
 */
export function assertDecisionDomain(domain: DecisionDomain): asserts domain is DecisionDomain {
  if (domain === null || typeof domain !== "object") {
    throw new TypeError("decision domain: expected an object");
  }
  for (const forbidden of ["verifyingContract", "salt"] as const) {
    if (forbidden in domain) {
      throw new Error(
        `decision domain: carries \`${forbidden}\` — that is a CONTRACT domain. ` +
          "Decision payloads are never submitted on chain and must not be confusable with one; " +
          "build the domain with decisionDomain().",
      );
    }
  }
  if (domain.name !== DECISION_DOMAIN_NAME || domain.version !== DECISION_DOMAIN_VERSION) {
    throw new Error(
      `decision domain: expected ("${DECISION_DOMAIN_NAME}", "${DECISION_DOMAIN_VERSION}"), ` +
        `got ("${domain.name}", "${domain.version}")`,
    );
  }
  if (!Number.isInteger(domain.chainId) || domain.chainId <= 0) {
    throw new RangeError(`decision domain: invalid chainId ${domain.chainId}`);
  }
}

/**
 * `keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(name), keccak256(version), chainId))`.
 *
 * Four 32-byte words, where the registry's `domainSeparator` produces five. That
 * length difference, plus the differing first word, is the whole non-confusability
 * argument reduced to arithmetic.
 */
export function decisionDomainSeparator(domain: DecisionDomain): Bytes32 {
  assertDecisionDomain(domain);
  return keccak256Concat(
    b32(keccak256Utf8(DECISION_EIP712_DOMAIN_TYPE)),
    b32(keccak256Utf8(domain.name)),
    b32(keccak256Utf8(domain.version)),
    uintWord(BigInt(domain.chainId)),
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 *  The two decision types
 * ──────────────────────────────────────────────────────────────────────────── */

/** The ABI types a decision struct is made of. `string` is the addition that
 *  `typedData.hashStruct` does not have and cannot grow without touching the
 *  registry path — a decision is mostly opaque application identifiers, which
 *  have no on-chain meaning and must stay human-readable in the wallet. */
type DecisionFieldType = "string" | "bytes32" | "uint256";

/**
 * The single source of truth for both structs: this table drives the wallet's
 * `types` (what the actor is SHOWN), the `encodeType` string, the type hash and
 * the member encoding — so they cannot drift, because there is only one of them.
 */
export const DECISION_TYPES = {
  Approval: [
    { name: "passportId", type: "string" },
    { name: "nodeId", type: "string" },
    { name: "role", type: "string" },
    { name: "snapshotHash", type: "bytes32" },
    { name: "decision", type: "string" },
    { name: "issuedAt", type: "uint256" },
  ],
  ChainHeadCheckpoint: [
    { name: "orgId", type: "string" },
    { name: "seq", type: "uint256" },
    { name: "headHash", type: "bytes32" },
    { name: "issuedAt", type: "uint256" },
  ],
} as const satisfies Record<string, readonly { name: string; type: DecisionFieldType }[]>;

export type DecisionPrimaryType = keyof typeof DECISION_TYPES;

/**
 * The closed set of approval outcomes.
 */
export const DECISION_OUTCOMES = ["approved", "changes_requested"] as const;
export type DecisionOutcome = (typeof DECISION_OUTCOMES)[number];

/**
 * Message values, as a wallet receives them.
 */
export interface ApprovalMessage {
  passportId: string;
  nodeId: string;
  role: string;
  snapshotHash: Bytes32;
  decision: DecisionOutcome;
  issuedAt: string;
}

export interface ChainHeadCheckpointMessage {
  orgId: string;
  seq: string;
  headHash: Bytes32;
  issuedAt: string;
}

export interface DecisionMessages {
  Approval: ApprovalMessage;
  ChainHeadCheckpoint: ChainHeadCheckpointMessage;
}

/** Exactly the object `eth_signTypedData_v4` / `signer.signTypedData` takes. */
export interface DecisionTypedDataPayload<P extends DecisionPrimaryType = DecisionPrimaryType> {
  domain: DecisionDomain;
  types: Record<string, readonly TypedDataField[]>;
  primaryType: P;
  message: DecisionMessages[P];
}

/**
 * The three-member `EIP712Domain` entry shipped in every payload's `types`.
 */
const DECISION_EIP712_DOMAIN_FIELDS: readonly TypedDataField[] = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
];

function payload<P extends DecisionPrimaryType>(
  domain: DecisionDomain,
  primaryType: P,
  message: DecisionMessages[P],
): DecisionTypedDataPayload<P> {
  assertDecisionDomain(domain);
  return {
    domain,
    types: { EIP712Domain: DECISION_EIP712_DOMAIN_FIELDS, [primaryType]: DECISION_TYPES[primaryType] },
    primaryType,
    message,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Builders
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * The operator's decision on one supplier contribution.
 */
export function buildApproval(
  domain: DecisionDomain,
  args: {
    passportId: string;
    /** `SupplyChainTier.id` — the bound node being reviewed. Never empty: an
     *  unbound node has nothing to review (`reviewTier` refuses it), so an
     *  approval without one would name no counterparty. */
    nodeId: string;
    /** The dpp-core stage this credential covers. One approval per
     *  (node, role) pair, because that is the grain `snapshotHash` has. */
    role: string;
    /** `snapshotHashFor(credential, prepared)` — see above. */
    snapshotHash: string;
    decision: DecisionOutcome;
    /** Unix SECONDS. A `Date` is accepted and floored to the second. */
    issuedAt: Date | bigint | number | string;
  },
): DecisionTypedDataPayload<"Approval"> {
  if (!DECISION_OUTCOMES.includes(args.decision)) {
    // An unrecognised outcome must never reach signed bytes: a verifier that
    // cannot interpret `decision` cannot say whether the passport was approved,
    // and a stored one would be a decision nobody can act on.
    throw new TypeError(
      `decision: expected one of ${DECISION_OUTCOMES.join(" | ")}, got ${JSON.stringify(args.decision)}`,
    );
  }
  return payload(domain, "Approval", {
    passportId: identifier(args.passportId, "passportId"),
    nodeId: identifier(args.nodeId, "nodeId"),
    role: identifier(args.role, "role"),
    snapshotHash: digest(args.snapshotHash, "snapshotHash"),
    decision: args.decision,
    issuedAt: instant(args.issuedAt, "issuedAt"),
  });
}

/**
 * The operator's commitment to their org's audit-chain head.
 */
export function buildChainHeadCheckpoint(
  domain: DecisionDomain,
  args: {
    orgId: string;
    /** The tip's `AuditEvent.seq`. Must be >= 1 — see above. */
    seq: bigint | number | string;
    /** The tip's `AuditEvent.hash` (sha256 hex, with or without `0x`). */
    headHash: string | null;
    issuedAt: Date | bigint | number | string;
  },
): DecisionTypedDataPayload<"ChainHeadCheckpoint"> {
  if (args.headHash === null || args.headHash === undefined || args.headHash === "") {
    throw new TypeError(
      "headHash: this org's audit chain is empty — there is nothing to checkpoint. " +
        "Refused rather than signed as bytes32(0), which is the codebase's uninitialised sentinel " +
        "and would be indistinguishable from a bug.",
    );
  }
  const seq = uint256(args.seq, "seq");
  if (seq === "0") {
    // Enforced together with the headHash guard so the pair can never disagree:
    // seq >= 1 ⟺ a real tip exists. A checkpoint at seq 0 with a non-zero hash
    // (or the reverse) would be internally inconsistent signed bytes.
    throw new RangeError("seq: must be >= 1 — seq 0 means an empty chain, which has no head to commit to");
  }
  return payload(domain, "ChainHeadCheckpoint", {
    orgId: identifier(args.orgId, "orgId"),
    seq,
    headHash: digest(args.headHash, "headHash"),
    issuedAt: instant(args.issuedAt, "issuedAt"),
  });
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Hashing — what the wallet actually signs
 * ──────────────────────────────────────────────────────────────────────────── */

/** `Approval(string passportId,string nodeId,…)` — EIP-712 `encodeType`. No
 *  referenced structs in either type, so no recursive expansion is needed. */
export function encodeDecisionType(primaryType: DecisionPrimaryType): string {
  const members = DECISION_TYPES[primaryType].map((f) => `${f.type} ${f.name}`).join(",");
  return `${primaryType}(${members})`;
}

/** `keccak256(encodeType(primaryType))`. */
export function decisionTypeHash(primaryType: DecisionPrimaryType): Bytes32 {
  return keccak256Utf8(encodeDecisionType(primaryType));
}

/**
 * `keccak256(typeHash ‖ encoded members)` — EIP-712 `hashStruct`.
 */
export function hashDecisionStruct<P extends DecisionPrimaryType>(
  primaryType: P,
  message: DecisionMessages[P],
): Bytes32 {
  const words = DECISION_TYPES[primaryType].map((field) => {
    const value = (message as unknown as Record<string, unknown>)[field.name];
    if (value === undefined || value === null) throw new TypeError(`${primaryType}.${field.name}: missing`);
    switch (field.type) {
      case "string":
        if (typeof value !== "string") throw new TypeError(`${primaryType}.${field.name}: expected a string`);
        return b32(keccak256Utf8(value));
      case "bytes32":
        return b32(toBytes32(String(value), `${primaryType}.${field.name}`));
      case "uint256":
        return uintWord(BigInt(uint256(value as string, `${primaryType}.${field.name}`)));
    }
  });
  return keccak256Concat(b32(decisionTypeHash(primaryType)), ...words);
}

/**
 * The 32-byte digest the actor's key signs: `keccak256(0x19 0x01 ‖
 * domainSeparator ‖ hashStruct)`.
 */
export function hashDecisionTypedData<P extends DecisionPrimaryType>(p: DecisionTypedDataPayload<P>): Bytes32 {
  return keccak256Concat(
    Uint8Array.of(0x19, 0x01),
    b32(decisionDomainSeparator(p.domain)),
    b32(hashDecisionStruct(p.primaryType, p.message)),
  );
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Verification
 * ──────────────────────────────────────────────────────────────────────────── */

/** What a decision verification established. Mirrors the shape `jose.ts`
 *  produces (and reuses its {@link VerificationCheck}), minus the credential
 *  vocabulary — a decision is not a VC and must not be cached as one. */
export interface DecisionVerification {
  /** The AND over every check. */
  verified: boolean;
  primaryType: DecisionPrimaryType;
  /** The digest that was checked — reproducible by anyone with the payload. */
  digest: Bytes32;
  /** Recovered from the signature, lower case. Null if recovery failed. */
  signerAddress: Address | null;
  /** The DID the CALLER claimed signed this. Echoed, never trusted. */
  signerDid: string;
  checks: VerificationCheck[];
  /** The first failure's detail, or null. */
  error: string | null;
}

/**
 * Recover the address behind a 65-byte EIP-712 signature over `digest`.
 */
export function recoverTypedDataSigner(digest: Bytes32, signature: Uint8Array | string): Address {
  const bytes =
    typeof signature === "string"
      ? hexToBytes(signature, { bytes: 65, label: "EIP-712 signature" })
      : signature;
  if (bytes.length !== 65) {
    throw new Error(`EIP-712 signature must be 65 bytes (r‖s‖v), got ${bytes.length}`);
  }
  const v = bytes[64]!;
  const recovery = v === 27 || v === 28 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`EIP-712 signature recovery id must be 0/1 or 27/28, got ${v}`);
  }

  let parsed;
  try {
    parsed = secp256k1.Signature.fromCompact(bytes.slice(0, 64));
  } catch {
    throw new Error("EIP-712 signature (r, s) is not a valid secp256k1 signature");
  }
  if (parsed.hasHighS()) {
    throw new Error("EIP-712 signature has high s — malleable encoding refused (EIP-2)");
  }

  let publicKey: Uint8Array;
  try {
    // The digest is the EIP-712 one — already keccak256'd. Passing it straight
    // to recovery is what makes this the EIP-712 recoverer rather than the JOSE
    // one; there is no second hash here and there must not be.
    publicKey = parsed
      .addRecoveryBit(recovery)
      .recoverPublicKey(hexToBytes(digest, { bytes: 32, label: "digest" }))
      .toRawBytes(false);
  } catch {
    throw new Error("EIP-712 signature does not recover to any public key");
  }
  // toRawBytes(false) → 0x04 ‖ X(32) ‖ Y(32); the address is over X‖Y only.
  const address = `0x${keccak256(publicKey.slice(1)).slice(-40)}`;
  if (address === ZERO_ADDRESS) {
    throw new Error("EIP-712 signature recovers to the zero address");
  }
  return asAddress(address, "recovered address");
}

/**
 * Did `claim.did` sign this decision?
 */
export function verifyDecision<P extends DecisionPrimaryType>(
  payload: DecisionTypedDataPayload<P>,
  signature: Uint8Array | string,
  claim: { did: string; chain: ChainBinding },
): DecisionVerification {
  const digest = hashDecisionTypedData(payload);

  let signerAddress: Address;
  try {
    signerAddress = recoverTypedDataSigner(digest, signature);
  } catch (err) {
    return result(payload.primaryType, digest, null, claim.did, [
      { name: "signature", ok: false, detail: (err as Error).message },
    ]);
  }

  if (!didMatchesAddress(claim.did, signerAddress, claim.chain)) {
    return result(payload.primaryType, digest, signerAddress, claim.did, [
      { name: "signature", ok: true, detail: `recovered ${signerAddress}` },
      {
        name: "signer-binding",
        ok: false,
        // The claimed DID is attacker-controlled in the general case, so it is
        // bounded before it reaches a log line — same rule as `jose.truncate`.
        detail: `signature recovers to ${signerAddress}, which is not ${truncate(claim.did)} on chain ${claim.chain.chainId}`,
      },
    ]);
  }

  return result(payload.primaryType, digest, signerAddress, claim.did, [
    { name: "signature", ok: true, detail: `recovered ${signerAddress}` },
    { name: "signer-binding", ok: true, detail: `${signerAddress} is ${claim.did}` },
  ]);
}

/**
 * Fold one more check into a verification — the composition seam.
 */
export function addDecisionCheck(v: DecisionVerification, check: VerificationCheck): DecisionVerification {
  return result(v.primaryType, v.digest, v.signerAddress, v.signerDid, [...v.checks, { ...check }]);
}

function result(
  primaryType: DecisionPrimaryType,
  digest: Bytes32,
  signerAddress: Address | null,
  signerDid: string,
  checks: VerificationCheck[],
): DecisionVerification {
  const failed = checks.find((c) => !c.ok);
  return {
    verified: checks.length > 0 && !failed,
    primaryType,
    digest,
    signerAddress,
    signerDid,
    checks,
    error: failed ? `${failed.name}: ${failed.detail ?? "failed"}` : null,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Encoding helpers
 * ──────────────────────────────────────────────────────────────────────────── */

const b32 = (hex: Bytes32): Uint8Array => hexToBytes(hex, { bytes: 32 });

/** ABI word for a `uint256`: big-endian, left-padded to 32 bytes. */
function uintWord(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Normalize an unsigned integer to its decimal string, bounded to `uint256`.
 *  Rejects negatives, non-integers and overflow. */
function uint256(value: bigint | number | string, label: string): string {
  let v: bigint;
  if (typeof value === "bigint") v = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError(`${label}: ${value} is not a safe integer — pass a bigint`);
    v = BigInt(value);
  } else if (typeof value === "string" && /^\d+$/.test(value.trim())) v = BigInt(value.trim());
  else throw new TypeError(`${label}: expected a non-negative integer, got ${JSON.stringify(value)}`);

  if (v < 0n) throw new RangeError(`${label}: must be non-negative`);
  if (v >= 1n << 256n) throw new RangeError(`${label}: exceeds uint256`);
  return v.toString(10);
}

/**
 * Unix SECONDS, not milliseconds.
 */
function instant(value: Date | bigint | number | string, label: string): string {
  if (value instanceof Date) {
    const ms = value.getTime();
    if (!Number.isFinite(ms)) throw new TypeError(`${label}: invalid Date`);
    if (ms < 0) throw new RangeError(`${label}: must not predate the Unix epoch`);
    return String(Math.floor(ms / 1000));
  }
  const seconds = uint256(value, label);
  if (seconds === "0") throw new RangeError(`${label}: must be a real instant, not 0`);
  return seconds;
}

/** Upper bound on an identifier's length. These are database ids and dpp-core
 *  stage codes — tens of characters — and the actor has to READ them in a wallet
 *  dialog for the ceremony to mean anything (WYSIWYS). A cap keeps an oversized
 *  value from being scrolled past rather than read. */
const MAX_IDENTIFIER_CHARS = 256;

/**
 * A non-empty application identifier, hashed as the EXACT characters given.
 */
function identifier(value: string, label: string): string {
  if (typeof value !== "string") throw new TypeError(`${label}: expected a string, got ${typeof value}`);
  if (value.length === 0) throw new TypeError(`${label}: must not be empty`);
  if (value !== value.trim()) throw new TypeError(`${label}: has leading or trailing whitespace — pass the exact id`);
  if (value.length > MAX_IDENTIFIER_CHARS) {
    throw new RangeError(`${label}: ${value.length} characters exceeds the ${MAX_IDENTIFIER_CHARS}-character limit`);
  }
  return value;
}

/**
 * A real 32-byte digest. Accepts the bare 64-hex form `canonicalHash` returns as
 * well as `0x`-prefixed, and normalises to one canonical lower-case spelling.
 */
function digest(value: string, label: string): Bytes32 {
  const b = toBytes32(value, label);
  if (isZeroBytes32(b)) throw new RangeError(`${label}: must not be the zero word (an uninitialised value, not a digest)`);
  return b;
}

/** Error messages carry caller-supplied strings (a DID). Bound them so a hostile
 *  value cannot turn a log line into a payload. */
function truncate(value: string, max = 120): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}
