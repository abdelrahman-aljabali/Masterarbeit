import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex as nobleBytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils";

/**
 * ─── keccak256 + bytes32, the EVM's two primitives ────────────────────────────
 * The single place this codebase turns bytes into a `bytes32`. Everything that
 * has to agree with a Solidity `keccak256` — Merkle leaves/nodes, EIP-712 type
 * hashes and struct hashes, `productId = keccak256(productDid)` — comes through
 * here, so there is exactly one implementation to get right and one place a
 * mismatch with the chain could hide.
 */

/** `0x` + 64 LOWERCASE hex chars. The TypeScript mirror of Solidity `bytes32`. */
export type Bytes32 = `0x${string}`;

/** `0x` + 40 lowercase hex chars. Solidity `address`, in its all-lowercase form.
 *  Deliberately not EIP-55 mixed case: ABI encoding ignores case, and carrying a
 *  single canonical spelling means two equal addresses always compare equal. */
export type Address = `0x${string}`;

const HEX_BODY = /^[0-9a-f]*$/;

/** Strip an optional `0x`, lowercase, and reject anything that is not hex. */
function hexBody(value: string, label: string): string {
  const body = (value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value).toLowerCase();
  if (!HEX_BODY.test(body)) throw new TypeError(`${label}: not a hex string ("${value}")`);
  if (body.length % 2 !== 0) throw new TypeError(`${label}: odd number of hex digits ("${value}")`);
  return body;
}

/** Parse hex (with or without `0x`) into bytes, optionally pinning the length. */
export function hexToBytes(value: string, opts: { bytes?: number; label?: string } = {}): Uint8Array {
  const label = opts.label ?? "hex";
  if (typeof value !== "string") throw new TypeError(`${label}: expected a string, got ${typeof value}`);
  const body = hexBody(value, label);
  if (opts.bytes !== undefined && body.length !== opts.bytes * 2) {
    throw new RangeError(`${label}: expected ${opts.bytes} bytes, got ${body.length / 2} ("${value}")`);
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Bytes → `0x…` lowercase hex. */
export function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${nobleBytesToHex(bytes)}`;
}

/**
 * Coerce anything that claims to be a `bytes32` into the ONE canonical spelling
 * (`0x` + 64 lowercase hex). Every comparison in this module — Merkle pair
 * ordering, root equality — is a string comparison over this form, so nothing
 * may reach a comparison without passing through here first.
 */
export function toBytes32(value: string, label = "bytes32"): Bytes32 {
  if (typeof value !== "string") throw new TypeError(`${label}: expected a string, got ${typeof value}`);
  const body = hexBody(value, label);
  if (body.length !== 64) {
    throw new RangeError(`${label}: expected 32 bytes (64 hex digits), got ${body.length / 2} ("${value}")`);
  }
  return `0x${body}` as Bytes32;
}

/** The same coercion for a 20-byte `address`. */
export function toAddress(value: string, label = "address"): Address {
  if (typeof value !== "string") throw new TypeError(`${label}: expected a string, got ${typeof value}`);
  const body = hexBody(value, label);
  if (body.length !== 40) {
    throw new RangeError(`${label}: expected 20 bytes (40 hex digits), got ${body.length / 2} ("${value}")`);
  }
  return `0x${body}` as Address;
}

/** keccak256 over raw bytes. */
export function keccak256(data: Uint8Array): Bytes32 {
  return bytesToHex(keccak_256(data)) as Bytes32;
}

/** keccak256 over the UTF-8 encoding of `text`.
 *
 *  This is the digest of the EXACT characters given — no JSON re-serialization,
 *  no normalization, no trimming. It is what a compact JWS, a DID string or an
 *  EIP-712 type string must be hashed as. */
export function keccak256Utf8(text: string): Bytes32 {
  return keccak256(utf8ToBytes(text));
}

/** keccak256 over the concatenation of the given byte runs — the TypeScript
 *  equivalent of Solidity's `keccak256(abi.encodePacked(a, b, …))`. */
export function keccak256Concat(...parts: Uint8Array[]): Bytes32 {
  return keccak256(concatBytes(...parts));
}

/**
 * Unsigned 256-bit comparison of two canonical `bytes32`, as `<` on `bytes32`
 * means in Solidity.
 */
export function compareBytes32(a: Bytes32, b: Bytes32): -1 | 0 | 1 {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** A 32-byte word of zeroes — the value every guard in `TrustAnchorRegistry`
 *  refuses (`ZeroProductId`, `ZeroMerkleRoot`, …). */
export const ZERO_BYTES32 = `0x${"0".repeat(64)}` as Bytes32;

/** `true` when `value` is the all-zero word. */
export function isZeroBytes32(value: Bytes32): boolean {
  return value === ZERO_BYTES32;
}
