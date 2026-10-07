import type { ChainGateway } from "./chainGateway.js";
import {
  asAddress,
  formatDidEthr,
  InvalidChainArgumentError,
  networkMatchesChain,
  parseDidEthr,
  ZERO_ADDRESS,
  type Address,
  type DidDocument,
  type DidVerificationMethod,
} from "./chainTypes.js";

/**
 * ─── did:ethr — the identity layer, composed (not reimplemented) ──────────────
 * This file is deliberately THIN. `chainTypes.ts` already owns the did:ethr
 * *grammar* (`parseDidEthr`, `formatDidEthr`, `networkMatchesChain`) and the DID
 * *document shape* (`buildDidDocument`), and both gateways call those same
 * functions so real and fake cannot drift.
 */

// ── The chain this stack is bound to ─────────────────────────────────────────

/**
 * The chain a DID is being interpreted against. Both `FakeChainGateway` and
 * `config.designA` structurally satisfy this (`chainId` + `chainName` public
 * readonly fields), so tests and production pass the object they already have
 * rather than re-typing two numbers that must not disagree.
 */
export interface ChainBinding {
  chainId: number;
  chainName: string;
}

/** A `did:ethr` that has been checked against one chain. */
export interface DidEthrIdentity {
  /** The DID exactly as it was written (NOT re-minted — the signed bytes say this). */
  did: string;
  /** The numeric chain id it was matched against — always the binding's. */
  chainId: number;
  /** Lower case, always. EIP-55 checksums are display, not identity. */
  address: Address;
}

// ── Mint ─────────────────────────────────────────────────────────────────────

/**
 * address → `did:ethr:0x<chainIdHex>:<address>`.
 */
export function mintDidEthr(address: string, chain: ChainBinding): string {
  return formatDidEthr(asAddress(address, "address"), chain.chainId);
}

// ── Parse ────────────────────────────────────────────────────────────────────

/**
 * Strict parse, bound to one chain. `null` — never a throw — for everything that
 * is not a `did:ethr` for THIS chain: another DID method (`did:web:…`), a
 * pubkey-form did:ethr, a malformed address, a mainnet DID on an Amoy stack, a
 * DID for some other chain id, junk.
 */
export function parseDidEthrOnChain(did: unknown, chain: ChainBinding): DidEthrIdentity | null {
  const parsed = parseDidEthr(did);
  if (!parsed) return null;
  if (!networkMatchesChain(parsed.network, chain.chainId, chain.chainName)) return null;
  // `did` is a string here — `parseDidEthr` returned non-null. Keep the ORIGINAL
  // spelling (trimmed only), because a verdict must report the identifier the
  // signed bytes actually carried, not a canonicalised rewrite of it.
  return { did: (did as string).trim(), chainId: chain.chainId, address: parsed.address };
}

/**
 * The address a `did:ethr` names, or `null` if it does not name one on this
 * chain. Sugar over {@link parseDidEthrOnChain} for the many call sites that
 * only want the address.
 */
export function didEthrAddress(did: unknown, chain: ChainBinding): Address | null {
  return parseDidEthrOnChain(did, chain)?.address ?? null;
}

// ── Address ⇄ DID equality ───────────────────────────────────────────────────

/**
 * Does `did` name `address` on this chain?
 */
export function didMatchesAddress(did: unknown, address: unknown, chain: ChainBinding): boolean {
  const parsed = parseDidEthrOnChain(did, chain);
  if (!parsed) return false;
  let normalized: Address;
  try {
    normalized = asAddress(address, "address");
  } catch {
    return false;
  }
  // Never let address(0) match anything. It is the ERC-1056 "deactivated" owner
  // and the value a broken recovery would most plausibly produce; treating it as
  // an identity would let a deactivated DID be impersonated by a signature that
  // recovers to nothing.
  if (normalized === ZERO_ADDRESS) return false;
  return parsed.address === normalized;
}

// ── Resolve ──────────────────────────────────────────────────────────────────

/**
 * Resolve a `did:ethr` through the INJECTED gateway.
 */
export async function resolveDidEthr(gateway: ChainGateway, did: unknown): Promise<DidDocument | null> {
  const parsed = parseDidEthr(did);
  if (!parsed) return null;
  return gateway.resolveDidDocument((did as string).trim());
}

// ── DID document → the addresses it authorizes ───────────────────────────────

/** A CAIP-10 account: `eip155:<chainId>:<address>`. */
export interface BlockchainAccount {
  chainId: number;
  address: Address;
}

/**
 * Parse a CAIP-10 `blockchainAccountId`, or `null` if it is not an EVM account
 * we understand.
 */
export function parseBlockchainAccountId(value: unknown): BlockchainAccount | null {
  if (typeof value !== "string") return null;
  const parts = value.trim().split(":");
  if (parts.length !== 3) return null;
  const [namespace, reference, account] = parts as [string, string, string];
  if (namespace.toLowerCase() !== "eip155") return null;
  if (!/^[0-9]+$/.test(reference)) return null;
  const chainId = Number(reference);
  if (!Number.isSafeInteger(chainId)) return null;
  let address: Address;
  try {
    address = asAddress(account, "blockchainAccountId.address");
  } catch {
    return null;
  }
  return { chainId, address };
}

/**
 * Every address the document permits to ASSERT (issue credentials), lower case
 * and de-duplicated.
 */
export function assertionAddresses(doc: DidDocument | null, chain: ChainBinding): Address[] {
  if (!doc) return [];
  const methods = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const refs = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  const out: Address[] = [];
  for (const vm of methods) {
    if (!isRecoveryMethod(vm)) continue;
    if (!refs.some((ref) => referencesMethod(ref, vm.id))) continue;
    const account = parseBlockchainAccountId(vm.blockchainAccountId);
    if (!account) continue;
    if (account.chainId !== chain.chainId) continue;
    if (account.address === ZERO_ADDRESS) continue;
    if (!out.includes(account.address)) out.push(account.address);
  }
  return out;
}

/**
 * May `address` issue credentials under this document *right now*?
 */
export function documentAuthorizesAddress(
  doc: DidDocument | null,
  address: unknown,
  chain: ChainBinding,
): boolean {
  let normalized: Address;
  try {
    normalized = asAddress(address, "address");
  } catch {
    return false;
  }
  if (normalized === ZERO_ADDRESS) return false;
  return assertionAddresses(doc, chain).includes(normalized);
}

/**
 * The verification method id an address is authorized by, or `null`. Used to
 * fill a verdict's `verificationMethod` with the method that ACTUALLY verified,
 * rather than with whatever a `kid` header claimed.
 */
export function assertionMethodIdFor(
  doc: DidDocument | null,
  address: unknown,
  chain: ChainBinding,
): string | null {
  if (!doc) return null;
  let normalized: Address;
  try {
    normalized = asAddress(address, "address");
  } catch {
    return null;
  }
  const refs = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  for (const vm of doc.verificationMethod ?? []) {
    if (!isRecoveryMethod(vm)) continue;
    if (!refs.some((ref) => referencesMethod(ref, vm.id))) continue;
    const account = parseBlockchainAccountId(vm.blockchainAccountId);
    if (account && account.chainId === chain.chainId && account.address === normalized) return vm.id;
  }
  return null;
}

// ── Internals ────────────────────────────────────────────────────────────────

function isRecoveryMethod(vm: unknown): vm is DidVerificationMethod {
  if (!vm || typeof vm !== "object") return false;
  const m = vm as Partial<DidVerificationMethod>;
  return typeof m.id === "string" && m.type === "EcdsaSecp256k1RecoveryMethod2020";
}

/**
 * Does a `assertionMethod` entry point at this verification method?
 */
function referencesMethod(ref: unknown, methodId: string): boolean {
  if (typeof ref !== "string") return false;
  if (ref === methodId) return true;
  if (!ref.startsWith("#")) return false;
  const hash = methodId.indexOf("#");
  return hash >= 0 && methodId.slice(hash) === ref;
}

/**
 * Guard for the one genuine programmer error this module can meet: a chain
 * binding that is not a chain. Exported because the provider's constructor is
 * the right place to fail, not the first verification an hour later.
 */
export function assertChainBinding(chain: unknown): asserts chain is ChainBinding {
  const c = chain as Partial<ChainBinding> | null;
  if (!c || !Number.isSafeInteger(c.chainId) || (c.chainId as number) <= 0 || typeof c.chainName !== "string") {
    throw new InvalidChainArgumentError("chain binding must be { chainId: positive integer, chainName: string }", {
      chain: JSON.stringify(chain ?? null),
    });
  }
}
