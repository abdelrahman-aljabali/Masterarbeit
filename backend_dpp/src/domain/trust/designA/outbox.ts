import type { Prisma, PrismaClient } from "@prisma/client";
import { normalizeSignedCall, type SignedCall } from "./chainTypes.js";

/**
 * ─── The enqueue half of the chain outbox ─────────────────────────────────────
 * `relayer.ts` drains; this file fills. They are deliberately separate files
 * because they have opposite trust properties: draining spends the platform's
 * gas, filling records what an ACTOR already authorized.
 */

/** Base client or transaction client — enqueue runs inside the caller's tx. */
type Db = PrismaClient | Prisma.TransactionClient;

/** Correlation only. None of this is authorization; the signature is. */
export interface AnchorTxContext {
  passportId?: string | null;
  orgId?: string | null;
  /** keccak256(productDid) as 0x-hex — a hash, so nothing linkable beyond what
   *  the public passport already publishes. */
  productId?: string | null;
  /**
   * The address that signed this payload, if the caller knows it (it built the
   * payload, so it does).
   */
  signer?: string | null;
  /**
   * Explicit queue position. Omit for a single row; REQUIRED when enqueuing
   * several rows for one signer inside one transaction.
   */
  createdAt?: Date;
}

/**
 * Queue a signed call for the relayer.
 *
 * `normalizeSignedCall` runs here and again in the gateway, so a malformed
 * payload is rejected at write time rather than becoming a row that can only
 * ever fail — and both ends reject exactly the same bytes.
 */
export async function enqueueSignedCall(
  db: Db,
  call: SignedCall,
  ctx: AnchorTxContext = {},
): Promise<{ id: string }> {
  const normalized = normalizeSignedCall(call);
  const row = await db.anchorTx.create({
    data: {
      kind: normalized.kind,
      passportId: ctx.passportId ?? null,
      orgId: ctx.orgId ?? null,
      productId: ctx.productId ?? normalized.productId,
      // Stored as JSON with bigints rendered as decimal strings: Prisma's Json
      // column cannot hold a bigint, and a lossy Number() conversion would
      // corrupt a nonce or a uint64 version silently — the two fields where a
      // wrong value produces an on-chain revert rather than an obvious bug.
      payload: serializeCall(normalized, ctx.signer) as Prisma.InputJsonValue,
      status: "pending",
      ...(ctx.createdAt ? { createdAt: ctx.createdAt } : {}),
    },
    select: { id: true },
  });
  return row;
}

/** JSON-safe form of a signed call. Inverse of {@link deserializeCall}.
 *  `signer` is a routing hint only — see {@link AnchorTxContext.signer}. */
export function serializeCall(call: SignedCall, signer?: string | null): Record<string, unknown> {
  const out: Record<string, unknown> = { kind: call.kind, productId: call.productId, nonce: call.nonce.toString(), signature: call.signature };
  if (signer) out.signer = String(signer).toLowerCase();
  if (call.kind === "claimProduct") out.controller = call.controller;
  if (call.kind === "setIssuer") { out.issuer = call.issuer; out.allowed = call.allowed; }
  // A COPY, and order-preserving. The array is inside the signed digest, so the
  // stored row must reproduce it exactly — sorting it on the way in or out would
  // guarantee the relayer submits bytes the signature does not cover.
  if (call.kind === "setIssuers") { out.issuers = [...call.issuers]; out.allowed = call.allowed; }
  if (call.kind === "anchor") { out.merkleRoot = call.merkleRoot; out.version = call.version.toString(); }
  return out;
}

/** A signed `address[]`, read back from storage.
 *
 *  Same discipline as {@link requiredUint}: absent or malformed must throw, never
 *  default to `[]`. An empty array is a payload the contract reverts on
 *  (`EmptyIssuerSet`), and substituting one would turn a corrupt row into a
 *  guaranteed on-chain failure that looks like the chain's fault rather than
 *  ours. */
function requiredAddresses(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`AnchorTx payload is missing signed field "${field}" — refusing to substitute a default.`);
  }
  return value.map((v) => String(v));
}

/** A uint field that was SIGNED, read back from storage.
 *
 *  Absent or unparseable must throw, never default. `nonce` and `version` are
 *  both inside the EIP-712 struct the actor signed, so substituting 0 for a
 *  missing value would silently submit a payload whose bytes differ from the
 *  ones that were signed — guaranteeing a revert, and disguising a corrupt row
 *  as a chain-side rejection. Loud failure at the read is the honest outcome. */
function requiredUint(value: unknown, field: string): bigint {
  if (value === null || value === undefined || value === "") {
    throw new TypeError(`AnchorTx payload is missing signed field "${field}" — refusing to substitute a default.`);
  }
  try {
    return BigInt(String(value));
  } catch {
    throw new TypeError(`AnchorTx payload has a non-integer "${field}": ${JSON.stringify(value)}`);
  }
}

/**
 * Rebuild a signed call from its stored JSON, then re-validate it.
 *
 * Re-validating on the way OUT matters as much as on the way in: the relayer is
 * about to spend gas on these bytes, and a row that was hand-edited in the
 * database must fail here rather than on-chain.
 */
export function deserializeCall(payload: unknown): SignedCall {
  const p = (payload ?? {}) as Record<string, unknown>;
  const base = { productId: p.productId, nonce: requiredUint(p.nonce, "nonce"), signature: p.signature };
  switch (p.kind) {
    case "claimProduct":
      return normalizeSignedCall({ kind: "claimProduct", ...base, controller: p.controller } as SignedCall);
    case "setIssuer":
      return normalizeSignedCall({ kind: "setIssuer", ...base, issuer: p.issuer, allowed: p.allowed } as SignedCall);
    case "setIssuers":
      return normalizeSignedCall({
        kind: "setIssuers",
        ...base,
        issuers: requiredAddresses(p.issuers, "issuers"),
        allowed: p.allowed,
      } as SignedCall);
    case "anchor":
      return normalizeSignedCall({
        kind: "anchor",
        ...base,
        merkleRoot: p.merkleRoot,
        version: requiredUint(p.version, "version"),
      } as SignedCall);
    default:
      throw new TypeError(`AnchorTx payload has unknown kind ${JSON.stringify(p.kind)}`);
  }
}
