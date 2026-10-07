import zlib from "zlib";
import crypto from "crypto";
import { Prisma } from "@prisma/client";
import type { PrismaClient } from "@prisma/client";
import { statusListUrl } from "./trustUrls.js";
import { signWithSubject } from "./sign.js";
import type { CredentialStatusEntry } from "./vc.js";
import type { EmbeddedProofCredential, UnsignedCredentialEnvelope } from "./types.js";

type Db = PrismaClient | Prisma.TransactionClient;

/**
 * ─── W3C Bitstring Status List v1.0 (revocation) ─────────────────────────────
 * One bitstring per issuer org. Spec-minimum 131,072 entries (16 KiB) so a
 * single list gives verifiers herd privacy — an index reveals nothing about how
 * many credentials exist. Indexes are allocated at publish; revocation flips the
 * bit.
 */

export const BITSTRING_BYTES = 16384; // 131,072 entries — spec minimum
export const BITSTRING_CAPACITY = BITSTRING_BYTES * 8;
const LIST = 1;

/** How long a served status-list credential stays fresh (`validUntil`). The
 *  bytes are re-signed on expiry and invalidated immediately on any bit flip,
 *  so a verifier caching for the full window can never miss a revocation by
 *  more than this. Bitstring SL 1.0 recommends bounding list validity. */
export const STATUS_LIST_TTL_MS = 24 * 60 * 60 * 1000;

/** Retries for the create-vs-claim race. Each loss means another caller made
 *  progress, so a handful is generous — this is not a spin-wait on a lock. */
const MAX_ALLOCATION_ATTEMPTS = 5;

// ── Randomized index assignment ──────────────────────────────────────────────

function feistel18(seed: Buffer, x: number): number {
  let l = x >> 9;
  let r = x & 0x1ff;
  for (let round = 0; round < 4; round++) {
    const digest = crypto.createHmac("sha256", seed).update(`sl-perm:${round}:${r}`).digest();
    const f = digest.readUInt16BE(0) & 0x1ff;
    const nl = r;
    r = l ^ f;
    l = nl;
  }
  return (l << 9) | r;
}

/** Map a sequential counter to its public index. Null seed = legacy list that
 *  already allocated sequentially — it stays on the identity mapping FOREVER
 *  (permuting it would collide new indexes with already-issued ones, aliasing
 *  revocations across credentials). */
export function permuteIndex(seed: Buffer | null, counter: number): number {
  if (!seed) return counter;
  let x = feistel18(seed, counter);
  while (x >= BITSTRING_CAPACITY) x = feistel18(seed, x);
  return x;
}

/**
 * Allocate the next free index in the issuer org's list (creating it lazily).
 */
export async function allocateStatusIndex(db: Db, orgId: string): Promise<number> {
  // Bounded retry, because "the UPDATE matched no row" has TWO causes — the list
  // does not exist yet, or it is genuinely full — and the first one is racy: a
  // concurrent publish can create the list between our claim and our check.
  // Distinguishing them by capacity (not by mere existence) is what keeps a
  // first-publish stampede from being misreported as an exhausted list.
  for (let attempt = 0; attempt < MAX_ALLOCATION_ATTEMPTS; attempt++) {
    const claimed = await claim(db, orgId);
    if (claimed !== null) return permuteIndex(claimed.permSeed, claimed.counter);

    const existing = await db.statusList.findUnique({ where: { orgId_list: { orgId, list: LIST } } });
    if (existing) {
      if (existing.nextIndex >= BITSTRING_CAPACITY) {
        // 131k revocable credentials per org — far beyond MVP scale. Fail loudly
        // rather than silently reusing an index (which would alias revocations).
        throw new Error(`Status list for ${orgId} is full — provision list ${LIST + 1}`);
      }
      continue; // created by someone else after our claim — claim again
    }

    try {
      const permSeed = crypto.randomBytes(32);
      await db.statusList.create({
        data: { orgId, list: LIST, bitstring: Buffer.alloc(BITSTRING_BYTES), nextIndex: 1, permSeed },
      });
      return permuteIndex(permSeed, 0);
    } catch (err) {
      // unique(orgId, list) race — a concurrent publish created the list first.
      if ((err as { code?: string })?.code !== "P2002") throw err;
    }
  }
  throw new Error(`Could not allocate a status index for ${orgId} after ${MAX_ALLOCATION_ATTEMPTS} attempts`);
}

/** One atomic counter claim (+ the immutable seed, in the same round trip).
 *  Null = no row matched (missing list, or full). */
async function claim(db: Db, orgId: string): Promise<{ counter: number; permSeed: Buffer | null } | null> {
  // `updatedAt` is set explicitly: raw SQL bypasses Prisma's @updatedAt.
  const rows = await db.$queryRaw<{ idx: number; permSeed: Uint8Array | null }[]>`
    UPDATE "StatusList"
       SET "nextIndex" = "nextIndex" + 1, "updatedAt" = now()
     WHERE "orgId" = ${orgId}
       AND "list" = ${LIST}
       AND "nextIndex" < ${BITSTRING_CAPACITY}
    RETURNING "nextIndex" - 1 AS idx, "permSeed"
  `;
  if (!rows.length) return null;
  const row = rows[0]!;
  return { counter: Number(row.idx), permSeed: row.permSeed ? Buffer.from(row.permSeed) : null };
}

/** The credentialStatus entry frozen into a signed credential. */
export function statusEntryFor(orgId: string, index: number): CredentialStatusEntry {
  const listUrl = statusListUrl(orgId, LIST);
  return {
    id: `${listUrl}#${index}`,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListCredential: listUrl,
    statusListIndex: String(index),
  };
}

/**
 * Flip (or clear) a bit. bit=true ⇒ REVOKED.
 */
export async function setStatusBit(tx: Db, orgId: string, index: number, bit: boolean): Promise<void> {
  const locked = await tx.$queryRaw<{ bitstring: Uint8Array }[]>`
    SELECT "bitstring" FROM "StatusList"
     WHERE "orgId" = ${orgId} AND "list" = ${LIST}
       FOR UPDATE
  `;
  if (!locked.length) throw new Error(`No status list for ${orgId}`);
  if (index < 0 || index >= BITSTRING_CAPACITY) throw new Error(`Status index ${index} out of range`);

  const buf = Buffer.from(locked[0]!.bitstring);
  const byte = index >> 3;
  // Spec bit order: index 0 is the LEFT-MOST bit of the first byte.
  const mask = 0x80 >> (index & 7);
  if (bit) buf[byte]! |= mask; else buf[byte]! &= ~mask;
  await tx.statusList.update({
    where: { orgId_list: { orgId, list: LIST } },
    // Drop the cached signature: these bytes no longer describe the list.
    data: { bitstring: buf, signedCredential: Prisma.DbNull, signedAt: null },
  });
}

/** Spec encoding: multibase base64url-nopad of the GZIP-compressed bitstring. */
export function encodeBitstring(bitstring: Buffer): string {
  return "u" + zlib.gzipSync(bitstring).toString("base64url");
}

/** The unsigned BitstringStatusListCredential body (exported for tests). */
export function buildStatusListEnvelope(
  orgId: string,
  issuerDid: string,
  bitstring: Buffer,
  now: Date,
): UnsignedCredentialEnvelope {
  const listUrl = statusListUrl(orgId, LIST);
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: listUrl,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: issuerDid,
    validFrom: now.toISOString(),
    // Bounded validity: without it a verifier may cache a stale list forever and
    // keep accepting a credential this platform has already revoked.
    validUntil: new Date(now.getTime() + STATUS_LIST_TTL_MS).toISOString(),
    credentialSubject: {
      id: `${listUrl}#list`,
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList: encodeBitstring(bitstring),
    },
  };
}

/**
 * The signed BitstringStatusListCredential for an issuer org.
 */
export async function buildStatusListCredential(
  prisma: PrismaClient,
  orgId: string,
  issuerDid: string,
): Promise<EmbeddedProofCredential> {
  const row = await prisma.statusList.findUnique({ where: { orgId_list: { orgId, list: LIST } } });
  const now = new Date();

  if (row?.signedCredential && row.signedAt && row.signedAt.getTime() + STATUS_LIST_TTL_MS > now.getTime()) {
    // Cached bytes we signed ourselves, coming back through a Json column — the
    // double assertion is the column's type-erasure, not a claim about content.
    return row.signedCredential as unknown as EmbeddedProofCredential;
  }

  const bitstring = row ? Buffer.from(row.bitstring) : Buffer.alloc(BITSTRING_BYTES);
  const signed = await signWithSubject(prisma, buildStatusListEnvelope(orgId, issuerDid, bitstring, now), issuerDid, orgId);

  if (row) {
    // Best-effort cache write. A concurrent revocation may have flipped a bit
    // between our read and here; that flip nulls the cache again on its own
    // update, and this row's `updatedAt` guard keeps us from resurrecting it.
    await prisma.statusList.updateMany({
      where: { orgId, list: LIST, updatedAt: row.updatedAt },
      data: { signedCredential: signed as Prisma.InputJsonValue, signedAt: now },
    });
  }
  return signed;
}
