import crypto from "crypto";
import type { PrismaClient } from "@prisma/client";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { config } from "../../config.js";
import { flushVerdictCacheForIssuer } from "./verdictCache.js";
import type { KeyRevocation, PublicKeyRecord } from "./types.js";

/**
 * ─── Custodied signing keys (Design B) ────────────────────────────────────────
 * One Ed25519 keypair per issuer subject (an org id, or "platform"). The PUBLIC
 * key is published as a Multikey verificationMethod in the subject's did:web
 * document; the PRIVATE key never leaves this service — platform custody IS the
 * Design B trust model (Design A replaces exactly this with non-custodial keys).
 */

export const PLATFORM_SUBJECT = "platform";

/** Stable verification-method fragment for a subject's first key. */
export const KEY_FRAGMENT = "key-1";

/** Ciphertext format marker for HKDF-wrapped rows ("v2.salt.iv.tag.ct"). */
const V2_PREFIX = "v2";

/**
 * Resolve the KEK secret a row was wrapped under.
 */
function kekSecretFor(kekId: string): string {
  const previous = config.previousKeks[kekId];
  if (previous) return previous;
  if (kekId === config.keyEncryptionKeyId || kekId === "legacy") return config.keyEncryptionKey;
  throw new Error(
    `No key-encryption key available for kekId "${kekId}" — supply it via KEY_ENCRYPTION_KEYS_PREVIOUS to decrypt this row.`,
  );
}

/** Per-row AES key: HKDF-SHA256(KEK, salt, info = subject/fragment binding). */
function deriveDek(kekSecret: string, salt: Buffer, subjectId: string, fragment: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", Buffer.from(kekSecret, "utf8"), salt, Buffer.from(`trustdpp:signing-key:${subjectId}:${fragment}`, "utf8"), 32),
  );
}

/** Legacy (pre-versioning) key: a bare single-pass SHA-256 of the KEK string. */
function legacyKey(kekSecret: string): Buffer {
  return crypto.createHash("sha256").update(kekSecret).digest();
}

function encrypt(plain: string, subjectId: string, fragment: string): { blob: string; kekId: string } {
  const kekId = config.keyEncryptionKeyId;
  const salt = crypto.randomBytes(16);
  const dek = deriveDek(kekSecretFor(kekId), salt, subjectId, fragment);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    blob: [V2_PREFIX, ...[salt, iv, tag, ct].map((b) => b.toString("base64url"))].join("."),
    kekId,
  };
}

function decrypt(enc: string, kekId: string, subjectId: string, fragment: string): string {
  const parts = enc.split(".");
  const kekSecret = kekSecretFor(kekId);

  if (parts[0] === V2_PREFIX) {
    const [salt, iv, tag, ct] = parts.slice(1).map((s) => Buffer.from(s, "base64url"));
    const decipher = crypto.createDecipheriv("aes-256-gcm", deriveDek(kekSecret, salt!, subjectId, fragment), iv!);
    decipher.setAuthTag(tag!);
    return Buffer.concat([decipher.update(ct!), decipher.final()]).toString("utf8");
  }

  // Legacy "iv.tag.ct" under sha256(KEK). Still readable so no re-wrap is
  // required before the next deploy; the job migrates them in the background.
  const [iv, tag, ct] = parts.map((s) => Buffer.from(s, "base64url"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", legacyKey(kekSecret), iv!);
  decipher.setAuthTag(tag!);
  return Buffer.concat([decipher.update(ct!), decipher.final()]).toString("utf8");
}

/** Re-wrap one stored ciphertext under the CURRENT KEK (used by the job). */
export function rewrapCiphertext(
  enc: string,
  fromKekId: string,
  subjectId: string,
  fragment: string,
): { blob: string; kekId: string } {
  return encrypt(decrypt(enc, fromKekId, subjectId, fragment), subjectId, fragment);
}

export interface SigningKeyPair {
  publicKeyMultibase: string;
  secretKeyMultibase: string;
  /** Verification-method fragment this pair signs under ("key-1", "key-2", …). */
  fragment: string;
}

/** Seam vocabulary: `PublicKeyRecord` and `KeyRevocation` now live in ./types.js
 *  so the TrustProvider interface doesn't depend on this Design B file. Note
 *  `SigningKeyPair` above deliberately does NOT move — it carries the DECRYPTED
 *  private key, which is custody, i.e. implementation. Re-exported here so
 *  existing importers of `./signingKeys.js` keep working unchanged. */
export type { KeyRevocation, PublicKeyRecord } from "./types.js";

/** The subject's ACTIVE keypair — created (and persisted encrypted) on first use. */
/**
 * Read-only sibling of `getOrCreateSigningKey`: returns the subject's active key
 * or null. NEVER writes.
 */
export async function getSigningKeyIfExists(
  prisma: PrismaClient,
  subjectId: string,
): Promise<SigningKeyPair | null> {
  const existing = await prisma.signingKey.findFirst({
    where: { subjectId, status: "active" },
    orderBy: { createdAt: "desc" },
  });
  if (!existing) return null;
  return {
    publicKeyMultibase: existing.publicKeyMultibase,
    secretKeyMultibase: decrypt(existing.privateKeyEncrypted, existing.kekId, subjectId, existing.fragment),
    fragment: existing.fragment,
  };
}

export async function getOrCreateSigningKey(
  prisma: PrismaClient,
  subjectId: string,
): Promise<SigningKeyPair> {
  const existing = await prisma.signingKey.findFirst({
    where: { subjectId, status: "active" },
    orderBy: { createdAt: "desc" },
  });
  if (existing) {
    return {
      publicKeyMultibase: existing.publicKeyMultibase,
      secretKeyMultibase: decrypt(existing.privateKeyEncrypted, existing.kekId, subjectId, existing.fragment),
      fragment: existing.fragment,
    };
  }

  const kp = await Ed25519Multikey.generate();
  const pair: SigningKeyPair = {
    publicKeyMultibase: kp.publicKeyMultibase,
    secretKeyMultibase: kp.secretKeyMultibase,
    fragment: KEY_FRAGMENT,
  };
  const wrapped = encrypt(pair.secretKeyMultibase, subjectId, KEY_FRAGMENT);
  try {
    await prisma.signingKey.create({
      data: {
        subjectId,
        fragment: KEY_FRAGMENT,
        publicKeyMultibase: pair.publicKeyMultibase,
        privateKeyEncrypted: wrapped.blob,
        kekId: wrapped.kekId,
      },
    });
    return pair;
  } catch (err) {
    // Unique(subjectId, fragment) race with a concurrent publish — use the winner's key.
    if ((err as { code?: string })?.code === "P2002") {
      const row = await prisma.signingKey.findUniqueOrThrow({
        where: { subjectId_fragment: { subjectId, fragment: KEY_FRAGMENT } },
      });
      return {
        publicKeyMultibase: row.publicKeyMultibase,
        secretKeyMultibase: decrypt(row.privateKeyEncrypted, row.kekId, subjectId, row.fragment),
        fragment: row.fragment,
      };
    }
    throw err;
  }
}

/** Public key for a SPECIFIC fragment (proof verification), or the active key
 *  when no fragment is given (DID-document default). Null = never provisioned. */
export async function getPublicKeyMultibase(
  prisma: PrismaClient,
  subjectId: string,
  fragment?: string,
): Promise<string | null> {
  const row = fragment
    ? await prisma.signingKey.findFirst({
        // Retired keys stay resolvable (historical proofs); REVOKED keys
        // (compromise) do not — their signatures must stop verifying.
        where: { subjectId, fragment, status: { not: "revoked" } },
        select: { publicKeyMultibase: true },
      })
    : await prisma.signingKey.findFirst({
        where: { subjectId, status: "active" },
        orderBy: { createdAt: "desc" },
        select: { publicKeyMultibase: true },
      });
  return row?.publicKeyMultibase ?? null;
}

/** All of a subject's public keys (active + retired) for DID-document rendering:
 *  retired keys stay LISTED (credentials signed under them must keep verifying)
 *  but only the active key appears in assertionMethod. */
export async function listPublicKeys(
  prisma: PrismaClient,
  subjectId: string,
): Promise<PublicKeyRecord[]> {
  const rows = await prisma.signingKey.findMany({
    where: { subjectId },
    orderBy: { createdAt: "asc" },
    select: { fragment: true, publicKeyMultibase: true, status: true },
  });
  return rows;
}

/**
 * Rotate the subject's signing key: retire the current active key and mint
 * key-(N+1). The retired PUBLIC key remains in the DID document's
 * verificationMethod list, so every credential signed before the rotation keeps
 * verifying; only NEW signatures use the new key.
 */
export async function rotateKey(prisma: PrismaClient, subjectId: string): Promise<SigningKeyPair> {
  const keys = await prisma.signingKey.findMany({ where: { subjectId }, select: { fragment: true } });
  const maxN = keys.reduce((m, k) => {
    const n = Number(/^key-(\d+)$/.exec(k.fragment)?.[1] ?? 0);
    return Math.max(m, n);
  }, 0);
  const nextFragment = `key-${maxN + 1}`;
  const kp = await Ed25519Multikey.generate();
  const wrapped = encrypt(kp.secretKeyMultibase, subjectId, nextFragment);
  await prisma.$transaction([
    prisma.signingKey.updateMany({
      where: { subjectId, status: "active" },
      data: { status: "retired", retiredAt: new Date() },
    }),
    prisma.signingKey.create({
      data: {
        subjectId,
        fragment: nextFragment,
        publicKeyMultibase: kp.publicKeyMultibase,
        privateKeyEncrypted: wrapped.blob,
        kekId: wrapped.kekId,
      },
    }),
  ]);
  return { publicKeyMultibase: kp.publicKeyMultibase, secretKeyMultibase: kp.secretKeyMultibase, fragment: nextFragment };
}

/**
 * COMPROMISE path: revoke one key (or every key) of a subject.
 */
export async function revokeKey(
  prisma: PrismaClient,
  subjectId: string,
  opts: { fragment?: string; reason: string; issuerDid?: string | null },
): Promise<KeyRevocation> {
  const targets = await prisma.signingKey.findMany({
    where: { subjectId, status: { not: "revoked" }, ...(opts.fragment ? { fragment: opts.fragment } : {}) },
    select: { fragment: true, status: true },
  });
  if (!targets.length) {
    throw new Error(
      opts.fragment
        ? `No revocable key "${opts.fragment}" for subject ${subjectId}`
        : `No revocable keys for subject ${subjectId}`,
    );
  }

  const now = new Date();
  await prisma.signingKey.updateMany({
    where: { subjectId, status: { not: "revoked" }, ...(opts.fragment ? { fragment: opts.fragment } : {}) },
    data: { status: "revoked", revokedAt: now, revokedReason: opts.reason },
  });

  // Mint a replacement whenever the subject is left with no active key.
  const stillActive = await prisma.signingKey.count({ where: { subjectId, status: "active" } });
  const replacement = stillActive === 0 ? (await rotateKey(prisma, subjectId)).fragment : null;

  const verdictsFlushed = opts.issuerDid ? await flushVerdictCacheForIssuer(prisma, opts.issuerDid) : 0;

  return { revoked: targets.map((t) => t.fragment), replacement, verdictsFlushed };
}
