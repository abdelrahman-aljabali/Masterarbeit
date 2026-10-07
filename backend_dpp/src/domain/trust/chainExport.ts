import type { PrismaClient } from "@prisma/client";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { HttpError } from "../../middleware/error.js";
import { canonicalHash } from "../integrity/hash.js";
import { getSigningKeyIfExists, PLATFORM_SUBJECT } from "./signingKeys.js";
import { didWebHost } from "./did.js";

/**
 * ─── External chain verifiability (P4-4) ──────────────────────────────────────
 * The audit chain is only tamper-EVIDENT to someone who can recompute it. These
 * helpers power the public export + the SIGNED chain head:
 */

export interface SignedChainHead {
  orgId: string;
  seq: number;
  headHash: string | null;
  at: string;
  /** sha256 hex the platform signed: canonicalHash({ orgId, seq, headHash, at }). */
  signedDigest: string;
  /** Ed25519 signature over the UTF-8 bytes of `signedDigest` (base64url). */
  signedHead: string;
  /** Where the verifying public key lives. */
  verificationMethod: string;
  publicKeyMultibase: string;
}

export async function signChainHead(prisma: PrismaClient, orgId: string): Promise<SignedChainHead> {
  const tip = await prisma.auditEvent.findFirst({
    where: { orgId, seq: { not: null } },
    orderBy: { seq: "desc" },
    select: { seq: true, hash: true },
  });
  const at = new Date().toISOString();
  const seq = tip?.seq ?? 0;
  const headHash = tip?.hash ?? null;
  const signedDigest = canonicalHash({ orgId, seq, headHash, at });

  // Read-only: this runs on an ANONYMOUS endpoint. Minting here would let a
  // stranger trigger a keygen + DB write via GET. The platform key is created at
  // provisioning/publish; if it does not exist yet, nothing has been signed and
  // there is no head to commit.
  const pair = await getSigningKeyIfExists(prisma, PLATFORM_SUBJECT);
  if (!pair) throw new HttpError(503, "Platform signing key is not provisioned yet — publish a passport first.");
  const platformDid = `did:web:${didWebHost()}`;
  const key = await Ed25519Multikey.from({
    type: "Multikey",
    id: `${platformDid}#${pair.fragment}`,
    controller: platformDid,
    publicKeyMultibase: pair.publicKeyMultibase,
    secretKeyMultibase: pair.secretKeyMultibase,
  });
  const signature = await key.signer().sign({ data: Buffer.from(signedDigest, "utf8") });

  return {
    orgId,
    seq,
    headHash,
    at,
    signedDigest,
    signedHead: Buffer.from(signature).toString("base64url"),
    verificationMethod: `${platformDid}#${pair.fragment}`,
    publicKeyMultibase: pair.publicKeyMultibase,
  };
}
