import type { PrismaClient } from "@prisma/client";
import type { Router } from "express";
import type {
  TrustProvider,
  ChainHeadCommitment,
  CredentialVerdict,
  MintedDid,
  RevocableCredential,
  Db,
} from "./TrustProvider.js";
import type {
  EmbeddedProofCredential,
  UnsignedCredentialEnvelope,
  VerifiableEnvelope,
} from "./types.js";
import { isEnvelopedCredential } from "./types.js";
import { HttpError } from "../../middleware/error.js";
import { signWithSubject, verifySignedCredential, CRYPTOSUITE, MODE } from "./sign.js";
import { rotateKey, revokeKey, listPublicKeys, type KeyRevocation, type PublicKeyRecord } from "./signingKeys.js";
import { rewrapSigningKeys, type RewrapReport } from "./rewrap.js";
import { signChainHead } from "./chainExport.js";
import { didWebHost, didShortOf } from "./did.js";
import { allocateStatusIndex, statusEntryFor, setStatusBit } from "./statusList.js";
import { createDesignBRoutes } from "./designBRoutes.js";

/**
 * ─── Design B — platform-custodied did:web trust ──────────────────────────────
 * The BUILT trust model: each org's credentials are signed by a custodied
 * Ed25519 key (DataIntegrityProof, eddsa-rdfc-2022), issuers resolve via did:web
 * served from this host, revocation is a per-issuer BitstringStatusList, and the
 * audit-chain head is committed by the PLATFORM signing it (verifiable offline
 * with the standalone verifier).
 */
export class DesignBTrust implements TrustProvider {
  readonly mode = MODE;
  readonly cryptosuite = CRYPTOSUITE;

  // did:web for both orgs and products, derived from CREDENTIAL_ORIGIN. Always mintable —
  // no external dependency (unlike A, where an org DID needs a wallet).
  async mintDid(_kind: "org" | "product", id: string): Promise<MintedDid | null> {
    const did = `did:web:${didWebHost()}:${id}`;
    return { did, didShort: didShortOf(did) };
  }

  // B's revocation model: allocate the next BitstringStatusList index in the
  // ISSUER org's list and freeze the statusList entry into the signed bytes.
  async prepareCredential(
    prisma: PrismaClient,
    envelope: UnsignedCredentialEnvelope,
    ctx: { subjectId: string | null },
  ): Promise<{ envelope: UnsignedCredentialEnvelope; statusListIndex: number | null }> {
    if (!ctx.subjectId) return { envelope, statusListIndex: null };
    const statusListIndex = await allocateStatusIndex(prisma, ctx.subjectId);
    return {
      envelope: { ...envelope, credentialStatus: statusEntryFor(ctx.subjectId, statusListIndex) },
      statusListIndex,
    };
  }

  // B's half of the union is fixed: an embedded-proof JSON-LD object, always.
  // Declaring the NARROW return (rather than the seam's `VerifiableEnvelope`) is
  // what lets this provider's own callers skip a branch they can never take.
  signCredential(
    prisma: PrismaClient,
    envelope: UnsignedCredentialEnvelope,
    issuerDid: string,
    subjectId: string,
  ): Promise<EmbeddedProofCredential> {
    return signWithSubject(prisma, envelope, issuerDid, subjectId);
  }

  /**
   * The union's ONE genuine runtime branch inside Design B — and the reason the
   * seam takes the union instead of B's narrow type: a stored credential is data,
   * and data outlives the design that wrote it. An `EnvelopedVerifiableCredential`
   * reaching B's verifier means an A-signed row is being read by a B instance (a
   * mode switch, or a restored backup).
   */
  verifyCredential(
    prisma: PrismaClient,
    credential: VerifiableEnvelope,
    opts?: { includeStatusCheck?: boolean },
  ): Promise<CredentialVerdict> {
    if (isEnvelopedCredential(credential)) {
      return Promise.resolve({
        // `id` stays null: an enveloped credential's id is the payload itself
        // (a multi-kilobyte data: URL), not a dereferenceable identifier — and
        // this verdict gets cached on the version row and split on "/" by the
        // /verify route to find the credential id. Issuer/role live inside the
        // JWS, which is precisely what this provider cannot open.
        id: null,
        issuer: null,
        role: null,
        verified: false,
        error:
          "enveloped credential (VC-JOSE-COSE) — this instance runs Design B, which verifies embedded proofs only",
        mode: this.mode,
        cryptosuite: null,
        verificationMethod: null,
      });
    }
    return verifySignedCredential(prisma, credential, opts);
  }

  // Flip the bit in the issuer org's bitstring. The shared route owns the
  // Credential.status update + audit; this is only B's model-specific part.
  async revokeCredential(tx: Db, credential: RevocableCredential): Promise<void> {
    if (credential.statusListIndex == null) {
      throw new HttpError(
        409,
        "This credential predates status lists and cannot be revoked via the bitstring — re-publish to mint revocable credentials.",
      );
    }
    const issuerOrg = credential.issuerDid
      ? await tx.organization.findFirst({ where: { did: credential.issuerDid }, select: { id: true } })
      : null;
    if (!issuerOrg) throw new HttpError(409, "Cannot resolve the credential's issuer organization.");
    await setStatusBit(tx, issuerOrg.id, credential.statusListIndex, true);
  }

  listSigningKeys(prisma: PrismaClient, subjectId: string): Promise<PublicKeyRecord[]> {
    return listPublicKeys(prisma, subjectId);
  }

  rewrapCustodyKeys(prisma: PrismaClient, opts?: { dryRun?: boolean }): Promise<RewrapReport> {
    return rewrapSigningKeys(prisma, opts);
  }

  // Custody is the model: the platform holds the private key, so the platform
  // is what rotates and revokes it. (Design A must reject both — the key lives
  // in the org's own wallet and only the org can re-key it.)
  async rotateSigningKey(prisma: PrismaClient, subjectId: string): Promise<{ fragment: string }> {
    const { fragment } = await rotateKey(prisma, subjectId);
    return { fragment };
  }

  revokeSigningKey(
    prisma: PrismaClient,
    subjectId: string,
    opts: { fragment?: string; reason: string; issuerDid?: string | null },
  ): Promise<KeyRevocation> {
    return revokeKey(prisma, subjectId, opts);
  }

  async commitChainHead(prisma: PrismaClient, orgId: string): Promise<ChainHeadCommitment> {
    const head = await signChainHead(prisma, orgId);
    const { orgId: _o, seq, headHash, at, ...proof } = head;
    return { mode: this.mode, orgId: _o, seq, headHash, at, proof };
  }

  // did:web resolution + signed status lists — endpoints that exist only under B.
  routes(prisma: PrismaClient): Router | null {
    return createDesignBRoutes(prisma);
  }
}
