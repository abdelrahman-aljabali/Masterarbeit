import type { PrismaClient, Prisma } from "@prisma/client";

type Db = PrismaClient | Prisma.TransactionClient;

/**
 * ─── Verification-verdict cache invalidation ──────────────────────────────────
 * `PassportVersion.verifyResult` caches the cryptographic verdict for a frozen
 * snapshot. That is sound while the VERIFIER agrees with itself — and wrong the
 * moment a signing key is REVOKED for compromise: the DID document stops
 * publishing the key, so the credential no longer verifies, but the cached row
 * would keep answering `verified: true` to every anonymous scan.
 */
export async function flushVerdictCacheForIssuer(db: Db, issuerDid: string): Promise<number> {
  // Two clauses because legacy credential rows (pre-P1-1) carry no
  // passportVersionId: reach those through their passport instead, which is a
  // superset covering every version of a passport this issuer ever signed for.
  const result = await db.$executeRaw`
    UPDATE "PassportVersion"
       SET "verifyResult" = NULL, "verifiedAt" = NULL
     WHERE "verifyResult" IS NOT NULL
       AND (
         "id" IN (
           SELECT "passportVersionId" FROM "Credential"
            WHERE "issuerDid" = ${issuerDid} AND "passportVersionId" IS NOT NULL
         )
         OR "passportId" IN (
           SELECT "passportId" FROM "Credential" WHERE "issuerDid" = ${issuerDid}
         )
       )
  `;
  return result;
}
