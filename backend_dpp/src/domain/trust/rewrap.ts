import type { PrismaClient } from "@prisma/client";
import { config } from "../../config.js";
import { rewrapCiphertext } from "./signingKeys.js";
import type { RewrapReport } from "./types.js";

/**
 * ─── KEK re-wrap (custody key rotation) ───────────────────────────────────────
 * Re-encrypts stored private keys under the CURRENT key-encryption key. The
 * Ed25519 keypairs are untouched: public keys, DID documents and every existing
 * signature are unaffected — only the at-rest wrapper changes.
 */

/** Seam vocabulary: `RewrapReport` now lives in ./types.js so the TrustProvider
 *  interface doesn't depend on this Design B file. Re-exported here so existing
 *  importers of `./rewrap.js` keep working unchanged. */
export type { RewrapReport } from "./types.js";

export async function rewrapSigningKeys(
  prisma: PrismaClient,
  opts: { dryRun?: boolean } = {},
): Promise<RewrapReport> {
  const currentKekId = config.keyEncryptionKeyId;
  const [totalKeys, stale] = await Promise.all([
    prisma.signingKey.count(),
    prisma.signingKey.findMany({
      where: { kekId: { not: currentKekId } },
      select: { id: true, subjectId: true, fragment: true, kekId: true, privateKeyEncrypted: true },
      orderBy: { createdAt: "asc" },
    }),
  ]);

  const report: RewrapReport = {
    currentKekId,
    stale: stale.reduce<Record<string, number>>((acc, r) => {
      acc[r.kekId] = (acc[r.kekId] ?? 0) + 1;
      return acc;
    }, {}),
    staleCount: stale.length,
    totalKeys,
    rewrapped: 0,
    failures: [],
  };
  if (opts.dryRun) return report;

  for (const row of stale) {
    try {
      // Decrypt under the row's OWN kekId, re-encrypt under the current one.
      // Committed per row: safe to interrupt, safe to re-run.
      const wrapped = rewrapCiphertext(row.privateKeyEncrypted, row.kekId, row.subjectId, row.fragment);
      await prisma.signingKey.update({
        where: { id: row.id },
        data: { privateKeyEncrypted: wrapped.blob, kekId: wrapped.kekId },
      });
      report.rewrapped += 1;
    } catch (err) {
      // Almost always "old secret missing from KEY_ENCRYPTION_KEYS_PREVIOUS".
      // Never destructive — the row keeps its existing wrapper.
      report.failures.push({ subjectId: row.subjectId, fragment: row.fragment, error: (err as Error).message });
    }
  }
  return report;
}
