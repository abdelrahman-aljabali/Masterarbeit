import type { PrismaClient } from "@prisma/client";
import { config } from "../../config.js";
import * as vc from "@digitalbazaar/vc";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { cryptosuite as eddsaRdfc2022CryptoSuite } from "@digitalbazaar/eddsa-rdfc-2022-cryptosuite";
import * as Ed25519Multikey from "@digitalbazaar/ed25519-multikey";
import { contexts as credentialsContexts } from "@digitalbazaar/credentials-context";
import didContext from "did-context";
import multikeyContext from "@digitalbazaar/multikey-context";
import { buildActorOrgDidDoc, buildOrgDidDoc, didWebHost } from "./did.js";
import { getOrCreateSigningKey, getPublicKeyMultibase, listPublicKeys, PLATFORM_SUBJECT } from "./signingKeys.js";
import { DPP_CONTEXT, CONTEXT_BODIES } from "./vcContext.js";
import { HISTORICAL_CONTEXT_URLS, HISTORICAL_HOSTS } from "./trustUrls.js";
import type { SigningKeyPair } from "./signingKeys.js";
import type { CredentialVerdict, EmbeddedProofCredential, UnsignedCredentialEnvelope } from "./types.js";

/**
 * ─── Sign & verify (Design B: DataIntegrityProof, eddsa-rdfc-2022) ────────────
 * Signing happens at publish with the ISSUER org's custodied Ed25519 key; the
 * proof's verificationMethod points into that org's did:web document. All
 * JSON-LD processing is OFFLINE — the document loader below serves every needed
 * context from bundled copies and resolves our own did:web URLs straight from
 * the database. Publishing and verification never fetch the network.
 */

export const CRYPTOSUITE = "eddsa-rdfc-2022";

/** The trust mode these signatures and verdicts belong to. A LITERAL, not
 *  `config.trustMode`: this file IS Design B, so a verdict it produced was
 *  produced by Design B — reading the running mode here would let a
 *  misconfigured process stamp B's verdicts with someone else's name (and it is
 *  a design branch outside the seam, which lint now rejects). */
export const MODE = "design-b" as const;

// ── Offline document loader ──────────────────────────────────────────────────

const STATIC_DOCS = new Map<string, unknown>();
// credentials/v2 (+ any siblings the package bundles)
for (const [url, doc] of credentialsContexts) STATIC_DOCS.set(url, doc);
STATIC_DOCS.set(didContext.constants.DID_CONTEXT_URL, didContext.contexts.get(didContext.constants.DID_CONTEXT_URL));
STATIC_DOCS.set(multikeyContext.constants.CONTEXT_URL, multikeyContext.contexts.get(multikeyContext.constants.CONTEXT_URL));

/** did:web:<host>[:<id>][#fragment] → { host (encoded), subject id ("platform"
 *  for the bare host), fragment }. Handles BOTH host spellings: the spec-correct
 *  `%3A`-encoded port (localhost%3A8080 — one segment) and the historical
 *  raw-colon dev form (localhost:8080 — the port lands in segments[1], which
 *  used to be misread as the SUBJECT id: the dev "No signing key" loader bug). */
function parseOwnDidUrl(url: string): { host: string; subjectId: string; fragment: string | null } | null {
  if (!url.startsWith("did:web:")) return null;
  const [didPart, fragment] = url.split("#");
  const segments = didPart.slice("did:web:".length).split(":");
  let host = segments[0] ?? "";
  let rest = segments.slice(1);
  if (!host.includes("%3A") && /^\d+$/.test(rest[0] ?? "")) {
    // Historical raw-colon port — fold it into the host (encoded form).
    host = `${host}%3A${rest[0]}`;
    rest = rest.slice(1);
  }
  return { host, subjectId: rest[0] ?? PLATFORM_SUBJECT, fragment: fragment ?? null };
}

/**
 * Document loader factory. Static contexts from bundled copies; our own did:web
 * DIDs (and their #key fragments) resolved from the database.
 */
export function makeDocumentLoader(prisma: PrismaClient) {
  return async (url: string): Promise<{ contextUrl: null; documentUrl: string; document: unknown }> => {
    // Any context URL EVER minted into signed bytes resolves to the bundled
    // body it was signed WITH — v1 URLs (incl. historical APP_URL-coupled
    // spellings) get the v1 body, v2 gets the v2 (@list) body. Serving a
    // different body than was signed would silently change the RDF and break
    // every proof minted against the original.
    const contextBody = CONTEXT_BODIES.get(url) ?? (HISTORICAL_CONTEXT_URLS.includes(url) ? DPP_CONTEXT : undefined);
    if (contextBody) {
      return { contextUrl: null, documentUrl: url, document: contextBody };
    }
    const staticDoc = STATIC_DOCS.get(url);
    if (staticDoc) return { contextUrl: null, documentUrl: url, document: staticDoc };

    const own = parseOwnDidUrl(url);
    if (own) {
      // Host gate (production only): resolve did:web documents from OUR
      // database only for hosts we have ever minted under. Without this, a
      // crafted did:web:evil.example:org_x would borrow our stored keys. Dev
      // stays open — APP_URL churns locally and mismatches are logged elsewhere.
      if (config.isProduction && own.host !== didWebHost() && !HISTORICAL_HOSTS.includes(own.host)) {
        throw new Error(`Refusing to resolve did:web host "${own.host}" — not this platform's host`);
      }
      const did = url.split("#")[0];
      if (own.fragment) {
        // Resolve the EXACT fragment — a proof signed under key-1 must verify
        // against key-1 forever, even after rotation retired it. (The old code
        // echoed any fragment against the single stored key.)
        const publicKeyMultibase = await getPublicKeyMultibase(prisma, own.subjectId, own.fragment);
        if (!publicKeyMultibase) throw new Error(`No signing key ${own.fragment} for ${did}`);
        return {
          contextUrl: null,
          documentUrl: url,
          document: {
            "@context": multikeyContext.constants.CONTEXT_URL,
            id: `${did}#${own.fragment}`,
            type: "Multikey",
            controller: did,
            publicKeyMultibase,
          },
        };
      }
      const keys = await listPublicKeys(prisma, own.subjectId);
      const doc =
        own.subjectId === PLATFORM_SUBJECT
          ? buildOrgDidDoc(keys)
          : buildActorOrgDidDoc(
              did,
              (await prisma.organization.findUnique({ where: { id: own.subjectId } }))?.name ?? own.subjectId,
              keys,
            );
      return { contextUrl: null, documentUrl: url, document: doc };
    }

    throw new Error(`Refusing to load remote document during signing/verification: ${url}`);
  };
}

// ── Sign / verify ────────────────────────────────────────────────────────────

/** Sign one credential envelope with the issuer's custodied key. Unsigned body
 *  in, embedded-proof credential out — B's whole half of the seam's union. */
export async function signCredential(
  prisma: PrismaClient,
  envelope: UnsignedCredentialEnvelope,
  issuerDid: string,
  keyPair: SigningKeyPair,
): Promise<EmbeddedProofCredential> {
  const key = await Ed25519Multikey.from({
    type: "Multikey",
    // The pair knows which fragment it signs under — after a rotation this is
    // key-N+1 while older proofs keep pointing at (still-resolvable) key-N.
    id: `${issuerDid}#${keyPair.fragment}`,
    controller: issuerDid,
    publicKeyMultibase: keyPair.publicKeyMultibase,
    secretKeyMultibase: keyPair.secretKeyMultibase,
  });
  const suite = new DataIntegrityProof({ signer: key.signer(), cryptosuite: eddsaRdfc2022CryptoSuite });
  return vc.issue({
    credential: { ...envelope },
    suite,
    documentLoader: makeDocumentLoader(prisma),
  });
}

/** Issuer-org key lookup + sign, in one call (used by the publish pipeline). */
export async function signWithSubject(
  prisma: PrismaClient,
  envelope: UnsignedCredentialEnvelope,
  issuerDid: string,
  subjectId: string,
): Promise<EmbeddedProofCredential> {
  const keyPair = await getOrCreateSigningKey(prisma, subjectId);
  return signCredential(prisma, envelope, issuerDid, keyPair);
}

/** Seam vocabulary: `CredentialVerdict` now lives in ./types.js so the
 *  TrustProvider interface doesn't depend on this Design B file. Re-exported
 *  here so existing importers of `./sign.js` keep working unchanged. */
export type { CredentialVerdict } from "./types.js";

/**
 * Verify one signed credential against our DID layer (offline).
 */
export async function verifySignedCredential(
  prisma: PrismaClient,
  credential: EmbeddedProofCredential,
  opts: { includeStatusCheck?: boolean } = {},
): Promise<CredentialVerdict> {
  const includeStatusCheck = opts.includeStatusCheck ?? true;
  const subject = (credential.credentialSubject ?? {}) as Record<string, unknown>;
  // A credential may carry an array of proofs; the first is what we report on.
  const proof = Array.isArray(credential.proof) ? credential.proof[0] : credential.proof;
  const base: Omit<CredentialVerdict, "verified" | "error"> = {
    id: (credential.id as string) ?? null,
    issuer: (credential.issuer as string) ?? null,
    role: (subject.role as string) ?? null,
    mode: MODE,
    cryptosuite: proof?.cryptosuite ?? null,
    verificationMethod: proof?.verificationMethod ?? null,
  };
  if (!credential.proof) {
    return { ...base, verified: false, error: "unsigned (no proof)" };
  }
  try {
    const suite = new DataIntegrityProof({ cryptosuite: eddsaRdfc2022CryptoSuite });
    // Status check against OUR OWN BitstringStatusList rows (offline, like the
    // rest of verification). The library REQUIRES this callback the moment a
    // credential carries `credentialStatus`. A revoked bit fails verification —
    // that is the W3C semantics: a revoked credential does not verify.
    const checkStatus = async ({ credential: cred }: { credential: Record<string, unknown> }) => {
      // The caller may want the PURE signature verdict (it is immutable and
      // cacheable per version) and handle revocation as live state instead.
      if (!includeStatusCheck) return { verified: true };
      const cs = cred.credentialStatus as { statusListCredential?: string; statusListIndex?: string } | undefined;
      if (!cs?.statusListCredential || cs.statusListIndex == null) return { verified: true };
      const m = /\/status\/([^/]+)\/(\d+)$/.exec(cs.statusListCredential);
      if (!m) return { verified: false, error: new Error("unresolvable statusListCredential") };
      const row = await prisma.statusList.findUnique({ where: { orgId_list: { orgId: m[1], list: Number(m[2]) } } });
      if (!row) return { verified: true }; // list never provisioned ⇒ nothing revoked
      const index = Number(cs.statusListIndex);
      const bit = (Buffer.from(row.bitstring)[index >> 3] ?? 0) & (0x80 >> (index & 7));
      return bit ? { verified: false, error: new Error("credential has been revoked") } : { verified: true };
    };
    const result = await vc.verifyCredential({
      credential,
      suite,
      documentLoader: makeDocumentLoader(prisma),
      checkStatus,
    });
    // Surface WHY it failed. The library reports a failed status check in
    // `statusResult`, not in `error`, so a revoked credential used to come back
    // as a bare "verification failed" — indistinguishable from a broken
    // signature, which is the one distinction a verifier most needs to see.
    const statusResult = result.statusResult as { verified?: boolean; error?: Error } | undefined;
    const statusFailed = statusResult && statusResult.verified === false;
    return {
      ...base,
      verified: !!result.verified,
      error: result.verified
        ? null
        : statusFailed
          ? String(statusResult.error?.message ?? "credential has been revoked")
          : String(result.error?.errors?.[0]?.message ?? result.error ?? "verification failed"),
    };
  } catch (err) {
    return { ...base, verified: false, error: (err as Error).message };
  }
}
