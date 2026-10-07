/**
 * ─── did:web documents (Design B — resolvable, SIGNED) ───────────────────────
 * Design B mints `did:web:<host>` (platform / responsible operator),
 * `did:web:<host>:<orgId>` (issuer orgs) and `did:web:<host>:<productId>`
 * (subjects).
 */
import { config } from "../../config.js";
import { normalizeGtin14 } from "../../dpp-core/index.js";

const MULTIKEY_CONTEXT = "https://w3id.org/security/multikey/v1";

/** One public key as the DID document lists it. */
export interface DidKeyEntry {
  fragment: string;
  publicKeyMultibase: string;
  status: string; // active | retired
}

/** Multikey verificationMethod + assertionMethod block for an issuer DID.
 *  RETIRED keys stay in BOTH lists: verifiers check that a proof's
 *  verificationMethod is authorized via assertionMethod in the controller
 *  document, so dropping a retired key there would break every credential
 *  signed before the rotation (retired = "we stopped signing with it", not
 *  "it was compromised"). Only REVOKED keys (compromise) are removed from
 *  both lists — after which their old signatures deliberately stop verifying. */
function keyBlock(did: string, keys: DidKeyEntry[]) {
  const usable = keys.filter((k) => k.status !== "revoked");
  // No keys → OMIT the properties entirely. An empty `verificationMethod: []`
  // is legal DID 1.0 but flagged noise for resolvers; absence says the same
  // thing cleanly (and matches how product DIDs — deliberately keyless — read).
  if (!usable.length) return {};
  return {
    verificationMethod: usable.map((k) => ({
      id: `${did}#${k.fragment}`,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: k.publicKeyMultibase,
    })),
    assertionMethod: usable.map((k) => `${did}#${k.fragment}`),
  };
}

const didContexts = (hasKey: boolean) =>
  hasKey ? ["https://www.w3.org/ns/did/v1", MULTIKEY_CONTEXT] : ["https://www.w3.org/ns/did/v1"];

/**
 * Derived from CREDENTIAL_ORIGIN (the PERMANENT per-stack domain —
 * app.trustdpp.co for Design B, web3.trustdpp.co for Design A), NOT from
 * APP_URL. A did:web host is frozen into every issuer DID, which is frozen into
 * the signed bytes of every credential that issuer signs.
 */
export function didWebHost(): string {
  return new URL(config.credentialOrigin).host.replace(":", "%3A");
}

/** Extract a did:web's host segment in ENCODED form, tolerating historical
 *  raw-colon dev DIDs (`did:web:localhost:8080:x` → `localhost%3A8080`). */
export function didWebHostOf(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const segments = did.slice("did:web:".length).split("#")[0].split(":");
  if (segments[0]?.includes("%3A")) return segments[0];
  // Historical raw-colon form: hostname followed by a numeric port segment.
  if (segments.length >= 2 && /^\d+$/.test(segments[1] ?? "")) return `${segments[0]}%3A${segments[1]}`;
  return segments[0] ?? null;
}

/** Compact display form of a DID: "did:web:…<last 8 chars>". */
export function didShortOf(did: string): string {
  return `did:web:…${did.slice(-8)}`;
}

/** Platform / responsible-operator DID document → served at /.well-known/did.json */
export function buildOrgDidDoc(keys: DidKeyEntry[] = []) {
  const did = `did:web:${didWebHost()}`;
  return {
    "@context": didContexts(keys.length > 0),
    id: did,
    controller: did,
    ...keyBlock(did, keys),
    service: [
      {
        id: `${did}#platform`,
        type: "TrustDPPPlatform",
        serviceEndpoint: config.appUrl,
      },
    ],
  };
}

/** Product DID document → served at /:productId/did.json
 *  Keyless BY DESIGN (products are subjects, never issuers), so no
 *  verificationMethod at all — an empty array was legal but noisy.
 *  @param did    the minted product DID (e.g. did:web:host:prod_x)
 *  @param dppId  the passport id the public view lives at (/passport/:dppId)
 *  @param gtin   the product's GS1 GTIN, when one is registered */
export function buildProductDidDoc(did: string, dppId: string, gtin?: string | null) {
  // Bind the product's TWO identities in one resolvable place: the same product
  // is `did:web:…:prod_x` to a credential verifier and `/01/<gtin>` to a GS1
  // Digital Link resolver — without this link, a regulator resolving the GTIN
  // and a verifier holding a credential about the DID cannot connect the two.
  // Canonical id.gs1.org first (the global identifier), our own resolver second.
  const gtin14 = gtin ? normalizeGtin14(gtin) : null;
  const alsoKnownAs = gtin14
    ? [`https://id.gs1.org/01/${gtin14}`, `${config.appUrl}/01/${gtin14}`]
    : null;
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    controller: `did:web:${didWebHost()}`,
    ...(alsoKnownAs ? { alsoKnownAs } : {}),
    service: [
      {
        id: `${did}#passport`,
        type: "DigitalProductPassport",
        serviceEndpoint: `${config.appUrl}/passport/${dppId}`,
      },
    ],
  };
}

/** Actor-organization DID document → served at /:orgId/did.json. This is what a
 *  credential's `issuer` resolves to — and where its proof's verificationMethod
 *  points; without it, attribution dead-ends.
 *  @param did      the org's stored DID (did:web:host:org_x)
 *  @param orgName  display name, exposed as the service label
 *  @param keys     the org's custodied keys (active + retired; [] = none provisioned) */
export function buildActorOrgDidDoc(did: string, orgName: string, keys: DidKeyEntry[] = []) {
  return {
    "@context": didContexts(keys.length > 0),
    id: did,
    controller: `did:web:${didWebHost()}`,
    ...keyBlock(did, keys),
    service: [
      {
        id: `${did}#org`,
        type: "SupplyChainActor",
        serviceEndpoint: config.appUrl,
        name: orgName,
      },
    ],
  };
}

/** True when a stored did:web's host differs from the host this server derives
 *  from CREDENTIAL_ORIGIN — a mis-hosted DID would not resolve via spec did:web resolution.
 *  Prefix comparison (not regex) so dev hosts with ports ("localhost:8080") work. */
export function didHostMismatch(did: string): boolean {
  if (!did.startsWith("did:web:")) return false;
  // Compare ENCODED host forms so historical raw-colon dev DIDs
  // (did:web:localhost:8080:x) match their %3A-encoded successors.
  return didWebHostOf(did) !== didWebHost();
}
