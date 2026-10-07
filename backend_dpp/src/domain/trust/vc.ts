import type { UnsignedCredential } from "../integrity/canonical.js";
import type { UnsignedCredentialEnvelope } from "./types.js";
import { buildCredentialEnvelope, buildAttestationBody, stripNonStringIds } from "../../dpp-core/index.js";
import type { CredentialStatusEntry } from "../../dpp-core/index.js";
import { credentialSchemaUrl } from "./credentialSchema.js";
import { dppContextUrl } from "./vcContext.js";

/**
 * ─── W3C VC envelopes (VC Data Model 2.0) — the server-side ADAPTER ───────────
 * Structurally complete VCDM 2.0 credentials. Design B SIGNS these at publish
 * (DataIntegrityProof, eddsa-rdfc-2022, issuer org's custodied key — see
 * domain/sign.ts); this builder produces the unsigned body the proof wraps.
 */

/** Re-exported from the kernel: the shape lands INSIDE the signed bytes, so it
 *  belongs with the builder. Importers here (statusList.ts, trust/index.ts)
 *  keep importing it from this module. */
export type { CredentialStatusEntry };

/** Re-exported from the kernel — the JSON-LD `@id` sanitizer the builder applies
 *  (a numeric packaging-layer row key would make signing throw). */
export { stripNonStringIds };

/**
 * The DPP tier credential's unsigned body — a fully-typed special case of the
 * seam's `UnsignedCredentialEnvelope`, which is what `trust.prepareCredential`
 * and `trust.signCredential` take. Extending it (rather than being converted to
 * it with `as unknown as Record<string, unknown>`, as publish used to) is what
 * makes the publish path type-check end to end under BOTH designs.
 */
export interface VcEnvelope extends UnsignedCredentialEnvelope {
  "@context": string[];
  type: string[];
  id: string;
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSchema: { id: string; type: "JsonSchema" };
  credentialStatus?: CredentialStatusEntry;
  credentialSubject: Record<string, unknown>;
  // `proof` is attached by domain/sign.ts at publish.
}

export function buildVcEnvelope(params: {
  credential: UnsignedCredential;
  /** Dereferenceable credential URL (…/api/public/credentials/<rowId>). */
  id: string;
  productDid: string | null;
  brandOrgDid: string | null;
  validFrom: Date;
  /** Passport expiration (textile.metadata.expiryDate — phase-1 required). */
  validUntil?: Date | null;
  /** BitstringStatusList revocation entry (allocated per issuer org at publish). */
  credentialStatus?: CredentialStatusEntry | null;
}): VcEnvelope {
  return buildCredentialEnvelope({
    // The two pinned, environment-independent identifiers. Resolved at CALL
    // time (not module load) exactly as before — `dppContextUrl()` and
    // `credentialSchemaUrl()` are functions so tests can load this module
    // without a configured origin.
    contextUrl: dppContextUrl(),
    schemaUrl: credentialSchemaUrl(),
    credential: params.credential, // UnsignedCredential satisfies RoleCredentialInput structurally
    id: params.id,
    productDid: params.productDid,
    brandOrgDid: params.brandOrgDid,
    validFrom: params.validFrom,
    validUntil: params.validUntil,
    credentialStatus: params.credentialStatus,
  });
}

/**
 * The ATTESTATION body — the same envelope minus `id`, which is what a Design A
 * contributor signs in their browser.
 */
export function buildAttestationEnvelope(params: {
  credential: UnsignedCredential;
  productDid: string | null;
  brandOrgDid: string | null;
  validFrom: Date;
  validUntil?: Date | null;
  credentialStatus?: CredentialStatusEntry | null;
}): Omit<VcEnvelope, "id"> {
  return buildAttestationBody({
    contextUrl: dppContextUrl(),
    schemaUrl: credentialSchemaUrl(),
    credential: params.credential,
    productDid: params.productDid,
    brandOrgDid: params.brandOrgDid,
    validFrom: params.validFrom,
    validUntil: params.validUntil,
    credentialStatus: params.credentialStatus,
  }) as Omit<VcEnvelope, "id">;
}
