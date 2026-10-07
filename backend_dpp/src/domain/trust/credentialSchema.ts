import { SCHEMA_URL, SCHEMA_URL_V2 } from "./trustUrls.js";

/**
 * ─── DppTierCredential JSON Schema (VCDM 2.0 `credentialSchema`) ──────────────
 * What a valid DppTierCredential looks like — referenced from every issued
 * credential via `credentialSchema` and served at a stable URL, so a verifier
 * can validate structure without out-of-band knowledge (Spherity's "DPP
 * guideline" link plays the same role). Design A adds a `proof` requirement; the
 * schema deliberately permits-but-does-not-require it.
 */

export const CREDENTIAL_SCHEMA_PATH = "/schemas/dpp-tier-credential.v1.json";
export const CREDENTIAL_SCHEMA_PATH_V2 = "/schemas/dpp-tier-credential.v2.json";

/** The PINNED, environment-independent schema id frozen into signed bytes.
 *  (Served at the schema path on any host; identifier ≠ serving host.)
 *  New credentials reference v2; v1 remains served for already-signed VCs. */
export const credentialSchemaUrl = () => SCHEMA_URL_V2;

export const DPP_TIER_CREDENTIAL_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: SCHEMA_URL,
  title: "DppTierCredential",
  description:
    "One supply-chain role's contribution to an EU Digital Product Passport, as a W3C Verifiable Credential (VC Data Model 2.0), signed with a DataIntegrityProof (eddsa-rdfc-2022) by the issuer organization's did:web key.",
  type: "object",
  required: ["@context", "type", "id", "issuer", "validFrom", "credentialSubject"],
  properties: {
    "@context": {
      type: "array",
      items: { type: "string" },
      contains: { const: "https://www.w3.org/ns/credentials/v2" },
    },
    type: {
      type: "array",
      items: { type: "string" },
      allOf: [
        { contains: { const: "VerifiableCredential" } },
        { contains: { const: "DppTierCredential" } },
      ],
    },
    // Dereferenceable https credential URL (current) or legacy urn:uuid (pre-signing versions).
    id: { type: "string", pattern: "^(https?://|urn:uuid:)" },
    issuer: { type: "string", pattern: "^did:" },
    validFrom: { type: "string", format: "date-time" },
    credentialSchema: {
      type: "object",
      required: ["id", "type"],
      properties: { id: { type: "string" }, type: { const: "JsonSchema" } },
    },
    credentialSubject: {
      type: "object",
      required: ["role"],
      properties: {
        id: { type: "string", description: "The product DID this credential is about." },
        role: {
          type: "string",
          description: "Supply-chain role this credential covers (dpp-core stage vocabulary).",
        },
      },
      additionalProperties: true,
    },
    proof: {
      type: "object",
      description:
        "W3C DataIntegrityProof (eddsa-rdfc-2022), signed with the issuer org's key — platform-custodied in Design B, non-custodial in Design A. Absent only on legacy pre-signing versions.",
    },
  },
  additionalProperties: false,
} as const;

/**
 * Schema v2 — v1 plus two ENUMERATED optional members (`additionalProperties`
 * stays false): `validUntil` (mirrors the passport's expiration date into the
 * signed bytes) and `credentialStatus` (BitstringStatusList v1.0 revocation
 * entry). v1 is immutable and stays served forever: credentials already signed
 * reference it by its frozen URL.
 */
export const DPP_TIER_CREDENTIAL_SCHEMA_V2 = {
  ...DPP_TIER_CREDENTIAL_SCHEMA,
  $id: SCHEMA_URL_V2,
  properties: {
    ...DPP_TIER_CREDENTIAL_SCHEMA.properties,
    validUntil: { type: "string", format: "date-time" },
    credentialStatus: {
      type: "object",
      required: ["type", "statusPurpose", "statusListCredential", "statusListIndex"],
      properties: {
        id: { type: "string" },
        type: { const: "BitstringStatusListEntry" },
        statusPurpose: { const: "revocation" },
        statusListCredential: { type: "string" },
        statusListIndex: { type: "string" },
      },
      additionalProperties: false,
    },
  },
} as const;
