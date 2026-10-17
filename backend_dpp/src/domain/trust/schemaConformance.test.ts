import { describe, it, expect } from "vitest";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { DPP_TIER_CREDENTIAL_SCHEMA, DPP_TIER_CREDENTIAL_SCHEMA_V2 } from "./credentialSchema.js";
import { buildVcEnvelope } from "./vc.js";
import { statusEntryFor } from "./statusList.js";
import { SCHEMA_URL_V2, CONTEXT_URL_V3 } from "./trustUrls.js";

/**
 * ─── credentialSchema conformance ─────────────────────────────────────────────
 * Every credential this platform signs points at
 * `/schemas/dpp-tier-credential.v2.json` and invites a verifier to validate
 * against it. Nothing checked that the invitation was honest; these tests do.
 */

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);

const validateV1 = ajv.compile(DPP_TIER_CREDENTIAL_SCHEMA);
const validateV2 = ajv.compile(DPP_TIER_CREDENTIAL_SCHEMA_V2);

const build = (over: Partial<Parameters<typeof buildVcEnvelope>[0]> = {}) =>
  buildVcEnvelope({
    credential: {
      role: "weaving",
      issuerDid: "did:web:trustdpp.co:org_x",
      credentialSubject: { facilityCountry: "PT", fibers: ["cotton 95%", "elastane 5%"] },
    } as never,
    id: "https://trustdpp.co/api/public/credentials/vc_1",
    productDid: "did:web:trustdpp.co:prod_1",
    brandOrgDid: null,
    validFrom: new Date("2026-07-26T00:00:00.000Z"),
    validUntil: new Date("2031-07-26T00:00:00.000Z"),
    credentialStatus: statusEntryFor("org_x", 42),
    ...over,
  });

describe("emitted envelopes satisfy the schema they advertise", () => {
  it("a full envelope validates against v2", () => {
    const envelope = build();
    expect(envelope.credentialSchema.id).toBe(SCHEMA_URL_V2);
    const ok = validateV2(envelope);
    expect(validateV2.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  it("validates without the optional members (no expiry, no revocation entry)", () => {
    const envelope = build({ validUntil: null, credentialStatus: null });
    expect(envelope).not.toHaveProperty("validUntil");
    expect(envelope).not.toHaveProperty("credentialStatus");
    expect(validateV2(envelope)).toBe(true);
  });

  it("references the pinned, environment-independent identifier URLs", () => {
    // These land inside the signed bytes; if they ever derive from APP_URL
    // again, every already-signed credential becomes unverifiable.
    const envelope = build();
    expect(envelope["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2", CONTEXT_URL_V3]);
    expect(envelope.id.startsWith("https://trustdpp.co/")).toBe(true);
    expect(envelope.credentialStatus?.statusListCredential.startsWith("https://trustdpp.co/")).toBe(true);
  });

  it("a signed envelope still validates once the proof is attached", () => {
    // `proof` is permitted-but-not-required (legacy pre-signing versions exist).
    const signed = { ...build(), proof: { type: "DataIntegrityProof", cryptosuite: "eddsa-rdfc-2022" } };
    expect(validateV2(signed)).toBe(true);
  });
});

describe("the schema actually rejects malformed credentials", () => {
  it("rejects a non-DID issuer", () => {
    expect(validateV2({ ...build(), issuer: "https://example.com/org" })).toBe(false);
  });

  it("rejects a credentialSubject with no role", () => {
    expect(validateV2({ ...build(), credentialSubject: { id: "did:web:trustdpp.co:prod_1" } })).toBe(false);
  });

  it("rejects an unknown top-level member (additionalProperties: false)", () => {
    expect(validateV2({ ...build(), somethingNew: true })).toBe(false);
  });

  it("rejects a credentialStatus that is not a BitstringStatusListEntry", () => {
    const bad = { ...build(), credentialStatus: { ...statusEntryFor("org_x", 1), type: "StatusList2021Entry" } };
    expect(validateV2(bad)).toBe(false);
  });
});

describe("schema v1 stays frozen", () => {
  it("still validates a v1-shaped credential", () => {
    // v1 is referenced by already-signed bytes and must never change.
    const v1 = build({ validUntil: null, credentialStatus: null });
    expect(validateV1({ ...v1, credentialSchema: { id: DPP_TIER_CREDENTIAL_SCHEMA.$id, type: "JsonSchema" } })).toBe(true);
  });

  it("does NOT accept the v2-only members", () => {
    // Proof that v2 is a real version bump rather than an in-place edit of v1.
    expect(validateV1(build())).toBe(false);
  });
});
