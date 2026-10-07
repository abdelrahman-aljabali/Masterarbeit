import { describe, it, expect } from "vitest";
import { config } from "../../config.js";
import {
  buildOrgDidDoc,
  buildActorOrgDidDoc,
  buildProductDidDoc,
  didWebHost,
  didWebHostOf,
  didHostMismatch,
} from "./did.js";

/**
 * ─── did:web document shape ───────────────────────────────────────────────────
 *
 * A DID document is the only thing standing between a credential's proof and
 * "unverifiable". These pin the properties an external resolver depends on —
 * and the key-status semantics that make rotation safe and revocation final.
 */

const HOST = "trustdpp.co";
const ORG_DID = `did:web:${HOST}:org_x`;

const key = (fragment: string, status: string) => ({
  fragment,
  publicKeyMultibase: `z6Mk${fragment}TestKeyMaterialPlaceholder00000000`,
  status,
});

describe("didWebHost", () => {
  it("derives from CREDENTIAL_ORIGIN — the permanent domain, not APP_URL", () => {
    // The host lands in every issuer DID and therefore in immutable signed
    // bytes. Deriving it from the per-environment APP_URL is what minted
    // `did:web:localhost%3A8080:org_x` into real credentials.
    expect(didWebHost()).toBe(new URL(config.credentialOrigin).host.replace(":", "%3A"));
    expect(didWebHost()).toBe(HOST);
  });

  it("percent-encodes a port so it is not read as a path segment", () => {
    // did:web §3.2 — `did:web:localhost:8080:org_x` resolves as host "localhost"
    // with path "8080/org_x", which is how the loader once lost its keys.
    expect(didWebHostOf("did:web:localhost%3A8080:org_x")).toBe("localhost%3A8080");
    // Historical raw-colon dev DIDs still parse to the same encoded host.
    expect(didWebHostOf("did:web:localhost:8080:org_x")).toBe("localhost%3A8080");
    expect(didWebHostOf("did:web:trustdpp.co:org_x#key-1")).toBe(HOST);
    expect(didWebHostOf("did:ethr:0xabc")).toBeNull();
  });

  it("flags DIDs minted under a host this instance does not serve", () => {
    expect(didHostMismatch(`did:web:${HOST}:org_x`)).toBe(false);
    expect(didHostMismatch("did:web:trustdpp.io:org_x")).toBe(true);
    expect(didHostMismatch("did:web:localhost%3A8080:org_x")).toBe(true);
  });
});

describe("issuer DID document", () => {
  it("publishes an active key in both verificationMethod and assertionMethod", () => {
    const doc = buildActorOrgDidDoc(ORG_DID, "Nordic Cotton", [key("key-1", "active")]);

    expect(doc.id).toBe(ORG_DID);
    expect(doc["@context"]).toContain("https://w3id.org/security/multikey/v1");
    expect(doc.verificationMethod).toEqual([
      { id: `${ORG_DID}#key-1`, type: "Multikey", controller: ORG_DID, publicKeyMultibase: expect.any(String) },
    ]);
    // A proof is only authorized if its verificationMethod appears here.
    expect(doc.assertionMethod).toEqual([`${ORG_DID}#key-1`]);
  });

  it("KEEPS retired keys in both lists so pre-rotation proofs still verify", () => {
    const doc = buildActorOrgDidDoc(ORG_DID, "Nordic Cotton", [
      key("key-1", "retired"),
      key("key-2", "active"),
    ]);
    // Dropping a retired key from assertionMethod would break every credential
    // signed before the rotation — "retired" means "we stopped signing with it",
    // not "it was compromised".
    expect(doc.assertionMethod).toEqual([`${ORG_DID}#key-1`, `${ORG_DID}#key-2`]);
    expect(doc.verificationMethod).toHaveLength(2);
  });

  it("REMOVES revoked keys from both lists so their signatures die", () => {
    const doc = buildActorOrgDidDoc(ORG_DID, "Nordic Cotton", [
      key("key-1", "revoked"),
      key("key-2", "active"),
    ]);
    expect(doc.assertionMethod).toEqual([`${ORG_DID}#key-2`]);
    expect(doc.verificationMethod).toHaveLength(1);
    expect(JSON.stringify(doc)).not.toContain("#key-1");
  });

  it("omits the Multikey context AND the key properties when no key is published", () => {
    const doc = buildActorOrgDidDoc(ORG_DID, "Nordic Cotton", []);
    expect(doc["@context"]).toEqual(["https://www.w3.org/ns/did/v1"]);
    // An empty `verificationMethod: []` was legal but noisy — absence is cleaner.
    expect(doc).not.toHaveProperty("verificationMethod");
    expect(doc).not.toHaveProperty("assertionMethod");
  });
});

describe("platform + product DID documents", () => {
  it("the platform DID controls itself", () => {
    const doc = buildOrgDidDoc([key("key-1", "active")]);
    expect(doc.id).toBe(`did:web:${HOST}`);
    expect(doc.controller).toBe(`did:web:${HOST}`);
  });

  it("a product DID is keyless and points at its passport", () => {
    // Products are SUBJECTS, never issuers — a product that could sign would
    // let a passport attest to itself.
    const doc = buildProductDidDoc(`did:web:${HOST}:prod_1`, "dpp_1");
    expect(doc).not.toHaveProperty("assertionMethod");
    expect(doc).not.toHaveProperty("verificationMethod");
    expect(doc.service?.[0]).toMatchObject({
      type: "DigitalProductPassport",
      serviceEndpoint: `${config.appUrl}/passport/dpp_1`,
    });
    expect(doc.controller).toBe(`did:web:${HOST}`);
  });

  it("binds the GS1 identity via alsoKnownAs when a GTIN is registered", () => {
    // A regulator resolving /01/<gtin> and a verifier holding a credential about
    // the DID must be able to connect the two identities — alsoKnownAs is the
    // registered DID property for exactly this. GTIN is zero-padded to GTIN-14
    // (the canonical GS1 DL form); canonical id.gs1.org first, our resolver second.
    const doc = buildProductDidDoc(`did:web:${HOST}:prod_1`, "dpp_1", "4056205334071");
    expect(doc.alsoKnownAs).toEqual([
      "https://id.gs1.org/01/04056205334071",
      `${config.appUrl}/01/04056205334071`,
    ]);

    // No GTIN (or an invalid one) → the property is absent, never empty/bogus.
    expect(buildProductDidDoc(`did:web:${HOST}:prod_1`, "dpp_1")).not.toHaveProperty("alsoKnownAs");
    expect(buildProductDidDoc(`did:web:${HOST}:prod_1`, "dpp_1", "not-a-gtin")).not.toHaveProperty("alsoKnownAs");
  });
});
