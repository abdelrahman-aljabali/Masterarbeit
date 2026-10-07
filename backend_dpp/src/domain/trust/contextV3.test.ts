import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
// @ts-expect-error — jsonld ships no types; it is the reference JSON-LD processor
import jsonld from "jsonld";
import { contexts as credentialsContexts } from "@digitalbazaar/credentials-context";
import { DPP_CONTEXT_V3, vocabDictionary } from "./vcContext.js";
import { CONTEXT_URL_V3, VOCAB_URL, VOCAB_UNREGISTERED_URL } from "./trustUrls.js";
import { buildVcEnvelope } from "./vc.js";
import { statusEntryFor } from "./statusList.js";

/**
 * ─── Context v3 — the @vocab drift guard (H1) ─────────────────────────────────
 * v1/v2 minted every subject term through `@vocab`: a renamed producer field or
 * a typo silently changed term IRIs in newly signed credentials — a semantic
 * break no test could catch, flagged as the top standards risk in the 2026-07
 * compliance review. v3 defines every term explicitly and demotes `@vocab` to a
 * QUARANTINE namespace. This suite is the tripwire:
 */

const DOCS = new Map<string, unknown>([[CONTEXT_URL_V3, DPP_CONTEXT_V3]]);
for (const [url, doc] of credentialsContexts) DOCS.set(url, doc);

const documentLoader = (url: string) => {
  const document = DOCS.get(url);
  if (!document) throw new Error(`no local context for ${url}`);
  return Promise.resolve({ contextUrl: null, documentUrl: url, document });
};

/** A golden envelope exercising EVERY subject shape the platform can sign:
 *  nested groups, all four object-array kinds, dates, numbers, booleans. */
function goldenEnvelope(): Record<string, unknown> {
  const base = buildVcEnvelope({
    credential: {
      role: "brand",
      issuerDid: "did:web:trustdpp.co:org_x",
      credentialSubject: {
        passport: { id: "urn:uuid:00000000-0000-5000-8000-000000000001", version: "1", status: "published", issuedAt: "2026-07-30", language: "EN", expiresAt: "2036-01-01" },
        product: { did: "did:web:trustdpp.co:prod_1", partId: "P-1", codeKey: "GTIN", granularity: "item", classification: { code: "C1", standard: "GPC" } },
        economicOperator: { name: "Org X", address: "Street 1", contact: "x@example.com", identifier: "VAT DE1" },
        origin: { country: "PT — Portugal", responsibleOperator: "VAT DE1" },
        composition: { fibers: [{ pct: 95, label: "Organic Cotton", origin: "India" }, { pct: 5, label: "Elastane", origin: "Italy" }] },
        substances: { present: true, items: [{ cas: "50-00-0", hazard: "CMR — Carcinogenic / Mutagenic / Reprotoxic", location: "print", concentration: "0.05" }] },
        transport: { legs: [{ from: "Porto", to: "Berlin", mode: "rail", distanceKm: 2480, weightKg: 500 }] },
        packaging: { layers: [{ role: "Primary", materialType: "paper", weightGrams: 20, recyclabilityGrade: "A", recycledContentPct: 40, disposalInstructions: "Paper recycling", reusable: true, compostable: false, selectedSymbols: ["iso7000"] }] },
        certifications: [{ scheme: "GOTS — Global Organic Textile Standard", number: "GOTS-1", scope: "95% organic", certifier: "Control Union", expiryDate: "2027-03-31", evidenceUrl: "https://example.com/cert.pdf" }],
        environmental: { recyclabilityPct: 87, waterLPerKg: 18 },
        manufacturing: { facilityId: "F-1" },
        fabric: { construction: "Woven", weightGsm: 458 },
      },
    } as never,
    id: "https://trustdpp.co/api/public/credentials/vc_ctx_golden",
    productDid: "did:web:trustdpp.co:prod_1",
    brandOrgDid: null,
    validFrom: new Date("2026-07-30T00:00:00.000Z"),
    validUntil: new Date("2036-01-01T00:00:00.000Z"),
    credentialStatus: statusEntryFor("org_x", 7),
  });
  return base as unknown as Record<string, unknown>;
}

/** Every IRI (predicates, types, datatypes) in an expanded JSON-LD document. */
function collectIris(node: unknown, out: Set<string>): void {
  if (Array.isArray(node)) return node.forEach((n) => collectIris(n, out));
  if (node === null || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k.startsWith("http")) out.add(k);
    if (k === "@type") for (const t of Array.isArray(v) ? v : [v]) if (typeof t === "string") out.add(t);
    collectIris(v, out);
  }
}

describe("context v3 — explicit semantics", () => {
  it("a fully loaded credential expands with ZERO quarantined terms", async () => {
    const expanded = await jsonld.expand(goldenEnvelope(), { documentLoader });
    const iris = new Set<string>();
    collectIris(expanded, iris);

    const quarantined = [...iris].filter((i) => i.startsWith(VOCAB_UNREGISTERED_URL));
    // A hit here means the catalog gained a vcPath (or an array gained an entry
    // key) that v3 does not define — add the term, don't loosen this test.
    expect(quarantined).toEqual([]);

    // And the vocabulary is actually in use — terms resolve into OUR namespace.
    expect([...iris].some((i) => i.startsWith(VOCAB_URL))).toBe(true);
  });

  it("a TYPO lands in quarantine (the failure mode is loud, not silent)", async () => {
    const envelope = goldenEnvelope();
    (envelope.credentialSubject as Record<string, unknown>)["enviromental"] = { oops: 1 }; // sic
    const expanded = await jsonld.expand(envelope, { documentLoader });
    const iris = new Set<string>();
    collectIris(expanded, iris);
    expect([...iris].some((i) => i.startsWith(`${VOCAB_UNREGISTERED_URL}enviromental`))).toBe(true);
  });

  it("dates are typed xsd:date; order-significant arrays stay @list", async () => {
    const expanded = await jsonld.expand(goldenEnvelope(), { documentLoader }) as unknown[];
    const json = JSON.stringify(expanded);
    expect(json).toContain("http://www.w3.org/2001/XMLSchema#date");
    expect(json).toContain("@list");
  });

  it("never redefines a term the VCDM 2.0 core context protects", () => {
    const core = Object.keys(
      (credentialsContexts.get("https://www.w3.org/ns/credentials/v2") as { "@context": Record<string, unknown> })["@context"],
    );
    const ours = Object.keys(DPP_CONTEXT_V3["@context"]).filter((k) => !k.startsWith("@"));
    const overlap = ours.filter((t) => core.includes(t) && t !== "DppTierCredential");
    expect(overlap).toEqual([]); // redefining a @protected term makes every expansion THROW
  });

  /**
   * The v3 context is served at a FROZEN URL that live Design B credentials name
   * inside their signed bytes. Its content is therefore not free to change: a
   * verifier dereferencing that URL must get what the issuer signed against, or
   * JSON-LD expansion shifts underneath credentials already in the wild.
   */
  it("the frozen v3 context bytes have not changed", () => {
    const serialized = JSON.stringify(DPP_CONTEXT_V3);
    expect(serialized.length).toBe(9262);
    expect(createHash("sha256").update(serialized).digest("hex")).toBe(
      "aad7bbed02770fea7e9a538893134b4b031029e30b6cd958a5afa0effd1b1e9e",
    );
  });

  it("every term is dereferenceable via /vocab", () => {
    const dict = vocabDictionary();
    const ctxTerms = Object.keys(DPP_CONTEXT_V3["@context"]).filter((k) => !k.startsWith("@") && k !== "DppTierCredential");
    expect(dict.terms.map((t) => t.term).sort()).toEqual(ctxTerms.sort());
    for (const t of dict.terms) expect(t.iri).toBe(`${VOCAB_URL}${t.term}`);
  });
});

