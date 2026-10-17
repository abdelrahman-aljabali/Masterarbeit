import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { PrismaClient } from "@prisma/client";
import { config } from "../../config.js";
import { signWithSubject, verifySignedCredential, makeDocumentLoader } from "./sign.js";
import { revokeKey, rotateKey, getOrCreateSigningKey, listPublicKeys } from "./signingKeys.js";
import { allocateStatusIndex, setStatusBit, statusEntryFor } from "./statusList.js";
import { buildVcEnvelope } from "./vc.js";

/**
 * ─── Credential lifecycle end-to-end ──────────────────────────────────────────
 * The signing/verification claims this platform makes to the outside world,
 * exercised against a real database: signing, tampering, and revocation.
 */

const hasDb = !!process.env.DATABASE_URL;
const prisma = new PrismaClient();

const SUBJECT = `test_lifecycle_${Date.now()}`;
const ISSUER_DID = `did:web:trustdpp.co:${SUBJECT}`;
const PRODUCT_DID = `did:web:trustdpp.co:prod_${SUBJECT}`;

function envelope(n: number, extra: Record<string, unknown> = {}) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://trustdpp.co/contexts/dpp-v3.jsonld"],
    id: `https://trustdpp.co/api/public/credentials/vc_test_${n}`,
    type: ["VerifiableCredential", "DppTierCredential"],
    issuer: ISSUER_DID,
    validFrom: "2026-07-26T00:00:00.000Z",
    credentialSubject: { id: PRODUCT_DID, role: "weaving", ...extra },
  };
}

describe.skipIf(!hasDb)("credential lifecycle", () => {
  beforeAll(async () => {
    await getOrCreateSigningKey(prisma, SUBJECT);
  });

  afterAll(async () => {
    await prisma.signingKey.deleteMany({ where: { subjectId: SUBJECT } });
    await prisma.statusList.deleteMany({ where: { orgId: SUBJECT } });
    await prisma.$disconnect();
  });

  it("a signed credential verifies, and reports what verified it", async () => {
    const signed = await signWithSubject(prisma, envelope(1), ISSUER_DID, SUBJECT);
    const verdict = await verifySignedCredential(prisma, signed);

    expect(verdict.verified).toBe(true);
    expect(verdict.issuer).toBe(ISSUER_DID);
    expect(verdict.role).toBe("weaving");
    // The stamp that lets a cached verdict be invalidated when the verifier
    // changes (mode switch, cryptosuite change, key revocation).
    expect(verdict.mode).toBe("design-b");
    expect(verdict.cryptosuite).toBe("eddsa-rdfc-2022");
    expect(verdict.verificationMethod).toBe(`${ISSUER_DID}#key-1`);
  });

  it("an unsigned credential verifies as UNSIGNED, never as valid", async () => {
    const verdict = await verifySignedCredential(prisma, envelope(2));
    expect(verdict.verified).toBe(false);
    expect(verdict.error).toMatch(/unsigned/);
  });

  it("tampering with the subject after signing breaks the proof", async () => {
    const signed = await signWithSubject(prisma, envelope(3, { fibers: ["cotton 95%", "elastane 5%"] }), ISSUER_DID, SUBJECT);
    expect((await verifySignedCredential(prisma, signed)).verified).toBe(true);

    const tampered = {
      ...signed,
      credentialSubject: { ...(signed.credentialSubject as object), role: "dyeing" },
    };
    expect((await verifySignedCredential(prisma, tampered)).verified).toBe(false);
  });

  it("reordering an @list array breaks the proof (composition order is signed data)", async () => {
    // The v2 context marks order-significant arrays as @container: @list. Without
    // it, "95% cotton, 5% elastane" and "5% cotton, 95% elastane" canonicalize
    // identically — this test is what keeps that fix from silently regressing.
    const signed = await signWithSubject(prisma, envelope(4, { fibers: ["cotton 95%", "elastane 5%"] }), ISSUER_DID, SUBJECT);
    const reordered = {
      ...signed,
      credentialSubject: { ...(signed.credentialSubject as object), fibers: ["elastane 5%", "cotton 95%"] },
    };
    expect((await verifySignedCredential(prisma, reordered)).verified).toBe(false);
  });

  it("flipping the revocation bit makes the credential fail verification", async () => {
    const index = await allocateStatusIndex(prisma, SUBJECT);
    const withStatus = { ...envelope(5), credentialStatus: statusEntryFor(SUBJECT, index) };
    const signed = await signWithSubject(prisma, withStatus, ISSUER_DID, SUBJECT);

    // Valid while the bit is clear…
    expect((await verifySignedCredential(prisma, signed)).verified).toBe(true);
    // …and the SIGNATURE-only verdict must stay true after revocation, because
    // that verdict is cached per immutable version and revocation is live state.
    await prisma.$transaction((tx) => setStatusBit(tx, SUBJECT, index, true));
    expect((await verifySignedCredential(prisma, signed, { includeStatusCheck: false })).verified).toBe(true);

    // With the status check on, a revoked credential does NOT verify (W3C semantics).
    const revoked = await verifySignedCredential(prisma, signed);
    expect(revoked.verified).toBe(false);
    expect(revoked.error).toMatch(/revoked/i);
  });

  it("REVOKING A KEY kills its signatures; rotating one does not", async () => {
    const subject = `${SUBJECT}_keys`;
    const did = `did:web:trustdpp.co:${subject}`;
    const env = { ...envelope(6), issuer: did };

    const signedUnderKey1 = await signWithSubject(prisma, env, did, subject);
    expect((await verifySignedCredential(prisma, signedUnderKey1)).verified).toBe(true);

    // Rotation is non-destructive: key-1 is retired but stays resolvable.
    await rotateKey(prisma, subject);
    expect((await verifySignedCredential(prisma, signedUnderKey1)).verified).toBe(true);

    // Revocation is destructive by design — this is the whole point of the
    // compromise path, and nothing verified it before.
    await revokeKey(prisma, subject, { fragment: "key-1", reason: "test compromise", issuerDid: did });
    const after = await verifySignedCredential(prisma, signedUnderKey1);
    expect(after.verified).toBe(false);

    // A replacement stays available so the org can keep publishing.
    const keys = await listPublicKeys(prisma, subject);
    expect(keys.find((k) => k.fragment === "key-1")?.status).toBe("revoked");
    expect(keys.some((k) => k.status === "active")).toBe(true);

    await prisma.signingKey.deleteMany({ where: { subjectId: subject } });
  });
});

describe.skipIf(!hasDb)("offline document loader — host gate", () => {
  const wasProduction = config.isProduction;
  // Its own subject: the lifecycle suite above deletes its keys in afterAll.
  const LOADER_SUBJECT = `test_loader_${Date.now()}`;

  beforeAll(async () => {
    await getOrCreateSigningKey(prisma, LOADER_SUBJECT);
  });

  afterAll(async () => {
    config.isProduction = wasProduction;
    await prisma.signingKey.deleteMany({ where: { subjectId: LOADER_SUBJECT } });
  });

  it("refuses to resolve a did:web on a host this platform never minted under", async () => {
    // The gate is production-only (dev APP_URLs churn), so assert it where it
    // actually runs. Without it, `did:web:evil.example:<orgId>` would resolve
    // from OUR database and borrow the real org's public key — letting an
    // attacker present a foreign-host DID that verifies against our keys.
    config.isProduction = true;
    const loader = makeDocumentLoader(prisma);

    await expect(loader(`did:web:evil.example:${LOADER_SUBJECT}`)).rejects.toThrow(/Refusing to resolve did:web host/);
    await expect(loader(`did:web:evil.example:${LOADER_SUBJECT}#key-1`)).rejects.toThrow(/Refusing to resolve did:web host/);
  });

  it("still resolves our own host, and never fetches the network", async () => {
    config.isProduction = true;
    const loader = makeDocumentLoader(prisma);

    const own = await loader(`did:web:trustdpp.co:${LOADER_SUBJECT}#key-1`);
    expect((own.document as { type: string }).type).toBe("Multikey");

    await expect(loader("https://example.com/some-context.jsonld")).rejects.toThrow(/Refusing to load remote document/);
  });
});

describe("envelope construction", () => {
  it("pins the unsigned envelope shape for fixed inputs", () => {
    // Golden vector for the SIGNING INPUT. The signature itself is not pinned
    // (fresh keys + a `created` timestamp make it non-deterministic), but the
    // bytes that get canonicalized are — and those are what a format drift
    // would silently change, breaking verification of everything already signed.
    const built = buildVcEnvelope({
      credential: {
        role: "weaving",
        issuerDid: ISSUER_DID,
        credentialSubject: { facilityCountry: "PT", layers: [{ id: 1, material: "paper" }] },
      } as never,
      id: "https://trustdpp.co/api/public/credentials/vc_golden",
      productDid: PRODUCT_DID,
      brandOrgDid: null,
      validFrom: new Date("2026-07-26T00:00:00.000Z"),
      validUntil: new Date("2031-07-26T00:00:00.000Z"),
      credentialStatus: statusEntryFor("org_golden", 7),
    });

    expect(built).toEqual({
      "@context": ["https://www.w3.org/ns/credentials/v2", "https://trustdpp.co/contexts/dpp-v3.jsonld"],
      type: ["VerifiableCredential", "DppTierCredential"],
      id: "https://trustdpp.co/api/public/credentials/vc_golden",
      issuer: ISSUER_DID,
      validFrom: "2026-07-26T00:00:00.000Z",
      validUntil: "2031-07-26T00:00:00.000Z",
      credentialSchema: {
        id: "https://trustdpp.co/schemas/dpp-tier-credential.v2.json",
        type: "JsonSchema",
      },
      credentialStatus: {
        id: "https://trustdpp.co/status/org_golden/1#7",
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListCredential: "https://trustdpp.co/status/org_golden/1",
        statusListIndex: "7",
      },
      credentialSubject: {
        id: PRODUCT_DID,
        role: "weaving",
        facilityCountry: "PT",
        // The numeric UI row key is dropped: a non-string `id` makes JSON-LD
        // expansion (and therefore signing) fail on "@id must be a string".
        layers: [{ material: "paper" }],
      },
    });
  });
});
