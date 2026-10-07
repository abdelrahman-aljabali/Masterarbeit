import { describe, it, expect, afterAll } from "vitest";
import zlib from "zlib";
import { PrismaClient } from "@prisma/client";
import { signWithSubject, verifySignedCredential } from "./sign.js";
import { rotateKey, listPublicKeys } from "./signingKeys.js";
import { encodeBitstring, BITSTRING_BYTES } from "./statusList.js";

const hasDb = !!process.env.DATABASE_URL;
const prisma = new PrismaClient();

// A throwaway signing subject: rotation must never touch real org keys.
const SUBJECT = `test_rotation_${Date.now()}`;
const ISSUER_DID = `did:web:localhost%3A8080:${SUBJECT}`;

const envelope = (n: number) => ({
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  id: `urn:uuid:00000000-0000-4000-8000-00000000000${n}`,
  type: ["VerifiableCredential"],
  issuer: ISSUER_DID,
  validFrom: new Date().toISOString(),
  credentialSubject: { id: `urn:example:${n}` },
});

describe.skipIf(!hasDb)("key rotation", () => {
  afterAll(async () => {
    await prisma.signingKey.deleteMany({ where: { subjectId: SUBJECT } });
    await prisma.$disconnect();
  });

  it("a credential signed BEFORE rotation still verifies AFTER rotation", async () => {
    const signedV1 = await signWithSubject(prisma, envelope(1), ISSUER_DID, SUBJECT);
    expect((signedV1.proof as { verificationMethod: string }).verificationMethod).toContain("#key-1");
    expect((await verifySignedCredential(prisma, signedV1)).verified).toBe(true);

    await rotateKey(prisma, SUBJECT);

    // Old signature keeps verifying (retired public key stays resolvable)…
    expect((await verifySignedCredential(prisma, signedV1)).verified).toBe(true);

    // …and NEW signatures use key-2.
    const signedV2 = await signWithSubject(prisma, envelope(2), ISSUER_DID, SUBJECT);
    expect((signedV2.proof as { verificationMethod: string }).verificationMethod).toContain("#key-2");
    expect((await verifySignedCredential(prisma, signedV2)).verified).toBe(true);
  });

  it("the DID key list retires the old key but keeps it resolvable", async () => {
    const keys = await listPublicKeys(prisma, SUBJECT);
    expect(keys.map((k) => [k.fragment, k.status])).toEqual([
      ["key-1", "retired"],
      ["key-2", "active"],
    ]);
  });
});

describe("bitstring status list encoding", () => {
  it("gzips + base64url-encodes with the multibase 'u' prefix, round-trips a set bit", () => {
    const bits = Buffer.alloc(BITSTRING_BYTES);
    bits[0] |= 0x80 >> 3; // index 3 revoked (left-most-bit-first order)
    const encoded = encodeBitstring(bits);
    expect(encoded.startsWith("u")).toBe(true);
    const decoded = zlib.gunzipSync(Buffer.from(encoded.slice(1), "base64url"));
    expect(decoded.length).toBe(BITSTRING_BYTES);
    expect(decoded[0] & (0x80 >> 3)).not.toBe(0); // index 3 set
    expect(decoded[0] & (0x80 >> 2)).toBe(0);     // neighbors clear
  });
});
