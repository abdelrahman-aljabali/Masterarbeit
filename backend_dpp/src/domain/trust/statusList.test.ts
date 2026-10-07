import { describe, it, expect, afterAll, beforeEach } from "vitest";
import { PrismaClient } from "@prisma/client";
import {
  allocateStatusIndex,
  setStatusBit,
  buildStatusListCredential,
  buildStatusListEnvelope,
  encodeBitstring,
  permuteIndex,
  BITSTRING_BYTES,
  STATUS_LIST_TTL_MS,
} from "./statusList.js";
import { verifySignedCredential } from "./sign.js";

/**
 * ─── BitstringStatusList: concurrency + serving contract ──────────────────────
 * The two tests that matter here are REGRESSION tests for silent data races that
 * shipped. Both mutations used to be read-modify-write round trips under
 * Postgres' default READ COMMITTED isolation:
 */

const hasDb = !!process.env.DATABASE_URL;
const prisma = new PrismaClient();

// StatusList has no FK to Organization, so a synthetic issuer id is safe.
const ORG = `test_sl_${Date.now()}`;
const ISSUER_DID = `did:web:localhost%3A8080:${ORG}`;

describe.skipIf(!hasDb)("BitstringStatusList — concurrency", () => {
  beforeEach(async () => {
    await prisma.statusList.deleteMany({ where: { orgId: ORG } });
  });

  afterAll(async () => {
    await prisma.statusList.deleteMany({ where: { orgId: ORG } });
    await prisma.signingKey.deleteMany({ where: { subjectId: ORG } });
    await prisma.$disconnect();
  });

  it("concurrent allocations never hand out the same index", async () => {
    const N = 24;
    const indexes = await Promise.all(
      Array.from({ length: N }, () => allocateStatusIndex(prisma, ORG)),
    );

    // Distinctness is the whole property: a shared index aliases two
    // credentials onto one revocation bit.
    expect(new Set(indexes).size).toBe(N);
    for (const i of indexes) {
      expect(i).toBeGreaterThanOrEqual(0);
      expect(i).toBeLessThan(BITSTRING_BYTES * 8);
    }
    // The COUNTER accounts for exactly what was handed out (capacity tracking),
    // even though the public indexes are a permutation, not the counter values.
    const row = await prisma.statusList.findUniqueOrThrow({
      where: { orgId_list: { orgId: ORG, list: 1 } },
    });
    expect(row.nextIndex).toBe(N);
  });

  it("indexes are RANDOMIZED, not sequential (herd privacy)", async () => {
    const N = 16;
    const indexes: number[] = [];
    for (let i = 0; i < N; i++) indexes.push(await allocateStatusIndex(prisma, ORG));

    // Sequential assignment leaks issuance order + volume — the very thing the
    // spec-minimum 131,072-entry list exists to hide. A fresh list must scatter.
    // (A random permutation emitting 0,1,2,…,15 in order has probability
    // ~1/131072^16 — if this ever fails, the permutation is broken, not unlucky.)
    expect(indexes).not.toEqual(Array.from({ length: N }, (_, i) => i));
    // Bijectivity in practice: still perfectly distinct.
    expect(new Set(indexes).size).toBe(N);
  });

  it("a LEGACY list (no permSeed) stays on the identity mapping forever", async () => {
    // A list created before seeding already issued sequential indexes into
    // signed credentials. Permuting its future allocations would collide them
    // with issued ones — one bit serving two credentials, aliased revocation.
    await prisma.statusList.create({
      data: { orgId: ORG, list: 1, bitstring: Buffer.alloc(BITSTRING_BYTES), nextIndex: 5, permSeed: null },
    });
    expect(await allocateStatusIndex(prisma, ORG)).toBe(5);
    expect(await allocateStatusIndex(prisma, ORG)).toBe(6);
  });

  it("the permutation is a bijection into the index space", () => {
    const seed = Buffer.alloc(32, 7);
    const seen = new Set<number>();
    for (let counter = 0; counter < 4096; counter++) {
      const idx = permuteIndex(seed, counter);
      expect(idx).toBeGreaterThanOrEqual(0);
      expect(idx).toBeLessThan(BITSTRING_BYTES * 8);
      seen.add(idx);
    }
    expect(seen.size).toBe(4096); // no collisions — counter capacity = real capacity
    // Deterministic: the same counter always maps to the same index.
    expect(permuteIndex(seed, 123)).toBe(permuteIndex(seed, 123));
    // And a null seed is the identity (legacy lists).
    expect(permuteIndex(null, 123)).toBe(123);
  });

  it("concurrent allocations on a NEW list survive the lazy-create race", async () => {
    // Every caller races to create the row; the losers must fall back to the
    // winner's row rather than surfacing a unique-constraint 500.
    const indexes = await Promise.all(
      Array.from({ length: 8 }, () => allocateStatusIndex(prisma, ORG)),
    );
    expect(new Set(indexes).size).toBe(8);
  });

  it("concurrent revocations do not lose each other's bits", async () => {
    const indexes = await Promise.all(
      Array.from({ length: 16 }, () => allocateStatusIndex(prisma, ORG)),
    );

    await Promise.all(
      indexes.map((i) => prisma.$transaction((tx) => setStatusBit(tx, ORG, i, true))),
    );

    const row = await prisma.statusList.findUniqueOrThrow({
      where: { orgId_list: { orgId: ORG, list: 1 } },
    });
    const buf = Buffer.from(row.bitstring);
    for (const i of indexes) {
      expect(buf[i >> 3]! & (0x80 >> (i & 7))).not.toBe(0);
    }
  });

  it("clearing a bit leaves its neighbours alone", async () => {
    const a = await allocateStatusIndex(prisma, ORG);
    const b = await allocateStatusIndex(prisma, ORG);
    await prisma.$transaction((tx) => setStatusBit(tx, ORG, a, true));
    await prisma.$transaction((tx) => setStatusBit(tx, ORG, b, true));
    await prisma.$transaction((tx) => setStatusBit(tx, ORG, a, false));

    const row = await prisma.statusList.findUniqueOrThrow({
      where: { orgId_list: { orgId: ORG, list: 1 } },
    });
    const buf = Buffer.from(row.bitstring);
    expect(buf[a >> 3]! & (0x80 >> (a & 7))).toBe(0);
    expect(buf[b >> 3]! & (0x80 >> (b & 7))).not.toBe(0);
  });

  it("rejects an out-of-range index instead of corrupting a random byte", async () => {
    await allocateStatusIndex(prisma, ORG);
    await expect(
      prisma.$transaction((tx) => setStatusBit(tx, ORG, BITSTRING_BYTES * 8, true)),
    ).rejects.toThrow(/out of range/);
  });
});

describe.skipIf(!hasDb)("BitstringStatusList — signed serving", () => {
  afterAll(async () => {
    await prisma.statusList.deleteMany({ where: { orgId: ORG } });
    await prisma.signingKey.deleteMany({ where: { subjectId: ORG } });
  });

  it("the served list is a credential that actually verifies", async () => {
    await allocateStatusIndex(prisma, ORG);
    const credential = await buildStatusListCredential(prisma, ORG, ISSUER_DID);

    expect(credential.type).toEqual(["VerifiableCredential", "BitstringStatusListCredential"]);
    // Status checking a status-list credential would recurse; it carries no
    // credentialStatus of its own, so this is the pure signature verdict.
    const verdict = await verifySignedCredential(prisma, credential, { includeStatusCheck: false });
    expect(verdict.verified).toBe(true);
    expect(verdict.cryptosuite).toBe("eddsa-rdfc-2022");
  });

  it("is cached between requests, and re-signed after a bit flips", async () => {
    const index = await allocateStatusIndex(prisma, ORG);

    const first = await buildStatusListCredential(prisma, ORG, ISSUER_DID);
    const second = await buildStatusListCredential(prisma, ORG, ISSUER_DID);
    // Cached: identical bytes, no fresh RDFC canonicalization + Ed25519 per GET.
    expect(second).toEqual(first);

    await prisma.$transaction((tx) => setStatusBit(tx, ORG, index, true));

    const third = await buildStatusListCredential(prisma, ORG, ISSUER_DID);
    // A flipped bit MUST invalidate the cache — serving the old signed bytes
    // would tell verifiers the credential is still valid.
    expect(third).not.toEqual(first);
    expect((await verifySignedCredential(prisma, third, { includeStatusCheck: false })).verified).toBe(true);

    const subject = third.credentialSubject as { encodedList: string };
    const expected = Buffer.alloc(BITSTRING_BYTES);
    expected[index >> 3]! |= 0x80 >> (index & 7);
    expect(subject.encodedList).toBe(encodeBitstring(expected));
  });
});

describe("BitstringStatusList — envelope shape", () => {
  it("bounds its own validity so a verifier cannot cache it forever", () => {
    const now = new Date("2026-07-26T12:00:00.000Z");
    const envelope = buildStatusListEnvelope("org_x", "did:web:trustdpp.co:org_x", Buffer.alloc(BITSTRING_BYTES), now);

    expect(envelope.validFrom).toBe("2026-07-26T12:00:00.000Z");
    expect(envelope.validUntil).toBe(new Date(now.getTime() + STATUS_LIST_TTL_MS).toISOString());
    expect(envelope.credentialSubject).toMatchObject({
      type: "BitstringStatusList",
      statusPurpose: "revocation",
    });
  });
});
