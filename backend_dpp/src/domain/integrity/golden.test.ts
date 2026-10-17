import { describe, it, expect } from "vitest";
import { stableStringify, canonicalHash } from "./hash.js";
import { passportUuid, PASSPORT_NAMESPACE } from "./uuid.js";
import { CONTEXT_URL, SCHEMA_URL, credentialIdUrl, DPP_CONTEXT_V3 } from "../trust/index.js";
import { DPP_FIELDS, PHASE1_MANDATORY, getStageById } from "../../dpp-core/index.js";

/**
 * ─── GOLDEN VECTORS — the frozen-format contract ──────────────────────────────
 * These byte-exact expectations pin every deterministic format that published,
 * signed artifacts depend on FOREVER: canonical hashing (audit chain, version
 * hashes), the v5 UUID derivation, and the pinned credential URLs.
 */

describe("stableStringify (canonical serializer)", () => {
  it("sorts object keys recursively, preserves array order", () => {
    expect(stableStringify({ b: 2, a: 1, c: { z: 9, y: [3, 1] } }))
      .toBe('{"a":1,"b":2,"c":{"y":[3,1],"z":9}}');
  });

  // ── P4-3 hardening (deliberate, versioned change of the pinned edge cases) ──
  // Old behavior: `{k: undefined}` → the literal text `{"k":undefined}` (not JSON)
  // and any Date → `{}` (all Dates aliased to identical bytes). Both were
  // silent-corruption hazards. New behavior: undefined/function values throw; Date
  // serializes as its ISO instant.
  it("hardened: undefined inside an object THROWS (was literal `undefined` text)", () => {
    expect(() => stableStringify({ k: undefined })).toThrow(/unserializable/);
  });
  it("hardened: function values THROW", () => {
    expect(() => stableStringify({ k: () => 1 })).toThrow(/unserializable/);
  });
  it("hardened: Date serializes as its ISO instant (was {})", () => {
    expect(stableStringify(new Date("2026-01-01T00:00:00Z"))).toBe('"2026-01-01T00:00:00.000Z"');
    expect(stableStringify({ at: new Date("2026-01-01T00:00:00Z") })).toBe('{"at":"2026-01-01T00:00:00.000Z"}');
  });
});

describe("canonicalHash (sha256 over stableStringify)", () => {
  it("simple object", () => {
    expect(canonicalHash({ hello: "world" }))
      .toBe("93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588");
  });
  it("audit-chain payload shape (genesis event)", () => {
    expect(canonicalHash({
      content: {
        at: "2026-01-01T00:00:00.000Z",
        action: "passport.publish",
        actorUserId: null,
        orgId: "org_test",
        targetType: "passport",
        targetId: "dpp_test",
        details: { version: 1 },
        seq: 1,
      },
      prevHash: null,
    })).toBe("dd037919c823b1aa7e4aba130644e9ed4a5bb15fe183a765b39d1fbe10cddf4e");
  });
});

describe("passportUuid (RFC 9562 v5, frozen namespace)", () => {
  it("namespace is frozen", () => {
    expect(PASSPORT_NAMESPACE).toBe("c7b3f8e2-4a61-4d05-9b2e-6f1d8a0c5e93");
  });
  it("derives deterministically", () => {
    expect(passportUuid("dpp_test_001")).toBe("942e5944-fb62-58cf-b862-116dd404fe5c");
    expect(passportUuid("dpp_shirt_001")).toBe("d94bdacf-92cf-515a-ad76-508ab05ce8bf");
  });
});

describe("pinned trust-layer URLs (frozen into signed bytes)", () => {
  // VERSIONED CHANGE (pre-production domain cutover): the canonical origin was
  // rebound trustdpp.io → trustdpp.co, the real owned domain, BEFORE any
  // production credential was signed. Safe precisely because nothing real is
  // bound to the old value yet. After the first prod publish this becomes
  // permanent again — a red vector here is then a STOP, not a value to update.
  it("context / schema / credential-id base pin to the canonical origin, not APP_URL", () => {
    expect(CONTEXT_URL).toBe("https://trustdpp.co/contexts/dpp-v1.jsonld");
    expect(SCHEMA_URL).toBe("https://trustdpp.co/schemas/dpp-tier-credential.v1.json");
    expect(credentialIdUrl("vc_abc")).toBe("https://trustdpp.co/api/public/credentials/vc_abc");
  });
});

describe("dpp-core catalog invariants", () => {
  it("no vcPath uses forbidden [] notation", () => {
    expect(DPP_FIELDS.filter((f) => f.vcPath.includes("[]"))).toEqual([]);
  });
  it("every field's stage exists in its sector's stage vocabulary", () => {
    const orphans = DPP_FIELDS.filter((f) => getStageById(String(f.stage))?.sector !== f.sector);
    expect(orphans).toEqual([]);
  });
  it("phase-1 mandatory set is non-empty and excludes system-owned fields", () => {
    expect(PHASE1_MANDATORY.length).toBeGreaterThan(0);
    expect(PHASE1_MANDATORY.every((f) => !f.systemOwned)).toBe(true);
  });

  // ── Context v3 byte pin (R-21) ───────────────────────────────────────────── v3
  // is GENERATED from the dpp-core catalog, so an innocuous catalog edit silently
  // changes the bytes every new credential is signed against — and the change is
  // invisible until an external verifier rejects a signature. v1 and v2 are
  // literals and cannot drift; v3 can, so it gets a hash pin.
  it("context v3 bytes are pinned — generated context must not drift", () => {
    expect(Object.keys((DPP_CONTEXT_V3 as Record<string, Record<string, unknown>>)["@context"]).length).toBe(154);
    expect(canonicalHash(DPP_CONTEXT_V3)).toBe(
      "8324c6c19aa7bd44693dcedff4e4bb7e65cff2224a9255cfa4b817394ad152e3",
    );
  });

});
