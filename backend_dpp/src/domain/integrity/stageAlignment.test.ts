import { describe, it, expect } from "vitest";
import { assembleCredentials, validateAndNormalize, canonicalFromStored } from "./canonical.js";
import { getFieldById } from "../../dpp-core/index.js";
import { DPP_STAGES, getStageById, stagesForSector, supplierStagesFor } from "../../dpp-core/index.js";

/**
 * ─── Supply Chain Taxonomy V2 alignment (AA-PAR-TAX-501-V2.0, July 2026) ──────
 * Pins the stage ladder to the harmonized apparel-alliance taxonomy (Aii,
 * Cascale, Textile Exchange, ZDHC) the EPRS study also follows. Two invariants
 * matter enough to freeze:
 */

describe("taxonomy V2 tier codes", () => {
  it("matches the official ladder (T0 brand … T4 raw material)", () => {
    const byId = Object.fromEntries(
      stagesForSector("textile").map((s) => [s.id, { tier: s.tier, order: s.order }]),
    );
    expect(byId).toEqual({
      brand:            { tier: 0, order: 0 },
      garment:          { tier: 1, order: 1 },
      dyeing:           { tier: 2, order: 2 },
      weaving:          { tier: 2, order: 3 }, // same OFFICIAL tier as dyeing — by design
      spinning:         { tier: 3, order: 4 },
      "cotton-farming": { tier: 4, order: 5 },
    });
  });

  it("orders are unique (they sequence the chain); tiers need not be", () => {
    const stages = DPP_STAGES.filter((s) => s.sector === "textile");
    expect(new Set(stages.map((s) => s.order)).size).toBe(stages.length);
  });

  it("weaving is an invitable supplier stage", () => {
    expect(supplierStagesFor("textile").map((s) => s.id)).toContain("weaving");
    expect(getStageById("weaving")?.role).toBe("supplier");
  });
});

describe("weaving credential assembly", () => {
  it("fabric-formation fields become their OWN credential, bound to the weaving node", () => {
    const canonical = {
      "textile.fabric.construction": "Woven",
      "textile.fabric.weightGsm": 458,
      "textile.composition.fibers": [{ material: "Cotton", percentage: 100 }], // spinning
      "textile.identity.countryOrigin": "TR", // cotton-farming
    };
    const nodes = [
      { id: "node_mill", roles: ["weaving"], issuerDid: "did:web:trustdpp.co:org_mill" },
      { id: "node_spin", roles: ["spinning"], issuerDid: "did:web:trustdpp.co:org_spin" },
    ];

    const credentials = assembleCredentials(canonical, nodes);
    const weaving = credentials.find((c) => c.role === "weaving");

    // The mill attests its own work — not the brand, not the dyehouse.
    expect(weaving).toBeDefined();
    expect(weaving!.nodeId).toBe("node_mill");
    expect(weaving!.issuerDid).toBe("did:web:trustdpp.co:org_mill");
    expect(weaving!.credentialSubject).toEqual({
      fabric: { construction: "Woven", weightGsm: 458 },
    });

    // And it does not leak into anyone else's credential.
    const others = credentials.filter((c) => c.role !== "weaving");
    for (const c of others) expect(JSON.stringify(c.credentialSubject)).not.toContain("fabric");
  });

  it("an unbound weaving role falls back to the brand, never to a fake issuer", () => {
    const credentials = assembleCredentials({ "textile.fabric.construction": "Knitted" }, []);
    const weaving = credentials.find((c) => c.role === "weaving");
    expect(weaving).toBeDefined();
    expect(weaving!.nodeId).toBeNull();
    expect(weaving!.issuerDid).toBeNull();
  });
});

describe("signed-bytes hygiene", () => {
  it("derived shadows are OMITTED when the authoritative field is present", () => {
    // packaging.primary.* duplicates packaging.layers[0]; transport.finalLeg.*
    // duplicates transport.legs[last]. One fact, one spelling, in signed bytes.
    const canonical = {
      "textile.supply.legs": [{ from: "Porto", to: "Berlin", mode: "rail", distanceKm: 2480 }],
      "textile.supply.legFrom": "Porto",
      "textile.supply.legTo": "Berlin",
      "textile.supply.legDistance": 2480,
      "textile.packaging.layers": [{ role: "Primary", materialType: "paper", weightGrams: 20 }],
      "textile.packaging.role": "Primary",
      "textile.packaging.weight": 20,
    };
    const [brand] = assembleCredentials(canonical, []);
    const subject = brand.credentialSubject as Record<string, Record<string, unknown>>;
    expect(subject.transport).toHaveProperty("legs");
    expect(subject.transport).not.toHaveProperty("finalLeg");
    expect(subject.packaging).toHaveProperty("layers");
    expect(subject.packaging).not.toHaveProperty("primary");
  });

  it("…but a LEGACY passport with only the single-leg fields keeps them", () => {
    // Omitting unconditionally would erase transport data from passports that
    // never had the multi-leg array. The shadow rule is conditional by design.
    const [brand] = assembleCredentials({ "textile.supply.legFrom": "Porto", "textile.supply.legTo": "Berlin" }, []);
    const subject = brand.credentialSubject as Record<string, Record<string, unknown>>;
    expect(subject.transport).toHaveProperty("finalLeg");
  });

  it("numeric-looking strings in array entries are coerced to numbers", () => {
    // Row editors submit strings; signed bytes must not carry "6200" next to 6200.
    const spec = getFieldById("textile.supply.legs")!;
    const r = validateAndNormalize(spec, [
      { from: "India", to: "Bangladesh", mode: "air", distanceKm: "6200", weightKg: "500" },
    ]);
    expect("value" in r && r.value).toEqual([
      { from: "India", to: "Bangladesh", mode: "air", distanceKm: 6200, weightKg: 500 },
    ]);

    // Non-numeric strings survive untouched — coercion, not corruption.
    const r2 = validateAndNormalize(spec, [{ from: "A", to: "B", distanceKm: "unknown" }]);
    expect("value" in r2 && r2.value).toEqual([{ from: "A", to: "B", distanceKm: "unknown" }]);
  });

  it("STORED rows with string numbers coerce at publish time (canonicalFromStored)", () => {
    // The v2 production publish shipped `"6200"` because coercion only ran on
    // SAVE — but publish replays rows stored before the fix existed. The publish
    // path is where bytes freeze, so it must normalize too.
    const canonical = canonicalFromStored({
      "textile.supply.legs": JSON.stringify([{ from: "India", to: "Bangladesh", mode: "air", distanceKm: "6200", weightKg: "500" }]),
      "textile.packaging.layers": JSON.stringify([{ role: "Primary", weightGrams: "20", recycledContentPct: "40" }]),
    });
    expect(canonical["textile.supply.legs"]).toEqual([
      { from: "India", to: "Bangladesh", mode: "air", distanceKm: 6200, weightKg: 500 },
    ]);
    expect(canonical["textile.packaging.layers"]).toEqual([
      { role: "Primary", weightGrams: 20, recycledContentPct: 40 },
    ]);
  });

  it("date fields always canonicalize to calendar-date form", () => {
    const spec = getFieldById("textile.metadata.expiryDate")!;
    const a = validateAndNormalize(spec, "2036-09-09");
    const b = validateAndNormalize(spec, "2036-09-09T14:30:00.000Z");
    expect("value" in a && a.value).toBe("2036-09-09");
    expect("value" in b && b.value).toBe("2036-09-09"); // instant → its UTC date
  });
});
