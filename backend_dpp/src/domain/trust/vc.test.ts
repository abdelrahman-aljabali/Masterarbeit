import { describe, it, expect } from "vitest";
import { stripNonStringIds } from "./vc.js";

/**
 * Regression: packaging layers carry a numeric `id` (a React row key). JSON-LD
 * treats `id` as an alias for `@id`, which MUST be a string IRI — a numeric one
 * made signing throw `Invalid JSON-LD syntax; "@id" value must a string`, so
 * every publish of a passport WITH packaging layers returned a 500.
 */
describe("stripNonStringIds (JSON-LD @id safety)", () => {
  it("drops the numeric row key on packaging layers", () => {
    const subject = {
      packaging: { layers: [{ id: 1, role: "Secondary", materialType: "cardboard" }] },
    };
    expect(stripNonStringIds(subject)).toEqual({
      packaging: { layers: [{ role: "Secondary", materialType: "cardboard" }] },
    });
  });

  it("KEEPS legitimate string ids (product DID, passport urn:uuid)", () => {
    const subject = {
      id: "did:web:trustdpp.co:prod_x",
      passport: { id: "urn:uuid:2c98402a-defc-57e7-8d1f-ad4d54f3ed12" },
      role: "brand",
    };
    expect(stripNonStringIds(subject)).toEqual(subject);
  });

  it("recurses through nested arrays and objects", () => {
    expect(
      stripNonStringIds({ a: [{ id: 7, keep: 1 }, { id: "ok" }], b: { c: { id: null, x: 2 } } }),
    ).toEqual({ a: [{ keep: 1 }, { id: "ok" }], b: { c: { x: 2 } } });
  });

  it("leaves primitives and empty values alone", () => {
    expect(stripNonStringIds(null)).toBeNull();
    expect(stripNonStringIds("x")).toBe("x");
    expect(stripNonStringIds([])).toEqual([]);
  });
});
