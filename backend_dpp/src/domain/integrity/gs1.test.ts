import { describe, it, expect } from "vitest";
import { isValidGtin, gs1CheckDigit, normalizeGtin14, isGtinShape } from "../../dpp-core/index.js";

/**
 * GTIN golden vectors — real-world check digits from the GS1 spec examples.
 * These pin the 3-1-3 weighting; a broken implementation typically passes
 * palindromic inputs but fails these.
 */
describe("gs1 gtin validation", () => {
  it("accepts known-valid GTINs of every length", () => {
    expect(isValidGtin("96385074")).toBe(true);        // GTIN-8 (GS1 doc example)
    expect(isValidGtin("036000291452")).toBe(true);    // GTIN-12 / UPC-A
    expect(isValidGtin("4006381333931")).toBe(true);   // GTIN-13 / EAN-13
    expect(isValidGtin("00012345600012")).toBe(true);  // GTIN-14
    expect(isValidGtin("4012345000009")).toBe(true);   // GS1 GLN-style example
  });

  it("rejects a flipped check digit and transposed digits", () => {
    expect(isValidGtin("4006381333932")).toBe(false);  // last digit off by one
    expect(isValidGtin("4006383133931")).toBe(false);  // adjacent transposition
  });

  it("rejects bad shapes", () => {
    expect(isValidGtin("")).toBe(false);
    expect(isValidGtin("1234567")).toBe(false);        // 7 digits
    expect(isValidGtin("123456789")).toBe(false);      // 9 digits
    expect(isValidGtin("40063813339311")).toBe(false); // 15 digits (shape gate)
    expect(isValidGtin("400638133393a")).toBe(false);  // non-digit
    expect(isGtinShape("4006381333931 ")).toBe(false); // trailing space
  });

  it("computes the documented check digit", () => {
    expect(gs1CheckDigit("400638133393")).toBe(1);
    expect(gs1CheckDigit("03600029145")).toBe(2);
    expect(gs1CheckDigit("9638507")).toBe(4);
  });

  it("normalizes to the 14-digit AI(01) form", () => {
    expect(normalizeGtin14("4006381333931")).toBe("04006381333931");
    expect(normalizeGtin14("96385074")).toBe("00000096385074");
    expect(normalizeGtin14("bad")).toBeNull();
  });
});
