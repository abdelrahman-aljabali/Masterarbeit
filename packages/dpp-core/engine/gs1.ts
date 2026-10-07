/**
 * ─── dpp-core / engine / gs1 ──────────────────────────────────────────────────
 *
 * GS1 GTIN validation (GTIN-8 / -12 / -13 / -14) per the GS1 General
 * Specifications §7.9: the last digit is a mod-10 check digit computed over the
 * preceding digits with 3-1-3-… weighting from the RIGHT. Pure functions, no
 * dependencies — shared by the editor (blur validation), the backend save path
 * (persist Product.gtin), and the GS1 Digital Link resolver (reject malformed
 * ids before touching the database).
 */

const GTIN_LENGTHS = new Set([8, 12, 13, 14]);

/** Strict shape check: digits only, one of the four GTIN lengths. */
export const isGtinShape = (s: string): boolean =>
  /^[0-9]+$/.test(s) && GTIN_LENGTHS.has(s.length);

/** GS1 mod-10 check digit for the payload (all digits EXCEPT the check digit). */
export function gs1CheckDigit(payload: string): number {
  let sum = 0;
  // weight 3 on the rightmost payload digit, alternating 3,1,3,1… leftwards
  for (let i = 0; i < payload.length; i++) {
    const digit = payload.charCodeAt(payload.length - 1 - i) - 48;
    sum += digit * (i % 2 === 0 ? 3 : 1);
  }
  return (10 - (sum % 10)) % 10;
}

/** Full GTIN validation: shape + check digit. */
export function isValidGtin(s: string): boolean {
  if (!isGtinShape(s)) return false;
  return gs1CheckDigit(s.slice(0, -1)) === Number(s[s.length - 1]);
}

/**
 * Normalize a GTIN to its 14-digit form (left-padded with zeros) — the GS1
 * Digital Link canonical AI(01) format. Returns null for invalid input.
 */
export function normalizeGtin14(s: string): string | null {
  if (!isValidGtin(s)) return null;
  return s.padStart(14, "0");
}
