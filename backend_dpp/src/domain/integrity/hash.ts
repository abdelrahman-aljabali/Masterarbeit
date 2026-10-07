import crypto from "crypto";

/**
 * ─── Canonical hashing (Design B integrity primitive) ─────────────────────────
 * One deterministic serialization + sha256, shared by the audit chain and the
 * publish-version digests, so "the same content" always means "the same hash".
 * Key order never matters: objects serialize with sorted keys, recursively.
 * (This is NOT JSON-LD/URDNA2015 — that arrives with Design A signing. For
 * hash-equality of our own records, sorted-key JSON is sufficient and cheap.)
 */

/**
 * Hardened (P4-3): - `Date` serializes as its ISO string (previously it hashed
 * as `{}` — every Date collapsed to the same bytes, so two records differing
 * only in a Date field hashed identically). - `undefined`/function values INSIDE
 * objects throw (previously the template emitted the literal `undefined` — not
 * JSON, and a silent aliasing hazard). Chain compatibility:
 */
export function stableStringify(value: unknown): string {
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (value === null || typeof value !== "object") {
    const s = JSON.stringify(value);
    if (s === undefined) {
      throw new TypeError(`stableStringify: unserializable value of type ${typeof value}`);
    }
    return s;
  }
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => {
      if (obj[k] === undefined || typeof obj[k] === "function") {
        throw new TypeError(`stableStringify: key "${k}" holds an unserializable ${typeof obj[k]}`);
      }
      return `${JSON.stringify(k)}:${stableStringify(obj[k])}`;
    })
    .join(",")}}`;
}

/** sha256 hex digest of the canonical serialization. */
export function canonicalHash(value: unknown): string {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}
