import type { DppFieldSpec } from "./types.js";

/**
 * Client-side blur validation. Returns a human-readable error, or null when the
 * value passes. This is UX, not security — the backend's canonicalizeFields
 * pipeline stays authoritative. The rules here MIRROR canonical.ts exactly
 * (unanchored pattern test, Number.isFinite, ≥/≤ ranges): the client must never
 * be stricter or looser than the server, or the inline error and the save
 * outcome would disagree.
 *
 * Empty value: flagged only when `required` — clearing an optional field is a
 * legitimate save (the backend treats blank as an explicit clear).
 */
export function validateFieldValue(spec: DppFieldSpec | undefined, raw: string): string | null {
  if (!spec) return null;
  const v = spec.validation;
  const s = raw.trim();
  if (s === "") return v?.required ? "This field is required." : null;

  switch (spec.type) {
    case "number": {
      const n = Number(s);
      if (!Number.isFinite(n)) return "Must be a number.";
      if (v?.min != null && n < v.min) return `Must be ≥ ${v.min}.`;
      if (v?.max != null && n > v.max) return `Must be ≤ ${v.max}.`;
      return null;
    }
    case "date":
      return Number.isNaN(Date.parse(s)) ? "Must be a valid date." : null;
    case "select":
      return spec.options?.length && !spec.options.includes(s)
        ? `Must be one of: ${spec.options.join(", ")}.`
        : null;
    case "boolean":
    case "array":
      return null; // structured editors own these; the server still checks
    default: { // text | textarea | color
      if (v?.maxLength != null && s.length > v.maxLength) return `Exceeds ${v.maxLength} characters.`;
      if (v?.pattern && !new RegExp(v.pattern).test(s)) return "Invalid format.";
      return null;
    }
  }
}
