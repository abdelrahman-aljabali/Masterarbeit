import { getFieldById } from "../../dpp-core/index.js";
import type { DppFieldSpec } from "../../dpp-core/index.js";
import { ownersByRole, resolveRoleOwner } from "../workflow/ownership.js";
import type { OwnerNode } from "../workflow/ownership.js";

/**
 * ─── Canonicalization (the VC pipeline, stage 0) ──────────────────────────────
 * Server-side field validation that does NOT stop at accept/reject. It also
 * *normalizes* each value into a deterministic canonical form and assembles the
 * per-actor credential payloads — the unsigned VC bodies.
 */

export type CanonicalValue = string | number | boolean | (string | Record<string, unknown>)[];

export interface FieldError {
  fieldId: string;
  code: "unknown" | "type" | "range" | "length" | "pattern" | "option";
  message: string;
}

const fail = (fieldId: string, code: FieldError["code"], message: string): FieldError => ({ fieldId, code, message });

/** Truthy-empty: a provided-but-blank value means "clear this field", not "invalid". */
const isBlank = (raw: unknown): boolean =>
  raw == null || (typeof raw === "string" && raw.trim() === "") || (Array.isArray(raw) && raw.length === 0);

const BOOL_TRUE = new Set(["true", "1", "yes", "on"]);
const BOOL_FALSE = new Set(["false", "0", "no", "off"]);

/**
 * Coerce numeric-looking strings for the entry keys the catalog declares
 * numeric (`entryNumericKeys`). Row editors submit every input as a string, so
 * signed bytes carried `"6200"` in `transport.legs` next to `6200` in the
 * derived final leg — the same fact, two JSON types, forever. Non-numeric
 * strings pass through untouched (validation, not silent data loss).
 */
function coerceEntryNumbers(entry: Record<string, unknown>, spec: DppFieldSpec): Record<string, unknown> {
  const keys = spec.entryNumericKeys;
  if (!keys?.length) return entry;
  const out: Record<string, unknown> = { ...entry };
  for (const k of keys) {
    const v = out[k];
    if (typeof v === "string" && v.trim() !== "" && /^-?\d+(\.\d+)?$/.test(v.trim())) {
      out[k] = Number(v.trim());
    }
  }
  return out;
}

/**
 * Validate one value against its spec and return the normalized canonical form.
 * Returns a FieldError instead of throwing so the caller can report every problem
 * in one pass (matches the existing `unknown field id(s)` batch-reporting style).
 */
export function validateAndNormalize(
  spec: DppFieldSpec,
  raw: unknown,
): { value: CanonicalValue } | { error: FieldError } {
  const v = spec.validation;

  switch (spec.type) {
    case "number": {
      const n = typeof raw === "number" ? raw : Number(String(raw).trim());
      if (!Number.isFinite(n)) return { error: fail(spec.id, "type", `${spec.label} must be a number`) };
      if (v?.min != null && n < v.min) return { error: fail(spec.id, "range", `${spec.label} must be ≥ ${v.min}`) };
      if (v?.max != null && n > v.max) return { error: fail(spec.id, "range", `${spec.label} must be ≤ ${v.max}`) };
      return { value: n };
    }
    case "boolean": {
      const s = String(raw).trim().toLowerCase();
      if (raw === true || BOOL_TRUE.has(s)) return { value: true };
      if (raw === false || BOOL_FALSE.has(s)) return { value: false };
      return { error: fail(spec.id, "type", `${spec.label} must be true or false`) };
    }
    case "date": {
      const s = String(raw).trim();
      const t = Date.parse(s);
      if (Number.isNaN(t)) return { error: fail(spec.id, "type", `${spec.label} must be a valid date`) };
      // ALWAYS calendar-date form (YYYY-MM-DD). Every catalog `date` field is a
      // calendar date (issue, expiry, shipment, market placement); an instant
      // slipping through an API client produced mixed lexical forms in signed
      // bytes — and context v3 types these terms xsd:date, whose lexical space
      // is date-only. Date-only inputs pass through untouched (no timezone
      // reinterpretation); instants are truncated to their UTC date.
      const value = /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : new Date(t).toISOString().slice(0, 10);
      return { value };
    }
    case "select": {
      const s = String(raw).trim();
      if (spec.options?.length && !spec.options.includes(s)) {
        return { error: fail(spec.id, "option", `${spec.label} must be one of: ${spec.options.join(", ")}`) };
      }
      return { value: s };
    }
    case "array": {
      // Accept: a real array, a JSON-stringified array (how the editor sends
      // structured rows like fibers/legs), or a comma-separated string. Entries
      // may be OBJECTS (fiber rows, transport legs) — preserve them; String()-
      // coercing an object to "[object Object]" silently corrupts the value.
      let items: unknown[];
      if (Array.isArray(raw)) {
        items = raw;
      } else {
        const s = String(raw).trim();
        try {
          const parsed = JSON.parse(s);
          items = Array.isArray(parsed) ? parsed : s.split(",");
        } catch {
          items = s.split(",");
        }
      }
      const arr = items
        .map((x) => (x !== null && typeof x === "object" ? coerceEntryNumbers(x as Record<string, unknown>, spec) : String(x).trim()))
        .filter((x) => (typeof x === "string" ? x.length > 0 : true)); // order preserved — composition order is meaningful
      return { value: arr as CanonicalValue };
    }
    default: {
      // text | textarea | color
      const s = String(raw).trim();
      if (v?.maxLength != null && s.length > v.maxLength) {
        return { error: fail(spec.id, "length", `${spec.label} exceeds ${v.maxLength} characters`) };
      }
      if (v?.pattern && !new RegExp(v.pattern).test(s)) {
        return { error: fail(spec.id, "pattern", `${spec.label} has an invalid format`) };
      }
      return { value: s };
    }
  }
}

export interface CanonicalResult {
  /** fieldId → canonical typed value, for fields that carry a value. */
  canonical: Record<string, CanonicalValue>;
  /** fieldId → string form to persist in the FieldValue column. */
  stored: Record<string, string>;
  /** fieldIds explicitly cleared (provided blank). */
  cleared: string[];
  /** All validation failures (empty ⇒ valid). */
  errors: FieldError[];
}

/** Serialize a canonical value to its stable string column form. */
export const toStored = (value: CanonicalValue): string =>
  Array.isArray(value) ? JSON.stringify(value) : String(value);

/**
 * Validate + normalize a whole `{ fieldId: raw }` batch. Unknown ids and bad
 * values are collected (not thrown) so the route returns one 400 listing them all.
 */
export function canonicalizeFields(values: Record<string, unknown>): CanonicalResult {
  const canonical: Record<string, CanonicalValue> = {};
  const stored: Record<string, string> = {};
  const cleared: string[] = [];
  const errors: FieldError[] = [];

  for (const [fieldId, raw] of Object.entries(values)) {
    const spec = getFieldById(fieldId);
    if (!spec) {
      errors.push(fail(fieldId, "unknown", `Unknown field id: ${fieldId}`));
      continue;
    }
    if (isBlank(raw)) {
      cleared.push(fieldId);
      stored[fieldId] = "";
      continue;
    }
    const r = validateAndNormalize(spec, raw);
    if ("error" in r) {
      errors.push(r.error);
      continue;
    }
    canonical[fieldId] = r.value;
    stored[fieldId] = toStored(r.value);
  }

  return { canonical, stored, cleared, errors };
}

/**
 * Reconstruct canonical typed values from the persisted string column form — the
 * inverse of `toStored`. Used at publish time to assemble credentials from already
 * stored, already validated FieldValue rows. Blank/cleared rows are skipped.
 */
export function canonicalFromStored(stored: Record<string, string>): Record<string, CanonicalValue> {
  const canonical: Record<string, CanonicalValue> = {};
  for (const [fieldId, s] of Object.entries(stored)) {
    const spec = getFieldById(fieldId);
    if (!spec || s == null || s === "") continue;
    switch (spec.type) {
      case "number": { const n = Number(s); if (Number.isFinite(n)) canonical[fieldId] = n; break; }
      case "boolean": canonical[fieldId] = s === "true"; break;
      // Entry-number coercion applies HERE too, not only on save: publish replays
      // STORED rows, and rows saved before the coercion existed still carry
      // string numbers. Publish is the moment bytes freeze — normalizing at this
      // choke point means every future version is clean regardless of when (or
      // through which client) the row was written. (v2 of the first production
      // passport shipped `"6200"` because this path didn't coerce.)
      case "array": { try { const a = JSON.parse(s); if (Array.isArray(a)) canonical[fieldId] = a.map((x) => (x !== null && typeof x === "object" ? coerceEntryNumbers(x as Record<string, unknown>, spec) : String(x))); } catch { /* skip malformed */ } break; }
      default: canonical[fieldId] = s;
    }
  }
  return canonical;
}

// ─── VC-graph assembly (unsigned) ─────────────────────────────────────────────

/** Nest `value` into `obj` at a dot-path (e.g. "manufacturing.facilityId"). */
function setPath(obj: Record<string, any>, path: string, value: unknown): void {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur[parts[i]] ??= {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

export interface UnsignedCredential {
  /** The role this credential covers — the field's DEFAULT actor (dpp-core `stage`). */
  role: string;
  /** Chain node bound to this role for this product, or null (brand-owned). */
  nodeId: string | null;
  /** Issuer DID resolved from the bound node's org, or null (brand / unbound). */
  issuerDid: string | null;
  /** The unsigned VC body, fields placed at their `vcPath`. */
  credentialSubject: Record<string, unknown>;
  /** Canonical ids included, for traceability. */
  fieldIds: string[];
}

/**
 * Group canonical field values by their default role (dpp-core `stage`), nest
 * each at its `vcPath`, and bind each role bucket to its OWNER — the chain node
 * that provides that role for this product (or the brand, when no node does).
 * This IS the VC graph minus the signatures; Phase 3 wraps each with the
 * issuer's proof.
 */
export function assembleCredentials(
  canonical: Record<string, CanonicalValue>,
  nodes: OwnerNode[] = [],
): UnsignedCredential[] {
  const owners = ownersByRole(nodes);
  const byRole = new Map<string, { subject: Record<string, unknown>; ids: string[] }>();

  for (const [fieldId, value] of Object.entries(canonical)) {
    const spec = getFieldById(fieldId);
    if (!spec?.vcPath) continue;
    // Derived shadows (packaging.primary.*, transport.finalLeg.*) exist for
    // phase-1 gates and the editor — NOT for signed bytes. When the
    // authoritative field is present, the shadow is omitted: a fact stated
    // twice in immutable signed data is two facts that can disagree forever.
    // (Conditional, not absolute: a legacy passport that only ever filled the
    // single-leg fields keeps them — omitting would erase its transport data.)
    if (spec.vcShadowOf && canonical[spec.vcShadowOf] != null) continue;
    const role = String(spec.stage); // dpp-core `stage` = the field's default role
    const bucket = byRole.get(role) ?? { subject: {}, ids: [] };
    setPath(bucket.subject, spec.vcPath, value);
    bucket.ids.push(fieldId);
    byRole.set(role, bucket);
  }

  return [...byRole.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([role, { subject, ids }]) => {
      const owner = resolveRoleOwner(role, owners);
      return {
        role,
        nodeId: owner.nodeId,
        issuerDid: owner.issuerDid,
        credentialSubject: subject,
        fieldIds: ids.sort(),
      };
    });
}

