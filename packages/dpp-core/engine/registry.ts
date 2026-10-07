import type { DppFieldSpec, Phase, Sector, StageSpec } from "./types.js";
import { TEXTILE_FIELDS } from "../sectors/textile.js";
import { TEXTILE_STAGES } from "../sectors/textile.stages.js";
import { sectorForCategory } from "../taxonomy.js";

/**
 * ─── dpp-core / engine / registry ─────────────────────────────────────────────
 *
 * Loads the sector schemas into one canonical field list and exposes the lookups
 * every consumer needs. Adding a sector = import its file and inject it here.
 */

const SECTOR_FILES: Record<Sector, { sector: Sector; fields: typeof TEXTILE_FIELDS; stages: typeof TEXTILE_STAGES }> = {
  textile:     { sector: "textile",     fields: TEXTILE_FIELDS, stages: TEXTILE_STAGES },
  // battery / electronics / furniture: add files of the same shape, same engine —
  // one `<sector>.ts` (fields) + one `<sector>.stages.ts` (stages) and it lights up
  // everywhere (editor, invite window, chain builder, validation) with no other change.
  battery:     { sector: "battery",     fields: [], stages: [] },
  electronics: { sector: "electronics", fields: [], stages: [] },
  furniture:   { sector: "furniture",   fields: [], stages: [] },
};

/** All fields across all loaded sectors, with `sector` injected. */
export const DPP_FIELDS: DppFieldSpec[] = Object.values(SECTOR_FILES).flatMap(
  ({ sector, fields }) => fields.map(f => ({ ...f, sector })),
);

// ─── Supply-chain stage vocabulary ──────────────────────────────────────────────
// One source of truth for supplier roles/tiers/labels, per sector. Consumed by the
// invite window, chain builder, directory filter, backend role validation and the
// publish gate. Replaces the frontend's old hardcoded `stages.ts` ladder.

/** All stages across all sectors, with `sector` injected. */
export const DPP_STAGES: StageSpec[] = Object.values(SECTOR_FILES).flatMap(
  ({ sector, stages }) => stages.map(s => ({ ...s, sector })),
);

const STAGE_BY_ID = new Map<string, StageSpec>(DPP_STAGES.map(s => [s.id, s]));

const STAGES_BY_SECTOR = DPP_STAGES.reduce((acc, s) => {
  (acc[s.sector] ??= []).push(s);
  return acc;
}, {} as Record<Sector, StageSpec[]>);

/** Every stage this sector defines, ordered consumer→upstream (operator first). */
export const stagesForSector = (sector: Sector | undefined): StageSpec[] =>
  sector ? [...(STAGES_BY_SECTOR[sector] ?? [])].sort((a, b) => a.order - b.order) : [];

/** Stages a supplier can be invited to attest (excludes the operator stage). */
export const supplierStagesFor = (sector: Sector | undefined): StageSpec[] =>
  stagesForSector(sector).filter(s => s.role === "supplier");

/** The accountable-operator stage for a sector (the ESPR REO position). */
export const operatorStageFor = (sector: Sector | undefined): StageSpec | undefined =>
  stagesForSector(sector).find(s => s.role === "operator");

/** Stage lookup by id (across all sectors — stage ids are globally unique). */
export const getStageById = (id: string): StageSpec | undefined => STAGE_BY_ID.get(id);

/** Human label for a stage id; falls back to the raw id for unknown stages. */
export const stageLabel = (id: string): string => STAGE_BY_ID.get(id)?.label ?? id;

/** Which sector a stage id belongs to. */
export const sectorOfStage = (id: string): Sector | undefined => STAGE_BY_ID.get(id)?.sector;

/** Whether a stage id is a defined role in any sector (role-validation primitive). */
export const isValidStage = (id: string): boolean => STAGE_BY_ID.has(id);

/** Whether `id` is a valid supplier role WITHIN the given sector (scoped validation). */
export const isSupplierStageInSector = (id: string, sector: Sector | undefined): boolean => {
  const s = STAGE_BY_ID.get(id);
  return !!s && s.sector === sector && s.role === "supplier";
};

// Drift guard: every field's `stage` MUST be a defined stage in the same sector.
// Fails fast at module load if the field catalog and stage vocabulary disagree —
// the same discipline the vcPath guard uses. Keeps the two-way binding honest.
{
  const bad = DPP_FIELDS.filter(f => {
    const s = STAGE_BY_ID.get(String(f.stage));
    return !s || s.sector !== f.sector;
  });
  if (bad.length) {
    throw new Error(
      `dpp-core: ${bad.length} field(s) reference an undefined/cross-sector stage: ` +
      bad.map(f => `${f.id}→"${f.stage}"`).join(", "),
    );
  }
}

// vcPath guard: bracket notation is FORBIDDEN. `setPath` splits on "." only, so
// "substances[].name" would produce a literal "substances[]" JSON key — a single
// object (one substance max, where ESPR Art.7(5) requires all) whose `[`/`]`
// expand to malformed IRIs inside the signed RDF canonicalization. Repeated
// groups are ONE `type: "array"` field of objects (composition.fibers pattern).
{
  const bad = DPP_FIELDS.filter(f => f.vcPath.includes("[]"));
  if (bad.length) {
    throw new Error(
      `dpp-core: vcPath '[]' notation is forbidden (use an array-typed field): ` +
      bad.map(f => `${f.id}→"${f.vcPath}"`).join(", "),
    );
  }
}

// ─── Sector availability ───────────────────────────────────────────────────────
// A sector is "supported" once it has a field schema loaded (non-empty). This is
// the single source of truth for what the editor can actually render — adding a
// sector's field file to SECTOR_FILES above flips it on everywhere (create gate,
// editor, backend validation) with no other change. Until then its categories
// stay selectable but create a "coming soon" state instead of a broken draft.

/** Sectors with a loaded (non-empty) field schema. */
export const SUPPORTED_SECTORS: Sector[] = (Object.keys(SECTOR_FILES) as Sector[])
  .filter(s => SECTOR_FILES[s].fields.length > 0);

/** Whether a sector has a usable field schema. */
export const isSectorSupported = (sector: Sector | undefined): sector is Sector =>
  !!sector && SECTOR_FILES[sector].fields.length > 0;

/** Whether a category path resolves to a supported sector — the create gate. */
export const isSupportedCategory = (path: string): boolean =>
  isSectorSupported(sectorForCategory(path));

// ─── Indexes ──────────────────────────────────────────────────────────────────

const BY_ID = new Map<string, DppFieldSpec>(DPP_FIELDS.map(f => [f.id, f]));

/** Canonical lookup by stable id. The old (section,label) lookup is gone —
 *  every consumer binds by id, so a label rename can't detach a field. */
export const getFieldById = (id: string): DppFieldSpec | undefined => BY_ID.get(id);

/** Whether a field is mandatory within its phase. */
export const isRequired = (f: DppFieldSpec): boolean => !!f.validation?.required;

/** Field count per phase (regulatory fields only). */
export const PHASE_COUNTS: Record<Phase, number> = DPP_FIELDS.reduce(
  (acc, f) => { if (!f.nonRegulatory) acc[f.phase] += 1; return acc; },
  { 1: 0, 2: 0, 3: 0 } as Record<Phase, number>,
);

/** Phase-1 mandatory set — what a 2027 textile DPP must satisfy. System-owned
 *  fields are excluded: the platform injects them at publish, so they can never
 *  legitimately block an operator (they'd be asking a human to type what the
 *  system already knows). */
export const PHASE1_MANDATORY = DPP_FIELDS.filter(
  f => f.phase === 1 && isRequired(f) && !f.nonRegulatory && !f.systemOwned,
);

/** Sector-scoped phase-1 mandatory set — completeness/publish gates must never
 *  count another sector's fields against a product (a battery DPP is not
 *  "incomplete" for lacking fibre composition). */
export const phase1MandatoryFor = (sector: Sector): DppFieldSpec[] =>
  PHASE1_MANDATORY.filter(f => f.sector === sector);

/** Per-sector field count per phase (regulatory fields only) — the editor's
 *  readiness widget shows the numbers for the PRODUCT's sector, not the union. */
export const phaseCountsFor = (sector: Sector): Record<Phase, number> =>
  DPP_FIELDS.reduce(
    (acc, f) => { if (!f.nonRegulatory && f.sector === sector) acc[f.phase] += 1; return acc; },
    { 1: 0, 2: 0, 3: 0 } as Record<Phase, number>,
  );

// Phase-1 readiness is computed authoritatively on the BACKEND (share of
// PHASE1_MANDATORY filled, from persisted FieldValue rows) and surfaced as
// `Passport.completenessScore`. The old client-side `computePhase1Readiness`
// heuristic was removed — it diverged from the catalog-driven score.
