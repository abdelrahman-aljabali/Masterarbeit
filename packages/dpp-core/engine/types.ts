/**
 * ─── dpp-core / engine / types ────────────────────────────────────────────────
 *
 * The CANONICAL field model. One authoritative definition of a DPP field, read by
 * every consumer (form renderer, validator, VC assembler, verifier) so they can
 * never drift apart.
 *
 * Framework-agnostic, dependency-free plain TS — no React, no DOM. This is what
 * lets the module move to a shared `packages/dpp-core` (consumed by frontend +
 * backend + CLI verifier) without changes. Keep it that way.
 *
 * Two dimensions beyond a plain form schema make this work for THIS project:
 *   - `stage`  : the field's DEFAULT owning role — which supply-chain actor TYPICALLY
 *                provides it. A hint/seed, NOT the authority: actual ownership is
 *                resolved per product from the chain nodes (SupplyChainTier.roles).
 *                The same field routes to different orgs in different chains.
 *   - `vcPath` : where the field lands inside a credential's `credentialSubject`
 *                → lets the backend assemble each role's VC from the same schema.
 */

/** EU textile DPP rollout phase (EPRS STU(2024)757808, Fig. 13/14/15). */
export type Phase = 1 | 2 | 3;

/** Product category. The schema mechanism is identical across sectors; only the
 *  field content differs. Add a sector = add a `sectors/<name>.ts` file. */
export type Sector = "textile" | "battery" | "electronics" | "furniture";

/** Default owning role for a field — the actor that TYPICALLY provides it. A seed
 *  for per-product node assignment, not a hard binding. Sector-specific; textile
 *  roles follow the harmonized Supply Chain Taxonomy tiers (apparel alliance
 *  AA-PAR-TAX-501-V2.0, July 2026 — Aii/Cascale/Textile Exchange/ZDHC), which the
 *  EPRS STU(2024)757808 ladder also matches (thesis §2.3 / §8).
 *
 *  NOTE: a tier is not a stage. Taxonomy V2 Tier 2 ("Material manufacturing")
 *  contains BOTH fabric formation (weaving/knitting) and wet processing (dyeing/
 *  finishing) as separate process categories — two stages, one tier. */
export type TextileStage =
  | "cotton-farming"   // Tier 4 — raw material production + primary processing
  | "spinning"         // Tier 3 — intermediate material processing (yarn)
  | "weaving"          // Tier 2 — material manufacturing: fabric formation (weaving/knitting)
  | "dyeing"           // Tier 2 — material manufacturing: wet processing (dyeing/finishing)
  | "garment"          // Tier 1 — finished product manufacturing (CMT)
  | "brand";           // Tier 0 — branding, retailing and distribution (ESPR REO)

export type Stage = TextileStage | string;

/** Input/value kind — drives validation and (eventually) schema-driven rendering. */
export type FieldType =
  | "text" | "textarea" | "select" | "number" | "date" | "color" | "boolean" | "array";

export interface FieldValidation {
  required?: boolean;     // mandatory WITHIN the field's phase
  min?: number;           // numbers
  max?: number;
  maxLength?: number;     // text
  pattern?: string;       // regex source string
}

export interface DppFieldSpec {
  /** Stable canonical key — e.g. "textile.composition.fibers". Never the label.
   *  The VC @context, validation and backend all bind to this, so it must not
   *  change when UI copy changes. */
  id: string;
  sector: Sector;
  /** DEFAULT owning role (a hint). Actual owner is resolved per product from the
   *  chain nodes (SupplyChainTier.roles), never from this static value. */
  stage: Stage;
  /** Editor section (UI grouping) — matches the frontend EditorSection union. */
  section: string;
  /** FormSection title the field renders under. */
  group: string;
  /** Rendered UI label. */
  label: string;
  type: FieldType;
  options?: string[];
  validation?: FieldValidation;
  phase: Phase;
  /** Regulatory / source reference (audit trail). */
  regRef: string;
  /** Dot-path inside credentialSubject where the value lands when assembling a VC. */
  vcPath: string;
  /**
   * This field is a DERIVED SHADOW of another field (its id given here), kept
   * for phase-1 gates and editor ergonomics. When the authoritative field is
   * present, the shadow is OMITTED from assembled credentials — signed bytes
   * must state each fact once (packaging.primary duplicated packaging.layers[0]
   * in immutable signed data; two spellings of one fact can drift forever).
   */
  vcShadowOf?: string;
  /**
   * For `type: "array"` fields whose entries are objects: entry keys whose
   * values are numeric. Canonicalization coerces numeric-looking strings for
   * these keys, so signed bytes carry numbers, never `"6200"` next to `6200`
   * (the editor's row inputs produce strings; typed facts must not depend on
   * which client wrote them).
   */
  entryNumericKeys?: string[];
  /** Value-add field that should NOT count toward ESPR readiness. */
  nonRegulatory?: boolean;
  /** Value is written by the PLATFORM (ids, versions, statuses, dates, DIDs) —
   *  never typed by an operator. Auto-injected at publish, rendered read-only in
   *  the editor, and excluded from publish blockers / completeness. The datum
   *  still lands in the snapshot + credentialSubject (the regulation requires it
   *  to be PRESENT, not to be hand-typed). */
  systemOwned?: boolean;
}

/** A sector file declares fields without repeating `sector` on every line; the
 *  registry injects it on load. */
export type SectorFieldSpec = Omit<DppFieldSpec, "sector">;

/**
 * ─── Supply-chain stage vocabulary ────────────────────────────────────────────
 *
 * The set of supply-chain positions a sector defines. This is the SINGLE SOURCE
 * OF TRUTH for supplier roles, tiers and labels — read by the invite window, the
 * chain builder, the directory filter, backend role validation, and the publish
 * gate. It replaces the hardcoded textile ladder that used to live in the
 * frontend (`components/producer/stages.ts`).
 *
 * Sector-neutral by construction:
 *   - `role: "operator"` is the accountable passport owner (the ESPR "Responsible
 *     Economic Operator"). Textile calls this actor a "Brand / Retail"; batteries
 *     an "OEM"; furniture a "Manufacturer". The CODE and UI must key off
 *     `role === "operator"`, NEVER off a sector word like "brand".
 *   - `role: "supplier"` is any upstream contributor that can be invited to
 *     self-attest its own data.
 * Adding a sector = add a `<sector>.stages.ts` file of `SectorStageSpec[]`.
 */
export type StageRole = "supplier" | "operator";

export interface StageSpec {
  /** Stable stage id. Matches the `stage` value on that sector's fields. */
  id: string;
  sector: Sector;
  /** Sector-neutral classification. `operator` = the accountable owner (never
   *  invitable/bindable as a supplier); `supplier` = an upstream contributor. */
  role: StageRole;
  /** Rendered label — sector-specific copy ("Spinning", "Cell Assembly"). */
  label: string;
  /** OFFICIAL supply-chain tier code (0–4) per the harmonized Supply Chain
   *  Taxonomy (AA-PAR-TAX-501-V2.0): 0 = branding/retail, 1 = finished product
   *  manufacturing, 2 = material manufacturing, 3 = intermediate material
   *  processing, 4 = raw material. NOT unique per stage — Tier 2 holds both
   *  fabric formation and wet processing. Use for regulatory display ("T2");
   *  use `order` for sequencing. */
  tier: number;
  /** Presentation order within the sector; 0 = closest to the consumer (the
   *  operator), higher = further upstream. UNIQUE per stage, unlike `tier` —
   *  this is what sorts a chain, never what labels it. */
  order: number;
  /** Upstream stage ids that feed this one. Empty today (linear chains infer
   *  order from `order`); populating it later expresses a BOM graph with NO
   *  schema change — the graph-readiness seam. */
  dependsOn?: string[];
  /** Regulatory / value-chain reference. */
  regRef?: string;
}

/** A sector file declares stages without repeating `sector`; the registry injects it. */
export type SectorStageSpec = Omit<StageSpec, "sector">;
