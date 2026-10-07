import type { SectorStageSpec } from "../engine/types.js";

/**
 * ─── Textile supply-chain stages ──────────────────────────────────────────────
 *
 * Aligned to the harmonized Supply Chain Taxonomy V2 (apparel alliance
 * AA-PAR-TAX-501-V2.0, July 2026 — Aii, Cascale, Textile Exchange, ZDHC), which
 * the EPRS STU(2024)757808 ladder also follows:
 *
 *   T0 branding/retail → T1 finished product mfg (CMT) → T2 material mfg →
 *   T3 intermediate material (yarn) → T4 raw material + primary processing
 *
 * `tier` is the OFFICIAL code (not unique: weaving and dyeing are both Tier 2 —
 * the taxonomy separates them as process categories "Weaving/Knitting" vs
 * "Pre-treatment/Dyeing/Finishing" within one tier). `order` is the unique
 * presentation sequence. Real facilities can straddle tiers (a denim mill that
 * rope-dyes yarn does a Tier 3 process and a Tier 2 one) — which is why nodes
 * bind ROLES, and tier labels are derived per node from its roles.
 *
 * `dependsOn` is the linear chain today; it is the seam that later expresses a
 * converging BOM graph for non-linear sectors.
 *
 * Ids MATCH the `stage` values used by TEXTILE_FIELDS — one vocabulary for stages
 * and fields, enforced by a load-time assertion in the registry.
 *
 * NOTE the tier-0 stage: its sector LABEL is "Brand / Retail" (what a textile
 * operator is called), but its sector-neutral ROLE is "operator" — the accountable
 * Responsible Economic Operator. Other sectors keep `role: "operator"` and change
 * only the label ("OEM", "Manufacturer"). Nothing in the platform hardcodes "brand".
 */
export const TEXTILE_STAGES: SectorStageSpec[] = [
  { id: "brand",          role: "operator", label: "Brand / Retail",       tier: 0, order: 0, dependsOn: ["garment"],        regRef: "AA-PAR-TAX-501-V2.0 · T0 branding, retailing and distribution; EPRS STU(2024)757808 · Tier 0 (Responsible Economic Operator)" },
  { id: "garment",        role: "supplier", label: "Garment / CMT",        tier: 1, order: 1, dependsOn: ["dyeing"],         regRef: "AA-PAR-TAX-501-V2.0 · T1 finished product manufacturing (Cut, Make, Trim); EPRS · Tier 1" },
  { id: "dyeing",         role: "supplier", label: "Dyeing & Finishing",   tier: 2, order: 2, dependsOn: ["weaving"],        regRef: "AA-PAR-TAX-501-V2.0 · T2 material manufacturing — pre-treatment/dyeing/printing/finishing process categories; EPRS · Tier 2 (wet processes)" },
  { id: "weaving",        role: "supplier", label: "Fabric Formation",     tier: 2, order: 3, dependsOn: ["spinning"],       regRef: "AA-PAR-TAX-501-V2.0 · T2 material manufacturing — weaving/knitting/non-woven process categories" },
  { id: "spinning",       role: "supplier", label: "Spinning",             tier: 3, order: 4, dependsOn: ["cotton-farming"], regRef: "AA-PAR-TAX-501-V2.0 · T3 intermediate material processing (yarn); EPRS · Tier 3" },
  { id: "cotton-farming", role: "supplier", label: "Cotton Farming",       tier: 4, order: 5, dependsOn: [],                 regRef: "AA-PAR-TAX-501-V2.0 · T4 raw material production and primary processing (4a farming, 4b ginning); EPRS · Tier 4" },
];
