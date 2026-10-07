import type { SectorFieldSpec } from "../engine/types.js";

/**
 * ─── Textile DPP — canonical field catalog ────────────────────────────────────
 *
 * The textile sector schema. Same SHAPE as any future sector (battery, etc.);
 * only the field content differs.
 *
 * `phase`  : EPRS STU(2024)757808 Fig. 13/14/15 (Phase 1 ≈ 2027 minimal,
 *            2 ≈ 2030 advanced, 3 ≈ 2033 full circular).
 * `regRef` : "Rulebook §x" = CIRPASS cross-sector rulebook; "EPRS Fig.x" = the
 *            textile study; ESPR / PPWR / REACH = the named regulation.
 * `stage`  : FIRST-PASS mapping onto the per-actor VC-graph (thesis §8). Section
 *            ≠ stage — e.g. "Colour Name" renders under Appearance but is signed
 *            at the dyeing stage. These assignments are domain judgments and
 *            should be reviewed against the final VC-graph before Phase 03.
 */
export const TEXTILE_FIELDS: SectorFieldSpec[] = [
  // ─── metadata (Rulebook §6.1 — structural, brand-issued) ──────────────────────
  // systemOwned: the platform IS the authority for these (the passport id is
  // minted at creation, version/status/issueDate are publish facts). They are
  // injected at publish and never typed — asking an operator to re-enter them
  // only lets the metadata contradict reality.
  { id: "textile.metadata.passportId",   stage: "brand", section: "metadata", group: "Passport Metadata", label: "Passport Identifier (UUID)", type: "text",     phase: 1, regRef: "Rulebook §6.1.1",  vcPath: "passport.id",            systemOwned: true },
  { id: "textile.metadata.version",       stage: "brand", section: "metadata", group: "Passport Metadata", label: "Version",                    type: "text",     phase: 1, regRef: "Rulebook §6.1.2",  vcPath: "passport.version",       systemOwned: true },
  { id: "textile.metadata.status",        stage: "brand", section: "metadata", group: "Passport Metadata", label: "Status",                     type: "select",   phase: 1, regRef: "Rulebook §6.1.3",  vcPath: "passport.status",        options: ["draft", "published", "archived"], systemOwned: true },
  { id: "textile.metadata.language",      stage: "brand", section: "metadata", group: "Passport Metadata", label: "Language",                   type: "select",   phase: 1, regRef: "Rulebook §6.1.4",  vcPath: "passport.language",      validation: { required: true } },
  { id: "textile.metadata.issueDate",     stage: "brand", section: "metadata", group: "Passport Metadata", label: "Issue Date",                 type: "date",     phase: 1, regRef: "Rulebook §6.1.8",  vcPath: "passport.issuedAt",      systemOwned: true },
  { id: "textile.metadata.expiryDate",    stage: "brand", section: "metadata", group: "Passport Metadata", label: "Expiration Date",            type: "date",     phase: 1, regRef: "Rulebook §6.1.9",  vcPath: "passport.expiresAt",     validation: { required: true } },
  { id: "textile.metadata.eoId",          stage: "brand", section: "metadata", group: "Economic Operator", label: "Economic Operator Identification", type: "text", phase: 1, regRef: "Rulebook §6.1.11", vcPath: "economicOperator.identifier",   validation: { required: true } },
  { id: "textile.metadata.eoName",        stage: "brand", section: "metadata", group: "Economic Operator", label: "Economic Operator Name",     type: "text",     phase: 1, regRef: "Rulebook §6.1.12", vcPath: "economicOperator.name",  validation: { required: true } },
  { id: "textile.metadata.eoContact",     stage: "brand", section: "metadata", group: "Economic Operator", label: "Economic Operator Contact",  type: "text",     phase: 1, regRef: "Rulebook §6.1.13", vcPath: "economicOperator.contact", validation: { required: true } },
  { id: "textile.metadata.eoAddress",     stage: "brand", section: "metadata", group: "Economic Operator", label: "Economic Operator Address",  type: "textarea", phase: 1, regRef: "Rulebook §6.1.14", vcPath: "economicOperator.address", validation: { required: true } },
  // Backup DPP service-provider reference — mandated DPP element; central to the
  // Art.10(4) backup scenario the thesis shutdown-attribution test relies on.
  { id: "textile.metadata.backupProvider", stage: "brand", section: "metadata", group: "Passport Metadata", label: "Backup DPP Provider Reference", type: "text", phase: 1, regRef: "ESPR Annex III(l) / Art.10(4)", vcPath: "passport.backupProvider" },

  // ─── identity (Rulebook §6.2 — brand declares product identity) ───────────────
  { id: "textile.identity.codeKey",       stage: "brand", section: "identity", group: "Product Identity", label: "Code Key",              type: "select", phase: 1, regRef: "Rulebook §6.2.7",  vcPath: "product.codeKey",   options: ["GTIN", "DID", "ISBN", "Hash", "TARIC", "CN", "HS"], validation: { required: true } },
  { id: "textile.identity.codeValue",     stage: "brand", section: "identity", group: "Product Identity", label: "Code Value",            type: "text",   phase: 1, regRef: "Rulebook §6.2.8",  vcPath: "product.codeValue",     validation: { required: true } },
  { id: "textile.identity.name",          stage: "brand", section: "identity", group: "Product Identity", label: "Name at Manufacturer",  type: "text",   phase: 1, regRef: "Rulebook §6.2.6",  vcPath: "product.name",          validation: { required: true } },
  { id: "textile.identity.partId",        stage: "brand", section: "identity", group: "Product Identity", label: "Manufacturer Part ID",  type: "text",   phase: 1, regRef: "Rulebook §6.2.5",  vcPath: "product.partId",        validation: { required: true } },
  { id: "textile.identity.category",      stage: "brand", section: "identity", group: "Product Identity", label: "ESPR Product Category", type: "select", phase: 1, regRef: "ESPR Art.4",       vcPath: "product.category",      validation: { required: true } },
  { id: "textile.identity.classStandard", stage: "brand", section: "identity", group: "Product Identity", label: "Classification Standard", type: "select", phase: 1, regRef: "Rulebook §6.2.12", vcPath: "product.classification.standard", options: ["GPC", "ECLASS 15.0", "HS Code", "CN Code", "TARIC"], validation: { required: true } },
  // Passport granularity (model / batch / item) — which level of product identity
  // this passport describes. Cheap to declare now, expensive to retrofit once
  // passports are in the wild; ESPR delegated acts will pin the required level.
  { id: "textile.identity.granularity",   stage: "brand", section: "identity", group: "Product Identity", label: "Passport Granularity", type: "select", phase: 1, regRef: "ESPR Art. 9 / Catena-X convention", vcPath: "product.granularity", options: ["model", "batch", "item"] },
  { id: "textile.identity.classId",       stage: "brand", section: "identity", group: "Product Identity", label: "Classification ID",     type: "text",   phase: 1, regRef: "Rulebook §6.2.13", vcPath: "product.classification.code", validation: { required: true } },
  { id: "textile.identity.shortDesc",     stage: "brand", section: "identity", group: "Product Identity", label: "Short Description",     type: "textarea", phase: 2, regRef: "EPRS Fig.14 — Description", vcPath: "product.description" },
  // Canonical "CC — Name" strings: self-describing on the public page, the ISO-2
  // code is the first two chars. Superset of the brand editor's shortlist, so
  // both editor and supplier-portal selections validate against this one list.
  { id: "textile.identity.countryOrigin", stage: "cotton-farming", section: "identity", group: "Origin & Traceability", label: "Country of Origin (ISO-2)", type: "select", phase: 1, regRef: "EPRS Fig.13 — Location / AGEC", vcPath: "origin.country",
    options: [
      "BD — Bangladesh", "BR — Brazil", "CN — China", "DE — Germany", "EG — Egypt", "ES — Spain",
      "ET — Ethiopia", "FR — France", "GR — Greece", "IN — India", "ID — Indonesia", "IT — Italy",
      "KH — Cambodia", "LK — Sri Lanka", "MA — Morocco", "MM — Myanmar", "MX — Mexico", "PK — Pakistan",
      "PL — Poland", "PT — Portugal", "RO — Romania", "TH — Thailand", "TN — Tunisia", "TR — Turkey",
      "TZ — Tanzania", "US — United States", "UZ — Uzbekistan", "VN — Vietnam",
    ],
    validation: { required: true } },
  { id: "textile.identity.responsibleEo",  stage: "brand", section: "identity", group: "Origin & Traceability", label: "Responsible Economic Operator (EU)", type: "text", phase: 1, regRef: "ESPR Annex III(k) / Art.27(6)", vcPath: "origin.responsibleOperator", validation: { required: true } },
  { id: "textile.identity.productDid",     stage: "brand", section: "identity", group: "Origin & Traceability", label: "Product DID", type: "text", phase: 1, regRef: "Rulebook §6.2", vcPath: "product.did", systemOwned: true },
  // Consumer-facing product picture (EPRS Fig.14 lists "Picture" for the finished
  // product). A URL, not a binary — media storage stays out of the field model.
  // maxLength guard: a URL, never an inline base64 blob (a data: URI here once
  // inflated every credential/snapshot by megabytes — uploads go through the
  // media endpoint, which stores bytes and returns a served URL).
  { id: "textile.identity.imageUrl",       stage: "brand", section: "identity", group: "Product Media", label: "Product Image (URL)", type: "text", phase: 2, regRef: "EPRS Fig.14 — Picture", vcPath: "product.imageUrl", validation: { maxLength: 2048 } },

  // ─── operation (Rulebook §6.3 — manufacturing = garment stage; importer = brand) ─
  { id: "textile.operation.facilityId",    stage: "garment", section: "operation", group: "Manufacturing", label: "Facility Identification",     type: "text", phase: 1, regRef: "Rulebook §6.3.1", vcPath: "manufacturing.facilityId", validation: { required: true } },
  { id: "textile.operation.manufacturerId", stage: "garment", section: "operation", group: "Manufacturing", label: "Manufacturer Identification", type: "text", phase: 1, regRef: "Rulebook §6.3.3", vcPath: "manufacturing.manufacturerId", validation: { required: true } },
  { id: "textile.operation.mfgDate",        stage: "garment", section: "operation", group: "Manufacturing", label: "Manufacturing Date",          type: "date", phase: 2, regRef: "Rulebook §6.3.7", vcPath: "manufacturing.date" },
  { id: "textile.operation.eori",           stage: "brand", section: "operation", group: "Importer (if applicable)", label: "EORI Number",            type: "text", phase: 2, regRef: "Rulebook §6.3.8.1", vcPath: "importer.eori" },
  { id: "textile.operation.importerId",     stage: "brand", section: "operation", group: "Importer (if applicable)", label: "Importer Identification", type: "text", phase: 2, regRef: "Rulebook §6.3.8.2", vcPath: "importer.identifier" },
  { id: "textile.operation.importerName",   stage: "brand", section: "operation", group: "Importer (if applicable)", label: "Importer Name",          type: "text", phase: 2, regRef: "Rulebook §6.3.8", vcPath: "importer.name" },
  { id: "textile.operation.importerAddr",   stage: "brand", section: "operation", group: "Importer (if applicable)", label: "Importer Address",       type: "textarea", phase: 2, regRef: "Rulebook §6.3.8", vcPath: "importer.address" },

  // ─── characteristics (Rulebook §6.5 + EPRS finished product → mostly Phase 2) ──
  { id: "textile.char.lifeType",   stage: "brand", section: "characteristics", group: "Lifetime", label: "Life Type",  type: "select", phase: 2, regRef: "Rulebook §6.5.1", vcPath: "lifetime.kind",  options: ["Guaranteed lifetime", "Technical lifetime", "MTBF"] },
  { id: "textile.char.lifeValue",  stage: "brand", section: "characteristics", group: "Lifetime", label: "Life Value", type: "number", phase: 2, regRef: "Rulebook §6.5.3", vcPath: "lifetime.value", validation: { min: 1 } },
  { id: "textile.char.lifeUnit",   stage: "brand", section: "characteristics", group: "Lifetime", label: "Life Unit",  type: "select", phase: 2, regRef: "Rulebook §6.5.4", vcPath: "lifetime.unit", options: ["year", "month", "day", "cycle", "running hour"] },
  // REVIEW (pending CIRPASS rulebook): volume/grossVolume/width/length/physState are generic
  // cross-sector "Rulebook §6.5" slots with no verifiable textile basis and low operator realism —
  // padding candidates to drop once the rulebook source is confirmed. Kept for now, not deleted.
  { id: "textile.char.weight",      stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Weight (g)",       type: "number", phase: 2, regRef: "Rulebook §6.5.19", vcPath: "dimensions.weightG",      validation: { min: 0 } },
  { id: "textile.char.grossWeight", stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Gross Weight (g)", type: "number", phase: 2, regRef: "Rulebook §6.5.13", vcPath: "dimensions.grossWeightG", validation: { min: 0 } },
  { id: "textile.char.volume",      stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Volume (cm³)",     type: "number", phase: 2, regRef: "Rulebook §6.5.15", vcPath: "dimensions.volumeCm3",   validation: { min: 0 } },
  { id: "textile.char.grossVolume", stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Gross Volume (cm³)", type: "number", phase: 2, regRef: "Rulebook §6.5.17", vcPath: "dimensions.grossVolumeCm3", validation: { min: 0 } },
  { id: "textile.char.width",       stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Width (cm)",       type: "number", phase: 3, regRef: "Rulebook §6.5.5", vcPath: "dimensions.widthCm",   validation: { min: 0 } },
  { id: "textile.char.length",      stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Length (cm)",      type: "number", phase: 3, regRef: "Rulebook §6.5.7", vcPath: "dimensions.lengthCm",  validation: { min: 0 } },
  { id: "textile.char.physState",   stage: "brand", section: "characteristics", group: "Physical Dimensions", label: "Physical State",   type: "select", phase: 3, regRef: "Rulebook §6.5.23", vcPath: "dimensions.physicalState", options: ["solid", "liquid", "gas", "plasma", "aerosol"] },
  // Appearance — colour is a dyeing-stage attribute; size/season/target are brand
  { id: "textile.char.colourName", stage: "dyeing", section: "characteristics", group: "Product Appearance", label: "Colour Name",    type: "text",   phase: 2, regRef: "EPRS Fig.14 — Colour",      vcPath: "appearance.colourName" },
  { id: "textile.char.colourHex",  stage: "dyeing", section: "characteristics", group: "Product Appearance", label: "Colour Hex",     type: "color",  phase: 2, regRef: "EPRS Fig.14 — Colour",      vcPath: "appearance.colourHex" },
  { id: "textile.char.size",       stage: "brand",  section: "characteristics", group: "Product Appearance", label: "Size",           type: "select", phase: 2, regRef: "EPRS Fig.14 — Size",        vcPath: "appearance.size" },
  { id: "textile.char.targetGroup", stage: "brand", section: "characteristics", group: "Product Appearance", label: "Target Group",   type: "select", phase: 2, regRef: "EPRS Fig.14 — Description", vcPath: "appearance.targetGroup", options: ["Women", "Men", "Unisex", "Girls", "Boys", "Baby / Infant"] },
  { id: "textile.char.season",     stage: "brand",  section: "characteristics", group: "Product Appearance", label: "Season",         type: "select", phase: 2, regRef: "EPRS Fig.14 — Description", vcPath: "appearance.season" },
  { id: "textile.char.marketingYear", stage: "brand", section: "characteristics", group: "Product Appearance", label: "Marketing Year", type: "number", phase: 2, regRef: "EPRS Fig.14 — Finished Product", vcPath: "appearance.marketingYear", validation: { min: 2020, max: 2050 } },
  { id: "textile.char.batchRef",   stage: "garment", section: "characteristics", group: "Production Batch", label: "Batch Reference", type: "text",   phase: 2, regRef: "EPRS Fig.14 — Quantity", vcPath: "batch.reference" },
  { id: "textile.char.unitsProduced", stage: "garment", section: "characteristics", group: "Production Batch", label: "Units Produced", type: "number", phase: 2, regRef: "EPRS Fig.14 — Quantity", vcPath: "batch.units", validation: { min: 1 } },
  // Repairability & Care (ESPR Annex I(b) — flagship repair parameter; Annex III(f) — user/care info)
  { id: "textile.char.repairScore",      stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Repairability Score",      type: "select",   phase: 2, regRef: "ESPR Annex I(b)",   vcPath: "repairability.score",        options: ["A", "B", "C", "D", "E", "Not assessed"] },
  { id: "textile.char.spareParts",       stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Spare Parts Availability", type: "select",   phase: 2, regRef: "ESPR Annex I(b)",   vcPath: "repairability.spareParts",   options: ["Available", "Limited", "Not available"] },
  { id: "textile.char.repairInstructions", stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Repair Instructions (URL)", type: "text", phase: 2, regRef: "ESPR Annex I(b)", vcPath: "repairability.instructionsUrl" },
  { id: "textile.char.careInstructions", stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Care Instructions",        type: "textarea", phase: 2, regRef: "ESPR Annex III(f)", vcPath: "use.careInstructions" },
  { id: "textile.char.safetyWarnings",   stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Safety Warnings",          type: "textarea", phase: 2, regRef: "ESPR Annex III(f)", vcPath: "use.safetyWarnings" },
  // Structured care labels (ISO 3758 / GINETEX symbol set). Enumerated so the
  // consumer viewer can render standardized care symbols instead of free text;
  // `careInstructions` above stays as the free-text supplement.
  { id: "textile.char.careWash",     stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Washing",      type: "select", phase: 2, regRef: "ISO 3758 / ESPR Annex III(f)", vcPath: "use.care.wash",     options: ["Wash 30°", "Wash 40°", "Wash 60°", "Hand wash only", "Do not wash"] },
  { id: "textile.char.careBleach",   stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Bleaching",    type: "select", phase: 2, regRef: "ISO 3758 / ESPR Annex III(f)", vcPath: "use.care.bleach",   options: ["Do not bleach", "Non-chlorine bleach only", "Bleach allowed"] },
  { id: "textile.char.careDry",      stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Drying",       type: "select", phase: 2, regRef: "ISO 3758 / ESPR Annex III(f)", vcPath: "use.care.dry",      options: ["Do not tumble dry", "Tumble dry low", "Tumble dry medium", "Line dry"] },
  { id: "textile.char.careIron",     stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Ironing",      type: "select", phase: 2, regRef: "ISO 3758 / ESPR Annex III(f)", vcPath: "use.care.iron",     options: ["Do not iron", "Iron max 110 °C", "Iron max 150 °C", "Iron max 200 °C"] },
  { id: "textile.char.careDryClean", stage: "brand", section: "characteristics", group: "Repairability & Care", label: "Dry Cleaning", type: "select", phase: 2, regRef: "ISO 3758 / ESPR Annex III(f)", vcPath: "use.care.dryClean", options: ["Do not dry clean", "Professional dry clean (P)", "Professional wet clean (W)"] },

  // ─── composition (Rulebook §6.7 — Phase-1 core; fibers=spinning, SVHC=dyeing) ──
  { id: "textile.composition.fibers", stage: "spinning", section: "composition", group: "Material Composition", label: "Material Composition", type: "array", phase: 1, regRef: "Rulebook §6.7 / EPRS Fig.13", vcPath: "composition.fibers", validation: { required: true }, entryNumericKeys: ["pct"] },
  // SVHC details are CONDITIONALLY required — only when substances are actually
  // present. Most garments declare none (cf. "No harmful substances per AFIRM,
  // REACH"); a hard `required` here made every clean product unpublishable. The
  // presence flag carries the declaration; detail fields apply only when true.
  { id: "textile.composition.svhcPresent",  stage: "dyeing", section: "composition", group: "Substances of Concern", label: "Substances of Concern Present", type: "boolean", phase: 1, regRef: "Rulebook §6.7.1 / ESPR Art.7(5)", vcPath: "substances.present" },
  // ONE array field for ALL substances of concern — ESPR Art.7(5) requires each
  // substance individually declared, so the old single-instance scalar fields
  // (substances[].name etc.) could never represent a real declaration, and their
  // `[]` vcPath notation leaked malformed IRIs into the signed RDF. Entries:
  // { name, cas, hazard, location, concentration, exemption? }. vcPath is
  // `substances.items` (NOT `substances`) because svhcPresent already claims
  // `substances.present` on the same object.
  { id: "textile.composition.substances", stage: "dyeing", section: "composition", group: "Substances of Concern", label: "Substances of Concern", type: "array", phase: 1, regRef: "ESPR Art.7(5)(c) / Rulebook §6.7.1 / REACH", vcPath: "substances.items",
    options: ["CMR — Carcinogenic / Mutagenic / Reprotoxic", "PBT — Persistent / Bioaccumulative / Toxic", "Endocrine Disruptor", "Sensitiser"] },

  // ─── fabric formation (Taxonomy V2 Tier 2 — weaving/knitting process categories) ──
  // The stage the catalog was missing: a fabric mill is a DIFFERENT company from
  // the dyehouse in most real chains, yet had no role to bind and no fields to
  // attest — its data rode along as free text with no credential behind it.
  // Phase 2, none required: adding a stage must never retro-block publishes.
  { id: "textile.fabric.construction",  stage: "weaving", section: "composition", group: "Fabric Construction", label: "Fabric Construction", type: "select", phase: 2, regRef: "AA-PAR-TAX-501-V2.0 · T2 process categories", vcPath: "fabric.construction",
    options: ["Woven", "Knitted", "Non-woven", "Composite"] },
  { id: "textile.fabric.processType",   stage: "weaving", section: "composition", group: "Fabric Construction", label: "Formation Process", type: "select", phase: 2, regRef: "AA-PAR-TAX-501-V2.0 · T2 process classification (weaving/knitting/non-woven)", vcPath: "fabric.processType",
    options: ["Air-jet loom weaving", "Projectile loom weaving", "Rapier loom weaving", "Shuttle loom weaving", "Water-jet loom weaving", "Circular knitting", "Flatbed knitting", "Warp knitting", "Melt-blowing", "Needle punching", "Spunbond", "Spunlace"] },
  { id: "textile.fabric.weightGsm",     stage: "weaving", section: "composition", group: "Fabric Construction", label: "Fabric Weight (g/m²)", type: "number", phase: 2, regRef: "EPRS Fig.13 — Product characteristics", vcPath: "fabric.weightGsm", validation: { min: 0, max: 5000 } },
  { id: "textile.fabric.constructionDetail", stage: "weaving", section: "composition", group: "Fabric Construction", label: "Construction Detail", type: "text", phase: 2, regRef: "AA-PAR-TAX-501-V2.0 · T2 finished material", vcPath: "fabric.constructionDetail", validation: { maxLength: 200 } },

  // ─── commercial (Rulebook §6.6 — brand; not Phase-1 mandatory) ────────────────
  { id: "textile.commercial.purpose",     stage: "brand", section: "commercial", group: "Commercial Data", label: "Purpose / Target Industry", type: "select", phase: 2, regRef: "Rulebook §6.6.2", vcPath: "commercial.purpose" },
  { id: "textile.commercial.placedOnMarket", stage: "brand", section: "commercial", group: "Commercial Data", label: "Placed on Market",       type: "date",   phase: 2, regRef: "Rulebook §6.6.1", vcPath: "commercial.placedOnMarket" },
  { id: "textile.commercial.poRef",       stage: "brand", section: "commercial", group: "Commercial Data", label: "Purchase Order Reference",  type: "text",   phase: 3, regRef: "Rulebook §6.6.3", vcPath: "commercial.poRef" },
  { id: "textile.commercial.recallStatus", stage: "brand", section: "commercial", group: "Recall Information", label: "Recall Status",          type: "select", phase: 2, regRef: "Reg (EU) 2023/988 §6.6.4", vcPath: "recall.status", options: ["No active recall", "Under investigation", "Recall issued"] },
  { id: "textile.commercial.safetyGate",  stage: "brand", section: "commercial", group: "Recall Information", label: "EU Safety Gate Reference", type: "text",  phase: 2, regRef: "Reg (EU) 2023/988", vcPath: "recall.safetyGateRef" },
  { id: "textile.commercial.recallDesc",  stage: "brand", section: "commercial", group: "Recall Information", label: "Recall Description",      type: "textarea", phase: 2, regRef: "Reg (EU) 2023/988", vcPath: "recall.description" },

  // ─── marketing (non-regulatory — excluded from ESPR readiness) ────────────────
  { id: "textile.marketing.statement", stage: "brand", section: "marketing", group: "Brand Story", label: "Brand Statement",  type: "textarea", phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.statement", nonRegulatory: true },
  { id: "textile.marketing.hashtag",   stage: "brand", section: "marketing", group: "Brand Story", label: "Campaign Hashtag", type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.hashtag",   nonRegulatory: true },
  { id: "textile.marketing.website",   stage: "brand", section: "marketing", group: "Social & Web", label: "Brand Website",   type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.website",   nonRegulatory: true },
  { id: "textile.marketing.instagram", stage: "brand", section: "marketing", group: "Social & Web", label: "Instagram",       type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.instagram", nonRegulatory: true },
  // Each accepts either a handle ("@brand") or a full profile URL — the consumer
  // page normalizes both to a link, so a producer never has to guess the format.
  { id: "textile.marketing.facebook",  stage: "brand", section: "marketing", group: "Social & Web", label: "Facebook",        type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.facebook",  nonRegulatory: true, validation: { maxLength: 200 } },
  { id: "textile.marketing.x",         stage: "brand", section: "marketing", group: "Social & Web", label: "X (Twitter)",     type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.x",         nonRegulatory: true, validation: { maxLength: 200 } },
  { id: "textile.marketing.linkedin",  stage: "brand", section: "marketing", group: "Social & Web", label: "LinkedIn",        type: "text",     phase: 3, regRef: "Non-regulatory (brand)", vcPath: "marketing.linkedin",  nonRegulatory: true, validation: { maxLength: 200 } },

  // ─── supply-chain (EPRS Transports — leg fields; brand aggregates logistics) ──
  // Full multi-leg route as one JSON array field (entries: {from,to,mode,distanceKm,
  // date?,company?}). The six single-leg fields below stay as the DERIVED final leg
  // (phase-1 readiness binds to them); the editor writes both from one form.
  { id: "textile.supply.legs",        stage: "brand", section: "supply-chain", group: "Transport Route", label: "Transport Route (all legs)", type: "array", phase: 1, regRef: "EPRS Fig.13 — Transports", vcPath: "transport.legs", entryNumericKeys: ["distanceKm", "weightKg"] },
  // The six single-leg fields are the DERIVED final leg (the route's last entry);
  // the editor writes both from one form. vcPath `transport.finalLeg.*` — the old
  // `transport[].x` bracket notation produced a literal "transport[]" JSON key
  // (one leg max, malformed IRIs in signed RDF); the full route lives in
  // `transport.legs` above.
  { id: "textile.supply.legFrom",     stage: "brand", section: "supply-chain", group: "Transport Leg", label: "From (origin)",     type: "text",   phase: 1, regRef: "EPRS Fig.13 — Location", vcPath: "transport.finalLeg.from", vcShadowOf: "textile.supply.legs", validation: { required: true } },
  { id: "textile.supply.legTo",       stage: "brand", section: "supply-chain", group: "Transport Leg", label: "To (destination)", type: "text",   phase: 1, regRef: "EPRS Fig.13 — Location", vcPath: "transport.finalLeg.to", vcShadowOf: "textile.supply.legs",   validation: { required: true } },
  { id: "textile.supply.legMode",     stage: "brand", section: "supply-chain", group: "Transport Leg", label: "Transport Mode",   type: "select", phase: 1, regRef: "EPRS Fig.13 — Transports: Means", vcPath: "transport.finalLeg.mode", vcShadowOf: "textile.supply.legs", options: ["sea", "air", "road", "rail", "barge"] },
  { id: "textile.supply.legDistance", stage: "brand", section: "supply-chain", group: "Transport Leg", label: "Distance (km)",    type: "number", phase: 1, regRef: "EPRS Fig.13 — Transports: Distance", vcPath: "transport.finalLeg.distanceKm", vcShadowOf: "textile.supply.legs", validation: { min: 0 } },
  { id: "textile.supply.legDate",     stage: "brand", section: "supply-chain", group: "Transport Leg", label: "Shipment Date",    type: "date",   phase: 3, regRef: "EPRS — Transports: Date (contested)",    vcPath: "transport.finalLeg.date", vcShadowOf: "textile.supply.legs" },
  { id: "textile.supply.legCompany",  stage: "brand", section: "supply-chain", group: "Transport Leg", label: "Logistics Company", type: "text",  phase: 3, regRef: "EPRS — Transports: Company (contested)", vcPath: "transport.finalLeg.company", vcShadowOf: "textile.supply.legs" },

  // ─── environmental (EPRS env + circularity = Phase 1; animal = Phase 2) ───────
  // CO₂/PEF footprint is an ADVANCED (2030, phase 2) expectation, not a 2027 phase-1 baseline — demoted from required.
  { id: "textile.env.co2",            stage: "brand", section: "environmental", group: "Environmental Data", label: "CO₂ Footprint (kg CO₂e)", type: "number", phase: 2, regRef: "EPRS Fig.13 — Environmental Impact (PEF)", vcPath: "environmental.co2eKg", validation: { min: 0 } },
  { id: "textile.env.recyclability",  stage: "brand", section: "environmental", group: "Environmental Data", label: "Recyclability Index (%)", type: "number", phase: 1, regRef: "EPRS Fig.13 — Recyclability", vcPath: "environmental.recyclabilityPct", validation: { required: true, min: 0, max: 100 } },
  { id: "textile.env.water",          stage: "dyeing", section: "environmental", group: "Environmental Data", label: "Water Usage (L/kg)",     type: "number", phase: 2, regRef: "EPRS — Environmental Impact (advanced)", vcPath: "environmental.waterLPerKg", validation: { min: 0 } },
  { id: "textile.env.recycledContent", stage: "spinning", section: "environmental", group: "Environmental Data", label: "Recycled Content (%)",  type: "number", phase: 1, regRef: "EPRS Fig.13 — Composition", vcPath: "environmental.recycledContentPct", validation: { required: true, min: 0, max: 100 } },
  // Microplastic release — textile-specific (synthetic fibres); required only when
  // the product contains synthetics. EPRS Phase-1 flagged "plastic microfibers".
  // EPRS phase-1 asks for the PRESENCE of plastic microfibers (a flag), not a measured release rate.
  { id: "textile.env.microplastic",   stage: "spinning", section: "environmental", group: "Environmental Data", label: "Contains Plastic Microfibers", type: "boolean", phase: 1, regRef: "EPRS Fig.13 — Composition (microfibers)", vcPath: "environmental.microfibresPresent" },
  { id: "textile.env.circularityProgrammes", stage: "brand", section: "environmental", group: "Circularity Strategy", label: "Circularity Programmes", type: "array", phase: 2, regRef: "EPRS Fig.13 — Circularity Strategy", vcPath: "circularity.programmes", options: ["Take-Back Scheme", "Repair Network", "Rental / Leasing", "Resale Programme", "Upcycling Service"] },
  { id: "textile.env.programmeUrl",   stage: "brand", section: "environmental", group: "Circularity Strategy", label: "Programme URL",          type: "text",     phase: 2, regRef: "EPRS — Circularity", vcPath: "circularity.programmeUrl" },
  { id: "textile.env.eolInstructions", stage: "brand", section: "environmental", group: "Circularity Strategy", label: "End-of-Life Instructions", type: "textarea", phase: 1, regRef: "EPRS Fig.13 — Circularity Strategy", vcPath: "circularity.endOfLife", validation: { required: true } },
  { id: "textile.env.takeback",       stage: "brand", section: "environmental", group: "Circularity Strategy", label: "Take-Back Instructions", type: "textarea", phase: 2, regRef: "EPRS — Circularity / WFD Art.11b", vcPath: "circularity.takeback" },
  // Option lists mirror the brand editor's (they were previously hard-coded there
  // as JSX — the catalog is now the single source of truth for valid values).
  { id: "textile.env.animalType",     stage: "cotton-farming", section: "environmental", group: "Animal Impact", label: "Animal Material Type",      type: "select", phase: 2, regRef: "EPRS Fig.14 — Animal Impact", vcPath: "animal.materialType",
    options: ["Wool", "Cashmere", "Silk", "Leather (bovine)", "Leather (other)", "Down / Feathers", "Fur", "Exotic leather", "Other"] },
  { id: "textile.env.animalCountry",  stage: "cotton-farming", section: "environmental", group: "Animal Impact", label: "Country of Animal Origin",  type: "text",   phase: 2, regRef: "EPRS Fig.14 — Animal Impact", vcPath: "animal.countryOfOrigin" },
  { id: "textile.env.welfareStandard", stage: "cotton-farming", section: "environmental", group: "Animal Impact", label: "Welfare Standard",         type: "select", phase: 2, regRef: "EPRS Fig.14 — Animal Impact", vcPath: "animal.welfareStandard",
    options: ["Responsible Wool Standard (RWS)", "ZQ Merino", "Responsible Down Standard (RDS)", "Certified Humane", "Global Animal Partnership (GAP)", "No certified standard", "Not applicable"] },
  { id: "textile.env.welfareBody",    stage: "cotton-farming", section: "environmental", group: "Animal Impact", label: "Welfare Certification Body", type: "text",  phase: 2, regRef: "EPRS Fig.14 — Animal Impact", vcPath: "animal.welfareBody" },

  // ─── cultivation & farm practice (farm-stage; Papile & Del Curto 2025 Fig. 5:
  //     fiber origin, treatments, certifications — the raw-fiber end of the DPP) ──
  { id: "textile.farm.cultivationMethod", stage: "cotton-farming", section: "identity", group: "Cultivation & Farm Practice", label: "Cultivation Method", type: "select", phase: 2, regRef: "EPRS Fig.13 — Fibre origin; Papile & Del Curto 2025 Fig.5", vcPath: "origin.cultivationMethod",
    options: ["Conventional cotton", "Organic (certified)", "Organic (in conversion)", "Better Cotton (BCI)", "Regenerative (certified)", "Recycled cotton feedstock"] },
  { id: "textile.farm.pesticideUse",      stage: "cotton-farming", section: "identity", group: "Cultivation & Farm Practice", label: "Pesticide Use", type: "select", phase: 2, regRef: "Papile & Del Curto 2025 Fig.5 — Treatments", vcPath: "origin.pesticideUse",
    options: ["None — pesticide-free", "Reduced — integrated pest management (IPM)", "Conventional pesticide regime"] },
  { id: "textile.farm.certification",     stage: "cotton-farming", section: "identity", group: "Cultivation & Farm Practice", label: "Farm Certification", type: "select", phase: 2, regRef: "Papile & Del Curto 2025 Fig.5 — Certifications", vcPath: "origin.farmCertification",
    options: ["GOTS — Global Organic Textile Standard", "OCS — Organic Content Standard", "BCI — Better Cotton Initiative", "Fairtrade Cotton", "regenagri", "None"] },

  // ─── packaging (PPWR — per-layer; recycled/recyclable/disposal = Phase-1) ─────
  // The scalar fields describe the PRIMARY layer (derived by the packaging route
  // from the validated Passport.packaging json; phase-1 readiness binds to them).
  // vcPath `packaging.primary.*` — the old `packaging[].x` bracket notation
  // produced a literal "packaging[]" key (one layer max, malformed IRIs in signed
  // RDF). The FULL layer array is the derived `packaging.layers` field below.
  { id: "textile.packaging.role",         stage: "brand", section: "packaging", group: "Packaging Layer", label: "Role",                 type: "select", phase: 1, regRef: "PPWR Art.11",   vcPath: "packaging.primary.role", vcShadowOf: "textile.packaging.layers",        validation: { required: true } },
  { id: "textile.packaging.material",     stage: "brand", section: "packaging", group: "Packaging Layer", label: "Material Type",        type: "select", phase: 1, regRef: "PPWR Annex II", vcPath: "packaging.primary.material", vcShadowOf: "textile.packaging.layers",    validation: { required: true } },
  { id: "textile.packaging.weight",       stage: "brand", section: "packaging", group: "Packaging Layer", label: "Weight (g)",           type: "number", phase: 1, regRef: "PPWR Art.9",    vcPath: "packaging.primary.weightG", vcShadowOf: "textile.packaging.layers",     validation: { required: true, min: 0 } },
  { id: "textile.packaging.recyclability", stage: "brand", section: "packaging", group: "Packaging Layer", label: "Recyclability Grade",  type: "select", phase: 1, regRef: "PPWR Art.6",    vcPath: "packaging.primary.recyclabilityGrade", vcShadowOf: "textile.packaging.layers", validation: { required: true } },
  { id: "textile.packaging.materialCode", stage: "brand", section: "packaging", group: "Packaging Layer", label: "Material Code",        type: "text",   phase: 2, regRef: "ISO/DIN code",  vcPath: "packaging.primary.materialCode", vcShadowOf: "textile.packaging.layers" },
  { id: "textile.packaging.recycledPct",  stage: "brand", section: "packaging", group: "Packaging Layer", label: "Recycled Content %",   type: "number", phase: 1, regRef: "PPWR Art.7 / EPRS Fig.13", vcPath: "packaging.primary.recycledContentPct", vcShadowOf: "textile.packaging.layers", validation: { required: true, min: 0, max: 100 } },
  { id: "textile.packaging.disposal",     stage: "brand", section: "packaging", group: "Packaging Layer", label: "Disposal Instructions", type: "text",  phase: 1, regRef: "PPWR Art.11",   vcPath: "packaging.primary.disposal", vcShadowOf: "textile.packaging.layers",    validation: { required: true } },
  // ALL packaging layers (primary + secondary + transport …) as one array —
  // derived by the packaging route from the validated layers json, never typed by
  // hand. Entries: { role, materialType, weightGrams, recyclabilityGrade,
  // recycledContentPct, disposalInstructions, materialCode? }.
  { id: "textile.packaging.layers",       stage: "brand", section: "packaging", group: "Packaging Layer", label: "All Packaging Layers", type: "array", phase: 1, regRef: "PPWR Art.9/11 (all components)", vcPath: "packaging.layers", entryNumericKeys: ["weightGrams", "recycledContentPct"] },

  // ─── compliance (brand) ───────────────────────────────────────────────────────
  { id: "textile.compliance.delegatedAct", stage: "brand", section: "compliance", group: "Legal & Compliance", label: "ESPR Delegated Act",          type: "text",   phase: 1, regRef: "ESPR", vcPath: "compliance.delegatedAct" },
  { id: "textile.compliance.reach",        stage: "brand", section: "compliance", group: "Legal & Compliance", label: "REACH Compliance",            type: "select", phase: 1, regRef: "REACH / Rulebook §6.7", vcPath: "compliance.reach", validation: { required: true } },
  { id: "textile.compliance.doc",          stage: "brand", section: "compliance", group: "Legal & Compliance", label: "Declaration of Conformity No.", type: "text", phase: 2, regRef: "ESPR", vcPath: "compliance.declarationOfConformity" },
  // Sustainability certifications (GOTS, OEKO-TEX, GRS, …). The most prominent
  // consumer-facing block in live DPPs (TrusTrace, Spherity) and a natural VC in
  // the trust layer — a GOTS certificate IS a third-party attestation. Optional:
  // uncertified products remain publishable.
  // ONE array field for ALL certifications — a product routinely holds several
  // (GOTS + OEKO-TEX + GRS …); the old single-instance scalar fields could hold
  // exactly one, and their `[]` vcPath notation leaked malformed IRIs into the
  // signed RDF.
  //
  // Entries follow the UNTP Digital Conformity Credential pattern (conformity
  // claim → independent assessment): { scheme, number?, scope?, certifier?,
  // expiryDate?, evidenceUrl?, certifierDid? }.
  //   - `certifier`   : the certification BODY (e.g. "Control Union") — who
  //                     assessed the claim, distinct from who states it here.
  //   - `expiryDate`  : certificate validity end (named expiryDate, NOT
  //                     validUntil — that term is @protected by the VCDM 2.0
  //                     context and must not be shadowed inside signed subjects).
  //   - `certifierDid`: RESERVED slot for a real third-party attestation (the
  //                     certifier's own signed credential / DID). Empty today —
  //                     until it is populated, every entry is a SELF-DECLARED
  //                     claim by the operator, and the UI must label it so.
  // `options` is the scheme vocabulary consumed by the row editor's select.
  { id: "textile.compliance.certifications", stage: "brand", section: "compliance", group: "Certifications", label: "Certifications", type: "array", phase: 1, regRef: "EPRS Fig.13 — Certifications", vcPath: "certifications",
    options: ["GOTS — Global Organic Textile Standard", "OEKO-TEX Standard 100", "OEKO-TEX STeP", "GRS — Global Recycled Standard", "OCS — Organic Content Standard", "RCS — Recycled Claim Standard", "bluesign", "Fairtrade Textile Standard", "EU Ecolabel", "Cradle to Cradle Certified", "Other"] },
];
