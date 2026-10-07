/**
 * dpp-core — canonical DPP schema + engine (framework-agnostic, dependency-free).
 *
 * Single source of truth for DPP fields, consumed by the form, validator, VC
 * assembler and verifier. Designed to move to a shared `packages/dpp-core` with
 * no code change when the backend wires in.
 */
export type {
  Phase, Sector, Stage, TextileStage, FieldType, FieldValidation,
  DppFieldSpec, SectorFieldSpec,
  StageRole, StageSpec, SectorStageSpec,
} from "./engine/types.js";

export {
  DPP_FIELDS,
  getFieldById,
  isRequired,
  PHASE_COUNTS,
  PHASE1_MANDATORY,
  phase1MandatoryFor,
  phaseCountsFor,
  SUPPORTED_SECTORS,
  isSectorSupported,
  isSupportedCategory,
  // Supply-chain stage vocabulary (single source of truth for supplier roles):
  DPP_STAGES,
  stagesForSector,
  supplierStagesFor,
  operatorStageFor,
  getStageById,
  stageLabel,
  sectorOfStage,
  isValidStage,
  isSupplierStageInSector,
} from "./engine/registry.js";

export { validateFieldValue } from "./engine/validate.js";
export { isGtinShape, gs1CheckDigit, isValidGtin, normalizeGtin14 } from "./engine/gs1.js";

export { TEXTILE_FIELDS } from "./sectors/textile.js";
export { TEXTILE_STAGES } from "./sectors/textile.stages.js";

// The W3C VC envelope builder — pure and isomorphic, so the browser that
// DISPLAYS a credential's values can build the exact bytes it then signs with a
// non-custodial key, and the server can rebuild them to check (D7 / WYSIWYS).
export type { CredentialStatusEntry, RoleCredentialInput, DppTierCredentialBody } from "./vc/envelope.js";
export { buildCredentialEnvelope, buildAttestationBody, stripNonStringIds } from "./vc/envelope.js";

export type { TaxNode, FlatCategory } from "./taxonomy.js";
export { DPP_TAXONOMY, flattenTaxonomy, isKnownCategory, delegatedActFor, sectorForCategory } from "./taxonomy.js";
