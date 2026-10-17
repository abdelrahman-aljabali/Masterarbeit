import { config } from "../../config.js";
import type { TrustProvider } from "./TrustProvider.js";
import { DesignBTrust } from "./designB.js";

/**
 * ─── The ONLY legal doorway into the trust layer ──────────────────────────────
 * Everything outside `domain/trust/` imports from THIS file and nothing else
 * (ESLint `no-restricted-imports` enforces it — a bypass is a build error). Two
 * kinds of exports live here: the seam's types and pure helpers, and the active
 * design's provider.
 */

export type { TrustProvider, ChainHeadCommitment, CredentialVerdict, MintedDid, RevocableCredential } from "./TrustProvider.js";
export type { KeyRevocation, PublicKeyRecord } from "./types.js";

// The seam's credential vocabulary. Design-NEUTRAL by construction: the union
// exists precisely BECAUSE the two designs disagree about what a credential is,
// and the guard/extractor are pure functions over VCDM 2.0's own wrapper. The
// public credential route needs them to answer `Accept: application/vc+jwt`
// without knowing (or asking) which design signed the row.
export type {
  EmbeddedProof,
  EmbeddedProofCredential,
  EnvelopedCredential,
  EnvelopedCredentialBytes,
  EnvelopedCredentialId,
  EnvelopedMediaType,
  JsonLdContext,
  UnsignedCredentialEnvelope,
  VerifiableEnvelope,
} from "./types.js";
export {
  ENVELOPED_CREDENTIAL_TYPE,
  ENVELOPED_MEDIA_TYPES,
  envelopedCredentialBytes,
  isEnvelopedCredential,
  parseEnvelopedCredentialId,
} from "./types.js";

// ── Design-neutral shared surface ────────────────────────────────────────────
export { buildVcEnvelope, stripNonStringIds, type VcEnvelope, type CredentialStatusEntry } from "./vc.js";
export { credentialIdUrl, CONTEXT_URL, CONTEXT_URL_V2, CONTEXT_URL_V3, VOCAB_URL, VOCAB_UNREGISTERED_URL, SCHEMA_URL, SCHEMA_URL_V2, statusListUrl, HISTORICAL_CONTEXT_URLS, HISTORICAL_HOSTS } from "./trustUrls.js";
export {
  CREDENTIAL_SCHEMA_PATH,
  CREDENTIAL_SCHEMA_PATH_V2,
  DPP_TIER_CREDENTIAL_SCHEMA,
  DPP_TIER_CREDENTIAL_SCHEMA_V2,
} from "./credentialSchema.js";
export {
  DPP_CONTEXT, DPP_CONTEXT_PATH,
  DPP_CONTEXT_V2, DPP_CONTEXT_PATH_V2,
  DPP_CONTEXT_V3, DPP_CONTEXT_PATH_V3,
  VOCAB_PATH, vocabDictionary,
} from "./vcContext.js";
// Deployment self-check: do the identifiers we freeze into signed bytes actually
// resolve to THIS instance? Design-neutral — both designs pin the same URLs.
export { checkCredentialOrigin, credentialOriginStatus, startCredentialOriginWatch, type OriginCheckResult } from "./originCheck.js";

/**
 * The active trust provider, selected ONCE at boot from TRUST_MODE. This is the
 * single `if` in the whole trust story — after this line, no code branches on
 * the design; it all goes through `trust`. A process is one design for its life.
 */
async function selectTrustProvider(): Promise<TrustProvider> {
  switch (config.trustMode) {
    case "design-b":
      return new DesignBTrust();
    case "design-a": {
      // Thesis track — did:ethr + non-custodial tKey + on-chain anchoring.
      const { DesignATrust } = await import("./designA/index.js");
      return new DesignATrust();
    }
    default:
      throw new Error(`Unknown TRUST_MODE "${config.trustMode}" — expected "design-b" or "design-a".`);
  }
}

/**
 * Top-level await, deliberately. It makes this an async module, which in ESM is
 * transparent to importers — they simply await its evaluation — and it is what
 * lets the A branch be a dynamic import while `trust` stays a plain value that
 * 60-odd call sites can use synchronously. The alternative (exporting a promise
 * or an init function) would push async into every caller to save nothing.
 */
export const trust: TrustProvider = await selectTrustProvider();
