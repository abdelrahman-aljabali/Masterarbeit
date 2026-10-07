/**
 * Canonical identifiers frozen into signed credentials.
 */
import { config } from "../../config.js";
const CANONICAL_ORIGIN = config.credentialOrigin;
const isProduction = config.isProduction;

/** Frozen into every credential's `@context`. */
export const CONTEXT_URL = `${CANONICAL_ORIGIN}/contexts/dpp-v1.jsonld`;

/** v2 adds `@container: @list` on order-significant arrays. v1 stays frozen. */
export const CONTEXT_URL_V2 = `${CANONICAL_ORIGIN}/contexts/dpp-v2.jsonld`;

/**
 * v3 defines every term explicitly and demotes `@vocab` to a quarantine
 * namespace, so a typo can never silently mint a legitimate-looking term into
 * signed RDF. v1/v2 stay served forever — signed bytes reference them.
 */
export const CONTEXT_URL_V3 = `${CANONICAL_ORIGIN}/contexts/dpp-v3.jsonld`;

/** Namespace term IRIs live under; dereferenceable at `/vocab`. */
export const VOCAB_URL = `${CANONICAL_ORIGIN}/vocab#`;

/** The `@vocab` fallback. Anything landing here is catalog drift; CI fails on it. */
export const VOCAB_UNREGISTERED_URL = `${CANONICAL_ORIGIN}/vocab/unregistered#`;

/** Frozen into every credential's `credentialSchema`. */
export const SCHEMA_URL = `${CANONICAL_ORIGIN}/schemas/dpp-tier-credential.v1.json`;

/** v2 adds `validUntil` + `credentialStatus`. v1 stays served forever. */
export const SCHEMA_URL_V2 = `${CANONICAL_ORIGIN}/schemas/dpp-tier-credential.v2.json`;

/** Frozen into signed bytes via `credentialStatus.statusListCredential`. */
export const statusListUrl = (orgId: string, list = 1): string =>
  `${CANONICAL_ORIGIN}/status/${orgId}/${list}`;

/** Frozen in the signed VC; must resolve forever. */
export const credentialIdUrl = (rowId: string): string =>
  `${CANONICAL_ORIGIN}/api/public/credentials/${rowId}`;

/**
 * Every did:web HOST (encoded) this platform has minted DIDs under. In
 * production the document loader gates on this list, so an attacker-crafted
 * did:web pointing at a foreign host cannot resolve from our database.
 * APPEND ONLY.
 */
export const HISTORICAL_HOSTS: readonly string[] = [
  "trustdpp.io", // pre-2026-07 domain; its issuer DIDs are in signed bytes
  // Dev hosts from when did:web derived from APP_URL. They exist only in
  // developer databases, so allowing them in production would widen the host
  // gate for nothing.
  ...(isProduction ? [] : ["localhost%3A8080", "localhost%3A3001"]),
];

/**
 * Every `@context` URL ever minted into a signed credential. The offline loader
 * resolves any of them to the bundled context, so credentials signed before
 * pinning still verify. APPEND ONLY — removing one breaks verification of
 * everything signed against it.
 */
export const HISTORICAL_CONTEXT_URLS: readonly string[] = [
  CONTEXT_URL,
  "https://trustdpp.io/contexts/dpp-v1.jsonld",
  "http://localhost:8080/contexts/dpp-v1.jsonld",
  "http://localhost:3001/contexts/dpp-v1.jsonld",
];
