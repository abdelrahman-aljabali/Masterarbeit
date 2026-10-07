/**
 * ─── The seam's vocabulary ────────────────────────────────────────────────────
 * The shapes `TrustProvider` speaks in. They belong to the INTERFACE, not to any
 * one design: a verification verdict, a subject's public keys, the result of a
 * key revocation, the result of a custody re-wrap. Design B produces them today;
 * Design A must produce the same shapes.
 */

// ── What "a credential" IS (the A/B representation split) ────────────────────

/**
 * The two designs do not produce the same KIND of artefact, and the seam used to
 * pretend they did (`Record<string, unknown>` on every credential parameter and
 * return) — finding H2 of the W3C compliance review:
 */

/** A JSON-LD `@context`: one IRI, or an array of IRIs / inline context objects. */
export type JsonLdContext = string | (string | Record<string, unknown>)[];

/**
 * An UNSIGNED credential body: a plain JSON object in BOTH designs (B
 * canonicalizes it and appends `proof`; A serializes it as the JWS payload).
 * This is deliberately NOT the union — see `prepareCredential`, which decorates
 * a credential BEFORE it is secured. Naming the shape is the whole gain: it used
 * to be `Record<string, unknown>`, which said nothing about being unsigned.
 */
export interface UnsignedCredentialEnvelope {
  "@context": JsonLdContext;
  /** VCDM 2.0: always an array, always containing "VerifiableCredential". */
  type: string[];
  [key: string]: unknown;
}

/** One proof on an embedded-proof credential (B: a DataIntegrityProof). */
export interface EmbeddedProof {
  type: string;
  cryptosuite?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  [key: string]: unknown;
}

/**
 * Design B's representation: the credential body WITH its proof inside it.
 */
export interface EmbeddedProofCredential extends UnsignedCredentialEnvelope {
  /** VCDM permits a SET of proofs; the first is the one verdicts report on. */
  proof?: EmbeddedProof | EmbeddedProof[];
}

/**
 * Media types that may appear inside an enveloped credential's `data:` URL.
 */
export const ENVELOPED_MEDIA_TYPES = ["application/vc+jwt"] as const;
export type EnvelopedMediaType = (typeof ENVELOPED_MEDIA_TYPES)[number];

/** VCDM 2.0's fixed `type` for the enveloping wrapper — and our discriminant. */
export const ENVELOPED_CREDENTIAL_TYPE = "EnvelopedVerifiableCredential";

/** `data:application/vc+jwt,<compact JWS>` — RFC 2397, no `;base64` (a JWS is
 *  already base64url text). */
export type EnvelopedCredentialId = `data:${EnvelopedMediaType},${string}`;

/**
 * Design A's representation: the VCDM 2.0 enveloping wrapper. Exactly three
 * members — anything else would be data the signature does not cover, i.e. a
 * place to smuggle unsigned claims past a verifier that only checks the JWS.
 */
export interface EnvelopedCredential {
  "@context": JsonLdContext;
  type: typeof ENVELOPED_CREDENTIAL_TYPE;
  id: EnvelopedCredentialId;
}

/**
 * What the seam hands around: either representation. Callers that only move a
 * credential (store it, hash it, hand it to a verifier) need no branch; callers
 * that want the SECURED BYTES must ask, via `isEnvelopedCredential` /
 * `envelopedCredentialBytes` — which is exactly the question that
 * `Record<string, unknown>` made unaskable.
 */
export type VerifiableEnvelope = EmbeddedProofCredential | EnvelopedCredential;

/** The securing mechanism's own bytes, pulled out of the wrapper's `data:` URL. */
export interface EnvelopedCredentialBytes {
  mediaType: EnvelopedMediaType;
  /** A compact JWS for application/vc+jwt. Serve/verify these bytes VERBATIM. */
  token: string;
}

/** Three non-empty base64url segments = a compact JWS (RFC 7515 §3.1). */
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Discriminate the two representations, at runtime — these values come out of a
 * JSON column, so the compiler's word is not evidence.
 */
export function isEnvelopedCredential(value: unknown): value is EnvelopedCredential {
  if (!value || typeof value !== "object") return false;
  const type = (value as { type?: unknown }).type;
  if (type === ENVELOPED_CREDENTIAL_TYPE) return true;
  return Array.isArray(type) && type.length === 1 && type[0] === ENVELOPED_CREDENTIAL_TYPE;
}

/**
 * Parse a `data:` envelope URL into { mediaType, token }, or null if it is not
 * one we can serve.
 */
export function parseEnvelopedCredentialId(id: unknown): EnvelopedCredentialBytes | null {
  if (typeof id !== "string" || !id.startsWith("data:")) return null;
  const comma = id.indexOf(",");
  if (comma < 0) return null;
  const [type, ...params] = id.slice("data:".length, comma).split(";");
  const token = id.slice(comma + 1);
  if (params.some((p) => p.trim().toLowerCase() === "base64")) return null;
  const mediaType = (type ?? "").trim().toLowerCase();
  if (!(ENVELOPED_MEDIA_TYPES as readonly string[]).includes(mediaType)) return null;
  // Token shape is per media type — SD-JWT VC's `<jwt>~<disclosure>~…` would
  // fail a JWS check, which is why this is a switch and not one regex.
  if (mediaType === "application/vc+jwt" && !COMPACT_JWS.test(token)) return null;
  return { mediaType: mediaType as EnvelopedMediaType, token };
}

/** Guard + parse in one, for callers that only want the bytes (the public
 *  credential route). Null means "not an enveloped credential we can serve". */
export function envelopedCredentialBytes(value: unknown): EnvelopedCredentialBytes | null {
  return isEnvelopedCredential(value) ? parseEnvelopedCredentialId(value.id) : null;
}

// ── Verification ─────────────────────────────────────────────────────────────

export interface CredentialVerdict {
  id: string | null;
  issuer: string | null;
  role: string | null;
  verified: boolean;
  error: string | null;
  /**
   * What PRODUCED this verdict. Cached verdicts live on the immutable
   * PassportVersion row, so without this stamp a verdict computed under one trust
   * mode / cryptosuite / signing key would be served forever — including after
   * that key was REVOKED for compromise, which is exactly the moment the platform
   * must stop vouching for it.
   */
  mode: string;
  cryptosuite: string | null;
  verificationMethod: string | null;
}

// ── Signing-key lifecycle ────────────────────────────────────────────────────

/** Public half of one key, as the DID document renders it. */
export interface PublicKeyRecord {
  fragment: string;
  publicKeyMultibase: string;
  status: string; // active | retired | revoked
}

export interface KeyRevocation {
  /** Fragments removed from the DID document. */
  revoked: string[];
  /** The replacement active key, when the revoked key was the active one. */
  replacement: string | null;
  /** How many cached verification verdicts were dropped. */
  verdictsFlushed: number;
}

// ── Custody re-wrap (KEK rotation) ───────────────────────────────────────────

export interface RewrapReport {
  /** KEK id everything is being moved onto. */
  currentKekId: string;
  /** Rows not yet wrapped under it, by the kekId they currently carry. */
  stale: Record<string, number>;
  staleCount: number;
  totalKeys: number;
  rewrapped: number;
  /** Rows whose old KEK secret was unavailable — left untouched, never lost. */
  failures: { subjectId: string; fragment: string; error: string }[];
}
