/**
 * ─── dpp-core / vc / envelope ─────────────────────────────────────────────────
 *
 * The W3C VC (VCDM 2.0) envelope builder, as a PURE function — one
 * implementation that Node and a browser both run to produce BYTE-IDENTICAL
 * unsigned credential bodies.
 *
 * WHY this is not a backend module (D7 / WYSIWYS)
 * ------------------------------------------------
 * Design A actors sign in their OWN browser with a non-custodial key (Web3Auth
 * tKey, 2-of-3; the platform holds no share and cannot sign). A signature over
 * bytes the server handed down finished would make non-custody of KEYS but not
 * non-custody of CONTENT: the screen could say one thing and the signed bytes
 * another. So the browser must ASSEMBLE the envelope from the values it
 * displayed, and the server must be able to rebuild the same bytes to check
 * them (see the content-mismatch check in the Design A ceremony routes). Two
 * implementations of "the same" format would diverge on the first edit; there
 * is one, and it lives here.
 *
 * WHY every URL is a parameter
 * ----------------------------
 * The `@context` URL, the `credentialSchema` id and the credential `id` are all
 * derived on the server from `config.credentialOrigin`. Reading config here —
 * directly or through one import hop — is exactly what made this code
 * un-runnable in a browser. They are inputs instead. This module imports
 * NOTHING, touches no `process.env`, no `window`, no I/O, and no clock: same
 * arguments in, same bytes out, in either runtime.
 *
 * FROZEN FORMAT — Design B is live in production and its signed bytes are
 * immutable. Member INSERTION ORDER below is observable (the enveloped JSON is
 * serialized as-is when served, and golden vectors pin the hashes), so treat
 * the order of the returned object literal as part of the contract, not as
 * style. Changing it breaks credentials that already exist in the world.
 */

/**
 * BitstringStatusList v1.0 revocation entry (VCDM 2.0 `credentialStatus`).
 * Lives here rather than backend-side because it lands INSIDE the signed bytes:
 * a browser that must reproduce those bytes must be able to name this shape.
 */
export interface CredentialStatusEntry {
  id: string;
  type: "BitstringStatusListEntry";
  statusPurpose: "revocation";
  statusListCredential: string;
  statusListIndex: string;
}

/**
 * The per-role contribution an envelope is built from — the MINIMAL structural
 * subset the builder actually reads.
 *
 * Deliberately not the backend's `UnsignedCredential` (domain/integrity/
 * canonical.ts). That type carries `nodeId` / `fieldIds` (server bookkeeping
 * the envelope never touches) and its module imports the workflow ownership
 * resolver — moving it here would drag the backend's chain-ownership logic into
 * a kernel that must stay dependency-free and browser-safe. Restating the three
 * members it needs keeps the arrow pointing outward: `UnsignedCredential`
 * satisfies this structurally, so backend callers pass one unchanged and no
 * conversion, cast or adapter type is required at the boundary.
 */
export interface RoleCredentialInput {
  /** The supply-chain role this credential covers (dpp-core stage vocabulary). */
  role: string;
  /** Issuer DID resolved from the bound node's org, or null (brand / unbound). */
  issuerDid?: string | null;
  /** Field values already placed at their `vcPath`. */
  credentialSubject: Record<string, unknown>;
}

/**
 * The DppTierCredential's unsigned body.
 *
 * A `type` ALIAS, not an `interface`, and that is load-bearing: the backend's
 * `VcEnvelope` extends `UnsignedCredentialEnvelope`, which carries an
 * `[key: string]: unknown` index signature. TypeScript infers an implicit index
 * signature for object-literal type aliases but NOT for interfaces, so
 * declaring this as an interface would make the adapter's return fail to
 * type-check and force an `as unknown as` cast — a cast at exactly the seam
 * where the compiler is the only thing checking that the shared builder still
 * produces what the seam promises.
 */
export type DppTierCredentialBody = {
  "@context": string[];
  type: string[];
  /**
   * OPTIONAL here, and required only on the PUBLISHED form
   * ({@link DppTierCredentialEnvelope}).
   *
   * The attestation body a contributor signs deliberately carries no `id`: the
   * credential id is minted per publish and would otherwise sit inside bytes
   * somebody else signed. Making it optional on the base type is what lets one
   * object literal serve both shapes, so their member order cannot drift.
   */
  id?: string;
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSchema: { id: string; type: "JsonSchema" };
  credentialStatus?: CredentialStatusEntry;
  credentialSubject: Record<string, unknown>;
  // `proof` is attached by the securing mechanism (Design B: domain/sign.ts).
};

/** The PUBLISHED form — a body that carries its dereferenceable credential id.
 *  This is what `buildCredentialEnvelope` returns and what the backend's
 *  `VcEnvelope` (which requires `id`) is checked against. */
export type DppTierCredentialEnvelope = DppTierCredentialBody & { id: string };

/**
 * JSON-LD safety: `id` is a RESERVED alias for `@id` and must be a string IRI at
 * every nesting level. Some catalog arrays carry a client-side row key
 * (packaging layers ship `id: 1`, a React list key with no regulatory meaning),
 * and a numeric `id` makes JSON-LD expansion — and therefore signing — fail with
 * `"@id" value must a string`.
 *
 * Strip those: an `id` whose value is NOT a string is UI bookkeeping, never data.
 * Legitimate ids (credentialSubject.id = the product DID, passport.id = urn:uuid)
 * are strings and survive untouched. Coercing to a string instead would mint a
 * meaningless IRI into signed bytes — dropping is the honest fix.
 *
 * Key order is preserved (`Object.entries` iterates insertion order), because
 * the surviving keys' order is part of the frozen serialization.
 */
export function stripNonStringIds<T>(value: T): T {
  if (Array.isArray(value)) return value.map(stripNonStringIds) as unknown as T;
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (k === "id" && typeof v !== "string") continue; // drop UI-only row keys
    out[k] = stripNonStringIds(v);
  }
  return out as unknown as T;
}

/**
 * Build one unsigned DppTierCredential body.
 *
 * `@context`: credentials/v2 + the caller-supplied TrustDPP context (the
 * semantic layer that makes RDF canonicalization of the full credentialSubject
 * lossless). `id`: a DEREFERENCEABLE https URL the caller mints — pinned to the
 * credential-origin domain, not to APP_URL, because it is frozen in the signed
 * bytes and must resolve forever.
 *
 * issuer resolution: the owning node's org DID; roles no node covers fall back
 * to the BRAND's org DID (the ESPR Art. 9 responsible operator attests what its
 * chain didn't), never to a fake value.
 *
 * Purity note: `Date` in / ISO string out. Converting here rather than in each
 * caller is the point — `toISOString()` is the one lexical form the signature
 * covers, and a browser re-deriving it independently is a byte-divergence
 * waiting to happen. The function never reads the clock; the instant is an
 * argument.
 */
export function buildCredentialEnvelope(params: {
  /** JSON-LD context IRI frozen into `@context` (server: CONTEXT_URL_V3). */
  contextUrl: string;
  /** JSON Schema IRI frozen into `credentialSchema` (server: SCHEMA_URL_V2). */
  schemaUrl: string;
  /** Dereferenceable credential URL (…/api/public/credentials/<rowId>). */
  id: string;
  credential: RoleCredentialInput;
  productDid: string | null;
  brandOrgDid: string | null;
  validFrom: Date;
  /** Passport expiration (textile.metadata.expiryDate — phase-1 required). */
  validUntil?: Date | null;
  /** BitstringStatusList revocation entry (allocated per issuer org at publish). */
  credentialStatus?: CredentialStatusEntry | null;
}): DppTierCredentialEnvelope {
  const {
    contextUrl, schemaUrl, credential, id, productDid, brandOrgDid,
    validFrom, validUntil, credentialStatus,
  } = params;
  // The narrowing is safe by construction: `id` is a required parameter here, so
  // `assemble` inserts the member. TypeScript cannot see through the conditional
  // spread, and this is the one place that fact is asserted rather than checked.
  return assemble(
    { contextUrl, schemaUrl, credential, productDid, brandOrgDid, validFrom, validUntil, credentialStatus },
    id,
  ) as DppTierCredentialEnvelope;
}

/**
 * The ATTESTATION body — what a contributor's browser actually signs.
 *
 * Identical to {@link buildCredentialEnvelope} except that `id` is absent, and
 * that absence is load-bearing rather than incidental:
 *
 * `Credential.id` is minted per PUBLISH (`vc_<random>`, the primary key of an
 * append-only table). A contributor signs once, at contribution time, and their
 * envelope may be reused across several re-publishes — so an `id` inside the
 * signed bytes would either collide on that key or force the server to rewrite
 * `id` inside bytes somebody else signed. The id therefore lives in the VCDM 2.0
 * enveloping wrapper, outside the signature. The upload route REFUSES a payload
 * that carries one.
 *
 * `validFrom` stays a parameter, and it is the SIGNER's instant, not the
 * server's: the contributor is asserting when THEY made this claim. The server
 * reads it back out of the token and rebuilds with that same value in order to
 * compare — which is only sound because this function is what both sides run.
 *
 * This exists in the kernel, rather than as a `delete body.id` on the server,
 * precisely because the browser has to reproduce it. A subtraction rule that
 * lives only in backend code is a rule the browser will eventually get wrong,
 * and the failure mode is a signature over bytes nobody can re-derive.
 */
export function buildAttestationBody(params: {
  contextUrl: string;
  schemaUrl: string;
  credential: RoleCredentialInput;
  productDid: string | null;
  brandOrgDid: string | null;
  /** The SIGNER's instant — whoever calls this is the one asserting it. */
  validFrom: Date;
  validUntil?: Date | null;
  credentialStatus?: CredentialStatusEntry | null;
}): Omit<DppTierCredentialBody, "id"> {
  return assemble(params, undefined);
}

/**
 * The one object literal. Both entry points go through it so the member
 * INSERTION ORDER — which is part of the frozen format, not style — cannot
 * drift between "with id" and "without id".
 *
 * Omitting `id` via a conditional spread rather than deleting it afterwards
 * keeps every following member in the same position, so the attestation body is
 * exactly the published envelope minus one key.
 */
function assemble(
  params: {
    contextUrl: string;
    schemaUrl: string;
    credential: RoleCredentialInput;
    productDid: string | null;
    brandOrgDid: string | null;
    validFrom: Date;
    validUntil?: Date | null;
    credentialStatus?: CredentialStatusEntry | null;
  },
  id: string | undefined,
): DppTierCredentialBody {
  const {
    contextUrl, schemaUrl, credential, productDid, brandOrgDid,
    validFrom, validUntil, credentialStatus,
  } = params;
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", contextUrl],
    type: ["VerifiableCredential", "DppTierCredential"],
    // `undefined` omits the member entirely; an empty string does NOT — callers
    // that pass "" still get `id: ""`, which is the pre-existing behaviour.
    ...(id === undefined ? {} : { id }),
    // Publish pre-validates that every issuer org holds a real DID (422 if not) —
    // the old "did:web:unresolved" sentinel minted a fake issuer into signed bytes.
    // The message names the backend entry point (`buildVcEnvelope`) on purpose:
    // that is what operators see in the stack and grep for in logs.
    issuer: credential.issuerDid ?? brandOrgDid ?? (() => {
      throw new Error("buildVcEnvelope: no issuer DID — publish pre-validation must prevent this");
    })(),
    validFrom: validFrom.toISOString(),
    ...(validUntil ? { validUntil: validUntil.toISOString() } : {}),
    credentialSchema: { id: schemaUrl, type: "JsonSchema" },
    ...(credentialStatus ? { credentialStatus } : {}),
    // Sanitized: any nested non-string `id` (UI row keys) is dropped so JSON-LD
    // expansion — and therefore signing — cannot fail on `"@id" must be a string`.
    credentialSubject: stripNonStringIds({
      id: productDid ?? undefined,
      role: credential.role,
      ...credential.credentialSubject,
    }),
  };
}
