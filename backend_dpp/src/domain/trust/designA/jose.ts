import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";
import { keccak256 } from "../../integrity/keccak.js";
import {
  isEnvelopedCredential,
  parseEnvelopedCredentialId,
  type CredentialVerdict,
} from "../types.js";
import { didMatchesAddress, parseDidEthrOnChain, type ChainBinding } from "./didEthr.js";
import { asAddress, ZERO_ADDRESS, type Address } from "./chainTypes.js";

/**
 * ─── VC-JOSE-COSE / ES256K-R — VERIFY ONLY ────────────────────────────────────
 * # This file contains no signing function, and must never gain one.
 */

/** The trust mode these verdicts belong to. A LITERAL, never `config.trustMode`:
 *  this file IS the Design A verifier, so a verdict it produced was produced by
 *  Design A. (Mirrors sign.ts's `MODE`, and the seam's one-read-of-trustMode rule.) */
export const MODE = "design-a" as const;

/**
 * The cryptosuite stamp on every verdict this file produces.
 */
export const CRYPTOSUITE = "ES256K-R" as const;

/** The one `alg` this verifier accepts. */
export const ES256K_R = "ES256K-R";

/** `typ` values a credential JWS may carry. See {@link checkHeader}. */
const ACCEPTED_TYP = new Set(["vc+jwt", "application/vc+jwt", "jwt"]);

// ── Result shape ─────────────────────────────────────────────────────────────

/**
 * One named thing that was checked. Ordered, and the list STOPS at the first
 * failure: once "this is not a JWS" is established, four more checks over
 * garbage are noise, not diagnosis.
 */
export interface VerificationCheck {
  /** `envelope` | `header` | `signature` | `issuer-binding` | `credential-shape`,
   *  plus whatever composes in later (`authorization`, `issuer-key-current`, …). */
  name: string;
  ok: boolean;
  /** Why, in one line. Present on failures; usually null on successes. */
  detail: string | null;
}

/**
 * The verifier's full answer: the seam's `CredentialVerdict` plus the working
 * that produced it, for the callers that have to compose on top of it.
 */
export interface Es256kVerification {
  /** Exactly the seam's shape — this is what gets cached and served. */
  verdict: CredentialVerdict;
  checks: VerificationCheck[];
  /** Issuer DID as written IN THE SIGNED PAYLOAD (not from any adjacent JSON). */
  issuerDid: string | null;
  /** The address recovered from the signature, lower case. Null if recovery failed. */
  signerAddress: Address | null;
  /**
   * The decoded JWS payload — i.e. THE CREDENTIAL, the exact bytes the signature
   * covers. Trustworthy precisely as far as the `signature` check is `ok`; before
   * that it is attacker-controlled JSON. Exposed because the composing layers
   * (authorization, anchoring) need the issuer and the product out of it, and
   * re-decoding the token in three places is how two of them end up disagreeing.
   */
  credential: Record<string, unknown> | null;
  /** The compact JWS, verbatim. Serve/store THESE bytes; never a re-serialization. */
  token: string | null;
}

// ── The entry point ──────────────────────────────────────────────────────────

/**
 * Verify one enveloped credential, offline.
 *
 * Synchronous and chain-free on purpose. Everything here is a property of the
 * BYTES — the signature, and whether the recovered address is the one the
 * payload's own `issuer` DID names. Nothing in it can be affected by an RPC
 * being up, which means it is fast, deterministic, cacheable per version, and
 * testable without a network. The chain-dependent questions (is the issuer's key
 * still current? is the issuer authorized for this product?) are strictly
 * additive and compose in through {@link addCheck}.
 *
 * TOTAL: it never throws for bad input. Malformed envelopes, junk base64,
 * `alg: "none"`, a signature over other bytes — all come back as
 * `verified: false` with a reason, because "this does not verify" is an answer a
 * verifier owes its caller, not an exception.
 *
 * @param credential the VCDM 2.0 `EnvelopedVerifiableCredential` wrapper, or the
 *   bare compact JWS string.
 * @param chain the chain the issuer DID must be on. A DID for another chain is
 *   not this stack's to verify — same address, different owner.
 */
export function verifyEnvelopedCredential(credential: unknown, chain: ChainBinding): Es256kVerification {
  // ── 1. envelope → bytes ──────────────────────────────────────────────────
  const token = extractJws(credential);
  if (!token) {
    return fail("envelope", "not an enveloped credential (design-a verifies data:application/vc+jwt only)", {
      token: null,
    });
  }

  const segments = token.split(".");
  if (segments.length !== 3) {
    return fail("envelope", `compact JWS must have 3 segments, got ${segments.length}`, { token });
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];

  // ── 2. header ────────────────────────────────────────────────────────────
  const header = decodeJson(encodedHeader);
  if (!header.ok) return fail("header", `protected header: ${header.error}`, { token });
  const headerProblem = checkHeader(header.value);
  if (headerProblem) return fail("header", headerProblem, { token });

  // ── 3. payload ───────────────────────────────────────────────────────────
  // Decoded BEFORE the signature is checked only so that a failure can name the
  // issuer it claimed. Nothing is believed until `signature` is ok.
  const payload = decodeJson(encodedPayload);
  if (!payload.ok) return fail("header", `payload: ${payload.error}`, { token });
  const claims = payload.value;
  const issuerDid = readIssuer(claims);

  const base = {
    token,
    credential: claims,
    issuerDid,
    id: typeof claims.id === "string" ? claims.id : null,
    role: readRole(claims),
    verificationMethod: readVerificationMethod(header.value, issuerDid),
  };

  // ── 4. signature ─────────────────────────────────────────────────────────
  const signature = decodeBase64Url(encodedSignature);
  if (!signature.ok) return fail("signature", `signature segment: ${signature.error}`, base);
  let signerAddress: Address;
  try {
    signerAddress = recoverSignerAddress(`${encodedHeader}.${encodedPayload}`, signature.value);
  } catch (err) {
    return fail("signature", (err as Error).message, base);
  }

  // ── 5. issuer binding ────────────────────────────────────────────────────
  // The join. Everything above proved SOMEBODY signed these exact bytes; this
  // proves it was the principal the bytes name as issuer.
  if (!issuerDid) {
    return fail("issuer-binding", "credential has no `issuer`", { ...base, signerAddress });
  }
  const issuer = parseDidEthrOnChain(issuerDid, chain);
  if (!issuer) {
    return fail(
      "issuer-binding",
      `issuer is not a did:ethr on chain ${chain.chainId} (${chain.chainName}): ${truncate(issuerDid)}`,
      { ...base, signerAddress },
    );
  }
  if (!didMatchesAddress(issuerDid, signerAddress, chain)) {
    return fail(
      "issuer-binding",
      `signature recovers to ${signerAddress}, but the issuer DID names ${issuer.address}`,
      { ...base, signerAddress },
    );
  }
  const kidProblem = checkKid(header.value, issuerDid);
  if (kidProblem) return fail("issuer-binding", kidProblem, { ...base, signerAddress });

  // ── 6. credential shape ──────────────────────────────────────────────────
  const shapeProblem = checkCredentialShape(claims);
  if (shapeProblem) return fail("credential-shape", shapeProblem, { ...base, signerAddress });

  return build(
    [
      { name: "envelope", ok: true, detail: null },
      { name: "header", ok: true, detail: `alg=${ES256K_R}` },
      { name: "signature", ok: true, detail: `recovered ${signerAddress}` },
      { name: "issuer-binding", ok: true, detail: `${issuer.address} is ${issuer.did}` },
      { name: "credential-shape", ok: true, detail: null },
    ],
    { ...base, signerAddress },
  );
}

/**
 * Fold one more check into a result — the composition seam.
 */
export function addCheck(result: Es256kVerification, check: VerificationCheck): Es256kVerification {
  const checks = [...result.checks, { ...check }];
  return {
    ...result,
    checks,
    verdict: verdictFrom(checks, {
      id: result.verdict.id,
      issuer: result.verdict.issuer,
      role: result.verdict.role,
      verificationMethod: result.verdict.verificationMethod,
    }),
  };
}

// ── The envelope ─────────────────────────────────────────────────────────────

/**
 * Pull the compact JWS out of a VCDM 2.0 enveloped credential (or accept one
 * directly).
 */
export function extractJws(credential: unknown): string | null {
  if (typeof credential === "string") return credential.trim() || null;
  if (!isEnvelopedCredential(credential)) return null;
  return parseEnvelopedCredentialId(credential.id)?.token ?? null;
}

// ── ES256K-R ─────────────────────────────────────────────────────────────────

/**
 * Recover the Ethereum address that produced a 65-byte ES256K-R signature over
 * `signingInput`.
 */
export function recoverSignerAddress(signingInput: string, signature: Uint8Array): Address {
  if (signature.length !== 65) {
    throw new Error(`ES256K-R signature must be 65 bytes (r‖s‖v), got ${signature.length}`);
  }
  const recovery = signature[64]!;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`ES256K-R recovery id must be 0 or 1, got ${recovery}`);
  }

  // The digest. Plain SHA-256 over the ASCII signing input — no EIP-191 prefix.
  const digest = sha256(utf8ToBytes(signingInput));

  let parsed;
  try {
    parsed = secp256k1.Signature.fromCompact(signature.slice(0, 64));
  } catch {
    throw new Error("ES256K-R signature (r, s) is not a valid secp256k1 signature");
  }
  if (parsed.hasHighS()) {
    throw new Error("ES256K-R signature has high s — malleable encoding refused (EIP-2)");
  }

  let publicKey: Uint8Array;
  try {
    publicKey = parsed.addRecoveryBit(recovery).recoverPublicKey(digest).toRawBytes(false);
  } catch {
    throw new Error("ES256K-R signature does not recover to any public key");
  }
  // toRawBytes(false) → 0x04 ‖ X(32) ‖ Y(32). The address is over X‖Y only.
  const address = `0x${keccak256(publicKey.slice(1)).slice(-40)}`;
  if (address === ZERO_ADDRESS) {
    throw new Error("ES256K-R signature recovers to the zero address");
  }
  return asAddress(address, "recovered address");
}

// ── Header / payload checks ──────────────────────────────────────────────────

/** `null` when the header is acceptable, otherwise the reason it is not. */
function checkHeader(header: Record<string, unknown>): string | null {
  const alg = header.alg;
  if (typeof alg !== "string") return "protected header has no `alg`";
  if (alg !== ES256K_R) {
    // `none` gets its own sentence because it is the one an attacker tries:
    // RFC 7515's unsecured JWS is syntactically a JWS with an empty signature,
    // and a verifier that dispatches on `alg` without an allow-list accepts it.
    // This verifier has an allow-list of exactly one entry.
    return alg.toLowerCase() === "none"
      ? "refused `alg: none` — an unsecured JWS is not a credential"
      : `unsupported alg "${truncate(alg)}" — design-a verifies ${ES256K_R} only`;
  }
  if ("crit" in header) {
    // RFC 7515 §4.1.11: `crit` names extensions the verifier MUST understand.
    // We implement none, so any `crit` at all is an instruction we cannot honour
    // — and ignoring it is exactly what the header forbids.
    return "protected header carries `crit` — this verifier implements no JWS extensions";
  }
  const typ = header.typ;
  if (typ !== undefined) {
    // Present-but-wrong is refused; absent is tolerated (VC-JOSE-COSE only
    // RECOMMENDS `typ`, and older did-jwt output omits it). The refusal blocks
    // cross-protocol replay: the actor's key also signs login and ceremony
    // artefacts, and a token minted `typ: "dpop+jwt"` must not be servable as a
    // credential just because the signature is genuine.
    if (typeof typ !== "string" || !ACCEPTED_TYP.has(typ.trim().toLowerCase())) {
      return `unexpected \`typ\` "${truncate(String(typ))}" — expected vc+jwt`;
    }
  }
  return null;
}

/**
 * A `kid` that names a different DID than the payload's `issuer` is an
 * internally inconsistent token: it asserts the signing key belongs to somebody
 * other than the issuer it claims. The signature already verified against the
 * ISSUER's address, so this cannot make a forgery pass — it catches confused
 * tooling and blocks a token being re-labelled for a second identity.
 */
function checkKid(header: Record<string, unknown>, issuerDid: string): string | null {
  const kid = header.kid;
  if (typeof kid !== "string" || kid.startsWith("#")) return null; // absent, or relative to the issuer
  const did = kid.split("#")[0]!;
  if (!did.startsWith("did:")) return null; // not a DID URL — nothing to contradict
  return did === issuerDid ? null : `\`kid\` names ${truncate(did)} but the issuer is ${truncate(issuerDid)}`;
}

/**
 * Is the signed payload a Verifiable Credential at all?
 */
function checkCredentialShape(claims: Record<string, unknown>): string | null {
  const type = claims.type;
  const types = typeof type === "string" ? [type] : Array.isArray(type) ? type : [];
  if (!types.includes("VerifiableCredential")) {
    return "payload `type` does not include \"VerifiableCredential\" — signed, but not a credential";
  }
  if (!("@context" in claims)) return "payload has no `@context`";
  return null;
}

/** `issuer` is a DID string or an object with an `id` (VCDM 2.0 allows both). */
function readIssuer(claims: Record<string, unknown>): string | null {
  const issuer = claims.issuer;
  if (typeof issuer === "string") return issuer;
  if (issuer && typeof issuer === "object" && !Array.isArray(issuer)) {
    const id = (issuer as { id?: unknown }).id;
    if (typeof id === "string") return id;
  }
  return null;
}

/** `credentialSubject.role`, mirroring Design B's verdict. VCDM allows an array
 *  of subjects; the first is the one a verdict reports on, as with proofs. */
function readRole(claims: Record<string, unknown>): string | null {
  const subject = Array.isArray(claims.credentialSubject) ? claims.credentialSubject[0] : claims.credentialSubject;
  if (!subject || typeof subject !== "object") return null;
  const role = (subject as { role?: unknown }).role;
  return typeof role === "string" ? role : null;
}

/**
 * The verdict's `verificationMethod`, from the header's `kid` — the JOSE
 * analogue of Design B's `proof.verificationMethod`. A relative `#fragment` is
 * resolved against the issuer DID, which is what a DID URL fragment means.
 */
function readVerificationMethod(header: Record<string, unknown>, issuerDid: string | null): string | null {
  const kid = header.kid;
  if (typeof kid !== "string" || kid.length === 0) return null;
  if (kid.startsWith("#")) return issuerDid ? `${issuerDid}${kid}` : kid;
  return kid;
}

// ── Strict decoding ──────────────────────────────────────────────────────────

type Decoded<T> = { ok: true; value: T } | { ok: false; error: string };

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * base64url → bytes, STRICTLY.
 */
function decodeBase64Url(segment: string): Decoded<Uint8Array> {
  if (!BASE64URL.test(segment)) return { ok: false, error: "not base64url" };
  if (segment.length % 4 === 1) return { ok: false, error: "truncated base64url" };
  const buf = Buffer.from(segment, "base64url");
  if (buf.toString("base64url") !== segment) return { ok: false, error: "non-canonical base64url" };
  return { ok: true, value: new Uint8Array(buf) };
}

/** base64url → UTF-8 → JSON object. Anything that is not a JSON OBJECT is
 *  refused: a JWS whose payload is `null`, a number or an array is not a header
 *  and not a credential. `TextDecoder(fatal)` rather than `Buffer.toString` so
 *  invalid UTF-8 is an error instead of a run of U+FFFD. */
function decodeJson(segment: string): Decoded<Record<string, unknown>> {
  const bytes = decodeBase64Url(segment);
  if (!bytes.ok) return bytes;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.value);
  } catch {
    return { ok: false, error: "not valid UTF-8" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "not valid JSON" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "not a JSON object" };
  }
  return { ok: true, value: parsed as Record<string, unknown> };
}

// ── Verdict assembly ─────────────────────────────────────────────────────────

interface VerdictFields {
  id: string | null;
  issuer: string | null;
  role: string | null;
  verificationMethod: string | null;
}

/**
 * What the verifier has established so far. Note there is no `issuer` member:
 * the verdict's issuer is ALWAYS `issuerDid`, i.e. the value read out of the
 * signed payload. Leaving a second, settable `issuer` here would be an
 * invitation to fill it from the wrapper or from a database row — which is the
 * one thing this verifier must never do.
 */
interface Working {
  token: string | null;
  credential?: Record<string, unknown> | null;
  issuerDid?: string | null;
  signerAddress?: Address | null;
  id?: string | null;
  role?: string | null;
  verificationMethod?: string | null;
}

/**
 * The seam's shape, assembled in ONE place.
 *
 * `verified` is the AND over every check and `error` is the FIRST failure's
 * detail — so a verdict can never disagree with the checks that produced it, and
 * a later-composed check (authorization) folds in with the same rule.
 */
function verdictFrom(checks: VerificationCheck[], fields: VerdictFields): CredentialVerdict {
  const failed = checks.find((c) => !c.ok);
  return {
    id: fields.id,
    issuer: fields.issuer,
    role: fields.role,
    verified: checks.length > 0 && !failed,
    error: failed ? `${failed.name}: ${failed.detail ?? "failed"}` : null,
    mode: MODE,
    cryptosuite: CRYPTOSUITE,
    verificationMethod: fields.verificationMethod,
  };
}

function build(checks: VerificationCheck[], working: Working): Es256kVerification {
  const fields: VerdictFields = {
    id: working.id ?? null,
    issuer: working.issuerDid ?? null,
    role: working.role ?? null,
    verificationMethod: working.verificationMethod ?? null,
  };
  return {
    verdict: verdictFrom(checks, fields),
    checks,
    issuerDid: working.issuerDid ?? null,
    signerAddress: working.signerAddress ?? null,
    credential: working.credential ?? null,
    token: working.token,
  };
}

/** A result that stops at the first failing check — see {@link VerificationCheck}. */
function fail(name: string, detail: string, working: Working): Es256kVerification {
  return build([{ name, ok: false, detail }], working);
}

/** Error messages carry attacker-controlled strings (an `alg`, a DID). Bound
 *  them so a hostile credential cannot turn a log line into a payload. */
function truncate(value: string, max = 120): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}
