import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";
import { utf8ToBytes } from "@noble/hashes/utils";
import { buildAttestationBody } from "@/dpp-core";
import type { WalletPhaseListener } from "./index";
// Type-only: erased at build time, so this stays outside the wallet wall.
import type { CeremonySession, SigningKey } from "./web3auth";

/**
 * ─── VC-JOSE-COSE / ES256K-R — SIGN ONLY, and the only file that touches a key ─
 * # Why "the only file" is the measured claim
 */

/** The one `alg` the verifier accepts. A LITERAL: `jose.ts` has an allow-list of
 *  exactly one entry, and a value read from config could disagree with it. */
export const ES256K_R = "ES256K-R" as const;

/** The verification method a `did:ethr` document publishes for its owner key —
 *  `chainTypes.ts` mints `${did}#controller` and `ethr-did-resolver` agrees. */
const KID_FRAGMENT = "#controller";

// ── What a browser is asked to attest ────────────────────────────────────────

/**
 * The decomposed values of one role's credential — the ONLY input to signing.
 */
export interface AttestationClaim {
  /** The supply-chain role this credential covers (dpp-core stage vocabulary). */
  role: string;
  /** The signer's own `did:ethr`. Lands in the payload AND in the `kid`, and is
   *  checked against the address the wallet reports before anything is signed. */
  issuerDid: string;
  /** `credentialSubject.id` — the product's DID, or null for an unbound draft. */
  productDid: string | null;
  /** JSON-LD context IRI frozen into `@context` (the server's CONTEXT_URL_V3). */
  contextUrl: string;
  /** JSON Schema IRI frozen into `credentialSchema` (the server's SCHEMA_URL_V2). */
  schemaUrl: string;
  /** Passport expiry, ISO — omitted from the document entirely when null. */
  validUntil: string | null;
  /** The attested field values, already at their `vcPath`s, WITHOUT `id`/`role`
   *  (both of which `buildAttestationBody` inserts itself, in that order). */
  subject: Record<string, unknown>;
}

/** What a completed ceremony hands back. No key material, by construction. */
export interface SignedAttestation {
  /** The VCDM 2.0 enveloping wrapper — exactly three members, per `types.ts`. */
  credential: { "@context": string; type: "EnvelopedVerifiableCredential"; id: string };
  /** The compact JWS, verbatim. THESE bytes are the credential. */
  jws: string;
  /** The instant the signer asserted, as it appears inside the signed bytes. */
  validFrom: string;
  /** The address the signature recovers to — self-verified before returning. */
  signerAddress: string;
}

// ── The document, and the bytes over it ──────────────────────────────────────

/**
 * Assemble the unsigned credential body and the JWS signing input.
 */
export function buildAttestationJws(claim: AttestationClaim, validFrom: Date): {
  body: Record<string, unknown>;
  header: Record<string, unknown>;
  signingInput: string;
} {
  const body = buildAttestationBody({
    contextUrl: claim.contextUrl,
    schemaUrl: claim.schemaUrl,
    credential: {
      role: claim.role,
      issuerDid: claim.issuerDid,
      credentialSubject: claim.subject,
    },
    productDid: claim.productDid,
    // Null, always: `brandOrgDid` is only the FALLBACK issuer for a role no
    // node covers, and a contributor signing their own slice always has an
    // issuer DID of their own. Passing anything else here would let a browser
    // mint a credential attributed to the brand.
    brandOrgDid: null,
    validFrom,
    validUntil: claim.validUntil ? new Date(claim.validUntil) : null,
  }) as unknown as Record<string, unknown>;

  const header = {
    alg: ES256K_R,
    // Present-but-wrong is refused by the verifier; absent is tolerated. Stating
    // it blocks cross-protocol replay — this key also signs login challenges and
    // EIP-712 decisions, and none of those may be servable as a credential.
    typ: "vc+jwt",
    kid: `${claim.issuerDid}${KID_FRAGMENT}`,
  };

  return {
    body,
    header,
    signingInput: `${base64url(jsonBytes(header))}.${base64url(jsonBytes(body))}`,
  };
}

/**
 * The ONE function in this application that reads a private key.
 */
export function signCompactJws(signingInput: string, privateKey: Uint8Array): string {
  const signature = secp256k1.sign(sha256(utf8ToBytes(signingInput)), privateKey);
  if (signature.hasHighS()) {
    throw new Error("Refusing a high-s ES256K-R signature (EIP-2) — the verifier would reject it.");
  }
  const recovery = signature.recovery;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`ES256K-R recovery id must be 0 or 1, got ${String(recovery)}.`);
  }
  const bytes = new Uint8Array(65);
  bytes.set(signature.toCompactRawBytes(), 0);
  bytes[64] = recovery;
  return `${signingInput}.${base64url(bytes)}`;
}

/**
 * The Ethereum address a private key controls.
 */
export function addressFromPrivateKey(privateKey: Uint8Array): string {
  const publicKey = secp256k1.getPublicKey(privateKey, false); // 0x04 ‖ X ‖ Y
  return `0x${toHex(keccak_256(publicKey.slice(1))).slice(-40)}`;
}

/**
 * The address a finished JWS recovers to — the verifier's own procedure, run
 * locally before the token is ever uploaded.
 */
function recoveredAddress(signingInput: string, signatureSegment: string): string {
  const bytes = fromBase64url(signatureSegment);
  const parsed = secp256k1.Signature.fromCompact(bytes.slice(0, 64)).addRecoveryBit(bytes[64]);
  const publicKey = parsed.recoverPublicKey(sha256(utf8ToBytes(signingInput))).toRawBytes(false);
  return `0x${toHex(keccak_256(publicKey.slice(1))).slice(-40)}`;
}

// ── The ceremony ─────────────────────────────────────────────────────────────

/**
 * Open the wallet, sign one attestation, tear the key down.
 */
export async function signAttestation(
  claim: AttestationClaim,
  opts: { onPhase?: WalletPhaseListener } = {},
): Promise<SignedAttestation> {
  const onPhase = opts.onPhase ?? (() => {});
  const expected = addressFromDid(claim.issuerDid);
  if (!expected) {
    throw new Error(`Your organization's issuer identity is not a did:ethr: ${claim.issuerDid}`);
  }

  // The signer's own instant, taken once, here — the value the server will read
  // back out of the token and rebuild with.
  const validFrom = new Date();
  const { signingInput } = buildAttestationJws(claim, validFrom);

  onPhase("loading-wallet");
  const { withSigningKey } = await import("./web3auth");

  const jws = await withSigningKey((key) => {
    // The key's own claim about which address it is, checked against what the
    // wallet reported. These disagree only if the key came from somewhere other
    // than the account the user chose — in which case nothing should be signed.
    const derived = addressFromPrivateKey(key.bytes);
    if (derived !== key.address.toLowerCase()) {
      throw new Error(
        "The reconstructed key does not match the address this wallet reports. Refusing to sign.",
      );
    }
    if (derived !== expected) {
      throw new Error(
        `This wallet controls ${derived}, but your organization issues as ${expected}. ` +
          "Sign in with the account whose wallet is bound to your organization.",
      );
    }
    onPhase("signing");
    return signCompactJws(signingInput, key.bytes);
  }, onPhase);

  // Self-verification, after the key is already gone: everything below is a
  // property of the BYTES, exactly as it is for the server.
  const signerAddress = recoveredAddress(signingInput, jws.slice(signingInput.length + 1));
  if (signerAddress !== expected) {
    throw new Error(
      `The signature recovers to ${signerAddress}, not to ${expected}. Nothing was uploaded.`,
    );
  }

  return {
    credential: {
      "@context": "https://www.w3.org/ns/credentials/v2",
      type: "EnvelopedVerifiableCredential",
      id: `data:application/vc+jwt,${jws}`,
    },
    jws,
    validFrom: validFrom.toISOString(),
    signerAddress,
  };
}
/**
 * Sign SEVERAL role credentials in ONE wallet session.
 */
export async function signAttestationBatch(
  claims: readonly AttestationClaim[],
  opts: {
    onPhase?: WalletPhaseListener;
    onEach?: (done: number, total: number) => void;
    /** A held ceremony session — the key is still reconstructed per use and
     *  zeroed after; only the CONNECTION is reused. */
    session?: CeremonySession;
  } = {},
): Promise<SignedAttestation[]> {
  const onPhase = opts.onPhase ?? (() => {});
  if (!claims.length) throw new Error("Refusing to open a wallet with nothing to sign.");

  // Prepared BEFORE the key exists, so a malformed claim cannot get as far as a
  // reconstructed key. `validFrom` is taken per claim, here, and is the value
  // the server reads back out of each token.
  const jobs = claims.map((claim) => {
    const expected = addressFromDid(claim.issuerDid);
    if (!expected) {
      throw new Error(`Your organization's issuer identity is not a did:ethr: ${claim.issuerDid}`);
    }
    const validFrom = new Date();
    return { claim, expected, validFrom, ...buildAttestationJws(claim, validFrom) };
  });

  const signWithKey = (key: SigningKey): string[] => {
    const derived = addressFromPrivateKey(key.bytes);
    if (derived !== key.address.toLowerCase()) {
      throw new Error("The reconstructed key does not match the address this wallet reports. Refusing to sign.");
    }
    onPhase("signing");
    const out: string[] = [];
    for (const job of jobs) {
      if (derived !== job.expected) {
        throw new Error(
          `This wallet controls ${derived}, but your organization issues as ${job.expected}. ` +
            "Sign in with the account whose wallet is bound to your organization.",
        );
      }
      out.push(signCompactJws(job.signingInput, key.bytes));
      opts.onEach?.(out.length, jobs.length);
    }
    return out;
  };

  let signed: string[];
  if (opts.session) {
    signed = await opts.session.useKey(signWithKey);
  } else {
    onPhase("loading-wallet");
    const { withSigningKey } = await import("./web3auth");
    signed = await withSigningKey(signWithKey, onPhase);
  }

  // Self-verification, after the key is gone — a property of the BYTES, exactly
  // as it is for the server, and exactly as the single-claim path does it.
  return jobs.map((job, i) => {
    const jws = signed[i];
    const signerAddress = recoveredAddress(job.signingInput, jws.slice(job.signingInput.length + 1));
    if (signerAddress !== job.expected) {
      throw new Error(`The signature recovers to ${signerAddress}, not to ${job.expected}. Nothing was uploaded.`);
    }
    return {
      credential: {
        "@context": "https://www.w3.org/ns/credentials/v2",
        type: "EnvelopedVerifiableCredential" as const,
        id: `data:application/vc+jwt,${jws}`,
      },
      jws,
      validFrom: job.validFrom.toISOString(),
      signerAddress,
    };
  });
}

// ── Encoding ─────────────────────────────────────────────────────────────────

/** `did:ethr:<chain>:<address>` → the address, lower case. Null for anything
 *  else — including a `did:web`, which under Design A means the caller is on the
 *  wrong stack rather than merely misconfigured. */
function addressFromDid(did: string): string | null {
  const match = /^did:ethr:(?:[^:]+:)?(0x[0-9a-fA-F]{40})$/.exec(did.trim());
  return match ? match[1].toLowerCase() : null;
}

/** JSON → UTF-8 bytes. `TextEncoder` rather than a hand-rolled encoder because
 *  the payload carries free-text field values in every language a supplier
 *  writes in, and a wrong multi-byte encoding is a signature over bytes the
 *  server will not reproduce. */
function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

/**
 * base64url, CANONICAL: the `-_` alphabet, no padding.
 */
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The inverse, for the local self-verification above. */
function fromBase64url(segment: string): Uint8Array {
  const binary = atob(segment.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
