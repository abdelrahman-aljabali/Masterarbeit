import type { PrismaClient, Prisma } from "@prisma/client";
import type { Router } from "express";
import type {
  CredentialVerdict,
  KeyRevocation,
  PublicKeyRecord,
  RewrapReport,
  UnsignedCredentialEnvelope,
  VerifiableEnvelope,
} from "./types.js";

/**
 * ─── TrustProvider — the Design A / Design B seam ─────────────────────────────
 * The whole difference between the two trust architectures lives behind this
 * interface. The rest of the platform (publish pipeline, provisioning, routes,
 * public verification) never branches on the design — it calls `trust.*` and
 * lets the selected provider decide HOW.
 */

export type { CredentialVerdict, UnsignedCredentialEnvelope, VerifiableEnvelope };

/** Base client or transaction client — revocation runs inside the caller's tx. */
export type Db = PrismaClient | Prisma.TransactionClient;

/** What committing an org's audit-chain head produced — the model-specific proof
 *  that the head existed at a point in time and can't be silently rewritten. */
export interface ChainHeadCommitment {
  /** Which trust model produced this commitment. */
  mode: string;
  orgId: string;
  seq: number;
  headHash: string | null;
  at: string;
  /** Model-specific payload:
   *   Design B → platform Ed25519 signature + verificationMethod (verify offline)
   *   Design A → on-chain anchor reference (tx hash, block, Merkle proof)
   *  Kept open so each provider returns exactly what its verification needs. */
  proof: Record<string, unknown>;
}

/** A minted decentralized identifier for a subject (org or product). */
export interface MintedDid {
  did: string;
  didShort: string;
}

/** Minimal credential-row shape revocation needs (from the Credential table). */
export interface RevocableCredential {
  id: string;
  issuerDid: string | null;
  statusListIndex: number | null;
}

/** See {@link TrustProvider.publicChainVerdict}. Every field is a statement a
 *  third party can reproduce from public chain state alone. */
export interface PublicChainVerdict {
  chainId: number;
  /** TrustAnchorRegistry address — where authorization + anchors live. */
  registry: string;
  /** ERC-1056 EthereumDIDRegistry address — where issuer identity resolves. */
  didRegistry: string;
  controller: string | null;
  issuers: { did: string; address: string | null; authorized: boolean | null }[];
  allAuthorized: boolean;
  anchor: {
    status: "anchored" | "absent" | "inconclusive";
    matches: boolean;
    expectedRoot: string;
    merkleRoot: string | null;
    txHash: string | null;
    blockNumber: number | null;
  } | null;
}

export interface TrustProvider {
  /** "design-b" | "design-a" — surfaced in verification output for transparency. */
  readonly mode: "design-b" | "design-a";
  /** The proof/cryptosuite label reported to verifiers. */
  readonly cryptosuite: string;

  /**
   * Mint a DID for a newly-provisioned org or newly-created product.
   * B → did:web derived from CREDENTIAL_ORIGIN. A → did:ethr (may return null when the
   * identifier can't exist yet, e.g. before the org's wallet is bound — the
   * schema's did columns are nullable and publish gates on their presence).
   */
  mintDid(kind: "org" | "product", id: string): Promise<MintedDid | null>;

  /**
   * The DID an org acquires when it binds its OWN signing key — the second half of
   * `mintDid`'s contract.
   */
  didForWalletAddress?(address: string): MintedDid | null;

  /**
   * Decorate an unsigned credential envelope with model-specific parts BEFORE
   * signing. B allocates a BitstringStatusList index and attaches the
   * `credentialStatus` entry; A attaches its own revocation reference or none.
   * `statusListIndex` is persisted on the Credential row (nullable, B-specific
   * column; A returns null).
   */
  prepareCredential(
    prisma: PrismaClient,
    envelope: UnsignedCredentialEnvelope,
    ctx: { subjectId: string | null },
  ): Promise<{ envelope: UnsignedCredentialEnvelope; statusListIndex: number | null }>;

  /**
   * Sign a credential envelope as `issuerDid`, using `subjectId`'s custody.
   */
  signCredential(
    prisma: PrismaClient,
    envelope: UnsignedCredentialEnvelope,
    issuerDid: string,
    subjectId: string,
  ): Promise<VerifiableEnvelope>;

  /** Verify one signed credential. `includeStatusCheck` lets the caller get the
   *  pure signature verdict (cacheable) and handle revocation as live state.
   *  Accepts EITHER representation: what is stored under one design may be
   *  handed to the other's verifier, and answering that honestly (a failed
   *  verdict naming the mismatch) beats crashing on it. */
  verifyCredential(
    prisma: PrismaClient,
    credential: VerifiableEnvelope,
    opts?: { includeStatusCheck?: boolean },
  ): Promise<CredentialVerdict>;

  /**
   * Model-specific revocation mechanics, run INSIDE the caller's transaction
   * (the shared route owns the row-status update + audit event). B flips the
   * issuer org's bitstring bit; A will do whatever its model requires. Throws
   * HttpError when this credential cannot be revoked under the model.
   */
  revokeCredential(tx: Db, credential: RevocableCredential): Promise<void>;

  /** Commit an org's current audit-chain head to whatever this model trusts:
   *  a platform signature (B) or a blockchain anchor (A). */
  commitChainHead(prisma: PrismaClient, orgId: string): Promise<ChainHeadCommitment>;

  /**
   * Refuse publication if any of these issuers is not entitled to issue for this
   * product, under whatever authority this design trusts.
   */
  /**
   * What the PUBLIC ledger currently says about this passport — for the anonymous
   * verification panel.
   */
  publicChainVerdict?(
    prisma: PrismaClient,
    args: {
      passportId: string;
      version: number | null;
      productDid: string | null;
      issuerDids: readonly string[];
    },
  ): Promise<PublicChainVerdict>;

  assertIssuersMayPublish?(
    productDid: string | null,
    issuerDids: readonly string[],
  ): Promise<void>;

  /** The subject's key lifecycle state, for the org's own key-management view. */
  listSigningKeys(prisma: PrismaClient, subjectId: string): Promise<PublicKeyRecord[]>;

  /**
   * Re-wrap whatever custody material this design holds under the CURRENT
   * key-encryption key (the operational half of KEK rotation). B re-encrypts
   * every stored private key; A holds none and reports an empty run.
   */
  rewrapCustodyKeys(prisma: PrismaClient, opts?: { dryRun?: boolean }): Promise<RewrapReport>;

  /**
   * ROUTINE re-key: retire the subject's active signing key and mint its
   * successor. Nothing already signed becomes invalid — the retired public key
   * stays in the DID document so pre-rotation proofs keep verifying.
   */
  rotateSigningKey(prisma: PrismaClient, subjectId: string): Promise<{ fragment: string }>;

  /**
   * COMPROMISE response: revoke a signing key so every signature it ever made
   * stops verifying. Destructive by design, and the reason this is separate
   * from rotation. Implementations must also invalidate any cached verification
   * verdicts — a cache that keeps answering "verified" for a disowned key would
   * silently defeat the revocation.
   */
  revokeSigningKey(
    prisma: PrismaClient,
    subjectId: string,
    opts: { fragment?: string; reason: string; issuerDid?: string | null },
  ): Promise<KeyRevocation>;

  /**
   * The provider's own public HTTP surface, mounted at the app root. B serves
   * did:web resolution (/.well-known/did.json, /:id/did.json) and the signed
   * revocation lists (/status/:orgId/:list). A (did:ethr resolves via the Ethereum
   * registry) may return null.
   */
  routes(prisma: PrismaClient): Router | null;

  /**
   * Start whatever long-running background work this design needs, returning a
   * stop function for graceful shutdown — or null when there is none.
   */
  startBackgroundWork?(prisma: PrismaClient): (() => void) | null;
}
