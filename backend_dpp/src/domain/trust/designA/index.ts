import type { PrismaClient } from "@prisma/client";
import type { Router } from "express";
import { HttpError } from "../../../middleware/error.js";
import { config } from "../../../config.js";
import { logger } from "../../../observability/logger.js";
import { didWebHost, didShortOf } from "../did.js";
import type {
  ChainHeadCommitment,
  Db,
  MintedDid,
  PublicChainVerdict,
  RevocableCredential,
  TrustProvider,
} from "../TrustProvider.js";
import type {
  CredentialVerdict,
  KeyRevocation,
  PublicKeyRecord,
  RewrapReport,
  UnsignedCredentialEnvelope,
  VerifiableEnvelope,
} from "../types.js";
import { createChainGateway, type ChainGateway } from "./chainGateway.js";
import { MODE, CRYPTOSUITE, verifyEnvelopedCredential, addCheck } from "./jose.js";
import { chainBinding, isIssuerAuthorized, issuerAddressOf } from "./authRoot.js";
import { productIdFromDid } from "./typedData.js";
import { mintDidEthr } from "./didEthr.js";
import { commitChainHeadUnsigned, findVersionAnchor } from "./anchor.js";
import { createDesignARoutes } from "./designARoutes.js";
import { startAnchorRelayer } from "./relayer.js";

/**
 * ─── DesignATrust — the thesis architecture ───────────────────────────────────
 * did:ethr identities · non-custodial Web3Auth tKey keys (2-of-3; the platform
 * holds no share) · VC-JOSE-COSE ES256K-R credentials · on-chain authorization
 * root and per-version Merkle anchors.
 */
export class DesignATrust implements TrustProvider {
  readonly mode = MODE;
  readonly cryptosuite = CRYPTOSUITE;

  /** Built once, lazily: constructing it opens RPC transports, and a process
   *  that never verifies anything should never open one. */
  #gateway: ChainGateway | null = null;
  private get gateway(): ChainGateway {
    this.#gateway ??= createChainGateway();
    return this.#gateway;
  }

  /**
   * **Products keep a `did:web` subject in BOTH designs — a deliberate, documented
   * deviation from thesis Entscheidung 4.**
   */
  async mintDid(kind: "org" | "product", id: string): Promise<MintedDid | null> {
    if (kind === "org") return null;
    const did = `did:web:${didWebHost()}:${id}`;
    return { did, didShort: didShortOf(did) };
  }

  /**
   * The other half of `mintDid`'s org contract: once a wallet is bound, the org
   * HAS an identifier, and it is the one the registry is keyed by.
   */
  didForWalletAddress(address: string): MintedDid | null {
    const did = mintDidEthr(address, chainBinding());
    return { did, didShort: `did:ethr:…${did.slice(-8)}` };
  }

  /**
   * Nothing to decorate. Design A's revocation is the removal of on-chain issuer
   * authorization, evaluated live at verification — there is no bitstring to
   * allocate an index in, and `statusListIndex` stays null on the shared column.
   */
  async prepareCredential(
    _prisma: PrismaClient,
    envelope: UnsignedCredentialEnvelope,
    _ctx: { subjectId: string | null },
  ): Promise<{ envelope: UnsignedCredentialEnvelope; statusListIndex: number | null }> {
    return { envelope, statusListIndex: null };
  }

  /**
   * **Always throws. This is the invariant, not a gap.**
   */
  signCredential(
    _prisma: PrismaClient,
    _envelope: UnsignedCredentialEnvelope,
    issuerDid: string,
    subjectId: string,
  ): Promise<VerifiableEnvelope> {
    logger.error(
      { issuerDid, subjectId },
      "design-a: signCredential was called — the platform holds no signing key; signatures are produced in the actor's browser",
    );
    return Promise.reject(
      new HttpError(
        501,
        "Design A cannot sign server-side: the platform holds no key material. " +
          "Credentials are signed in the contributor's browser and assembled at publish.",
      ),
    );
  }

  /**
   * Signature first (offline, deterministic, cacheable), authorization second
   * (live chain state) — the same split Design B makes between a proof and its
   * revocation status, which is why the verdict cache stays correct for both.
   */
  async verifyCredential(
    _prisma: PrismaClient,
    credential: VerifiableEnvelope,
    opts?: { includeStatusCheck?: boolean },
  ): Promise<CredentialVerdict> {
    const chain = chainBinding();
    let result = verifyEnvelopedCredential(credential, chain);

    // Authorization is Mechanism 4: a signature proves WHO spoke, the auth root
    // proves they were ENTITLED to speak about this product. Skipped when the
    // caller wants the pure cacheable verdict, and skipped when the signature
    // already failed — there is nothing to authorize.
    if (opts?.includeStatusCheck !== false && result.verdict.verified) {
      result = addCheck(result, await this.#authorizationCheck(result.issuerDid, result.credential));
    }
    return result.verdict;
  }

  /**
   * The on-chain authorization check, rendered as a check rather than an
   * exception.
   */
  async #authorizationCheck(issuerDid: string | null, credential: unknown) {
    const productDid = (credential as { credentialSubject?: { id?: unknown } } | null)?.credentialSubject?.id;
    if (typeof productDid !== "string" || !issuerDid) {
      return { name: "authorization", ok: false, detail: "credential does not name both an issuer and a product subject" };
    }
    try {
      const ok = await isIssuerAuthorized(this.gateway, productDid, issuerDid);
      return {
        name: "authorization",
        ok,
        detail: ok ? null : "issuer is not authorized on-chain for this product",
      };
    } catch (err) {
      logger.warn({ err, issuerDid }, "design-a: authorization check could not reach the chain");
      return { name: "authorization", ok: false, detail: "authorization could not be checked — chain unreachable" };
    }
  }

  /**
   * Revocation under Design A is removing the issuer's on-chain authorization, and
   * only the product's controller can sign that — with a key this server does not
   * have. So it cannot happen inside the caller's transaction the way B's
   * bitstring flip does.
   */
  async revokeCredential(_tx: Db, credential: RevocableCredential): Promise<void> {
    throw new HttpError(
      501,
      "Design A revokes by removing on-chain issuer authorization, which the product's controller must sign. " +
        "Build a setIssuer(allowed=false) payload, have it signed in the controller's wallet, and queue it for the relayer.",
      { credentialId: credential.id, issuerDid: credential.issuerDid },
    );
  }

  /** No platform signature — the evidence is on chain. See `anchor.ts` for the
   *  full reasoning; the short version is that A removes the self-attestation. */
  /**
   * The chain decides who may publish. Asked once per DISTINCT issuer, at publish,
   * over the whole set — so the refusal names every unauthorized issuer rather
   * than the first, and the operator learns in one message what they still have to
   * authorize.
   */
  async assertIssuersMayPublish(productDid: string | null, issuerDids: readonly string[]): Promise<void> {
    if (!productDid) {
      throw new HttpError(409, "This product has no DID, so no issuer can be authorized for it.");
    }
    const distinct = [...new Set(issuerDids)];
    const refused: string[] = [];
    for (const did of distinct) {
      let ok = false;
      try {
        ok = await isIssuerAuthorized(this.gateway, productDid, did);
      } catch (err) {
        logger.warn({ err, did }, "design-a: publish authorization check could not reach the chain");
        throw new HttpError(
          503,
          "The chain could not be read, so issuer authorization could not be checked. " +
            "Refusing to publish rather than assume it.",
        );
      }
      if (!ok) refused.push(did);
    }
    if (refused.length) {
      throw new HttpError(
        409,
        "Cannot publish — the chain does not authorize every contributor for this product yet.",
        { unauthorizedIssuers: refused, productDid },
      );
    }
  }

  /**
   * The three public-ledger facts the anonymous verification panel reports.
   */
  async publicChainVerdict(
    prisma: PrismaClient,
    args: { passportId: string; version: number | null; productDid: string | null; issuerDids: readonly string[] },
  ): Promise<PublicChainVerdict> {
    const a = config.designA;
    if (!a) throw new Error("publicChainVerdict: unreachable under Design B");

    const distinct = [...new Set(args.issuerDids)];
    const issuers: PublicChainVerdict["issuers"] = [];
    for (const did of distinct) {
      const address = issuerAddressOf(did);
      // `null`, not `false`: a DID that is not a did:ethr on this chain has no
      // address to ask the registry about — "no answer exists", not "the chain
      // said no". The same three-valued honesty the authorizations endpoint uses.
      const authorized = address && args.productDid
        ? await isIssuerAuthorized(this.gateway, args.productDid, did)
        : null;
      issuers.push({ did, address, authorized });
    }

    const controller = args.productDid
      ? await this.gateway.productController(productIdFromDid(args.productDid))
      : null;

    // The anchor lookup 404s when the version predates freezing and 422s when
    // the product has no DID — real states of old passports, not chain failures,
    // so they degrade to `anchor: null` while the issuer rows stay live.
    let anchor: PublicChainVerdict["anchor"] = null;
    if (args.version !== null) {
      try {
        const found = await findVersionAnchor(prisma, this.gateway, {
          passportId: args.passportId,
          version: args.version,
        });
        anchor = {
          status: found.presence,
          matches: found.matches,
          expectedRoot: found.expectedRoot,
          merkleRoot: found.anchor?.merkleRoot ?? null,
          txHash: found.anchor?.txHash ?? null,
          blockNumber: found.anchor?.blockNumber ?? null,
        };
      } catch (err) {
        if (!(err instanceof HttpError)) throw err;
      }
    }

    return {
      chainId: a.chainId,
      registry: a.anchorRegistryAddress,
      didRegistry: a.didRegistryAddress,
      controller,
      issuers,
      // Strict: an issuer with no address on this chain cannot be authorized,
      // and counting it as anything but a failure would tick a box the contract
      // would refuse. The controller-implicit rule is already inside
      // `isIssuerAuthorized`.
      allAuthorized: issuers.length > 0 && issuers.every((i) => i.authorized === true),
      anchor,
    };
  }

  commitChainHead(prisma: PrismaClient, orgId: string): Promise<ChainHeadCommitment> {
    return commitChainHeadUnsigned(prisma, orgId);
  }

  /** Always empty, and truthfully so: the platform custodies no signing keys.
   *  An org's key management happens in its own wallet, not here. */
  async listSigningKeys(_prisma: PrismaClient, _subjectId: string): Promise<PublicKeyRecord[]> {
    return [];
  }

  /**
   * A no-op run, reported honestly rather than refused. KEK rotation is an
   * operational job that sweeps every design; under A it finds nothing to
   * re-wrap because there is nothing custodied, and a zero-row report is the
   * correct answer to "is anything still under the old KEK?".
   */
  async rewrapCustodyKeys(_prisma: PrismaClient, _opts?: { dryRun?: boolean }): Promise<RewrapReport> {
    return { currentKekId: "n/a", stale: {}, staleCount: 0, totalKeys: 0, rewrapped: 0, failures: [] };
  }

  /**
   * Rotation lives in the org's wallet and on ERC-1056, not here — exactly as
   * the interface documentation already promised. `changeOwner` on the registry
   * re-points the DID at a new address; the DID string is unchanged, so
   * everything previously signed keeps verifying while the old key stops being
   * able to assert.
   */
  async rotateSigningKey(_prisma: PrismaClient, subjectId: string): Promise<{ fragment: string }> {
    throw new HttpError(
      501,
      "Design A cannot rotate a key the platform does not hold. Rotate in the org's wallet via the " +
        "ERC-1056 registry (changeOwner); the did:ethr identifier is unchanged and prior signatures keep verifying.",
      { subjectId },
    );
  }

  /** Same reasoning as rotation, with a sharper edge: a key this server never
   *  held is not one it can disown on the org's behalf. */
  async revokeSigningKey(
    _prisma: PrismaClient,
    subjectId: string,
    opts: { fragment?: string; reason: string; issuerDid?: string | null },
  ): Promise<KeyRevocation> {
    throw new HttpError(
      501,
      "Design A cannot revoke a key the platform does not hold. Use the org's wallet: ERC-1056 changeOwner " +
        "retires the key, and removing the issuer's on-chain authorization stops its credentials verifying.",
      { subjectId, reason: opts.reason },
    );
  }

  /**
   * The ceremony: attestation upload, signed workflow decisions, chain writes.
   */
  routes(prisma: PrismaClient): Router | null {
    return createDesignARoutes(prisma, () => this.gateway);
  }

  /**
   * Drain the `AnchorTx` outbox: submit actors' pre-signed payloads and follow
   * them to confirmation.
   */
  startBackgroundWork(prisma: PrismaClient): () => void {
    logger.info("design-a: starting the anchor relayer (single replica, one nonce lane)");
    return startAnchorRelayer(prisma, this.gateway);
  }
}
