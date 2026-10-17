import { Router } from "express";
import type { Organization, Prisma, PrismaClient } from "@prisma/client";
import { z } from "zod";
import { asyncHandler, HttpError } from "../../../middleware/error.js";
import { requireAuth } from "../../../middleware/auth.js";
import { clientIp, loadOwnedPassport, requireOrg } from "../../../db/tenant.js";
import { makeLimiter } from "../../../security/rateLimit.js";
import { logger } from "../../../observability/logger.js";
import { recordAudit } from "../../workflow/audit.js";
import { canonicalHash } from "../../integrity/hash.js";
import type { UnsignedCredential } from "../../integrity/canonical.js";
import { buildAttestationEnvelope } from "../vc.js";
import { ENVELOPED_CREDENTIAL_TYPE, isEnvelopedCredential, type EnvelopedCredential } from "../types.js";
import type { ChainGateway } from "./chainGateway.js";
import { asAddress, type Address, type SignedCall } from "./chainTypes.js";
import { didMatchesAddress, documentAuthorizesAddress, resolveDidEthr } from "./didEthr.js";
import { extractJws, verifyEnvelopedCredential, addCheck } from "./jose.js";
import {
  addDecisionCheck,
  buildApproval,
  buildChainHeadCheckpoint,
  decisionDomain,
  verifyDecision,
  type DecisionOutcome,
  type DecisionTypedDataPayload,
  type DecisionVerification,
} from "./decisions.js";
import { buildAnchorRequest, enqueueAnchor, findVersionAnchor } from "./anchor.js";
import {
  buildAuthorizationRequest,
  chainBinding,
  enqueueAuthorization,
  isIssuerAuthorized,
  issuerAddressOf,
  registryDomain,
} from "./authRoot.js";
import { buildClaimProduct, buildSetIssuer, buildSetIssuers, productIdFromDid, type TypedDataPayload } from "./typedData.js";
import { enqueueSignedCall } from "./outbox.js";
// TYPE ONLY — `import type` is erased at compile time, so this adds no runtime
// edge to the workflow layer. That distinction is load-bearing here; see the
// deadlock note on `workflowPublish` below.
import type { VerifiedApproval } from "../../workflow/chainNodes.js";

/**
 * ─── Design A's authenticated HTTP surface — the ceremony ─────────────────────
 * Everything an ACTOR has to sign with a key this platform does not hold, and
 * the endpoints that hand them the exact bytes to sign. Four flows: credential
 * upload, review decisions, the signed chain head, and the chain writes (claim,
 * issuer authorization, anchor, publish plan).
 */

const workflowPublish = () => import("../../workflow/publish.js");
const workflowChainNodes = () => import("../../workflow/chainNodes.js");

/**
 * Every POST here does real cryptography on caller-supplied bytes — secp256k1
 * recovery, keccak/EIP-712 encoding, JSON-LD-shaped canonical hashing. These are
 * authenticated endpoints, so the global 300/min already applies; this bounds
 * the CPU a single authenticated session can command, the same reasoning as
 * `public.ts`'s verifyLimiter.
 */
const ceremonyLimiter = makeLimiter("design-a-ceremony", { windowMs: 60 * 1000, max: 60 });

/**
 * How far from the server's clock an actor's claimed `issuedAt` may sit.
 */
const ISSUED_AT_FUTURE_SKEW_S = 5 * 60;
const ISSUED_AT_PAST_SKEW_S = 60 * 60;

/** `0x` + 65 bytes. Rejected by zod (→ 400) rather than by `asSignature65`,
 *  whose `InvalidChainArgumentError` is a programmer-error class and would
 *  surface as a 500. */
const signature65 = z.string().regex(/^0x[0-9a-fA-F]{130}$/, "expected a 0x-prefixed 65-byte signature");
const unixSeconds = z.number().int().positive();
const roleName = z.string().trim().min(1).max(120);

export const createDesignARoutes = (
  prisma: PrismaClient,
  /** A THUNK, not the gateway: `DesignATrust` builds its gateway lazily (it opens
   *  RPC transports) and `routes()` runs at boot, before anything has asked a
   *  chain a question. Taking a getter keeps that laziness intact. */
  gatewayOf: () => ChainGateway,
): Router => {
  const root = Router();
  const api = Router();
  // One place that decides the prefix. Root-mounted like Design B's routes, but
  // under /api because this surface is the SPA's, not a protocol's: nothing here
  // is dereferenced by an external verifier.
  root.use("/api/trust/design-a", api);

  // Every endpoint is an actor doing something with their own key. There is no
  // anonymous surface here at all — the public, verifier-facing side of Design A
  // is the chain and `routes/public.ts`.
  api.use(requireAuth);

  const chain = () => chainBinding();

  /**
   * The caller's org, its bound wallet, and the `did:ethr` they must agree on.
   */
  const walletBoundOrg = async (orgId: string): Promise<{ org: Organization; address: Address; did: string }> => {
    const org = await prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) throw new HttpError(404, "Organization not found");
    if (!org.walletAddress || !org.walletBoundAt) {
      throw new HttpError(
        409,
        "This organization has not bound a wallet yet. Under Design A the platform holds no key, so an " +
          "organization can only act once it controls one.",
        { orgId },
      );
    }
    if (!org.did || !didMatchesAddress(org.did, org.walletAddress, chain())) {
      // A misconfiguration, not a user error: something bound a wallet without
      // minting the matching DID (or minted one for another chain). Loud, because
      // the quiet alternative is signatures verifying against the wrong identity.
      logger.error({ orgId, did: org.did }, "design-a: org DID does not name its bound wallet");
      throw new HttpError(
        409,
        "This organization's DID does not name its bound wallet on this chain — refusing to verify a " +
          "signature against an identity it may not control.",
        { orgId },
      );
    }
    return { org, address: asAddress(org.walletAddress, "walletAddress"), did: org.did };
  };

  /** `issuedAt` as the actor claimed it, bounded to a plausible instant. */
  const boundedIssuedAt = (issuedAt: number): Date => {
    const now = Math.floor(Date.now() / 1000);
    if (issuedAt > now + ISSUED_AT_FUTURE_SKEW_S) {
      throw new HttpError(400, "issuedAt is in the future — a decision cannot be dated ahead of the clock.", {
        issuedAt,
        now,
      });
    }
    if (issuedAt < now - ISSUED_AT_PAST_SKEW_S) {
      throw new HttpError(400, "issuedAt is too old — rebuild the payload and sign it again.", { issuedAt, now });
    }
    return new Date(issuedAt * 1000);
  };

  /** Turn a verification into a 400 unless every check passed. */
  const assertVerified = (v: DecisionVerification, what: string): void => {
    if (v.verified) return;
    throw new HttpError(400, `${what} does not verify`, { error: v.error, checks: v.checks, digest: v.digest });
  };

  /**
   * Verify one EIP-712 decision against the org's identity AND its bound wallet.
   */
  const verifyAgainstOrg = <P extends "Approval" | "ChainHeadCheckpoint">(
    payload: DecisionTypedDataPayload<P>,
    signature: string,
    signer: { address: Address; did: string },
  ): DecisionVerification => {
    const verification = verifyDecision(payload, signature, { did: signer.did, chain: chain() });
    if (!verification.verified) return verification;
    const recovered = verification.signerAddress?.toLowerCase() ?? null;
    return addDecisionCheck(verification, {
      name: "wallet-binding",
      ok: recovered === signer.address.toLowerCase(),
      detail:
        recovered === signer.address.toLowerCase()
          ? `${recovered} is the organization's bound wallet`
          : `signature recovers to ${recovered ?? "nothing"}, which is not this organization's bound wallet`,
    });
  };

  // ── 1. Attestations — a contributor signs their own slice ───────────────────

  /**
   * What each role of this passport currently needs, and which of them the caller
   * may sign.
   */
  api.get("/passports/:id/attestations", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, nodes } = await visibleForContribution(prisma, req.params.id, orgId);
    const { prepared, byRole } = await (await workflowPublish()).currentRoleSnapshots(prisma, passport.id);

    const stored = await prisma.pendingAttestation.findMany({
      where: { passportId: passport.id, supersededAt: null },
      orderBy: { createdAt: "desc" },
      select: { role: true, snapshotHash: true, issuerDid: true, orgId: true, createdAt: true },
    });
    const current = new Map<string, (typeof stored)[number]>();
    for (const row of stored) if (!current.has(row.role)) current.set(row.role, row);

    const nodeOrg = new Map(nodes.map((n) => [n.id, n.orgId]));

    /*
     * INFORMATIONAL now, not a gate. The upload route stores an unauthorized
     * issuer's attestation as staged (the refusal moved to publish, where the
     * operator's plan grants the authorization in the same ceremony), so the
     * portal no longer withholds anything on this answer — it uses it to tell
     * the contributor their confirmation goes live with the operator's next
     * publish.
     */
    const productDid = passport.product.did;
    const asked = new Map<string, boolean | null>();
    const askChain = async (issuerDid: string): Promise<boolean | null> => {
      if (asked.has(issuerDid)) return asked.get(issuerDid) ?? null;
      let answer: boolean | null = null;
      if (productDid) {
        try {
          answer = await isIssuerAuthorized(gatewayOf(), productDid, issuerDid);
        } catch (err) {
          logger.warn({ err, issuerDid }, "design-a: could not read issuer authorization for the portal");
        }
      }
      asked.set(issuerDid, answer);
      return answer;
    };

    const snaps = [...byRole.values()];
    const isMine = (snap: (typeof snaps)[number]): boolean =>
      snap.nodeId ? nodeOrg.get(snap.nodeId) === orgId : passport.product.orgId === orgId;
    const authByRole = new Map<string, boolean | null>();
    for (const snap of snaps) {
      if (isMine(snap) && snap.issuerDid) authByRole.set(snap.role, await askChain(snap.issuerDid));
    }

    res.json({
      passportId: passport.id,
      roles: snaps.map((snap) => {
        const held = current.get(snap.role);
        const mine = isMine(snap);
        return {
          /** true = the chain accepts this issuer · false = it does not yet ·
           *  null = not established. Only present for the caller's own roles. */
          authorized: mine ? (authByRole.get(snap.role) ?? null) : undefined,
          role: snap.role,
          nodeId: snap.nodeId,
          issuerDid: snap.issuerDid,
          snapshotHash: snap.snapshotHash,
          state: !held ? "awaiting" : held.snapshotHash === snap.snapshotHash ? "attested" : "stale",
          attestedAt: held?.createdAt ?? null,
          attestedBy: held?.issuerDid ?? null,
          mine,
          // The unsigned body, for DISPLAY and as the reference the browser's own
          // build must match (D7: the browser builds what it signs; the server
          // checks the result byte for byte on upload, below).
          credential: mine ? unsignedBodyFor(snap, prepared) : undefined,
        };
      }),
    });
  }));

  /**
   * Accept one signed credential.
   */
  api.post("/passports/:id/attestations", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const body = z
      .object({
        role: roleName,
        /** The VCDM 2.0 wrapper, or the bare compact JWS. Only the JWS is
         *  evidence — the wrapper is unsigned decoration and is rebuilt below. */
        credential: z.union([z.string().min(1), z.record(z.string(), z.unknown())]),
      })
      .parse(req.body);

    const { passport, nodes } = await visibleForContribution(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);

    // 1 — signature + issuer binding, offline.
    const token = extractJws(body.credential);
    if (!token) throw new HttpError(400, "Not an enveloped credential (data:application/vc+jwt,<compact JWS>).");
    let verification = verifyEnvelopedCredential(token, chain());
    if (!verification.verdict.verified) {
      throw new HttpError(400, "Credential does not verify", {
        error: verification.verdict.error,
        checks: verification.checks,
      });
    }

    // 2 — the signer is the caller's org, not merely a valid signer.
    const issuerDid = verification.issuerDid ?? "";
    if (issuerDid !== signer.did) {
      throw new HttpError(403, "This credential was issued by another DID than your organization's.", {
        issuer: issuerDid.slice(0, 120),
        expected: signer.did,
      });
    }

    // 3 — the chain-dependent half: the issuer key must still be current in the
    // resolved DID document. It folds in as a CHECK (monotone downward), so it
    // cannot rescue anything and is visible in the refusal. An unreachable chain
    // is a refusal too, never an assumption. Issuer authorization is not checked
    // here; assertIssuersMayPublish enforces it at publication.
    const gateway = gatewayOf();
    try {
      const document = await resolveDidEthr(gateway, issuerDid);
      verification = addCheck(verification, {
        name: "issuer-key-current",
        ok: documentAuthorizesAddress(document, verification.signerAddress, chain()),
        detail: "the resolved DID document no longer authorizes this address to assert",
      });
    } catch (err) {
      logger.warn({ err, issuerDid }, "design-a: attestation upload could not reach the chain");
      throw new HttpError(
        503,
        "The issuer key could not be checked against the chain; try again.",
      );
    }
    if (!verification.verdict.verified) {
      throw new HttpError(403, "Credential rejected", {
        error: verification.verdict.error,
        checks: verification.checks,
      });
    }

    // 4 + 5 — the content. Rebuilt from the database, never from the request.
    const { prepared, byRole } = await (await workflowPublish()).currentRoleSnapshots(prisma, passport.id);
    const snap = byRole.get(body.role);
    if (!snap) {
      throw new HttpError(422, "This passport currently has no credential for that role.", {
        role: body.role,
        roles: [...byRole.keys()],
      });
    }
    const nodeOrg = new Map(nodes.map((n) => [n.id, n.orgId]));
    const ownsRole = snap.nodeId ? nodeOrg.get(snap.nodeId) === orgId : passport.product.orgId === orgId;
    if (!ownsRole) {
      throw new HttpError(403, "Your organization does not own this role on this passport.", { role: body.role });
    }

    const mismatch = describeContentMismatch(verification.credential, snap, prepared);
    if (mismatch) {
      // 409: nothing is malformed and nobody is unauthorized — the signed bytes
      // simply are not the current bytes. Either the data moved while the wallet
      // was open, or the browser built a different envelope than this server
      // would. Both are resolved by rebuilding and re-signing, not by correcting
      // the request.
      throw new HttpError(409, "The signed credential does not match this passport's current data.", {
        role: body.role,
        reason: mismatch,
        snapshotHash: snap.snapshotHash,
      });
    }

    // Store the wrapper REBUILT from the verified token, not the object that was
    // posted: VCDM 2.0's enveloped form has exactly three members and nothing
    // outside the JWS is evidence, so anything else a client attached would be
    // unsigned data riding into a published version.
    const envelope: EnvelopedCredential = {
      "@context": "https://www.w3.org/ns/credentials/v2",
      type: ENVELOPED_CREDENTIAL_TYPE,
      id: `data:application/vc+jwt,${token}`,
    };

    const stored = await prisma.$transaction(async (tx) => {
      const at = new Date();
      // Supersede by ROLE, not by org: a rebinding changes who owns a role, and
      // the previous holder's attestation must stop being current at the same
      // instant the new one starts.
      await tx.pendingAttestation.updateMany({
        where: { passportId: passport.id, role: snap.role, supersededAt: null },
        data: { supersededAt: at },
      });
      const row = await tx.pendingAttestation.create({
        data: {
          passportId: passport.id,
          role: snap.role,
          nodeId: snap.nodeId,
          orgId,
          issuerDid,
          snapshotHash: snap.snapshotHash,
          envelope: envelope as unknown as Prisma.InputJsonValue,
        },
        select: { id: true, role: true, createdAt: true, snapshotHash: true },
      });
      await recordAudit(tx, {
        action: "passport.attestation.sign",
        actorUserId: req.auth?.userId ?? null,
        ip: clientIp(req),
        orgId,
        targetType: "pendingAttestation",
        targetId: row.id,
        data: {
          dppId: passport.id,
          role: snap.role,
          nodeId: snap.nodeId,
          issuerDid,
          signerAddress: verification.signerAddress,
          snapshotHash: snap.snapshotHash,
        },
      });
      return row;
    });

    res.status(201).json({ attestation: stored, verified: true, checks: verification.checks });
  }));

  // ── 2. Approval — the operator signs their review decision ──────────────────

  /**
   * The payloads the operator must sign to review one node — one per ROLE.
   *
   * `decision` is a query parameter because it is INSIDE the signed struct: the
   * wallet must show "approved" or "changes_requested" as part of the sentence
   * the operator is agreeing to. There is no single payload that covers both.
   */
  api.get("/passports/:id/nodes/:nodeId/review", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const query = z
      .object({ decision: z.enum(["approved", "changes_requested"]).default("approved") })
      .parse(req.query);

    const node = await prisma.supplyChainTier.findFirst({
      where: { id: req.params.nodeId, passportId: passport.id },
      select: { id: true, roles: true, orgId: true, dataStatus: true },
    });
    if (!node) throw new HttpError(404, "Tier not found");
    if (!node.orgId) throw new HttpError(409, "Node is not bound to a supplier — nothing to review");

    const { byRole } = await (await workflowPublish()).currentRoleSnapshots(prisma, passport.id);
    const live = await prisma.approvalAttestation.findMany({
      where: { passportId: passport.id, nodeId: node.id, supersededAt: null },
      select: { role: true, decision: true, snapshotHash: true, issuedAt: true },
    });
    const incumbent = new Map(live.map((r) => [r.role, r]));
    const attestations = await prisma.pendingAttestation.findMany({
      where: { passportId: passport.id, role: { in: node.roles ?? [] }, supersededAt: null },
      select: { role: true, snapshotHash: true },
    });
    const attested = new Map(attestations.map((r) => [r.role, r.snapshotHash]));

    // One `issuedAt` for the whole ceremony: the operator makes one decision
    // about one node, and N wallet prompts are an implementation detail of the
    // per-role grain — not N decisions at N different instants.
    const issuedAt = Math.floor(Date.now() / 1000);
    const domain = decisionDomain();

    res.json({
      passportId: passport.id,
      nodeId: node.id,
      decision: query.decision,
      issuedAt,
      signerDid: signer.did,
      roles: (node.roles ?? []).map((role) => {
        const snap = byRole.get(role);
        const prior = incumbent.get(role);
        return {
          role,
          // A role the chain graph no longer produces a credential for has no
          // content to bind — reported honestly rather than given a payload
          // built over a hash of nothing.
          signable: !!snap,
          snapshotHash: snap?.snapshotHash ?? null,
          // What the SUPPLIER signed, so the UI can warn before a wallet opens:
          // approving data whose attestation is stale produces an approval that
          // publish will accept while `CeremonyAssembly` still blocks the role.
          attestationState: !snap
            ? "no-credential"
            : !attested.has(role)
              ? "awaiting"
              : attested.get(role) === snap.snapshotHash
                ? "attested"
                : "stale",
          currentDecision: prior
            ? { decision: prior.decision, issuedAt: prior.issuedAt, snapshotHash: prior.snapshotHash, stale: !!snap && prior.snapshotHash !== snap.snapshotHash }
            : null,
          payload: snap
            ? buildApproval(domain, {
                passportId: passport.id,
                nodeId: node.id,
                role,
                snapshotHash: snap.snapshotHash,
                decision: query.decision,
                issuedAt,
              })
            : null,
        };
      }),
    });
  }));

  /**
   * Record a signed review.
   */
  api.post("/passports/:id/nodes/:nodeId/review", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const body = z
      .object({
        action: z.enum(["approve", "request_changes"]),
        note: z.string().trim().max(500).optional(),
        issuedAt: unixSeconds,
        signatures: z.array(z.object({ role: roleName, signature: signature65 })).min(1).max(12),
      })
      .parse(req.body);

    const decision: DecisionOutcome = body.action === "approve" ? "approved" : "changes_requested";
    const issuedAt = boundedIssuedAt(body.issuedAt);
    const { byRole } = await (await workflowPublish()).currentRoleSnapshots(prisma, passport.id);
    const domain = decisionDomain();

    const approvals: VerifiedApproval[] = body.signatures.map((sig) => {
      const snap = byRole.get(sig.role);
      if (!snap) {
        throw new HttpError(422, "This passport currently has no credential for that role.", { role: sig.role });
      }
      const payload = buildApproval(domain, {
        passportId: passport.id,
        nodeId: req.params.nodeId,
        role: sig.role,
        snapshotHash: snap.snapshotHash,
        decision,
        issuedAt: body.issuedAt,
      });
      const verification = verifyAgainstOrg(payload, sig.signature, signer);
      assertVerified(verification, `the signed decision for role "${sig.role}"`);
      return {
        role: sig.role,
        decision,
        snapshotHash: snap.snapshotHash,
        issuedAt,
        signerDid: signer.did,
        signerAddress: verification.signerAddress!,
        payload: payload as unknown as Prisma.InputJsonValue,
        signature: sig.signature.toLowerCase(),
      };
    });

    // Coverage, the replay rule and the write itself belong to the workflow
    // layer — they are database transactions, not cryptography, and `reviewTier`
    // is where the node's status, the audit event and these rows commit together.
    const { reviewTier } = await workflowChainNodes();
    const tier = await reviewTier(
      prisma,
      { orgId, userId: req.auth?.userId ?? null, ip: clientIp(req) },
      passport.id,
      req.params.nodeId,
      body.action,
      body.note,
      approvals,
    );
    res.json({
      nodeId: tier.id,
      dataStatus: tier.dataStatus,
      reviewedAt: tier.reviewedAt,
      signedRoles: approvals.map((a) => a.role),
    });
  }));

  // ── 3. Chain-head checkpoint ────────────────────────────────────────────────

  /**
   * The payload committing to this org's audit-log tip.
   */
  api.get("/orgs/:id/chain-head/payload", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    if (req.params.id !== orgId) throw new HttpError(403, "An organization may only checkpoint its own chain.");
    const signer = await walletBoundOrg(orgId);
    const tip = await chainTip(prisma, orgId);
    if (!tip) {
      // Honest absence. `buildChainHeadCheckpoint` refuses to sign an empty
      // chain rather than encode bytes32(0), and this is that refusal surfaced
      // as a status instead of a 500.
      throw new HttpError(409, "This organization's audit chain is empty — there is nothing to checkpoint yet.", {
        orgId,
      });
    }
    const issuedAt = Math.floor(Date.now() / 1000);
    res.json({
      orgId,
      seq: tip.seq,
      headHash: tip.hash,
      issuedAt,
      signerDid: signer.did,
      payload: buildChainHeadCheckpoint(decisionDomain(), {
        orgId,
        seq: tip.seq,
        headHash: tip.hash,
        issuedAt,
      }),
    });
  }));

  /**
   * Store a signed checkpoint.
   */
  api.post("/orgs/:id/chain-head", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    if (req.params.id !== orgId) throw new HttpError(403, "An organization may only checkpoint its own chain.");
    const signer = await walletBoundOrg(orgId);
    const body = z.object({ seq: z.number().int().positive(), issuedAt: unixSeconds, signature: signature65 }).parse(req.body);
    const issuedAt = boundedIssuedAt(body.issuedAt);

    // The client SELECTS a seq; the server supplies the hash for it. That keeps
    // the rule intact — nothing the client sent enters the digest.
    const event = await prisma.auditEvent.findFirst({
      where: { orgId, seq: body.seq },
      select: { seq: true, hash: true },
    });
    if (!event?.hash || event.seq === null) {
      throw new HttpError(409, "No audit event with that seq in this organization's chain.", { seq: body.seq });
    }

    const latest = await latestCheckpoint(prisma, orgId);
    if (latest && body.seq < latest.seq) {
      throw new HttpError(409, "A checkpoint may not commit to an earlier seq than the one already stored.", {
        seq: body.seq,
        currentSeq: latest.seq,
      });
    }
    if (latest && issuedAt.getTime() <= latest.issuedAt.getTime()) {
      throw new HttpError(409, "Replayed checkpoint refused: issuedAt must be strictly later than the last one.", {
        issuedAt: issuedAt.toISOString(),
        currentIssuedAt: latest.issuedAt.toISOString(),
      });
    }

    const payload = buildChainHeadCheckpoint(decisionDomain(), {
      orgId,
      seq: event.seq,
      headHash: event.hash,
      issuedAt: body.issuedAt,
    });
    const verification = verifyAgainstOrg(payload, body.signature, signer);
    assertVerified(verification, "the signed chain-head checkpoint");

    const stored = await prisma.$transaction(async (tx) => {
      const row = await tx.chainHeadCheckpoint.create({
        data: {
          orgId,
          seq: event.seq!,
          headHash: event.hash!,
          signerDid: signer.did,
          signerAddress: verification.signerAddress!.toLowerCase(),
          payload: payload as unknown as Prisma.InputJsonValue,
          signature: body.signature.toLowerCase(),
          issuedAt,
        },
        select: { id: true, seq: true, headHash: true, issuedAt: true, createdAt: true },
      });
      await recordAudit(tx, {
        action: "org.chainhead.checkpoint",
        actorUserId: req.auth?.userId ?? null,
        ip: clientIp(req),
        orgId,
        targetType: "chainHeadCheckpoint",
        targetId: row.id,
        data: { seq: row.seq, headHash: row.headHash, signerAddress: verification.signerAddress },
      });
      return row;
    });

    res.status(201).json({ checkpoint: stored, verified: true });
  }));

  // ── 4. Chain writes — anchor and issuer authorization ───────────────────────

  /**
   * Where a version's anchor stands on chain, and whether it still matches the
   * bytes this server serves. The mismatch case is the interesting one: it says
   * the anchored root and the served version disagree.
   */
  api.get("/passports/:id/anchor", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const query = z.object({ version: z.coerce.number().int().positive().optional() }).parse(req.query);
    const version =
      query.version ??
      (await prisma.passportVersion.findFirst({
        where: { passportId: passport.id },
        orderBy: { version: "desc" },
        select: { version: true },
      }))?.version;
    if (!version) throw new HttpError(404, "No published version to anchor.");

    const queued = await prisma.anchorTx.findMany({
      where: { passportId: passport.id, kind: "anchor" },
      orderBy: { createdAt: "desc" },
      take: 5,
      select: { id: true, status: true, txHash: true, blockNumber: true, lastError: true, createdAt: true, confirmedAt: true },
    });
    const onChain = await withChain(() => findVersionAnchor(prisma, gatewayOf(), { passportId: passport.id, version }));
    res.json({
      passportId: passport.id,
      version,
      expectedRoot: onChain.expectedRoot,
      status: onChain.presence,
      matches: onChain.matches,
      anchor: onChain.anchor
        ? { ...onChain.anchor, version: onChain.anchor.version.toString() }
        : null,
      // What the search actually covered, so `inconclusive` is auditable rather
      // than a shrug: which blocks were read, how the answer was obtained
      // (`receipt` = the recorded transaction hint, `log-scan` = a sweep), and
      // whether the endpoint forced the window down.
      coverage: {
        complete: onChain.coverage.complete,
        scannedFrom: onChain.coverage.scannedFrom,
        scannedTo: onChain.coverage.scannedTo,
        requests: onChain.coverage.requests,
        window: onChain.coverage.window,
        capped: onChain.coverage.capped,
        via: onChain.coverage.via,
      },
      queue: queued,
    });
  }));

  /** The anchor payload for a frozen version. The Merkle root is recomputed from
   *  the stored version every time — a cached root would be a second source of
   *  truth for the one value whose whole job is to be reproducible by a stranger. */
  api.get("/passports/:id/anchor/payload", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const query = z.object({ version: z.coerce.number().int().positive().optional() }).parse(req.query);
    const request = await withChain(() =>
      buildAnchorRequest(prisma, gatewayOf(), {
        passportId: passport.id,
        version: query.version,
        controller: signer.address,
      }),
    );
    res.json(serializeAnchorRequest(request));
  }));

  /**
   * Queue a controller-signed anchor.
   */
  api.post("/passports/:id/anchor", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const body = z
      .object({ version: z.number().int().positive().optional(), nonce: z.string().regex(/^\d+$/), signature: signature65 })
      .parse(req.body);

    const request = await withChain(() =>
      buildAnchorRequest(prisma, gatewayOf(), {
        passportId: passport.id,
        version: body.version,
        controller: signer.address,
      }),
    );
    assertFreshNonce(body.nonce, request.nonce);

    const call: Extract<SignedCall, { kind: "anchor" }> = {
      kind: "anchor",
      productId: request.productId,
      merkleRoot: request.merkleRoot,
      version: BigInt(request.version),
      nonce: request.nonce,
      signature: body.signature.toLowerCase(),
    };

    const queued = await prisma.$transaction(async (tx) => {
      const row = await enqueueAnchor(tx, call, { passportId: passport.id, orgId });
      await recordAudit(tx, {
        action: "passport.anchor.enqueue",
        actorUserId: req.auth?.userId ?? null,
        ip: clientIp(req),
        orgId,
        targetType: "anchorTx",
        targetId: row.id,
        data: {
          dppId: passport.id,
          version: request.version,
          merkleRoot: request.merkleRoot,
          productId: request.productId,
          signer: signer.address,
        },
      });
      return row;
    });

    res.status(202).json({ queued: queued.id, version: request.version, merkleRoot: request.merkleRoot });
  }));

  /**
   * ─── Claiming a product on chain — the root of everything else ──────────────
   * `productController` is what `setIssuer` and `anchor` both authorize against,
   * so until a product is claimed BOTH of those revert `NotController` and the
   * entire on-chain half of Design A is inert. This is the first link.
   */
  api.get("/passports/:id/claim", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, productDid } = await controlledProduct(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const productId = productIdFromDid(productDid);
    const controller = await withChain(() => gatewayOf().productController(productId));
    const mine = controller !== null && controller.toLowerCase() === signer.address.toLowerCase();

    // The outbox rows for THIS step, alongside the chain state.
    const queue = await prisma.anchorTx.findMany({
      where: { passportId: passport.id, kind: "claimProduct" },
      orderBy: { createdAt: "desc" },
      take: 5,
      select: {
        id: true, status: true, txHash: true, blockNumber: true,
        attempts: true, lastError: true, createdAt: true, confirmedAt: true, nextTryAt: true,
      },
    });

    res.json({
      passportId: passport.id,
      productDid,
      productId,
      controller,
      claimed: controller !== null,
      claimedByThisOrg: mine,
      // Newest-first, so [0] is the attempt an operator is waiting on.
      queue: queue.map((q) => ({ ...q, nextTryAt: q.status === "pending" ? q.nextTryAt : null })),
      // What the operator can do next, so the UI never has to re-derive the rule.
      canClaim: controller === null,
      canAuthorize: mine,
      canAnchor: mine,
      registry: registryDomain().verifyingContract,
      chainId: registryDomain().chainId,
      ...(controller !== null && !mine
        ? {
            reason:
              "This product is already claimed by another address. Claiming is first-claim-wins and permanent; " +
              "only the current controller can transfer it. Neither authorization nor anchoring is possible from this org.",
          }
        : {}),
    });
  }));

  /**
   * The payload the operator signs to claim. `controller` is THIS org's bound
   * address and nothing else — a request body cannot choose it, because a claim
   * that installed a controller the caller does not control would be either
   * useless or an attack, and the contract would reject it anyway.
   */
  api.get("/passports/:id/claim/payload", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, productDid } = await controlledProduct(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const productId = productIdFromDid(productDid);

    const existing = await withChain(() => gatewayOf().productController(productId));
    if (existing !== null) {
      throw new HttpError(409, "This product is already claimed on chain.", {
        productId,
        controller: existing,
        claimedByThisOrg: existing.toLowerCase() === signer.address.toLowerCase(),
      });
    }

    const nonce = await withChain(() => gatewayOf().nonceOf(signer.address));
    res.json({
      passportId: passport.id,
      productDid,
      productId,
      controller: signer.address,
      nonce: nonce.toString(),
      payload: serializeTypedData(buildClaimProduct(registryDomain(), { productId, controller: signer.address, nonce })),
    });
  }));

  /** Queue the operator-signed claim. Same rebuild-and-echo discipline as the
   *  anchor: the client's `nonce` is a staleness selector only, and authority is
   *  left entirely to the contract's `ecrecover`. */
  api.post("/passports/:id/claim", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, productDid } = await controlledProduct(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const body = z.object({ nonce: z.string().regex(/^\d+$/), signature: signature65 }).parse(req.body);
    const productId = productIdFromDid(productDid);

    // Re-checked here and not only in the payload route: minutes may pass while
    // a wallet is open, and paying gas to be told `ProductAlreadyClaimed` is a
    // worse answer than refusing now.
    const existing = await withChain(() => gatewayOf().productController(productId));
    if (existing !== null) {
      throw new HttpError(409, "This product was claimed on chain while you were signing.", {
        productId,
        controller: existing,
      });
    }
    assertFreshNonce(body.nonce, await withChain(() => gatewayOf().nonceOf(signer.address)));

    const call: Extract<SignedCall, { kind: "claimProduct" }> = {
      kind: "claimProduct",
      productId,
      controller: signer.address,
      nonce: BigInt(body.nonce),
      signature: body.signature.toLowerCase(),
    };

    const queued = await prisma.$transaction(async (tx) => {
      const row = await enqueueSignedCall(tx, call, { passportId: passport.id, orgId, productId, signer: signer.address });
      await recordAudit(tx, {
        action: "passport.claim.enqueue",
        actorUserId: req.auth?.userId ?? null,
        ip: clientIp(req),
        orgId,
        targetType: "anchorTx",
        targetId: row.id,
        data: { dppId: passport.id, productDid, productId, controller: signer.address, signer: signer.address },
      });
      return row;
    });

    res.status(202).json({ queued: queued.id, productId, controller: signer.address });
  }));

  /**
   * Every on-chain write queued for this passport, all three kinds.
   */
  api.get("/passports/:id/chain-activity", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const passport = await loadOwnedPassport(prisma, req.params.id, orgId);
    const rows = await prisma.anchorTx.findMany({
      where: { passportId: passport.id },
      orderBy: { createdAt: "desc" },
      take: 50,
      select: {
        id: true, kind: true, status: true, txHash: true, blockNumber: true,
        attempts: true, lastError: true, createdAt: true, confirmedAt: true,
        nextTryAt: true, payload: true,
      },
    });

    res.json({
      passportId: passport.id,
      activity: rows.map((r) => {
        const p = (r.payload ?? {}) as Record<string, unknown>;
        return {
          id: r.id,
          kind: r.kind,
          status: r.status,
          txHash: r.txHash,
          blockNumber: r.blockNumber,
          attempts: r.attempts,
          lastError: r.lastError,
          createdAt: r.createdAt,
          confirmedAt: r.confirmedAt,
          // Only meaningful while something is still being retried; surfacing it
          // lets a UI say "next attempt in 2 minutes" instead of "pending" forever.
          nextTryAt: r.status === "pending" ? r.nextTryAt : null,
          // The one payload member a lifecycle view needs: which issuer a
          // setIssuer row is about, so it can be matched to a supplier node.
          // `controller` likewise for a claim. Never the signature or the nonce.
          issuer: typeof p.issuer === "string" ? p.issuer : null,
          allowed: typeof p.allowed === "boolean" ? p.allowed : null,
          controller: typeof p.controller === "string" ? p.controller : null,
        };
      }),
    });
  }));

  /**
   * ─── What the CHAIN currently says about who may issue for this product ─────
   * The complement of `/chain-activity`, and deliberately not an extension of it:
   * that endpoint reports the OUTBOX — what this platform queued, sent, or failed
   * to send — which is a statement about us. This one reports
   * `authorized[productId][issuer]` as read from the registry right now, which is
   * a statement anyone with an RPC endpoint can reproduce without us.
   */
  api.get("/passports/:id/authorizations", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, nodes } = await visibleForContribution(prisma, req.params.id, orgId);
    const productDid = passport.product.did;
    if (!productDid) {
      throw new HttpError(422, "This product has no DID, so it has no on-chain identity to authorize against.", {
        passportId: passport.id,
      });
    }
    const productId = productIdFromDid(productDid);

    const boundOrgIds = [...new Set(nodes.map((n) => n.orgId).filter((id): id is string => !!id))];
    const orgs = boundOrgIds.length
      ? await prisma.organization.findMany({
          where: { id: { in: boundOrgIds } },
          select: { id: true, name: true, did: true, walletAddress: true },
        })
      : [];
    const orgById = new Map(orgs.map((o) => [o.id, o]));

    const controller = await withChain(() => gatewayOf().productController(productId));

    // One chain answer per distinct issuer DID: several nodes commonly bind to
    // the same supplier org, and asking twice about one address would double the
    // RPC cost to produce a value the gateway's own cache would return anyway.
    const answered = new Map<string, boolean>();
    const authorizedFor = async (issuerDid: string): Promise<boolean> => {
      const cached = answered.get(issuerDid);
      if (cached !== undefined) return cached;
      const decided = await withChain(() => isIssuerAuthorized(gatewayOf(), productDid, issuerDid));
      answered.set(issuerDid, decided);
      return decided;
    };

    const rows: unknown[] = [];
    for (const node of nodes) {
      const org = node.orgId ? orgById.get(node.orgId) : undefined;
      const issuerDid = org?.did ?? null;
      const issuer = issuerDid ? issuerAddressOf(issuerDid) : null;
      // `null`, not `false`: an unbound node (or an org whose DID is not a
      // did:ethr on this chain) has no issuer to ask the chain about. Reporting
      // `false` would read as "the chain said no" for a question nobody asked.
      const authorized = issuerDid && issuer ? await authorizedFor(issuerDid) : null;
      rows.push({
        nodeId: node.id,
        roles: node.roles,
        orgId: node.orgId,
        orgName: org?.name ?? null,
        issuerDid,
        issuerAddress: issuer,
        authorized,
        // Which of the two ways an issuer can be entitled applies — so a UI can
        // say "authorized as the product's controller" without re-deriving the
        // policy, and so an operator can see that a controller needs no
        // `setIssuer` transaction (and no gas) for its own product.
        viaController: authorized === true && issuer !== null && issuer === controller,
        detail:
          authorized === null
            ? node.orgId
              ? "this node's organization has no did:ethr on this chain, so there is no issuer to authorize"
              : "no organization is bound to this node yet"
            : authorized
              ? "the registry currently authorizes this issuer for this product"
              : "the registry does not authorize this issuer — the product's controller must sign a setIssuer",
      });
    }

    // Queued setIssuer calls for THIS product, so a authorization that is signed and
    // submitted but not yet mined is visible as itself.
    const queued = await prisma.anchorTx.findMany({
      where: { passportId: passport.id, kind: { in: ["setIssuer", "setIssuers"] } },
      orderBy: { createdAt: "desc" },
      take: 10,
      select: {
        id: true, status: true, txHash: true, blockNumber: true, kind: true,
        lastError: true, createdAt: true, confirmedAt: true, payload: true,
      },
    });
    /*
     * belongs to without re-deriving anything. The address lives in the signed
     * payload, which is the only place it is authoritative.
     */
    const queueByIssuer = queued.flatMap((row) => {
      const payload = (row.payload ?? {}) as Record<string, unknown>;
      const { payload: _dropped, ...rest } = row;
      const allowed = typeof payload.allowed === "boolean" ? payload.allowed : null;
      const issuers =
        row.kind === "setIssuers"
          ? (Array.isArray(payload.issuers) ? payload.issuers : []).map((i) => String(i).toLowerCase())
          : [typeof payload.issuer === "string" ? payload.issuer.toLowerCase() : null];
      // An undecodable row still belongs in the list — it is a transaction the
      // operator is waiting on — so it keeps a `null` issuer rather than vanishing.
      return (issuers.length ? issuers : [null]).map((issuer) => ({ ...rest, issuer, allowed }));
    });

    res.json({
      passportId: passport.id,
      productDid,
      productId,
      // address(0) reads as `null`: the product is unclaimed, which means every
      // setIssuer AND every anchor for it currently reverts NotController.
      controller,
      claimed: controller !== null,
      nodes: rows,
      queue: queueByIssuer,
    });
  }));

  /** The payload a controller signs to authorize (or de-authorize) an issuer for
   *  this passport's product — Mechanism 4's write side. */
  api.get("/passports/:id/authorizations/payload", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, productDid } = await controlledProduct(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    // NOT `z.coerce.boolean()`. Coercion is JS truthiness, and `Boolean("false")` is
    // TRUE — so `?allowed=false` silently built an ALLOW payload. The write side
    // (`z.boolean()` on a JSON body) was always correct, which is exactly what hid
    // this: every caller in the repo passes `allowed: true`, the permissive
    // direction, where the bug is invisible.
    const query = z
      .object({
        issuerDid: z.string().trim().min(1).max(256),
        allowed: z.enum(["true", "false"]).default("true").transform((s) => s === "true"),
      })
      .parse(req.query);

    const request = await withChain(() =>
      buildAuthorizationRequest(gatewayOf(), {
        productDid,
        issuerDid: query.issuerDid,
        allowed: query.allowed,
        controller: signer.address,
      }),
    ).catch(rethrowAsBadRequest);
    res.json({
      passportId: passport.id,
      productDid,
      issuerDid: query.issuerDid,
      allowed: query.allowed,
      issuer: request.issuer,
      productId: request.productId,
      nonce: request.nonce.toString(),
      payload: serializeTypedData(request.payload),
    });
  }));

  /** Queue a controller-signed `setIssuer`. Same rebuild-and-echo discipline as
   *  the anchor above, and the same deference to the contract on authority. */
  api.post("/passports/:id/authorizations", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const { passport, productDid } = await controlledProduct(prisma, req.params.id, orgId);
    const signer = await walletBoundOrg(orgId);
    const body = z
      .object({
        issuerDid: z.string().trim().min(1).max(256),
        allowed: z.boolean(),
        nonce: z.string().regex(/^\d+$/),
        signature: signature65,
      })
      .parse(req.body);

    const request = await withChain(() =>
      buildAuthorizationRequest(gatewayOf(), {
        productDid,
        issuerDid: body.issuerDid,
        allowed: body.allowed,
        controller: signer.address,
      }),
    ).catch(rethrowAsBadRequest);
    assertFreshNonce(body.nonce, request.nonce);

    const call: Extract<SignedCall, { kind: "setIssuer" }> = {
      kind: "setIssuer",
      productId: request.productId,
      issuer: request.issuer,
      allowed: body.allowed,
      nonce: request.nonce,
      signature: body.signature.toLowerCase(),
    };

    const queued = await prisma.$transaction(async (tx) => {
      const row = await enqueueAuthorization(tx, call, { passportId: passport.id, orgId });
      await recordAudit(tx, {
        action: "passport.authorization.enqueue",
        actorUserId: req.auth?.userId ?? null,
        ip: clientIp(req),
        orgId,
        targetType: "anchorTx",
        targetId: row.id,
        data: {
          dppId: passport.id,
          productDid,
          issuerDid: body.issuerDid,
          issuer: request.issuer,
          allowed: body.allowed,
          signer: signer.address,
        },
      });
      return row;
    });

    res.status(202).json({ queued: queued.id, issuer: request.issuer, allowed: body.allowed });
  }));

  /**
   * ─── One click: the whole chain prerequisite of a publish, as one list ───────
   * The operator's path to a published passport used to be a scavenger hunt across
   * three panels: claim the product (Step 1), wait; authorize each supplier one at
   * a time (Step 2), wait after each; publish (topbar); anchor (Step 5). Five-plus
   * destinations and `2 + S` separate wallet ceremonies for ONE intention —
   * "publish this passport".
   */

  /** One chain write, with the nonce it must carry. Order is significant. */
  type PlanStep =
    | { kind: "claim"; issuers: never[]; orgNames: never[]; nonce: bigint }
    | {
        /**
         * ONE step for ALL contributors. `TrustAnchorRegistry.setIssuers` grants the
         * whole set against a single nonce, which turns a four-supplier passport from
         * four transactions into one: measured at 240 864 gas against 138 423
         * total-transaction gas, a 42% saving, and — because the registry's nonce is
         * strictly sequential per signer — four serialized block waits into one.
         */
        kind: "authorize";
        issuers: { issuerDid: string; issuerAddress: Address }[];
        orgNames: string[];
        nonce: bigint;
      };

  /**
   * Derive the plan from live chain state. Called by BOTH the GET and the POST,
   * so what the operator signed and what the server queues cannot drift: the
   * POST re-derives and compares rather than trusting the list it was handed.
   */
  const derivePublishPlan = async (passportId: string, orgId: string) => {
    const { passport, productDid } = await controlledProduct(prisma, passportId, orgId);
    const signer = await walletBoundOrg(orgId);
    const productId = productIdFromDid(productDid);
    const me = signer.address.toLowerCase();

    const controller = await withChain(() => gatewayOf().productController(productId));
    if (controller !== null && controller.toLowerCase() !== me) {
      // Claiming is first-claim-wins and permanent. Nothing this org signs can
      // change that, so refuse before building a plan whose every step reverts.
      throw new HttpError(
        409,
        "Another address controls this product on chain. Only the current controller can authorize " +
          "issuers or anchor versions, and control can only be transferred by them.",
        { productId, controller },
      );
    }

    /*
     * `nonceOf` reports what has been MINED. A row sitting in the outbox is a
     * signature over the current value that has not landed, so a plan built now
     * would assign that same value to its first step — two payloads for one nonce,
     * one of which reverts. Scoped to the ORG, not the passport, because the nonce
 * belongs to the org's signing address and every passport shares it.
     */
    const inFlight = await prisma.anchorTx.findMany({
      where: { orgId, status: { in: ["pending", "sent"] } },
      orderBy: { createdAt: "asc" },
      select: { id: true, kind: true, status: true, txHash: true, passportId: true, createdAt: true },
      take: 25,
    });

    // The SAME issuer set publish will check. Read through `preparePublish` with
    // the gates off rather than re-deriving from nodes, so this list and
    // `assertIssuersMayPublish`'s list are the same list by construction — a
    // plan that authorized a different set would be a plan that completes and
    // then fails to publish.
    const { prepared } = await (await workflowPublish()).preparePublish(prisma, passportId, {
      enforceGates: false,
    });
    const issuerDids = [...new Set(prepared.credentials.map((c) => c.issuerDid).filter((d): d is string => !!d))];

    const namesByDid = new Map<string, string>();
    if (issuerDids.length) {
      const orgs = await prisma.organization.findMany({
        where: { did: { in: issuerDids } },
        select: { did: true, name: true },
      });
      for (const o of orgs) if (o.did) namesByDid.set(o.did, o.name);
    }

    // An issuer DID that is not a did:ethr on THIS chain can never be authorized
    // — `setIssuer` takes an address and there is none to take. Reported, never
    // silently dropped: publish would refuse afterwards and the operator would
    // have paid gas to arrive at a wall.
    const unresolvable: string[] = [];
    const pendingAuthorization: { issuerDid: string; issuerAddress: Address }[] = [];
    for (const issuerDid of issuerDids) {
      const issuerAddress = issuerAddressOf(issuerDid);
      if (!issuerAddress) {
        unresolvable.push(issuerDid);
        continue;
      }
      // The controller is implicitly authorized for its own product
      // (`isIssuerAuthorized` owns that policy) — no transaction, no gas.
      if (issuerAddress.toLowerCase() === me) continue;
      // An unclaimed product has controller `address(0)`, which nothing can
      // equal, so every issuer is unauthorized and asking the chain S times
      // would spend S round-trips to learn what the claim step already implies.
      const ok =
        controller === null
          ? false
          : await withChain(() => isIssuerAuthorized(gatewayOf(), productDid, issuerDid));
      if (!ok) pendingAuthorization.push({ issuerDid, issuerAddress });
    }

    // The review gate, restated from `preparePublish` — reported, not enforced.
    const unapproved = (
      await prisma.supplyChainTier.findMany({
        where: {
          passportId,
          dataStatus: { not: "approved" },
          OR: [{ orgId: { not: null } }, { inviteId: { not: null } }],
        },
        select: { id: true, tierName: true, tierRole: true, tierIndex: true, dataStatus: true, inviteId: true },
        orderBy: { tierIndex: "asc" },
      })
    ).map((t) => ({
      nodeId: t.id,
      label: t.tierRole ?? t.tierName ?? `Node ${t.tierIndex}`,
      dataStatus: t.inviteId ? "invited" : (t.dataStatus ?? "pending"),
    }));

    const baseNonce = await withChain(() => gatewayOf().nonceOf(signer.address));
    const steps: PlanStep[] = [];
    if (controller === null) {
      steps.push({ kind: "claim", issuers: [], orgNames: [], nonce: 0n });
    }
    if (pendingAuthorization.length) {
      // ONE step, whatever the number of contributors. Order is preserved from
      // `issuerDids` and is part of the signed digest — `setIssuers` hashes the
      // array as a concatenation, so re-sorting this list anywhere downstream
      // would produce bytes the operator's signature does not cover.
      steps.push({
        kind: "authorize",
        issuers: pendingAuthorization,
        orgNames: pendingAuthorization.map((p) => namesByDid.get(p.issuerDid) ?? "a contributor"),
        nonce: 0n,
      });
    }
    // Assigned in one place, after the list is final: `base, base+1, base+2 …`
    // is the only sequence the contract will accept, and the relayer submits
    // oldest-first with one payload per signer in flight, which is what makes
    // "queued in this order" and "mined in this order" the same statement.
    steps.forEach((s, i) => {
      s.nonce = baseNonce + BigInt(i);
    });

    return {
      passport,
      productDid,
      productId,
      signer,
      controller,
      steps,
      baseNonce,
      inFlight,
      unresolvable,
      unapproved,
    };
  };

  /** The payload for one plan step — built here, never accepted from a client. */
  const planStepPayload = (
    plan: Awaited<ReturnType<typeof derivePublishPlan>>,
    step: PlanStep,
  ): TypedDataPayload<"ClaimProduct"> | TypedDataPayload<"SetIssuers"> =>
    step.kind === "claim"
      ? buildClaimProduct(registryDomain(), {
          productId: plan.productId,
          controller: plan.signer.address,
          nonce: step.nonce,
        })
      : buildSetIssuers(registryDomain(), {
          productId: plan.productId,
          issuers: step.issuers.map((i) => i.issuerAddress),
          allowed: true,
          nonce: step.nonce,
        });

  /** The sentence under the step, in the operator's language. */
  const planStepLabel = (step: PlanStep): string => {
    if (step.kind === "claim") return "Register this product in your name";
    const names = step.orgNames;
    if (names.length === 1) return `Let ${names[0]} contribute to this product`;
    return `Let ${names.slice(0, -1).join(", ")} and ${names[names.length - 1]} contribute to this product`;
  };

  /** What still has to be signed before this passport can publish and anchor. */
  api.get("/passports/:id/publish/plan", asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const plan = await derivePublishPlan(req.params.id, orgId);

    res.json({
      passportId: plan.passport.id,
      productDid: plan.productDid,
      productId: plan.productId,
      controller: plan.controller,
      signer: plan.signer.address,
      baseNonce: plan.baseNonce.toString(),
      steps: plan.steps.map((s) => ({
        kind: s.kind,
        // Arrays on both kinds, empty on `claim` — one shape for the client to
        // read, and the batch means "which issuers" is never a single value.
        issuerDids: s.issuers.map((i) => i.issuerDid),
        issuerAddresses: s.issuers.map((i) => i.issuerAddress),
        orgNames: s.orgNames,
        nonce: s.nonce.toString(),
        payload: serializeTypedData(planStepPayload(plan, s)),
        label: planStepLabel(s),
      })),
      // Everything below is a REASON THE CLICK WILL NOT FINISH, separated from
      // the steps because none of it is fixed by signing.
      awaitingReview: plan.unapproved,
      unresolvableIssuers: plan.unresolvable,
      inFlight: plan.inFlight,
      // The one-click path is available when nothing is mid-flight; the steps
      // themselves may legitimately be empty (already claimed, already
      // authorized), which is a publish that needs no signature at all.
      ready: plan.inFlight.length === 0 && plan.unresolvable.length === 0,
    });
  }));

  /**
   * Queue the whole plan, signed.
   */
  api.post("/passports/:id/publish/plan", ceremonyLimiter, asyncHandler(async (req, res) => {
    const orgId = requireOrg(req);
    const body = z
      .object({
        baseNonce: z.string().regex(/^\d+$/),
        steps: z
          .array(
            z.object({
              kind: z.enum(["claim", "authorize"]),
              // Echoed so the comparison below can name what the client thought
              // it was signing. Empty (or absent) on `claim`.
              issuerDids: z.array(z.string().trim().min(1).max(256)).max(64).optional(),
              nonce: z.string().regex(/^\d+$/),
              signature: signature65,
            }),
          )
          .min(1)
          // At most one claim and one batch authorization — the plan cannot
          // produce more, so anything longer is not a plan this server built.
          .max(2),
      })
      .parse(req.body);

    const plan = await derivePublishPlan(req.params.id, orgId);

    if (plan.inFlight.length) {
      throw new HttpError(409, "Chain work for this organization is still in flight. Wait for it to settle, then re-plan.", {
        inFlight: plan.inFlight.map((r) => ({ id: r.id, kind: r.kind, status: r.status })),
      });
    }
    if (plan.baseNonce !== BigInt(body.baseNonce) || plan.steps.length !== body.steps.length) {
      throw new HttpError(409, "The chain moved while this was being signed. Rebuild the plan and sign it again.", {
        signedBaseNonce: body.baseNonce,
        currentBaseNonce: plan.baseNonce.toString(),
        signedSteps: body.steps.length,
        currentSteps: plan.steps.length,
      });
    }
    plan.steps.forEach((step, i) => {
      const sent = body.steps[i];
      const expectedDids = step.issuers.map((x) => x.issuerDid);
      const sentDids = sent.issuerDids ?? [];
      // ORDER-SENSITIVE, deliberately. `SetIssuers` hashes the address array as a
      // concatenation, so [A,B] and [B,A] are different signatures — comparing
      // them as sets would accept a list whose signature covers a different one.
      const sameIssuers =
        expectedDids.length === sentDids.length && expectedDids.every((d, k) => d === sentDids[k]);
      if (sent.kind !== step.kind || !sameIssuers || BigInt(sent.nonce) !== step.nonce) {
        throw new HttpError(409, "The signed plan does not match what this passport needs now. Rebuild and sign again.", {
          at: i,
          expected: { kind: step.kind, issuerDids: expectedDids, nonce: step.nonce.toString() },
          received: { kind: sent.kind, issuerDids: sentDids, nonce: sent.nonce },
        });
      }
    });

    /* Spaced `createdAt`, one millisecond apart.
     *
     * The relayer submits oldest-first, and `CURRENT_TIMESTAMP` inside a
     * transaction is the transaction's start — identical for every row here. See
     * `AnchorTxContext.createdAt`: with strictly sequential nonces, an ambiguous
     * order is a guaranteed revert, not a cosmetic wobble. */
    const t0 = Date.now();

    const queued = await prisma.$transaction(async (tx) => {
      const ids: { id: string; kind: PlanStep["kind"] }[] = [];
      for (const [i, step] of plan.steps.entries()) {
        const signature = body.steps[i].signature.toLowerCase();
        const call: SignedCall =
          step.kind === "claim"
            ? {
                kind: "claimProduct",
                productId: plan.productId,
                controller: plan.signer.address,
                nonce: step.nonce,
                signature,
              }
            : {
                kind: "setIssuers",
                productId: plan.productId,
                issuers: step.issuers.map((x) => x.issuerAddress),
                allowed: true,
                nonce: step.nonce,
                signature,
              };
        const row = await enqueueSignedCall(tx, call, {
          passportId: plan.passport.id,
          orgId,
          productId: plan.productId,
          signer: plan.signer.address,
          createdAt: new Date(t0 + i),
        });
        await recordAudit(tx, {
          action: step.kind === "claim" ? "passport.claim.enqueue" : "passport.authorization.enqueue",
          actorUserId: req.auth?.userId ?? null,
          ip: clientIp(req),
          orgId,
          targetType: "anchorTx",
          targetId: row.id,
          data: {
            dppId: plan.passport.id,
            productDid: plan.productDid,
            productId: plan.productId,
            signer: plan.signer.address,
            viaPublishPlan: true,
            ...(step.kind === "claim"
              ? { controller: plan.signer.address }
              : {
                  issuerDids: step.issuers.map((x) => x.issuerDid),
                  issuers: step.issuers.map((x) => x.issuerAddress),
                  allowed: true,
                }),
          },
        });
        ids.push({ id: row.id, kind: step.kind });
      }
      return ids;
    });

    res.status(202).json({ queued, count: queued.length });
  }));

  return root;
};

// ── Shared helpers ───────────────────────────────────────────────────────────

/**
 * A passport the caller may CONTRIBUTE to: they own it, or one of its nodes is
 * bound to their org.
 */
async function visibleForContribution(prisma: PrismaClient, passportId: string, orgId: string) {
  const passport = await prisma.passport.findUnique({
    where: { id: passportId },
    include: { product: { select: { id: true, orgId: true, did: true } } },
  });
  if (!passport) throw new HttpError(404, "DPP not found");
  const nodes = await prisma.supplyChainTier.findMany({
    where: { passportId },
    select: { id: true, orgId: true, roles: true },
  });
  const mayContribute = passport.product.orgId === orgId || nodes.some((n) => n.orgId === orgId);
  if (!mayContribute) throw new HttpError(404, "DPP not found");
  return { passport, nodes };
}

/** A passport whose PRODUCT the caller's org controls, with the product DID that
 *  keys everything on chain (`keccak256(productDid)`). */
async function controlledProduct(prisma: PrismaClient, passportId: string, orgId: string) {
  const passport = await loadOwnedPassport(prisma, passportId, orgId);
  const productDid = passport.product.did;
  if (!productDid) {
    throw new HttpError(422, "This product has no DID, so it has no on-chain identity to authorize against.", {
      passportId,
    });
  }
  return { passport, productDid };
}

/** The org's audit-chain tip, or null for an empty chain. */
async function chainTip(prisma: PrismaClient, orgId: string): Promise<{ seq: number; hash: string } | null> {
  const tip = await prisma.auditEvent.findFirst({
    where: { orgId, seq: { not: null } },
    orderBy: { seq: "desc" },
    select: { seq: true, hash: true },
  });
  return tip?.seq && tip.hash ? { seq: tip.seq, hash: tip.hash } : null;
}

/** The newest stored checkpoint. Ordered by seq then issuedAt — the write path
 *  enforces both to be non-decreasing / strictly increasing, so this is
 *  unambiguously "the strongest commitment the operator has made". */
async function latestCheckpoint(prisma: PrismaClient, orgId: string) {
  return prisma.chainHeadCheckpoint.findFirst({
    where: { orgId },
    orderBy: [{ seq: "desc" }, { issuedAt: "desc" }],
    select: { seq: true, issuedAt: true },
  });
}

/** The unsigned credential body for one role — what a browser must build
 *  byte-identically before signing it (D7). */
function unsignedBodyFor(
  snap: { credential: UnsignedCredential },
  prepared: { productDid: string | null; brandOrgDid: string | null; validUntil: Date | null },
): Record<string, unknown> {
  // `buildAttestationEnvelope` omits `id` in the KERNEL — the same function the
  // browser runs — rather than this route building a full envelope and deleting
  // a member. A subtraction rule that lives only here is one the browser will
  // eventually get wrong, and the failure mode is a signature over bytes nobody
  // can re-derive.
  const body = buildAttestationEnvelope({
    credential: snap.credential,
    productDid: prepared.productDid,
    brandOrgDid: prepared.brandOrgDid,
    // Placeholder, removed immediately below: `validFrom` is the SIGNER's
    // instant and the browser fills it in. This payload is for DISPLAY — what
    // the contributor reads before signing — so shipping the server's clock
    // would show them a value that will not be in what they sign.
    validFrom: new Date(),
    validUntil: prepared.validUntil,
  }) as unknown as Record<string, unknown>;
  delete body.validFrom;
  return body;
}

/**
 * Are the signed bytes the bytes this server would have built for this role?
 */
function describeContentMismatch(
  claims: Record<string, unknown> | null,
  snap: { role: string; credential: UnsignedCredential },
  prepared: { productDid: string | null; brandOrgDid: string | null; validUntil: Date | null },
): string | null {
  if (!claims) return "the token carried no payload";
  if ("id" in claims) {
    return "the signed payload carries an `id` — the credential id is minted at publish and must stay outside the signed bytes";
  }
  const validFrom = typeof claims.validFrom === "string" ? Date.parse(claims.validFrom) : NaN;
  if (Number.isNaN(validFrom)) return "`validFrom` is missing or not an ISO instant";
  if (validFrom > Date.now() + ISSUED_AT_FUTURE_SKEW_S * 1000) return "`validFrom` is in the future";

  // Rebuilt with the SAME kernel function the contributor's browser ran, and
  // with the `validFrom` read back out of their token — the comparison is only
  // sound because neither side owns its own copy of the format.
  const expected = buildAttestationEnvelope({
    credential: snap.credential,
    productDid: prepared.productDid,
    brandOrgDid: prepared.brandOrgDid,
    validFrom: new Date(validFrom),
    validUntil: prepared.validUntil,
  }) as unknown as Record<string, unknown>;

  if (canonicalHash(expected) === canonicalHash(claims)) return null;
  // Name the first field that differs — a bare "does not match" sends a
  // contributor hunting through a whole document.
  for (const key of new Set([...Object.keys(expected), ...Object.keys(claims)])) {
    if (canonicalHash(expected[key] ?? null) !== canonicalHash(claims[key] ?? null)) {
      return `\`${key}\` differs from what this passport's current data produces`;
    }
  }
  return "the signed document differs from what this passport's current data produces";
}

/** The client's echoed nonce against the one the chain reports now. */
function assertFreshNonce(claimed: string, actual: bigint): void {
  if (BigInt(claimed) !== actual) {
    throw new HttpError(
      409,
      "The nonce moved since this payload was built — the signature would revert on chain. Rebuild, re-display and re-sign.",
      { signedNonce: claimed, currentNonce: actual.toString() },
    );
  }
}

/**
 * Chain reads fail as 503, never as a wrong answer.
 */
async function withChain<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError) throw err;
    logger.warn({ err }, "design-a: chain read failed");
    throw new HttpError(503, "The chain could not be read. Nothing was queued and nothing was assumed.");
  }
}

/** A `TypeError` from a builder means the CALLER passed something impossible
 *  (a DID that is not did:ethr on this chain) — a 400, not a 500. */
function rethrowAsBadRequest(err: unknown): never {
  if (err instanceof HttpError) throw err;
  if (err instanceof TypeError) throw new HttpError(400, err.message);
  throw err;
}

/** EIP-712 payloads carry `bigint`s, which `JSON.stringify` throws on. Rendered
 *  as decimal strings — the form every wallet accepts for integer types, and the
 *  only one that survives past 2^53. */
function serializeTypedData(payload: { domain: unknown; types: unknown; primaryType: string; message: object }) {
  const message: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload.message)) message[k] = typeof v === "bigint" ? v.toString() : v;
  return { domain: payload.domain, types: payload.types, primaryType: payload.primaryType, message };
}

function serializeAnchorRequest(request: Awaited<ReturnType<typeof buildAnchorRequest>>) {
  return {
    productId: request.productId,
    merkleRoot: request.merkleRoot,
    version: request.version,
    nonce: request.nonce.toString(),
    // WYSIWYS (D7): the per-credential digests and the snapshot digest are what
    // the root is built FROM, so a controller can see what they are committing
    // to instead of approving an opaque 32-byte word.
    credentialDigests: request.credentialDigests,
    snapshotDigest: request.snapshotDigest,
    payload: serializeTypedData(request.payload),
  };
}
