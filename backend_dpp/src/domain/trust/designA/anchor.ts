import type { Prisma, PrismaClient } from "@prisma/client";
import { HttpError } from "../../../middleware/error.js";
import { versionMerkleRoot } from "../../integrity/merkle.js";
import type { ChainHeadCommitment } from "../TrustProvider.js";
import type { ChainGateway } from "./chainGateway.js";
import {
  anchorPresence,
  type Address,
  type AnchorLookup,
  type AnchorPresence,
  type AnchorRecord,
  type ProductId,
  type SignedCall,
} from "./chainTypes.js";
import { buildAnchor, productIdFromDid, type TypedDataPayload } from "./typedData.js";
import { registryDomain } from "./authRoot.js";
import { enqueueSignedCall } from "./outbox.js";

/**
 * ─── Anchoring a published version ────────────────────────────────────────────
 * **Why anchoring is a separate step from publishing, and not a bug that it
 * is.**
 */

type Db = PrismaClient | Prisma.TransactionClient;

/** What a controller's browser needs in order to display and sign an anchor. */
export interface AnchorRequest {
  payload: TypedDataPayload<"Anchor">;
  productId: ProductId;
  merkleRoot: string;
  version: number;
  nonce: bigint;
  /** The per-credential digests, so the UI can show WHAT is being committed to
   *  rather than asking someone to sign an opaque 32-byte root (D7 / WYSIWYS). */
  credentialDigests: readonly string[];
  snapshotDigest: string;
}

/**
 * Build the anchor payload for a frozen passport version.
 */
export async function buildAnchorRequest(
  prisma: PrismaClient,
  gateway: ChainGateway,
  args: { passportId: string; version?: number; controller: Address },
): Promise<AnchorRequest> {
  const row = await prisma.passportVersion.findFirst({
    where: { passportId: args.passportId, ...(args.version ? { version: args.version } : {}) },
    orderBy: { version: "desc" },
    select: { version: true, snapshot: true, credentials: true, passport: { select: { product: { select: { did: true } } } } },
  });
  if (!row) throw new HttpError(404, "No published version to anchor.");

  const productDid = row.passport?.product?.did ?? null;
  if (!productDid) {
    // Anchoring keys on keccak256(productDid); without a product DID there is no
    // on-chain identity to anchor against. Publish already gates on issuer DIDs,
    // so this is a data-integrity failure, not a user error.
    throw new HttpError(422, "Cannot anchor: the product has no DID.", { passportId: args.passportId });
  }

  const tree = versionMerkleRoot({
    snapshot: row.snapshot,
    credentials: (row.credentials ?? []) as unknown[],
    version: row.version,
  });
  const productId = productIdFromDid(productDid);
  const nonce = await gateway.nonceOf(args.controller);

  return {
    payload: buildAnchor(registryDomain(), { productId, merkleRoot: tree.root, version: row.version, nonce }),
    productId,
    merkleRoot: tree.root,
    version: row.version,
    nonce,
    credentialDigests: tree.credentialDigests,
    snapshotDigest: tree.snapshotDigest,
  };
}

/** Queue a controller-signed anchor. Inside the caller's transaction, so the
 *  publish/anchor record and the chain write commit together. */
export async function enqueueAnchor(
  db: Db,
  call: Extract<SignedCall, { kind: "anchor" }>,
  ctx: { passportId?: string | null; orgId?: string | null } = {},
): Promise<{ id: string }> {
  return enqueueSignedCall(db, call, { ...ctx, productId: call.productId });
}

/**
 * The on-chain anchor for a version, read from event logs — the verification
 * side of the above, and the one an INDEPENDENT verifier performs with nothing
 * but an RPC endpoint.
 */
export async function findVersionAnchor(
  prisma: PrismaClient,
  gateway: ChainGateway,
  args: { passportId: string; version: number },
): Promise<{
  anchor: AnchorRecord | null;
  expectedRoot: string;
  matches: boolean;
  presence: AnchorPresence;
  coverage: AnchorLookup;
}> {
  const row = await prisma.passportVersion.findFirst({
    where: { passportId: args.passportId, version: args.version },
    select: { version: true, snapshot: true, credentials: true, passport: { select: { product: { select: { did: true } } } } },
  });
  if (!row) throw new HttpError(404, "No such passport version.");
  const productDid = row.passport?.product?.did;
  if (!productDid) throw new HttpError(422, "Cannot verify anchor: the product has no DID.");

  const expectedRoot = versionMerkleRoot({
    snapshot: row.snapshot,
    credentials: (row.credentials ?? []) as unknown[],
    version: row.version,
  }).root;

  const lookup = await gateway.findAnchor(productIdFromDid(productDid), row.version, {
    txHash: await confirmedAnchorTxHash(prisma, args.passportId, row.version),
  });
  const anchor = lookup.anchor;
  return {
    anchor,
    expectedRoot,
    matches: anchor !== null && anchor.merkleRoot.toLowerCase() === expectedRoot.toLowerCase(),
    presence: anchorPresence(lookup),
    coverage: lookup,
  };
}

/**
 * The transaction this platform relayed for a version's anchor, if it confirmed.
 */
async function confirmedAnchorTxHash(
  prisma: PrismaClient,
  passportId: string,
  version: number,
): Promise<string | null> {
  const rows = await prisma.anchorTx.findMany({
    where: { passportId, kind: "anchor", status: "confirmed", txHash: { not: null } },
    orderBy: { confirmedAt: "desc" },
    take: 10,
    select: { txHash: true, payload: true },
  });
  const wanted = String(version);
  for (const row of rows) {
    const payload = (row.payload ?? {}) as Record<string, unknown>;
    if (String(payload.version ?? "") === wanted) return row.txHash;
  }
  return null;
}

/**
 * Design A's answer to `commitChainHead`.
 */
export async function commitChainHeadUnsigned(
  prisma: PrismaClient,
  orgId: string,
): Promise<ChainHeadCommitment> {
  const tip = await prisma.auditEvent.findFirst({
    where: { orgId, seq: { not: null } },
    orderBy: { seq: "desc" },
    select: { seq: true, hash: true },
  });

  // The org's confirmed on-chain anchors — where this design's evidence actually is.
  const anchors = await prisma.anchorTx.findMany({
    where: { orgId, kind: "anchor", status: "confirmed" },
    orderBy: { confirmedAt: "desc" },
    take: 20,
    select: { passportId: true, txHash: true, blockNumber: true, confirmedAt: true },
  });

  return {
    mode: "design-a",
    orgId,
    seq: tip?.seq ?? 0,
    headHash: tip?.hash ?? null,
    at: new Date().toISOString(),
    proof: {
      type: "on-chain-anchors",
      note:
        "Design A does not sign chain heads: the platform holds no signing key. " +
        "Tamper-evidence for published data comes from per-version Merkle roots anchored " +
        "on chain by each product's controller, listed below and verifiable independently " +
        "of this platform.",
      chainId: registryDomain().chainId,
      registry: registryDomain().verifyingContract,
      anchors: anchors.map((a) => ({
        passportId: a.passportId,
        txHash: a.txHash,
        blockNumber: a.blockNumber,
        confirmedAt: a.confirmedAt?.toISOString() ?? null,
      })),
    },
  };
}
