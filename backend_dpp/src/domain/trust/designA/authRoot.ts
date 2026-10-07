import type { Prisma, PrismaClient } from "@prisma/client";
import { config } from "../../../config.js";
import { type Address, type ProductId, type SignedCall } from "./chainTypes.js";
import { didEthrAddress, type ChainBinding } from "./didEthr.js";
import { toAddress } from "../../integrity/keccak.js";
import type { ChainGateway } from "./chainGateway.js";
import {
  buildSetIssuer,
  productIdFromDid,
  REGISTRY_DOMAIN_NAME,
  REGISTRY_DOMAIN_VERSION,
  type Eip712Domain,
  type TypedDataPayload,
} from "./typedData.js";
import { enqueueSignedCall } from "./outbox.js";

/**
 * ─── Mechanism 4: the on-chain authorization root ─────────────────────────────
 * The question this file answers is the one that makes per-actor attribution
 * mean anything: *a credential verifies cryptographically, but was this issuer
 * ever entitled to speak about this product?*
 */

type Db = PrismaClient | Prisma.TransactionClient;

/** The registry's EIP-712 domain for THIS deployment.
 *
 *  Built from config rather than read over RPC because a wallet must be able to
 *  display and sign a payload without a chain round-trip. `assertRegistryDomain`
 *  (typedData.ts) validates this against the contract's own ERC-5267
 *  `eip712Domain()` — do that once at boot, not per signature. */
export function registryDomain(): Eip712Domain {
  const a = config.designA;
  if (!a) throw new Error("registryDomain: Design A config is absent — this code is unreachable under Design B.");
  return {
    name: REGISTRY_DOMAIN_NAME,
    version: REGISTRY_DOMAIN_VERSION,
    chainId: a.chainId,
    // `toAddress` rather than a cast: config validated the SHAPE at boot, but
    // typedData's Address is a branded `0x${string}` and this is the value that
    // ends up in the domain separator every signature is bound to. Validating
    // again here costs nothing and cannot be wrong.
    verifyingContract: toAddress(a.anchorRegistryAddress, "ANCHOR_REGISTRY_ADDRESS"),
  };
}

/**
 * Is `issuerDid` entitled to issue credentials about `productDid`?
 */
export async function isIssuerAuthorized(
  gateway: ChainGateway,
  productDid: string,
  issuerDid: string,
): Promise<boolean> {
  const issuer = issuerAddressOf(issuerDid);
  if (!issuer) return false; // not a did:ethr on this chain — a real "no", not an error
  const productId = productIdFromDid(productDid);

  if (await gateway.isAuthorized(productId, issuer)) return true;

  const controller = await gateway.productController(productId);
  return controller !== null && controller.toLowerCase() === issuer.toLowerCase();
}

/** This deployment's chain, as the `did:ethr` helpers want it. */
export function chainBinding(): ChainBinding {
  const a = config.designA;
  if (!a) throw new Error("chainBinding: Design A config is absent — this code is unreachable under Design B.");
  return { chainId: a.chainId, chainName: a.chainName };
}

/**
 * The address a `did:ethr` issuer resolves to, or null when the DID is not a
 * did:ethr this deployment serves (wrong method, wrong chain, malformed).
 */
export function issuerAddressOf(issuerDid: string): Address | null {
  return didEthrAddress(issuerDid, chainBinding());
}

/**
 * Build the payload a controller signs to authorize (or de-authorize) an issuer.
 */
export async function buildAuthorizationRequest(
  gateway: ChainGateway,
  args: { productDid: string; issuerDid: string; allowed: boolean; controller: Address },
): Promise<{ payload: TypedDataPayload<"SetIssuer">; productId: ProductId; issuer: Address; nonce: bigint }> {
  const issuer = issuerAddressOf(args.issuerDid);
  if (!issuer) {
    throw new TypeError(`buildAuthorizationRequest: ${args.issuerDid} is not a did:ethr on chain ${config.designA?.chainId}`);
  }
  const productId = productIdFromDid(args.productDid);
  const nonce = await gateway.nonceOf(args.controller);
  return {
    payload: buildSetIssuer(registryDomain(), { productId, issuer, allowed: args.allowed, nonce }),
    productId,
    issuer,
    nonce,
  };
}

/**
 * Queue a controller-signed authorization. Runs inside the caller's transaction
 * so the database record of the decision and the chain write commit together.
 */
export async function enqueueAuthorization(
  db: Db,
  call: Extract<SignedCall, { kind: "setIssuer" }>,
  ctx: { orgId?: string | null; passportId?: string | null } = {},
): Promise<{ id: string }> {
  return enqueueSignedCall(db, call, { ...ctx, productId: call.productId });
}
