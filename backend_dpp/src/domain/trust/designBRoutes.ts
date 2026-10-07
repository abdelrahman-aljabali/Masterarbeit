import { Router } from "express";
import type { PrismaClient } from "@prisma/client";
import { asyncHandler } from "../../middleware/error.js";
import { publicCors } from "../../middleware/publicCors.js";
import { logger } from "../../observability/logger.js";
import {
  buildOrgDidDoc,
  buildProductDidDoc,
  buildActorOrgDidDoc,
  didHostMismatch,
} from "./did.js";
import { listPublicKeys, PLATFORM_SUBJECT } from "./signingKeys.js";
import { buildStatusListCredential } from "./statusList.js";

/**
 * ─── Design B's public HTTP surface (did:web resolution + status lists) ───────
 * Lives INSIDE the trust wall because it exists only under Design B: did:ethr
 * (Design A) resolves via the Ethereum registry, not via HTTPS paths on this
 * host, and A's revocation is not a served bitstring. Mounted at the app root
 * via `trust.routes()` — on a Design-A instance these endpoints simply do not
 * exist.
 */
export const createDesignBRoutes = (prisma: PrismaClient): Router => {
  const router = Router();

  // did:web documents and status-list credentials are what an EXTERNAL verifier
  // dereferences; the app-wide credentialed CORS policy made them unreachable
  // from any browser-based verifier. They carry no credentials and no private
  // data, so they answer every origin.
  router.use(publicCors);

  // BitstringStatusList v1.0 — the signed revocation-list credential for an
  // issuer org. Referenced from every v2 credential's `credentialStatus`.
  // Freshly signed per request (the list mutates on revocation); short cache.
  router.get("/status/:orgId/:list", asyncHandler(async (req, res) => {
    if (req.params.list !== "1") return res.status(404).json({ error: "Status list not found" });
    const org = await prisma.organization.findUnique({ where: { id: req.params.orgId } });
    if (!org?.did) return res.status(404).json({ error: "Status list not found" });
    const credential = await buildStatusListCredential(prisma, org.id, org.did);
    return res
      .type("application/json")
      .set("Cache-Control", "public, max-age=60")
      .json(credential);
  }));

  // Platform / responsible-operator DID — did:web:<host>. Publishes the platform
  // signing key once provisioned (first platform-signed credential).
  router.get("/.well-known/did.json", asyncHandler(async (_req, res) => {
    const keys = await listPublicKeys(prisma, PLATFORM_SUBJECT);
    res
      .type("application/did+json")
      .set("Cache-Control", "public, max-age=300")
      .json(buildOrgDidDoc(keys));
  }));

  // Subject DID — did:web:<host>:<id> resolves here. Tries product first, then
  // org. Products resolve only when PUBLISHED (a draft DID would leak the
  // existence of an unpublished product); orgs resolve whenever they hold a DID.
  router.get("/:id/did.json", asyncHandler(async (req, res) => {
    const id = req.params.id;

    const product = await prisma.product.findUnique({
      where: { id },
      include: { passport: true },
    });
    if (product?.did && product.passport?.status === "published") {
      // Serve, but fail loudly in logs when the stored DID's host isn't ours —
      // that DID will never resolve via spec did:web resolution.
      if (didHostMismatch(product.did)) {
        logger.warn({ did: product.did, id }, "did:web host mismatch — stored DID host differs from CREDENTIAL_ORIGIN host");
      }
      return res
        .type("application/did+json")
        .set("Cache-Control", "public, max-age=300")
        // gtin → alsoKnownAs: binds the DID identity to the GS1 identity.
        .json(buildProductDidDoc(product.did, product.passport.id, product.gtin));
    }

    const org = await prisma.organization.findUnique({ where: { id } });
    if (org?.did) {
      if (didHostMismatch(org.did)) {
        logger.warn({ did: org.did, id }, "did:web host mismatch — stored DID host differs from CREDENTIAL_ORIGIN host");
      }
      // Publish the org's signing key (custodied) once provisioned — this is
      // what a credential proof's verificationMethod dereferences to.
      const keys = await listPublicKeys(prisma, org.id);
      return res
        .type("application/did+json")
        .set("Cache-Control", "public, max-age=300")
        .json(buildActorOrgDidDoc(org.did, org.name, keys));
    }

    return res.status(404).json({ error: "DID not found" });
  }));

  return router;
};
