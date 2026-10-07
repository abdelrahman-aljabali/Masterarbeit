import crypto from "crypto";

/**
 * ─── Regulation-facing passport UUID (RFC 9562 §5.5, name-based v5) ───────────
 * The internal `dpp_*` id stays the routing/DB key everywhere (URLs, DIDs, QR).
 * The RULEBOOK-facing "Passport Identifier (UUID)" (§6.1.1, RFC 4122/9562) is
 * DERIVED from it deterministically: same passport → same UUID, forever, with no
 * stored column and no migration. Published snapshots/VCs carry this value.
 */

// Fixed namespace for TrustDPP passport identifiers. NEVER change this value —
// the UUIDs derived under it are frozen into published snapshots and VCs.
export const PASSPORT_NAMESPACE = "c7b3f8e2-4a61-4d05-9b2e-6f1d8a0c5e93";

const uuidBytes = (uuid: string): Buffer => Buffer.from(uuid.replace(/-/g, ""), "hex");

/** RFC 9562 name-based UUID (version 5, SHA-1). */
export function uuidV5(name: string, namespace: string = PASSPORT_NAMESPACE): string {
  const hash = crypto
    .createHash("sha1")
    .update(uuidBytes(namespace))
    .update(name, "utf8")
    .digest();
  const b = hash.subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC variant
  const h = Buffer.from(b).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** The passport's RFC 9562 UUID, derived from the internal passport id. */
export const passportUuid = (dppId: string): string => uuidV5(`passport:${dppId}`);
