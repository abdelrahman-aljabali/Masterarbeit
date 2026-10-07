import { describe, it, expect } from "vitest";
import { TypedDataEncoder } from "ethers";
import { buildSetIssuers, buildSetIssuer, hashTypedData, typeHash, encodeType } from "./typedData.js";
import { EIP712_TYPES, EIP712_PRIMARY_TYPE, eip712Message, normalizeSignedCall } from "./chainTypes.js";
import { serializeCall, deserializeCall } from "./outbox.js";

/**
 * ─── `SetIssuers`: three encoders, one digest ─────────────────────────────────
 * The batch authorization is the first payload in this system with a DYNAMIC
 * ARRAY member, and it is hashed by three independent implementations:
 */

/** Fixed inputs, matching the Solidity golden-vector test member for member. */
const DOMAIN = {
  name: "TrustAnchorRegistry",
  version: "1",
  chainId: 80002,
  verifyingContract: "0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f",
} as const;

const PRODUCT_ID = "0x00000000000000000000000000000000000000000000000000000000000000aa";
const ISSUERS = [
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
];
const NONCE = 42n;

/** Emitted by the Solidity test above. Changing this constant means the CONTRACT
 *  changed, and every stored signature built against the old one is dead. */
const GOLDEN_DIGEST = "0x2218ff5286bac39bd04c0c8ed7517faee21ac71d0fb0fafbcc4ee506c12201e3";

describe("SetIssuers typed data", () => {
  it("the hand-rolled encoder reproduces the contract's digest", () => {
    const payload = buildSetIssuers(DOMAIN, {
      productId: PRODUCT_ID,
      issuers: ISSUERS,
      allowed: true,
      nonce: NONCE,
    });
    expect(hashTypedData(payload)).toBe(GOLDEN_DIGEST);
  });

  it("ethers reproduces the same digest from the same payload", () => {
    // The gateway's path: recoverSigner builds the digest with ethers, from
    // EIP712_TYPES + eip712Message. If this and the test above ever disagree, a
    // signature would verify locally and revert on chain, or the reverse.
    const call = normalizeSignedCall({
      kind: "setIssuers",
      productId: PRODUCT_ID,
      issuers: ISSUERS,
      allowed: true,
      nonce: NONCE,
      signature: `0x${"11".repeat(65)}`,
    } as Parameters<typeof normalizeSignedCall>[0]);

    const digest = TypedDataEncoder.hash(
      DOMAIN,
      { [EIP712_PRIMARY_TYPE.setIssuers]: EIP712_TYPES.setIssuers },
      eip712Message(call),
    );
    expect(digest).toBe(GOLDEN_DIGEST);
  });

  it("the type string is the one the contract hashes", () => {
    expect(encodeType("SetIssuers")).toBe("SetIssuers(bytes32 productId,address[] issuers,bool allowed,uint256 nonce)");
  });

  /**
   * The security property the separate type buys. `SetIssuer` and `SetIssuers`
   * must not produce the same digest for a one-element batch, or every
   * single-issuer signature ever collected becomes a replayable batch.
   */
  it("a one-element batch does not collide with the single-issuer struct", () => {
    const one = [ISSUERS[0]];
    const batch = hashTypedData(
      buildSetIssuers(DOMAIN, { productId: PRODUCT_ID, issuers: one, allowed: true, nonce: NONCE }),
    );
    const single = hashTypedData(
      buildSetIssuer(DOMAIN, { productId: PRODUCT_ID, issuer: one[0], allowed: true, nonce: NONCE }),
    );
    expect(batch).not.toBe(single);
    expect(typeHash("SetIssuers")).not.toBe(typeHash("SetIssuer"));
  });

  /** Order is inside the digest — the array hashes as a concatenation, not a set. */
  it("reordering the issuers changes the digest", () => {
    const forward = hashTypedData(
      buildSetIssuers(DOMAIN, { productId: PRODUCT_ID, issuers: ISSUERS, allowed: true, nonce: NONCE }),
    );
    const reversed = hashTypedData(
      buildSetIssuers(DOMAIN, { productId: PRODUCT_ID, issuers: [...ISSUERS].reverse(), allowed: true, nonce: NONCE }),
    );
    expect(forward).not.toBe(reversed);
  });

  it("refuses an empty set rather than building a payload the contract reverts on", () => {
    expect(() =>
      buildSetIssuers(DOMAIN, { productId: PRODUCT_ID, issuers: [], allowed: true, nonce: NONCE }),
    ).toThrow(/at least one address/);
  });

  /**
   * The outbox round trip. The array is inside the signed digest, so a row that
   * loses it — or reorders it — submits bytes the signature does not cover, and
   * the operator pays gas for an `InvalidNonce`-shaped mystery.
   */
  it("survives serialization to the outbox and back, in order", () => {
    const call = normalizeSignedCall({
      kind: "setIssuers",
      productId: PRODUCT_ID,
      issuers: ISSUERS,
      allowed: true,
      nonce: NONCE,
      signature: `0x${"22".repeat(65)}`,
    } as Parameters<typeof normalizeSignedCall>[0]);

    const restored = deserializeCall(serializeCall(call));
    expect(restored.kind).toBe("setIssuers");
    if (restored.kind !== "setIssuers") throw new Error("unreachable");
    expect(restored.issuers).toEqual(ISSUERS);
    expect(restored.allowed).toBe(true);
    expect(restored.nonce).toBe(NONCE);
  });

  it("refuses a stored row whose issuers went missing, rather than defaulting", () => {
    expect(() =>
      deserializeCall({
        kind: "setIssuers",
        productId: PRODUCT_ID,
        nonce: "42",
        allowed: true,
        signature: `0x${"33".repeat(65)}`,
      }),
    ).toThrow(/missing signed field "issuers"/);
  });

  it("refuses a zero address anywhere in the batch", () => {
    expect(() =>
      normalizeSignedCall({
        kind: "setIssuers",
        productId: PRODUCT_ID,
        issuers: [ISSUERS[0], "0x0000000000000000000000000000000000000000"],
        allowed: true,
        nonce: NONCE,
        signature: `0x${"44".repeat(65)}`,
      } as Parameters<typeof normalizeSignedCall>[0]),
    ).toThrow(/ZeroIssuer/);
  });
});
