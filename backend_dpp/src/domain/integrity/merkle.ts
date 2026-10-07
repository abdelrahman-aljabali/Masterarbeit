import { stableStringify } from "./hash.js";
// The seam's VOCABULARY only — see credentialDigest for why the doorway
// (trust/index.js) must not be imported here.
import { isEnvelopedCredential, parseEnvelopedCredentialId } from "../trust/types.js";
import {
  compareBytes32,
  hexToBytes,
  keccak256Concat,
  keccak256Utf8,
  toBytes32,
  type Bytes32,
} from "./keccak.js";

/**
 * ─── The Merkle convention, off-chain half ────────────────────────────────────
 * `contracts/src/TrustAnchorRegistry.sol` is the NORMATIVE specification of what
 * is in this file. Its `hashLeaf` / `hashNode` / `verifyInclusion` are `pure`,
 * so they exist precisely to give this builder an executable spec instead of a
 * prose one — and the cross-check runs them on a real chain, over RPC, against
 * roots and proofs built here.
 */

/** `keccak256(0x00 ‖ digest)`. Mirrors `TrustAnchorRegistry.hashLeaf`. */
export function hashLeaf(digest: string): Bytes32 {
  const d = toBytes32(digest, "digest");
  return keccak256Concat(Uint8Array.of(0x00), hexToBytes(d, { bytes: 32, label: "digest" }));
}

/** `keccak256(0x01 ‖ min ‖ max)`. Mirrors `TrustAnchorRegistry.hashNode`. */
export function hashNode(a: string, b: string): Bytes32 {
  const x = toBytes32(a, "node.a");
  const y = toBytes32(b, "node.b");
  const [lo, hi] = compareBytes32(x, y) <= 0 ? [x, y] : [y, x];
  return keccak256Concat(
    Uint8Array.of(0x01),
    hexToBytes(lo, { bytes: 32 }),
    hexToBytes(hi, { bytes: 32 }),
  );
}

/** One level of the tree, folded into the next. Shared by the root builder and
 *  the proof builder so the two can never disagree about the promotion rule. */
function foldLevel(level: readonly Bytes32[]): Bytes32[] {
  const next: Bytes32[] = [];
  let i = 0;
  for (; i + 1 < level.length; i += 2) next.push(hashNode(level[i]!, level[i + 1]!));
  // Odd count: the last element rides up unchanged.
  if (level.length % 2 === 1) next.push(level[level.length - 1]!);
  return next;
}

function toLeaves(digests: readonly string[]): Bytes32[] {
  if (digests.length === 0) {
    // There is no root for the empty set, and inventing one would be worse than
    // refusing: `bytes32(0)` is the value `TrustAnchorRegistry.anchor` rejects
    // with `ZeroMerkleRoot` precisely because an all-zero root "anchors nothing
    // while looking like a valid anchor". Unreachable from `versionMerkleRoot`,
    // which always appends the snapshot digest — so the tree there has ≥ 1 leaf
    // even for a passport version carrying no credentials at all.
    throw new RangeError("merkle: cannot build a tree over zero digests");
  }
  return digests.map((d, i) => hashLeaf(toBytes32(d, `digests[${i}]`)));
}

/**
 * Build the tree over an ORDERED list of 32-byte digests.
 *
 * @returns `root` — what gets anchored on-chain — and `leaves`, the tagged
 * level-0 hashes (`leaves[i] === hashLeaf(digests[i])`), which a verifier needs
 * to reproduce a proof and which are NOT the input digests.
 */
export function buildMerkleTree(digests: string[]): { root: Bytes32; leaves: Bytes32[] } {
  const leaves = toLeaves(digests);
  let level: Bytes32[] = leaves;
  while (level.length > 1) level = foldLevel(level);
  return { root: level[0]!, leaves };
}

/**
 * The sibling path proving `digests[index]`, leaf-to-root.
 */
export function merkleProof(digests: string[], index: number): Bytes32[] {
  if (!Number.isInteger(index) || index < 0 || index >= digests.length) {
    throw new RangeError(`merkle: index ${index} out of range for ${digests.length} digests`);
  }
  let level: Bytes32[] = toLeaves(digests);
  let pos = index;
  const proof: Bytes32[] = [];

  while (level.length > 1) {
    const next: Bytes32[] = [];
    let nextPos = pos;
    let i = 0;
    for (; i + 1 < level.length; i += 2) {
      if (pos === i) {
        proof.push(level[i + 1]!);
        nextPos = next.length;
      } else if (pos === i + 1) {
        proof.push(level[i]!);
        nextPos = next.length;
      }
      next.push(hashNode(level[i]!, level[i + 1]!));
    }
    if (level.length % 2 === 1) {
      // The promoted node contributes NOTHING to the proof this round — it has
      // no sibling to name. Getting this wrong is the classic odd-tree bug.
      if (pos === level.length - 1) nextPos = next.length;
      next.push(level[level.length - 1]!);
    }
    pos = nextPos;
    level = next;
  }
  return proof;
}

/**
 * Re-derive the root from one digest and its sibling path.
 */
export function verifyMerkleProof(root: string, digest: string, proof: string[]): boolean {
  let node: Bytes32 = hashLeaf(digest);
  for (const sibling of proof) node = hashNode(node, sibling);
  return node === toBytes32(root, "root");
}

/* ────────────────────────────────────────────────────────────────────────────
 *  Tying the tree to a published passport version
 * ──────────────────────────────────────────────────────────────────────────── */

/**
 * Domain tag inside the snapshot digest's pre-image.
 */
export const VERSION_SNAPSHOT_DIGEST_KIND = "trustdpp/version-snapshot/v1";

/**
 * The digest of ONE stored credential — over its EXACT stored bytes.
 */
export function credentialDigest(stored: unknown): Bytes32 {
  if (typeof stored === "string") return keccak256Utf8(stored);
  if (!stored || typeof stored !== "object") {
    throw new TypeError(`credentialDigest: expected a credential object or token, got ${typeof stored}`);
  }
  if (!isEnvelopedCredential(stored)) return keccak256Utf8(stableStringify(stored));
  const parsed = parseEnvelopedCredentialId((stored as { id?: unknown }).id);
  if (!parsed) {
    throw new TypeError("credentialDigest: EnvelopedVerifiableCredential without a parseable data: URL id");
  }
  return keccak256Utf8(parsed.token);
}

/**
 * The digest that carries ORDER, and the final leaf of every version tree.
 */
export function snapshotDigest(input: {
  snapshot: unknown;
  version: number;
  credentialDigests: readonly string[];
}): Bytes32 {
  return keccak256Utf8(
    stableStringify({
      kind: VERSION_SNAPSHOT_DIGEST_KIND,
      version: input.version,
      credentialDigests: input.credentialDigests.map((d, i) => toBytes32(d, `credentialDigests[${i}]`)),
      snapshot: input.snapshot,
    }),
  );
}

/** Everything a publish needs to anchor a version, and everything a verifier
 *  needs to reproduce it. */
export interface VersionMerkleTree {
  /** The value signed into an `Anchor` payload and emitted by `Anchored`. */
  root: Bytes32;
  /** Per-credential digests, in publish order. */
  credentialDigests: Bytes32[];
  /** The order-carrying final leaf's digest. */
  snapshotDigest: Bytes32;
  /** The digests actually fed to the tree: `[...credentialDigests, snapshotDigest]`. */
  digests: Bytes32[];
  /** Tagged level-0 hashes, aligned with `digests`. */
  leaves: Bytes32[];
}

/**
 * Build the per-version Merkle root: the ordered credential digests, with the
 * snapshot digest appended as the FINAL leaf.
 */
export function versionMerkleRoot(input: {
  snapshot: unknown;
  credentials: readonly unknown[];
  version: number;
}): VersionMerkleTree {
  const credentialDigests = input.credentials.map(credentialDigest);
  const snapDigest = snapshotDigest({
    snapshot: input.snapshot,
    version: input.version,
    credentialDigests,
  });
  const digests = [...credentialDigests, snapDigest];
  const { root, leaves } = buildMerkleTree(digests);
  return { root, credentialDigests, snapshotDigest: snapDigest, digests, leaves };
}

/**
 * The proof for one credential of a published version, by publish index.
 *
 * Pass `index === credentials.length` to prove the snapshot leaf itself — the
 * proof a verifier uses to establish that THIS ordered credential list is the
 * one the root commits to.
 */
export function versionMerkleProof(
  input: { snapshot: unknown; credentials: readonly unknown[]; version: number },
  index: number,
): { root: Bytes32; digest: Bytes32; proof: Bytes32[] } {
  const tree = versionMerkleRoot(input);
  return { root: tree.root, digest: tree.digests[index]!, proof: merkleProof(tree.digests, index) };
}
