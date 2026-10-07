import type { ChainGateway } from "./chainGateway.js";
import {
  asAddress,
  asBytes32,
  asUint,
  buildDidDocument,
  ChainCallRevertedError,
  ChainUnavailableError,
  InvalidChainArgumentError,
  latestAnchor,
  networkMatchesChain,
  normalizeSignedCall,
  parseDidEthr,
  RelayerMayNotAuthorizeError,
  ZERO_ADDRESS,
  type Address,
  type AnchorHint,
  type AnchorLookup,
  type AnchorRecord,
  type Bytes32,
  type DidDocument,
  type ProductId,
  type SignedCall,
  type Signature65,
  type TxStatus,
} from "./chainTypes.js";

/**
 * ─── FakeChainGateway — the same object, without a chain ──────────────────────
 * In-memory, deterministic, zero network — so minting, signing, verification,
 * authorization and anchoring can be exercised without an RPC endpoint, a funded
 * relayer, or a testnet that is having a bad day.
 */

interface PendingTx {
  txHash: string;
  call: SignedCall;
  signer: Address;
  status: "pending" | "confirmed" | "failed";
  blockNumber?: number;
}

export interface FakeChainGatewayOptions {
  chainId?: number;
  chainName?: string;
  /** The relayer's address — payloads recovering to it are refused, as on the real gateway. */
  relayerAddress?: Address;
  /**
   * Apply a submitted call immediately and mark it confirmed (the default).
   * `false` keeps transactions `pending` until `confirm()` / `fail()`, which is
   * how the outbox worker's polling path gets exercised.
   */
  autoConfirm?: boolean;
  /** Block number of the first auto-confirmed transaction; incremented per block. */
  startBlock?: number;
}

export class FakeChainGateway implements ChainGateway {
  readonly chainId: number;
  readonly chainName: string;
  readonly relayerAddress: Address;

  private readonly autoConfirm: boolean;
  private block: number;

  // ── Modelled chain state ────────────────────────────────────────────────
  private readonly controllers = new Map<ProductId, Address>();
  private readonly authorizations = new Map<string, boolean>();
  private readonly nonces = new Map<Address, bigint>();
  private readonly anchors: AnchorRecord[] = [];
  /** ERC-1056 `owners[identity]`; absent = never changed. */
  private readonly didOwners = new Map<Address, Address>();
  private readonly txs = new Map<string, PendingTx>();
  private txCount = 0;

  // ── Injected failure ────────────────────────────────────────────────────
  private unavailable: string | null = null;
  private failNext = 0;

  constructor(opts: FakeChainGatewayOptions = {}) {
    this.chainId = opts.chainId ?? 80002;
    this.chainName = opts.chainName ?? "amoy";
    this.relayerAddress = asAddress(opts.relayerAddress ?? "0x00000000000000000000000000000000000000f1", "relayerAddress");
    this.autoConfirm = opts.autoConfirm ?? true;
    this.block = opts.startBlock ?? 1_000_000;
  }

  // ── Seeding ────────────────────────────────────────────────────────────────
  // Direct state writes, bypassing signatures. Tests that care about the
  // authorization RULES go through `submitSignedCall` with `signatureOf()`;
  // tests that just need a world to exist use these.

  /** Install a controller for a product (as a successful `claimProduct` would). */
  setController(productId: ProductId, controller: Address): this {
    this.controllers.set(asBytes32(productId, "productId"), asAddress(controller, "controller"));
    return this;
  }

  /** Grant or revoke an issuer (as a successful `setIssuer` would). */
  authorize(productId: ProductId, issuer: Address, allowed = true): this {
    this.authorizations.set(this.authKey(productId, issuer), allowed);
    return this;
  }

  /** Record an `Anchored` log entry. */
  recordAnchor(
    productId: ProductId,
    merkleRoot: Bytes32,
    version: number | bigint,
    by: Address,
    at?: { blockNumber?: number; txHash?: string },
  ): AnchorRecord {
    const record: AnchorRecord = {
      productId: asBytes32(productId, "productId"),
      merkleRoot: asBytes32(merkleRoot, "merkleRoot"),
      version: asUint(version, "version"),
      by: asAddress(by, "by"),
      txHash: at?.txHash ?? this.nextTxHash(),
      blockNumber: at?.blockNumber ?? this.block++,
      logIndex: this.anchors.length,
      occurrences: 1,
    };
    this.anchors.push(record);
    return record;
  }

  /** Set `owners[identity]` in the modelled ERC-1056 registry (rotation). */
  setDidOwner(identity: Address, owner: Address): this {
    this.didOwners.set(asAddress(identity, "identity"), asAddress(owner, "owner"));
    return this;
  }

  /** Deactivate a `did:ethr` the way the method spec does: owner → address(0). */
  deactivateDid(identity: Address): this {
    return this.setDidOwner(identity, ZERO_ADDRESS);
  }

  /** Preload a signer's nonce (the contract's `nonces[signer]`). */
  setNonce(signer: Address, nonce: number | bigint): this {
    this.nonces.set(asAddress(signer, "signer"), asUint(nonce, "nonce"));
    return this;
  }

  // ── Injected failure ───────────────────────────────────────────────────────

  /** Every call throws `ChainUnavailableError` until `setUnavailable(null)`. */
  setUnavailable(reason: string | null = "both RPC endpoints are down (simulated)"): this {
    this.unavailable = reason;
    return this;
  }

  /** Fail the next `count` operations only — the retry/failover path. */
  failNextRead(count = 1): this {
    this.failNext = count;
    return this;
  }

  // ── Transaction lifecycle (autoConfirm: false) ─────────────────────────────

  /**
   * Mine a pending transaction. The call is re-validated first, so a payload
   * that was valid when submitted but has since been overtaken (someone else
   * used that nonce) lands as `failed` — which is exactly what happens on a real
   * chain, and is the case an outbox worker gets wrong if it never sees it.
   */
  confirm(txHash: string): TxStatus {
    const tx = this.mustFindTx(txHash);
    if (tx.status !== "pending") return this.statusOf(tx);
    try {
      this.applyCall(tx.call, tx.signer);
      tx.status = "confirmed";
    } catch {
      tx.status = "failed";
    }
    tx.blockNumber = this.block++;
    return this.statusOf(tx);
  }

  /** Mine a pending transaction as reverted, without applying it. */
  fail(txHash: string): TxStatus {
    const tx = this.mustFindTx(txHash);
    tx.status = "failed";
    tx.blockNumber ??= this.block++;
    return this.statusOf(tx);
  }

  // ── Signature helper ───────────────────────────────────────────────────────

  /**
   * A 65-byte "signature" that recovers to `signer`: the address, then padding.
   * Deterministic and cryptographically meaningless — the point is that the
   * fake, like the contract, decides authority from the RECOVERED SIGNER and
   * never from who submitted it.
   */
  static signatureOf(signer: Address): Signature65 {
    return `0x${asAddress(signer, "signer").slice(2)}${"0".repeat(90)}`;
  }

  static recoverSigner(signature: Signature65): Address {
    if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
      throw new ChainCallRevertedError("signature does not recover to any address", "ECDSAInvalidSignature");
    }
    const addr = `0x${signature.slice(2, 42)}`.toLowerCase();
    if (addr === ZERO_ADDRESS) {
      // The contract's ECDSA.recover reverts rather than returning address(0) —
      // a zero recovery would otherwise impersonate an unclaimed product's
      // address(0) controller.
      throw new ChainCallRevertedError("signature does not recover to any address", "ECDSAInvalidSignature");
    }
    return addr;
  }

  // ── ChainGateway ───────────────────────────────────────────────────────────

  async resolveDidDocument(did: string): Promise<DidDocument | null> {
    this.guardAvailable("resolveDidDocument");
    const parsed = parseDidEthr(did);
    if (!parsed) return null;
    if (!networkMatchesChain(parsed.network, this.chainId, this.chainName)) return null;
    // Absent from the owners map = never changed on-chain = the address-derived
    // default document, which is the overwhelmingly common case for did:ethr.
    const owner = this.didOwners.get(parsed.address) ?? parsed.address;
    return buildDidDocument({ did, owner, chainId: this.chainId });
  }

  async isAuthorized(productId: ProductId, issuer: Address): Promise<boolean> {
    this.guardAvailable("isAuthorized");
    return this.authorizations.get(this.authKey(productId, issuer)) ?? false;
  }

  async productController(productId: ProductId): Promise<Address | null> {
    this.guardAvailable("productController");
    return this.controllers.get(asBytes32(productId, "productId")) ?? null;
  }

  /**
   * The same three-way answer the real gateway gives, minus the reason it needs
   * one. An in-memory array has no range caps and no request budget, so a search
   * here is always `complete: true` — i.e. the fake can produce "anchored" and
   * "absent" but never "inconclusive".
   */
  async findAnchor(productId: ProductId, version: number | bigint, _hint: AnchorHint = {}): Promise<AnchorLookup> {
    this.guardAvailable("findAnchor");
    const id = asBytes32(productId, "productId");
    const wanted = asUint(version, "version");
    const matches = this.anchors.filter((a) => a.productId === id && a.version === wanted);
    // `latestAnchor` is the REAL gateway's own picker, so "which anchor counts"
    // has exactly one definition across both.
    const anchor = latestAnchor(matches);
    return {
      anchor,
      complete: true,
      scannedFrom: 0,
      scannedTo: this.block,
      requests: 0,
      window: 0,
      capped: false,
      via: "log-scan",
    };
  }

  async nonceOf(signer: Address): Promise<bigint> {
    this.guardAvailable("nonceOf");
    return this.nonces.get(asAddress(signer, "signer")) ?? 0n;
  }

  async submitSignedCall(call: SignedCall): Promise<{ txHash: string; signer: Address }> {
    this.guardAvailable("submitSignedCall");
    const normalized = normalizeSignedCall(call);
    const signer = FakeChainGateway.recoverSigner(normalized.signature);
    if (signer === this.relayerAddress) {
      throw new RelayerMayNotAuthorizeError(
        "Refusing to submit a payload whose recovered signer is the relayer.",
        { kind: normalized.kind },
      );
    }

    // The real gateway estimates gas before signing, so a doomed call throws
    // here rather than becoming a failed transaction. Same shape, same moment.
    this.validateCall(normalized, signer);

    const txHash = this.nextTxHash();
    const tx: PendingTx = { txHash, call: normalized, signer, status: "pending" };
    this.txs.set(txHash, tx);
    if (this.autoConfirm) {
      this.applyCall(normalized, signer);
      tx.status = "confirmed";
      tx.blockNumber = this.block++;
    }
    return { txHash, signer };
  }

  async txStatus(txHash: string): Promise<TxStatus> {
    this.guardAvailable("txStatus");
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      throw new ChainCallRevertedError("txHash must be a 0x-prefixed 32-byte hash", null, { txHash });
    }
    const tx = this.txs.get(txHash.toLowerCase());
    // Never submitted here → the modelled node has never heard of it.
    return tx ? this.statusOf(tx) : { status: "unknown" };
  }

  // ── The modelled state machine ─────────────────────────────────────────────

  /** Exactly the checks TrustAnchorRegistry makes, in the order it makes them. */
  private validateCall(call: SignedCall, signer: Address): void {
    switch (call.kind) {
      case "claimProduct": {
        const previous = this.controllers.get(call.productId);
        if (!previous) {
          if (signer !== call.controller) {
            throw new ChainCallRevertedError("claimProduct reverted: ClaimMustBeSelfSigned", "ClaimMustBeSelfSigned", {
              signer,
              controller: call.controller,
            });
          }
        } else if (signer !== previous) {
          throw new ChainCallRevertedError("claimProduct reverted: NotController", "NotController", {
            signer,
            controller: previous,
          });
        }
        break;
      }
      case "setIssuer":
      case "setIssuers":
      case "anchor": {
        // An unclaimed product has controller address(0), which no recovered
        // signer can equal — so this is also the "unclaimed" error, as on-chain.
        const controller = this.controllers.get(call.productId) ?? ZERO_ADDRESS;
        if (signer !== controller) {
          throw new ChainCallRevertedError(`${call.kind} reverted: NotController`, "NotController", {
            signer,
            controller,
          });
        }
        break;
      }
    }
    const expected = this.nonces.get(signer) ?? 0n;
    if (call.nonce !== expected) {
      throw new ChainCallRevertedError("call reverted: InvalidNonce", "InvalidNonce", {
        signer,
        expected: expected.toString(),
        provided: call.nonce.toString(),
      });
    }
  }

  private applyCall(call: SignedCall, signer: Address): void {
    this.validateCall(call, signer);
    this.nonces.set(signer, (this.nonces.get(signer) ?? 0n) + 1n);
    switch (call.kind) {
      case "claimProduct":
        this.controllers.set(call.productId, call.controller);
        return;
      case "setIssuer":
        this.authorizations.set(this.authKey(call.productId, call.issuer), call.allowed);
        return;
      case "setIssuers":
        // One nonce (already consumed above), N writes — the contract's loop.
        for (const issuer of call.issuers) {
          this.authorizations.set(this.authKey(call.productId, issuer), call.allowed);
        }
        return;
      case "anchor":
        this.recordAnchor(call.productId, call.merkleRoot, call.version, signer);
        return;
    }
  }

  // ── Internals ──────────────────────────────────────────────────────────────

  private guardAvailable(op: string): void {
    if (this.unavailable !== null) {
      throw new ChainUnavailableError(`${op}: ${this.unavailable}`, { op });
    }
    if (this.failNext > 0) {
      this.failNext--;
      throw new ChainUnavailableError(`${op}: injected endpoint failure`, { op });
    }
  }

  private authKey(productId: ProductId, issuer: Address): string {
    return `${asBytes32(productId, "productId")}:${asAddress(issuer, "issuer")}`;
  }

  private statusOf(tx: PendingTx): TxStatus {
    return tx.blockNumber === undefined ? { status: tx.status } : { status: tx.status, blockNumber: tx.blockNumber };
  }

  private mustFindTx(txHash: string): PendingTx {
    const tx = this.txs.get(txHash.toLowerCase());
    if (!tx) throw new InvalidChainArgumentError("unknown transaction hash", { txHash });
    return tx;
  }

  /** Deterministic and collision-free — no hashing, so no ethers. */
  private nextTxHash(): string {
    return `0x${(++this.txCount).toString(16).padStart(64, "0")}`;
  }
}
