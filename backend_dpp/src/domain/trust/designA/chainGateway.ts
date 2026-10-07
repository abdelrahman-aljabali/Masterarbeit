import {
  FetchRequest,
  Interface,
  JsonRpcProvider,
  Network,
  Transaction,
  TypedDataEncoder,
  Wallet,
  isError,
  recoverAddress,
  zeroPadValue,
  type Result,
} from "ethers";
import { config } from "../../../config.js";
import { getRedis } from "../../../cache/redis.js";
import { logger } from "../../../observability/logger.js";
import {
  asAddress,
  asBytes32,
  asUint,
  buildDidDocument,
  ChainCallRevertedError,
  ChainGatewayError,
  ChainMisconfiguredError,
  ChainUnavailableError,
  eip712Message,
  EIP712_DOMAIN_NAME,
  EIP712_DOMAIN_VERSION,
  EIP712_PRIMARY_TYPE,
  EIP712_TYPES,
  latestAnchor,
  networkMatchesChain,
  normalizeSignedCall,
  parseDidEthr,
  RelayerMayNotAuthorizeError,
  signedCallSummary,
  ZERO_ADDRESS,
  type Address,
  type AnchorHint,
  type AnchorLookup,
  type AnchorRecord,
  type Bytes32,
  type DidDocument,
  type ProductId,
  type SignedCall,
  type TxStatus,
} from "./chainTypes.js";

export type {
  Address,
  AnchorHint,
  AnchorLookup,
  AnchorRecord,
  Bytes32,
  DidDocument,
  ProductId,
  SignedCall,
  TxStatus,
} from "./chainTypes.js";
export {
  ChainCallRevertedError,
  ChainGatewayError,
  ChainMisconfiguredError,
  ChainUnavailableError,
  InvalidChainArgumentError,
  RelayerMayNotAuthorizeError,
  anchorPresence,
  formatDidEthr,
  parseDidEthr,
} from "./chainTypes.js";

/**
 * ─── ChainGateway — the ONLY file in this codebase that imports `ethers` ──────
 * Design A's entire chain surface is these six methods. ESLint forbids `ethers`
 * (and `viem`, `web3`, `@web3auth/*`, `jose`, `did-jwt*`, `ethr-did*`) anywhere
 * outside `domain/trust/designA/`, and inside that folder the one-importer rule
 * is this file. That buys three things the thesis actually needs:
 */
export interface ChainGateway {
  /**
   * Resolve a `did:ethr` against the ERC-1056 registry. `null` means "not a DID
   * this gateway serves" (malformed, pubkey-form, or another chain) — never
   * "the chain was unreachable", which throws.
   */
  resolveDidDocument(did: string): Promise<DidDocument | null>;

  /**
   * `authorized[productId][issuer]` — verbatim. The product's controller is NOT
   * implicitly authorized here, because it is not implicitly authorized
   * on-chain; whether a controller may issue for its own product is a policy
   * question for the provider, and answering it here would put policy in the
   * transport.
   */
  isAuthorized(productId: ProductId, issuer: Address): Promise<boolean>;

  /** `productController[productId]`, or `null` for an unclaimed product. */
  productController(productId: ProductId): Promise<Address | null>;

  /**
   * Search for the latest `Anchored` log for this `(productId, version)`.
   */
  findAnchor(productId: ProductId, version: number | bigint, hint?: AnchorHint): Promise<AnchorLookup>;

  /** `nonces[signer]` — the next nonce the contract will accept from this key. */
  nonceOf(signer: Address): Promise<bigint>;

  /** Forward a pre-signed EIP-712 payload, paying gas. Returns the recovered signer. */
  submitSignedCall(call: SignedCall): Promise<{ txHash: string; signer: Address }>;

  /** Where a submitted transaction got to. */
  txStatus(txHash: string): Promise<TxStatus>;
}

// ── ABIs ─────────────────────────────────────────────────────────────────────
// Hand-written minimal fragments rather than generated artifacts: the backend
// consumes `contracts/deployments/<network>.json` for ADDRESSES and nothing
// else (deployments/README.md), so importing `contracts/out/**` here would
// create exactly the build-artifact dependency that directory exists to
// prevent. These fragments are a transcription of the two contracts' public
// surface; anything mistyped fails loudly at the first call, not silently.

const ANCHOR_REGISTRY_ABI = [
  "function productController(bytes32 productId) view returns (address)",
  "function authorized(bytes32 productId, address issuer) view returns (bool)",
  "function nonces(address signer) view returns (uint256)",
  "function claimProduct(bytes32 productId, address controller, uint256 nonce, bytes sig)",
  "function setIssuer(bytes32 productId, address issuer, bool ok, uint256 nonce, bytes sig)",
  "function setIssuers(bytes32 productId, address[] issuers, bool ok, uint256 nonce, bytes sig)",
  "function anchor(bytes32 productId, bytes32 merkleRoot, uint64 version, uint256 nonce, bytes sig)",
  "event Anchored(bytes32 indexed productId, bytes32 merkleRoot, uint64 version, address indexed by)",
  "event IssuerAuthorized(bytes32 indexed productId, address indexed issuer, bool allowed)",
  "event ProductClaimed(bytes32 indexed productId, address indexed controller, address indexed previous)",
  // Custom errors — listed so a revert decodes to its NAME instead of a hex blob.
  "error InvalidNonce(address signer, uint256 expected, uint256 provided)",
  "error ClaimMustBeSelfSigned(bytes32 productId, address signer, address controller)",
  "error NotController(bytes32 productId, address signer, address controller)",
  "error ZeroController(bytes32 productId)",
  "error ZeroProductId()",
  "error ZeroIssuer()",
  "error EmptyIssuerSet()",
  "error ZeroMerkleRoot()",
] as const;

const DID_REGISTRY_ABI = [
  "function owners(address identity) view returns (address)",
  "function changed(address identity) view returns (uint256)",
  "function identityOwner(address identity) view returns (address)",
  "event DIDOwnerChanged(address indexed identity, address owner, uint256 previousChange)",
  "event DIDDelegateChanged(address indexed identity, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange)",
  "event DIDAttributeChanged(address indexed identity, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)",
] as const;

// ── Options ──────────────────────────────────────────────────────────────────

export interface ChainGatewayOptions {
  rpcUrl: string;
  rpcUrlFallback: string;
  chainId: number;
  chainName: string;
  didRegistryAddress: string;
  anchorRegistryAddress: string;
  relayerPrivateKey: string;
  /** Per-request HTTP timeout. A hung endpoint must become a failover, not a hang. */
  timeoutMs?: number;
  /** `isAuthorized` cache lifetime. 0 disables caching entirely. */
  authCacheTtlMs?: number;
  /**
   * The oldest block an anchor search will look at — the FLOOR of the backwards
   * sweep, and the block below which "absent" becomes a sound claim.
   */
  anchorsFromBlock?: number;
  /**
   * Blocks per `eth_getLogs` when sweeping. Shrinks automatically (÷4) when an
   * endpoint refuses the range, so this is an optimistic starting width, not a
   * promise; 2000 is what an unthrottled endpoint answers happily.
   */
  anchorLogWindow?: number;
  /**
   * RPC budget for ONE anchor search. Bounds the cost of a sweep on an endpoint
   * that caps ranges at single digits; exceeding it yields `complete: false`
   * (inconclusive), never a fabricated "absent".
   */
  anchorScanMaxRequests?: number;
  /** Max `previousChange` hops when walking an identity's ERC-1056 history. */
  maxChangeLogHops?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_AUTH_TTL_MS = 60_000;
const DEFAULT_MAX_HOPS = 64;
const DEFAULT_ANCHOR_LOG_WINDOW = 2_000;
/**
 * 200 requests ≈ 20 s against a 10-block-capped endpoint. Chosen as the point
 * where a hint-less sweep stops being an API read and starts being a batch job:
 * a caller that hits it gets `inconclusive` and the honest advice to supply the
 * transaction hint (which the platform records for every anchor it relays) or to
 * point the stack at an endpoint without a range cap.
 */
const DEFAULT_ANCHOR_SCAN_MAX_REQUESTS = 200;

/**
 * Two endpoint refusals that look alike in a message string and must be handled
 * OPPOSITELY (the lesson is `scripts/verify-passport.mjs`'s, learned against
 * real endpoints):
 */
const RANGE_ERROR = /block range|range should|up to a \d+ block|query returned more than|too many results|exceeds? .{0,20}block|logs matched/i;
const RATE_ERROR = /rate limit|compute unit|throughput|capacity|too many requests|429|slow down|exceeded.*(second|quota)/i;

/**
 * Endpoints that cap ranges usually SAY what they would accept ("up to a 10
 * block range", "max 1000 blocks"). Believing them — as an upper bound only — is
 * worth about 40 % of the sweep's coverage: blind ÷4 halving from 2000 lands on
 * 7 against Alchemy's limit of 10, so every request thereafter buys three fewer
 * blocks than the endpoint was willing to serve, forever.
 */
const RANGE_SUGGESTION = /up to (?:a )?(\d+) block|max(?:imum)?(?: of)? (\d+) blocks?|(\d+) block range/i;

function suggestedWindow(reason: string): number | null {
  const m = RANGE_SUGGESTION.exec(reason);
  if (!m) return null;
  const value = Number(m[1] ?? m[2] ?? m[3]);
  return Number.isInteger(value) && value > 0 ? value : null;
}

interface Endpoint {
  /** "primary" | "fallback". The URL is NEVER logged: RPC URLs carry API keys. */
  label: string;
  provider: JsonRpcProvider;
  verified: boolean;
}

// ── isAuthorized cache ───────────────────────────────────────────────────────

/**
 * A 60-second memo over `authorized[productId][issuer]`.
 */
class AuthorizationCache {
  private readonly local = new Map<string, { value: boolean; expiresAt: number }>();
  private static readonly LOCAL_MAX = 5_000;

  constructor(
    private readonly ttlMs: number,
    private readonly prefix: string,
  ) {}

  async get(key: string): Promise<boolean | null> {
    if (this.ttlMs <= 0) return null;
    const redis = this.redis();
    if (redis) {
      try {
        const hit = await redis.get(this.prefix + key);
        return hit === "1" ? true : hit === "0" ? false : null;
      } catch (err) {
        // A cache that cannot be read is a cache miss. It must never be able to
        // make a chain read fail, and it must never invent an answer.
        logger.warn({ err }, "designA: authorization cache read failed — falling through to chain");
        return null;
      }
    }
    const hit = this.local.get(key);
    if (!hit) return null;
    if (hit.expiresAt <= Date.now()) {
      this.local.delete(key);
      return null;
    }
    return hit.value;
  }

  async set(key: string, value: boolean): Promise<void> {
    if (this.ttlMs <= 0) return;
    const redis = this.redis();
    if (redis) {
      try {
        await redis.set(this.prefix + key, value ? "1" : "0", "PX", this.ttlMs);
      } catch (err) {
        logger.warn({ err }, "designA: authorization cache write failed");
      }
      return;
    }
    if (this.local.size >= AuthorizationCache.LOCAL_MAX) this.prune();
    this.local.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  /**
   * Drop an entry. Called the moment a `setIssuer` is FORWARDED, not when it
   * confirms: invalidation can only ever cause an extra chain read, so doing it
   * early is free, while doing it late would keep answering with the world as it
   * was before the actor changed it.
   */
  async invalidate(key: string): Promise<void> {
    this.local.delete(key);
    const redis = this.redis();
    if (!redis) return;
    try {
      await redis.del(this.prefix + key);
    } catch (err) {
      logger.warn({ err }, "designA: authorization cache invalidation failed");
    }
  }

  private redis() {
    return this.ttlMs > 0 ? getRedis() : null;
  }

  private prune(): void {
    const now = Date.now();
    for (const [k, v] of this.local) if (v.expiresAt <= now) this.local.delete(k);
    // Still full of live entries: evict oldest-inserted (Map keeps insertion order).
    let excess = this.local.size - AuthorizationCache.LOCAL_MAX + 1;
    if (excess <= 0) return;
    for (const k of this.local.keys()) {
      this.local.delete(k);
      if (--excess <= 0) break;
    }
  }
}

// ── The implementation ───────────────────────────────────────────────────────

export class EthersChainGateway implements ChainGateway {
  private readonly endpoints: Endpoint[];
  private readonly anchorIface = new Interface(ANCHOR_REGISTRY_ABI as unknown as string[]);
  private readonly didIface = new Interface(DID_REGISTRY_ABI as unknown as string[]);
  private readonly anchorAddress: Address;
  private readonly didAddress: Address;
  private readonly chainId: number;
  private readonly chainName: string;
  private readonly anchorsFromBlock: number;
  private readonly anchorLogWindow: number;
  private readonly anchorScanMaxRequests: number;
  private readonly maxChangeLogHops: number;
  private readonly authCache: AuthorizationCache;

  /**
   * The relayer. PRIVATE and never returned: it signs transaction ENVELOPES
   * (gas), never EIP-712 payloads (authority). Constructed without a provider
   * and connected per broadcast, so a failover cannot leave it bound to a dead
   * endpoint.
   */
  private readonly relayer: Wallet;

  /** Public so ops can fund/monitor it. Authority-free by construction. */
  readonly relayerAddress: Address;

  constructor(opts: ChainGatewayOptions) {
    this.chainId = opts.chainId;
    this.chainName = opts.chainName;
    this.anchorAddress = asAddress(opts.anchorRegistryAddress, "anchorRegistryAddress");
    this.didAddress = asAddress(opts.didRegistryAddress, "didRegistryAddress");
    this.anchorsFromBlock = Math.max(0, Math.floor(opts.anchorsFromBlock ?? 0));
    this.anchorLogWindow = Math.max(1, Math.floor(opts.anchorLogWindow ?? DEFAULT_ANCHOR_LOG_WINDOW));
    this.anchorScanMaxRequests = Math.max(1, Math.floor(opts.anchorScanMaxRequests ?? DEFAULT_ANCHOR_SCAN_MAX_REQUESTS));
    this.maxChangeLogHops = opts.maxChangeLogHops ?? DEFAULT_MAX_HOPS;
    if (this.anchorAddress === this.didAddress) {
      throw new ChainMisconfiguredError(
        "DID_REGISTRY_ADDRESS and ANCHOR_REGISTRY_ADDRESS are the same address — one of them is wrong " +
          "(they are two different contracts; pin both from contracts/deployments/<network>.json).",
      );
    }

    const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.endpoints = [
      { label: "primary", provider: this.makeProvider(opts.rpcUrl, timeout), verified: false },
      { label: "fallback", provider: this.makeProvider(opts.rpcUrlFallback, timeout), verified: false },
    ];

    try {
      this.relayer = new Wallet(opts.relayerPrivateKey);
    } catch {
      // Never echo the key, not even a prefix of it.
      throw new ChainMisconfiguredError("RELAYER_PRIVATE_KEY is not a valid secp256k1 private key");
    }
    this.relayerAddress = this.relayer.address.toLowerCase();

    this.authCache = new AuthorizationCache(
      opts.authCacheTtlMs ?? DEFAULT_AUTH_TTL_MS,
      `da:auth:${this.chainId}:${this.anchorAddress}:`,
    );
  }

  private makeProvider(url: string, timeoutMs: number): JsonRpcProvider {
    const request = new FetchRequest(url);
    // ethers aborts the underlying fetch on timeout, so a hung endpoint becomes
    // a failover instead of a stuck request holding a socket open.
    request.timeout = timeoutMs;
    return new JsonRpcProvider(request, Network.from(this.chainId), {
      // We verify the chain id ourselves (see `verifyChain`), once, loudly.
      staticNetwork: true,
      // Public Amoy endpoints are inconsistent about JSON-RPC batching; one
      // request per call costs a round trip and removes a whole class of
      // "works on Alchemy, 400s on the fallback" failure.
      batchMaxCount: 1,
    });
  }

  // ── Reads ──────────────────────────────────────────────────────────────────

  async resolveDidDocument(did: string): Promise<DidDocument | null> {
    const parsed = parseDidEthr(did);
    if (!parsed) return null;
    if (!networkMatchesChain(parsed.network, this.chainId, this.chainName)) return null;

    const identity = parsed.address;
    // Both reads in ONE failover attempt: mixing an `owners` from the primary
    // with a `changed` from the fallback would be reading two moments in time.
    const [ownerSlot, changedAt] = await this.read("resolveDidDocument", async (p) => {
      const owner = await this.view(p, this.didIface, this.didAddress, "owners", [identity], (r) =>
        asAddress(r[0] as string, "owner"),
      );
      const changed = await this.view(p, this.didIface, this.didAddress, "changed", [identity], (r) =>
        asUint(r[0] as bigint, "changed"),
      );
      return [owner, changed] as const;
    });

    let owner: Address;
    if (changedAt === 0n) {
      // The address-derived DEFAULT document: no registry event has ever touched
      // this identity, and it still resolves — the key IS the identifier.
      owner = identity;
    } else if (ownerSlot !== ZERO_ADDRESS) {
      // Owner was rotated at least once and the latest value is non-zero, so it
      // is the current controller and the DID is not deactivated.
      owner = ownerSlot;
    } else {
      // `owners[identity] == 0` with history is AMBIGUOUS, and this is the case
      // `identityOwner()` cannot see: the ERC-1056 getter answers `identity`
      // whenever the slot is zero, so a DID deactivated by
      // `changeOwner(identity, 0x0)` would read back as a perfectly healthy
      // default document — a revoked identity that still verifies. Only the
      // event log distinguishes "deactivated" from "only delegates/attributes
      // ever changed", so we walk it.
      owner = await this.resolveOwnerFromChangeLog(identity, changedAt);
    }

    return buildDidDocument({ did, owner, chainId: this.chainId });
  }

  /**
   * Walk `previousChange` backwards until a `DIDOwnerChanged` appears.
   */
  private async resolveOwnerFromChangeLog(identity: Address, changedAt: bigint): Promise<Address> {
    const identityTopic = zeroPadValue(identity, 32);
    return this.read("resolveDidDocument:changeLog", async (p) => {
      let block = Number(changedAt);
      for (let hop = 0; hop < this.maxChangeLogHops; hop++) {
        const logs = await p.getLogs({
          address: this.didAddress,
          // topic0 unconstrained: all three ERC-1056 events carry `identity` as
          // topic1, and we need whichever of them is the newest.
          topics: [null, identityTopic],
          fromBlock: block,
          toBlock: block,
        });

        let ownerAtBlock: string | null = null;
        let previous = 0;
        for (const log of logs) {
          const event = this.didIface.parseLog({ topics: [...log.topics], data: log.data });
          if (!event) continue;
          // Only the FIRST event in a block carries the true predecessor block:
          // the contract emits `changed[identity]` and then overwrites it with
          // `block.number`, so later events in the same block point at
          // themselves. Take the smallest value strictly below this block.
          const prev = Number(event.args.previousChange as bigint);
          if (prev > 0 && prev < block && (previous === 0 || prev < previous)) previous = prev;
          // Ascending log order: the last owner change in the block wins.
          if (event.name === "DIDOwnerChanged") ownerAtBlock = String(event.args.owner);
        }

        if (ownerAtBlock !== null) return asAddress(ownerAtBlock, "owner");
        if (previous === 0) return identity; // Start of history, owner never changed.
        block = previous;
      }
      throw new ChainUnavailableError(
        "did:ethr change log is longer than the configured hop limit — refusing to guess the current owner",
        { identity, hops: this.maxChangeLogHops },
      );
    });
  }

  /**
   * ⚠ Read this method as a security control, not a lookup.
   */
  async isAuthorized(productId: ProductId, issuer: Address): Promise<boolean> {
    const id = asBytes32(productId, "productId");
    const addr = asAddress(issuer, "issuer");
    const key = `${id}:${addr}`;

    const cached = await this.authCache.get(key);
    if (cached !== null) return cached;

    const allowed = await this.read("isAuthorized", (p) =>
      this.view(p, this.anchorIface, this.anchorAddress, "authorized", [id, addr], (r) => r[0] === true),
    );
    await this.authCache.set(key, allowed);
    return allowed;
  }

  async productController(productId: ProductId): Promise<Address | null> {
    const id = asBytes32(productId, "productId");
    const controller = await this.read("productController", (p) =>
      this.view(p, this.anchorIface, this.anchorAddress, "productController", [id], (r) =>
        asAddress(r[0] as string, "controller"),
      ),
    );
    // address(0) is the contract's "unclaimed", a real answer from a healthy
    // chain — hence `null`, which is NOT what an unreachable chain returns.
    return controller === ZERO_ADDRESS ? null : controller;
  }

  async nonceOf(signer: Address): Promise<bigint> {
    const addr = asAddress(signer, "signer");
    return this.read("nonceOf", (p) =>
      this.view(p, this.anchorIface, this.anchorAddress, "nonces", [addr], (r) => asUint(r[0] as bigint, "nonce")),
    );
  }

  /**
   * ─── Anchors live in LOGS, and logs are rationed ───────────────────────────
   * The contract has no `anchors` mapping (an event is roughly an order of
   * magnitude cheaper per publish), so the only way to read an anchor is
   * `eth_getLogs` on the indexed `productId`, with `version` filtered client side
   * because it sits in the data, not the topics.
   */
  async findAnchor(productId: ProductId, version: number | bigint, hint: AnchorHint = {}): Promise<AnchorLookup> {
    const id = asBytes32(productId, "productId");
    const wanted = asUint(version, "version");

    if (hint.txHash && TX_HASH_RE.test(hint.txHash)) {
      const found = await this.anchorFromReceipt(hint.txHash.toLowerCase(), id, wanted);
      if (found) {
        return {
          anchor: found,
          complete: true,
          scannedFrom: found.blockNumber,
          scannedTo: found.blockNumber,
          requests: 1,
          window: 1,
          capped: false,
          via: "receipt",
        };
      }
      // A hint that names no matching log is a WRONG HINT, not an absent anchor:
      // a re-anchor, a replaced transaction or a stale row all look like this.
      // Fall through to the search that needs no hint.
      logger.debug({ productId: id, version: wanted.toString() }, "designA: anchor hint did not match — sweeping logs");
    }

    return this.scanForAnchor(id, wanted);
  }

  /** The hinted fast path: one receipt, every property re-derived from its logs. */
  private async anchorFromReceipt(txHash: string, id: ProductId, wanted: bigint): Promise<AnchorRecord | null> {
    return this.read("findAnchor:receipt", async (p) => {
      const receipt = await p.getTransactionReceipt(txHash);
      if (!receipt) return null;
      const matches: AnchorRecord[] = [];
      for (const log of receipt.logs) {
        // The address filter is not a formality: a hostile hint could name a
        // transaction whose logs come from an impostor contract emitting the
        // same event shape. Only OUR registry's logs are anchors.
        if (log.address.toLowerCase() !== this.anchorAddress) continue;
        const record = this.decodeAnchorLog(log, id, wanted);
        if (record) matches.push(record);
      }
      return latestAnchor(matches);
    });
  }

  /** The hint-less sweep. Whole scan inside ONE `read`, so the answer and its
   *  coverage claim come from a single endpoint's view of the chain. */
  private async scanForAnchor(id: ProductId, wanted: bigint): Promise<AnchorLookup> {
    const topic0 = this.anchorIface.getEvent("Anchored")!.topicHash;

    return this.read("findAnchor", async (p) => {
      const head = await p.getBlockNumber();
      const floor = Math.min(this.anchorsFromBlock, head);
      const matches: AnchorRecord[] = [];
      let window = this.anchorLogWindow;
      let hi = head;
      let requests = 1; // the head read
      let capped = false;

      while (hi >= floor) {
        if (requests >= this.anchorScanMaxRequests) {
          // Everything above `hi` was read and held no anchor; everything below
          // is UNREAD. Reporting the boundary is what keeps this honest.
          return { anchor: null, complete: false, scannedFrom: hi + 1, scannedTo: head, requests, window, capped, via: "log-scan" };
        }
        const lo = Math.max(floor, hi - window + 1);
        let logs;
        try {
          requests++;
          logs = await p.getLogs({ address: this.anchorAddress, topics: [topic0, id], fromBlock: lo, toBlock: hi });
        } catch (err) {
          const reason = rpcFailureReason(err);
          // Order matters: a rate limit that reads as a range refusal would send
          // us into ever-narrower requests against an endpoint asking for fewer.
          if (!RATE_ERROR.test(reason) && RANGE_ERROR.test(reason) && window > 1) {
            // Take the endpoint's own number when it named one, otherwise ÷4.
            // Clamped to a STRICT decrease either way, which is what guarantees
            // this loop terminates: every iteration either makes progress down
            // the chain or makes the window smaller, and the window bottoms out
            // at 1 where no cap can refuse it.
            const suggested = suggestedWindow(reason);
            window = suggested !== null && suggested < window ? suggested : Math.max(1, Math.floor(window / 4));
            capped = true;
            logger.debug({ window, reason }, "designA: endpoint capped the log range — narrowing");
            continue;
          }
          throw err; // transport → `read` fails over, then throws ChainUnavailableError
        }

        for (const log of logs) {
          const record = this.decodeAnchorLog(log, id, wanted);
          if (record) matches.push(record);
        }
        if (matches.length > 0) {
          // Backwards: the first window containing a match holds the newest one,
          // so there is nothing older worth paying for.
          return { anchor: latestAnchor(matches), complete: true, scannedFrom: lo, scannedTo: head, requests, window, capped, via: "log-scan" };
        }
        hi = lo - 1;
      }
      return { anchor: null, complete: true, scannedFrom: floor, scannedTo: head, requests, window, capped, via: "log-scan" };
    });
  }

  /** One log → an `AnchorRecord`, or null if it is not an `Anchored` for this
   *  `(productId, version)`. The single definition of "matching", shared by the
   *  receipt path and the sweep so the two cannot disagree. */
  private decodeAnchorLog(
    log: { topics: readonly string[]; data: string; transactionHash: string; blockNumber: number; index: number },
    id: ProductId,
    wanted: bigint,
  ): AnchorRecord | null {
    const event = this.anchorIface.parseLog({ topics: [...log.topics], data: log.data });
    if (!event || event.name !== "Anchored") return null;
    if (asBytes32(event.args.productId as string, "productId") !== id) return null;
    if (asUint(event.args.version as bigint, "version") !== wanted) return null;
    return {
      productId: id,
      merkleRoot: asBytes32(event.args.merkleRoot as string, "merkleRoot"),
      version: wanted,
      by: asAddress(event.args.by as string, "by"),
      txHash: log.transactionHash,
      blockNumber: log.blockNumber,
      logIndex: log.index,
      occurrences: 1,
    };
  }

  // ── Writes: forwarding, never authoring ────────────────────────────────────

  /**
   * Forward a pre-signed EIP-712 payload and pay its gas.
   */
  async submitSignedCall(call: SignedCall): Promise<{ txHash: string; signer: Address }> {
    const normalized = normalizeSignedCall(call);
    const signer = this.recoverSigner(normalized);

    if (signer === this.relayerAddress) {
      throw new RelayerMayNotAuthorizeError(
        "Refusing to submit a payload whose recovered signer is the relayer. The relayer pays gas and " +
          "holds no authority; a payload it signed would make the platform the authority.",
        signedCallSummary(normalized),
      );
    }

    const data = this.encodeCall(normalized);
    const raw = await this.signTransaction(data);
    const txHash = Transaction.from(raw).hash!;
    await this.broadcast(raw, txHash, normalized);

    if (normalized.kind === "setIssuer") {
      // The authorization the world is about to see changed. Drop the memo now.
      await this.authCache.invalidate(`${normalized.productId}:${normalized.issuer}`);
    }
    if (normalized.kind === "setIssuers") {
      // EVERY issuer in the batch, not just the first: a stale memo for one of
      // them would report "not authorized" for a grant already in flight, which
      // is the exact confusion the single-issuer invalidation exists to prevent.
      await Promise.all(
        normalized.issuers.map((issuer) => this.authCache.invalidate(`${normalized.productId}:${issuer}`)),
      );
    }
    logger.info({ ...signedCallSummary(normalized), txHash, signer }, "designA: forwarded pre-signed call");
    return { txHash, signer };
  }

  /**
   * Recover the payload signer locally, from the same typed data the contract
   * hashes. Two jobs: it is the relayer check's evidence, and it kills a
   * malformed or misdomained signature before it costs gas — the contract would
   * revert on it anyway, and this way the caller learns why in one round trip
   * instead of via `ECDSAInvalidSignature`.
   */
  private recoverSigner(call: SignedCall): Address {
    const domain = {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: this.chainId,
      verifyingContract: this.anchorAddress,
    };
    const types = { [EIP712_PRIMARY_TYPE[call.kind]]: EIP712_TYPES[call.kind] };
    let digest: string;
    try {
      digest = TypedDataEncoder.hash(domain, types, eip712Message(call));
    } catch (err) {
      throw new ChainCallRevertedError("could not build the EIP-712 digest for this call", null, {
        ...signedCallSummary(call),
        cause: describeError(err),
      });
    }
    try {
      return recoverAddress(digest, call.signature).toLowerCase();
    } catch (err) {
      // ECDSA.recover in the contract reverts rather than returning address(0);
      // refusing here keeps the same shape and saves the gas.
      throw new ChainCallRevertedError("signature does not recover to any address", "ECDSAInvalidSignature", {
        ...signedCallSummary(call),
        cause: describeError(err),
      });
    }
  }

  private encodeCall(call: SignedCall): string {
    switch (call.kind) {
      case "claimProduct":
        return this.anchorIface.encodeFunctionData("claimProduct", [
          call.productId,
          call.controller,
          call.nonce,
          call.signature,
        ]);
      case "setIssuer":
        return this.anchorIface.encodeFunctionData("setIssuer", [
          call.productId,
          call.issuer,
          call.allowed,
          call.nonce,
          call.signature,
        ]);
      case "setIssuers":
        return this.anchorIface.encodeFunctionData("setIssuers", [
          call.productId,
          // Spread: ethers mutates nothing, but `readonly Address[]` is not
          // assignable to its parameter type and a cast would hide that.
          [...call.issuers],
          call.allowed,
          call.nonce,
          call.signature,
        ]);
      case "anchor":
        return this.anchorIface.encodeFunctionData("anchor", [
          call.productId,
          call.merkleRoot,
          call.version,
          call.nonce,
          call.signature,
        ]);
    }
  }

  /** Populate (nonce, fees, gas — the estimate is also the revert check) and sign. */
  private async signTransaction(data: string): Promise<string> {
    const populated = await this.read("submitSignedCall:populate", async (p) => {
      const connected = this.relayer.connect(p);
      return connected.populateTransaction({ to: this.anchorAddress, data, chainId: this.chainId });
    });
    // `from` is implied by the signature; leaving it in makes ethers reject the
    // unsigned transaction it is about to sign.
    delete (populated as { from?: unknown }).from;
    return this.relayer.signTransaction(populated);
  }

  private async broadcast(raw: string, txHash: string, call: SignedCall): Promise<void> {
    const attempts: { endpoint: string; error: string }[] = [];
    for (const endpoint of this.endpoints) {
      try {
        await this.verifyChain(endpoint);
        const sent = await endpoint.provider.broadcastTransaction(raw);
        if (sent.hash.toLowerCase() !== txHash.toLowerCase()) {
          throw new ChainMisconfiguredError("endpoint returned a different transaction hash than we signed", {
            expected: txHash,
            returned: sent.hash,
          });
        }
        return;
      } catch (err) {
        if (err instanceof ChainGatewayError && !(err instanceof ChainUnavailableError)) throw err;
        // The same raw transaction on a second endpoint is the SAME transaction,
        // so a node that already has it is a success, not a failure.
        if (isAlreadyKnown(err)) return;
        const reverted = this.asRevert(err, "submitSignedCall");
        if (reverted) throw reverted;
        attempts.push({ endpoint: endpoint.label, error: describeError(err) });
        logger.warn({ endpoint: endpoint.label, err }, "designA: broadcast failed, trying next endpoint");
      }
    }
    throw new ChainUnavailableError("no RPC endpoint accepted the transaction", {
      ...signedCallSummary(call),
      txHash,
      attempts,
    });
  }

  async txStatus(txHash: string): Promise<TxStatus> {
    if (!TX_HASH_RE.test(txHash)) {
      throw new ChainCallRevertedError("txHash must be a 0x-prefixed 32-byte hash", null, { txHash });
    }
    return this.read("txStatus", async (p) => {
      const receipt = await p.getTransactionReceipt(txHash);
      if (receipt) {
        return receipt.status === 1
          ? { status: "confirmed" as const, blockNumber: receipt.blockNumber }
          : { status: "failed" as const, blockNumber: receipt.blockNumber };
      }
      const tx = await p.getTransaction(txHash);
      // No receipt but the node knows it → queued. Nothing at all → the node has
      // never seen it: dropped, replaced, or never broadcast. See `TxState`.
      return { status: tx ? ("pending" as const) : ("unknown" as const) };
    });
  }

  // ── Transport ──────────────────────────────────────────────────────────────

  /**
   * Run a read against the primary, then the fallback, then give up LOUDLY.
   */
  private async read<T>(op: string, fn: (p: JsonRpcProvider) => Promise<T>): Promise<T> {
    const attempts: { endpoint: string; error: string }[] = [];
    for (const endpoint of this.endpoints) {
      try {
        await this.verifyChain(endpoint);
        return await fn(endpoint.provider);
      } catch (err) {
        if (err instanceof ChainGatewayError && !(err instanceof ChainUnavailableError)) throw err;
        const reverted = this.asRevert(err, op);
        if (reverted) throw reverted;
        attempts.push({ endpoint: endpoint.label, error: describeError(err) });
        logger.warn({ op, endpoint: endpoint.label, err }, "designA: RPC endpoint failed, trying next");
      }
    }
    throw new ChainUnavailableError(`${op}: no RPC endpoint could answer`, { op, attempts });
  }

  /**
   * Confirm, once per endpoint, that it serves the chain we were configured for.
   */
  private async verifyChain(endpoint: Endpoint): Promise<void> {
    if (endpoint.verified) return;
    let reported: bigint;
    try {
      const raw: unknown = await endpoint.provider.send("eth_chainId", []);
      reported = BigInt(raw as string);
    } catch (err) {
      throw new ChainUnavailableError(`${endpoint.label} endpoint did not answer eth_chainId`, {
        endpoint: endpoint.label,
        error: describeError(err),
      });
    }
    if (reported !== BigInt(this.chainId)) {
      throw new ChainMisconfiguredError(
        `${endpoint.label} RPC endpoint serves chain ${reported.toString()}, but this stack is configured ` +
          `for ${this.chainId}. Refusing to read or write — every DID and EIP-712 signature is bound to the chain id.`,
        { endpoint: endpoint.label, reported: reported.toString(), expected: this.chainId },
      );
    }
    endpoint.verified = true;
  }

  private async view<T>(
    provider: JsonRpcProvider,
    iface: Interface,
    address: Address,
    fn: string,
    args: unknown[],
    pick: (result: Result) => T,
  ): Promise<T> {
    const data = iface.encodeFunctionData(fn, args);
    const returned = await provider.call({ to: address, data });
    return pick(iface.decodeFunctionResult(fn, returned));
  }

  /** An ethers CALL_EXCEPTION is the chain's own "no" — decode it, never retry it. */
  private asRevert(err: unknown, op: string): ChainCallRevertedError | null {
    if (!isError(err, "CALL_EXCEPTION")) return null;
    let name: string | null = err.reason ?? null;
    let args: string[] = [];
    if (typeof err.data === "string" && err.data.length > 2) {
      const parsed = this.anchorIface.parseError(err.data);
      if (parsed) {
        name = parsed.name;
        args = parsed.args.map((a) => String(a));
      }
    }
    return new ChainCallRevertedError(`${op} reverted${name ? `: ${name}` : ""}`, name, { op, args });
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * Strip anything URL-shaped. RPC endpoints carry API keys in their path or
 * subdomain, and this is not theoretical: ethers' `assertOk()` puts
 * `info.requestUrl` — the FULL endpoint including the key — into `error.message`
 * for every non-2xx response, so `${err.name}:
 */
function redactUrls(text: string): string {
  return text.replace(/\b(?:https?|wss?):\/\/\S+/gi, "[endpoint redacted]");
}

/** Never includes a URL: RPC endpoints carry API keys in their path or subdomain. */
function describeError(err: unknown): string {
  const raw = err instanceof Error ? `${err.name}: ${rpcFailureReason(err)}` : String(err);
  return redactUrls(raw).slice(0, 300);
}

/**
 * Everything an endpoint said about a failure, in one string safe to match and
 * to log.
 */
function rpcFailureReason(err: unknown): string {
  const e = err as { shortMessage?: unknown; message?: unknown; info?: { error?: { message?: unknown }; responseBody?: unknown }; error?: { message?: unknown } };
  const parts: string[] = [];
  const push = (value: unknown) => {
    if (typeof value === "string" && value.length > 0) parts.push(value.slice(0, 400));
  };
  push(e?.shortMessage ?? e?.message);
  push(e?.info?.error?.message);
  push(e?.error?.message);
  push(e?.info?.responseBody);
  return redactUrls(parts.join(" | "));
}

function isAlreadyKnown(err: unknown): boolean {
  const message = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    message.includes("already known") ||
    message.includes("already exists") ||
    message.includes("transaction underpriced") ||
    message.includes("nonce too low")
  );
}

/**
 * Build the gateway from `config.designA`, which is fail-closed at boot (no
 * defaults, throws naming the missing variable). Reading `process.env` here
 * would re-open the hole that block exists to close.
 */
export function createChainGateway(overrides: Partial<ChainGatewayOptions> = {}): EthersChainGateway {
  const a = config.designA;
  if (!a) {
    throw new ChainMisconfiguredError(
      "config.designA is null — the chain gateway is only constructible under TRUST_MODE=design-a.",
    );
  }
  return new EthersChainGateway({
    rpcUrl: a.rpcUrl,
    rpcUrlFallback: a.rpcUrlFallback,
    chainId: a.chainId,
    chainName: a.chainName,
    didRegistryAddress: a.didRegistryAddress,
    anchorRegistryAddress: a.anchorRegistryAddress,
    relayerPrivateKey: a.relayerPrivateKey,
    // The registry's deployment block. Nothing can be anchored before the
    // contract existed, so this is the floor below which "no anchor" is a sound
    // claim rather than an unread range — and it is what makes a full sweep
    // finite (84 k blocks on Amoy today) instead of a walk back to genesis.
    anchorsFromBlock: a.anchorRegistryBlock,
    ...overrides,
  });
}
