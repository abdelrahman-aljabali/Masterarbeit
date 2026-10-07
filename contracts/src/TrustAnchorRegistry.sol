// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title  TrustAnchorRegistry
/// @notice Authorization root and anchor log for TrustDPP "Design A" digital product passports.
///
/// @dev ## What this contract answers
///
/// 1. *Was this issuer authorized by the product's controller to make claims about this product?*
///    -> `productController` + `authorized`.
/// 2. *Did this exact set of credentials exist at this block?*
///    -> the `Anchored` event log (a Merkle root per passport version).
///
/// ## THE BINDING RULE: `msg.sender` IS NEVER AUTHORIZATION
///
/// Every state transition in this contract is authorized by an EIP-712 payload signature
/// recovered with `ecrecover`. `msg.sender` is never read, never compared, never stored and
/// never emitted. There is no `onlyOwner`, no admin, no proxy and no upgrade path.
///
/// The reason is load-bearing for the architecture: the TrustDPP platform runs a funded
/// *relayer* that submits every transaction so that attesting organizations never need to hold
/// MATIC. Therefore `msg.sender` is *always* the platform relayer. If any state transition
/// were authorized on `msg.sender`, the platform would become the controller of every product
/// and the "the platform cannot forge" property would collapse.
///
/// The relayer must be able to *pay gas and nothing else*. It can submit what an actor has
/// already signed, or refuse to submit it (censorship — a modelled and accepted threat), but it
/// can never forge or authorize. A direct, literal consequence: every call carries the complete
/// pre-signed payload, so *any* address on earth can submit any of these transactions and the
/// outcome is identical. Relayer identity is not an input to the state machine.
///
/// ## Anchors live in logs, not storage
///
/// `Anchored` is emitted and nothing is written. An offline verifier reads anchors from logs via
/// `eth_getLogs` (indexed on `productId`), which is roughly an order of magnitude cheaper than
/// an `SSTORE` per anchor. There is deliberately no `anchors` mapping, and consequently no
/// on-chain monotonicity check on `version`: ordering of passport versions is established by the
/// block/log index plus the off-chain snapshot, and enforcing it on-chain would require exactly
/// the storage this design rejects.
///
/// ## No personally identifying data on-chain
///
/// `productId == keccak256(productDid)`. No GTIN, no product name, no company name, no URL.
/// The pre-image is the public product DID; the chain holds only its digest.
contract TrustAnchorRegistry is EIP712 {
    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice productId => the address currently controlling that product.
    /// @dev `address(0)` means "unclaimed".
    mapping(bytes32 productId => address controller) public productController;

    /// @notice productId => issuer address => may this issuer make claims about this product.
    mapping(bytes32 productId => mapping(address issuer => bool allowed)) public authorized;

    /// @notice Next expected nonce for a signer.
    ///
    /// @dev Nonces are **per signer**, not per product. The signer — a secp256k1 key held
    /// non-custodially by an attesting organization — is the security principal that a replay attack
    /// targets, so the replay counter belongs to the key, not to the object being acted on.
    /// Concretely, per-product nonces would be wrong here for two reasons:
    ///
    /// - `claimProduct` can *transfer* control. A per-product counter would then be shared
    ///   mutable state between two different keys: the new controller would inherit a counter
    ///   position set by the old one, and a signature the old controller prepared but never
    ///   submitted could still be replayed into the new controller's sequence.
    /// - One controller holds many products. A per-product counter forces an actor (and the
    ///   relayer queueing on its behalf) to track N independent counters instead of one, with no
    ///   security gain — the signature is bound to `productId` by the typed-data struct anyway.
    ///
    /// The accepted cost is that a single signer's operations are strictly serialized: a signer
    /// cannot have two transactions in flight at once. That is the desired behaviour for a
    /// single relayer submitting on an actor's behalf.
    mapping(address signer => uint256 nextNonce) public nonces;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A passport version was anchored.
    /// @param productId  keccak256(productDid).
    /// @param merkleRoot Merkle root over the ordered credential digests plus the snapshot digest.
    /// @param version    Passport version this root belongs to (off-chain assigned).
    /// @param by         The **recovered signer** — the controller. Never `msg.sender`.
    event Anchored(bytes32 indexed productId, bytes32 merkleRoot, uint64 version, address indexed by);

    /// @notice An issuer's authorization for a product was set or cleared.
    event IssuerAuthorized(bytes32 indexed productId, address indexed issuer, bool allowed);

    /// @notice A product was claimed for the first time, or control was transferred.
    /// @dev Not part of the minimal spec, but required for off-chain indexing: without it the
    /// only way to learn the controller history is to replay every transaction. `previous` is
    /// `address(0)` for a first claim, which is how an indexer distinguishes claim from transfer.
    event ProductClaimed(bytes32 indexed productId, address indexed controller, address indexed previous);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice `nonce` did not equal the signer's next expected nonce.
    error InvalidNonce(address signer, uint256 expected, uint256 provided);

    /// @notice First claim of a product was not signed by the address being installed as controller.
    error ClaimMustBeSelfSigned(bytes32 productId, address signer, address controller);

    /// @notice The recovered signer is not the product's current controller.
    /// @dev Also the error for operating on an unclaimed product: `controller` is then `address(0)`
    /// and no signer can ever equal it, because `ECDSA.recover` reverts rather than returning zero.
    error NotController(bytes32 productId, address signer, address controller);

    /// @notice Refused: `controller` was `address(0)`.
    /// @dev Assigning control to the zero address would "unclaim" the product and re-open it to
    /// squatting by anyone. Burning a product is not a supported operation.
    error ZeroController(bytes32 productId);

    /// @notice Refused: `productId` was `bytes32(0)`.
    /// @dev keccak256 of any DID is never zero, so an all-zero id is an uninitialised value
    /// off-chain. Permanently claiming that slot would be a foot-gun with no recovery path.
    error ZeroProductId();

    /// @notice Refused: `issuer` was `address(0)`.
    error ZeroIssuer();

    /// @notice Refused: {setIssuers} was called with no issuers.
    /// @dev An empty batch would consume a nonce and emit nothing — a transaction whose only effect
    /// is to invalidate the signer's other pending signatures. Almost certainly an off-chain bug
    /// (a filter that removed every element), and silently succeeding would hide it.
    error EmptyIssuerSet();

    /// @notice Refused: `merkleRoot` was `bytes32(0)`.
    /// @dev The root of a non-empty credential set is never zero; an all-zero root is an
    /// uninitialised value and would anchor nothing while looking like a valid anchor.
    error ZeroMerkleRoot();

    /*//////////////////////////////////////////////////////////////
                              EIP-712 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("ClaimProduct(bytes32 productId,address controller,uint256 nonce)")
    bytes32 public constant CLAIM_PRODUCT_TYPEHASH =
        keccak256("ClaimProduct(bytes32 productId,address controller,uint256 nonce)");

    /// @dev keccak256("SetIssuer(bytes32 productId,address issuer,bool allowed,uint256 nonce)")
    bytes32 public constant SET_ISSUER_TYPEHASH =
        keccak256("SetIssuer(bytes32 productId,address issuer,bool allowed,uint256 nonce)");

    /// @dev keccak256("SetIssuers(bytes32 productId,address[] issuers,bool allowed,uint256 nonce)")
    ///
    /// A DISTINCT type, not a reuse of `SetIssuer` with one element. EIP-712 hashes the type string
    /// into the struct hash, so `SetIssuer(…address issuer…)` and `SetIssuers(…address[] issuers…)`
    /// produce different digests for the same intent — which is the point: a signature collected
    /// for one can never be replayed as the other, whatever the array length.
    bytes32 public constant SET_ISSUERS_TYPEHASH =
        keccak256("SetIssuers(bytes32 productId,address[] issuers,bool allowed,uint256 nonce)");

    /// @dev keccak256("Anchor(bytes32 productId,bytes32 merkleRoot,uint64 version,uint256 nonce)")
    bytes32 public constant ANCHOR_TYPEHASH =
        keccak256("Anchor(bytes32 productId,bytes32 merkleRoot,uint64 version,uint256 nonce)");

    /*//////////////////////////////////////////////////////////////
                            MERKLE CONVENTION
    //////////////////////////////////////////////////////////////*/

    /// @dev Domain-separation tag prefixed to leaves. See {hashLeaf}.
    bytes1 public constant MERKLE_LEAF_PREFIX = 0x00;

    /// @dev Domain-separation tag prefixed to internal nodes. See {hashNode}.
    bytes1 public constant MERKLE_NODE_PREFIX = 0x01;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTION
    //////////////////////////////////////////////////////////////*/

    /// @dev Domain separator handling: inherited from OpenZeppelin's `EIP712`, which caches the
    /// separator (and the `chainid` / `address(this)` it was built from) at construction and
    /// **rebuilds it on the fly whenever `block.chainid` or `address(this)` no longer matches**.
    ///
    /// Chosen over recomputing unconditionally on every call because the recompute costs three
    /// `keccak256` rounds over ~160 bytes of memory per call, which every non-forked call would
    /// pay forever, and gas per publish is a measured quantity for this thesis. Chosen over a
    /// plain `immutable` separator because a plain immutable is *wrong across a chain fork*: both
    /// forks would accept the same signature. The OZ implementation is the vetted version of the
    /// conditional-recompute pattern and additionally implements ERC-5267 `eip712Domain()`, which
    /// lets the off-chain TypeScript signer read the domain off the contract instead of
    /// hard-coding it — the single most common source of EIP-712 integration bugs.
    ///
    /// `chainId` and `verifyingContract` are both in the domain, so a signature is bound to one
    /// chain and one deployment: it cannot be replayed on another chain (Polygon mainnet vs Amoy)
    /// nor against a redeployed registry.
    constructor() EIP712("TrustAnchorRegistry", "1") {}

    /*//////////////////////////////////////////////////////////////
                            STATE TRANSITIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Claim an unclaimed product, or transfer control of a claimed one.
    ///
    /// @dev **Semantics: first-claim-wins, then controller-only transfer.**
    ///
    /// - If `productController[productId] == address(0)` (unclaimed) the signature MUST be by
    ///   `controller` itself — a *self-claim*. Requiring self-signature means nobody can install
    ///   a third party as controller of a product without that party's key participating, so a
    ///   controller entry always corresponds to a key that demonstrably exists and consented.
    /// - If the product is already claimed, only the **current** controller may reassign it. That
    ///   is a transfer (e.g. brand handover, key rotation), and the nonce consumed is the *current*
    ///   controller's, not the incoming one's.
    ///
    /// **Known limitation — front-running / DID squatting.** `productId` is `keccak256(productDid)`
    /// and the product DID is, by design, a public identifier. An adversary who learns a product
    /// DID *before* its brand claims it can call `claimProduct` first and permanently become its
    /// controller; there is no admin key and no recovery path, by design (see contract docs).
    /// Mitigation, and the operational rule this contract assumes: **the brand claims the product
    /// at creation time, in the same workflow step that mints the DID, before the DID is published
    /// anywhere.** The window between DID generation and the claim landing on-chain is the entire
    /// attack surface, it is under the platform's control, and it is measured in seconds. A weaker
    /// residual risk remains: the relayer can *delay* (censor) a claim transaction and a colluding
    /// party could claim in the gap. That is the same censoring-relayer threat already modelled
    /// for every other operation, and it is accepted rather than mitigated on-chain — mitigating
    /// it would require a commit-reveal scheme, which costs a second transaction per product and
    /// buys nothing against a relayer that simply refuses to submit either transaction.
    ///
    /// @param productId  keccak256(productDid).
    /// @param controller Address to install as controller.
    /// @param nonce      Must equal `nonces[signer]`, where `signer` is `controller` on a first
    ///                   claim and the incumbent controller on a transfer.
    /// @param sig        65-byte EIP-712 signature over `ClaimProduct`.
    function claimProduct(bytes32 productId, address controller, uint256 nonce, bytes calldata sig) external {
        if (productId == bytes32(0)) revert ZeroProductId();
        if (controller == address(0)) revert ZeroController(productId);

        address signer = ECDSA.recover(
            _hashTypedDataV4(keccak256(abi.encode(CLAIM_PRODUCT_TYPEHASH, productId, controller, nonce))), sig
        );

        address previous = productController[productId];
        if (previous == address(0)) {
            // First claim: self-claim only.
            if (signer != controller) revert ClaimMustBeSelfSigned(productId, signer, controller);
        } else {
            // Transfer: incumbent controller only.
            if (signer != previous) revert NotController(productId, signer, previous);
        }

        _useNonce(signer, nonce);
        productController[productId] = controller;
        emit ProductClaimed(productId, controller, previous);
    }

    /// @notice Grant or revoke an issuer's authority to make claims about a product.
    /// @dev Authorized by the recovered signer being the product's current controller. Note that
    /// an unclaimed product has controller `address(0)`, which no recovered signer can equal, so
    /// this reverts `NotController(productId, signer, address(0))` for unclaimed products.
    /// @param productId keccak256(productDid).
    /// @param issuer    The issuer's `did:ethr` address.
    /// @param ok        `true` to authorize, `false` to revoke.
    /// @param nonce     Must equal `nonces[controller]`.
    /// @param sig       65-byte EIP-712 signature over `SetIssuer`.
    function setIssuer(bytes32 productId, address issuer, bool ok, uint256 nonce, bytes calldata sig) external {
        if (issuer == address(0)) revert ZeroIssuer();

        address signer = ECDSA.recover(
            _hashTypedDataV4(keccak256(abi.encode(SET_ISSUER_TYPEHASH, productId, issuer, ok, nonce))), sig
        );

        address controller = productController[productId];
        if (signer != controller) revert NotController(productId, signer, controller);

        _useNonce(signer, nonce);
        authorized[productId][issuer] = ok;
        emit IssuerAuthorized(productId, issuer, ok);
    }

    /// @notice Grant or revoke SEVERAL issuers' authority over one product, in one transaction.
    ///
    /// @dev Same authority rule as {setIssuer}, same events, one nonce. It exists because the
    /// per-issuer route made a publish cost one transaction *per contributor*: a four-supplier
    /// passport paid four base fees, four blocks of latency, and — because the registry's nonce is
    /// strictly sequential per signer — four strictly serialized round trips, since payload N+1
    /// cannot be submitted until N is mined. `IssuerAuthorized` is emitted once per issuer either
    /// way, so an indexer built against {setIssuer} needs no change.
    ///
    /// **`allowed` is shared across the batch, deliberately.** A per-issuer `bool[]` would let one
    /// signature both grant and revoke, and the operator reading it in a wallet would have to align
    /// two parallel arrays by index to know what they were agreeing to. Grant-many and revoke-many
    /// are two calls, and each one is a sentence.
    ///
    /// **Duplicates are not rejected.** `authorized[productId][issuer] = ok` is idempotent, so a
    /// repeated address costs a redundant `IssuerAuthorized` event and nothing else. Rejecting it
    /// would mean an O(n²) scan or a storage-backed set, both paid for by every honest caller to
    /// prevent a harmless mistake.
    ///
    /// @param productId keccak256(productDid).
    /// @param issuers   The issuers' `did:ethr` addresses. Must be non-empty; no element may be zero.
    /// @param ok        `true` to authorize every listed issuer, `false` to revoke every one.
    /// @param nonce     Must equal `nonces[controller]`. ONE nonce for the whole batch.
    /// @param sig       65-byte EIP-712 signature over `SetIssuers`.
    function setIssuers(bytes32 productId, address[] calldata issuers, bool ok, uint256 nonce, bytes calldata sig)
        external
    {
        uint256 n = issuers.length;
        if (n == 0) revert EmptyIssuerSet();

        // EIP-712 encodes a dynamic array as `keccak256(concat(encodeData(e) for e in array))`, and
        // `encodeData` of an `address` is the 32-byte LEFT-PADDED word — not the 20 raw bytes.
        // `abi.encodePacked(issuers)` would pack 20 bytes each and produce a digest no
        // spec-conformant signer (ethers, viem, MetaMask) will ever agree with, so the words are
        // widened first and packed as `bytes32[]`, which concatenates full words.
        bytes32[] memory words = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            if (issuers[i] == address(0)) revert ZeroIssuer();
            words[i] = bytes32(uint256(uint160(issuers[i])));
        }

        address signer = ECDSA.recover(
            _hashTypedDataV4(
                keccak256(abi.encode(SET_ISSUERS_TYPEHASH, productId, keccak256(abi.encodePacked(words)), ok, nonce))
            ),
            sig
        );

        address controller = productController[productId];
        if (signer != controller) revert NotController(productId, signer, controller);

        // Nonce BEFORE the writes, exactly as the single-issuer path does. Ordering is immaterial
        // to correctness here (no external calls, so no reentrancy), and matching the sibling
        // function is worth more than a micro-optimisation nobody would remember the reason for.
        _useNonce(signer, nonce);
        for (uint256 i = 0; i < n; ++i) {
            authorized[productId][issuers[i]] = ok;
            emit IssuerAuthorized(productId, issuers[i], ok);
        }
    }

    /// @notice Anchor a passport version by publishing its Merkle root to the log.
    /// @dev Writes no storage. See contract docs for why anchors are events.
    /// @param productId  keccak256(productDid).
    /// @param merkleRoot Root over the ordered credential digests plus the snapshot digest, built
    ///                   off-chain with the convention documented on {hashLeaf} / {hashNode}.
    /// @param version    Passport version. Not checked for monotonicity on-chain — see contract docs.
    /// @param nonce      Must equal `nonces[controller]`.
    /// @param sig        65-byte EIP-712 signature over `Anchor`.
    function anchor(bytes32 productId, bytes32 merkleRoot, uint64 version, uint256 nonce, bytes calldata sig) external {
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();

        address signer = ECDSA.recover(
            _hashTypedDataV4(keccak256(abi.encode(ANCHOR_TYPEHASH, productId, merkleRoot, version, nonce))), sig
        );

        address controller = productController[productId];
        if (signer != controller) revert NotController(productId, signer, controller);

        _useNonce(signer, nonce);
        emit Anchored(productId, merkleRoot, version, signer);
    }

    /*//////////////////////////////////////////////////////////////
                          OFF-CHAIN SIGNING AIDS
    //////////////////////////////////////////////////////////////*/

    /// @notice The EIP-712 domain separator currently in force.
    /// @dev Recomputed automatically if `block.chainid` or `address(this)` has changed since
    /// construction (chain fork). See {eip712Domain} for the full ERC-5267 description.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Digest the off-chain signer must sign for {claimProduct}.
    function hashClaimProduct(bytes32 productId, address controller, uint256 nonce) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CLAIM_PRODUCT_TYPEHASH, productId, controller, nonce)));
    }

    /// @notice Digest the off-chain signer must sign for {setIssuer}.
    function hashSetIssuer(bytes32 productId, address issuer, bool ok, uint256 nonce) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(SET_ISSUER_TYPEHASH, productId, issuer, ok, nonce)));
    }

    /// @notice Digest the off-chain signer must sign for {setIssuers}.
    /// @dev The array-hashing rule lives in exactly one place — see {setIssuers} — so an off-chain
    /// builder can check itself against this rather than reimplement it and hope.
    function hashSetIssuers(bytes32 productId, address[] calldata issuers, bool ok, uint256 nonce)
        external
        view
        returns (bytes32)
    {
        bytes32[] memory words = new bytes32[](issuers.length);
        for (uint256 i = 0; i < issuers.length; ++i) {
            words[i] = bytes32(uint256(uint160(issuers[i])));
        }
        return _hashTypedDataV4(
            keccak256(abi.encode(SET_ISSUERS_TYPEHASH, productId, keccak256(abi.encodePacked(words)), ok, nonce))
        );
    }

    /// @notice Digest the off-chain signer must sign for {anchor}.
    function hashAnchor(bytes32 productId, bytes32 merkleRoot, uint64 version, uint256 nonce)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(ANCHOR_TYPEHASH, productId, merkleRoot, version, nonce)));
    }

    /*//////////////////////////////////////////////////////////////
                        MERKLE INCLUSION (PURE HELPERS)
    //////////////////////////////////////////////////////////////*/

    /// @notice Hash a credential digest into a Merkle leaf.
    ///
    /// @dev **Normative convention. The off-chain TypeScript builder MUST match this byte for
    /// byte.** These three functions are `pure`, so they cost a verifier nothing (`eth_call`) and
    /// exist so that the off-chain builder has an executable specification to test against rather
    /// than a prose one.
    ///
    /// ```
    /// leaf(d)      = keccak256( 0x00 ‖ d )                      // d is a 32-byte digest
    /// node(a, b)   = keccak256( 0x01 ‖ min(a,b) ‖ max(a,b) )    // unsigned 256-bit comparison
    /// ```
    ///
    /// Tree construction, given the **ordered** list of 32-byte credential digests with the
    /// snapshot digest appended as the final element:
    ///
    /// 1. `level = digests.map(leaf)`.
    /// 2. While `level.length > 1`: pair left-to-right, `next[i] = node(level[2i], level[2i+1])`.
    ///    If `level.length` is odd, the **last element is promoted unchanged** to the next level
    ///    (it is *not* duplicated and *not* paired with itself).
    /// 3. `root = level[0]`. A one-element tree has `root == leaf(digests[0])`.
    ///
    /// Two properties this convention buys, both of which the naive "keccak256 of sorted pairs"
    /// convention lacks:
    ///
    /// - **Second-preimage resistance.** Leaves are 33-byte pre-images tagged `0x00` and internal
    ///   nodes are 65-byte pre-images tagged `0x01`, so an internal node's hash can never be
    ///   presented as a leaf digest. Without the tags, an attacker holding an internal node could
    ///   claim it as a credential digest.
    /// - **Proofs need no direction bits.** Pairs are ordered by value, so a proof is a bare
    ///   `bytes32[]` of siblings.
    ///
    /// The cost of value-ordered pairing is that the tree does not commit to left/right position,
    /// so it proves *set membership*, not position. Ordering of credentials within a passport
    /// version is carried by the off-chain snapshot (which is itself a leaf), not by the tree.
    function hashLeaf(bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(MERKLE_LEAF_PREFIX, digest));
    }

    /// @notice Hash two Merkle nodes into their parent, ordering the pair by value.
    /// @dev See {hashLeaf} for the full convention.
    function hashNode(bytes32 a, bytes32 b) public pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(MERKLE_NODE_PREFIX, a, b))
            : keccak256(abi.encodePacked(MERKLE_NODE_PREFIX, b, a));
    }

    /// @notice Verify that `digest` was a member of the credential set committed to by `root`.
    /// @dev Pure; charges the caller nothing when invoked via `eth_call`. Provided so a verifier
    /// can check *one* credential against an anchored root without holding the whole bundle
    /// (selective proof). See {hashLeaf} for the convention `proof` must have been built with.
    /// @param root   A `merkleRoot` taken from an {Anchored} log entry.
    /// @param digest The 32-byte credential digest being proved.
    /// @param proof  Sibling hashes from leaf to root; empty for a single-credential tree.
    function verifyInclusion(bytes32 root, bytes32 digest, bytes32[] calldata proof) external pure returns (bool) {
        bytes32 node = hashLeaf(digest);
        for (uint256 i = 0; i < proof.length; ++i) {
            node = hashNode(node, proof[i]);
        }
        return node == root;
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Consume `signer`'s nonce, enforcing strict `nonce == nonces[signer]` then increment.
    /// Strict equality (rather than `>=`) means a signature is valid at exactly one position in
    /// the signer's sequence, so a captured signature is dead the moment the next one lands.
    /// The increment cannot realistically overflow a `uint256`; `unchecked` saves the check.
    function _useNonce(address signer, uint256 nonce) private {
        uint256 expected = nonces[signer];
        if (nonce != expected) revert InvalidNonce(signer, expected, nonce);
        unchecked {
            nonces[signer] = expected + 1;
        }
    }
}
