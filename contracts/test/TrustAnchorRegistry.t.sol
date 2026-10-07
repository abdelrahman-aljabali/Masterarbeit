// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TrustAnchorRegistry} from "../src/TrustAnchorRegistry.sol";

/// @title TrustAnchorRegistry test suite
/// @notice The load-bearing test in this file is
///         {test_RelayerIsNeverAuthorization_AttributionFollowsTheSigner}. Everything else
///         supports it. See the "CORE SECURITY PROPERTY" section.
/// @dev EIP-712 digests are reconstructed here from literals — the domain typehash, the name and
/// the version are written out again rather than read off the contract — so that an encoding bug
/// in `TrustAnchorRegistry` cannot hide by being mirrored in the test. {test_DomainSeparator_...}
/// then pins the contract's own view against these literals.
contract TrustAnchorRegistryTest is Test {
    /*//////////////////////////////////////////////////////////////
                                FIXTURES
    //////////////////////////////////////////////////////////////*/

    /// @dev Polygon Amoy. Design A's target chain, and the chain the domain binds to.
    uint256 internal constant AMOY = 80002;
    /// @dev Polygon mainnet — the "other chain" for cross-chain replay tests.
    uint256 internal constant POLYGON = 137;

    /// @dev secp256k1 group order, for signature-malleability construction.
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant CLAIM_PRODUCT_TYPEHASH =
        keccak256("ClaimProduct(bytes32 productId,address controller,uint256 nonce)");
    bytes32 internal constant SET_ISSUER_TYPEHASH =
        keccak256("SetIssuer(bytes32 productId,address issuer,bool allowed,uint256 nonce)");
    bytes32 internal constant SET_ISSUERS_TYPEHASH =
        keccak256("SetIssuers(bytes32 productId,address[] issuers,bool allowed,uint256 nonce)");
    bytes32 internal constant ANCHOR_TYPEHASH =
        keccak256("Anchor(bytes32 productId,bytes32 merkleRoot,uint64 version,uint256 nonce)");

    TrustAnchorRegistry internal registry;

    // Actors. `brand` and `supplier` hold non-custodial secp256k1 keys (Web3Auth tKey in
    // production); the platform holds no share of them and cannot sign on their behalf.
    uint256 internal brandPk = 0xB1A4D;
    uint256 internal supplierPk = 0x50FF11E4;
    uint256 internal squatterPk = 0x5A0A77E4;
    address internal brand;
    address internal supplier;
    address internal squatter;

    // The platform relayer: funds gas, holds no authority. Plus two unrelated relayers used to
    // demonstrate that relayer identity is not an input to the state machine.
    address internal relayer = makeAddr("platformRelayer");
    address internal otherRelayer = makeAddr("someoneElsesRelayer");
    address internal hostileRelayer = makeAddr("hostileRelayer");

    bytes32 internal constant PRODUCT_DID_HASH = keccak256("did:web:app.trustdpp.co:passport:0001");
    bytes32 internal productId = PRODUCT_DID_HASH;
    bytes32 internal constant ROOT_V1 = keccak256("merkle-root-v1");
    bytes32 internal constant ROOT_V2 = keccak256("merkle-root-v2");

    // Mirrors of the contract's events, for `vm.expectEmit`.
    event Anchored(bytes32 indexed productId, bytes32 merkleRoot, uint64 version, address indexed by);
    event IssuerAuthorized(bytes32 indexed productId, address indexed issuer, bool allowed);
    event ProductClaimed(bytes32 indexed productId, address indexed controller, address indexed previous);

    function setUp() public {
        // Deploy *on* Amoy's chain id so the cached domain separator is the production one.
        vm.chainId(AMOY);
        registry = new TrustAnchorRegistry();
        brand = vm.addr(brandPk);
        supplier = vm.addr(supplierPk);
        squatter = vm.addr(squatterPk);
        vm.label(brand, "brand");
        vm.label(supplier, "supplier");
        vm.label(squatter, "squatter");
        vm.label(address(registry), "TrustAnchorRegistry");
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNING HELPERS (INDEPENDENT)
    //////////////////////////////////////////////////////////////*/

    function _domainSeparator(address verifyingContract, uint256 chainId) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("TrustAnchorRegistry")),
                keccak256(bytes("1")),
                chainId,
                verifyingContract
            )
        );
    }

    function _digest(bytes32 structHash, address verifyingContract, uint256 chainId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _domainSeparator(verifyingContract, chainId), structHash));
    }

    function _claimStruct(bytes32 pid, address controller, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(CLAIM_PRODUCT_TYPEHASH, pid, controller, nonce));
    }

    function _issuerStruct(bytes32 pid, address issuer, bool ok, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(SET_ISSUER_TYPEHASH, pid, issuer, ok, nonce));
    }

    /// @dev EIP-712 §"Definition of encodeData": a dynamic array hashes to
    /// `keccak256(concat(encodeData(e) for e in array))`, and an `address` element encodes as its
    /// 32-byte LEFT-PADDED word. Written out here from the SPEC rather than by calling the
    /// contract's own helper — a test that asks the implementation what the answer should be
    /// cannot catch the implementation being wrong.
    function _issuersStruct(bytes32 pid, address[] memory issuers, bool ok, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        bytes memory packed;
        for (uint256 i = 0; i < issuers.length; ++i) {
            packed = abi.encodePacked(packed, bytes32(uint256(uint160(issuers[i]))));
        }
        return keccak256(abi.encode(SET_ISSUERS_TYPEHASH, pid, keccak256(packed), ok, nonce));
    }

    function _anchorStruct(bytes32 pid, bytes32 root, uint64 version, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(ANCHOR_TYPEHASH, pid, root, version, nonce));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signClaim(uint256 pk, bytes32 pid, address controller, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _digest(_claimStruct(pid, controller, nonce), address(registry), block.chainid));
    }

    function _signSetIssuer(uint256 pk, bytes32 pid, address issuer, bool ok, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _digest(_issuerStruct(pid, issuer, ok, nonce), address(registry), block.chainid));
    }

    function _signSetIssuers(uint256 pk, bytes32 pid, address[] memory issuers, bool ok, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _digest(_issuersStruct(pid, issuers, ok, nonce), address(registry), block.chainid));
    }

    function _signAnchor(uint256 pk, bytes32 pid, bytes32 root, uint64 version, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _digest(_anchorStruct(pid, root, version, nonce), address(registry), block.chainid));
    }

    /// @dev Four distinct supplier addresses — the shape of a real textile passport
    /// (cotton farm, spinning, weaving/dyeing, cut-sew).
    function _fourSuppliers() internal pure returns (address[] memory issuers) {
        issuers = new address[](4);
        issuers[0] = address(0xA11CE);
        issuers[1] = address(0xB0B);
        issuers[2] = address(0xCA401);
        issuers[3] = address(0xD1DD);
    }

    /// @dev Claim `productId` for `brand`, submitted by the platform relayer. The normal setup.
    function _claimForBrand() internal {
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, _signClaim(brandPk, productId, brand, 0));
    }

    /*//////////////////////////////////////////////////////////////
                          CORE SECURITY PROPERTY
    //////////////////////////////////////////////////////////////*/

    /// @notice THE MOST IMPORTANT TEST IN THIS FILE.
    ///
    /// A transaction submitted by a relayer address that is *not* the signer succeeds, and every
    /// piece of resulting state and every event attributes to the **signer**. The relayer gains
    /// nothing whatsoever from being `msg.sender`: it does not become controller, it does not
    /// become an authorized issuer, it is not named in the anchor log, and its nonce is untouched.
    ///
    /// This is the on-chain half of the thesis claim that the platform "can pay gas and nothing
    /// else". If this test can be made to fail, the platform becomes the controller of every
    /// product and the non-custodial architecture collapses.
    function test_RelayerIsNeverAuthorization_AttributionFollowsTheSigner() public {
        // ── 1. Claim: brand signs, relayer submits.
        bytes memory claimSig = _signClaim(brandPk, productId, brand, 0);

        vm.expectEmit(true, true, true, true, address(registry));
        emit ProductClaimed(productId, brand, address(0));
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, claimSig);

        assertEq(registry.productController(productId), brand, "controller must be the SIGNER");
        assertTrue(registry.productController(productId) != relayer, "relayer must NOT become controller");
        assertEq(registry.nonces(brand), 1, "signer's nonce advanced");
        assertEq(registry.nonces(relayer), 0, "relayer's nonce untouched");

        // ── 2. setIssuer: brand signs, a completely unrelated relayer submits.
        bytes memory issuerSig = _signSetIssuer(brandPk, productId, supplier, true, 1);

        vm.expectEmit(true, true, true, true, address(registry));
        emit IssuerAuthorized(productId, supplier, true);
        vm.prank(otherRelayer);
        registry.setIssuer(productId, supplier, true, 1, issuerSig);

        assertTrue(registry.authorized(productId, supplier), "issuer named in the payload is authorized");
        assertFalse(registry.authorized(productId, otherRelayer), "submitting relayer is NOT authorized");
        assertFalse(registry.authorized(productId, relayer), "platform relayer is NOT authorized");

        // ── 3. anchor: brand signs, a third relayer submits. `by` is the signer, not msg.sender.
        bytes memory anchorSig = _signAnchor(brandPk, productId, ROOT_V1, 1, 2);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Anchored(productId, ROOT_V1, 1, brand); // <-- `by` == brand, NOT hostileRelayer
        vm.prank(hostileRelayer);
        registry.anchor(productId, ROOT_V1, 1, 2, anchorSig);

        assertEq(registry.nonces(brand), 3, "all three ops consumed the SIGNER's nonces");
        assertEq(registry.nonces(relayer), 0);
        assertEq(registry.nonces(otherRelayer), 0);
        assertEq(registry.nonces(hostileRelayer), 0);

        // ── 4. The relayer cannot authorize anything by virtue of being msg.sender.
        // It holds no key for `brand`, so the only signature it can produce is its own, and that
        // signature does not recover to the controller. Being msg.sender changes nothing.
        uint256 hostilePk = 0xDEADBEEF;
        address hostile = vm.addr(hostilePk);
        vm.deal(hostile, 1 ether);

        // 4a. It cannot install itself as an issuer.
        bytes memory selfIssuerSig = _signSetIssuer(hostilePk, productId, hostile, true, 0);
        vm.prank(hostile);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, hostile, brand));
        registry.setIssuer(productId, hostile, true, 0, selfIssuerSig);

        // 4b. It cannot anchor.
        bytes memory selfAnchorSig = _signAnchor(hostilePk, productId, ROOT_V2, 2, 0);
        vm.prank(hostile);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, hostile, brand));
        registry.anchor(productId, ROOT_V2, 2, 0, selfAnchorSig);

        // 4c. It cannot seize control of the product.
        bytes memory seizeSig = _signClaim(hostilePk, productId, hostile, 0);
        vm.prank(hostile);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, hostile, brand));
        registry.claimProduct(productId, hostile, 0, seizeSig);

        assertEq(registry.productController(productId), brand, "state unchanged after hostile attempts");
        assertFalse(registry.authorized(productId, hostile));
    }

    /// @notice The pre-signed payload is portable: *any* relayer can submit it, byte for byte,
    ///         with an identical outcome. Relayer identity is not an input to the state machine.
    /// @dev Demonstrated by replaying the exact same calldata from 5 unrelated senders, reverting
    /// chain state between each, and asserting the resulting state is identical every time.
    function test_AnyRelayerCanSubmitTheSamePreSignedPayload() public {
        bytes memory sig = _signClaim(brandPk, productId, brand, 0);
        bytes memory callData = abi.encodeCall(TrustAnchorRegistry.claimProduct, (productId, brand, 0, sig));

        address[5] memory senders =
            [relayer, otherRelayer, hostileRelayer, makeAddr("randomBystander"), address(0xdeadbeef)];

        for (uint256 i = 0; i < senders.length; ++i) {
            uint256 snap = vm.snapshotState();

            vm.prank(senders[i]);
            (bool ok,) = address(registry).call(callData);
            assertTrue(ok, "identical calldata must succeed from any sender");
            assertEq(registry.productController(productId), brand, "same outcome from any sender");
            assertEq(registry.nonces(senders[i]), 0, "sender's own nonce never moves");

            vm.revertToState(snap);
        }
    }

    /// @notice Evidence at the bytecode level: the deployed runtime code never executes CALLER
    ///         (0x33, `msg.sender`). Authorization cannot depend on something the code never reads.
    /// @dev Walks the runtime bytecode as an opcode stream, skipping PUSHn immediates so that
    /// constant data inside PUSH arguments cannot produce a false positive.
    function test_RuntimeBytecodeNeverExecutesCALLER() public view {
        bytes memory code = address(registry).code;
        assertGt(code.length, 0, "no runtime code");

        uint256 callerOccurrences = 0;
        uint256 i = 0;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            if (op == 0x33) callerOccurrences += 1;
            if (op >= 0x60 && op <= 0x7f) {
                i += uint256(op) - 0x5f; // skip the PUSHn immediate
            }
            i += 1;
        }
        assertEq(callerOccurrences, 0, "runtime bytecode contains a CALLER opcode");
    }

    /*//////////////////////////////////////////////////////////////
                               HAPPY PATHS
    //////////////////////////////////////////////////////////////*/

    function test_ClaimProduct_HappyPath() public {
        assertEq(registry.productController(productId), address(0));

        vm.expectEmit(true, true, true, true, address(registry));
        emit ProductClaimed(productId, brand, address(0));
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, _signClaim(brandPk, productId, brand, 0));

        assertEq(registry.productController(productId), brand);
        assertEq(registry.nonces(brand), 1);
    }

    function test_SetIssuer_HappyPath() public {
        _claimForBrand();

        vm.expectEmit(true, true, true, true, address(registry));
        emit IssuerAuthorized(productId, supplier, true);
        vm.prank(relayer);
        registry.setIssuer(productId, supplier, true, 1, _signSetIssuer(brandPk, productId, supplier, true, 1));
        assertTrue(registry.authorized(productId, supplier));

        // …and revocation.
        vm.expectEmit(true, true, true, true, address(registry));
        emit IssuerAuthorized(productId, supplier, false);
        vm.prank(relayer);
        registry.setIssuer(productId, supplier, false, 2, _signSetIssuer(brandPk, productId, supplier, false, 2));
        assertFalse(registry.authorized(productId, supplier));
        assertEq(registry.nonces(brand), 3);
    }

    // ── setIssuers: the batch ────────────────────────────────────────────────────────────────

    function test_SetIssuers_HappyPath() public {
        _claimForBrand();
        address[] memory issuers = _fourSuppliers();

        // One `IssuerAuthorized` per issuer, in list order — an indexer written against the
        // single-issuer path sees exactly what it already understands.
        for (uint256 i = 0; i < issuers.length; ++i) {
            vm.expectEmit(true, true, true, true, address(registry));
            emit IssuerAuthorized(productId, issuers[i], true);
        }
        vm.prank(relayer);
        registry.setIssuers(productId, issuers, true, 1, _signSetIssuers(brandPk, productId, issuers, true, 1));

        for (uint256 i = 0; i < issuers.length; ++i) {
            assertTrue(registry.authorized(productId, issuers[i]));
        }
        // ONE nonce for four grants — the whole point.
        assertEq(registry.nonces(brand), 2);

        // …and revocation of the same set.
        vm.prank(relayer);
        registry.setIssuers(productId, issuers, false, 2, _signSetIssuers(brandPk, productId, issuers, false, 2));
        for (uint256 i = 0; i < issuers.length; ++i) {
            assertFalse(registry.authorized(productId, issuers[i]));
        }
        assertEq(registry.nonces(brand), 3);
    }

    /// The digest the contract builds must equal the one built from the SPEC, or no
    /// spec-conformant wallet (ethers, viem, MetaMask) will ever produce an acceptable signature.
    /// This is the test that catches `abi.encodePacked(address[])`'s 20-byte packing.
    function test_SetIssuers_ArrayEncodingMatchesTheEip712Spec() public view {
        address[] memory issuers = _fourSuppliers();
        assertEq(
            registry.hashSetIssuers(productId, issuers, true, 7),
            _digest(_issuersStruct(productId, issuers, true, 7), address(registry), block.chainid)
        );
    }

    /// @notice A digest over FIXED inputs, for the off-chain encoders to be pinned against.
    ///
    /// @dev The backend hand-rolls EIP-712 (`typedData.ts`, so a payload can be hashed without
    /// pulling ethers into every path) and the gateway uses ethers' `TypedDataEncoder`. Three
    /// implementations of the same spec, and `address[]` is the member where they can silently
    /// disagree — pack an address as 20 bytes instead of a 32-byte word and every signature this
    /// system produces is rejected on chain, after the gas is spent.
    ///
    /// So this prints the answer for inputs nothing else depends on, and
    /// `designA/typedData.setIssuers.test.ts` asserts the same constant. If solc, ethers, or the
    /// hand-rolled encoder ever moves, exactly one of the two tests fails and says which.
    function test_SetIssuers_GoldenDigestForOffChainEncoders() public view {
        address[] memory issuers = new address[](3);
        issuers[0] = 0x1111111111111111111111111111111111111111;
        issuers[1] = 0x2222222222222222222222222222222222222222;
        issuers[2] = 0x3333333333333333333333333333333333333333;

        bytes32 pid = 0x00000000000000000000000000000000000000000000000000000000000000AA;
        bytes32 digest = registry.hashSetIssuers(pid, issuers, true, 42);

        console2.log("=== SetIssuers golden vector ===");
        console2.log("chainId          ", block.chainid);
        console2.log("verifyingContract", address(registry));
        console2.logBytes32(digest);

        // Also pinned: the type hash itself, which is the string the three encoders must agree on
        // character for character before any member encoding matters.
        assertEq(
            registry.SET_ISSUERS_TYPEHASH(),
            keccak256("SetIssuers(bytes32 productId,address[] issuers,bool allowed,uint256 nonce)")
        );
    }

    /// A `SetIssuer` signature must not be usable as a one-element `SetIssuers`, or the batch would
    /// be a replay channel for every single-issuer signature ever collected. The distinct typehash
    /// is what prevents it; this proves the typehash is actually load-bearing.
    function test_RevertWhen_SingleIssuerSignatureIsReplayedAsABatch() public {
        _claimForBrand();
        address[] memory one = new address[](1);
        one[0] = supplier;

        bytes memory singleSig = _signSetIssuer(brandPk, productId, supplier, true, 1);

        vm.prank(relayer);
        vm.expectRevert(); // recovers to some other address; never the controller
        registry.setIssuers(productId, one, true, 1, singleSig);

        assertFalse(registry.authorized(productId, supplier));
        assertEq(registry.nonces(brand), 1);
    }

    /// …and the reverse: a batch signature is not a single-issuer signature.
    function test_RevertWhen_BatchSignatureIsReplayedAsSingle() public {
        _claimForBrand();
        address[] memory one = new address[](1);
        one[0] = supplier;

        bytes memory batchSig = _signSetIssuers(brandPk, productId, one, true, 1);

        vm.prank(relayer);
        vm.expectRevert();
        registry.setIssuer(productId, supplier, true, 1, batchSig);

        assertFalse(registry.authorized(productId, supplier));
    }

    /// A different set is a different signature. Proves the array is inside the digest rather than
    /// alongside it — otherwise a relayer could swap the list and authorize anyone.
    function test_RevertWhen_RelayerSubstitutesADifferentIssuerList() public {
        _claimForBrand();
        address[] memory signedFor = _fourSuppliers();
        bytes memory sig = _signSetIssuers(brandPk, productId, signedFor, true, 1);

        address[] memory tampered = _fourSuppliers();
        tampered[2] = squatter; // one address swapped

        vm.prank(relayer);
        vm.expectRevert();
        registry.setIssuers(productId, tampered, true, 1, sig);
        assertFalse(registry.authorized(productId, squatter));
    }

    /// Order is part of the digest too — the array hash is a concatenation, not a set.
    function test_RevertWhen_IssuerListIsReordered() public {
        _claimForBrand();
        address[] memory signedFor = _fourSuppliers();
        bytes memory sig = _signSetIssuers(brandPk, productId, signedFor, true, 1);

        address[] memory reordered = new address[](4);
        reordered[0] = signedFor[3];
        reordered[1] = signedFor[2];
        reordered[2] = signedFor[1];
        reordered[3] = signedFor[0];

        vm.prank(relayer);
        vm.expectRevert();
        registry.setIssuers(productId, reordered, true, 1, sig);
    }

    function test_RevertWhen_IssuerSetIsEmpty() public {
        _claimForBrand();
        address[] memory none = new address[](0);
        vm.prank(relayer);
        vm.expectRevert(TrustAnchorRegistry.EmptyIssuerSet.selector);
        registry.setIssuers(productId, none, true, 1, _signSetIssuers(brandPk, productId, none, true, 1));
        assertEq(registry.nonces(brand), 1); // no nonce consumed
    }

    /// A zero anywhere in the list reverts the WHOLE batch — checked before recovery, so a
    /// malformed list cannot half-apply.
    function test_RevertWhen_AnyIssuerInTheBatchIsZero() public {
        _claimForBrand();
        address[] memory issuers = _fourSuppliers();
        issuers[2] = address(0);

        vm.prank(relayer);
        vm.expectRevert(TrustAnchorRegistry.ZeroIssuer.selector);
        registry.setIssuers(productId, issuers, true, 1, _signSetIssuers(brandPk, productId, issuers, true, 1));

        assertFalse(registry.authorized(productId, issuers[0]));
        assertEq(registry.nonces(brand), 1);
    }

    function test_RevertWhen_SetIssuersBySomeoneWhoIsNotTheController() public {
        _claimForBrand();
        address[] memory issuers = _fourSuppliers();
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, squatter, brand)
        );
        registry.setIssuers(productId, issuers, true, 0, _signSetIssuers(squatterPk, productId, issuers, true, 0));
    }

    function test_RevertWhen_SetIssuersOnUnclaimedProduct() public {
        address[] memory issuers = _fourSuppliers();
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, brand, address(0))
        );
        registry.setIssuers(productId, issuers, true, 0, _signSetIssuers(brandPk, productId, issuers, true, 0));
    }

    function test_RevertWhen_ReplayingTheSameSignature_SetIssuers() public {
        _claimForBrand();
        address[] memory issuers = _fourSuppliers();
        bytes memory sig = _signSetIssuers(brandPk, productId, issuers, true, 1);

        vm.prank(relayer);
        registry.setIssuers(productId, issuers, true, 1, sig);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 2, 1));
        registry.setIssuers(productId, issuers, true, 1, sig);
    }

    /// Documented behaviour: duplicates are idempotent, not an error. Rejecting them would cost
    /// every honest caller an O(n²) scan to prevent a harmless mistake.
    function test_SetIssuers_DuplicatesAreIdempotent() public {
        _claimForBrand();
        address[] memory dupes = new address[](3);
        dupes[0] = supplier;
        dupes[1] = supplier;
        dupes[2] = supplier;

        vm.prank(relayer);
        registry.setIssuers(productId, dupes, true, 1, _signSetIssuers(brandPk, productId, dupes, true, 1));
        assertTrue(registry.authorized(productId, supplier));
        assertEq(registry.nonces(brand), 2);
    }

    function testFuzz_SetIssuers(uint256 ctrlSeed, address a, address b, bool ok, address submitter) public {
        uint256 pk = bound(ctrlSeed, 1, SECP256K1_N - 1);
        address controller = vm.addr(pk);
        vm.assume(a != address(0) && b != address(0));

        bytes32 pid = keccak256("fuzz:setIssuers");
        vm.prank(submitter);
        registry.claimProduct(pid, controller, 0, _signClaim(pk, pid, controller, 0));

        address[] memory issuers = new address[](2);
        issuers[0] = a;
        issuers[1] = b;

        vm.prank(submitter);
        registry.setIssuers(pid, issuers, ok, 1, _signSetIssuers(pk, pid, issuers, ok, 1));

        assertEq(registry.authorized(pid, a), ok);
        assertEq(registry.authorized(pid, b), ok);
        assertEq(registry.nonces(controller), 2);
    }

    function test_Anchor_HappyPath() public {
        _claimForBrand();

        vm.expectEmit(true, true, true, true, address(registry));
        emit Anchored(productId, ROOT_V1, 1, brand);
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V1, 1, 1, _signAnchor(brandPk, productId, ROOT_V1, 1, 1));

        // A second version anchors to the same product; nothing is overwritten, both live in logs.
        vm.expectEmit(true, true, true, true, address(registry));
        emit Anchored(productId, ROOT_V2, 2, brand);
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V2, 2, 2, _signAnchor(brandPk, productId, ROOT_V2, 2, 2));

        assertEq(registry.nonces(brand), 3);
    }

    /// @dev No storage is written by `anchor` — the design puts anchors in logs only.
    function test_Anchor_WritesNoStorageBeyondTheNonce() public {
        _claimForBrand();

        vm.record();
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V1, 1, 1, _signAnchor(brandPk, productId, ROOT_V1, 1, 1));
        (, bytes32[] memory writes) = vm.accesses(address(registry));

        assertEq(writes.length, 1, "anchor must write exactly one slot: the signer's nonce");
        // `nonces` is slot 4 (slots 0-1 are OZ EIP712's string fallbacks, 2 is productController,
        // 3 is authorized) — see `forge inspect TrustAnchorRegistry storage-layout`.
        assertEq(writes[0], keccak256(abi.encode(brand, uint256(4))), "the written slot is nonces[signer]");
    }

    /*//////////////////////////////////////////////////////////////
                         claimProduct SEMANTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice First claim must be self-signed: X cannot install Y as controller.
    function test_RevertWhen_FirstClaimIsNotSelfSigned() public {
        // squatter signs, but names `brand` as controller.
        bytes memory sig = _signClaim(squatterPk, productId, brand, 0);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.ClaimMustBeSelfSigned.selector, productId, squatter, brand)
        );
        registry.claimProduct(productId, brand, 0, sig);
        assertEq(registry.productController(productId), address(0));
    }

    /// @notice Transfer: only the *incumbent* controller may reassign, and the nonce consumed is
    ///         the incumbent's — not the incoming controller's.
    function test_ClaimProduct_TransferByCurrentController() public {
        _claimForBrand();
        assertEq(registry.nonces(brand), 1);
        assertEq(registry.nonces(supplier), 0);

        vm.expectEmit(true, true, true, true, address(registry));
        emit ProductClaimed(productId, supplier, brand);
        vm.prank(relayer);
        registry.claimProduct(productId, supplier, 1, _signClaim(brandPk, productId, supplier, 1));

        assertEq(registry.productController(productId), supplier);
        assertEq(registry.nonces(brand), 2, "the INCUMBENT's nonce was consumed");
        assertEq(registry.nonces(supplier), 0, "the incoming controller's nonce is untouched");

        // The old controller can no longer act.
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, brand, supplier));
        registry.anchor(productId, ROOT_V1, 1, 2, _signAnchor(brandPk, productId, ROOT_V1, 1, 2));
    }

    function test_RevertWhen_TransferAttemptedByNonController() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, squatter, brand));
        registry.claimProduct(productId, squatter, 0, _signClaim(squatterPk, productId, squatter, 0));
        assertEq(registry.productController(productId), brand);
    }

    /// @notice KNOWN LIMITATION, asserted rather than hidden: `productId` is derived from a public
    ///         product DID, so an adversary who learns a DID before the brand claims it can squat
    ///         the product permanently. There is no admin key and no recovery path, by design.
    /// @dev The mitigation is operational, not on-chain: the brand claims at product creation, in
    /// the same workflow step that mints the DID, before the DID is published anywhere. This test
    /// exists so the limitation is a documented, tested property of the artifact and not a
    /// surprise found later.
    function test_KnownLimitation_DidSquattingIsPossibleBeforeTheBrandClaims() public {
        // The adversary learned the product DID and claims it first.
        vm.prank(hostileRelayer);
        registry.claimProduct(productId, squatter, 0, _signClaim(squatterPk, productId, squatter, 0));
        assertEq(registry.productController(productId), squatter);

        // The legitimate brand is now permanently locked out. No recovery exists.
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, brand, squatter));
        registry.claimProduct(productId, brand, 0, _signClaim(brandPk, productId, brand, 0));
    }

    /*//////////////////////////////////////////////////////////////
                            NONCE / REPLAY
    //////////////////////////////////////////////////////////////*/

    function test_RevertWhen_ReplayingTheSameSignature_Claim() public {
        bytes memory sig = _signClaim(brandPk, productId, brand, 0);
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, sig);

        // Byte-identical resubmission, by anyone, at any time.
        vm.prank(otherRelayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 1, 0));
        registry.claimProduct(productId, brand, 0, sig);
    }

    function test_RevertWhen_ReplayingTheSameSignature_SetIssuer() public {
        _claimForBrand();
        bytes memory sig = _signSetIssuer(brandPk, productId, supplier, true, 1);
        vm.prank(relayer);
        registry.setIssuer(productId, supplier, true, 1, sig);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 2, 1));
        registry.setIssuer(productId, supplier, true, 1, sig);
    }

    /// @notice A replayed anchor is the attack that would let a stale passport version be
    ///         re-attested. The nonce kills it.
    function test_RevertWhen_ReplayingTheSameSignature_Anchor() public {
        _claimForBrand();
        bytes memory sig = _signAnchor(brandPk, productId, ROOT_V1, 1, 1);
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V1, 1, 1, sig);

        vm.prank(hostileRelayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 2, 1));
        registry.anchor(productId, ROOT_V1, 1, 1, sig);
    }

    function test_RevertWhen_NonceIsTooHigh() public {
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 0, 1));
        registry.claimProduct(productId, brand, 1, _signClaim(brandPk, productId, brand, 1));
    }

    function test_RevertWhen_NonceIsStale() public {
        _claimForBrand(); // nonces[brand] == 1
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 1, 0));
        registry.setIssuer(productId, supplier, true, 0, _signSetIssuer(brandPk, productId, supplier, true, 0));
    }

    /// @notice Nonces are per signer, not per product: one controller's sequence spans all of its
    ///         products, and two different signers never share a counter.
    function test_NoncesArePerSignerNotPerProduct() public {
        bytes32 pidA = keccak256("did:a");
        bytes32 pidB = keccak256("did:b");

        vm.prank(relayer);
        registry.claimProduct(pidA, brand, 0, _signClaim(brandPk, pidA, brand, 0));
        // Nonce 1, not 0 again, even though pidB has never been touched.
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 1, 0));
        registry.claimProduct(pidB, brand, 0, _signClaim(brandPk, pidB, brand, 0));

        vm.prank(relayer);
        registry.claimProduct(pidB, brand, 1, _signClaim(brandPk, pidB, brand, 1));
        assertEq(registry.nonces(brand), 2);

        // A different signer's counter is entirely independent and still at 0.
        assertEq(registry.nonces(supplier), 0);
        vm.prank(relayer);
        registry.claimProduct(keccak256("did:c"), supplier, 0, _signClaim(supplierPk, keccak256("did:c"), supplier, 0));
        assertEq(registry.nonces(supplier), 1);
    }

    /*//////////////////////////////////////////////////////////////
                        DOMAIN BINDING / REPLAY ACROSS
    //////////////////////////////////////////////////////////////*/

    function test_DomainSeparator_MatchesTheIndependentlyComputedValue() public view {
        assertEq(registry.domainSeparator(), _domainSeparator(address(registry), AMOY));
    }

    /// @notice ERC-5267: the off-chain signer can read the domain off the contract.
    function test_Eip712DomainIsSelfDescribing() public view {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            registry.eip712Domain();
        assertEq(name, "TrustAnchorRegistry");
        assertEq(version, "1");
        assertEq(chainId, AMOY);
        assertEq(verifyingContract, address(registry));
    }

    /// @notice A signature produced for Amoy is rejected on Polygon mainnet.
    /// @dev The signature recovers to a *different* (garbage) address under the other chain's
    /// domain separator, so the contract reports `ClaimMustBeSelfSigned` rather than accepting it.
    function test_RevertWhen_CrossChainReplay() public {
        bytes memory amoySig = _signClaim(brandPk, productId, brand, 0);

        // Same registry address, different chain (a fork, or the same code deployed on mainnet).
        vm.chainId(POLYGON);
        assertTrue(
            registry.domainSeparator() != _domainSeparator(address(registry), AMOY),
            "separator must be REBUILT after the chain id changes"
        );
        assertEq(registry.domainSeparator(), _domainSeparator(address(registry), POLYGON));

        vm.prank(relayer);
        vm.expectRevert(); // recovers to some other address; never to `brand`
        registry.claimProduct(productId, brand, 0, amoySig);
        assertEq(registry.productController(productId), address(0));

        // …and a signature made *for* Polygon works there, proving the rebuild is correct and not
        // merely "always fails after a fork".
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, _signClaim(brandPk, productId, brand, 0));
        assertEq(registry.productController(productId), brand);
    }

    /// @notice A signature for registry A is rejected by registry B (`verifyingContract` binding).
    function test_RevertWhen_CrossContractReplay() public {
        TrustAnchorRegistry other = new TrustAnchorRegistry();
        assertTrue(other.domainSeparator() != registry.domainSeparator());

        bytes memory sigForRegistry = _signClaim(brandPk, productId, brand, 0);
        vm.prank(relayer);
        vm.expectRevert();
        other.claimProduct(productId, brand, 0, sigForRegistry);
        assertEq(other.productController(productId), address(0));
    }

    /// @notice A `ClaimProduct` signature cannot be reinterpreted as `SetIssuer` or `Anchor`:
    ///         distinct type hashes keep the three payload shapes disjoint.
    function test_RevertWhen_SignatureIsReusedAcrossPayloadTypes() public {
        _claimForBrand();
        // Signature over ClaimProduct(productId, supplier, 1) …
        bytes memory claimSig = _signClaim(brandPk, productId, supplier, 1);
        // … replayed as SetIssuer(productId, supplier, true, 1).
        vm.prank(relayer);
        vm.expectRevert();
        registry.setIssuer(productId, supplier, true, 1, claimSig);
        assertFalse(registry.authorized(productId, supplier));
    }

    /*//////////////////////////////////////////////////////////////
                       AUTHORIZATION FAILURE MODES
    //////////////////////////////////////////////////////////////*/

    function test_RevertWhen_SetIssuerBySomeoneWhoIsNotTheController() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, supplier, brand));
        registry.setIssuer(productId, supplier, true, 0, _signSetIssuer(supplierPk, productId, supplier, true, 0));
    }

    function test_RevertWhen_AnchorBySomeoneWhoIsNotTheController() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, supplier, brand));
        registry.anchor(productId, ROOT_V1, 1, 0, _signAnchor(supplierPk, productId, ROOT_V1, 1, 0));
    }

    /// @notice An *authorized issuer* is authorized to sign credentials off-chain — it is NOT
    ///         authorized to touch the registry. Only the controller can.
    function test_RevertWhen_AuthorizedIssuerTriesToAnchor() public {
        _claimForBrand();
        vm.prank(relayer);
        registry.setIssuer(productId, supplier, true, 1, _signSetIssuer(brandPk, productId, supplier, true, 1));
        assertTrue(registry.authorized(productId, supplier));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, supplier, brand));
        registry.anchor(productId, ROOT_V1, 1, 0, _signAnchor(supplierPk, productId, ROOT_V1, 1, 0));
    }

    function test_RevertWhen_SetIssuerOnUnclaimedProduct() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, brand, address(0))
        );
        registry.setIssuer(productId, supplier, true, 0, _signSetIssuer(brandPk, productId, supplier, true, 0));
    }

    function test_RevertWhen_AnchorOnUnclaimedProduct() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, brand, address(0))
        );
        registry.anchor(productId, ROOT_V1, 1, 0, _signAnchor(brandPk, productId, ROOT_V1, 1, 0));
    }

    /*//////////////////////////////////////////////////////////////
                            SANITY GUARDS
    //////////////////////////////////////////////////////////////*/

    function test_RevertWhen_ProductIdIsZero() public {
        vm.prank(relayer);
        vm.expectRevert(TrustAnchorRegistry.ZeroProductId.selector);
        registry.claimProduct(bytes32(0), brand, 0, _signClaim(brandPk, bytes32(0), brand, 0));
    }

    function test_RevertWhen_ControllerIsZero() public {
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.ZeroController.selector, productId));
        registry.claimProduct(productId, address(0), 0, _signClaim(brandPk, productId, address(0), 0));
    }

    /// @notice Control cannot be "burned" back to `address(0)` — that would re-open the product to
    ///         squatting by anyone.
    function test_RevertWhen_TransferringControlToZero() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.ZeroController.selector, productId));
        registry.claimProduct(productId, address(0), 1, _signClaim(brandPk, productId, address(0), 1));
    }

    function test_RevertWhen_IssuerIsZero() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(TrustAnchorRegistry.ZeroIssuer.selector);
        registry.setIssuer(productId, address(0), true, 1, _signSetIssuer(brandPk, productId, address(0), true, 1));
    }

    function test_RevertWhen_MerkleRootIsZero() public {
        _claimForBrand();
        vm.prank(relayer);
        vm.expectRevert(TrustAnchorRegistry.ZeroMerkleRoot.selector);
        registry.anchor(productId, bytes32(0), 1, 1, _signAnchor(brandPk, productId, bytes32(0), 1, 1));
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Malleability: for every valid `(v, r, s)` there is a second, equally valid
    ///         `(v', r, N - s)` recovering the same address. Accepting both would mean one
    ///         authorization has two distinct on-chain representations.
    /// @dev Rejected by OpenZeppelin's `ECDSA`, which enforces `s <= N/2` (the EIP-2 / Homestead
    /// canonical form) *before* calling `ecrecover`, and reverts `ECDSAInvalidSignatureS`.
    function test_RevertWhen_SignatureIsMalleable_HighS() public {
        bytes32 digest = _digest(_claimStruct(productId, brand, 0), address(registry), block.chainid);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(brandPk, digest);

        // Flip to the high-s twin. Same recovered address, different bytes.
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        assertEq(ecrecover(digest, flippedV, r, highS), brand, "the twin really does recover to the signer");

        bytes memory malleable = abi.encodePacked(r, highS, flippedV);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, highS));
        registry.claimProduct(productId, brand, 0, malleable);
    }

    /// @notice `ecrecover` returns `address(0)` on failure rather than reverting. If that were not
    ///         checked, a garbage signature would "recover" to `address(0)` — which is exactly the
    ///         value an unclaimed product's controller has.
    function test_RevertWhen_SignatureIsAllZeroes() public {
        bytes memory zeroSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        vm.prank(relayer);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        registry.claimProduct(productId, brand, 0, zeroSig);
    }

    /// @notice The `address(0)` recovery hazard, stated directly: a signature that recovers to
    ///         zero must never be able to satisfy the "is the controller" check on an unclaimed
    ///         product. It cannot, because recovery reverts before the comparison happens.
    function test_ZeroRecoveryCannotImpersonateAnUnclaimedProductsController() public {
        bytes memory zeroSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));
        assertEq(registry.productController(productId), address(0), "product is unclaimed");
        vm.prank(relayer);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        registry.anchor(productId, ROOT_V1, 1, 0, zeroSig);
    }

    function test_RevertWhen_SignatureHasInvalidV() public {
        bytes32 digest = _digest(_claimStruct(productId, brand, 0), address(registry), block.chainid);
        (, bytes32 r, bytes32 s) = vm.sign(brandPk, digest);
        bytes memory badV = abi.encodePacked(r, s, uint8(29));
        vm.prank(relayer);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        registry.claimProduct(productId, brand, 0, badV);
    }

    function test_RevertWhen_SignatureIsWrongLength() public {
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, uint256(64)));
        registry.claimProduct(productId, brand, 0, new bytes(64));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, uint256(0)));
        registry.claimProduct(productId, brand, 0, "");
    }

    function test_RevertWhen_SignatureIsGarbage() public {
        bytes memory garbage = abi.encodePacked(keccak256("garbage-r"), keccak256("garbage-s"), uint8(27));
        vm.prank(relayer);
        vm.expectRevert(); // recovers to *some* address, never to `brand`
        registry.claimProduct(productId, brand, 0, garbage);
        assertEq(registry.productController(productId), address(0));
    }

    /// @notice A signature over a *different* payload than the one submitted is rejected: the
    ///         relayer cannot tamper with the arguments of a payload it is forwarding.
    function test_RevertWhen_RelayerTampersWithTheSignedArguments() public {
        _claimForBrand();
        // Brand authorised `supplier`. The relayer tries to forward it naming itself instead.
        bytes memory sig = _signSetIssuer(brandPk, productId, supplier, true, 1);
        vm.prank(relayer);
        vm.expectRevert();
        registry.setIssuer(productId, relayer, true, 1, sig);
        assertFalse(registry.authorized(productId, relayer));

        // Likewise the anchored root cannot be swapped in flight.
        bytes memory anchorSig = _signAnchor(brandPk, productId, ROOT_V1, 1, 1);
        vm.prank(relayer);
        vm.expectRevert();
        registry.anchor(productId, ROOT_V2, 1, 1, anchorSig);
    }

    /*//////////////////////////////////////////////////////////////
                                  FUZZ
    //////////////////////////////////////////////////////////////*/

    function _boundPk(uint256 seed) internal pure returns (uint256) {
        return _bound(seed, 1, SECP256K1_N - 1);
    }

    /// @notice Fuzz: state transition 1 — controller assignment.
    /// For any key, any product id and any submitting relayer, a self-signed claim installs the
    /// SIGNER as controller and never the submitter.
    function testFuzz_ClaimProduct(uint256 pkSeed, bytes32 pid, address submitter) public {
        uint256 pk = _boundPk(pkSeed);
        address owner = vm.addr(pk);
        vm.assume(pid != bytes32(0));

        vm.prank(submitter);
        registry.claimProduct(pid, owner, 0, _signClaim(pk, pid, owner, 0));

        assertEq(registry.productController(pid), owner);
        assertEq(registry.nonces(owner), 1);
        if (submitter != owner) {
            assertEq(registry.nonces(submitter), 0, "submitter never consumes a nonce");
            assertTrue(registry.productController(pid) != submitter, "submitter never becomes controller");
        }
    }

    /// @notice Fuzz: nobody but the key holder can claim a product for themselves.
    function testFuzz_ClaimProductRejectsForeignSigner(uint256 ownerSeed, uint256 attackerSeed, bytes32 pid) public {
        uint256 ownerPk = _boundPk(ownerSeed);
        uint256 attackerPk = _boundPk(attackerSeed);
        vm.assume(pid != bytes32(0));
        vm.assume(vm.addr(ownerPk) != vm.addr(attackerPk));

        address owner = vm.addr(ownerPk);
        vm.prank(hostileRelayer);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.ClaimMustBeSelfSigned.selector, pid, vm.addr(attackerPk), owner)
        );
        registry.claimProduct(pid, owner, 0, _signClaim(attackerPk, pid, owner, 0));
        assertEq(registry.productController(pid), address(0));
    }

    /// @notice Fuzz: state transition 2 — issuer authorization.
    /// Only the controller's signature moves the bit, for any issuer, any flag, any submitter.
    function testFuzz_SetIssuer(uint256 ctrlSeed, address issuer, bool ok, address submitter, bytes32 pid) public {
        uint256 ctrlPk = _boundPk(ctrlSeed);
        address controller = vm.addr(ctrlPk);
        vm.assume(pid != bytes32(0));
        vm.assume(issuer != address(0));

        vm.prank(submitter);
        registry.claimProduct(pid, controller, 0, _signClaim(ctrlPk, pid, controller, 0));

        vm.prank(submitter);
        registry.setIssuer(pid, issuer, ok, 1, _signSetIssuer(ctrlPk, pid, issuer, ok, 1));

        assertEq(registry.authorized(pid, issuer), ok);
        assertEq(registry.nonces(controller), 2);
        if (submitter != controller) assertEq(registry.nonces(submitter), 0);
    }

    /// @notice Fuzz: a non-controller can never move the issuer bit, whoever submits.
    function testFuzz_SetIssuerRejectsNonController(uint256 ctrlSeed, uint256 attackerSeed, address issuer) public {
        uint256 ctrlPk = _boundPk(ctrlSeed);
        uint256 attackerPk = _boundPk(attackerSeed);
        address controller = vm.addr(ctrlPk);
        address attacker = vm.addr(attackerPk);
        vm.assume(controller != attacker);
        vm.assume(issuer != address(0));

        vm.prank(relayer);
        registry.claimProduct(productId, controller, 0, _signClaim(ctrlPk, productId, controller, 0));

        // The attacker submits its own transaction *and* signs it — msg.sender buys nothing.
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(TrustAnchorRegistry.NotController.selector, productId, attacker, controller)
        );
        registry.setIssuer(productId, issuer, true, 0, _signSetIssuer(attackerPk, productId, issuer, true, 0));
        assertFalse(registry.authorized(productId, issuer));
    }

    /// @notice Fuzz: anchoring emits the signer, for any root/version/submitter.
    function testFuzz_AnchorAttributesToSigner(bytes32 root, uint64 version, address submitter) public {
        vm.assume(root != bytes32(0));
        _claimForBrand();

        vm.expectEmit(true, true, true, true, address(registry));
        emit Anchored(productId, root, version, brand);
        vm.prank(submitter);
        registry.anchor(productId, root, version, 1, _signAnchor(brandPk, productId, root, version, 1));
    }

    /// @notice Fuzz: any nonce other than the expected one is rejected.
    function testFuzz_WrongNonceAlwaysRejected(uint256 nonce) public {
        vm.assume(nonce != 0);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(TrustAnchorRegistry.InvalidNonce.selector, brand, 0, nonce));
        registry.claimProduct(productId, brand, nonce, _signClaim(brandPk, productId, brand, nonce));
    }

    /// @notice Fuzz: cross-chain replay fails for every chain id other than the signing one.
    function testFuzz_CrossChainReplayRejected(uint64 otherChainId) public {
        vm.assume(otherChainId != AMOY && otherChainId != 0);
        bytes memory amoySig = _signClaim(brandPk, productId, brand, 0);

        vm.chainId(otherChainId);
        vm.prank(relayer);
        vm.expectRevert();
        registry.claimProduct(productId, brand, 0, amoySig);
        assertEq(registry.productController(productId), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          MERKLE CONVENTION
    //////////////////////////////////////////////////////////////*/

    /// @dev Builds a root with the documented convention: leaves tagged 0x00, internal nodes
    /// tagged 0x01 over the value-sorted pair, odd node promoted unchanged.
    function _buildRoot(bytes32[] memory digests) internal view returns (bytes32) {
        uint256 n = digests.length;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            level[i] = registry.hashLeaf(digests[i]);
        }
        while (n > 1) {
            uint256 m = 0;
            for (uint256 i = 0; i + 1 < n; i += 2) {
                level[m++] = registry.hashNode(level[i], level[i + 1]);
            }
            if (n % 2 == 1) level[m++] = level[n - 1];
            n = m;
        }
        return level[0];
    }

    function test_Merkle_SingleLeafRootIsTheLeaf() public view {
        bytes32 d = keccak256("credential-0");
        assertEq(registry.verifyInclusion(registry.hashLeaf(d), d, new bytes32[](0)), true);
    }

    function test_Merkle_LeafAndNodeAreDomainSeparated() public view {
        bytes32 d = keccak256("x");
        assertEq(registry.hashLeaf(d), keccak256(abi.encodePacked(bytes1(0x00), d)));
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        assertEq(registry.hashNode(a, b), keccak256(abi.encodePacked(bytes1(0x01), a, b)));
        assertEq(registry.hashNode(b, a), registry.hashNode(a, b), "pair ordering is by value");
        // A node hash can never be mistaken for a leaf hash: different tags, different lengths.
        assertTrue(registry.hashNode(a, b) != registry.hashLeaf(a));
    }

    /// @notice Selective proof: one credential is proved against an anchored root without the
    ///         verifier holding the rest of the bundle.
    function test_Merkle_SelectiveInclusionProof() public view {
        bytes32[] memory digests = new bytes32[](4);
        digests[0] = keccak256("cred-a");
        digests[1] = keccak256("cred-b");
        digests[2] = keccak256("cred-c");
        digests[3] = keccak256("snapshot"); // snapshot digest appended last, per the convention

        bytes32 l0 = registry.hashLeaf(digests[0]);
        bytes32 l1 = registry.hashLeaf(digests[1]);
        bytes32 l2 = registry.hashLeaf(digests[2]);
        bytes32 l3 = registry.hashLeaf(digests[3]);
        bytes32 root = registry.hashNode(registry.hashNode(l0, l1), registry.hashNode(l2, l3));
        assertEq(root, _buildRoot(digests), "helper and hand-built tree agree");

        // Proof for cred-a: sibling leaf, then the right subtree root.
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = l1;
        proof[1] = registry.hashNode(l2, l3);
        assertTrue(registry.verifyInclusion(root, digests[0], proof));

        // A credential that was never in the set does not verify.
        assertFalse(registry.verifyInclusion(root, keccak256("cred-forged"), proof));
    }

    function testFuzz_MerkleInclusionForOddTrees(uint8 sizeSeed, uint8 indexSeed) public view {
        uint256 size = _bound(sizeSeed, 1, 33);
        uint256 idx = _bound(indexSeed, 0, size - 1);

        bytes32[] memory digests = new bytes32[](size);
        for (uint256 i = 0; i < size; ++i) {
            digests[i] = keccak256(abi.encode("cred", i));
        }
        bytes32 root = _buildRoot(digests);

        (bytes32[] memory proof) = _proofFor(digests, idx);
        assertTrue(registry.verifyInclusion(root, digests[idx], proof), "member verifies");
        assertFalse(registry.verifyInclusion(root, keccak256("not-a-member"), proof), "non-member does not");
    }

    /// @dev Reference proof builder matching {_buildRoot}'s promotion rule.
    function _proofFor(bytes32[] memory digests, uint256 idx) internal view returns (bytes32[] memory proof) {
        uint256 n = digests.length;
        bytes32[] memory level = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) {
            level[i] = registry.hashLeaf(digests[i]);
        }
        bytes32[] memory buf = new bytes32[](64);
        uint256 pLen = 0;
        uint256 pos = idx;
        while (n > 1) {
            uint256 m = 0;
            uint256 newPos = pos;
            for (uint256 i = 0; i + 1 < n; i += 2) {
                if (pos == i) {
                    buf[pLen++] = level[i + 1];
                    newPos = m;
                } else if (pos == i + 1) {
                    buf[pLen++] = level[i];
                    newPos = m;
                }
                level[m++] = registry.hashNode(level[i], level[i + 1]);
            }
            if (n % 2 == 1) {
                if (pos == n - 1) newPos = m;
                level[m++] = level[n - 1];
            }
            pos = newPos;
            n = m;
        }
        proof = new bytes32[](pLen);
        for (uint256 i = 0; i < pLen; ++i) {
            proof[i] = buf[i];
        }
    }

    /*//////////////////////////////////////////////////////////////
                            GAS MEASUREMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev Intrinsic tx cost (EIP-2028): 21000 base + 16 per non-zero calldata byte + 4 per zero.
    function _intrinsicGas(bytes memory callData) internal pure returns (uint256 g) {
        g = 21_000;
        for (uint256 i = 0; i < callData.length; ++i) {
            g += callData[i] == 0 ? 4 : 16;
        }
    }

    // Storage slots, per `forge inspect TrustAnchorRegistry storage-layout`.
    // 0-1 are OpenZeppelin EIP712's string fallbacks (unused: name and version both fit in 31 bytes).
    uint256 internal constant SLOT_PRODUCT_CONTROLLER = 2;
    uint256 internal constant SLOT_AUTHORIZED = 3;
    uint256 internal constant SLOT_NONCES = 4;

    /// @dev Mark every slot an operation touches as cold, so the measurement reflects a *standalone*
    /// transaction — which is what a relayer actually submits — rather than one warmed by earlier
    /// calls in the same test. The contract account itself is deliberately left warm: EIP-2929
    /// pre-warms a transaction's `to` address, so cooling it would overcharge by 2500 gas.
    function _coolSlots(bytes32 pid, address signer, address issuer) internal {
        vm.coolSlot(address(registry), keccak256(abi.encode(pid, SLOT_PRODUCT_CONTROLLER)));
        vm.coolSlot(address(registry), keccak256(abi.encode(signer, SLOT_NONCES)));
        vm.coolSlot(address(registry), keccak256(abi.encode(issuer, keccak256(abi.encode(pid, SLOT_AUTHORIZED)))));
    }

    /// @notice Records execution gas per operation and prints the full on-chain transaction cost a
    ///         relayer actually pays (execution + intrinsic + calldata). These are the numbers the
    ///         thesis reports for "gas per publish".
    /// @dev Every measured call is preceded by {_coolSlots}, so each figure is the cost of that
    /// operation as its own transaction, with cold storage — the realistic relayer cost.
    function test_Gas_PerOperation() public {
        // ── claimProduct: two cold SSTOREs from zero (controller + first nonce).
        bytes memory claimSig = _signClaim(brandPk, productId, brand, 0);
        bytes memory claimData = abi.encodeCall(TrustAnchorRegistry.claimProduct, (productId, brand, 0, claimSig));
        _coolSlots(productId, brand, supplier);
        vm.prank(relayer);
        registry.claimProduct(productId, brand, 0, claimSig);
        uint256 gClaim = vm.snapshotGasLastCall("TrustAnchorRegistry", "claimProduct");

        // ── setIssuer: one cold SSTORE from zero (authorization bit) + nonce update.
        bytes memory issuerSig = _signSetIssuer(brandPk, productId, supplier, true, 1);
        bytes memory issuerData =
            abi.encodeCall(TrustAnchorRegistry.setIssuer, (productId, supplier, true, 1, issuerSig));
        _coolSlots(productId, brand, supplier);
        vm.prank(relayer);
        registry.setIssuer(productId, supplier, true, 1, issuerSig);
        uint256 gIssuer = vm.snapshotGasLastCall("TrustAnchorRegistry", "setIssuer");

        // ── anchor: no storage but the nonce. This is the recurring per-publish cost.
        bytes memory anchorSig = _signAnchor(brandPk, productId, ROOT_V1, 1, 2);
        bytes memory anchorData = abi.encodeCall(TrustAnchorRegistry.anchor, (productId, ROOT_V1, 1, 2, anchorSig));
        _coolSlots(productId, brand, supplier);
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V1, 1, 2, anchorSig);
        uint256 gAnchor = vm.snapshotGasLastCall("TrustAnchorRegistry", "anchor");

        console2.log("=== gas, cold slots (standalone tx) ===");
        console2.log("           execution | intrinsic+calldata | TOTAL TX");
        console2.log("claimProduct", gClaim, _intrinsicGas(claimData), gClaim + _intrinsicGas(claimData));
        console2.log("setIssuer   ", gIssuer, _intrinsicGas(issuerData), gIssuer + _intrinsicGas(issuerData));
        console2.log("anchor      ", gAnchor, _intrinsicGas(anchorData), gAnchor + _intrinsicGas(anchorData));

        // Same three ops with slots already warm — the marginal cost when several land in one block
        // or are batched behind one another by the relayer.
        bytes memory anchor2Sig = _signAnchor(brandPk, productId, ROOT_V2, 2, 3);
        vm.prank(relayer);
        registry.anchor(productId, ROOT_V2, 2, 3, anchor2Sig);
        uint256 gAnchorWarm = vm.snapshotGasLastCall("TrustAnchorRegistry", "anchor_warmSlots");
        console2.log("anchor (warm slots, execution only)", gAnchorWarm);

        // Sanity floor: ecrecover alone is 3000 gas, so nothing here can be under that.
        assertGt(gAnchor, 3000);
    }

    /// @notice What the batch actually buys, on a four-supplier passport (RQ3).
    ///
    /// @dev Measured as TOTAL TRANSACTION cost — execution plus the intrinsic 21 000 and calldata —
    /// because the thing being compared is *four transactions against one*, and the per-transaction
    /// floor is most of the difference. An execution-only figure would understate the saving by the
    /// three base fees it hides, which is precisely the quantity a brand pays.
    ///
    /// Both sides authorize the same four addresses from cold slots, so the storage writes are
    /// identical and the delta is purely the per-transaction overhead the batch removes.
    function test_Gas_SetIssuersVersusFourSetIssuerCalls() public {
        address[] memory issuers = _fourSuppliers();

        // ── Four separate transactions, the pre-batch path.
        _claimForBrand();
        uint256 singlesTotal = 0;
        for (uint256 i = 0; i < issuers.length; ++i) {
            uint256 nonce = i + 1;
            bytes memory sig = _signSetIssuer(brandPk, productId, issuers[i], true, nonce);
            bytes memory data = abi.encodeCall(TrustAnchorRegistry.setIssuer, (productId, issuers[i], true, nonce, sig));
            _coolSlots(productId, brand, issuers[i]);
            vm.prank(relayer);
            registry.setIssuer(productId, issuers[i], true, nonce, sig);
            singlesTotal += vm.snapshotGasLastCall("TrustAnchorRegistry", "setIssuer_ofFour") + _intrinsicGas(data);
        }

        // ── One transaction, on a FRESH product so every slot is cold on this side too.
        bytes32 pid2 = keccak256("gas:batch");
        vm.prank(relayer);
        registry.claimProduct(pid2, brand, 5, _signClaim(brandPk, pid2, brand, 5));

        bytes memory batchSig = _signSetIssuers(brandPk, pid2, issuers, true, 6);
        bytes memory batchData = abi.encodeCall(TrustAnchorRegistry.setIssuers, (pid2, issuers, true, 6, batchSig));
        _coolSlots(pid2, brand, issuers[0]);
        vm.prank(relayer);
        registry.setIssuers(pid2, issuers, true, 6, batchSig);
        uint256 batchTotal = vm.snapshotGasLastCall("TrustAnchorRegistry", "setIssuers_four") + _intrinsicGas(batchData);

        console2.log("=== authorizing four suppliers, TOTAL TX gas ===");
        console2.log("4 x setIssuer", singlesTotal);
        console2.log("1 x setIssuers", batchTotal);
        console2.log("saved        ", singlesTotal - batchTotal);

        // The claim this change is made on. Four ecrecovers become one and three base fees vanish,
        // so the batch cannot merely tie — if this ever fails, the batch has stopped being worth
        // the extra function.
        assertLt(batchTotal, singlesTotal, "batching four grants must cost less than four transactions");
    }
}
