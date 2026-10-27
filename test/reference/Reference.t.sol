// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Simple7702Account} from "account-abstraction/accounts/Simple7702Account.sol";
import {ReferenceHarness} from "./ReferenceHarness.sol";
import {MockToken} from "../mocks/MockToken.sol";
import {BrokenDelegate} from "../control/BrokenDelegate.sol";
import {ReferenceDelegate} from "../../src/ReferenceDelegate.sol";

contract PayableVault {
    function deposit() external payable {}
}

/// @notice MUST PASS. The shared property suite (inherited) plus the reference-specific
/// properties.
contract ReferenceDelegateTest is ReferenceHarness {
    bytes32 internal constant STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("reference-delegate.storage.v1")) - 1)) & ~bytes32(uint256(0xff));
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // ---------------------------------------------------------------- allowlist

    function test_OnlyAllowlistedTargets() public {
        _ownerSetup();
        MockToken other = new MockToken();
        other.mint(account, 1e18);

        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReferenceDelegate.CallNotAllowed.selector, address(other), MockToken.transfer.selector
            )
        );
        acct.execute(_one(address(other), 0, abi.encodeCall(MockToken.transfer, (bob, 1e18))));

        vm.prank(account);
        acct.execute(_transfer(bob, 1e18));
        assertEq(token.balanceOf(bob), 1e18);
    }

    function test_SelectorMismatchReverts() public {
        _ownerSetup();
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReferenceDelegate.CallNotAllowed.selector, address(token), MockToken.approve.selector
            )
        );
        acct.execute(_one(address(token), 0, abi.encodeCall(MockToken.approve, (bob, 1))));
    }

    function test_Tier1RecipientChecked() public {
        _ownerSetup();
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, carol));
        acct.execute(_transfer(carol, 1e18));
    }

    function test_Tier1SpenderChecked() public {
        _ownerSetup();
        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.approve.selector, 0, false)));

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotSpender.selector, carol));
        acct.execute(_one(address(token), 0, abi.encodeCall(MockToken.approve, (carol, 1))));

        _asOwner(abi.encodeCall(ReferenceDelegate.addSpender, (carol)));
        vm.warp(block.timestamp + TIMELOCK);
        vm.prank(account);
        acct.execute(_one(address(token), 0, abi.encodeCall(MockToken.approve, (carol, 1))));
        assertEq(token.allowance(account, carol), 1);
    }

    /// `approve(x, 0)` looks like a revocation, but the same selector is ERC-721 `approve(to, tokenId)`
    /// and 0 is a valid tokenId. It must not be exempt.
    function test_Tier1ApproveZeroIsNotExempt() public {
        _ownerSetup();
        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.approve.selector, 0, false)));
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotSpender.selector, attacker));
        acct.execute(_one(address(token), 0, abi.encodeCall(MockToken.approve, (attacker, 0))));
    }

    /// The account's EntryPoint gas deposit is an asset: `depositTo(x)` with value credits x.
    function test_Tier1EntryPointDepositChecked() public {
        _ownerSetup();
        bytes4 depositTo = bytes4(keccak256("depositTo(address)"));
        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(ENTRY_POINT), depositTo, 0, true)));
        vm.warp(block.timestamp + TIMELOCK);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, attacker));
        acct.execute(_one(address(ENTRY_POINT), 1 ether, abi.encodeWithSelector(depositTo, attacker)));
        assertEq(ENTRY_POINT.balanceOf(attacker), 0);

        vm.prank(account);
        acct.execute(_one(address(ENTRY_POINT), 1 ether, abi.encodeWithSelector(depositTo, account)));
        assertEq(ENTRY_POINT.balanceOf(account), 1 ether);
    }

    function test_ValueOnlyToRecipientWithEmptyCalldata() public {
        _ownerSetup();

        vm.prank(account);
        acct.execute(_one(bob, 1 ether, ""));
        assertEq(bob.balance, 1 ether);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, attacker));
        acct.execute(_one(attacker, 1 ether, ""));
    }

    function test_ValueBitTimelocked() public {
        _ownerSetup();
        PayableVault vault = new PayableVault();
        ReferenceDelegate.Call[] memory deposit =
            _one(address(vault), 1 ether, abi.encodeCall(PayableVault.deposit, ()));

        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(vault), PayableVault.deposit.selector, 0, false)));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReferenceDelegate.ValueNotAllowed.selector, address(vault), PayableVault.deposit.selector
            )
        );
        acct.execute(deposit);

        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(vault), PayableVault.deposit.selector, 0, true)));
        vm.prank(account);
        vm.expectRevert(
            abi.encodeWithSelector(
                ReferenceDelegate.ValueNotAllowed.selector, address(vault), PayableVault.deposit.selector
            )
        );
        acct.execute(deposit);

        vm.warp(block.timestamp + TIMELOCK);
        vm.prank(account);
        acct.execute(deposit);
        assertEq(address(vault).balance, 1 ether);
    }

    function test_RecipientAdditionTimelocked() public {
        _ownerSetup();
        _asOwner(abi.encodeCall(ReferenceDelegate.addRecipient, (carol)));

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, carol));
        acct.execute(_transfer(carol, 1e18));

        vm.warp(block.timestamp + TIMELOCK - 1);
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, carol));
        acct.execute(_transfer(carol, 1e18));

        vm.warp(block.timestamp + 1);
        vm.prank(account);
        acct.execute(_transfer(carol, 1e18));
        assertEq(token.balanceOf(carol), 1e18);

        _asOwner(abi.encodeCall(ReferenceDelegate.removeRecipient, (carol)));
        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.NotRecipient.selector, carol));
        acct.execute(_transfer(carol, 1e18));
    }

    function testFuzz_TokensOnlyReachAllowedParties(uint8 which, address to, uint96 amount) public {
        _ownerSetup();
        vm.assume(to != bob && to != account && to != address(0));
        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.approve.selector, 0, false)));
        _asOwner(
            abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.transferFrom.selector, 0, false))
        );

        bytes memory data;
        if (which % 3 == 0) data = abi.encodeCall(MockToken.transfer, (to, amount));
        else if (which % 3 == 1) data = abi.encodeCall(MockToken.approve, (to, amount));
        else data = abi.encodeCall(MockToken.transferFrom, (account, to, amount));

        bool ok =
            _callAs(account, account, 0, abi.encodeCall(ReferenceDelegate.execute, (_one(address(token), 0, data))));
        assertFalse(ok, "call to a non-allowlisted party went through");
        assertEq(token.balanceOf(to), 0);
        assertEq(token.allowance(account, to), 0);
    }

    // ---------------------------------------------------------------- who may execute

    /// The policy alone would allow these calls (bob is a recipient), so only the caller checks stop
    /// a stranger from spending the account's funds on its own behalf.
    function test_OnlySelfAndEntryPointCanExecute() public {
        _ownerSetup();

        vm.prank(attacker);
        vm.expectRevert(ReferenceDelegate.Unauthorized.selector);
        acct.execute(_transfer(bob, 1e18));

        PackedUserOperation memory op = _op(_transfer(bob, 1e18));
        vm.prank(attacker);
        vm.expectRevert(ReferenceDelegate.Unauthorized.selector);
        (bool ok,) = account.call(abi.encodeWithSelector(ReferenceDelegate.executeUserOp.selector, op, bytes32(0)));
        ok;

        vm.prank(attacker);
        vm.expectRevert(ReferenceDelegate.Unauthorized.selector);
        (ok,) = account.call(abi.encodeWithSelector(ReferenceDelegate.validateUserOp.selector, op, bytes32(0), 1 ether));
        ok;

        assertEq(token.balanceOf(bob), 0);
        assertEq(account.balance, START_ETH);
    }

    // ---------------------------------------------------------------- policy can't be changed from inside

    function test_EntryPointCannotMutatePolicy() public {
        _ownerSetup();
        vm.prank(address(ENTRY_POINT));
        vm.expectRevert(ReferenceDelegate.Unauthorized.selector);
        acct.addRecipient(attacker);

        // A signed UserOp whose batch targets the account itself lands, but its execution reverts.
        PackedUserOperation memory op =
            _sign(_op(_one(account, 0, abi.encodeCall(ReferenceDelegate.addRecipient, (attacker)))), OWNER_PK);
        assertTrue(_handle(op));
        vm.warp(block.timestamp + TIMELOCK);
        assertFalse(acct.isRecipient(attacker));
        assertEq(acct.recipients().length, 1);
    }

    function test_BatchCannotMutatePolicy() public {
        _ownerSetup();
        vm.prank(account);
        vm.expectRevert(ReferenceDelegate.SelfCallBlocked.selector);
        acct.execute(_one(account, 0, abi.encodeCall(ReferenceDelegate.addRecipient, (attacker))));
    }

    // ---------------------------------------------------------------- 4337 replay and gas

    /// Issue A, both directions. The EntryPoint nonce is shared by every delegate the EOA uses, and
    /// without the 0x7702 initCode marker the EntryPoint's userOpHash is the same under all of them.
    /// Only the signed digest tells delegates apart.
    function test_CrossDelegateReplayRejected() public {
        _ownerSetup();
        Simple7702Account simple = new Simple7702Account();
        PackedUserOperation memory op = _op(_transfer(bob, 1e18));
        bytes32 hashUnderReference = ENTRY_POINT.getUserOpHash(op);

        // (1) Signed for Simple7702Account (plain userOpHash), replayed back under the reference delegate.
        _redelegate(address(simple));
        assertEq(ENTRY_POINT.getUserOpHash(op), hashUnderReference, "the EntryPoint hash ignores the delegate");
        PackedUserOperation memory forSimple = _signPlain(op, OWNER_PK);
        _redelegate(address(impl));

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        ENTRY_POINT.handleOps(_ops(forSimple), payable(relayer));

        // (2) Signed for the reference delegate, replayed after moving to Simple7702Account.
        PackedUserOperation memory forReference = _sign(op, OWNER_PK);
        _redelegate(address(simple));

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(relayer, relayer);
        ENTRY_POINT.handleOps(_ops(forReference), payable(relayer));

        assertEq(token.balanceOf(bob), 0);
    }

    function test_UserOpSigningHashIsDelegateBound() public {
        bytes32 userOpHash = keccak256("some userOpHash");
        assertEq(acct.userOpSigningHash(userOpHash), _signingHash(userOpHash), "matches the documented digest");
        assertEq(acct.DELEGATE(), address(impl), "under delegation DELEGATE names the implementation");

        // Even another deployment of the same code (an old version, say) signs a different digest.
        _redelegate(address(new ReferenceDelegate()));
        assertTrue(acct.userOpSigningHash(userOpHash) != _signingHash(userOpHash));
    }

    /// No initCode is needed: bundlers that demand an eip7702Auth for the 0x7702 marker never see one.
    function test_PlainUserOpWorksWithoutInitCode() public {
        _ownerSetup();
        PackedUserOperation memory op = _sign(_op(_transfer(bob, 1e18)), OWNER_PK);
        assertEq(op.initCode.length, 0);
        assertTrue(_handle(op));
        assertEq(token.balanceOf(bob), 1e18);
    }

    /// Issue B. A phisher holds an op that fails today and submits it after the policy widens.
    function test_HeldSignatureDiesOnPolicyChange() public {
        _ownerSetup();
        uint192 signedEpoch = acct.policyEpoch();
        PackedUserOperation memory held = _sign(_op(_transfer(carol, 1e18)), OWNER_PK);

        _asOwner(abi.encodeCall(ReferenceDelegate.addRecipient, (carol)));
        vm.warp(block.timestamp + TIMELOCK);
        assertEq(acct.policyEpoch(), signedEpoch + 1);

        uint256 ethBefore = account.balance;
        vm.expectEmit(true, true, false, true, address(ENTRY_POINT));
        emit IEntryPoint.UserOperationRevertReason(
            ENTRY_POINT.getUserOpHash(held),
            account,
            held.nonce,
            abi.encodeWithSelector(ReferenceDelegate.StalePolicyEpoch.selector, signedEpoch, signedEpoch + 1)
        );
        assertTrue(_handle(held), "validation can't read the epoch, so the bundle lands");
        assertEq(token.balanceOf(carol), 0, "held op executed under the new policy");
        assertLe(ethBefore - account.balance, GAS_CAP, "griefing is bounded by the gas cap");
        assertFalse(_handle(held), "its nonce is consumed");

        assertTrue(_handle(_sign(_op(_transfer(carol, 1e18)), OWNER_PK)));
        assertEq(token.balanceOf(carol), 1e18, "a fresh op under the new epoch works");
    }

    /// A phished UserOp with an absurd fee would pay the bundler (who may be the attacker).
    function test_GasCapBlocksFeeDrain() public {
        _ownerSetup();
        PackedUserOperation memory op = _op(_transfer(bob, 1));
        uint256 fee = 1000 gwei;
        op.gasFees = bytes32((fee << 128) | fee);
        op = _sign(op, OWNER_PK);
        uint256 maxCost = (VERIFICATION_GAS + CALL_GAS + PRE_VERIFICATION_GAS) * fee;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(ReferenceDelegate.GasCapExceeded.selector, maxCost, GAS_CAP)
            )
        );
        vm.prank(relayer, relayer);
        ENTRY_POINT.handleOps(_ops(op), payable(relayer));
        assertEq(account.balance, START_ETH);
    }

    function test_GasCapRaiseTimelockedLowerInstant() public {
        _ownerSetup();
        _asOwner(abi.encodeCall(ReferenceDelegate.proposeGasCap, (1 ether)));
        (uint256 cap,,) = acct.gasCap();
        assertEq(cap, GAS_CAP);

        vm.prank(account);
        vm.expectRevert(abi.encodeWithSelector(ReferenceDelegate.GasCapTimelocked.selector, block.timestamp + TIMELOCK));
        acct.applyGasCap();

        vm.warp(block.timestamp + TIMELOCK);
        _asOwner(abi.encodeCall(ReferenceDelegate.applyGasCap, ()));
        (cap,,) = acct.gasCap();
        assertEq(cap, 1 ether);

        _asOwner(abi.encodeCall(ReferenceDelegate.proposeGasCap, (0)));
        (cap,,) = acct.gasCap();
        assertEq(cap, 0);
    }

    // ---------------------------------------------------------------- storage and revocation

    /// The account previously ran BrokenDelegate and an attacker grabbed its slot-0 owner. Back on
    /// the reference delegate, the leftover slot means nothing.
    function test_StorageCollisionSafeOnRedelegate() public {
        _redelegate(address(new BrokenDelegate()));
        _callAs(attacker, account, 0, abi.encodeCall(BrokenDelegate.initialize, (attacker)));
        assertEq(address(uint160(uint256(vm.load(account, 0)))), attacker);

        _redelegate(address(impl));
        _attackDirect();
        _assertUntouched();
        assertEq(acct.accountStorageBases()[0], STORAGE_SLOT);
    }

    function test_RevokeWipesPolicyKeepsNonce() public {
        _ownerSetup();
        _asOwner(abi.encodeCall(ReferenceDelegate.addSpender, (carol)));
        PackedUserOperation memory held = _sign(_op(_transfer(bob, 1e18)), OWNER_PK);
        uint192 epochBefore = acct.policyEpoch();
        uint256 nonceBefore = ENTRY_POINT.getNonce(account, epochBefore);

        _asOwner(abi.encodeCall(ReferenceDelegate.revoke, ()));

        assertEq(acct.policyEpoch(), epochBefore + 1);
        assertEq(ENTRY_POINT.getNonce(account, epochBefore), nonceBefore, "revoke never touches nonces");
        assertEq(acct.callRules().length, 0);
        assertEq(acct.recipients().length, 0);
        assertEq(acct.spenders().length, 0);
        assertFalse(acct.isRecipient(bob));
        assertFalse(acct.callRule(address(token), MockToken.transfer.selector).allowed);
        assertFalse(_handle(held), "op signed before revoke still executed");
        assertEq(token.balanceOf(bob), 0);

        // The real revocation is an authorization to address(0). Storage survives it, which is why
        // revoke() wipes first: the namespace must be empty afterwards.
        _redelegate(address(0));
        assertEq(account.code.length, 0);
        // Layout has 9 top-level slots: 2 arrays, 2 mappings, 2 arrays, 3 uint256.
        for (uint256 i; i < 9; ++i) {
            assertEq(vm.load(account, bytes32(uint256(STORAGE_SLOT) + i)), bytes32(0));
        }
        bytes32 recipientSlot = keccak256(abi.encode(bob, uint256(STORAGE_SLOT) + 3));
        assertEq(vm.load(account, recipientSlot), bytes32(0));
        bytes32 ruleSlot = keccak256(
            abi.encode(MockToken.transfer.selector, keccak256(abi.encode(address(token), uint256(STORAGE_SLOT) + 1)))
        );
        assertEq(vm.load(account, ruleSlot), bytes32(0));
    }

    // ---------------------------------------------------------------- signatures and hooks

    function test_IsValidSignatureIsPlainEoaBehaviour() public view {
        bytes32 hash = keccak256("any message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, hash);
        assertEq(acct.isValidSignature(hash, abi.encodePacked(r, s, v)), bytes4(0x1626ba7e));

        // The malleable twin (s' = n - s, v flipped) is rejected.
        bytes32 sHigh = bytes32(SECP256K1_N - uint256(s));
        assertEq(
            acct.isValidSignature(hash, abi.encodePacked(r, sHigh, v == 27 ? uint8(28) : uint8(27))), bytes4(0xffffffff)
        );

        (v, r, s) = vm.sign(ATTACKER_PK, hash);
        assertEq(acct.isValidSignature(hash, abi.encodePacked(r, s, v)), bytes4(0xffffffff));
    }

    /// No fallback: a mistyped config call reverts instead of succeeding silently, and ETH with
    /// non-empty calldata is refused. Plain ETH still lands (IncomingEthStays).
    function test_UnknownSelectorReverts() public {
        vm.deal(bob, 2 ether);
        bytes memory typo = abi.encodeWithSignature("addRecipeint(address)", bob);
        assertFalse(_callAs(account, account, 0, typo), "mistyped config call must revert");
        assertFalse(_callAs(bob, account, 1 ether, hex"deadbeef"), "ETH with calldata must revert");
        assertTrue(_callAs(bob, account, 1 ether, ""), "plain ETH must land");
        assertEq(account.balance, START_ETH + 1 ether);
    }

    function test_ReceiverHooksAndInterfaces() public view {
        assertEq(acct.onERC721Received(address(0), address(0), 0, ""), bytes4(0x150b7a02));
        assertEq(acct.onERC1155Received(address(0), address(0), 0, 0, ""), bytes4(0xf23a6e61));
        assertTrue(acct.supportsInterface(0x01ffc9a7)); // ERC-165
        assertTrue(acct.supportsInterface(0x1626ba7e)); // ERC-1271
        assertTrue(acct.supportsInterface(0x150b7a02)); // ERC-721 receiver
        assertTrue(acct.supportsInterface(0x4e2312e0)); // ERC-1155 receiver
        assertFalse(acct.supportsInterface(0xffffffff));
    }
}
