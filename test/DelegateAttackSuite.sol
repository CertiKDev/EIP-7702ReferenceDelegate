// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MockToken} from "./mocks/MockToken.sol";

/// @notice Safety properties every EIP-7702 delegate should hold, written once and run against
/// several delegates through small adapters. The control delegates in test/control/ are expected
/// to fail these; the reference delegate must pass them.
abstract contract DelegateAttackSuite is Test {
    uint256 internal constant OWNER_PK = 0xA11CE;
    uint256 internal constant START_ETH = 10 ether;
    uint256 internal constant START_TOKENS = 1_000e18;

    address internal account; // the EOA that delegates; its key is OWNER_PK
    address internal attacker = makeAddr("attacker");
    address internal bob = makeAddr("bob");
    address internal relayer = makeAddr("relayer");
    MockToken internal token;

    // ---------------------------------------------------------------- adapters

    /// Deploys the delegate implementation under test.
    function _deployDelegate() internal virtual returns (address);

    /// The owner's own setup after delegating (initializer, allowlist, ...). May fail silently:
    /// the front-running test runs it after an attacker has already moved.
    function _ownerSetup() internal virtual;

    /// A third party with no signature from the owner tries to move the account's funds.
    function _attackDirect() internal virtual;

    /// A third party moves between the delegation and the owner's setup, then uses whatever it
    /// gained to move the account's funds.
    function _attackSetup() internal virtual;

    /// The owner signs a payload that makes the account send `amount` tokens to bob.
    function _ownerSignsTransfer(uint256 amount) internal virtual returns (bytes memory signed);

    /// Anyone submits a signed payload. Returns whether the submission succeeded.
    function _submit(bytes memory signed) internal virtual returns (bool ok);

    // ---------------------------------------------------------------- setup

    function setUp() public virtual {
        account = vm.addr(OWNER_PK);
        token = new MockToken();

        address impl = _deployDelegate();
        vm.signAndAttachDelegation(impl, OWNER_PK);
        // The authorization rides on this call. Per the spec the delegation is written even if the
        // carrier call reverts (an uninitialized CrimeEnjoyor rejects ETH, for instance), so the
        // call's result is irrelevant; the code check below is what matters.
        (bool ok,) = account.call("");
        (ok);

        // The designator is 23 bytes (EXTCODESIZE == 23), not the 2-byte 0xef01 of an old draft.
        assertEq(account.code, abi.encodePacked(hex"ef0100", impl));

        vm.deal(account, START_ETH);
        token.mint(account, START_TOKENS);
    }

    // ---------------------------------------------------------------- properties

    function test_ThirdPartyCannotMoveFunds() public virtual {
        _ownerSetup();
        _attackDirect();
        _assertUntouched();
    }

    function test_SetupCannotBeFrontRun() public virtual {
        _attackSetup();
        _ownerSetup();
        _assertUntouched();
    }

    function test_SignatureCannotBeReplayed() public virtual {
        _ownerSetup();
        bytes memory signed = _ownerSignsTransfer(1e18);
        assertTrue(_submit(signed), "first submission should succeed");

        _submit(signed); // same payload again
        assertEq(token.balanceOf(bob), 1e18, "signed transfer executed more than once");
    }

    function test_SignatureBoundToChain() public virtual {
        _ownerSetup();
        bytes memory signed = _ownerSignsTransfer(1e18); // signed for this chain

        vm.chainId(block.chainid + 1); // same account, same delegate, another 7702 chain
        _submit(signed);
        assertEq(token.balanceOf(bob), 0, "signature executed on a chain it was not signed for");
    }

    function test_IncomingEthStays() public virtual {
        _ownerSetup();
        vm.deal(bob, 1 ether);
        assertTrue(_callAs(bob, account, 1 ether, ""), "account must accept ETH");
        assertEq(account.balance, START_ETH + 1 ether, "incoming ETH did not stay in the account");
    }

    // ---------------------------------------------------------------- helpers

    function _assertUntouched() internal view {
        assertEq(account.balance, START_ETH, "ETH left the account");
        assertEq(token.balanceOf(account), START_TOKENS, "tokens left the account");
        assertEq(attacker.balance, 0, "attacker received ETH");
        assertEq(token.balanceOf(attacker), 0, "attacker received tokens");
    }

    function _callAs(address from, address to, uint256 value, bytes memory data) internal returns (bool ok) {
        vm.prank(from);
        (ok,) = to.call{value: value}(data);
    }
}
