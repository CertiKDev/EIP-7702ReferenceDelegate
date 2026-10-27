// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, Vm} from "forge-std/Test.sol";
import {BrokenDelegate} from "./control/BrokenDelegate.sol";
import {ReferenceDelegate} from "../src/ReferenceDelegate.sol";

/// @notice EIP-7702 facts the talk relies on, as runnable tests (sections 1.1 and 2.3). Nothing here
/// is about this repo's delegate; it is about the protocol. MUST PASS.
contract Spec7702Test is Test {
    uint256 internal constant OWNER_PK = 0xA11CE;
    address internal account = vm.addr(OWNER_PK);
    address internal attacker = makeAddr("attacker");
    address internal impl;

    function setUp() public {
        impl = address(new ReferenceDelegate());
    }

    /// 1.1: the designator is 23 bytes; EXTCODESIZE sees it, EXTCODEHASH hashes it, neither follows it.
    function test_DesignatorIs23BytesAndIsNotFollowedByCodeReadingOpcodes() public {
        _delegate(impl);
        assertEq(account.code.length, 23);
        assertEq(account.code, abi.encodePacked(hex"ef0100", impl));
        assertEq(
            account.codehash,
            keccak256(abi.encodePacked(hex"ef0100", impl)),
            "hash of the designator, not of the delegate"
        );
        assertTrue(account.codehash != impl.codehash);
        // Code-executing opcodes do follow it: a call to the account runs the delegate.
        assertEq(ReferenceDelegate(payable(account)).DELEGATE(), impl);
    }

    /// 2.3: an authorization with chain_id = 0 is one and the same tuple on every chain: the chain id
    /// of the moment plays no part in the signature.
    function test_ChainIdZeroTupleIsIdenticalOnEveryChain() public {
        vm.chainId(1);
        Vm.SignedDelegation memory onMainnet = vm.signDelegation(impl, OWNER_PK, true);
        vm.chainId(10);
        Vm.SignedDelegation memory onOptimism = vm.signDelegation(impl, OWNER_PK, true);
        assertEq(onMainnet.r, onOptimism.r);
        assertEq(onMainnet.s, onOptimism.s);
        assertEq(onMainnet.v, onOptimism.v);
        assertEq(onMainnet.nonce, onOptimism.nonce);
    }

    /// ...and it delegates on whichever chain it lands on. One test per chain because Foundry's
    /// cheatcode tracks attached delegations itself; `integration/spec-demo.sh` does the same with
    /// one signature on two real Anvil chains.
    function test_ChainIdZeroTupleDelegatesOnChain1() public {
        _attachChainIdZeroTupleOn(1);
    }

    function test_ChainIdZeroTupleDelegatesOnChain10() public {
        _attachChainIdZeroTupleOn(10);
    }

    function _attachChainIdZeroTupleOn(uint256 chain) internal {
        vm.chainId(chain);
        Vm.SignedDelegation memory anyChain = vm.signDelegation(impl, OWNER_PK, true); // chain_id = 0
        vm.attachDelegation(anyChain, true);
        _carrier();
        assertEq(account.code, abi.encodePacked(hex"ef0100", impl));
    }

    /// 2.3: a tuple signed with the chain's own id does nothing anywhere else. This is the wallet's
    /// one job in the replay story: never sign with chain_id = 0.
    function test_ChainBoundAuthorizationIsRejectedElsewhere() public {
        Vm.SignedDelegation memory homeOnly = vm.signDelegation(impl, OWNER_PK); // chain_id = block.chainid

        vm.chainId(block.chainid + 1);
        (bool accepted,) = address(vm)
            .call(abi.encodeWithSignature("attachDelegation((uint8,bytes32,bytes32,uint64,address))", homeOnly));
        if (accepted) _carrier();
        assertEq(account.code.length, 0, "a tuple signed for the home chain must not delegate elsewhere");
    }

    /// 2.3: revoking (authorization to address(0)) clears the code and nothing else. Whatever the
    /// delegate stored stays under the EOA's address, and re-delegating to a delegate with the same
    /// layout brings it straight back. Here: an attacker-claimed slot-0 owner survives revocation.
    function test_RevocationLeavesStorageAndRedelegationRevivesIt() public {
        BrokenDelegate broken = new BrokenDelegate();
        _delegate(address(broken));
        vm.prank(attacker);
        BrokenDelegate(payable(account)).initialize(attacker);
        assertEq(BrokenDelegate(payable(account)).owner(), attacker);

        // The owner "revokes".
        _delegate(address(0));
        assertEq(account.code.length, 0, "code is cleared");
        assertEq(vm.load(account, 0), bytes32(uint256(uint160(attacker))), "slot 0 is not");

        // Months later the owner delegates again, to anything that keeps an owner in slot 0.
        _delegate(address(broken));
        assertEq(BrokenDelegate(payable(account)).owner(), attacker, "the attacker is back without lifting a finger");

        vm.deal(account, 1 ether);
        BrokenDelegate.Call[] memory calls = new BrokenDelegate.Call[](1);
        calls[0] = BrokenDelegate.Call(attacker, 1 ether, "");
        vm.prank(attacker);
        BrokenDelegate(payable(account)).ownerExecute(calls);
        assertEq(attacker.balance, 1 ether);
    }

    function _delegate(address to) internal {
        vm.signAndAttachDelegation(to, OWNER_PK);
        _carrier();
    }

    function _carrier() internal {
        (bool ok,) = account.call("");
        (ok);
    }
}
