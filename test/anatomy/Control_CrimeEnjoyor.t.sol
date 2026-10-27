// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {DelegateAttackSuite} from "../DelegateAttackSuite.sol";
import {CrimeEnjoyorV1Bytecode} from "./CrimeEnjoyorV1.bytecode.sol";
import {CrimeEnjoyorCloneBytecode} from "./CrimeEnjoyorClone.bytecode.sol";

/// @notice EXPECTED TO FAIL. The property suite run against the real CrimeEnjoyor bytecode copied
/// from Ethereum mainnet (no fork needed: the runtime code is pinned in the fixtures). The sweeper
/// has no signature path, so those properties are skipped rather than failed.
abstract contract Control_CrimeEnjoyor is DelegateAttackSuite {
    address internal sweeper = makeAddr("sweeper-impl");
    /// Where the legitimate owner would point the forwarder. Not the account itself: a forwarder
    /// whose destination is itself recurses on every receive() and reverts.
    address internal ownerVault = makeAddr("owner-vault");

    function _bytecode() internal pure virtual returns (bytes memory);
    function _codehash() internal pure virtual returns (bytes32);

    function _deployDelegate() internal override returns (address) {
        bytes memory code = _bytecode();
        assertEq(keccak256(code), _codehash(), "fixture does not match the pinned mainnet codehash");
        vm.etch(sweeper, code);
        return sweeper;
    }

    /// The victim's key is already in the attacker's hands; the "owner setup" that exists on-chain is
    /// the attacker's own initialize(). Here the legitimate owner tries to claim the destination.
    function _ownerSetup() internal override {
        _callAs(account, account, 0, abi.encodeWithSignature("initialize(address)", ownerVault));
    }

    /// Nothing to do: the sweeper never moves funds that are already there. It waits for new ones.
    function _attackDirect() internal override {}

    /// initialize() has no access control: whoever calls it first owns the destination.
    function _attackSetup() internal override {
        _callAs(attacker, account, 0, abi.encodeWithSignature("initialize(address)", attacker));
    }

    function _ownerSignsTransfer(uint256) internal pure override returns (bytes memory) {
        return "";
    }

    function _submit(bytes memory) internal pure override returns (bool) {
        return false;
    }

    function test_SignatureCannotBeReplayed() public override {
        vm.skip(true, "sweeper has no signature path");
    }

    function test_SignatureBoundToChain() public override {
        vm.skip(true, "sweeper has no signature path");
    }

    /// Extra: once initialized, every incoming wei is forwarded in the same transaction. A rescue
    /// attempt that tops the account up with gas money funds the attacker instead.
    function test_RescueGasIsSweptOnArrival() public {
        _attackSetup();
        vm.deal(bob, 0.05 ether);
        assertTrue(_callAs(bob, account, 0.05 ether, ""), "sweeper accepts plain ETH");
        assertEq(account.balance, START_ETH, "the rescue money never stayed");
        assertEq(attacker.balance, 0.05 ether, "it went straight to the attacker");
    }

    /// Extra: the sweeper works at the account level, so per-token approval monitoring sees nothing:
    /// there is no approval, no transferFrom, no token call at all. Only an internal ETH transfer.
    function test_NoApprovalNoTokenCall() public {
        _attackSetup();
        vm.deal(bob, 1 ether);
        vm.recordLogs();
        _callAs(bob, account, 1 ether, "");
        assertEq(vm.getRecordedLogs().length, 0, "not a single event is emitted");
    }
}

/// The original: 0x89383882Fc2D0Cd4d7952a3267A3b6dAE967E704 ("Crime Enjoyor: EIP-7702 Delegator 3").
contract Control_CrimeEnjoyorV1 is Control_CrimeEnjoyor {
    function _bytecode() internal pure override returns (bytes memory) {
        return CrimeEnjoyorV1Bytecode.code();
    }

    function _codehash() internal pure override returns (bytes32) {
        return CrimeEnjoyorV1Bytecode.CODEHASH;
    }

    /// v1 has no "already initialized" guard, so the real owner can re-claim the destination. The
    /// front-run is reversible here; the clone below closed that.
    function test_V1IsReinitializable() public {
        _attackSetup();
        _ownerSetup();
        vm.deal(bob, 1 ether);
        assertTrue(_callAs(bob, account, 1 ether, ""));
        assertEq(attacker.balance, 0, "the attacker lost the destination");
        assertEq(ownerVault.balance, 1 ether, "the owner re-claimed it");
    }
}

/// The clone: 0x0727ca41efc85f75cef26ee48f825893b4836786 (532k live accounts on Ethereum).
contract Control_CrimeEnjoyorClone is Control_CrimeEnjoyor {
    function _bytecode() internal pure override returns (bytes memory) {
        return CrimeEnjoyorCloneBytecode.code();
    }

    function _codehash() internal pure override returns (bytes32) {
        return CrimeEnjoyorCloneBytecode.CODEHASH;
    }

    /// The clone added an "Already initialized" guard: whoever initializes first keeps the account
    /// for as long as the delegation stands. The owner's only way out is re-delegation.
    function test_CloneFrontRunIsPermanent() public {
        _attackSetup();
        assertFalse(
            _callAs(account, account, 0, abi.encodeWithSignature("initialize(address)", account)),
            "owner cannot re-initialize"
        );
        vm.deal(bob, 1 ether);
        _callAs(bob, account, 1 ether, "");
        assertEq(attacker.balance, 1 ether);
    }

    /// Until someone initializes it, the clone rejects all incoming ETH ("Not initialized"), so a
    /// delegated-but-unclaimed account cannot even be paid.
    function test_UninitializedCloneRejectsEth() public {
        vm.deal(bob, 1 ether);
        assertFalse(_callAs(bob, account, 1 ether, ""));
    }
}
