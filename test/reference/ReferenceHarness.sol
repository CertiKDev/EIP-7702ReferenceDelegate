// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {DelegateAttackSuite} from "../DelegateAttackSuite.sol";
import {MockToken} from "../mocks/MockToken.sol";
import {ReferenceDelegate} from "../../src/ReferenceDelegate.sol";

/// @notice Adapters and helpers that run the property suite against ReferenceDelegate, going
/// through the real EntryPoint v0.8 (etched at its canonical address).
abstract contract ReferenceHarness is DelegateAttackSuite {
    EntryPoint internal constant ENTRY_POINT = EntryPoint(payable(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108));
    uint256 internal constant ATTACKER_PK = 0xBAD;
    uint256 internal constant GAS_CAP = 0.01 ether;
    uint256 internal constant TIMELOCK = 48 hours;

    // Gas fields of every test UserOp: worst case (500k + 1M + 50k) * 1 gwei = 0.00155 ETH.
    uint256 internal constant VERIFICATION_GAS = 500_000;
    uint256 internal constant CALL_GAS = 1_000_000;
    uint256 internal constant PRE_VERIFICATION_GAS = 50_000;
    uint256 internal constant FEE = 1 gwei;

    address internal carol = makeAddr("carol");
    ReferenceDelegate internal impl;
    ReferenceDelegate internal acct; // the account, seen through the delegate's ABI

    function setUp() public virtual override {
        super.setUp();
        acct = ReferenceDelegate(payable(account));
    }

    // ---------------------------------------------------------------- adapters

    function _deployDelegate() internal override returns (address) {
        vm.etch(address(ENTRY_POINT), address(new EntryPoint()).code);
        impl = new ReferenceDelegate();
        return address(impl);
    }

    /// Same-tx setup by the owner: allow token transfers to bob, then raise the gas cap from 0.
    function _ownerSetup() internal override {
        _asOwner(abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.transfer.selector, 0, false)));
        _asOwner(abi.encodeCall(ReferenceDelegate.addRecipient, (bob)));
        _asOwner(abi.encodeCall(ReferenceDelegate.proposeGasCap, (GAS_CAP)));
        vm.warp(block.timestamp + TIMELOCK);
        _asOwner(abi.encodeCall(ReferenceDelegate.applyGasCap, ()));
    }

    function _attackDirect() internal override {
        // 1. the self path
        _callAs(attacker, account, 0, abi.encodeCall(ReferenceDelegate.execute, (_drainCalls())));
        // 2. the EntryPoint-only hook, called directly
        PackedUserOperation memory op = _op(_drainCalls());
        _callAs(attacker, account, 0, abi.encodeWithSelector(ReferenceDelegate.executeUserOp.selector, op, bytes32(0)));
        // 3. a UserOp signed with a key that isn't the account's
        _handle(_sign(op, ATTACKER_PK));
    }

    function _attackSetup() internal override {
        _callAs(attacker, account, 0, abi.encodeCall(ReferenceDelegate.addRecipient, (attacker)));
        _callAs(
            attacker,
            account,
            0,
            abi.encodeCall(ReferenceDelegate.allowCall, (address(token), MockToken.transfer.selector, 0, true))
        );
        _callAs(attacker, account, 0, abi.encodeCall(ReferenceDelegate.proposeGasCap, (type(uint256).max)));
        vm.warp(block.timestamp + TIMELOCK);
        _callAs(attacker, account, 0, abi.encodeCall(ReferenceDelegate.execute, (_drainCalls())));
    }

    function _ownerSignsTransfer(uint256 amount) internal view override returns (bytes memory) {
        return abi.encode(_sign(_op(_transfer(bob, amount)), OWNER_PK));
    }

    function _submit(bytes memory signed) internal override returns (bool) {
        return _handle(abi.decode(signed, (PackedUserOperation)));
    }

    // ---------------------------------------------------------------- helpers

    function _asOwner(bytes memory data) internal {
        assertTrue(_callAs(account, account, 0, data), "owner self-call failed");
    }

    function _one(address target, uint256 value, bytes memory data)
        internal
        pure
        returns (ReferenceDelegate.Call[] memory calls)
    {
        calls = new ReferenceDelegate.Call[](1);
        calls[0] = ReferenceDelegate.Call(target, value, data);
    }

    function _transfer(address to, uint256 amount) internal view returns (ReferenceDelegate.Call[] memory) {
        return _one(address(token), 0, abi.encodeCall(MockToken.transfer, (to, amount)));
    }

    function _drainCalls() internal view returns (ReferenceDelegate.Call[] memory calls) {
        calls = new ReferenceDelegate.Call[](2);
        calls[0] =
            ReferenceDelegate.Call(address(token), 0, abi.encodeCall(MockToken.transfer, (attacker, START_TOKENS)));
        calls[1] = ReferenceDelegate.Call(attacker, START_ETH, "");
    }

    /// A UserOp in the shape the delegate requires: executeUserOp callData and the current policy
    /// epoch as nonce key. No initCode: the account is already delegated.
    function _op(ReferenceDelegate.Call[] memory calls) internal view returns (PackedUserOperation memory) {
        return _opWithKey(calls, acct.policyEpoch());
    }

    function _opWithKey(ReferenceDelegate.Call[] memory calls, uint192 key)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = account;
        op.nonce = ENTRY_POINT.getNonce(account, key);
        op.callData = abi.encodePacked(ReferenceDelegate.executeUserOp.selector, abi.encode(calls));
        op.accountGasLimits = bytes32((VERIFICATION_GAS << 128) | CALL_GAS);
        op.preVerificationGas = PRE_VERIFICATION_GAS;
        op.gasFees = bytes32((FEE << 128) | FEE);
    }

    /// Signs the way the reference delegate expects: the delegate-bound EIP-712 digest.
    function _sign(PackedUserOperation memory op, uint256 pk) internal view returns (PackedUserOperation memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _signingHash(ENTRY_POINT.getUserOpHash(op)));
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    /// Signs the plain userOpHash, the way Simple7702Account (and most delegates) expect.
    function _signPlain(PackedUserOperation memory op, uint256 pk) internal view returns (PackedUserOperation memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ENTRY_POINT.getUserOpHash(op));
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    /// The digest from the delegate's docs, computed here independently of the contract.
    function _signingHash(bytes32 userOpHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ReferenceDelegate"),
                keccak256("1"),
                block.chainid,
                account
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(keccak256("DelegatedUserOp(bytes32 userOpHash,address delegate)"), userOpHash, address(impl))
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _ops(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /// Submits as a bundler. True if the bundle landed (the op's execution may still have reverted).
    function _handle(PackedUserOperation memory op) internal returns (bool ok) {
        PackedUserOperation[] memory ops = _ops(op);
        vm.prank(relayer, relayer);
        try ENTRY_POINT.handleOps(ops, payable(relayer)) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    function _redelegate(address delegate) internal {
        vm.signAndAttachDelegation(delegate, OWNER_PK);
        (bool ok,) = account.call("");
        require(ok, "redelegation call failed");
    }
}
