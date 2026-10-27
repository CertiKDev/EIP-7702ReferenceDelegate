// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {DelegateAttackSuite} from "../DelegateAttackSuite.sol";
import {MockToken} from "../mocks/MockToken.sol";
import {BrokenDelegate} from "./BrokenDelegate.sol";

/// @notice EXPECTED TO FAIL. Runs the property suite against BrokenDelegate: every property except
/// IncomingEthStays is broken. (A delegate can be buggy without being a sweeper.)
contract Control_BrokenDelegate is DelegateAttackSuite {
    function _deployDelegate() internal override returns (address) {
        return address(new BrokenDelegate());
    }

    function _ownerSetup() internal override {
        // The owner's own tx to itself, sent after the delegation landed.
        _callAs(account, account, 0, abi.encodeCall(BrokenDelegate.initialize, (account)));
    }

    function _attackDirect() internal override {
        _callAs(attacker, account, 0, abi.encodeCall(BrokenDelegate.execute, (_drainCalls())));
    }

    function _attackSetup() internal override {
        _callAs(attacker, account, 0, abi.encodeCall(BrokenDelegate.initialize, (attacker)));
        _callAs(attacker, account, 0, abi.encodeCall(BrokenDelegate.ownerExecute, (_drainCalls())));
    }

    function _ownerSignsTransfer(uint256 amount) internal view override returns (bytes memory) {
        BrokenDelegate.Call[] memory calls = new BrokenDelegate.Call[](1);
        calls[0] = BrokenDelegate.Call(address(token), 0, abi.encodeCall(MockToken.transfer, (bob, amount)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, keccak256(abi.encode(calls)));
        return abi.encodeCall(BrokenDelegate.executeWithSig, (calls, v, r, s));
    }

    function _submit(bytes memory signed) internal override returns (bool) {
        return _callAs(relayer, account, 0, signed);
    }

    function _drainCalls() internal view returns (BrokenDelegate.Call[] memory calls) {
        calls = new BrokenDelegate.Call[](2);
        calls[0] = BrokenDelegate.Call(address(token), 0, abi.encodeCall(MockToken.transfer, (attacker, START_TOKENS)));
        calls[1] = BrokenDelegate.Call(attacker, START_ETH, "");
    }
}
