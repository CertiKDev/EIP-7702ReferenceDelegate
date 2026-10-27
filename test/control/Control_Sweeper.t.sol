// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {DelegateAttackSuite} from "../DelegateAttackSuite.sol";
import {SweeperLike} from "./SweeperLike.sol";

/// @notice EXPECTED TO FAIL. Runs the property suite against a CrimeEnjoyor-style sweeper: funds
/// leave on arrival and on demand. The signature and setup properties don't apply (it has neither).
contract Control_Sweeper is DelegateAttackSuite {
    function _deployDelegate() internal override returns (address) {
        return address(new SweeperLike(attacker));
    }

    function _ownerSetup() internal override {}

    function _attackDirect() internal override {
        _callAs(attacker, account, 0, abi.encodeCall(SweeperLike.sweep, (address(token))));
    }

    function _attackSetup() internal override {}

    function _ownerSignsTransfer(uint256) internal pure override returns (bytes memory) {
        return "";
    }

    function _submit(bytes memory) internal pure override returns (bool) {
        return false;
    }

    function test_SetupCannotBeFrontRun() public override {
        vm.skip(true, "sweeper has no setup step");
    }

    function test_SignatureCannotBeReplayed() public override {
        vm.skip(true, "sweeper has no signature path");
    }

    function test_SignatureBoundToChain() public override {
        vm.skip(true, "sweeper has no signature path");
    }
}
