// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice A deliberately broken EIP-7702 delegate. DO NOT DEPLOY.
/// Each bug is a class documented in real delegates and audit write-ups (Nethermind, Fireblocks,
/// QuillAudits, go-ethereum #31485). The control suite exploits every one of them.
contract BrokenDelegate {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    // BUG (storage): plain slot 0, no ERC-7201 namespace. Collides with whatever a previous
    // delegate left in the account's storage.
    address public owner;

    // BUG (access control): anyone can make the account call anything. Nethermind's canonical
    // example of a delegate missing `msg.sender == address(this)`.
    function execute(Call[] calldata calls) external payable {
        _run(calls);
    }

    // BUG (front-running): 7702 runs no initcode, so setup is a separate call that anyone can make
    // between the delegation and the owner's own setup transaction.
    function initialize(address newOwner) external {
        require(owner == address(0), "initialized");
        owner = newOwner;
    }

    function ownerExecute(Call[] calldata calls) external {
        require(msg.sender == owner, "not owner");
        _run(calls);
    }

    // BUG (replay): the signature covers only the calls. No nonce, so it can be submitted again;
    // no chain id, so it is valid on every chain the account is delegated on.
    function executeWithSig(Call[] calldata calls, uint8 v, bytes32 r, bytes32 s) external {
        require(ecrecover(keccak256(abi.encode(calls)), v, r, s) == address(this), "bad sig");
        _run(calls);
    }

    receive() external payable {}

    function _run(Call[] calldata calls) internal {
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }
}
