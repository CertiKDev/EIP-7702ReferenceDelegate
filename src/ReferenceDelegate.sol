// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @dev The two EntryPoint v0.8 nonce functions the delegate uses. Declared locally: the
/// eth-infinitism sources are GPL-3.0.
interface IEntryPointNonces {
    function getNonce(address sender, uint192 key) external view returns (uint256);
    function incrementNonce(uint192 key) external;
}

/// @title ReferenceDelegate (placeholder name)
/// @notice A minimal EIP-7702 delegate.
///
/// Execution paths
///   1. `execute`: the EOA's own transaction to itself (`msg.sender == address(this)`).
///   2. ERC-4337 via EntryPoint v0.8: `validateUserOp` + `executeUserOp`.
/// Both run every call through the same policy:
///   - Tier 2 (user-set): a (target, selector) allowlist, optional recipient argument check, and a
///     value bit that only takes effect after TIMELOCK.
///   - Tier 1 (fixed): known token-moving selectors must name an allowlisted recipient or spender.
///     Tier 1 only restricts; it never grants a call that Tier 2 doesn't list.
///   - Plain ETH sends (empty calldata) only go to recipients. Calls to the account itself are
///     always blocked, so a batch can never change the policy.
/// Policy changes are self-calls only. Each one bumps a policy epoch kept in the EntryPoint, which
/// kills every UserOp signed under the previous policy.
///
/// UserOp signatures are over `userOpSigningHash(userOpHash)`, an EIP-712 digest that names this
/// delegate's own address. A signature made for this delegate is useless under any other one, and
/// vice versa, even though the EntryPoint nonce is shared by every delegate the EOA ever uses.
contract ReferenceDelegate is ReentrancyGuardTransient {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    struct CallRule {
        bool allowed;
        uint8 recipientArg; // 0 = none, n = static argument n-1 must be a recipient
        uint256 valueActiveAt; // 0 = no ETH value
    }

    struct RuleKey {
        address target;
        bytes4 selector;
    }

    enum Party {
        None,
        Recipient,
        Spender,
        Blocked
    }

    /// @custom:storage-location erc7201:reference-delegate.storage.v1
    struct Layout {
        RuleKey[] ruleKeys;
        mapping(address target => mapping(bytes4 selector => CallRule)) rules;
        address[] recipients;
        mapping(address recipient => uint256 activeAt) recipientActiveAt;
        address[] spenders;
        mapping(address spender => uint256 activeAt) spenderActiveAt;
        uint256 gasCap;
        uint256 pendingGasCap;
        uint256 pendingGasCapAt;
    }

    /* CONSTANTS */

    address public constant ENTRY_POINT = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108; // v0.8
    /// @notice EntryPoint nonce key whose sequence is the policy epoch. Only this account can bump
    /// it, it only goes up, and no delegate can wipe EntryPoint storage.
    uint192 public constant EPOCH_KEY = type(uint192).max;
    uint256 public constant TIMELOCK = 48 hours;
    uint256 public constant MAX_CALL_RULES = 64;
    uint256 public constant MAX_PARTIES = 32;

    /// @dev keccak256(abi.encode(uint256(keccak256("reference-delegate.storage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_SLOT = 0xdc339b4bc18935ae7f6cb30c71453d415c5e72f932d389bf98039afb6d56ba00;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant DELEGATED_USER_OP_TYPEHASH =
        keccak256("DelegatedUserOp(bytes32 userOpHash,address delegate)");
    bytes32 private constant NAME_HASH = keccak256("ReferenceDelegate");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 private constant SECP256K1N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /* EVENTS */

    event CallAllowed(address indexed target, bytes4 indexed selector, uint8 recipientArg, uint256 valueActiveAt);
    event CallRemoved(address indexed target, bytes4 indexed selector);
    event RecipientAdded(address indexed recipient, uint256 activeAt);
    event RecipientRemoved(address indexed recipient);
    event SpenderAdded(address indexed spender, uint256 activeAt);
    event SpenderRemoved(address indexed spender);
    event GasCapProposed(uint256 cap, uint256 activeAt);
    event GasCapSet(uint256 cap);
    event Revoked();

    /* ERRORS */

    error Unauthorized();
    error SelfCallBlocked();
    error MalformedCalldata();
    error CallNotAllowed(address target, bytes4 selector);
    error ValueNotAllowed(address target, bytes4 selector);
    error SelectorBlocked(bytes4 selector);
    error NotRecipient(address account);
    error NotSpender(address account);
    error CallFailed(uint256 index, bytes reason);
    error MustUseExecuteUserOp();
    error ReservedNonceKey();
    error GasCapExceeded(uint256 maxCost, uint256 cap);
    error StalePolicyEpoch(uint192 signedEpoch, uint192 currentEpoch);
    error AlreadyListed(address account);
    error NotListed(address account);
    error InvalidParty(address account);
    error TooManyEntries();
    error NoPendingGasCap();
    error GasCapTimelocked(uint256 activeAt);

    /* VARIABLES */

    // This implementation's own address.
    address public immutable DELEGATE;

    /* CONSTRUCTOR */

    constructor() {
        DELEGATE = address(this);
    }

    /* MODIFIERS */

    modifier onlySelf() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != ENTRY_POINT) revert Unauthorized();
        _;
    }

    /// @dev Every policy change: self-call only, never while an execution is in progress, and bumps
    /// the epoch so that UserOps signed under the old policy can no longer execute.
    modifier changesPolicy() {
        if (msg.sender != address(this)) revert Unauthorized();
        if (_reentrancyGuardEntered()) revert ReentrancyGuardReentrantCall();
        _;
        IEntryPointNonces(ENTRY_POINT).incrementNonce(EPOCH_KEY);
    }

    /* FUNCTIONS */

    function execute(Call[] calldata calls) external payable onlySelf nonReentrant {
        _run(calls);
    }

    /// @notice ERC-4337 validation. Policy is enforced at execution, not here.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        // Forces execution through executeUserOp, where the policy epoch is checked.
        if (userOp.callData.length < 4 || bytes4(userOp.callData[:4]) != this.executeUserOp.selector) {
            revert MustUseExecuteUserOp();
        }
        if (uint192(userOp.nonce >> 64) == EPOCH_KEY) revert ReservedNonceKey();
        if (userOp.paymasterAndData.length == 0) {
            uint256 maxCost = _maxGasCost(userOp);
            uint256 cap = _layout().gasCap;
            if (maxCost > cap) revert GasCapExceeded(maxCost, cap);
        }

        bool valid = _recover(userOpSigningHash(userOpHash), userOp.signature) == address(this);
        validationData = valid ? 0 : SIG_VALIDATION_FAILED;

        if (missingAccountFunds != 0) {
            // The EntryPoint verifies the deposit itself, so the result can be ignored.
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok);
        }
    }

    /// @notice ERC-4337 execution
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external onlyEntryPoint nonReentrant {
        uint192 signedEpoch = uint192(userOp.nonce >> 64);
        uint192 currentEpoch = policyEpoch();
        if (signedEpoch != currentEpoch) revert StalePolicyEpoch(signedEpoch, currentEpoch);
        _run(abi.decode(userOp.callData[4:], (Call[])));
    }

    /// @notice Add or update a Tier 2 rule. Takes effect immediately, except the value bit, which
    /// waits TIMELOCK. Tier 2 can never loosen a Tier 1 check.
    function allowCall(address target, bytes4 selector, uint8 recipientArg, bool allowValue) external changesPolicy {
        if (target == address(this)) revert SelfCallBlocked();
        Layout storage $ = _layout();
        CallRule storage rule = $.rules[target][selector];
        if (!rule.allowed) {
            if ($.ruleKeys.length >= MAX_CALL_RULES) revert TooManyEntries();
            $.ruleKeys.push(RuleKey({target: target, selector: selector}));
            rule.allowed = true;
        }
        rule.recipientArg = recipientArg;
        if (!allowValue) rule.valueActiveAt = 0;
        else if (rule.valueActiveAt == 0) rule.valueActiveAt = block.timestamp + TIMELOCK;
        emit CallAllowed(target, selector, recipientArg, rule.valueActiveAt);
    }

    function removeCall(address target, bytes4 selector) external changesPolicy {
        Layout storage $ = _layout();
        if (!$.rules[target][selector].allowed) revert CallNotAllowed(target, selector);
        RuleKey[] storage keys = $.ruleKeys;
        for (uint256 i; i < keys.length; ++i) {
            if (keys[i].target == target && keys[i].selector == selector) {
                keys[i] = keys[keys.length - 1];
                keys.pop();
                break;
            }
        }
        delete $.rules[target][selector];
        emit CallRemoved(target, selector);
    }

    function addRecipient(address recipient) external changesPolicy {
        Layout storage $ = _layout();
        uint256 activeAt = _addParty($.recipients, $.recipientActiveAt, recipient);
        emit RecipientAdded(recipient, activeAt);
    }

    function removeRecipient(address recipient) external changesPolicy {
        Layout storage $ = _layout();
        _removeParty($.recipients, $.recipientActiveAt, recipient);
        emit RecipientRemoved(recipient);
    }

    function addSpender(address spender) external changesPolicy {
        Layout storage $ = _layout();
        uint256 activeAt = _addParty($.spenders, $.spenderActiveAt, spender);
        emit SpenderAdded(spender, activeAt);
    }

    function removeSpender(address spender) external changesPolicy {
        Layout storage $ = _layout();
        _removeParty($.spenders, $.spenderActiveAt, spender);
        emit SpenderRemoved(spender);
    }

    function proposeGasCap(uint256 cap) external changesPolicy {
        Layout storage $ = _layout();
        if (cap <= $.gasCap) {
            $.gasCap = cap;
            delete $.pendingGasCap;
            delete $.pendingGasCapAt;
            emit GasCapSet(cap);
        } else {
            uint256 activeAt = block.timestamp + TIMELOCK;
            $.pendingGasCap = cap;
            $.pendingGasCapAt = activeAt;
            emit GasCapProposed(cap, activeAt);
        }
    }

    function applyGasCap() external changesPolicy {
        Layout storage $ = _layout();
        uint256 activeAt = $.pendingGasCapAt;
        if (activeAt == 0) revert NoPendingGasCap();
        if (block.timestamp < activeAt) revert GasCapTimelocked(activeAt);
        $.gasCap = $.pendingGasCap;
        delete $.pendingGasCap;
        delete $.pendingGasCapAt;
        emit GasCapSet($.gasCap);
    }

    function revoke() external changesPolicy {
        Layout storage $ = _layout();
        for (uint256 i; i < $.ruleKeys.length; ++i) {
            RuleKey storage key = $.ruleKeys[i];
            delete $.rules[key.target][key.selector];
        }
        delete $.ruleKeys;
        for (uint256 i; i < $.recipients.length; ++i) {
            delete $.recipientActiveAt[$.recipients[i]];
        }
        delete $.recipients;
        for (uint256 i; i < $.spenders.length; ++i) {
            delete $.spenderActiveAt[$.spenders[i]];
        }
        delete $.spenders;
        delete $.gasCap;
        delete $.pendingGasCap;
        delete $.pendingGasCapAt;
        emit Revoked();
    }

    function policyEpoch() public view returns (uint192) {
        return uint192(uint64(IEntryPointNonces(ENTRY_POINT).getNonce(address(this), EPOCH_KEY)));
    }

    function userOpSigningHash(bytes32 userOpHash) public view returns (bytes32) {
        bytes32 domainSeparator =
            keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
        bytes32 structHash = keccak256(abi.encode(DELEGATED_USER_OP_TYPEHASH, userOpHash, DELEGATE));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function callRule(address target, bytes4 selector) external view returns (CallRule memory) {
        return _layout().rules[target][selector];
    }

    function callRules() external view returns (RuleKey[] memory) {
        return _layout().ruleKeys;
    }

    function recipients() external view returns (address[] memory) {
        return _layout().recipients;
    }

    function spenders() external view returns (address[] memory) {
        return _layout().spenders;
    }

    function isRecipient(address account) public view returns (bool) {
        return account == address(this) || _isActive(_layout().recipientActiveAt[account]);
    }

    function isSpender(address account) public view returns (bool) {
        return account == address(this) || _isActive(_layout().spenderActiveAt[account]);
    }

    function gasCap() external view returns (uint256 cap, uint256 pendingCap, uint256 pendingAt) {
        Layout storage $ = _layout();
        return ($.gasCap, $.pendingGasCap, $.pendingGasCapAt);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _recover(hash, signature) == address(this) ? this.isValidSignature.selector : bytes4(0xffffffff);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 // ERC-165
            || interfaceId == this.isValidSignature.selector // ERC-1271
            || interfaceId == this.onERC721Received.selector // ERC-721 receiver
            || interfaceId == (this.onERC1155Received.selector ^ this.onERC1155BatchReceived.selector) // ERC-1155 receiver
            || interfaceId == this.validateUserOp.selector // IAccount
            || interfaceId == this.executeUserOp.selector // IAccountExecute
            || interfaceId == (this.accountId.selector ^ this.accountStorageBases.selector); // ERC-7779
    }

    function accountId() external pure returns (string memory) {
        return "reference-delegate.v1";
    }

    function accountStorageBases() external pure returns (bytes32[] memory bases) {
        bases = new bytes32[](1);
        bases[0] = STORAGE_SLOT;
    }

    receive() external payable {}

    function _run(Call[] memory calls) internal {
        Layout storage $ = _layout();
        for (uint256 i; i < calls.length; ++i) {
            Call memory c = calls[i];
            _checkCall($, c.target, c.value, c.data);
            (bool ok, bytes memory reason) = c.target.call{value: c.value}(c.data);
            if (!ok) revert CallFailed(i, reason);
        }
    }

    function _checkCall(Layout storage $, address target, uint256 value, bytes memory data) internal view {
        if (target == address(this)) revert SelfCallBlocked();

        if (data.length == 0) {
            if (!isRecipient(target)) revert NotRecipient(target);
            return;
        }
        if (data.length < 4) revert MalformedCalldata();

        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 selector = bytes4(data);
        CallRule memory rule = $.rules[target][selector];
        if (!rule.allowed) revert CallNotAllowed(target, selector);
        if (value != 0 && !_isActive(rule.valueActiveAt)) revert ValueNotAllowed(target, selector);

        (Party party, uint256 argIndex) = _tier1(selector);
        if (party == Party.Blocked) revert SelectorBlocked(selector);
        if (party != Party.None && !_tier1Exempt(selector, data)) {
            address who = _addressArg(data, argIndex);
            if (party == Party.Recipient) {
                if (!isRecipient(who)) revert NotRecipient(who);
            } else if (!isSpender(who)) {
                revert NotSpender(who);
            }
        }

        if (rule.recipientArg != 0) {
            address who = _addressArg(data, rule.recipientArg - 1);
            if (!isRecipient(who)) revert NotRecipient(who);
        }
    }

    /// @dev Tier 1: static, known asset-moving selectors and which static argument names the party.
    function _tier1(bytes4 s) internal pure returns (Party, uint256) {
        // ERC-20 / ERC-721
        if (s == 0xa9059cbb) return (Party.Recipient, 0); // transfer(address,uint256)
        if (s == 0x23b872dd) return (Party.Recipient, 1); // transferFrom(address,address,uint256)
        if (s == 0x42842e0e) return (Party.Recipient, 1); // safeTransferFrom(address,address,uint256)
        if (s == 0xb88d4fde) return (Party.Recipient, 1); // safeTransferFrom(address,address,uint256,bytes)
        if (s == 0x095ea7b3) return (Party.Spender, 0); // approve(address,uint256)
        if (s == 0x39509351) return (Party.Spender, 0); // increaseAllowance(address,uint256)
        if (s == 0xa22cb465) return (Party.Spender, 0); // setApprovalForAll(address,bool)
        // ERC-1155
        if (s == 0xf242432a) return (Party.Recipient, 1); // safeTransferFrom(address,address,uint256,uint256,bytes)
        if (s == 0x2eb2c2d6) return (Party.Recipient, 1); // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
        // ERC-1363
        if (s == 0x1296ee62) return (Party.Recipient, 0); // transferAndCall(address,uint256)
        if (s == 0x4000aea0) return (Party.Recipient, 0); // transferAndCall(address,uint256,bytes)
        if (s == 0xd8fbe994) return (Party.Recipient, 1); // transferFromAndCall(address,address,uint256)
        if (s == 0xc1d34b89) return (Party.Recipient, 1); // transferFromAndCall(address,address,uint256,bytes)
        if (s == 0x3177029f) return (Party.Spender, 0); // approveAndCall(address,uint256)
        if (s == 0xcae9ca51) return (Party.Spender, 0); // approveAndCall(address,uint256,bytes)
        // ERC-777
        if (s == 0x9bd9bbc6) return (Party.Recipient, 0); // send(address,uint256,bytes)
        if (s == 0x62ad1b83) return (Party.Recipient, 1); // operatorSend(address,address,uint256,bytes,bytes)
        if (s == 0x959b8c3f) return (Party.Spender, 0); // authorizeOperator(address)
        // ERC-4626 (shares or assets go to `receiver`)
        if (s == 0x6e553f65) return (Party.Recipient, 1); // deposit(uint256,address)
        if (s == 0x94bf804d) return (Party.Recipient, 1); // mint(uint256,address)
        if (s == 0xb460af94) return (Party.Recipient, 1); // withdraw(uint256,address,address)
        if (s == 0xba087652) return (Party.Recipient, 1); // redeem(uint256,address,address)
        // Permit2
        if (s == 0x87517c45) return (Party.Spender, 1); // approve(address,address,uint160,uint48)
        if (s == 0x36c78516) return (Party.Recipient, 1); // transferFrom(address,address,uint160,address)
        if (s == 0x0d58b1db) return (Party.Blocked, 0); // transferFrom((address,address,uint160,address)[]): recipients not statically checkable
        // EntryPoint deposit and stake (the account's gas deposit is an asset too)
        if (s == 0xb760faf9) return (Party.Recipient, 0); // depositTo(address): value credits that address
        if (s == 0x205c2878) return (Party.Recipient, 0); // withdrawTo(address,uint256)
        if (s == 0xc23a5cea) return (Party.Recipient, 0); // withdrawStake(address)
        return (Party.None, 0);
    }

    function _tier1Exempt(bytes4 s, bytes memory data) internal pure returns (bool) {
        if (s == 0xa22cb465) return _wordArg(data, 1) == 0; // setApprovalForAll(x, false)
        if (s == 0x095ea7b3) return _wordArg(data, 0) == 0; // approve(address(0), id): ERC-721 clear
        return false;
    }

    function _addParty(address[] storage list, mapping(address => uint256) storage activeAt, address account)
        internal
        returns (uint256 at)
    {
        if (account == address(0) || account == address(this)) revert InvalidParty(account);
        if (activeAt[account] != 0) revert AlreadyListed(account);
        if (list.length >= MAX_PARTIES) revert TooManyEntries();
        at = block.timestamp + TIMELOCK;
        list.push(account);
        activeAt[account] = at;
    }

    function _removeParty(address[] storage list, mapping(address => uint256) storage activeAt, address account)
        internal
    {
        if (activeAt[account] == 0) revert NotListed(account);
        for (uint256 i; i < list.length; ++i) {
            if (list[i] == account) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }
        delete activeAt[account];
    }

    function _isActive(uint256 activeAt) internal view returns (bool) {
        return activeAt != 0 && activeAt <= block.timestamp;
    }

    function _maxGasCost(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        uint256 verificationGasLimit = uint128(bytes16(userOp.accountGasLimits));
        uint256 callGasLimit = uint128(uint256(userOp.accountGasLimits));
        uint256 maxFeePerGas = uint128(uint256(userOp.gasFees));
        return (verificationGasLimit + callGasLimit + userOp.preVerificationGas) * maxFeePerGas;
    }

    function _wordArg(bytes memory data, uint256 index) internal pure returns (uint256 word) {
        if (data.length < 4 + 32 * (index + 1)) revert MalformedCalldata();
        assembly ("memory-safe") {
            word := mload(add(add(data, 36), mul(index, 32)))
        }
    }

    function _addressArg(bytes memory data, uint256 index) internal pure returns (address) {
        uint256 word = _wordArg(data, index);
        // Dirty upper bits: a Solidity target would reject them, a hand-written one might truncate.
        if (word >> 160 != 0) revert MalformedCalldata();
        // forge-lint: disable-next-line(unsafe-typecast)
        return address(uint160(word)); // lossless: the check above guarantees word < 2**160
    }

    function _recover(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1N_HALF || (v != 27 && v != 28)) return address(0);
        return ecrecover(hash, v, r, s);
    }

    function _layout() internal pure returns (Layout storage $) {
        assembly ("memory-safe") {
            $.slot := STORAGE_SLOT
        }
    }
}
