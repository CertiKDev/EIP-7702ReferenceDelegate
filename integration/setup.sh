#!/usr/bin/env bash
# Point an EOA at ReferenceDelegate and configure it, exactly as verified on a Sepolia fork on
# 2026-10-26 (Anvil fork, real EntryPoint v0.8, Alto 0.0.21). Everything happens with the EOA's own
# key in self-sponsored transactions; no relayer, no initializer, nothing to front-run.
#
# Usage:
#   RPC=http://127.0.0.1:8545 IMPL=0x... OWNER_PK=0x... TOKEN=0x... VAULT=0x... ./setup.sh
#     IMPL   deployed ReferenceDelegate
#     TOKEN  an ERC-20 the account will be allowed to transfer
#     VAULT  an address the user controls (cold wallet); the only place tokens may go
#
# What it does:
#   tx 1  type-4: delegate + allowCall(TOKEN, transfer, no arg check, no value)  (one transaction)
#   tx 2  addRecipient(VAULT)                    active after 48h
#   tx 3  proposeGasCap(0.01 ETH)                 raise waits 48h, then applyGasCap()
#   ---- 48h later ----
#   tx 4  applyGasCap()
# Every one of tx 1-4 bumps the policy epoch; wallets read policyEpoch() to build UserOp nonces.
set -euo pipefail
: "${RPC:?}" "${IMPL:?}" "${OWNER_PK:?}" "${TOKEN:?}" "${VAULT:?}"
OWNER=$(cast wallet address "$OWNER_PK")
TRANSFER=0xa9059cbb
ENTRY_POINT=0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108

# Every policy change bumps an epoch stored in EntryPoint v0.8, so the chain must have it. Mainnet,
# Sepolia and the major L2s do. On a fresh devnet deploy it first (lib/account-abstraction) or
# anvil_setCode its runtime bytecode at the canonical address.
if [ "$(cast code "$ENTRY_POINT" --rpc-url "$RPC")" = "0x" ]; then
  echo "EntryPoint v0.8 not found at $ENTRY_POINT on this chain; policy calls would revert." >&2
  exit 1
fi

echo "account      $OWNER"
echo "code before  $(cast code "$OWNER" --rpc-url "$RPC")"

# tx 1: the authorization tuple (non-zero chain id, signed by the account's key) rides on a call to
# the account itself, so delegation and the first policy entry land together.
cast send "$OWNER" "allowCall(address,bytes4,uint8,bool)" "$TOKEN" $TRANSFER 0 false \
  --auth "$IMPL" --rpc-url "$RPC" --private-key "$OWNER_PK" --json | jq -r '"tx1 delegate+allowCall  type=\(.type) status=\(.status)"'
echo "code after   $(cast code "$OWNER" --rpc-url "$RPC")   (0xef0100 || delegate)"

cast send "$OWNER" "addRecipient(address)" "$VAULT" --rpc-url "$RPC" --private-key "$OWNER_PK" --json \
  | jq -r '"tx2 addRecipient         status=\(.status)"'
cast send "$OWNER" "proposeGasCap(uint256)" 10000000000000000 --rpc-url "$RPC" --private-key "$OWNER_PK" --json \
  | jq -r '"tx3 proposeGasCap        status=\(.status)"'

echo "policyEpoch  $(cast call "$OWNER" 'policyEpoch()(uint192)' --rpc-url "$RPC")"
echo "DELEGATE()   $(cast call "$OWNER" 'DELEGATE()(address)' --rpc-url "$RPC")   (the implementation, read through the account)"
echo "recipient    active: $(cast call "$OWNER" 'isRecipient(address)(bool)' "$VAULT" --rpc-url "$RPC")   (true only after 48h)"
echo
echo "After 48h:   cast send $OWNER 'applyGasCap()' --rpc-url $RPC --private-key \$OWNER_PK"
echo "To revoke:   cast send $OWNER 'revoke()' ... ; then cast send $OWNER --auth 0x0000000000000000000000000000000000000000 ..."
