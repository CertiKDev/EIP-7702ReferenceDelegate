#!/usr/bin/env bash
# Two EIP-7702 protocol facts, demonstrated on real EVMs (two Anvil chains), not with cheatcodes.
# Foundry's attachDelegation applies the code at attach time and tracks nonces itself, so neither
# fact can be tested faithfully there.
#
#   1. An authorization with chain_id = 0 is valid on every chain: ONE signed tuple delegates the
#      same EOA on chain A and on chain B. A tuple signed with chain A's id does nothing on chain B.
#   2. The delegation is written even when the transaction's call reverts.
#
# Usage: RPC_A=http://127.0.0.1:8548 RPC_B=http://127.0.0.1:8549 ./spec-demo.sh
#   (e.g. anvil --port 8548 --chain-id 31337 ; anvil --port 8549 --chain-id 31338)
set -euo pipefail
: "${RPC_A:?}" "${RPC_B:?}"
cd "$(dirname "$0")/.."
DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0
CHAIN_A=$(cast chain-id --rpc-url "$RPC_A"); CHAIN_B=$(cast chain-id --rpc-url "$RPC_B")
echo "chain A = $CHAIN_A   chain B = $CHAIN_B"

# Same deployer, same nonce, same bytecode: the delegate lands at the same address on both chains.
IMPL_A=$(forge create src/ReferenceDelegate.sol:ReferenceDelegate --rpc-url "$RPC_A" --private-key $DEPLOYER_PK --broadcast --json 2>/dev/null | jq -r .deployedTo)
IMPL_B=$(forge create src/ReferenceDelegate.sol:ReferenceDelegate --rpc-url "$RPC_B" --private-key $DEPLOYER_PK --broadcast --json 2>/dev/null | jq -r .deployedTo)
[ "$IMPL_A" = "$IMPL_B" ] || { echo "delegate addresses differ: $IMPL_A vs $IMPL_B"; exit 1; }
IMPL=$(echo "$IMPL_A" | tr A-Z a-z); echo "delegate on both chains: $IMPL"

fund() { cast rpc anvil_setBalance "$2" 0xDE0B6B3A7640000 --rpc-url "$1" >/dev/null; }
code() { cast code "$2" --rpc-url "$1"; }

echo
echo "== 1a. chain_id = 0: one tuple, two chains"
PK=$(cast wallet new --json | jq -r '.[0].private_key'); EOA=$(cast wallet address "$PK")
fund "$RPC_A" "$EOA"; fund "$RPC_B" "$EOA"
AUTH0=$(cast wallet sign-auth --chain 0 --nonce 0 --private-key "$PK" "$IMPL")     # signed ONCE
echo "tuple: $(echo "$AUTH0" | cut -c1-40)…  (chain_id 0, nonce 0)"
# Sponsored by the deployer so the EOA's own nonce stays 0 on both chains (as it would in reality).
cast send "$EOA" --auth "$AUTH0" --rpc-url "$RPC_A" --private-key $DEPLOYER_PK --json | jq -r '"chain A: type=\(.type) status=\(.status)"'
cast send "$EOA" --auth "$AUTH0" --rpc-url "$RPC_B" --private-key $DEPLOYER_PK --json | jq -r '"chain B: type=\(.type) status=\(.status)"'
echo "code on A: $(code "$RPC_A" "$EOA")"
echo "code on B: $(code "$RPC_B" "$EOA")"
[ "$(code "$RPC_A" "$EOA")" = "0xef0100${IMPL:2}" ] && [ "$(code "$RPC_B" "$EOA")" = "0xef0100${IMPL:2}" ] \
  && echo "RESULT: the same signature delegated the account on both chains" || { echo "FAIL"; exit 1; }

echo
echo "== 1b. chain-bound tuple: signed for chain A, sent on chain B"
PK2=$(cast wallet new --json | jq -r '.[0].private_key'); EOA2=$(cast wallet address "$PK2")
fund "$RPC_A" "$EOA2"; fund "$RPC_B" "$EOA2"
AUTHA=$(cast wallet sign-auth --chain "$CHAIN_A" --nonce 0 --private-key "$PK2" "$IMPL")
cast send "$EOA2" --auth "$AUTHA" --rpc-url "$RPC_B" --private-key $DEPLOYER_PK --json | jq -r '"chain B: type=\(.type) status=\(.status)  (the tx itself is fine; the tuple is skipped)"'
echo "code on B: '$(code "$RPC_B" "$EOA2")'"
cast send "$EOA2" --auth "$AUTHA" --rpc-url "$RPC_A" --private-key $DEPLOYER_PK --json | jq -r '"chain A: type=\(.type) status=\(.status)"'
echo "code on A: $(code "$RPC_A" "$EOA2")"
[ "$(code "$RPC_B" "$EOA2")" = "0x" ] && [ "$(code "$RPC_A" "$EOA2")" = "0xef0100${IMPL:2}" ] \
  && echo "RESULT: a chain-bound tuple only works on its chain" || { echo "FAIL"; exit 1; }

echo
echo "== 2. the delegation is written even if the call reverts"
# Target: the real CrimeEnjoyor clone bytecode from test/anatomy (its receive() reverts until initialized).
CLONE=0x0727ca41efc85f75cef26ee48f825893b4836786 # lowercase on purpose: cast code prints lowercase
CLONE_CODE=$(grep -o 'hex"[0-9a-f]*"' test/anatomy/CrimeEnjoyorClone.bytecode.sol | tr -d 'hex"')
cast rpc anvil_setCode "$CLONE" "0x$CLONE_CODE" --rpc-url "$RPC_A" >/dev/null
PK3=$(cast wallet new --json | jq -r '.[0].private_key'); EOA3=$(cast wallet address "$PK3")
fund "$RPC_A" "$EOA3"
# Self-sponsored type-4 tx sending 1 wei to itself: the clone's receive() reverts "Not initialized".
set +e
OUT=$(cast send "$EOA3" --auth "$CLONE" --value 1 --gas-limit 200000 --rpc-url "$RPC_A" --private-key "$PK3" --json 2>&1)
set -e
STATUS=$(echo "$OUT" | jq -r .status 2>/dev/null || echo "n/a")
echo "tx status: $STATUS  (0x0 = the call reverted)"
echo "code on A: $(code "$RPC_A" "$EOA3")"
[ "$(code "$RPC_A" "$EOA3")" = "0xef0100${CLONE:2}" ] \
  && echo "RESULT: delegated anyway; a reverting call does not undo the authorization" || { echo "FAIL"; echo "$OUT"; exit 1; }
