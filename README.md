# EIP-7702 reference delegate

## Overview

An EIP-7702 delegate for ordinary accounts (EOAs). Through it, an account does only what its owner
listed in advance. Presented at DeFi Security Summit (DSS) 2026.

When an EOA delegates to this contract:

- **Only two paths can make the account act:** the owner's own transaction to itself (`execute`),
  and an ERC-4337 user operation the owner signed, delivered by EntryPoint v0.8.
- **Every outgoing call is checked against a policy.** The owner lists which contracts and functions
  may be called. For 28 known token-moving functions (ERC-20, ERC-721, ERC-1155, Permit2 and
  others), the recipient or spender must also be on the owner's list. Anything not listed reverts.
- **The policy is slow to widen and fast to narrow.** New recipients, spenders, value targets and
  gas-cap raises wait 48 hours. Removals are instant. Only the owner's own transaction can change
  the policy.
- **Signatures can't be replayed elsewhere.** A user-operation signature names this delegate, so
  no other delegate accepts it. Every policy change invalidates signatures made under the old one.
- **Revocation is clean.** `revoke()` wipes the policy without resetting nonces, so old signatures
  stay dead if the account ever returns.
- **Incoming ETH stays in the account.**

The repo also contains an attack-test suite. It runs the same safety properties against this
delegate, a deliberately broken delegate, and the real "CrimeEnjoyor" sweeper bytecode from
Ethereum mainnet.

It does not protect against a leaked key, re-delegation by the key, or approvals signed before
delegating.

> Unaudited. Do not use it with real funds. Do not deploy anything in `test/control/`.

## Setup

1. Install Foundry (version 1.0 or later):

   ```shell
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. Clone the repo with its dependencies:

   ```shell
   git clone --recursive <repo-url>
   cd <repo-dir>
   ```

   If you already cloned without `--recursive`, run `git submodule update --init`.

3. Build:

   ```shell
   forge build
   ```

4. Only for the scripts in `integration/`: install `jq`, then Node.js and viem:

   ```shell
   npm install viem
   ```

## Test

1. Run the tests that must pass:

   ```shell
   forge test --no-match-contract Control_
   ```

   Expected: 35 tests pass.

2. Run the control suites. They fail on purpose; each failure is an attack that works against a
   broken delegate or the real sweeper bytecode:

   ```shell
   forge test --match-contract Control_
   ```

3. Run one test with its trace:

   ```shell
   forge test --match-test test_CrossDelegateReplayRejected -vvvv
   ```

4. Optional: show two EIP-7702 protocol facts on two real local chains (a `chain_id = 0`
   authorization works on both; a delegation is written even when the call reverts):

   ```shell
   anvil --port 8548 --chain-id 31337
   anvil --port 8549 --chain-id 31338
   RPC_A=http://127.0.0.1:8548 RPC_B=http://127.0.0.1:8549 ./integration/spec-demo.sh
   ```

   Run each `anvil` in its own terminal.

## Run

How a project (a wallet, or a dApp that manages accounts) puts this into production on a live chain.
The project deploys the delegate once per chain. Each user's account then delegates to it with the
user's own key.

Commands use Foundry's `cast` and `forge` with an encrypted keystore (`--account`). Never put a
private key on the command line. In a wallet, each `cast send` below is a transaction the wallet
builds and the user approves.

The variables are: `RPC` (the chain's RPC URL), `DELEGATE` (the deployed delegate), `ACCOUNT` (the
user's address, signed for by the `owner` keystore), `TOKEN` (an ERC-20), `VAULT` (an address the
user controls) and `ROUTER` (a protocol the user trusts).

### A. Deploy once per chain (project team)

1. Check that the chain has EntryPoint v0.8. The output must not be `0x`:

   ```shell
   cast code 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 --rpc-url $RPC
   ```

2. Import the deployer key into an encrypted keystore:

   ```shell
   cast wallet import deployer --interactive
   ```

3. Deploy the delegate and verify its source:

   ```shell
   forge create src/ReferenceDelegate.sol:ReferenceDelegate \
     --rpc-url $RPC --account deployer --broadcast \
     --verify --etherscan-api-key $ETHERSCAN_API_KEY
   ```

4. Record the deployed address and its code hash:

   ```shell
   cast codehash $DELEGATE --rpc-url $RPC
   ```

5. Ship both values in the wallet's own configuration. Before every delegation, check that the code
   at the address still has this hash. Never accept a delegate address from a dApp.

### B. Onboard a user account (from the user's wallet)

6. Delegate the account and add its first allowed call in one type-4 transaction to itself. The
   example allows `transfer` on one token. The authorization is signed with the chain's id; never
   sign one with chain id 0.

   ```shell
   cast send $ACCOUNT "allowCall(address,bytes4,uint8,bool)" $TOKEN 0xa9059cbb 0 false \
     --auth $DELEGATE --rpc-url $RPC --account owner
   ```

7. Check the delegation. The output must be `0xef0100` followed by the delegate's address:

   ```shell
   cast code $ACCOUNT --rpc-url $RPC
   ```

8. Add the addresses tokens may go to (the user's own addresses), and the protocols the account may
   approve (routers, Permit2). Show each change to the user the way an approval is shown today.

   ```shell
   cast send $ACCOUNT "addRecipient(address)" $VAULT --rpc-url $RPC --account owner
   cast send $ACCOUNT "addSpender(address)" $ROUTER --rpc-url $RPC --account owner
   ```

9. Allow more contract calls the same way as in step 6. `allowCall` takes the target, the function
   selector, the position of a recipient argument to check (0 for none), and whether the call may
   send ETH.

10. If the account will pay for its own user operations, propose a gas cap in wei:

    ```shell
    cast send $ACCOUNT "proposeGasCap(uint256)" 10000000000000000 --rpc-url $RPC --account owner
    ```

11. Wait 48 hours. New recipients, spenders, ETH-sending calls and gas-cap raises only take effect
    then. Check with `isRecipient(address)` and `isSpender(address)`, then apply the gas cap:

    ```shell
    cast send $ACCOUNT "applyGasCap()" --rpc-url $RPC --account owner
    ```

### C. Daily use

12. Send a batch from the user's own key. Each call is a `(target, value, data)` entry:

    ```shell
    cast send $ACCOUNT "execute((address,uint256,bytes)[])" \
      "[($TOKEN,0,$(cast calldata 'transfer(address,uint256)' $VAULT 1000000))]" \
      --rpc-url $RPC --account owner
    ```

13. Or send a user operation through any ERC-4337 bundler, with EntryPoint v0.8:
    - Read `policyEpoch()` from the account. Use it as the nonce key, and read the nonce with
      `EntryPoint.getNonce(account, epoch)`.
    - Set `callData` to the `executeUserOp` selector followed by the ABI-encoded list of calls.
    - Leave `initCode` empty; the account is already delegated.
    - Get `userOpHash` from `EntryPoint.getUserOpHash(op)`. Have the user sign
      `userOpSigningHash(userOpHash)`, not the plain `userOpHash`. `integration/signUserOp.mjs`
      builds this EIP-712 signature with viem.
    - Submit it with `eth_sendUserOperation`.

14. Show the delegate's errors to the user in plain words. The common ones are `CallNotAllowed`,
    `NotRecipient`, `NotSpender`, `ValueNotAllowed`, `GasCapExceeded` and `StalePolicyEpoch`. The
    last one means the policy changed after the operation was signed; sign it again.

### D. Narrow or leave

15. Removals take effect immediately:

    ```shell
    cast send $ACCOUNT "removeRecipient(address)" $VAULT --rpc-url $RPC --account owner
    cast send $ACCOUNT "removeSpender(address)" $ROUTER --rpc-url $RPC --account owner
    cast send $ACCOUNT "removeCall(address,bytes4)" $TOKEN 0xa9059cbb --rpc-url $RPC --account owner
    ```

16. To leave, wipe the policy first, then remove the delegation. Offer both inside the wallet:

    ```shell
    cast send $ACCOUNT "revoke()" --rpc-url $RPC --account owner
    cast send $ACCOUNT --auth 0x0000000000000000000000000000000000000000 --rpc-url $RPC --account owner
    ```

17. Approvals the account made before delegating still work and the delegate can't see them. Show
    them to the user and offer to revoke them.
