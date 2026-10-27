// Signing helper for ReferenceDelegate UserOps (viem).
//
// The account's key does NOT sign the EntryPoint's userOpHash directly. It signs EIP-712 typed data
// that names the delegate, so the signature is useless under any other delegate:
//
//   domain: { name: "ReferenceDelegate", version: "1", chainId, verifyingContract: <the account> }
//   types:  DelegatedUserOp(bytes32 userOpHash, address delegate)
//
// Usage from a wallet or dApp:
//   const sig = await signDelegatedUserOp({ account, userOpHash, delegate, chainId, signTypedData })
// where `signTypedData` is the wallet's EIP-712 signer (viem walletClient.signTypedData, or
// eth_signTypedData_v4). The digest must equal `account.userOpSigningHash(userOpHash)` on-chain;
// `delegatedUserOpDigest` computes it locally for checking.

import { hashTypedData } from "viem";

export const DELEGATED_USER_OP_TYPES = {
  DelegatedUserOp: [
    { name: "userOpHash", type: "bytes32" },
    { name: "delegate", type: "address" },
  ],
};

export function delegatedUserOpTypedData({ account, userOpHash, delegate, chainId }) {
  return {
    domain: { name: "ReferenceDelegate", version: "1", chainId, verifyingContract: account },
    types: DELEGATED_USER_OP_TYPES,
    primaryType: "DelegatedUserOp",
    message: { userOpHash, delegate },
  };
}

export function delegatedUserOpDigest(args) {
  return hashTypedData(delegatedUserOpTypedData(args));
}

export async function signDelegatedUserOp({ signTypedData, ...args }) {
  return signTypedData(delegatedUserOpTypedData(args));
}

// Build the nonce a UserOp must carry: key = current policy epoch, sequence from the EntryPoint.
//   nonce = (epoch << 64n) | seq
export function userOpNonce({ policyEpoch, sequence }) {
  return (BigInt(policyEpoch) << 64n) | BigInt(sequence);
}
