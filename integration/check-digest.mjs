// Checks that the viem helper produces exactly the digest the delegate computes on-chain.
// Usage: node check-digest.mjs <rpcUrl> <account> <delegate>
import { createPublicClient, http, keccak256, toHex } from "viem";
import { delegatedUserOpDigest } from "./signUserOp.mjs";

const [rpcUrl, account, delegate] = process.argv.slice(2);
const client = createPublicClient({ transport: http(rpcUrl) });
const chainId = await client.getChainId();
const abi = [{
  type: "function", name: "userOpSigningHash", stateMutability: "view",
  inputs: [{ name: "userOpHash", type: "bytes32" }], outputs: [{ type: "bytes32" }],
}];

let mismatches = 0;
for (const label of ["a", "b", "c"]) {
  const userOpHash = keccak256(toHex(`some userOpHash ${label}`));
  const onchain = await client.readContract({ address: account, abi, functionName: "userOpSigningHash", args: [userOpHash] });
  const local = delegatedUserOpDigest({ account, userOpHash, delegate, chainId });
  const ok = onchain.toLowerCase() === local.toLowerCase();
  if (!ok) mismatches++;
  console.log(`${ok ? "OK  " : "FAIL"} userOpHash=${userOpHash.slice(0, 10)}… onchain=${onchain.slice(0, 18)}… local=${local.slice(0, 18)}…`);
}
process.exit(mismatches ? 1 : 0);
