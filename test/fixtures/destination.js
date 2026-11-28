// Synthetic public test keys only. Never use these accounts on a network.
import { SigningKey, computeAddress } from "ethers";
import { buildApprovalRequest } from "../../src/approvals.js";
import { evmAddressToBech32 } from "../../src/address.js";
import { XITCOIN_TESTNET_ROUTE_ID, DIRECTION_INBOUND } from "../../src/protocol.js";
export const keys = [1, 2, 3, 4].map((n) => new SigningKey(`0x${n.toString(16).padStart(64, "0")}`));
export const signers = keys.slice(0, 3).map((k) => computeAddress(k.publicKey));
export function sign(request, indexes = [1, 0]) {
  return indexes.map((i) => ({ signer: computeAddress(keys[i].publicKey), digest: request.digest,
    signature: keys[i].sign(request.digest).serialized }));
}
export function inbound(overrides = {}) {
  const request = buildApprovalRequest({ direction: DIRECTION_INBOUND, payload: {
    destinationChainId: "xitcoin-testnet-v2-1", routeId: XITCOIN_TESTNET_ROUTE_ID, sourceChainId: "338", sourceRef: `0x${"aa".repeat(32)}`,
    nonce: "18446744073709551615", destination: evmAddressToBech32(signers[0]), amount: "10",
    // 1999999997 gives the two fixture approvals different recovery bytes
    // (0x1b and 0x1c) under the v2 digest of the stored testnet route ID.
    deadlineUnix: "1999999997", ...overrides,
  } });
  return { chainId: "xitcoin-testnet-v2-1", request, approvals: sign(request), authorizedSigners: signers,
    submitter: evmAddressToBech32(signers[2]), nowUnix: 1_900_000_000 };
}
