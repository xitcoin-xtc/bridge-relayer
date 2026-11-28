import { Interface, getAddress } from "ethers";

import { buildApprovalRequest } from "./approvals.js";
import { CronosRpcQuorum } from "./cronos-rpc.js";
import { DIRECTION_INBOUND, DIRECTION_OUTBOUND, attestationId, normalizeBytes32 } from "./protocol.js";
import { XITCOIN_TESTNET_CHAIN_ID } from "./xitcoin-transaction.js";
import { XitcoinRpcQuorum } from "./xitcoin-rpc.js";

// Destination proof that an approval can never be used again, required before
// any re-issue for the same source event is requested or signed.
//
// Both destinations accept an approval only while the executing block's time
// is at or before its deadline (Cronos vault `release`: `block.timestamp >
// deadline` reverts; Xitcoin `Attestation.ValidateAt`: `ctx.BlockTime() >
// deadline` fails), and block time never decreases. So an approval is retired
// at a final height H when:
//   1. block H's time is strictly later than the approval's deadline, and
//   2. the transfer's replay key is unused at H (Cronos `processedBurns` is
//      false; the Xitcoin attestation record is ATTESTATION_STATE_ABSENT),
// every origin serving H and agreeing on the block and on both reads. Every
// later block also has a later time, so the approval is dead forever; the
// replay key being unused at H shows it was not used before.
//
// Cronos: H = tip - confirmations (tip = the lowest head across origins).
// Xitcoin: H = one block below the lowest height any origin reports (CometBFT
// stores a block before the application commits it; commits are final).
export class RetirementUnproven extends Error {
  constructor(code) { super("previous approval is not provably retired on the destination"); this.code = code; }
}

const VAULT = new Interface(["function processedBurns(bytes32) view returns (bool)"]);

function fail(code) { return new RetirementUnproven(code); }

function classify(error) {
  if (error instanceof RetirementUnproven) return error;
  if (error?.code === "rpc_disagreement") return fail("destination_disagreement");
  return fail("destination_unavailable");
}

function deadline(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw fail("invalid_previous_deadline");
  return value;
}

export function createApprovalRetirementVerifier({ cronos, cronosVault, cronosChainId = 338, cronosConfirmations, xitcoin }) {
  if (!(cronos instanceof CronosRpcQuorum) || !(xitcoin instanceof XitcoinRpcQuorum)) {
    throw new Error("bounded Cronos and Xitcoin quorum transports are required");
  }
  const vault = getAddress(cronosVault);
  if (cronosChainId !== 338) throw new Error("only the Cronos testnet destination is supported");
  if (!Number.isSafeInteger(cronosConfirmations) || cronosConfirmations < 1 || cronosConfirmations > 10_000) {
    throw new Error("Cronos confirmations are invalid");
  }

  async function cronosRetired(payload, previousDeadline) {
    if (String(payload.chainId) !== String(cronosChainId) || getAddress(payload.vault) !== vault) throw fail("destination_mismatch");
    await cronos.chainId();
    const height = (await cronos.tip()) - cronosConfirmations;
    if (height < 1) throw fail("destination_unavailable");
    const block = await cronos.block(height);
    const processed = await cronos.call({ to: vault, data: VAULT.encodeFunctionData("processedBurns", [normalizeBytes32(payload.sourceBurnId)]) }, height);
    if (!/^0x0{63}[01]$/.test(processed)) throw fail("destination_unavailable");
    if ((await cronos.block(height)).hash !== block.hash) throw fail("destination_disagreement");
    // A used replay key at a final height is definitive, whatever the time.
    if (processed.endsWith("1")) throw fail("transfer_processed");
    if (block.timestamp <= previousDeadline) throw fail("deadline_not_passed");
    return Object.freeze({ retired: true, destination: "cronos", height, blockHash: block.hash, blockTime: block.timestamp });
  }

  async function xitcoinRetired(payload, previousDeadline) {
    if (payload.destinationChainId !== XITCOIN_TESTNET_CHAIN_ID) throw fail("destination_mismatch");
    const height = Math.min(...(await xitcoin.chainId()).map((status) => status.height)) - 1;
    if (!Number.isSafeInteger(height) || height < 1) throw fail("destination_unavailable");
    const block = await xitcoin.block(height);
    const id = attestationId({ ...payload, direction: DIRECTION_INBOUND });
    const answers = await xitcoin.attestations(id, height);
    if (answers.some((answer) => JSON.stringify(answer) !== JSON.stringify(answers[0]))) throw fail("destination_disagreement");
    // A used replay key at a committed height is definitive, whatever the time.
    if (answers[0].status !== "absent") throw fail("transfer_processed");
    if (block.time <= previousDeadline) throw fail("deadline_not_passed");
    return Object.freeze({ retired: true, destination: "xitcoin", height, blockHash: block.hash, blockTime: block.time });
  }

  // Resolves with the evidence when retired; rejects with RetirementUnproven
  // (code: transfer_processed, deadline_not_passed, destination_mismatch,
  // destination_disagreement, destination_unavailable) otherwise.
  // `transfer_processed` (every origin shows the replay key used at the final
  // height) is permanent: that approval or an earlier one was used.
  return async function verifyRetired({ request, previousDeadlineUnix }) {
    try {
      const canonical = buildApprovalRequest(request);
      const previous = deadline(previousDeadlineUnix);
      if (canonical.direction === DIRECTION_OUTBOUND) return await cronosRetired(canonical.payload, previous);
      if (canonical.direction === DIRECTION_INBOUND) return await xitcoinRetired(canonical.payload, previous);
      throw fail("destination_mismatch");
    } catch (error) { throw classify(error); }
  };
}

// Checks a verifier's answer before it is trusted: a retirement result must
// be explicit and name a block time strictly after the retired deadline.
export function retirementEvidence(value, previousDeadlineUnix) {
  if (!value || typeof value !== "object" || value.retired !== true || !Number.isSafeInteger(value.height) || value.height < 1
      || !Number.isSafeInteger(value.blockTime) || value.blockTime <= previousDeadlineUnix
      || !["cronos", "xitcoin"].includes(value.destination)) throw fail("invalid_retirement_evidence");
  return Object.freeze({ destination: value.destination, height: value.height, blockTime: value.blockTime });
}
