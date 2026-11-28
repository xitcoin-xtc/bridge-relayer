import { randomBytes } from "node:crypto";
import { lstatSync } from "node:fs";
import { isAbsolute, join, normalize } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { Interface, Signature, Transaction, getAddress, keccak256 } from "ethers";
import { BroadcastLedger } from "./broadcast-ledger.js";
import { TransportError, createBoundedGetFetch } from "./bounded-transport.js";
import { buildTransferApprovalRequest } from "./coordinator.js";
import { inspectCronosSignedTransaction, prepareCronosRelease } from "./cronos-destination.js";
import { CronosRpcQuorum, RpcDisagreement, RpcInvalid, data as returnData, normalizeBlock, safeQuantity } from "./cronos-rpc.js";
import { verifiedDestinationQuorum } from "./destination-validation.js";
import { runDurableSubmissionCycle, SubmissionUnavailable } from "./durable-broadcast.js";
import { CometBftHttpClient, decodeXitcoinOutboundBlock, decodeXitcoinOutboundTransaction } from "./network.js";
import { TESTNET_ROUTE_ID } from "./preflight.js";
import { DIRECTION_OUTBOUND } from "./protocol.js";
import { createEncryptedKeystoreDigestSigner } from "./secure-keystore.js";
import { createOutboundSourceVerifier } from "./source-verification.js";
import { RelayStore, isRelayStoreBusy } from "./store.js";
import { validateCronosTestnetManifest } from "./submitter-manifest.js";
import { XitcoinFinalizedWatcher } from "./watchers.js";

// Cronos testnet (chain ID 338) destination adapter for the durable engine.
// Every decision comes from bounded reads that must agree across independent
// origins. Identity (code hash, route, signer set and version) is read at a
// finalized height; live conditions (pause, replay, liquidity, simulation) must
// be acceptable on every origin at the latest block. The adapter never retries
// with new bytes: the engine may only resend the identical persisted transaction.
const VAULT = new Interface([
  "function release(bytes32 sourceBurnId,address recipient,uint256 amount,uint64 signerSetVersion,uint256 deadline,bytes[] signatures)",
  "event Released(bytes32 indexed sourceBurnId,address indexed recipient,uint256 amount,uint64 signerSetVersion)",
  "function paused() view returns (bool)",
  "function routeId() view returns (bytes32)",
  "function signerSetVersion() view returns (uint64)",
  "function signers() view returns (address[3])",
  "function processedBurns(bytes32) view returns (bool)",
  "function maxReleaseAmount() view returns (uint256)",
  "function availableLiquidity() view returns (uint256)",
  "function dailyReleaseLimit() view returns (uint256)",
  "function releaseDay() view returns (uint256)",
  "function releasedToday() view returns (uint256)",
]);
const RELEASED_TOPIC = VAULT.getEvent("Released").topicHash;
const ZERO_WORD = "0".repeat(64);
const halt = (code) => ({ action: "halt", code });
// Route-scoped waits stop the cycle; transfer-scoped waits defer only that
// transfer so the queue keeps moving.
const wait = (code) => ({ action: "wait", code });
const defer = (code) => ({ action: "wait", code, defer: true });
const hex = (number) => `0x${number.toString(16)}`;
const unavailable = (code) => new SubmissionUnavailable(code);

function words(value, count) {
  if (typeof value !== "string" || value.length !== 2 + 64 * count) throw unavailable("vault_read_invalid");
  return Array.from({ length: count }, (_, index) => value.slice(2 + 64 * index, 66 + 64 * index));
}
function boolean(value) {
  const [word] = words(value, 1);
  if (word === ZERO_WORD) return false;
  if (word === `${"0".repeat(63)}1`) return true;
  throw unavailable("vault_read_invalid");
}
const uint = (value) => BigInt(`0x${words(value, 1)[0]}`);
const bytes32 = (value) => `0x${words(value, 1)[0]}`;
function addresses(value) {
  return words(value, 3).map((word) => {
    if (!word.startsWith("0".repeat(24))) throw unavailable("vault_read_invalid");
    return getAddress(`0x${word.slice(24)}`);
  });
}
const max = (values) => values.reduce((a, b) => (b > a ? b : a));
const min = (values) => values.reduce((a, b) => (b < a ? b : a));
const stable = (value) => JSON.stringify(value);
const sorted = (values) => values.map((value) => value.toLowerCase()).sort();

export function createCronosAdapter({ manifest, rpc, signer, verifySource }) {
  const config = validateCronosTestnetManifest(manifest);
  const cronos = config.cronos;
  if (!(rpc instanceof CronosRpcQuorum) || !signer || typeof signer.signDigest !== "function"
      || signer.signerAddress !== cronos.submitter || typeof verifySource !== "function") {
    throw unavailable("invalid_adapter_dependencies");
  }
  const vault = cronos.vault, submitter = cronos.submitter;
  const gasLimit = BigInt(cronos.gasLimit), maxGasPrice = BigInt(cronos.maxGasPrice), maxFee = BigInt(cronos.maxFee);
  const margin = cronos.minDeadlineMarginSeconds;
  const encode = (name, args = []) => VAULT.encodeFunctionData(name, args);
  const view = (name, args = []) => ({ to: vault, data: encode(name, args) });

  function calldata(request, approvals) {
    const p = request.payload;
    return VAULT.encodeFunctionData("release", [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion, p.deadline,
      approvals.map((approval) => approval.signature)]);
  }

  // The persisted request must be exactly what the coordinator derives from the
  // stored finalized source transfer for this route, vault and signer version.
  function storedRequestMatches(transfer, request, approvals) {
    try {
      if (transfer.source_chain !== "xitcoin" || request.direction !== DIRECTION_OUTBOUND
          || request.payload.chainId !== 338 || getAddress(request.payload.vault) !== vault
          || request.payload.routeId !== config.routeId
          || String(request.payload.signerSetVersion) !== cronos.signerSetVersion) return false;
      const rebuilt = buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" }, routeId: config.routeId,
        cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: vault,
        signerSetVersion: request.payload.signerSetVersion, deadlineUnix: request.deadlineUnix });
      return isDeepStrictEqual(request, JSON.parse(JSON.stringify(rebuilt)))
        && approvals.length >= 2 && approvals.length <= 3 && approvals.every((approval) => approval.digest === request.digest);
    } catch { return false; }
  }

  async function identityAt(height) {
    const block = await rpc.block(height);
    if (keccak256(await rpc.code(vault, height)) !== cronos.vaultCodeHash) throw unavailable("vault_code_mismatch");
    const [route, version, signerList, maxRelease] = await Promise.all([
      rpc.call(view("routeId"), height), rpc.call(view("signerSetVersion"), height),
      rpc.call(view("signers"), height), rpc.call(view("maxReleaseAmount"), height)]);
    if (bytes32(route) !== cronos.cronosRouteId) throw unavailable("vault_route_mismatch");
    const chainVersion = uint(version);
    if (chainVersion >= 1n << 64n || chainVersion.toString() !== cronos.signerSetVersion) throw unavailable("signer_set_version_mismatch");
    if (!isDeepStrictEqual(sorted(addresses(signerList)), sorted(cronos.authorizedSigners))) throw unavailable("signer_set_mismatch");
    return { blockHash: block.hash, maxReleaseAmount: uint(maxRelease) };
  }

  async function viewEach(name, args, parse) {
    const result = await rpc.callVerdict(view(name, args), "latest");
    if (result.reverted) throw unavailable("vault_read_reverted");
    return result.values.map(parse);
  }

  async function live(transferId) {
    const [paused, processed, liquidity, blocks] = await Promise.all([viewEach("paused", [], boolean),
      viewEach("processedBurns", [transferId], boolean), viewEach("availableLiquidity", [], uint), rpc.latestBlocks()]);
    const times = blocks.map((block) => block.timestamp);
    return { paused: paused.some(Boolean), processedAll: processed.every(Boolean), processedAny: processed.some(Boolean),
      liquidity: min(liquidity), chainTime: Math.max(...times) };
  }

  // Reads of history older than the recent window (the last
  // releaseLookbackBlocks blocks). A provider that explicitly cannot serve them
  // (null, JSON-RPC error: pruned or state-synced) will not start to; that ends
  // the search as unreachable instead of stopping temporarily forever.
  // Transport failures stay temporary. Recent history must always be served.
  const UNREACHABLE = Symbol("unreachable");
  async function historical(old, read) {
    if (!old) return read();
    try { return await read(); }
    catch (error) {
      if (error instanceof RpcDisagreement || (error instanceof TransportError && error.code === "rpc_error")) return UNREACHABLE;
      throw error;
    }
  }

  // Highest block at or before the approval deadline, searched only within the
  // recent window; null when the deadline precedes it. No release using this
  // request or an earlier one (re-issues only extend the deadline) is later.
  async function deadlineBlock(deadline, tip, recent) {
    if ((await rpc.block(tip)).timestamp <= deadline) return tip;
    if ((await rpc.block(recent)).timestamp > deadline) return null;
    let low = recent, high = tip - 1;
    while (low < high) {
      const middle = Math.floor((low + high + 1) / 2);
      if ((await rpc.block(middle)).timestamp <= deadline) low = middle; else high = middle - 1;
    }
    return low;
  }

  // The vault's Released event for this burn from any transaction, identical
  // on every origin. Searched first back from our own receipt block (a
  // front-run is mined no later than our revert), then back from the deadline
  // block within the recent window. Every approved field the event carries must
  // match; the receipt must succeed and contain it; its block must be
  // canonical. Returns evidence, { mismatch }, { final: false }, null (nothing
  // in the searched windows) or { unreachable } (history no longer served).
  async function releaseElsewhere(request, ownHash = null, ownBlock = null) {
    const p = request.payload, burn = String(p.sourceBurnId).toLowerCase();
    const expected = VAULT.encodeEventLog(VAULT.getEvent("Released"), [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion]);
    const tip = await rpc.tip();
    const recent = Math.max(0, tip - cronos.releaseLookbackBlocks);
    let unreachable = false;
    const anchors = ownBlock === null ? [] : [ownBlock];
    const deadlineAnchor = await deadlineBlock(request.deadlineUnix, tip, recent);
    if (deadlineAnchor === null) unreachable = true;
    else if (!anchors.includes(deadlineAnchor)) anchors.push(deadlineAnchor);
    for (const anchor of anchors) {
      const lowest = Math.max(0, anchor - cronos.releaseLookbackBlocks);
      for (let to = anchor; to >= lowest; to -= cronos.logRangeBlocks) {
        const from = Math.max(lowest, to - cronos.logRangeBlocks + 1);
        const fetched = await historical(from < recent,
          () => rpc.logs({ address: vault, topics: [RELEASED_TOPIC, burn], fromBlock: hex(from), toBlock: hex(to) }));
        if (fetched === UNREACHABLE) { unreachable = true; break; }
        const logs = fetched.filter((log) => !log.removed && log.address === vault.toLowerCase() && log.topics[0] === RELEASED_TOPIC && log.topics[1] === burn);
        if (!logs.length) continue;
        const log = logs[0];
        if (logs.length > 1 || stable(log.topics) !== stable(expected.topics.map((topic) => topic.toLowerCase()))
            || log.data !== expected.data.toLowerCase()) return { mismatch: true };
        if (log.transactionHash === ownHash) return { final: false };
        const old = log.blockNumber < recent;
        const receipts = await historical(old, () => rpc.receipts(log.transactionHash));
        if (receipts === UNREACHABLE || (old && receipts.some((receipt) => receipt === null))) { unreachable = true; break; }
        if (receipts.some((receipt) => receipt === null)) return { final: false };
        if (receipts.some((receipt) => stable(receipt) !== stable(receipts[0]))) throw new RpcDisagreement();
        const receipt = receipts[0];
        if (receipt.status !== "0x1" || receipt.blockHash !== log.blockHash || receipt.blockNumber !== log.blockNumber
            || !receipt.logs.some((item) => stable(item) === stable(log))) return { mismatch: true };
        const block = await historical(old, () => rpc.block(log.blockNumber));
        if (block === UNREACHABLE) { unreachable = true; break; }
        if (block.hash !== log.blockHash || log.blockNumber > tip - cronos.confirmations) return { final: false };
        return { final: true, releaseHash: log.transactionHash, blockNumber: log.blockNumber, blockHash: log.blockHash };
      }
    }
    return unreachable ? { unreachable: true } : null;
  }
  const released = (evidence) => ({ action: "released_elsewhere", releaseHash: evidence.releaseHash,
    blockNumber: evidence.blockNumber, blockHash: evidence.blockHash });

  // Latest block timestamps from the origins that answer (a strict majority).
  async function latestTimes() {
    return (await rpc.majorityAnswers("eth_getBlockByNumber", ["latest", false], normalizeBlock)).map((block) => block.timestamp);
  }

  // A vault condition at the inclusion block, identical on every origin, that
  // explains a revert and belongs to this transfer. It never authorizes a new
  // transaction: the transfer is only parked without blocking the queue.
  async function lastingRevertCause(request, receipt, block, tx) {
    if (BigInt(receipt.gasUsed) >= tx.gasLimit) return null; // out of gas: a gas policy problem for every transfer
    const at = receipt.blockNumber;
    // A pause is a route-wide guardian incident, not a condition of this
    // transfer: a revert under a pause stays `failed` for operator review.
    const [version, maxRelease, dailyLimit, day, releasedToday, liquidity] = await Promise.all(
      ["signerSetVersion", "maxReleaseAmount", "dailyReleaseLimit", "releaseDay", "releasedToday", "availableLiquidity"]
        .map((name) => rpc.call(view(name), at)));
    const amount = BigInt(request.payload.amount);
    if (uint(version).toString() !== String(request.payload.signerSetVersion)) return "signer_set_rotated";
    if (amount > uint(maxRelease)) return "release_limit_exceeded";
    if (uint(day) === BigInt(block.timestamp) / 86_400n && uint(releasedToday) + amount > uint(dailyLimit)) return "daily_release_limit_exhausted";
    if (uint(liquidity) < amount) return "insufficient_vault_liquidity";
    return null;
  }

  // False only when every origin reports an execution revert.
  async function simulate(request) {
    const result = await rpc.callVerdict(request, "latest");
    if (result.reverted) return false;
    if (result.values.some((value) => value !== "0x")) throw unavailable("simulation_invalid");
    return true;
  }

  async function accountNonces() {
    const [latest, pending] = await Promise.all([rpc.nonces(submitter, "latest"), rpc.nonces(submitter, "pending")]);
    if (new Set(latest).size !== 1 || new Set(pending).size !== 1) return null; // propagation lag
    return { latest: latest[0], pending: pending[0] };
  }

  function parseStored(row) {
    const tx = Transaction.from(row.signedHex);
    if (tx.serialized !== row.signedHex || !tx.isSigned() || tx.type !== 0 || tx.chainId !== 338n || tx.from !== submitter
        || tx.to !== vault || tx.value !== 0n || tx.nonce !== row.nonce || tx.gasLimit > gasLimit || tx.gasPrice > maxGasPrice
        || tx.gasLimit * tx.gasPrice > maxFee || keccak256(row.signedHex) !== row.transactionHash) throw unavailable("stored_transaction_mismatch");
    return tx;
  }

  function matchesProvider(observed, tx) {
    return observed.hash === keccak256(tx.serialized) && observed.from === tx.from.toLowerCase()
      && observed.to === tx.to.toLowerCase() && observed.input === tx.data.toLowerCase() && observed.nonce === tx.nonce
      && observed.value === "0" && observed.gas === tx.gasLimit.toString() && observed.gasPrice === tx.gasPrice.toString()
      && observed.type === 0 && [null, "338"].includes(observed.chainId)
      && observed.v === (338n * 2n + 35n + BigInt(tx.signature.yParity)).toString()
      && observed.r === BigInt(tx.signature.r).toString() && observed.s === BigInt(tx.signature.s).toString();
  }

  function releasedMatches(receipt, request) {
    const p = request.payload;
    const expected = VAULT.encodeEventLog(VAULT.getEvent("Released"), [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion]);
    let matches = 0;
    for (const log of receipt.logs) {
      if (log.removed || log.transactionHash !== receipt.transactionHash || log.blockHash !== receipt.blockHash) return false;
      if (log.address === vault.toLowerCase() && log.topics[0] === RELEASED_TOPIC) {
        if (stable(log.topics) !== stable(expected.topics.map((topic) => topic.toLowerCase()))
            || log.data !== expected.data.toLowerCase()) return false;
        matches += 1;
      }
    }
    return matches === 1;
  }

  return Object.freeze({
    destination: "cronos",
    maxBroadcastAttempts: cronos.maxBroadcastAttempts,

    transferId(request) { return String(request?.payload?.sourceBurnId).toLowerCase(); },

    async assess({ transfer, request, approvals, transferId, nowUnix }) {
      await rpc.chainId();
      if (!storedRequestMatches(transfer, request, approvals) || transferId !== transfer.source_ref) return halt("stored_request_mismatch");
      const recipient = String(request.payload.recipient).toLowerCase();
      // The vault refuses these recipients forever: reject this transfer alone.
      if (!/^0x[0-9a-f]{40}$/.test(recipient) || /^0x0{40}$/.test(recipient) || recipient === "0x000000000000000000000000000000000000dead"
          || recipient === vault.toLowerCase()) return { action: "reject", code: "invalid_recipient" };
      if (request.deadlineUnix < nowUnix + margin) return defer("approval_expired_awaiting_reissue");
      const identity = await identityAt(Math.max(0, await rpc.tip() - cronos.confirmations));
      try {
        const quorum = verifiedDestinationQuorum(request, approvals, cronos.authorizedSigners, nowUnix);
        if (quorum.some(({ signature }) => ![27, 28].includes(Number.parseInt(signature.slice(130, 132), 16)))) throw new Error();
      } catch { return halt("stored_quorum_invalid"); }
      const amount = BigInt(request.payload.amount);
      if (amount > BigInt(cronos.maxAmount) || amount > identity.maxReleaseAmount) return defer("amount_above_release_limit");
      const state = await live(transferId);
      if (state.paused) return wait("route_paused");
      if (state.processedAll) {
        // Released by another transaction (anyone may call the vault with valid approvals).
        const evidence = await releaseElsewhere(request);
        if (evidence?.mismatch) return halt("processed_with_mismatching_release");
        if (evidence && !evidence.unreachable) return evidence.final ? released(evidence) : defer("release_elsewhere_not_final");
        // Processed at a finalized height yet no matching release in the
        // searched window: a persistent, non-blocking alert, never a completion.
        const finalized = Math.max(0, await rpc.tip() - cronos.confirmations);
        if (boolean(await rpc.call(view("processedBurns", [transferId]), finalized))) return { action: "release_unverified" };
        return defer("release_elsewhere_not_final");
      }
      if (state.processedAny) return defer("replay_state_unsettled");
      if (request.deadlineUnix < Math.max(nowUnix, state.chainTime) + margin) return defer("approval_expired_awaiting_reissue");
      if (state.liquidity < amount) return defer("insufficient_vault_liquidity");
      try { await verifySource(request); } catch { throw unavailable("source_finality_unverified"); }
      const data = calldata(request, approvals);
      const gasPrice = max(await rpc.gasPrices());
      if (gasPrice < 1n || gasPrice > maxGasPrice) return wait("gas_price_above_cap");
      const estimate = await rpc.estimateVerdict({ from: submitter, to: vault, data });
      if (estimate.reverted) return defer("release_simulation_reverted");
      if (estimate.values.some((value) => value > gasLimit)) return defer("gas_estimate_above_limit");
      if (!await simulate({ from: submitter, to: vault, data })) return defer("release_simulation_reverted");
      if (min(await rpc.balances(submitter)) < gasLimit * gasPrice) return wait("submitter_balance_insufficient");
      return { action: "sign", context: Object.freeze({ gasPrice: gasPrice.toString(), blockHash: identity.blockHash }) };
    },

    async sign({ request, approvals, nowUnix, context, expectedNonce }) {
      await rpc.chainId();
      const nonces = await accountNonces();
      if (!nonces) return wait("account_nonce_unsettled");
      if (nonces.pending !== nonces.latest) return halt("foreign_pending_transaction");
      if (expectedNonce !== null && nonces.latest !== expectedNonce) return halt("account_nonce_not_owned");
      let plan, custody;
      try {
        plan = prepareCronosRelease({ request, approvals, authorizedSigners: [...cronos.authorizedSigners], nowUnix,
          identity: { chainId: 338, vault, codeHash: cronos.vaultCodeHash, routeId: cronos.cronosRouteId, submitter },
          state: { chainId: 338, vault, codeHash: cronos.vaultCodeHash, routeId: cronos.cronosRouteId, paused: false,
            processed: false, signerSetVersion: cronos.signerSetVersion, blockHash: context.blockHash },
          transaction: { nonce: String(nonces.latest), gasLimit: cronos.gasLimit, gasPrice: context.gasPrice },
          limits: { maxGas: cronos.gasLimit, maxGasPrice: cronos.maxGasPrice, maxFee: cronos.maxFee } });
      } catch { throw unavailable("release_plan_rejected"); }
      const tx = Transaction.from({ type: 0, chainId: 338, to: plan.to, data: plan.data, value: 0,
        nonce: Number(plan.nonce), gasLimit: plan.gasLimit, gasPrice: plan.gasPrice });
      try {
        tx.signature = Signature.from(await signer.signDigest(tx.unsignedHash));
        custody = inspectCronosSignedTransaction(plan, tx.serialized);
      } catch { throw unavailable("submitter_signature_rejected"); }
      return { action: "signed", nonce: nonces.latest, signedHex: custody.signedHex, transactionHash: custody.transactionHash };
    },

    async verifyStored({ row, request, approvals }) {
      try {
        const tx = parseStored(row);
        if (tx.data !== calldata(request, approvals) || row.transferId !== String(request.payload.sourceBurnId).toLowerCase()) throw new Error();
        return { action: "valid" };
      } catch { return halt("stored_transaction_mismatch"); }
    },

    async beforeFirstSend({ row, request, nowUnix }) {
      const tx = parseStored(row);
      // Once the local clock says the approval margin is lost, send the stored
      // bytes without consulting any origin: sending our own committed bytes is
      // never unsafe, and no origin fault can keep their reserved nonce unused.
      if (request.deadlineUnix < nowUnix + margin) return { action: "send" };
      // Strict-majority reads: with three or more origins one faulty origin
      // cannot hold the row until its approval expires. They only decide to
      // proceed or wait; a persisted halt still needs every origin to agree.
      await rpc.chainIdMajority();
      const [latest, pending] = await Promise.all([rpc.majority("eth_getTransactionCount", [submitter, "latest"], safeQuantity),
        rpc.majority("eth_getTransactionCount", [submitter, "pending"], safeQuantity)]);
      if (latest.unanimous && pending.unanimous) {
        if (latest.value > row.nonce) return halt("nonce_consumed_before_send");
        if (latest.value < row.nonce) return halt("account_nonce_regressed");
        if (pending.value !== latest.value) return halt("foreign_pending_transaction");
      } else if (latest.value !== row.nonce || pending.value !== row.nonce) return wait("account_nonce_unsettled");
      const [paused, processed, times] = await Promise.all([rpc.majority("eth_call", [view("paused"), "latest"], returnData),
        rpc.majority("eth_call", [view("processedBurns", [row.transferId]), "latest"], returnData), latestTimes()]);
      if (boolean(paused.value)) return wait("route_paused");
      // Released elsewhere after our bytes were committed: send them once anyway
      // so their reserved nonce is consumed; the observation then records the
      // release, a mismatch halt or an unverified-release alert.
      if (boolean(processed.value)) return { action: "send" };
      if (request.deadlineUnix < Math.max(nowUnix, ...times) + margin) return { action: "send" };
      const exact = { from: submitter, to: vault, data: tx.data, gas: `0x${tx.gasLimit.toString(16)}`, gasPrice: `0x${tx.gasPrice.toString(16)}` };
      const verdict = await rpc.callMajorityVerdict(exact, "latest");
      if (verdict.reverted) return wait("release_simulation_reverted");
      if (verdict.values.some((value) => value !== "0x")) throw unavailable("simulation_invalid");
      return { action: "send" };
    },

    async send({ row }) { await rpc.sendRaw(row.signedHex); },

    async observe({ row, request, nowUnix }) {
      await rpc.chainId();
      const tx = parseStored(row);
      const receipts = await rpc.receipts(row.transactionHash);
      if (receipts.every((receipt) => receipt === null)) {
        const seen = await rpc.transactions(row.transactionHash);
        if (seen.some((observed) => observed && !matchesProvider(observed, tx))) throw unavailable("rpc_transaction_mismatch");
        if (seen.some(Boolean)) return { action: "pending" };
        // Re-observe before every halt: the transaction may have been included
        // or gossiped to an origin between the reads above and below.
        const visible = async () => {
          const [again, seenAgain] = await Promise.all([rpc.receipts(row.transactionHash), rpc.transactions(row.transactionHash)]);
          return again.some(Boolean) || seenAgain.some(Boolean);
        };
        const nonces = await accountNonces();
        if (!nonces) return { action: "pending" };
        if (nonces.latest > row.nonce) return await visible() ? { action: "pending" } : halt("nonce_consumed_without_receipt");
        if (nonces.latest < row.nonce) return halt("account_nonce_regressed");
        if (nonces.pending !== nonces.latest) return await visible() ? { action: "pending" } : halt("foreign_pending_transaction");
        const state = await live(row.transferId);
        if (state.paused) return wait("route_paused");
        if (state.processedAny) {
          if (!state.processedAll || await visible()) return { action: "pending" };
          const again = await accountNonces();
          if (again?.latest !== row.nonce) return { action: "pending" };
          // Still unknown with our nonce unused: another transaction released it.
          // Resend the identical bytes so the reserved nonce is consumed.
          const evidence = await releaseElsewhere(request, row.transactionHash);
          if (evidence?.mismatch) return halt("processed_with_mismatching_release");
        }
        // Even after the deadline the identical bytes are resent: they then
        // revert and consume the reserved nonce (`expired`, never blocking).
        if (row.broadcastAttempts >= cronos.maxBroadcastAttempts) return halt("broadcast_attempts_exhausted");
        return { action: "rebroadcast" };
      }
      const present = receipts.filter(Boolean);
      if (present.some((receipt) => stable(receipt) !== stable(present[0]))) throw new RpcDisagreement();
      if (present.length !== receipts.length) return { action: "pending" }; // indexing lag
      const receipt = present[0];
      if (receipt.transactionHash !== row.transactionHash || receipt.from !== submitter.toLowerCase()
          || receipt.to !== vault.toLowerCase() || receipt.contractAddress !== null) return halt("receipt_mismatch");
      const included = await rpc.transactions(row.transactionHash);
      if (included.some((observed) => observed === null)) return { action: "pending" };
      // Persist a mismatch only when every origin returns the same object.
      if (included.some((observed) => stable(observed) !== stable(included[0]))) throw new RpcDisagreement();
      if (!matchesProvider(included[0], tx)) return halt("included_transaction_mismatch");
      if (included.some((observed) => observed.blockHash !== receipt.blockHash || observed.blockNumber !== receipt.blockNumber)) {
        return { action: "pending" };
      }
      const tip = await rpc.tip();
      const block = await rpc.block(receipt.blockNumber);
      if (block.hash !== receipt.blockHash) return { action: "pending" }; // reorganizing
      if (receipt.status === "0x1" && !releasedMatches(receipt, request)) return halt("release_event_mismatch");
      const finalizedHeight = tip - cronos.confirmations;
      if (receipt.blockNumber > finalizedHeight) return { action: "pending" };
      const inclusion = { blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
      if (receipt.status === "0x0") {
        // A revert because another finalized transaction already released this
        // transfer (for example a front-run copying our calldata) is not a failure.
        if (boolean(await rpc.call(view("processedBurns", [row.transferId]), finalizedHeight))) {
          const evidence = await releaseElsewhere(request, row.transactionHash, receipt.blockNumber);
          if (evidence?.mismatch) return halt("processed_with_mismatching_release");
          // Searched back from our receipt and from the deadline within the
          // recent window, never the whole chain. Evidence that is absent or
          // whose history is no longer served becomes a persistent non-blocking
          // alert instead of a temporary stop repeated forever.
          if (!evidence || evidence.unreachable) return { action: "release_unverified", ...inclusion };
          return evidence.final ? released(evidence) : { action: "pending" };
        }
        // Mined after the approval deadline (agreed block timestamp): the
        // approval expired; our nonce is consumed and the queue moves on.
        if (block.timestamp > request.deadlineUnix) return { action: "expired", ...inclusion };
        // Mined before the deadline: a lasting condition of this transfer at the
        // inclusion block (every origin agreeing) is transfer-specific and does
        // not block the queue. Out of gas or an unexplained revert still does.
        const cause = await lastingRevertCause(request, receipt, block, tx);
        return cause ? { action: "reverted", code: cause, ...inclusion } : { action: "failed", ...inclusion };
      }
      if (!boolean(await rpc.call(view("processedBurns", [row.transferId]), finalizedHeight))) return halt("replay_flag_missing_after_release");
      return { action: "finalized", ...inclusion };
    },
  });
}

export function cronosLedgerBinding(manifest) {
  const config = validateCronosTestnetManifest(manifest);
  return Object.freeze({ destination: "cronos", chainId: "338", routeId: config.routeId, target: config.cronos.vault,
    targetIdentity: config.cronos.vaultCodeHash, account: config.cronos.submitter });
}

// RelayStore is created by the coordinator. Never create an empty one here.
export function openExistingRelayStore(path, options) {
  if (typeof path !== "string" || !isAbsolute(path) || normalize(path) !== path) throw unavailable("relay_store_unavailable");
  const info = lstatSync(path, { throwIfNoEntry: false });
  if (!info || !info.isFile() || info.isSymbolicLink()) throw unavailable("relay_store_unavailable");
  return new RelayStore(path, options);
}

// Conditions that persist nothing and may clear by themselves: the runtime
// pauses and retries. Persisted halts, identity or configuration mismatches and
// unknown errors still stop the process for an operator.
const TEMPORARY_CODES = new Set(["rpc_transaction_mismatch", "source_finality_unverified"]);
export function isTemporaryStop(error) {
  return error instanceof TransportError || error instanceof RpcDisagreement || error instanceof RpcInvalid
    || isRelayStoreBusy(error) || (error instanceof SubmissionUnavailable && TEMPORARY_CODES.has(error.code));
}
function temporaryCode(error) {
  if (isRelayStoreBusy(error)) return "relay_store_busy";
  return typeof error?.code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(error.code) ? error.code : "temporary_condition";
}

const delay = (ms, signal) => new Promise((resolve) => {
  if (signal?.aborted) return resolve();
  const timer = setTimeout(done, ms);
  function done() { clearTimeout(timer); signal?.removeEventListener?.("abort", done); resolve(); }
  signal?.addEventListener?.("abort", done, { once: true });
});

export async function buildCronosSubmitterRuntime(manifest, { credentialsDirectory, fetchImpl = globalThis.fetch,
  loadSigner = createEncryptedKeystoreDigestSigner, makeLedger = (path, binding) => new BroadcastLedger(path, binding),
  makeStore = openExistingRelayStore, boundary = async () => {}, now = Date.now,
  log = (report) => process.stdout.write(`${JSON.stringify(report)}\n`) } = {}) {
  const config = validateCronosTestnetManifest(manifest);
  if (typeof credentialsDirectory !== "string" || !isAbsolute(credentialsDirectory)) throw unavailable("credentials_directory_required");
  const rpc = new CronosRpcQuorum({ urls: [...config.cronos.rpcUrls], allowLoopbackHttp: config.cronos.allowLoopbackHttp, fetchImpl });
  await rpc.chainId();
  const boundedGet = createBoundedGetFetch({ fetchImpl });
  const clients = config.xitcoin.rpcUrls.map((url) => new CometBftHttpClient({ url, chainId: config.xitcoinChainId,
    decodeBlock: decodeXitcoinOutboundBlock, decodeTransaction: decodeXitcoinOutboundTransaction,
    allowHttp: config.xitcoin.allowLoopbackHttp, fetchImpl: boundedGet }));
  const xitcoinWatcher = new XitcoinFinalizedWatcher({ clients, chainId: config.xitcoinChainId, routeId: config.routeId,
    safetyLag: config.xitcoin.safetyLag, maxBatch: 1 });
  let signer;
  try {
    signer = await loadSigner({ keystorePath: config.keystorePath,
      credentialPath: join(credentialsDirectory, "keystore-password"), expectedAddress: config.cronos.submitter });
  } catch { throw unavailable("submitter_key_unavailable"); }
  let ledger, store;
  try {
    ledger = makeLedger(config.ledgerPath, cronosLedgerBinding(config));
    store = makeStore(config.relayStorePath);
    const adapter = createCronosAdapter({ manifest: config, rpc, signer, verifySource: createOutboundSourceVerifier({ xitcoinWatcher }) });
    const owner = randomBytes(16).toString("hex");
    const runOnce = () => runDurableSubmissionCycle({ store, ledger, adapter, owner, nowMs: now(), boundary,
      leaseTtlMs: Math.max(60_000, config.cycleIntervalMs * 6) });
    return Object.freeze({
      manifest: config,
      runOnce,
      async run({ signal } = {}) {
        let failures = 0;
        while (!signal?.aborted) {
          try {
            log(await runOnce());
            failures = 0;
            await delay(config.cycleIntervalMs, signal);
          } catch (error) {
            if (!isTemporaryStop(error)) throw error;
            failures = Math.min(failures + 1, 8);
            log(Object.freeze({ destination: "cronos", action: "temporarily_stopped", code: temporaryCode(error) }));
            await delay(Math.min(config.cycleIntervalMs * 2 ** failures, 300_000), signal);
          }
        }
      },
      close() {
        // Release this worker's lease on clean shutdown; a takeover after a
        // crash still waits for expiry and increments the fencing epoch.
        try { ledger.releaseLease(ledger.acquireLease(owner, { nowMs: now(), ttlMs: 1_000 })); } catch { /* Not held. */ }
        try { ledger.close(); } finally { store.close(); }
      },
    });
  } catch (error) {
    try { ledger?.close(); } catch { /* Preserve the original failure. */ }
    try { store?.close(); } catch { /* Preserve the original failure. */ }
    throw error instanceof SubmissionUnavailable ? error : unavailable("submitter_state_unavailable");
  }
}
