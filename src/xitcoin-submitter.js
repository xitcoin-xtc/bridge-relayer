import { randomBytes } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { computeAddress, getAddress } from "ethers";
import { evmAddressToBech32 } from "./address.js";
import { BroadcastLedger } from "./broadcast-ledger.js";
import { TransportError } from "./bounded-transport.js";
import { buildTransferApprovalRequest } from "./coordinator.js";
import { openExistingRelayStore } from "./cronos-submitter.js";
import { CronosRpcQuorum, RpcDisagreement, RpcInvalid } from "./cronos-rpc.js";
import { boundedCronosProviders } from "./cronos-source.js";
import { verifiedDestinationQuorum } from "./destination-validation.js";
import { runDurableSubmissionCycle, SubmissionUnavailable } from "./durable-broadcast.js";
import { TESTNET_ROUTE_ID } from "./preflight.js";
import { DIRECTION_INBOUND, attestationId, attestationPayloadHash } from "./protocol.js";
import { createEncryptedKeystoreDigestSigner } from "./secure-keystore.js";
import { createInboundSourceVerifier } from "./source-verification.js";
import { isRelayStoreBusy } from "./store.js";
import { validateXitcoinTestnetManifest } from "./submitter-manifest.js";
import { CronosFinalizedWatcher } from "./watchers.js";
import { XitcoinRpcDisagreement, XitcoinRpcInvalid, XitcoinRpcQuorum } from "./xitcoin-rpc.js";
import { XITCOIN_TESTNET_CHAIN_ID, accountOfPublicKey, assembleSimulationTx, assembleTxRaw, buildXitcoinSignDoc, cosmosSignature,
  decodeXitcoinTransaction, encodeSubmitAttestation, sameSignedContent, signedContent, verifyXitcoinSignature } from "./xitcoin-transaction.js";

// Xitcoin testnet (xitcoin-testnet-v2-1) destination adapter for the durable
// engine: one signed Cosmos transaction carrying MsgSubmitAttestation per
// Cronos deposit. Every decision comes from bounded reads of independent
// origins; route identity, replay state (the typed attestation query) and
// inclusion (CometBFT tx_search, block, attestation record) must agree on every
// origin before a transfer is claimed, completed or halted. Only the decision
// to send or wait for already committed bytes uses a strict majority. The
// adapter never produces new bytes for a transfer: the engine may only resend
// the identical persisted transaction.
const halt = (code) => ({ action: "halt", code });
const wait = (code) => ({ action: "wait", code });
const defer = (code) => ({ action: "wait", code, defer: true });
const unavailable = (code) => new SubmissionUnavailable(code);
const UNREACHABLE = Symbol("unreachable");
// A transaction whose block is this many blocks deep and that a strict
// majority of origins still does not return from its transaction index is no
// longer indexing lag: its result is settled from consensus state only.
const INDEX_LAG_BLOCKS = 100;
const max = (values) => values.reduce((a, b) => (b > a ? b : a));
const min = (values) => values.reduce((a, b) => (b < a ? b : a));
const sorted = (values) => values.map((value) => value.toLowerCase()).sort();
const stable = (value) => JSON.stringify(value);
const lower = (hash) => hash.toLowerCase();
// A canonical lower-case Xitcoin account of 20 bytes, other than the zero and
// 0x...dEaD accounts (evmAddressToBech32 refuses both).
function validRecipient(value) {
  if (typeof value !== "string" || !/^xtc1[02-9ac-hj-np-z]{38}$/.test(value)) return false;
  try {
    const bytes = bech32Bytes(value);
    return bytes.length === 20 && evmAddressToBech32(`0x${Buffer.from(bytes).toString("hex")}`) === value;
  } catch { return false; }
}

export function createXitcoinAdapter({ manifest, rpc, signer, verifySource }) {
  const config = validateXitcoinTestnetManifest(manifest);
  const x = config.xitcoin;
  if (!(rpc instanceof XitcoinRpcQuorum) || !signer || typeof signer.signDigest !== "function"
      || typeof signer.compressedPublicKey !== "string" || typeof verifySource !== "function") {
    throw unavailable("invalid_adapter_dependencies");
  }
  const publicKey = signer.compressedPublicKey;
  if (accountOfPublicKey(publicKey) !== x.submitter || evmAddressToBech32(computeAddress(publicKey)) !== x.submitter
      || evmAddressToBech32(signer.signerAddress) !== x.submitter) throw unavailable("submitter_key_mismatch");
  const submitter = x.submitter, routeId = config.routeId, chainId = XITCOIN_TESTNET_CHAIN_ID;
  const margin = x.minDeadlineMarginSeconds;
  const maxGas = BigInt(x.maxGas), maxGasPrice = BigInt(x.maxGasPrice), maxFee = BigInt(x.maxFee);
  let accountNumber = null;

  // The persisted request must be exactly what the coordinator derives from the
  // stored finalized Cronos deposit for this route, vault and chain.
  function storedRequestMatches(transfer, request, approvals) {
    try {
      const p = request.payload;
      if (transfer.source_chain !== "cronos" || request.direction !== DIRECTION_INBOUND || p.destinationChainId !== chainId
          || p.routeId !== routeId || p.sourceChainId !== "338") return false;
      const rebuilt = buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" }, routeId,
        cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: config.cronos.vault, xitcoinChainId: chainId,
        deadlineUnix: request.deadlineUnix });
      return isDeepStrictEqual(request, JSON.parse(JSON.stringify(rebuilt)))
        && approvals.length >= 2 && approvals.length <= 3 && approvals.every((approval) => approval.digest === request.digest);
    } catch { return false; }
  }

  // MsgSubmitAttestation exactly as the chain hashes and stores it; the
  // approval request fields are passed verbatim (test/fixtures/xitcoin-chain-vectors.json).
  function messageOf(request, approvals) {
    const p = request.payload;
    return encodeSubmitAttestation({ submitter, routeId: p.routeId, direction: request.direction, sourceChainId: p.sourceChainId,
      sourceRef: p.sourceRef, nonce: p.nonce, destination: p.destination, amount: p.amount, deadlineUnix: String(p.deadlineUnix),
      signatures: approvals.map((approval) => approval.signature) });
  }

  // Every approved field the record must carry. `exact` also requires our
  // approval (deadline, digests, approvers): a record of our own transaction.
  function recordMatches(record, request, approvals, { exact }) {
    const p = request.payload;
    const approved = record.routeId === routeId && record.direction === DIRECTION_INBOUND && record.sourceChainId === p.sourceChainId
      && record.sourceRef === p.sourceRef.slice(2) && record.nonce === p.nonce && record.recipient === p.destination
      && record.amount === p.amount && record.destinationChainId === chainId;
    if (!approved || !exact) return approved;
    return record.deadlineUnix === String(p.deadlineUnix) && record.signingDigest === request.digest
      && record.payloadHash === attestationPayloadHash({ ...p, direction: request.direction })
      && record.signerSetVersion === x.signerSetVersion
      && isDeepStrictEqual(record.approvers, approvals.map((approval) => getAddress(approval.signer)));
  }

  async function knownAccountNumber() {
    if (accountNumber !== null) return accountNumber;
    const accounts = await rpc.accounts(submitter);
    if (accounts.some((account) => account.accountNumber !== accounts[0].accountNumber)) throw new XitcoinRpcDisagreement();
    if (accounts.some((account) => account.publicKey !== null && account.publicKey !== publicKey)) throw unavailable("submitter_key_mismatch");
    accountNumber = accounts[0].accountNumber;
    return accountNumber;
  }

  // Route identity on every origin at its latest committed height. A paused or
  // disabled route is a route-scoped wait; any identity mismatch stops.
  async function routeState() {
    const [params, routes] = await Promise.all([rpc.params(), rpc.routes(routeId)]);
    if (params.chainId !== chainId || params.nativeDenom !== "axtc" || params.requiredApprovals !== 2 || params.signerSetSize !== 3
        || params.attestationDomain !== `xitcoin-bridge-attestation-v2/${chainId}`
        || params.sourceDepositDomain !== "xitcoin-bridge-source-deposit-v1") throw unavailable("chain_params_mismatch");
    // Identity must be identical on every origin before it is compared with
    // the pins: one origin's answer can cause a temporary stop, never a
    // configuration stop.
    const identity = ({ height, controlNonce, outboundNonce, enabled, paused, maxTransferAmount, dailyLimit, maxOutstandingAmount,
      ...rest }) => rest;
    if (routes.some((route) => stable(identity(route)) !== stable(identity(routes[0])))) throw new XitcoinRpcDisagreement();
    const route = routes[0];
    if (route.sourceChainId !== "338") throw unavailable("route_identity_mismatch");
    if (!isDeepStrictEqual(sorted(route.bridgeSigners), sorted(x.authorizedSigners))) throw unavailable("signer_set_mismatch");
    if (route.signerSetVersion !== x.signerSetVersion) throw unavailable("signer_set_version_mismatch");
    return { usable: routes.every((item) => item.enabled && !item.paused), maxTransferAmount: min(routes.map((item) => BigInt(item.maxTransferAmount))) };
  }

  // Price per gas the transaction pays, in axtc: the highest requirement any
  // origin reports, times the configured multiplier, rounded up.
  async function gasPrice() {
    const markets = await rpc.feeMarkets();
    const required = max(markets.map((market) => {
      const base = market.noBaseFee ? 0n : market.baseFee;
      return base > market.minGasPrice ? base : market.minGasPrice;
    }));
    const scale = 100n * 10n ** 18n;
    const price = (required * BigInt(x.feeMultiplierPercent) + scale - 1n) / scale;
    return price < 1n ? 1n : price;
  }

  function signDoc(message, sequence, gasLimit, feeAmount, number) {
    return buildXitcoinSignDoc({ messageBytes: message, publicKey, accountNumber: number, sequence: String(sequence),
      gasLimit: gasLimit.toString(), feeAmount: feeAmount.toString(), chainId });
  }

  async function sequences() {
    const accounts = await rpc.accounts(submitter);
    if (accounts.some((account) => account.publicKey !== null && account.publicKey !== publicKey)) throw unavailable("submitter_key_mismatch");
    if (new Set(accounts.map((account) => account.sequence)).size !== 1) return null; // propagation lag
    return accounts[0].sequence;
  }

  // The stored bytes must be exactly one MsgSubmitAttestation for this request
  // signed by our key at the row's sequence, within the gas and fee caps.
  async function parseStored(row, request, approvals) {
    const decoded = decodeXitcoinTransaction(row.signedHex);
    const number = await knownAccountNumber();
    const gas = BigInt(decoded.gasLimit), fee = BigInt(decoded.feeAmount);
    if (decoded.transactionHash !== row.transactionHash || decoded.publicKey !== publicKey || decoded.sequence !== String(row.nonce)
        || !encodeSubmitAttestation(decoded.message).equals(messageOf(request, approvals))
        || gas > maxGas || fee > maxFee || fee > gas * maxGasPrice
        || !verifyXitcoinSignature({ ...decoded, chainId, accountNumber: number })) throw unavailable("stored_transaction_mismatch");
    return decoded;
  }

  // The value a strict majority of origins returns identically for a
  // transaction lookup (absent and failing answers never count). With two
  // origins that is both; with three, two. Null without such a majority.
  function majorityValue(answers) {
    const counts = new Map();
    for (const answer of answers) {
      if (!answer.ok || answer.value === null) continue;
      const key = stable(answer.value);
      counts.set(key, { value: answer.value, count: (counts.get(key)?.count ?? 0) + 1 });
    }
    const best = [...counts.values()].sort((a, b) => b.count - a.count)[0];
    return best && best.count >= rpc.majoritySize ? best.value : null;
  }

  // Whether the stored transaction's fee would be admitted now: its price per
  // gas covers the base fee and the minimum gas price that a strict majority of
  // origins report (the highest of them). Only decides send or wait.
  async function admissibleFee(decoded) {
    const gas = BigInt(decoded.gasLimit), fee = BigInt(decoded.feeAmount) * 10n ** 18n;
    for (const market of await rpc.feeMarketsMajority()) {
      const base = market.noBaseFee ? 0n : market.baseFee;
      if (fee < base * gas || fee < market.minGasPrice * gas) return false;
    }
    return true;
  }

  // The attestation on every origin. Returns { absent }, { processed: record },
  // { withoutRecord } or { unsettled } (origins differ, for example a lagging
  // node), or { mismatch } when ANY origin returns a record whose approved
  // fields differ from the request: only a compromised signer quorum (or a
  // lying origin, settled in the offline review) produces one, and a halt is
  // preferred to an alert.
  async function attestationState(request, approvals) {
    const id = attestationId({ ...request.payload, direction: request.direction });
    const answers = await rpc.attestationsSettled(id);
    if (answers.some((answer) => answer.ok && answer.value.record && !recordMatches(answer.value.record, request, approvals, { exact: false }))) {
      return { mismatch: true };
    }
    const failure = answers.find((answer) => !answer.ok);
    if (failure) throw failure.error;
    const values = answers.map((answer) => answer.value);
    if (values.every((value) => value.status === "absent")) return { absent: true };
    if (values.every((value) => value.status === "processed_without_record")) return { withoutRecord: true };
    if (values.every((value) => value.status === "processed") && values.every((value) => stable(value.record) === stable(values[0].record))) {
      return { processed: values[0].record };
    }
    return { unsettled: true };
  }

  // The transaction named by a processing record, committed with code 0 at the
  // record height on every origin, inside a block every origin agrees on.
  async function committedRecordTransaction(record) {
    const lookups = await rpc.txSettled(lower(record.txHash));
    const failure = lookups.find((answer) => !answer.ok);
    if (failure) throw failure.error;
    if (lookups.some((answer) => answer.value === null)) return null; // indexing lag
    if (lookups.some((answer) => stable(answer.value) !== stable(lookups[0].value))) throw new XitcoinRpcDisagreement();
    const tx = lookups[0].value;
    if (tx.height !== record.height || tx.code !== 0) throw new XitcoinRpcDisagreement();
    const block = await rpc.block(record.height);
    if (!block.txHashes.includes(lower(record.txHash))) throw new XitcoinRpcDisagreement();
    return { blockNumber: record.height, blockHash: block.hash };
  }

  // Released by another transaction with every approved field: final once its
  // block has the configured confirmations.
  async function releasedElsewhere(record) {
    const tip = await rpc.tip();
    if (record.height + x.confirmations > tip) return { final: false };
    const inclusion = await committedRecordTransaction(record);
    if (!inclusion) return { final: false };
    return { final: true, releaseHash: lower(record.txHash), ...inclusion };
  }
  const released = (evidence) => ({ action: "released_elsewhere", releaseHash: evidence.releaseHash,
    blockNumber: evidence.blockNumber, blockHash: evidence.blockHash });

  // The lowest height whose committed state shows our sequence consumed (the
  // block that consumed it), searched within the last `historyBlocks` blocks
  // with height-pinned reads every origin agrees on; null when it was consumed
  // before that window, undefined when not yet at the lowest origin height.
  async function sequenceConsumedAt(nonce, tip) {
    let low = Math.max(1, tip - x.historyBlocks), high = tip;
    if (await rpc.sequenceAt(submitter, high) <= nonce) return undefined;
    if (await rpc.sequenceAt(submitter, low) > nonce) return null;
    while (high - low > 1) {
      const middle = Math.floor((low + high) / 2);
      if (await rpc.sequenceAt(submitter, middle) > nonce) high = middle; else low = middle;
    }
    return high;
  }

  // State at the end of the block before ours and at the end of ours, read with
  // height-pinned queries on every origin. A condition counts only when it
  // holds at both heights, so a change made by another transaction in the same
  // block is never taken as the cause; such a failure stays `failed`. Returns a
  // code, null (unexplained) or UNREACHABLE (history no longer served).
  async function lastingFailureCause(request, approvals, inclusion, blockTime, tip) {
    if (BigInt(inclusion.gasUsed) >= BigInt(inclusion.gasWanted)) return null; // out of gas: a gas policy problem
    const before = inclusion.height - 1, at = inclusion.height;
    let read;
    try {
      read = await Promise.all([before, at].map((height) => Promise.all([rpc.routes(routeId, height), rpc.dailyUsages(height),
        rpc.outstandings(height)])));
    } catch (error) {
      if (before < tip - x.historyBlocks && error instanceof TransportError
          && (error.code === "rpc_error" || (error.code === "http_status" && error.httpStatus >= 400 && error.httpStatus < 500))) return UNREACHABLE;
      throw error;
    }
    const states = read.map(([routes, usages, outstandings]) => {
      for (const list of [routes, usages, outstandings]) {
        const strip = ({ height, controlNonce, outboundNonce, ...rest }) => rest;
        if (list.some((item) => stable(strip(item)) !== stable(strip(list[0])))) throw new XitcoinRpcDisagreement();
      }
      return { route: routes[0], usage: usages[0], outstanding: outstandings[0] };
    });
    const amount = BigInt(request.payload.amount), day = BigInt(Math.floor(blockTime / 86_400));
    const approvers = approvals.map((approval) => approval.signer.toLowerCase());
    const causes = [
      ["route_paused", (s) => s.route.paused || !s.route.enabled],
      ["signer_set_rotated", (s) => s.route.signerSetVersion !== x.signerSetVersion
        || approvers.some((signer) => !sorted(s.route.bridgeSigners).includes(signer))],
      ["transfer_limit_exceeded", (s) => amount > BigInt(s.route.maxTransferAmount)],
      ["daily_limit_exhausted", (s) => (BigInt(s.usage.utcDay) === day ? BigInt(s.usage.usedAmount) : 0n) + amount > BigInt(s.usage.dailyLimit)],
      ["outstanding_limit_reached", (s) => BigInt(s.outstanding.outstandingAmount) + amount > BigInt(s.outstanding.maxOutstandingAmount)],
    ];
    return causes.find(([, holds]) => holds(states[0]) && holds(states[1]))?.[0] ?? null;
  }

  // Our sequence is unused: our signed content is pending, was dropped or
  // evicted, or failed in the ante handler (for example a fee below a risen
  // base fee). The signed bytes stay valid for anyone, so this is never a
  // persisted halt: the identical bytes are resent only when nothing carrying
  // them is in flight and they would be admitted now, and otherwise it waits.
  async function notConsumed(row, request, approvals, ours, decoded) {
    const mempools = await rpc.mempools();
    if (mempools.some((mempool) => mempool.txs.some((tx) => sameSignedContent(signedContent(tx), ours)))) return { action: "pending" };
    // A mempool listing that is not complete cannot prove the transaction gone.
    if (mempools.some((mempool) => !mempool.complete)) return { action: "pending" };
    const route = await routeState();
    if (!route.usable) return wait("route_paused");
    const state = await attestationState(request, approvals);
    if (state.mismatch) return halt("processed_with_mismatching_record");
    if (state.unsettled) return { action: "pending" };
    // Resend also when another transaction already processed the attestation or
    // the deadline passed, so the reserved sequence is consumed (the observation
    // then records released_elsewhere or expired).
    if (!await admissibleFee(decoded)) return wait("fee_below_required");
    if (row.broadcastAttempts >= x.maxBroadcastAttempts) return wait("broadcast_attempts_exhausted");
    return { action: "rebroadcast" };
  }

  // Our sequence is consumed. Find the transaction that consumed it and decide
  // from evidence a strict majority of origins returns identically (every
  // origin for state and blocks), never from one origin's transaction result.
  async function consumed(row, request, approvals, ours, tip) {
    const nonceEvent = `${submitter}/${row.nonce}`;
    let inclusion = null;
    const exact = majorityValue(await rpc.txSettled(row.transactionHash));
    if (exact && exact.accountSequences.includes(nonceEvent)) {
      inclusion = { hash: row.transactionHash, result: exact, block: await rpc.block(exact.height) };
    } else {
      // The block whose committed state first shows our sequence consumed
      // (height-pinned reads on every origin), and in it a transaction
      // carrying our signed content: our bytes or a re-encoding of them.
      const consumedAt = await sequenceConsumedAt(row.nonce, tip);
      if (consumedAt === undefined) return { action: "pending" }; // not yet at every origin's height
      if (consumedAt === null) return consumedBeforeWindow(row, request, approvals);
      const block = await rpc.block(consumedAt);
      const candidates = block.txs.flatMap((tx, index) => (sameSignedContent(signedContent(tx), ours) ? [block.txHashes[index]] : []));
      if (!candidates.length) return halt("nonce_consumed_without_inclusion");
      for (const hash of candidates) {
        const result = majorityValue(await rpc.txSettled(hash));
        if (result && result.height === consumedAt && result.accountSequences.includes(nonceEvent)) {
          inclusion = { hash, result, block };
          break;
        }
      }
      if (!inclusion) {
        // Recent: the transaction index lags behind commits.
        if (consumedAt > tip - INDEX_LAG_BLOCKS) return { action: "pending" };
        // Older history whose results no strict majority serves: settle from
        // consensus state only (a record naming our signed content and
        // approval), otherwise a persistent non-blocking alert.
        if (consumedAt + x.confirmations > tip) return { action: "pending" };
        const state = await attestationState(request, approvals);
        if (state.mismatch) return halt("processed_with_mismatching_record");
        if (state.unsettled) return { action: "pending" };
        const record = state.processed;
        if (record && candidates.includes(lower(record.txHash)) && record.height === consumedAt
            && recordMatches(record, request, approvals, { exact: true })) {
          return ownInclusion(row, lower(record.txHash), { blockNumber: consumedAt, blockHash: block.hash });
        }
        if (record && !candidates.includes(lower(record.txHash))) {
          const evidence = await releasedElsewhere(record);
          if (evidence.final) return released(evidence);
        }
        return { action: "release_unverified", code: "inclusion_history_unserved", blockNumber: consumedAt, blockHash: block.hash };
      }
    }
    const { hash, result, block } = inclusion;
    if (!block.txHashes.includes(hash)) throw new XitcoinRpcDisagreement();
    if (result.height + x.confirmations > tip) return { action: "pending" };
    const position = { blockNumber: result.height, blockHash: block.hash };
    const state = await attestationState(request, approvals);
    if (state.mismatch) return halt("processed_with_mismatching_record");
    if (state.unsettled) return { action: "pending" };
    if (result.code === 0) {
      // Our signed content executed: the record must name that transaction and
      // our exact approval.
      if (!state.processed || lower(state.processed.txHash) !== hash || state.processed.height !== result.height
          || !recordMatches(state.processed, request, approvals, { exact: true })) return halt("record_mismatch_after_success");
      return ownInclusion(row, hash, position);
    }
    // Our signed content failed in its message after consuming our sequence.
    if (state.processed) {
      if (lower(state.processed.txHash) === hash) return halt("record_names_failed_transaction");
      // Another transaction processed the attestation first (for example a
      // copy of our pending message): not a failure.
      const evidence = await releasedElsewhere(state.processed);
      return evidence.final ? released(evidence) : { action: "pending" };
    }
    if (state.withoutRecord) return { action: "release_unverified", code: "processed_without_record", ...position };
    // Committed after the approval deadline (agreed block time): expired; our
    // sequence is consumed and the queue moves on.
    if (block.time > request.deadlineUnix) return { action: "expired", ...position };
    const cause = await lastingFailureCause(request, approvals, { height: result.height, gasUsed: result.gasUsed,
      gasWanted: result.gasWanted }, block.time, tip);
    if (cause === UNREACHABLE) return { action: "release_unverified", code: "failure_history_unserved", ...position };
    return cause ? { action: "reverted", code: cause, ...position } : { action: "failed", ...position };
  }

  // Our own bytes are finalized; a re-encoding of our signed content (another
  // hash) is recorded as a release by that transaction, so RelayStore names
  // the transaction that actually executed.
  function ownInclusion(row, hash, position) {
    return hash === row.transactionHash ? { action: "finalized", ...position }
      : { action: "released_elsewhere", releaseHash: hash, ...position };
  }

  // Consumed before the searched window: complete only on a record naming our
  // own transaction and approval in a block every origin still serves.
  async function consumedBeforeWindow(row, request, approvals) {
    const state = await attestationState(request, approvals);
    if (state.mismatch) return halt("processed_with_mismatching_record");
    const record = state.processed;
    if (record && lower(record.txHash) === row.transactionHash && recordMatches(record, request, approvals, { exact: true })) {
      const block = await rpc.block(record.height);
      if (!block.txHashes.includes(row.transactionHash)) throw new XitcoinRpcDisagreement();
      return { action: "finalized", blockNumber: record.height, blockHash: block.hash };
    }
    return halt("nonce_consumed_without_inclusion");
  }

  return Object.freeze({
    destination: "xitcoin",
    maxBroadcastAttempts: x.maxBroadcastAttempts,

    transferId(request) { return attestationId({ ...request?.payload, direction: request?.direction }); },

    async assess({ transfer, request, approvals, transferId, nowUnix }) {
      const statuses = await rpc.chainId();
      if (!storedRequestMatches(transfer, request, approvals)
          || transferId !== attestationId({ ...request.payload, direction: request.direction })) return halt("stored_request_mismatch");
      // The chain mints only to a canonical 20-byte account; anything else can never be sent.
      if (!validRecipient(request.payload.destination)) return { action: "reject", code: "invalid_recipient" };
      if (request.deadlineUnix < nowUnix + margin) return defer("approval_expired_awaiting_reissue");
      const route = await routeState();
      try { verifiedDestinationQuorum(request, approvals, [...x.authorizedSigners], nowUnix); }
      catch { return halt("stored_quorum_invalid"); }
      if (!route.usable) return wait("route_paused");
      const amount = BigInt(request.payload.amount);
      if (amount > BigInt(x.maxAmount) || amount > route.maxTransferAmount) return defer("amount_above_transfer_limit");
      const state = await attestationState(request, approvals);
      if (state.mismatch) return halt("processed_with_mismatching_record");
      if (state.unsettled) return defer("replay_state_unsettled");
      // Processed before the processing records existed: minted, but by which
      // transaction cannot be verified. A persistent, non-blocking alert.
      if (state.withoutRecord) return { action: "release_unverified", code: "processed_without_record" };
      if (state.processed) {
        const evidence = await releasedElsewhere(state.processed);
        return evidence.final ? released(evidence) : defer("release_elsewhere_not_final");
      }
      const chainTime = Math.max(...statuses.map((status) => status.time));
      if (request.deadlineUnix < Math.max(nowUnix, chainTime) + margin) return defer("approval_expired_awaiting_reissue");
      const [usages, outstandings] = await Promise.all([rpc.dailyUsages(), rpc.outstandings()]);
      if (min(usages.map((usage) => BigInt(usage.remainingAmount))) < amount) return defer("daily_limit_exhausted");
      if (min(outstandings.map((item) => BigInt(item.remainingAmount))) < amount) return defer("outstanding_limit_reached");
      try { await verifySource(request); } catch { throw unavailable("source_finality_unverified"); }
      const number = await knownAccountNumber();
      const sequence = await sequences();
      if (sequence === null) return wait("account_sequence_unsettled");
      const price = await gasPrice();
      if (price > maxGasPrice) return wait("gas_price_above_cap");
      const message = messageOf(request, approvals);
      // Gas from simulation of this exact message on every origin, plus headroom
      // (the processing record of the v2 upgrade alone adds about 22k gas).
      const simulation = await rpc.simulateEach(assembleSimulationTx(signDoc(message, sequence, maxGas, price * maxGas, number)));
      if (simulation.failed) return defer("attestation_simulation_failed");
      const gasLimit = (max(simulation.gasUsed) * BigInt(x.gasAdjustmentPercent) + 99n) / 100n + BigInt(x.gasHeadroom);
      if (gasLimit > maxGas) return defer("gas_estimate_above_limit");
      const feeAmount = gasLimit * price;
      if (feeAmount > maxFee) return wait("fee_above_cap");
      if (min(await rpc.balances(submitter)) < feeAmount) return wait("submitter_balance_insufficient");
      return { action: "sign", context: Object.freeze({ gasLimit: gasLimit.toString(), feeAmount: feeAmount.toString() }) };
    },

    async sign({ request, approvals, nowUnix, context, expectedNonce }) {
      await rpc.chainId();
      const sequence = await sequences();
      if (sequence === null) return wait("account_sequence_unsettled");
      // After our first transaction the account is ours alone: the chain's
      // sequence must equal the ledger's next nonce.
      if (expectedNonce !== null && sequence !== expectedNonce) return halt("account_sequence_not_owned");
      let custody;
      try {
        verifiedDestinationQuorum(request, approvals, [...x.authorizedSigners], nowUnix);
        const number = await knownAccountNumber();
        const gasLimit = BigInt(context.gasLimit), feeAmount = BigInt(context.feeAmount);
        if (gasLimit > maxGas || feeAmount > maxFee || feeAmount > gasLimit * maxGasPrice) throw new Error();
        const doc = signDoc(messageOf(request, approvals), sequence, gasLimit, feeAmount, number);
        const signature = cosmosSignature(await signer.signDigest(doc.signingDigest), doc.signingDigest, publicKey);
        custody = assembleTxRaw({ ...doc, signature });
        const decoded = decodeXitcoinTransaction(custody.signedHex);
        if (decoded.sequence !== String(sequence) || decoded.transactionHash !== custody.transactionHash
            || !verifyXitcoinSignature({ ...decoded, chainId, accountNumber: number })) throw new Error();
      } catch (error) {
        if (error instanceof TransportError || error instanceof XitcoinRpcDisagreement || error instanceof XitcoinRpcInvalid) throw error;
        throw unavailable("submitter_signature_rejected");
      }
      return { action: "signed", nonce: sequence, signedHex: custody.signedHex, transactionHash: custody.transactionHash };
    },

    async verifyStored({ row, request, approvals }) {
      try {
        if (row.transferId !== attestationId({ ...request.payload, direction: request.direction })) throw new Error();
        await parseStored(row, request, approvals);
        return { action: "valid" };
      } catch (error) {
        if (error instanceof TransportError || error instanceof XitcoinRpcDisagreement || error instanceof XitcoinRpcInvalid) throw error;
        return halt("stored_transaction_mismatch");
      }
    },

    async beforeFirstSend({ row, request, approvals, nowUnix }) {
      const decoded = await parseStored(row, request, approvals);
      // Once the local clock says the approval margin is lost, the stored bytes
      // are sent even if origins fail: sending our own committed bytes is never
      // unsafe, and no origin fault can keep their reserved sequence unused. A
      // pause or a fee below the base fee that a strict majority reports is
      // still honoured (a send that would not be admitted spends an attempt).
      if (request.deadlineUnix < nowUnix + margin) {
        let hold = null;
        try {
          const route = (await rpc.routeMajority(routeId)).value;
          if (route.paused || !route.enabled) hold = "route_paused";
          else if (!await admissibleFee(decoded)) hold = "fee_below_required";
        } catch { hold = null; } // reads failed: send blind
        return hold ? wait(hold) : { action: "send" };
      }
      // Strict-majority reads only decide whether to send or wait; a persisted
      // halt still needs every origin to agree.
      const statuses = await rpc.chainIdMajority();
      const account = await rpc.accountMajority(submitter);
      if (account.unanimous) {
        if (account.value.sequence > row.nonce) return halt("nonce_consumed_before_send");
        if (account.value.sequence < row.nonce) return halt("account_sequence_regressed");
      } else if (account.value.sequence !== row.nonce) return wait("account_sequence_unsettled");
      const route = (await rpc.routeMajority(routeId)).value;
      if (route.paused || !route.enabled) return wait("route_paused");
      if (!await admissibleFee(decoded)) return wait("fee_below_required");
      // Processed by another transaction after our bytes were committed: send
      // them once anyway so their reserved sequence is consumed; the
      // observation then records the release or a mismatch halt.
      const replay = (await rpc.attestationMajority(row.transferId)).value;
      if (replay.status !== "absent") return { action: "send" };
      if (request.deadlineUnix < Math.max(nowUnix, ...statuses.map((status) => status.time)) + margin) return { action: "send" };
      const verdict = await rpc.simulateMajority(Buffer.from(row.signedHex.slice(2), "hex"));
      if (verdict.failed) return wait("attestation_simulation_failed");
      return { action: "send" };
    },

    async send({ row }) { await rpc.broadcast(row.signedHex); },

    async observe({ row, request, approvals }) {
      await rpc.chainId();
      const decoded = await parseStored(row, request, approvals);
      const ours = signedContent(row.signedHex);
      const tip = await rpc.tip();
      const sequence = await sequences();
      if (sequence === null) return { action: "pending" }; // propagation lag
      if (sequence < row.nonce) return halt("account_sequence_regressed");
      if (sequence === row.nonce) return notConsumed(row, request, approvals, ours, decoded);
      return consumed(row, request, approvals, ours, tip);
    },
  });

}

export function xitcoinLedgerBinding(manifest) {
  const config = validateXitcoinTestnetManifest(manifest);
  return Object.freeze({ destination: "xitcoin", chainId: config.xitcoinChainId, routeId: config.routeId, target: "x/bridge",
    targetIdentity: config.xitcoin.chainSchemaCommit, account: config.xitcoin.submitter });
}

// Conditions that persist nothing and may clear by themselves: the runtime
// pauses and retries. Persisted halts, identity or configuration mismatches and
// unknown errors still stop the process for an operator.
const TEMPORARY_CODES = new Set(["source_finality_unverified"]);
export function isTemporaryStop(error) {
  return error instanceof TransportError || error instanceof XitcoinRpcDisagreement || error instanceof XitcoinRpcInvalid
    || error instanceof RpcDisagreement || error instanceof RpcInvalid || isRelayStoreBusy(error)
    || (error instanceof SubmissionUnavailable && TEMPORARY_CODES.has(error.code));
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

export async function buildXitcoinSubmitterRuntime(manifest, { credentialsDirectory, fetchImpl = globalThis.fetch,
  loadSigner = createEncryptedKeystoreDigestSigner, makeLedger = (path, binding) => new BroadcastLedger(path, binding),
  makeStore = openExistingRelayStore, boundary = async () => {}, now = Date.now,
  log = (report) => process.stdout.write(`${JSON.stringify(report)}\n`) } = {}) {
  const config = validateXitcoinTestnetManifest(manifest);
  if (typeof credentialsDirectory !== "string" || !isAbsolute(credentialsDirectory)) throw unavailable("credentials_directory_required");
  const rpc = new XitcoinRpcQuorum({ origins: [...config.xitcoin.origins], allowLoopbackHttp: config.xitcoin.allowLoopbackHttp, fetchImpl });
  await rpc.chainId();
  const cronos = new CronosRpcQuorum({ urls: [...config.cronos.rpcUrls], allowLoopbackHttp: config.cronos.allowLoopbackHttp, fetchImpl });
  await cronos.chainId();
  const cronosWatcher = new CronosFinalizedWatcher({ providers: [...boundedCronosProviders({ urls: [...config.cronos.rpcUrls],
    allowLoopbackHttp: config.cronos.allowLoopbackHttp, fetchImpl })], vault: config.cronos.vault, routeId: TESTNET_ROUTE_ID,
  confirmations: config.cronos.confirmations, maxBatch: 1 });
  let signer;
  try {
    signer = await loadSigner({ keystorePath: config.keystorePath, credentialPath: join(credentialsDirectory, "keystore-password"),
      expectedAddress: getAddress(`0x${Buffer.from(bech32Bytes(config.xitcoin.submitter)).toString("hex")}`) });
  } catch { throw unavailable("submitter_key_unavailable"); }
  let ledger, store;
  try {
    ledger = makeLedger(config.ledgerPath, xitcoinLedgerBinding(config));
    store = makeStore(config.relayStorePath);
    const adapter = createXitcoinAdapter({ manifest: config, rpc, signer,
      verifySource: createInboundSourceVerifier({ cronosWatcher, cronosRouteId: TESTNET_ROUTE_ID }) });
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
            log(Object.freeze({ destination: "xitcoin", action: "temporarily_stopped", code: temporaryCode(error) }));
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

function bech32Bytes(value) {
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  let accumulator = 0, bits = 0;
  const bytes = [];
  for (const character of value.slice(4, -6)) {
    accumulator = (accumulator << 5) | charset.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 0xff); }
  }
  return bytes;
}
