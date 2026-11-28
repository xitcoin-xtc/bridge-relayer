import { FinalityViolation } from "./watchers.js";
import { RetirementUnproven } from "./approval-retirement.js";
import {
  APPROVAL_REISSUE_GRACE_SECONDS,
  approvalContentHash,
  approvalSourceKey,
  buildApprovalRequest,
  collectApprovalQuorum,
} from "./approvals.js";
import { DIRECTION_INBOUND, DIRECTION_OUTBOUND, normalizeBytes32, validateChainId, validateRouteId } from "./protocol.js";
export { submitApprovedTransfer } from "./submission.js";

function height(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`${label} must be a non-negative safe integer`);
  return number;
}

function positiveInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${label} must be a positive safe integer`);
  return number;
}

function payloadOf(transfer) {
  try {
    const payload = typeof transfer.payload === "string" ? JSON.parse(transfer.payload) : transfer.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error();
    return payload;
  } catch {
    throw new Error("stored transfer payload is invalid");
  }
}

function sourceEvidence(transfer) {
  const transactionHash = normalizeBytes32(transfer.transaction_hash);
  return Object.freeze({
    blockHeight: positiveInteger(transfer.block_height, "source block height"),
    blockHash: normalizeBytes32(transfer.block_hash),
    transactionHash,
    eventIndex: positiveInteger(Number(transfer.event_index) + 1, "source event index offset") - 1,
  });
}

function storedSourceRef(value) {
  const text = String(value);
  return normalizeBytes32(text.startsWith("0x") ? text : `0x${text}`);
}

export function buildTransferApprovalRequest({
  transfer,
  routeId,
  cronosRouteId,
  cronosChainId,
  cronosVault,
  xitcoinChainId,
  signerSetVersion = 1,
  deadlineUnix,
}) {
  if (!transfer || transfer.state !== "finalized") throw new Error("a finalized transfer is required");
  const canonicalRouteId = validateRouteId(routeId);
  const chainId = positiveInteger(cronosChainId, "Cronos chain ID");
  const deadline = positiveInteger(deadlineUnix, "approval deadline");
  const payload = payloadOf(transfer);
  const evidence = sourceEvidence(transfer);

  if (transfer.source_chain === "cronos") {
    if (normalizeBytes32(transfer.route_id) !== normalizeBytes32(cronosRouteId)) throw new Error("Cronos route mapping mismatch");
    const sourceRef = normalizeBytes32(payload.depositId);
    if (sourceRef !== storedSourceRef(transfer.source_ref)) throw new Error("Cronos source reference mismatch");
    return buildApprovalRequest({ direction: DIRECTION_INBOUND, payload: {
      destinationChainId: validateChainId(xitcoinChainId),
      routeId: canonicalRouteId,
      sourceChainId: String(chainId),
      sourceRef,
      nonce: String(payload.nonce),
      destination: String(payload.destination),
      amount: String(payload.amount),
      deadlineUnix: deadline,
      sourceEvidence: evidence,
    } });
  }

  if (transfer.source_chain === "xitcoin") {
    if (String(transfer.route_id) !== canonicalRouteId) throw new Error("Xitcoin route mapping mismatch");
    const sourceBurnId = normalizeBytes32(payload.requestId);
    if (sourceBurnId !== storedSourceRef(transfer.source_ref)) throw new Error("Xitcoin source reference mismatch");
    return buildApprovalRequest({ direction: DIRECTION_OUTBOUND, payload: {
      routeId: canonicalRouteId,
      chainId,
      vault: cronosVault,
      sourceBurnId,
      recipient: String(payload.destination),
      amount: String(payload.amount),
      signerSetVersion: positiveInteger(signerSetVersion, "signer set version"),
      deadline,
      sourceEvidence: evidence,
    } });
  }

  throw new Error("unsupported source chain");
}

export async function approveFinalizedTransfer({
  store,
  sourceChain,
  sourceRef,
  request,
  clients,
  authorizedSigners,
  threshold = 2,
  nowUnix,
}) {
  if (!store || !sourceChain || !sourceRef) throw new Error("store and source transfer are required");
  const transfer = store.get(sourceChain, sourceRef);
  if (!transfer) throw new Error("transfer not found");
  if (transfer.state === "approved") {
    return { transfer, approvals: store.approvals(sourceChain, sourceRef), idempotent: true };
  }
  if (transfer.state !== "finalized") throw new Error("only finalized transfers may be approved");
  const canonicalRequest = buildApprovalRequest(request);
  const persistedRequest = store.persistApprovalRequest(sourceChain, sourceRef, canonicalRequest);
  // A re-issued request goes to every signer with its explicit declaration.
  const approvals = await collectApprovalQuorum({
    clients, request: persistedRequest, authorizedSigners, threshold, nowUnix, reissue: store.approvalReissue(sourceChain, sourceRef),
  });
  for (const approval of approvals) store.recordApproval(sourceChain, sourceRef, approval);
  const approved = store.transition(sourceChain, sourceRef, "approved");
  return { transfer: approved, approvals: store.approvals(sourceChain, sourceRef), idempotent: false };
}

// Returns the request to use for a finalized transfer this cycle, or the
// reason it waits ({ wait: code }). A persisted request is never replaced
// while valid and never reused after expiry. An expired one is re-issued with
// a new deadline for the same source event (same source key and content) only
// after the re-issue grace by the local clock AND after `verifyRetired` proved
// on the destination that it can never be used (approval-retirement.js).
export async function currentApprovalRequest({ store, transfer, build, nowUnix, windowSeconds,
  graceSeconds = APPROVAL_REISSUE_GRACE_SECONDS, verifyRetired }) {
  const persisted = store.approvalRequest(transfer.source_chain, transfer.source_ref);
  if (!persisted) return { request: build(nowUnix + windowSeconds) };
  if (persisted.deadlineUnix >= nowUnix) return { request: persisted };
  if (persisted.deadlineUnix + graceSeconds >= nowUnix) return { wait: "approval_reissue_grace" };
  const next = build(nowUnix + windowSeconds);
  if (approvalSourceKey(next) !== approvalSourceKey(persisted)
      || approvalContentHash(next) !== approvalContentHash(persisted)) {
    throw new Error("re-issued approval request does not match the persisted source event");
  }
  const retired = await retirement(verifyRetired, next, persisted.deadlineUnix);
  if (retired.wait) return retired;
  return { request: store.reissueApprovalRequest(transfer.source_chain, transfer.source_ref, persisted, next, { nowUnix }) };
}

async function retirement(verifyRetired, request, previousDeadlineUnix) {
  if (typeof verifyRetired !== "function") return { wait: "retirement_verifier_missing" };
  try {
    await verifyRetired({ request, previousDeadlineUnix });
    return { retired: true };
  } catch (error) {
    if (error instanceof RetirementUnproven) return { wait: error.code };
    throw error;
  }
}

// Approved or submitted transfers whose destination submitter gave up their
// expired approval (RelayStore `requestReissue`: it will never send it and
// holds no other transaction for it). After the re-issue grace and a
// destination proof that the approval can never be used, each returns to
// `finalized` with a re-issued request for the same source event, and is
// approved again through the normal path. A rejected transfer (for example an
// invalid recipient) never asks for this: it stays rejected.
export async function returnExpiredApprovals({ store, build, nowUnix, windowSeconds, graceSeconds = APPROVAL_REISSUE_GRACE_SECONDS,
  verifyRetired, limit = 100 }) {
  let returned = 0;
  const waiting = [];
  for (const transfer of store.reissueRequests({ limit })) {
    const previous = store.approvalRequest(transfer.source_chain, transfer.source_ref);
    if (!previous || previous.deadlineUnix + graceSeconds >= nowUnix) { waiting.push("approval_reissue_grace"); continue; }
    const next = build(transfer, nowUnix + windowSeconds);
    if (approvalSourceKey(next) !== approvalSourceKey(previous) || approvalContentHash(next) !== approvalContentHash(previous)) {
      throw new Error("re-issued approval request does not match the persisted source event");
    }
    const retired = await retirement(verifyRetired, next, previous.deadlineUnix);
    if (retired.wait) { waiting.push(retired.wait); continue; }
    store.returnForReissue(transfer.source_chain, transfer.source_ref, previous, next, { nowUnix });
    returned += 1;
  }
  return Object.freeze({ returned, waiting: Object.freeze(waiting) });
}

export async function scanFinalizedBatch({ watcher, store, sourceChain, startHeight = 1, maxBatch = 100 }) {
  if (!watcher || !store || !sourceChain) throw new Error("watcher, store and source chain are required");
  const first = height(startHeight, "start height");
  const batch = height(maxBatch, "maximum batch");
  if (batch < 1) throw new Error("maximum batch must be positive");
  const checkpoint = store.checkpoint(sourceChain);
  const from = checkpoint ? checkpoint.block_height + 1 : first;
  const finalized = height(await watcher.latestFinalizedHeight(), "finalized height");
  if (from > finalized) return { from, to: finalized, observed: 0, idle: true };
  const to = Math.min(finalized, from + batch - 1);
  const events = await watcher.events(from, to);
  for (const record of events) {
    if (record.sourceChain !== sourceChain) throw new FinalityViolation("watcher returned the wrong source chain");
    await watcher.verifyCanonicalEvent(record);
    const current = store.observe(record);
    if (current.state === "observed") store.transition(sourceChain, record.sourceRef, "finalized");
  }
  const canonical = await watcher.canonicalBlock(to);
  if (Number(canonical.height ?? canonical.number) !== to) {
    throw new FinalityViolation("checkpoint block height mismatch");
  }
  store.advanceCheckpoint(sourceChain, to, canonical.hash);
  return { from, to, observed: events.length, idle: false };
}

export async function runApprovalOnlyCycle({
  store,
  cronosWatcher,
  xitcoinWatcher,
  clients,
  authorizedSigners,
  routeId,
  cronosRouteId,
  cronosChainId,
  cronosVault,
  xitcoinChainId,
  signerSetVersion = 1,
  approvalWindowSeconds = 300,
  nowUnix = Math.floor(Date.now() / 1000),
  startHeights = { cronos: 1, xitcoin: 1 },
  maxBatch = 100,
  maximumApprovals = 100,
  verifyRetired,
}) {
  if (!store || !cronosWatcher || !xitcoinWatcher) throw new Error("approval-only coordinator dependencies are required");
  const now = height(nowUnix, "current time");
  const window = positiveInteger(approvalWindowSeconds, "approval window");
  const limit = positiveInteger(maximumApprovals, "maximum approvals per cycle");
  if (window > 900) throw new Error("approval window exceeds coordinator limit");
  if (limit > 100) throw new Error("approval cycle exceeds bounded transfer limit");

  const scans = {
    cronos: await scanFinalizedBatch({ watcher: cronosWatcher, store, sourceChain: "cronos", startHeight: startHeights.cronos, maxBatch }),
    xitcoin: await scanFinalizedBatch({ watcher: xitcoinWatcher, store, sourceChain: "xitcoin", startHeight: startHeights.xitcoin, maxBatch }),
  };
  const build = (transfer, deadlineUnix) => buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" },
    routeId, cronosRouteId, cronosChainId, cronosVault, xitcoinChainId, signerSetVersion, deadlineUnix });
  const returns = await returnExpiredApprovals({ store, build, nowUnix: now, windowSeconds: window, verifyRetired, limit });
  const finalized = store.pending().filter((transfer) => transfer.state === "finalized").slice(0, limit);
  const results = [];
  const reissueWaiting = [...returns.waiting];
  let waiting = 0;
  for (const transfer of finalized) {
    const current = await currentApprovalRequest({
      store, transfer, nowUnix: now, windowSeconds: window, verifyRetired,
      build: (deadlineUnix) => build(transfer, deadlineUnix),
    });
    if (current.wait) { waiting += 1; reissueWaiting.push(current.wait); continue; }
    const request = current.request;
    results.push(await approveFinalizedTransfer({
      store,
      sourceChain: transfer.source_chain,
      sourceRef: transfer.source_ref,
      request,
      clients,
      authorizedSigners,
      threshold: 2,
      nowUnix: now,
    }));
  }
  return Object.freeze({
    mode: "approval_only",
    scans: Object.freeze(scans),
    finalized: finalized.length,
    approved: results.length,
    awaitingReissue: waiting,
    returnedForReissue: returns.returned,
    reissueWaiting: Object.freeze(reissueWaiting),
    submissions: 0,
  });
}
