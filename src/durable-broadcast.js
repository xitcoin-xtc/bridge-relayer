import { createHash } from "node:crypto";
import { BroadcastLedger, LEDGER_MAX_BROADCAST_ATTEMPTS } from "./broadcast-ledger.js";
import { RelayStore } from "./store.js";

// Destination-generic durable submission engine. The adapter is trusted,
// reviewed destination code (chain reads, signing, byte validation); this
// engine owns ordering, persistence and recovery:
//   1. revalidate the persisted approval request and claim the transfer;
//   2. sign and commit exact bytes, hash and nonce to the ledger;
//   3. bind RelayStore to that one transaction hash (`submitted`);
//   4. commit a write-ahead broadcast marker, then send identical bytes;
//   5. complete RelayStore only after the ledger records destination finality.
// Ambiguity never authorizes new bytes: recovery can only observe, resend the
// identical persisted transaction under adapter-verified conditions, or halt.
export class SubmissionHalt extends Error {
  constructor(code) { super("destination submission halted; offline review required"); this.code = code; }
}
export class SubmissionUnavailable extends Error {
  constructor(code) { super("destination submission unavailable"); this.code = code; }
}
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const MAX_ROW_TEXT = 32_768;
const SOURCE = Object.freeze({ cronos: "xitcoin", xitcoin: "cronos" });

function code(value) { return typeof value === "string" && CODE.test(value) ? value : "invalid_adapter_result"; }
function decision(value, allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
      || !allowed.includes(value.action)) throw new SubmissionUnavailable("invalid_adapter_result");
  return value;
}

// Bounded snapshot of the persisted approval request and approvals. The hash
// binds the ledger row to the exact stored bytes; any later change halts.
function storedRequest(store, sourceChain, sourceRef) {
  const size = store.database.prepare(`SELECT length(payload) AS p, length(approval_request) AS r FROM transfers
    WHERE source_chain = ? AND source_ref = ?`).get(sourceChain, sourceRef);
  if (!size || !size.r || size.p > MAX_ROW_TEXT || size.r > MAX_ROW_TEXT) throw new SubmissionUnavailable("stored_request_unavailable");
  const transfer = store.get(sourceChain, sourceRef);
  const count = store.database.prepare("SELECT count(*) AS n FROM approvals WHERE source_chain = ? AND source_ref = ?").get(sourceChain, sourceRef).n;
  if (count < 2 || count > 3) throw new SubmissionUnavailable("stored_quorum_unavailable");
  const approvals = store.approvals(sourceChain, sourceRef).map(({ signer, digest, signature }) => ({ signer, digest, signature }));
  if (JSON.stringify(approvals).length > MAX_ROW_TEXT) throw new SubmissionUnavailable("stored_quorum_unavailable");
  const requestHash = `0x${createHash("sha256").update(JSON.stringify({ request: transfer.approval_request, approvals })).digest("hex")}`;
  return { transfer, request: JSON.parse(transfer.approval_request), approvals, requestHash };
}

export async function runDurableSubmissionCycle({ store, ledger, adapter, owner, nowMs = Date.now(),
  leaseTtlMs = 60_000, maximumCandidates = 8, boundary = async () => {} }) {
  if (!(store instanceof RelayStore) || !(ledger instanceof BroadcastLedger) || !adapter || typeof boundary !== "function"
      || adapter.destination !== ledger.destination || !Object.hasOwn(SOURCE, adapter.destination)
      || !Number.isSafeInteger(adapter.maxBroadcastAttempts) || adapter.maxBroadcastAttempts < 1
      || adapter.maxBroadcastAttempts > LEDGER_MAX_BROADCAST_ATTEMPTS
      || !Number.isSafeInteger(maximumCandidates) || maximumCandidates < 1 || maximumCandidates > 64) {
    throw new SubmissionUnavailable("invalid_submission_dependencies");
  }
  const sourceChain = SOURCE[adapter.destination];
  const lease = ledger.acquireLease(owner, { nowMs, ttlMs: leaseTtlMs });
  const nowUnix = Math.floor(nowMs / 1000);
  const report = (action, details = {}) => Object.freeze({ destination: adapter.destination, epoch: lease.epoch, action, ...details });

  async function halt(transferId, stored, haltCode) {
    ledger.halt(lease, { transferId, approvalDigest: stored.request.digest, requestHash: stored.requestHash, code: code(haltCode) });
    await boundary("halted");
    throw new SubmissionHalt(code(haltCode));
  }

  function transferIdOf(stored) {
    const transferId = adapter.transferId(stored.request);
    if (typeof transferId !== "string" || !HASH.test(transferId)) throw new SubmissionUnavailable("invalid_adapter_result");
    return transferId;
  }

  function relaySubmitted(stored, row) {
    const current = store.get(sourceChain, stored.transfer.source_ref);
    if (current.state === "approved") {
      store.transition(sourceChain, current.source_ref, "submitted", { destinationRef: row.transactionHash });
      return true;
    }
    if (!["submitted", "completed"].includes(current.state) || current.destination_ref !== row.transactionHash) return false;
    return true;
  }

  async function send(row) {
    const marked = ledger.markBroadcast(lease, row.transferId, { maxAttempts: adapter.maxBroadcastAttempts });
    await boundary("broadcast-recorded");
    // The adapter sends only these persisted bytes; send errors are never a
    // decision input. The next observation decides from canonical chain state.
    try { await adapter.send({ row: marked }); } catch { /* Ambiguous; observed next. */ }
    await boundary("sent");
    return marked;
  }

  async function complete(stored, row, inclusion) {
    const before = store.get(sourceChain, stored.transfer.source_ref);
    if (before.destination_ref !== null && before.destination_ref !== row.transactionHash) {
      if (row.state === "finalized") throw new SubmissionHalt("relay_store_reference_mismatch");
      await halt(row.transferId, stored, "relay_store_reference_mismatch");
    }
    const final = ledger.finalize(lease, row.transferId, inclusion);
    await boundary("ledger-finalized");
    let current = store.get(sourceChain, stored.transfer.source_ref);
    if (current.state === "approved") current = store.transition(sourceChain, current.source_ref, "submitted", { destinationRef: final.transactionHash });
    if (current.state === "submitted") store.transition(sourceChain, current.source_ref, "completed");
    await boundary("relay-completed");
    return report("finalized", { transferId: row.transferId, transactionHash: final.transactionHash });
  }

  async function advance(row, stored) {
    if (stored.requestHash !== row.requestHash || stored.request.digest !== row.approvalDigest) {
      await halt(row.transferId, stored, "stored_request_changed");
    }
    const verified = decision(await adapter.verifyStored({ row, ...stored, nowUnix }), ["valid", "halt"]);
    if (verified.action === "halt") await halt(row.transferId, stored, verified.code);
    if (!relaySubmitted(stored, row)) await halt(row.transferId, stored, "relay_store_reference_mismatch");
    await boundary("relay-submitted");
    if (row.state === "signed") {
      const ready = decision(await adapter.beforeFirstSend({ row, ...stored, nowUnix }), ["send", "wait", "halt"]);
      if (ready.action === "halt") await halt(row.transferId, stored, ready.code);
      if (ready.action === "wait") return report("waiting", { transferId: row.transferId, code: code(ready.code) });
      row = await send(row);
      // Observe in a later cycle: propagation delay must not look like a drop.
      return report("submitted", { transferId: row.transferId, transactionHash: row.transactionHash });
    }
    const observed = decision(await adapter.observe({ row, ...stored, nowUnix }),
      ["pending", "wait", "rebroadcast", "finalized", "failed", "halt"]);
    switch (observed.action) {
      case "pending": return report("pending", { transferId: row.transferId, transactionHash: row.transactionHash });
      case "wait": return report("waiting", { transferId: row.transferId, code: code(observed.code) });
      case "rebroadcast":
        row = await send(row);
        return report("rebroadcast", { transferId: row.transferId, transactionHash: row.transactionHash, attempts: row.broadcastAttempts });
      case "finalized": return complete(stored, row, { blockNumber: observed.blockNumber, blockHash: observed.blockHash });
      case "failed":
        ledger.markFailed(lease, row.transferId, { blockNumber: observed.blockNumber, blockHash: observed.blockHash });
        await boundary("ledger-failed");
        throw new SubmissionHalt("destination_execution_failed");
      default: return halt(row.transferId, stored, observed.code);
    }
  }

  async function start(stored, transferId) {
    const assessed = decision(await adapter.assess({ ...stored, transferId, nowUnix }), ["sign", "wait", "halt"]);
    if (assessed.action === "halt") await halt(transferId, stored, assessed.code);
    if (assessed.action === "wait") return report("waiting", { transferId, code: code(assessed.code) });
    const claimed = ledger.claim(lease, { transferId, approvalDigest: stored.request.digest, requestHash: stored.requestHash });
    await boundary("claimed");
    if (claimed.state !== "claimed") throw new SubmissionUnavailable("ledger_state_changed");
    const signed = decision(await adapter.sign({ ...stored, transferId, nowUnix, context: assessed.context,
      expectedNonce: ledger.nextNonce() }), ["signed", "wait", "halt"]);
    if (signed.action === "halt") await halt(transferId, stored, signed.code);
    if (signed.action === "wait") return report("waiting", { transferId, code: code(signed.code) });
    const row = ledger.recordSigned(lease, { transferId, nonce: signed.nonce, signedHex: signed.signedHex,
      transactionHash: signed.transactionHash });
    await boundary("signed");
    return advance(row, stored);
  }

  if (ledger.blocking().length) throw new SubmissionHalt("ledger_requires_review");
  const active = ledger.active();
  if (active.length > 1) throw new SubmissionHalt("ledger_invariant_violation");

  // RelayStore may never reference a transaction the ledger does not hold.
  const submitted = store.database.prepare(`SELECT source_ref FROM transfers WHERE source_chain = ? AND state = 'submitted'
    ORDER BY updated_at, source_ref LIMIT 64`).all(sourceChain);
  for (const { source_ref: sourceRef } of submitted) {
    const stored = storedRequest(store, sourceChain, sourceRef);
    const transferId = transferIdOf(stored);
    const row = ledger.inspect(transferId);
    if (!row.found || row.transactionHash !== stored.transfer.destination_ref) await halt(transferId, stored, "submitted_without_ledger_custody");
    if (row.state === "finalized") return complete(stored, row, { blockNumber: row.blockNumber, blockHash: row.blockHash });
  }

  if (active.length === 1) {
    const row = active[0];
    const candidates = store.database.prepare(`SELECT source_ref FROM transfers WHERE source_chain = ?
      AND state IN ('approved', 'submitted') ORDER BY updated_at, source_ref LIMIT 256`).all(sourceChain);
    for (const { source_ref: sourceRef } of candidates) {
      const stored = storedRequest(store, sourceChain, sourceRef);
      if (transferIdOf(stored) !== row.transferId) continue;
      return row.state === "claimed" ? start(stored, row.transferId) : advance(row, stored);
    }
    throw new SubmissionHalt("ledger_transfer_missing_from_relay_store");
  }

  const approved = store.database.prepare(`SELECT source_ref FROM transfers WHERE source_chain = ? AND state = 'approved'
    ORDER BY updated_at, source_ref LIMIT ?`).all(sourceChain, maximumCandidates);
  const waiting = [];
  for (const { source_ref: sourceRef } of approved) {
    const stored = storedRequest(store, sourceChain, sourceRef);
    const transferId = transferIdOf(stored);
    const existing = ledger.inspect(transferId);
    if (existing.found) {
      if (existing.state === "finalized") return complete(stored, existing, { blockNumber: existing.blockNumber, blockHash: existing.blockHash });
      throw new SubmissionHalt("ledger_invariant_violation");
    }
    const result = await start(stored, transferId);
    if (result.action !== "waiting") return result;
    waiting.push(result.code);
  }
  return report(waiting.length ? "waiting" : "idle", { waiting: Object.freeze(waiting) });
}
