import { createHash } from "node:crypto";
import { BroadcastLedger, LEDGER_MAX_BROADCAST_ATTEMPTS } from "./broadcast-ledger.js";
import { RelayStore } from "./store.js";

// Destination-generic durable submission engine. The adapter is trusted,
// reviewed destination code (chain reads, signing, byte validation); this
// engine owns ordering, persistence, scheduling and recovery:
//   1. revalidate the persisted approval request and claim the transfer;
//   2. sign and commit exact bytes, hash and nonce to the ledger;
//   3. bind RelayStore to that one transaction hash (`submitted`);
//   4. commit a write-ahead broadcast marker, then send identical bytes;
//   5. complete RelayStore only after the ledger records destination finality,
//      or after the adapter proves a finalized release by another transaction.
// Ambiguity never authorizes new bytes: recovery can only observe, resend the
// identical persisted transaction under adapter-verified conditions, or halt.
// A transfer that cannot proceed yet is deferred durably, and a transfer that
// can never be sent is rejected; neither blocks the transfers behind it.
//
// Expired approvals: when the approval of a transfer without bytes is too
// close to (or past) its deadline, or our bytes for it ended `expired`, the
// engine records in RelayStore that it gives up that approval
// (`requestReissue`) and never claims the transfer under it again. The
// coordinator re-approves it only after the destination shows the approval
// dead; an `expired` ledger row then continues as a new attempt
// (`reopenExpired`). When the destination instead shows that approval used
// by another transaction, the transfer completes as `released_elsewhere`
// from the adapter's verified evidence. A `rejected` transfer is never
// re-issued.
export class SubmissionHalt extends Error {
  constructor(code) { super("destination submission halted; offline review required"); this.code = code; }
}
export class SubmissionUnavailable extends Error {
  constructor(code) { super("destination submission unavailable"); this.code = code; }
}
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const MAX_ROW_TEXT = 32_768;
const PAGE = 256;
const SOURCE = Object.freeze({ cronos: "xitcoin", xitcoin: "cronos" });
// The adapters' transfer-scoped wait for an approval too close to its deadline.
export const APPROVAL_EXPIRED_CODE = "approval_expired_awaiting_reissue";

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
  leaseTtlMs = 60_000, maximumCandidates = 8, maximumScan = 100_000, boundary = async () => {} }) {
  if (!(store instanceof RelayStore) || !(ledger instanceof BroadcastLedger) || !adapter || typeof boundary !== "function"
      || adapter.destination !== ledger.destination || !Object.hasOwn(SOURCE, adapter.destination)
      // A capped destination asks for at most LEDGER_MAX_BROADCAST_ATTEMPTS
      // sends; null means the adapter paces resends of the identical bytes itself.
      || (adapter.maxBroadcastAttempts !== null && (!Number.isSafeInteger(adapter.maxBroadcastAttempts)
        || adapter.maxBroadcastAttempts < 1 || adapter.maxBroadcastAttempts > LEDGER_MAX_BROADCAST_ATTEMPTS))
      || (adapter.stalledAlertSeconds !== undefined && (!Number.isSafeInteger(adapter.stalledAlertSeconds) || adapter.stalledAlertSeconds < 1))
      || !Number.isSafeInteger(maximumCandidates) || maximumCandidates < 1 || maximumCandidates > 64
      || !Number.isSafeInteger(maximumScan) || maximumScan < 1 || maximumScan > 1_000_000) {
    throw new SubmissionUnavailable("invalid_submission_dependencies");
  }
  const sourceChain = SOURCE[adapter.destination];
  const lease = ledger.acquireLease(owner, { nowMs, ttlMs: leaseTtlMs });
  const nowUnix = Math.floor(nowMs / 1000);
  // Every report carries the permanent non-blocking rows needing review, so an
  // alert persists in each cycle's log instead of disappearing into backoff.
  // With a destination threshold it also counts unfinished rows signed longer
  // ago than that (`stalled`), never a halt.
  const attention = adapter.stalledAlertSeconds === undefined ? ledger.attention()
    : ledger.attention({ nowMs, stalledAfterSeconds: adapter.stalledAlertSeconds });
  const report = (action, details = {}) => Object.freeze({ destination: adapter.destination, epoch: lease.epoch, action,
    ...details, attention });
  const identity = (stored, transferId) => ({ transferId, sourceRef: stored.transfer.source_ref,
    approvalDigest: stored.request.digest, requestHash: stored.requestHash });

  // Gives up the stored approval of a transfer that holds no bytes for it
  // (or only `expired` bytes): RelayStore records that this submitter will
  // never send it, and the transfer waits for the coordinator instead of for
  // a deferral. False when RelayStore no longer matches (then it is deferred).
  async function requestReissue(stored, transferId, destinationRef) {
    if (!store.requestReissue(sourceChain, stored.transfer.source_ref, { digest: stored.request.digest, destinationRef })) return false;
    await boundary("reissue-requested");
    ledger.clearDeferral(lease, { transferId, sourceRef: stored.transfer.source_ref });
    return true;
  }
  const awaitingReissue = (transfer, digest) => {
    const marker = transfer.reissue_requested ? store.reissueRequested(sourceChain, transfer.source_ref) : null;
    return marker !== null && marker.digest === digest;
  };

  async function halt(transferId, stored, haltCode) {
    ledger.halt(lease, { ...identity(stored, transferId), code: code(haltCode) });
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

  // RelayStore follows the ledger and never references any other transaction
  // than our persisted bytes (or none, when we never signed for this transfer).
  // `release_ref` records the transaction that actually executed the release,
  // where a reconciler reads RelayStore.
  function completeRelay(stored, transactionHash, releaseRef) {
    let current = store.get(sourceChain, stored.transfer.source_ref);
    if (current.state === "approved") {
      current = store.transition(sourceChain, current.source_ref, "submitted", transactionHash ? { destinationRef: transactionHash } : {});
    }
    if (current.state === "submitted") store.transition(sourceChain, current.source_ref, "completed", { releaseRef });
  }

  async function relayReference(stored, transferId, row) {
    const before = store.get(sourceChain, stored.transfer.source_ref);
    const expected = row?.transactionHash ?? null;
    if (before.destination_ref !== null && before.destination_ref !== expected) {
      if (!row || ["claimed", "signed", "broadcast"].includes(row.state)) await halt(transferId, stored, "relay_store_reference_mismatch");
      throw new SubmissionHalt("relay_store_reference_mismatch");
    }
    return expected;
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
    await relayReference(stored, row.transferId, row);
    const final = ledger.finalize(lease, row.transferId, inclusion);
    await boundary("ledger-finalized");
    completeRelay(stored, final.transactionHash, final.transactionHash);
    await boundary("relay-completed");
    return report("finalized", { transferId: row.transferId, transactionHash: final.transactionHash });
  }

  // Another finalized transaction released this transfer with every approved
  // field (verified by the adapter on every origin). Our bytes, if any, were
  // sent and their nonce consumed, so the queue may move on.
  async function releasedElsewhere(stored, transferId, row, observed) {
    const expected = await relayReference(stored, transferId, row);
    const released = ledger.releasedElsewhere(lease, { ...identity(stored, transferId),
      releaseHash: observed.releaseHash, blockNumber: observed.blockNumber, blockHash: observed.blockHash });
    await boundary("ledger-released-elsewhere");
    completeRelay(stored, expected, released.releaseHash);
    await boundary("relay-completed");
    return report("released_elsewhere", { transferId, releaseHash: released.releaseHash });
  }

  // The destination reports the transfer processed but no matching release was
  // verified: never a completion. RelayStore is left unchanged (in flight).
  async function releaseUnverified(stored, transferId, observed) {
    const reason = observed.code === undefined ? null : code(observed.code);
    const row = ledger.releaseUnverified(lease, { ...identity(stored, transferId),
      blockNumber: observed.blockNumber ?? null, blockHash: observed.blockHash ?? null, code: reason });
    await boundary("ledger-release-unverified");
    return report("release_unverified", { transferId, transactionHash: row.transactionHash, ...(reason ? { code: reason } : {}) });
  }

  async function reject(stored, transferId, rejectCode) {
    ledger.reject(lease, { ...identity(stored, transferId), code: code(rejectCode) });
    await boundary("rejected");
    return report("rejected", { transferId, code: code(rejectCode) });
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
      ["pending", "wait", "rebroadcast", "finalized", "failed", "released_elsewhere", "expired", "release_unverified", "reverted", "halt"]);
    switch (observed.action) {
      case "pending": return report("pending", { transferId: row.transferId, transactionHash: row.transactionHash });
      case "wait": return report("waiting", { transferId: row.transferId, code: code(observed.code) });
      case "rebroadcast":
        row = await send(row);
        return report("rebroadcast", { transferId: row.transferId, transactionHash: row.transactionHash, attempts: row.broadcastAttempts });
      case "finalized": return complete(stored, row, { blockNumber: observed.blockNumber, blockHash: observed.blockHash });
      case "released_elsewhere": return releasedElsewhere(stored, row.transferId, row, observed);
      case "release_unverified": return releaseUnverified(stored, row.transferId, observed);
      case "reverted": {
        // Mined before the deadline, reverted for a lasting condition of this
        // transfer; nonce consumed. Non-blocking; RelayStore stays in flight.
        ledger.markReverted(lease, row.transferId, { blockNumber: observed.blockNumber, blockHash: observed.blockHash, code: code(observed.code) });
        await boundary("ledger-reverted");
        return report("reverted", { transferId: row.transferId, transactionHash: row.transactionHash, code: code(observed.code) });
      }
      case "expired": {
        // Our bytes were mined after the deadline and reverted; their nonce is
        // consumed. RelayStore stays `submitted` with our reference, so the
        // transfer remains in flight until a new approval is handled.
        ledger.markExpired(lease, row.transferId, { blockNumber: observed.blockNumber, blockHash: observed.blockHash });
        await boundary("ledger-expired");
        return report("expired", { transferId: row.transferId, transactionHash: row.transactionHash });
      }
      case "failed":
        ledger.markFailed(lease, row.transferId, { blockNumber: observed.blockNumber, blockHash: observed.blockHash });
        await boundary("ledger-failed");
        throw new SubmissionHalt("destination_execution_failed");
      default: return halt(row.transferId, stored, observed.code);
    }
  }

  async function start(stored, transferId, claimedRow = null) {
    const assessed = decision(await adapter.assess({ ...stored, transferId, nowUnix }),
      ["sign", "wait", "halt", "reject", "released_elsewhere", "release_unverified"]);
    if (assessed.action === "halt") await halt(transferId, stored, assessed.code);
    if (assessed.action === "reject") return reject(stored, transferId, assessed.code);
    if (assessed.action === "released_elsewhere") return releasedElsewhere(stored, transferId, claimedRow, assessed);
    if (assessed.action === "release_unverified") return releaseUnverified(stored, transferId, { code: assessed.code });
    if (assessed.action === "wait") return report("waiting", { transferId, code: code(assessed.code), defer: assessed.defer === true });
    const claimed = ledger.claim(lease, identity(stored, transferId));
    await boundary("claimed");
    if (claimed.state !== "claimed") throw new SubmissionUnavailable("ledger_state_changed");
    const signed = decision(await adapter.sign({ ...stored, transferId, nowUnix, context: assessed.context,
      expectedNonce: ledger.nextNonce() }), ["signed", "wait", "halt", "reject"]);
    if (signed.action === "halt") await halt(transferId, stored, signed.code);
    if (signed.action === "reject") return reject(stored, transferId, signed.code);
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
  // Every `submitted` row is checked by keyset pages: rows parked as expired,
  // reverted or unverified stay `submitted`, and must never hide a newer row
  // whose ledger finalization still has to be mirrored into RelayStore.
  const firstSubmitted = store.database.prepare(`SELECT source_ref, updated_at FROM transfers WHERE source_chain = ? AND state = 'submitted'
    ORDER BY updated_at, source_ref LIMIT ${PAGE}`);
  const nextSubmitted = store.database.prepare(`SELECT source_ref, updated_at FROM transfers WHERE source_chain = ? AND state = 'submitted'
    AND (updated_at > ? OR (updated_at = ? AND source_ref > ?)) ORDER BY updated_at, source_ref LIMIT ${PAGE}`);
  for (let position = null, checked = 0; checked < maximumScan;) {
    const page = position ? nextSubmitted.all(sourceChain, position.updated_at, position.updated_at, position.source_ref) : firstSubmitted.all(sourceChain);
    if (!page.length) break;
    for (const submittedRow of page) {
      position = submittedRow;
      checked += 1;
      const sourceRef = submittedRow.source_ref;
      const stored = storedRequest(store, sourceChain, sourceRef);
      const transferId = transferIdOf(stored);
      const row = ledger.inspect(transferId);
      if (!row.found || row.sourceRef !== sourceRef || row.transactionHash !== stored.transfer.destination_ref) {
        if (!row.found || ["claimed", "signed", "broadcast"].includes(row.state)) await halt(transferId, stored, "submitted_without_ledger_custody");
        throw new SubmissionHalt("submitted_without_ledger_custody");
      }
      if (row.state === "finalized") return complete(stored, row, { blockNumber: row.blockNumber, blockHash: row.blockHash });
      if (row.state === "released_elsewhere") return releasedElsewhere(stored, transferId, row, row);
      // Our bytes were mined after the deadline and reverted: give up this
      // approval so the coordinator can re-issue it (idempotent).
      if (row.state === "expired" && row.approvalDigest === stored.request.digest && !awaitingReissue(stored.transfer, stored.request.digest)) {
        await requestReissue(stored, transferId, row.transactionHash);
      }
    }
  }

  // The unfinished transfer is found by the source reference the ledger stores,
  // never by a bounded window over RelayStore rows.
  if (active.length === 1) {
    const row = active[0];
    const relay = store.get(sourceChain, row.sourceRef);
    if (!relay || !["approved", "submitted"].includes(relay.state)) throw new SubmissionHalt("ledger_transfer_missing_from_relay_store");
    const stored = storedRequest(store, sourceChain, row.sourceRef);
    if (transferIdOf(stored) !== row.transferId) throw new SubmissionHalt("ledger_transfer_missing_from_relay_store");
    if (row.state !== "claimed") return advance(row, stored);
    const result = await start(stored, row.transferId, row);
    // A claimed row has no bytes and no nonce. A transfer-scoped wait (for
    // example its approval expired) releases the claim and defers it, so it
    // never holds the single unfinished slot.
    if (result.action === "waiting" && result.defer) {
      ledger.unclaim(lease, row.transferId);
      await boundary("unclaimed");
      if (result.code !== APPROVAL_EXPIRED_CODE || !(await requestReissue(stored, row.transferId, null))) {
        ledger.defer(lease, { transferId: row.transferId, sourceRef: row.sourceRef, code: result.code }, { nowMs });
      }
      return report("waiting", { transferId: row.transferId, code: result.code, unclaimed: true });
    }
    return result;
  }

  // Approved transfers in order, by keyset pages. Rejected and still-deferred
  // transfers are skipped cheaply; a transfer-scoped wait defers it durably and
  // the scan moves on. A route-scoped wait (for example a paused vault) stops.
  const waiting = [], rejected = [];
  let assessed = 0, scanned = 0, cursor = null;
  const first = store.database.prepare(`SELECT source_ref, updated_at FROM transfers WHERE source_chain = ? AND state = 'approved'
    ORDER BY updated_at, source_ref LIMIT ${PAGE}`);
  const next = store.database.prepare(`SELECT source_ref, updated_at FROM transfers WHERE source_chain = ? AND state = 'approved'
    AND (updated_at > ? OR (updated_at = ? AND source_ref > ?)) ORDER BY updated_at, source_ref LIMIT ${PAGE}`);
  scan: while (scanned < maximumScan) {
    const page = cursor ? next.all(sourceChain, cursor.updated_at, cursor.updated_at, cursor.source_ref) : first.all(sourceChain);
    if (!page.length) break;
    for (const candidate of page) {
      cursor = candidate;
      if (++scanned > maximumScan) break scan;
      const scheduled = ledger.scheduling(candidate.source_ref);
      if (["rejected", "release_unverified"].includes(scheduled.state)) continue;
      if (scheduled.state === "finalized" || scheduled.state === "released_elsewhere") {
        const stored = storedRequest(store, sourceChain, candidate.source_ref);
        const row = ledger.inspect(transferIdOf(stored));
        if (row.transferId !== scheduled.transferId) throw new SubmissionHalt("ledger_invariant_violation");
        return row.state === "finalized" ? complete(stored, row, { blockNumber: row.blockNumber, blockHash: row.blockHash })
          : releasedElsewhere(stored, row.transferId, row, row);
      }
      if (scheduled.state !== null && !["unclaimed", "expired"].includes(scheduled.state)) throw new SubmissionHalt("ledger_invariant_violation");
      const relay = store.get(sourceChain, candidate.source_ref);
      if (relay.reissue_requested !== null) {
        // Given up by this submitter: never claimed under that approval again.
        // A stale scheduling hint must not delay the re-issued approval.
        const stored = storedRequest(store, sourceChain, candidate.source_ref);
        if (awaitingReissue(relay, stored.request.digest)) {
          const transferId = transferIdOf(stored);
          if (scheduled.deferredUntilMs !== null) ledger.clearDeferral(lease, { transferId, sourceRef: candidate.source_ref });
          // The coordinator's proof found this approval's replay key already
          // used (for example leaked signatures before the deadline): it is
          // never re-issued; complete it from the release by that other
          // transaction. Nothing is ever signed for it.
          if (store.processedElsewhere(sourceChain, candidate.source_ref) === stored.request.digest
              && typeof adapter.releasedElsewhere === "function" && scheduled.state !== "expired") {
            if (assessed >= maximumCandidates) break scan;
            assessed += 1;
            const found = decision(await adapter.releasedElsewhere({ ...stored, transferId, nowUnix }),
              ["released_elsewhere", "release_unverified", "wait", "halt"]);
            if (found.action === "halt") await halt(transferId, stored, found.code);
            if (found.action === "released_elsewhere") {
              return releasedElsewhere(stored, transferId, scheduled.state === null ? null : ledger.inspect(transferId), found);
            }
            if (found.action === "release_unverified") { await releaseUnverified(stored, transferId, { code: found.code }); continue; }
            waiting.push(code(found.code));
          }
          continue;
        }
      }
      if (scheduled.state !== "expired" && scheduled.deferredUntilMs !== null && scheduled.deferredUntilMs > nowMs) continue;
      if (assessed >= maximumCandidates) break scan;
      const stored = storedRequest(store, sourceChain, candidate.source_ref);
      const transferId = transferIdOf(stored);
      if (scheduled.transferId !== null && scheduled.transferId !== transferId) throw new SubmissionHalt("ledger_invariant_violation");
      if (scheduled.state === "expired") {
        // Our expired bytes for an earlier approval; RelayStore now holds a
        // re-issued one. The row continues as a new attempt.
        const row = ledger.inspect(transferId);
        if (row.approvalDigest === stored.request.digest || stored.transfer.destination_ref !== null) {
          throw new SubmissionHalt("ledger_invariant_violation");
        }
        ledger.reopenExpired(lease, identity(stored, transferId));
        await boundary("reopened");
      }
      assessed += 1;
      const result = await start(stored, transferId);
      if (result.action === "rejected") { rejected.push(result.code); continue; }
      if (result.action === "release_unverified") continue;
      if (result.action !== "waiting") return result;
      waiting.push(result.code);
      if (!result.defer) break scan;
      if (result.code === APPROVAL_EXPIRED_CODE && await requestReissue(stored, transferId, null)) continue;
      ledger.defer(lease, { transferId, sourceRef: candidate.source_ref, code: result.code }, { nowMs });
    }
  }
  return report(waiting.length || rejected.length ? "waiting" : "idle",
    { waiting: Object.freeze(waiting), rejected: Object.freeze(rejected) });
}
