import { DatabaseSync } from "node:sqlite";

import { approvalContentHash, approvalSourceKey, buildApprovalRequest, reissueDeclaration } from "./approvals.js";

export const STATES = Object.freeze([
  "observed", "finalized", "approved", "submitted", "completed", "failed", "reorged",
]);

const progress = new Map(STATES.map((state, index) => [state, index]));

// The coordinator and the Cronos submitter both write this database. Lock
// contention waits for a bounded interval, then fails with SQLITE_BUSY, which
// callers must treat as a temporary condition (see isRelayStoreBusy).
export const RELAY_STORE_BUSY_TIMEOUT_MS = 5_000;

export function isRelayStoreBusy(error) {
  try {
    if (!error || typeof error !== "object") return false;
    const descriptor = Object.getOwnPropertyDescriptor(error, "errcode");
    const errcode = descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
    return Number.isSafeInteger(errcode) && [5, 6].includes(errcode & 0xff); // SQLITE_BUSY, SQLITE_LOCKED
  } catch { return false; }
}

// A re-issue pair: `next` spends the same source event with the same content
// as the expired `previous`, with a strictly later deadline that has not
// passed, and a new digest.
function reissuePair(previous, next, nowUnix) {
  if (!next || typeof next !== "object" || Array.isArray(next) || JSON.stringify(next).length > 65_536) {
    throw new Error("invalid approval request");
  }
  if (!Number.isSafeInteger(previous?.deadlineUnix) || !Number.isSafeInteger(next.deadlineUnix)
      || previous.deadlineUnix >= nowUnix || next.deadlineUnix <= nowUnix || next.deadlineUnix <= previous.deadlineUnix) {
    throw new Error("only an expired approval request may be re-issued with a later deadline");
  }
  let same;
  try {
    const before = buildApprovalRequest(previous), after = buildApprovalRequest(next);
    same = before.digest === previous.digest && after.digest === next.digest && before.digest !== after.digest
      && approvalSourceKey(before) === approvalSourceKey(after) && approvalContentHash(before) === approvalContentHash(after);
  } catch { same = false; }
  if (!same) throw new Error("re-issued approval request does not match the persisted source event");
  return { previousEncoded: JSON.stringify(previous), nextEncoded: JSON.stringify(next),
    declaration: reissueDeclaration({ previousDigest: previous.digest, previousDeadlineUnix: previous.deadlineUnix }) };
}

function reissueMarker(value) {
  const digest = String(value?.digest ?? "").toLowerCase();
  const destinationRef = value?.destinationRef === null || value?.destinationRef === undefined ? null : String(value.destinationRef).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(digest) || (destinationRef !== null && !/^0x[0-9a-f]{64}$/.test(destinationRef))) {
    throw new Error("invalid re-issue request");
  }
  return Object.freeze({ digest, destinationRef });
}

export class RelayStore {
  constructor(path = ":memory:", { busyTimeoutMs = RELAY_STORE_BUSY_TIMEOUT_MS } = {}) {
    if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) throw new Error("invalid RelayStore busy timeout");
    this.database = new DatabaseSync(path, { timeout: busyTimeoutMs });
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS transfers (
        source_chain TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        route_id TEXT NOT NULL,
        state TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        transaction_hash TEXT,
        event_index INTEGER,
        payload TEXT NOT NULL,
        approval_request TEXT,
        destination_ref TEXT,
        error TEXT,
        updated_at INTEGER NOT NULL,
        release_ref TEXT,
        PRIMARY KEY (source_chain, source_ref)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS checkpoints (
        source_chain TEXT PRIMARY KEY,
        block_height INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS approvals (
        source_chain TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        signer TEXT NOT NULL,
        digest TEXT NOT NULL,
        signature TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (source_chain, source_ref, signer),
        FOREIGN KEY (source_chain, source_ref)
          REFERENCES transfers(source_chain, source_ref)
      ) STRICT;
    `);
    const columns = new Set(this.database.prepare("PRAGMA table_info(transfers)").all().map((column) => column.name));
    if (!columns.has("transaction_hash")) this.database.exec("ALTER TABLE transfers ADD COLUMN transaction_hash TEXT");
    if (!columns.has("event_index")) this.database.exec("ALTER TABLE transfers ADD COLUMN event_index INTEGER");
    if (!columns.has("approval_request")) this.database.exec("ALTER TABLE transfers ADD COLUMN approval_request TEXT");
    // The destination transaction that actually executed the transfer. It may
    // differ from destination_ref (our submitted transaction) when another
    // transaction released it first, for example after a front-run.
    if (!columns.has("release_ref")) this.database.exec("ALTER TABLE transfers ADD COLUMN release_ref TEXT");
    // Set by a destination submitter that gives up an expired approval: the
    // digest it will never send and the destination transaction it holds for
    // it (null when it never sent one). Only then may the coordinator re-issue
    // an approved or submitted transfer.
    if (!columns.has("reissue_requested")) this.database.exec("ALTER TABLE transfers ADD COLUMN reissue_requested TEXT");
    // For a re-issued approval request, the explicit declaration
    // ({ previousDigest, previousDeadlineUnix }) sent to signers with it.
    if (!columns.has("approval_reissue")) this.database.exec("ALTER TABLE transfers ADD COLUMN approval_reissue TEXT");
    // Set by the coordinator when its re-issue proof shows that the replay key
    // of a given-up approval is already used on the destination (for example
    // with leaked signatures before the deadline): never re-issued, the
    // destination submitter completes it from the release evidence instead.
    if (!columns.has("processed_elsewhere")) this.database.exec("ALTER TABLE transfers ADD COLUMN processed_elsewhere TEXT");
    // Every approval request that was replaced by a re-issue, with its
    // approvals and the destination transaction bound to it. Append-only.
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS approval_history (
        seq INTEGER PRIMARY KEY,
        source_chain TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        state TEXT NOT NULL,
        approval_request TEXT NOT NULL,
        approvals TEXT NOT NULL,
        destination_ref TEXT,
        replaced_by TEXT NOT NULL,
        replaced_at INTEGER NOT NULL
      ) STRICT;
      CREATE TRIGGER IF NOT EXISTS approval_history_no_update BEFORE UPDATE ON approval_history
        BEGIN SELECT RAISE(ABORT, 'permanent'); END;
      CREATE TRIGGER IF NOT EXISTS approval_history_no_delete BEFORE DELETE ON approval_history
        BEGIN SELECT RAISE(ABORT, 'permanent'); END;
    `);
  }

  observe(record) {
    const now = Math.floor(Date.now() / 1000);
    const statement = this.database.prepare(`
      INSERT INTO transfers
        (source_chain, source_ref, route_id, state, block_height, block_hash,
         transaction_hash, event_index, payload, updated_at)
      VALUES (?, ?, ?, 'observed', ?, ?, ?, ?, ?, ?)
      ON CONFLICT(source_chain, source_ref) DO UPDATE SET
        block_height = excluded.block_height,
        block_hash = excluded.block_hash,
        transaction_hash = excluded.transaction_hash,
        event_index = excluded.event_index,
        payload = excluded.payload,
        updated_at = excluded.updated_at
      WHERE transfers.state IN ('observed', 'reorged')
    `);
    statement.run(
      record.sourceChain,
      record.sourceRef.toLowerCase(),
      record.routeId,
      record.blockHeight,
      record.blockHash.toLowerCase(),
      record.transactionHash?.toLowerCase() ?? null,
      record.logIndex ?? record.messageIndex ?? null,
      JSON.stringify(record.payload),
      now,
    );
    return this.get(record.sourceChain, record.sourceRef);
  }

  transition(sourceChain, sourceRef, nextState, details = {}) {
    if (!progress.has(nextState)) throw new Error("unknown lifecycle state");
    const current = this.get(sourceChain, sourceRef);
    if (!current) throw new Error("transfer not found");
    if (["completed", "failed", "reorged"].includes(current.state)) throw new Error("terminal lifecycle state is immutable");
    if (details.destinationRef != null && (nextState !== "submitted"
        || (current.destination_ref !== null && current.destination_ref !== details.destinationRef))) {
      throw new Error("destination reference is immutable");
    }
    if (details.releaseRef != null && (nextState !== "completed" || !/^0x[0-9a-f]{64}$/.test(details.releaseRef)
        || (current.release_ref !== null && current.release_ref !== details.releaseRef))) {
      throw new Error("release reference is immutable and recorded only on completion");
    }
    const terminalOverride = nextState === "failed" || nextState === "reorged";
    if (!terminalOverride && progress.get(nextState) !== progress.get(current.state) + 1) {
      throw new Error(`invalid lifecycle transition ${current.state} -> ${nextState}`);
    }
    const result = this.database.prepare(`
      UPDATE transfers
      SET state = ?, destination_ref = COALESCE(?, destination_ref), release_ref = COALESCE(?, release_ref),
          error = ?, updated_at = ?
      WHERE source_chain = ? AND source_ref = ? AND state = ? AND destination_ref IS ?
    `).run(
      nextState,
      details.destinationRef ?? null,
      details.releaseRef ?? null,
      details.error ?? null,
      Math.floor(Date.now() / 1000),
      sourceChain,
      sourceRef.toLowerCase(),
      current.state,
      current.destination_ref,
    );
    if (result.changes !== 1) throw new Error("concurrent lifecycle transition");
    return this.get(sourceChain, sourceRef);
  }

  get(sourceChain, sourceRef) {
    return this.database.prepare(
      "SELECT * FROM transfers WHERE source_chain = ? AND source_ref = ?",
    ).get(sourceChain, sourceRef.toLowerCase());
  }

  pending() {
    return this.database.prepare(
      "SELECT * FROM transfers WHERE state NOT IN ('completed', 'failed', 'reorged') ORDER BY updated_at",
    ).all();
  }

  persistApprovalRequest(sourceChain, sourceRef, request) {
    const current = this.get(sourceChain, sourceRef);
    if (!current || current.state !== "finalized") throw new Error("approval request requires a finalized transfer");
    const encoded = JSON.stringify(request);
    if (!request || typeof request !== "object" || Array.isArray(request) || encoded.length > 65_536) {
      throw new Error("invalid approval request");
    }
    if (current.approval_request && current.approval_request !== encoded) {
      throw new Error("conflicting approval request");
    }
    if (!current.approval_request) {
      this.database.prepare(`
        UPDATE transfers SET approval_request = ?, updated_at = ?
        WHERE source_chain = ? AND source_ref = ? AND state = 'finalized' AND approval_request IS NULL
      `).run(encoded, Math.floor(Date.now() / 1000), sourceChain, sourceRef.toLowerCase());
    }
    const persisted = this.get(sourceChain, sourceRef);
    if (persisted.state !== "finalized" || persisted.approval_request !== encoded) {
      throw new Error("concurrent or conflicting approval request");
    }
    return JSON.parse(persisted.approval_request);
  }

  // Replaces a persisted approval request whose deadline has passed with a
  // re-issued one for the same source event (finalized transfers, whose
  // approvals were never complete). The caller (coordinator) must have proved
  // on the destination that the expired request can never be used
  // (approval-retirement.js). This method re-checks atomically that `next`
  // spends the same source event with the same content and a strictly later
  // deadline, the persisted bytes, the lifecycle state and expiry; it archives
  // the expired request with the approvals collected for it, which can no
  // longer be submitted, and records the explicit re-issue declaration that
  // signers receive with the new request.
  reissueApprovalRequest(sourceChain, sourceRef, previous, next, { nowUnix = Math.floor(Date.now() / 1000) } = {}) {
    const { previousEncoded, nextEncoded, declaration } = reissuePair(previous, next, nowUnix);
    const ref = sourceRef.toLowerCase();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const current = this.get(sourceChain, ref);
      if (!current || current.state !== "finalized" || current.approval_request !== previousEncoded) {
        throw new Error("concurrent or conflicting approval request");
      }
      this.#archive(current, next.digest);
      const updated = this.database.prepare(`
        UPDATE transfers SET approval_request = ?, approval_reissue = ?, updated_at = ?
        WHERE source_chain = ? AND source_ref = ? AND state = 'finalized' AND approval_request = ?
      `).run(nextEncoded, JSON.stringify(declaration), Math.floor(Date.now() / 1000), sourceChain, ref, previousEncoded);
      if (updated.changes !== 1) throw new Error("concurrent or conflicting approval request");
      this.database.prepare("DELETE FROM approvals WHERE source_chain = ? AND source_ref = ?").run(sourceChain, ref);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return JSON.parse(this.get(sourceChain, sourceRef).approval_request);
  }

  #archive(current, replacedBy) {
    const approvals = this.approvals(current.source_chain, current.source_ref)
      .map(({ signer, digest, signature }) => ({ signer, digest, signature }));
    this.database.prepare(`
      INSERT INTO approval_history (source_chain, source_ref, state, approval_request, approvals, destination_ref, replaced_by, replaced_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(current.source_chain, current.source_ref, current.state, current.approval_request, JSON.stringify(approvals),
      current.destination_ref, replacedBy, Math.floor(Date.now() / 1000));
  }

  // Destination submitter side of an approved-transfer re-issue: it declares
  // that it will never send `digest` (the current approval) and that it holds
  // no transaction for it other than `destinationRef` (null when it never
  // sent one). Conditional on the RelayStore row matching exactly; idempotent.
  requestReissue(sourceChain, sourceRef, { digest, destinationRef = null }) {
    const marker = reissueMarker({ digest, destinationRef });
    const ref = sourceRef.toLowerCase();
    const result = this.database.prepare(`
      UPDATE transfers SET reissue_requested = ?
      WHERE source_chain = ? AND source_ref = ? AND reissue_requested IS NULL
        AND json_extract(approval_request, '$.digest') = ?
        AND ((state = 'approved' AND destination_ref IS NULL AND ? IS NULL) OR (state = 'submitted' AND destination_ref = ?))
    `).run(JSON.stringify(marker), sourceChain, ref, marker.digest, marker.destinationRef, marker.destinationRef);
    if (result.changes === 1) return true;
    return this.get(sourceChain, ref)?.reissue_requested === JSON.stringify(marker);
  }

  reissueRequested(sourceChain, sourceRef) {
    const encoded = this.get(sourceChain, sourceRef)?.reissue_requested;
    return encoded ? reissueMarker(JSON.parse(encoded)) : null;
  }

  // Coordinator side: the given-up approval `digest` can never be re-issued
  // because the destination shows its replay key used. Conditional on the
  // submitter's request for exactly that approval; idempotent.
  markProcessedElsewhere(sourceChain, sourceRef, { digest }) {
    const marker = reissueMarker({ digest });
    const result = this.database.prepare(`
      UPDATE transfers SET processed_elsewhere = ?
      WHERE source_chain = ? AND source_ref = ? AND processed_elsewhere IS NULL AND state IN ('approved', 'submitted')
        AND json_extract(reissue_requested, '$.digest') = ? AND json_extract(approval_request, '$.digest') = ?
    `).run(JSON.stringify({ digest: marker.digest }), sourceChain, sourceRef.toLowerCase(), marker.digest, marker.digest);
    if (result.changes === 1) return true;
    return this.processedElsewhere(sourceChain, sourceRef) === marker.digest;
  }

  processedElsewhere(sourceChain, sourceRef) {
    const encoded = this.get(sourceChain, sourceRef)?.processed_elsewhere;
    return encoded ? reissueMarker(JSON.parse(encoded)).digest : null;
  }

  // Approved or submitted transfers whose submitter requested a re-issue.
  reissueRequests({ limit = 100 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new Error("invalid re-issue request limit");
    return this.database.prepare(`SELECT * FROM transfers WHERE reissue_requested IS NOT NULL AND state IN ('approved', 'submitted')
      ORDER BY updated_at, source_chain, source_ref LIMIT ?`).all(limit);
  }

  // Coordinator side of an approved-transfer re-issue. Only after the
  // submitter's request for exactly this approval and transaction, and after
  // the coordinator proved on the destination that the expired approval can
  // never be used: the transfer returns to `finalized` with a re-issued
  // request for the same source event, its old request, approvals and
  // destination transaction archived, so the coordinator collects new
  // approvals (with the explicit re-issue declaration) through the normal path.
  returnForReissue(sourceChain, sourceRef, previous, next, { nowUnix = Math.floor(Date.now() / 1000) } = {}) {
    const { previousEncoded, nextEncoded, declaration } = reissuePair(previous, next, nowUnix);
    const ref = sourceRef.toLowerCase();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const current = this.get(sourceChain, ref);
      const marker = current?.reissue_requested ? reissueMarker(JSON.parse(current.reissue_requested)) : null;
      if (!current || !marker || current.processed_elsewhere !== null || current.approval_request !== previousEncoded || marker.digest !== previous.digest
          || !((current.state === "approved" && current.destination_ref === null && marker.destinationRef === null)
            || (current.state === "submitted" && current.destination_ref === marker.destinationRef))) {
        throw new Error("transfer is not awaiting this re-issue");
      }
      this.#archive(current, next.digest);
      const updated = this.database.prepare(`
        UPDATE transfers SET state = 'finalized', approval_request = ?, approval_reissue = ?, destination_ref = NULL,
          reissue_requested = NULL, error = NULL, updated_at = ?
        WHERE source_chain = ? AND source_ref = ? AND state = ? AND approval_request = ? AND destination_ref IS ?
          AND reissue_requested = ?
      `).run(nextEncoded, JSON.stringify(declaration), Math.floor(Date.now() / 1000), sourceChain, ref, current.state,
        previousEncoded, current.destination_ref, current.reissue_requested);
      if (updated.changes !== 1) throw new Error("transfer is not awaiting this re-issue");
      this.database.prepare("DELETE FROM approvals WHERE source_chain = ? AND source_ref = ?").run(sourceChain, ref);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.get(sourceChain, sourceRef);
  }

  approvalReissue(sourceChain, sourceRef) {
    const encoded = this.get(sourceChain, sourceRef)?.approval_reissue;
    return encoded ? reissueDeclaration(JSON.parse(encoded)) : null;
  }

  approvalHistory(sourceChain, sourceRef) {
    return this.database.prepare("SELECT * FROM approval_history WHERE source_chain = ? AND source_ref = ? ORDER BY seq")
      .all(sourceChain, sourceRef.toLowerCase());
  }

  approvalRequest(sourceChain, sourceRef) {
    const encoded = this.get(sourceChain, sourceRef)?.approval_request;
    return encoded ? JSON.parse(encoded) : undefined;
  }

  recordApproval(sourceChain, sourceRef, approval) {
    const current = this.get(sourceChain, sourceRef);
    if (!current) throw new Error("transfer not found");
    if (current.state !== "finalized" && current.state !== "approved") {
      throw new Error("approvals may only be recorded for finalized transfers");
    }
    const signer = String(approval.signer).toLowerCase();
    const digest = String(approval.digest).toLowerCase();
    const signature = String(approval.signature).toLowerCase();
    const existing = this.database.prepare(`
      SELECT * FROM approvals
      WHERE source_chain = ? AND source_ref = ? AND signer = ?
    `).get(sourceChain, sourceRef.toLowerCase(), signer);
    if (existing) {
      if (existing.digest !== digest || existing.signature !== signature) {
        throw new Error("conflicting signer approval");
      }
      return existing;
    }
    this.database.prepare(`
      INSERT INTO approvals
        (source_chain, source_ref, signer, digest, signature, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sourceChain, sourceRef.toLowerCase(), signer, digest, signature, Math.floor(Date.now() / 1000));
    return this.database.prepare(`
      SELECT * FROM approvals
      WHERE source_chain = ? AND source_ref = ? AND signer = ?
    `).get(sourceChain, sourceRef.toLowerCase(), signer);
  }

  approvals(sourceChain, sourceRef) {
    return this.database.prepare(`
      SELECT signer, digest, signature, created_at FROM approvals
      WHERE source_chain = ? AND source_ref = ? ORDER BY signer
    `).all(sourceChain, sourceRef.toLowerCase());
  }

  checkpoint(sourceChain) {
    return this.database.prepare(
      "SELECT * FROM checkpoints WHERE source_chain = ?",
    ).get(sourceChain);
  }

  advanceCheckpoint(sourceChain, blockHeight, blockHash) {
    if (!Number.isSafeInteger(blockHeight) || blockHeight < 0) {
      throw new Error("checkpoint height must be a non-negative safe integer");
    }
    const normalizedHash = String(blockHash).toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(normalizedHash)) throw new Error("invalid checkpoint hash");
    const current = this.checkpoint(sourceChain);
    if (current && blockHeight < current.block_height) throw new Error("checkpoint regression");
    if (current && blockHeight === current.block_height && normalizedHash !== current.block_hash) {
      throw new Error("checkpoint finality violation");
    }
    const result = this.database.prepare(`
      INSERT INTO checkpoints (source_chain, block_height, block_hash, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(source_chain) DO UPDATE SET
        block_height = excluded.block_height,
        block_hash = excluded.block_hash,
        updated_at = excluded.updated_at
      WHERE checkpoints.block_height < excluded.block_height
         OR (checkpoints.block_height = excluded.block_height AND checkpoints.block_hash = excluded.block_hash)
    `).run(sourceChain, blockHeight, normalizedHash, Math.floor(Date.now() / 1000));
    if (result.changes !== 1) throw new Error("concurrent checkpoint regression or finality violation");
    return this.checkpoint(sourceChain);
  }

  close() {
    this.database.close();
  }
}
