import { DatabaseSync } from "node:sqlite";

import { APPROVAL_REISSUE_GRACE_SECONDS, reissueDeclaration } from "./approvals.js";

const HEX32 = /^0x[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;

function hex32(value, label) {
  const text = String(value ?? "").toLowerCase();
  if (!HEX32.test(text)) throw new Error(`${label} must contain 32 bytes`);
  return text;
}

function unix(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new Error(`${label} must be a non-negative safe integer`);
  return number;
}

function declaration(value) {
  try { return reissueDeclaration(value); } catch { throw new SignerJournalConflict("re-issue declaration is invalid"); }
}

function reissueRecord(value, deadline) {
  const replacedDigest = value?.replacedDigest === null ? null : hex32(value?.replacedDigest, "replaced digest");
  const declared = declaration(value?.declared);
  const retireAfter = unix(value?.retireAfter, "retired deadline");
  const evidence = value?.evidence;
  if (retireAfter < declared.previousDeadlineUnix || deadline <= retireAfter || !evidence
      || !["cronos", "xitcoin"].includes(evidence.destination) || !Number.isSafeInteger(evidence.height) || evidence.height < 1
      || !Number.isSafeInteger(evidence.blockTime) || evidence.blockTime <= retireAfter) {
    throw new SignerJournalConflict("re-issue evidence is invalid");
  }
  return Object.freeze({ replacedDigest, declared, retireAfter, evidence });
}

export class SignerJournalConflict extends Error {
  constructor(message) {
    super(message);
    this.name = "SignerJournalConflict";
  }
}

// Durable record of every approval one signer has produced, keyed by the
// source event it spends (approvals.js approvalSourceKey). It is the signer's
// own defense against a compromised or faulty coordinator:
//   - a second request for the same source event with different content
//     (destination, amount, nonce, route, chain, vault, ...) is refused forever;
//   - the identical request returns the identical stored signature;
//   - a request that changes only the deadline (or, for releases, the vault
//     signer-set version) is refused unless it is an explicit re-issue: it
//     declares the approval it replaces, its deadline is strictly later than
//     both the declared and the signed deadline, the signed deadline plus
//     APPROVAL_REISSUE_GRACE_SECONDS has passed locally, and the signer service
//     has verified on the destination that the replaced approval can never be
//     used (src/approval-retirement.js). Each re-issue is appended to
//     `approval_reissues` in the same transaction as the new signature;
//   - an operator can close a source event (for example after an approved
//     refund of an oversize deposit); a closed event is never signed again.
// Since two valid 2-of-3 approvals for one source event would need a signer
// common to both quorums, and that signer signs the second only after the
// first is dead on the destination, at most one usable approval per source
// event ever exists. Rows are written with synchronous=FULL before a signature
// leaves the service. The chain and the vault enforce replay protection
// independently.
export class SignerApprovalJournal {
  constructor(path = ":memory:") {
    this.database = new DatabaseSync(path);
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS signed_approvals (
        source_key TEXT PRIMARY KEY NOT NULL,
        direction TEXT,
        content_hash TEXT,
        digest TEXT,
        deadline INTEGER,
        signature TEXT,
        state TEXT NOT NULL CHECK(state IN ('signed', 'closed')),
        close_reason TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS approval_reissues (
        seq INTEGER PRIMARY KEY,
        source_key TEXT NOT NULL CHECK(length(source_key) = 66),
        replaced_digest TEXT CHECK(replaced_digest IS NULL OR length(replaced_digest) = 66),
        declared_digest TEXT NOT NULL CHECK(length(declared_digest) = 66),
        declared_deadline INTEGER NOT NULL CHECK(declared_deadline >= 1),
        retired_after INTEGER NOT NULL CHECK(retired_after >= 1),
        digest TEXT NOT NULL CHECK(length(digest) = 66),
        deadline INTEGER NOT NULL CHECK(deadline > retired_after),
        destination TEXT NOT NULL CHECK(destination IN ('cronos', 'xitcoin')),
        destination_height INTEGER NOT NULL CHECK(destination_height >= 1),
        destination_block_time INTEGER NOT NULL CHECK(destination_block_time > retired_after),
        recorded_at INTEGER NOT NULL
      ) STRICT;
      CREATE TRIGGER IF NOT EXISTS approval_reissues_no_update BEFORE UPDATE ON approval_reissues
        BEGIN SELECT RAISE(ABORT, 'permanent'); END;
      CREATE TRIGGER IF NOT EXISTS approval_reissues_no_delete BEFORE DELETE ON approval_reissues
        BEGIN SELECT RAISE(ABORT, 'permanent'); END;
    `);
  }

  get(sourceKey) {
    return this.database.prepare("SELECT * FROM signed_approvals WHERE source_key = ?").get(hex32(sourceKey, "source key"));
  }

  // Decides, before any signing, whether a request may be signed. Returns
  // { action: "sign" }, { action: "reuse", signature } or, for an explicit
  // re-issue, { action: "reissue", replacedDigest, retireAfter }: the caller
  // must then prove on the destination that no approval with a deadline up to
  // `retireAfter` can still be used. Throws SignerJournalConflict otherwise.
  plan({ sourceKey, contentHash, digest, deadline, nowUnix, reissue = null }) {
    const key = hex32(sourceKey, "source key");
    const content = hex32(contentHash, "content hash");
    const expected = hex32(digest, "digest");
    const until = unix(deadline, "deadline");
    const now = unix(nowUnix, "current time");
    const declared = reissue === null ? null : declaration(reissue);
    const row = this.get(key);
    if (row?.state === "closed") throw new SignerJournalConflict("source event is closed in the signer journal");
    if (row && row.content_hash !== content) throw new SignerJournalConflict("conflicting request for an already signed source event");
    if (row && row.digest === expected) return Object.freeze({ action: "reuse", signature: row.signature });
    if (!declared) {
      if (row) throw new SignerJournalConflict("an approval for this source event already exists; only an explicit re-issue may replace it");
      return Object.freeze({ action: "sign" });
    }
    if (declared.previousDigest === expected) throw new SignerJournalConflict("a re-issue must replace a different approval");
    const retireAfter = Math.max(declared.previousDeadlineUnix, row?.deadline ?? 0);
    if (until <= retireAfter) throw new SignerJournalConflict("a re-issued approval needs a strictly later deadline");
    if (row && now <= row.deadline + APPROVAL_REISSUE_GRACE_SECONDS) {
      throw new SignerJournalConflict("an unexpired approval for this source event already exists");
    }
    return Object.freeze({ action: "reissue", replacedDigest: row?.digest ?? null, retireAfter, declared });
  }

  // Persists a produced signature. The write is conditional on the state
  // that plan() observed, so a concurrent request for the same source event
  // cannot be recorded twice; on failure the signature must be discarded. A
  // re-issue (`reissue`: the plan and the destination evidence) also appends
  // its record in the same transaction.
  record({ sourceKey, direction, contentHash, digest, deadline, signature, nowUnix, reissue }) {
    const key = hex32(sourceKey, "source key");
    const content = hex32(contentHash, "content hash");
    const signed = hex32(digest, "digest");
    const until = unix(deadline, "deadline");
    const now = unix(nowUnix, "current time");
    const encoded = String(signature ?? "").toLowerCase();
    if (!SIGNATURE.test(encoded)) throw new Error("signature must contain 65 bytes");
    if (!["cronos_to_xitcoin", "xitcoin_to_cronos"].includes(direction)) throw new Error("invalid direction");
    const replacement = reissue === undefined ? null : reissueRecord(reissue, until);
    let changes = 0;
    try {
      this.database.exec("BEGIN IMMEDIATE");
      try {
        if (replacement === null || replacement.replacedDigest === null) {
          changes = this.database.prepare(`
            INSERT INTO signed_approvals
              (source_key, direction, content_hash, digest, deadline, signature, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'signed', ?, ?)
          `).run(key, direction, content, signed, until, encoded, now, now).changes;
        } else {
          changes = this.database.prepare(`
            UPDATE signed_approvals
            SET digest = ?, deadline = ?, signature = ?, updated_at = ?
            WHERE source_key = ? AND state = 'signed' AND direction = ? AND content_hash = ?
              AND digest = ? AND deadline + ? < ? AND deadline < ?
          `).run(signed, until, encoded, now, key, direction, content, replacement.replacedDigest,
            APPROVAL_REISSUE_GRACE_SECONDS, now, until).changes;
        }
        if (changes === 1 && replacement !== null) {
          this.database.prepare(`
            INSERT INTO approval_reissues (source_key, replaced_digest, declared_digest, declared_deadline, retired_after, digest,
              deadline, destination, destination_height, destination_block_time, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(key, replacement.replacedDigest, replacement.declared.previousDigest, replacement.declared.previousDeadlineUnix,
            replacement.retireAfter, signed, until, replacement.evidence.destination, replacement.evidence.height,
            replacement.evidence.blockTime, now);
        }
        if (changes === 1) this.database.exec("COMMIT");
        else this.database.exec("ROLLBACK");
      } catch (error) {
        this.database.exec("ROLLBACK");
        throw error;
      }
    } catch {
      changes = 0;
    }
    if (changes !== 1) {
      // A concurrent identical request produced the identical (RFC 6979)
      // signature for the identical digest: idempotent, not a conflict.
      const row = this.get(key);
      if (row?.state === "signed" && row.digest === signed && row.signature === encoded) return row;
      throw new SignerJournalConflict("concurrent or conflicting approval for this source event");
    }
    return this.get(key);
  }

  // Every explicit re-issue this signer recorded for one source event.
  reissues(sourceKey) {
    return this.database.prepare("SELECT * FROM approval_reissues WHERE source_key = ? ORDER BY seq").all(hex32(sourceKey, "source key"));
  }

  // Permanently refuses further approvals for one source event.
  closeSourceEvent(sourceKey, reason, { nowUnix = Math.floor(Date.now() / 1000) } = {}) {
    const key = hex32(sourceKey, "source key");
    const text = String(reason ?? "").trim();
    if (!text || text.length > 256) throw new Error("close reason must contain 1 to 256 characters");
    const now = unix(nowUnix, "current time");
    this.database.prepare(`
      INSERT INTO signed_approvals (source_key, state, close_reason, created_at, updated_at)
      VALUES (?, 'closed', ?, ?, ?)
      ON CONFLICT(source_key) DO UPDATE SET state = 'closed', close_reason = excluded.close_reason,
        updated_at = excluded.updated_at
    `).run(key, text, now, now);
    return this.get(key);
  }

  shutdown() {
    this.database.close();
  }
}
