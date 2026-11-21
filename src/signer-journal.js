import { DatabaseSync } from "node:sqlite";

import { APPROVAL_REISSUE_GRACE_SECONDS } from "./approvals.js";

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
//   - a re-issue that changes only the deadline (or, for releases, the vault
//     signer-set version) is signed only after the previously signed deadline
//     plus APPROVAL_REISSUE_GRACE_SECONDS has passed, so at most one unexpired
//     approval per source event exists;
//   - an operator can close a source event (for example after an approved
//     refund of an oversize deposit); a closed event is never signed again.
// Rows are written with synchronous=FULL before a signature leaves the
// service. The chain and the vault enforce replay protection independently.
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
    `);
  }

  get(sourceKey) {
    return this.database.prepare("SELECT * FROM signed_approvals WHERE source_key = ?").get(hex32(sourceKey, "source key"));
  }

  // Decides, before any signing, whether a request may be signed.
  // Returns { action: "sign" } or { action: "reuse", signature }; throws
  // SignerJournalConflict otherwise.
  plan({ sourceKey, contentHash, digest, nowUnix }) {
    const key = hex32(sourceKey, "source key");
    const content = hex32(contentHash, "content hash");
    const expected = hex32(digest, "digest");
    const now = unix(nowUnix, "current time");
    const row = this.get(key);
    if (!row) return Object.freeze({ action: "sign" });
    if (row.state === "closed") throw new SignerJournalConflict("source event is closed in the signer journal");
    if (row.content_hash !== content) throw new SignerJournalConflict("conflicting request for an already signed source event");
    if (row.digest === expected) return Object.freeze({ action: "reuse", signature: row.signature });
    if (now <= row.deadline + APPROVAL_REISSUE_GRACE_SECONDS) {
      throw new SignerJournalConflict("an unexpired approval for this source event already exists");
    }
    return Object.freeze({ action: "sign", reissueOf: row.digest });
  }

  // Persists a produced signature. The write is conditional on the state
  // that plan() observed, so a concurrent request for the same source event
  // cannot be recorded twice; on failure the signature must be discarded.
  record({ sourceKey, direction, contentHash, digest, deadline, signature, nowUnix, reissueOf }) {
    const key = hex32(sourceKey, "source key");
    const content = hex32(contentHash, "content hash");
    const signed = hex32(digest, "digest");
    const until = unix(deadline, "deadline");
    const now = unix(nowUnix, "current time");
    const encoded = String(signature ?? "").toLowerCase();
    if (!SIGNATURE.test(encoded)) throw new Error("signature must contain 65 bytes");
    if (!["cronos_to_xitcoin", "xitcoin_to_cronos"].includes(direction)) throw new Error("invalid direction");
    let changes;
    try {
      if (reissueOf === undefined) {
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
            AND digest = ? AND deadline + ? < ?
        `).run(signed, until, encoded, now, key, direction, content, hex32(reissueOf, "previous digest"),
          APPROVAL_REISSUE_GRACE_SECONDS, now).changes;
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
