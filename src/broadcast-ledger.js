import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { lstatSync } from "node:fs";
import { userInfo } from "node:os";
import { types } from "node:util";
import { getAddress } from "ethers";
import { bech32Encode } from "./address.js";
import { PrivateJournalPath } from "./journal-path.js";

// Destination-generic durable broadcast ledger. One SQLite database per
// destination submitter account. Every state change is one immediate
// transaction fenced by the worker lease epoch. The ledger itself enforces:
//   - one row per transfer, created only by the current lease holder;
//   - exact signed bytes and transaction hash committed BEFORE any send;
//   - one transaction per transfer and per account nonce, forever;
//   - strictly sequential nonces and at most one unfinished transfer;
//   - forward-only states with no delete, reset, replacement or retry API;
//   - halted and failed rows block every new claim until offline review.
// Destination adapters validate the bytes; this module treats them as opaque.
const failure = () => new Error("broadcast ledger unavailable or conflicting");
const HASH = /^0x[0-9a-f]{64}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const OWNER = /^[0-9a-f]{32}$/;
export const LEDGER_MAX_BROADCAST_ATTEMPTS = 32;
const MAX_SIGNED_HEX = 65_536;
const TERMINAL = Object.freeze(["finalized", "failed", "halted"]);

const SCHEMA = `CREATE TABLE ledger_binding (id INTEGER PRIMARY KEY CHECK(id = 1), binding TEXT NOT NULL) STRICT;
CREATE TABLE worker_lease (
  id INTEGER PRIMARY KEY CHECK(id = 1), owner TEXT NOT NULL CHECK(length(owner) = 32),
  epoch INTEGER NOT NULL CHECK(epoch >= 1), expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
) STRICT;
CREATE TABLE account_nonce (id INTEGER PRIMARY KEY CHECK(id = 1), next_nonce INTEGER NOT NULL CHECK(next_nonce >= 1)) STRICT;
CREATE TABLE transfers (
  transfer_id TEXT PRIMARY KEY NOT NULL CHECK(length(transfer_id) = 66),
  approval_digest TEXT NOT NULL CHECK(length(approval_digest) = 66),
  request_hash TEXT NOT NULL CHECK(length(request_hash) = 66),
  state TEXT NOT NULL CHECK(state IN ('claimed', 'signed', 'broadcast', 'finalized', 'failed', 'halted')),
  claim_epoch INTEGER NOT NULL CHECK(claim_epoch >= 1),
  nonce INTEGER UNIQUE CHECK(nonce >= 0),
  signed_hex TEXT CHECK(length(signed_hex) BETWEEN 4 AND ${MAX_SIGNED_HEX}),
  transaction_digest TEXT UNIQUE CHECK(length(transaction_digest) = 66),
  transaction_hash TEXT UNIQUE CHECK(length(transaction_hash) = 66),
  broadcast_attempts INTEGER NOT NULL CHECK(broadcast_attempts BETWEEN 0 AND ${LEDGER_MAX_BROADCAST_ATTEMPTS}),
  block_number INTEGER CHECK(block_number >= 0),
  block_hash TEXT CHECK(length(block_hash) = 66),
  halt_code TEXT CHECK(length(halt_code) BETWEEN 1 AND 64),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  CHECK((signed_hex IS NULL) = (nonce IS NULL) AND (nonce IS NULL) = (transaction_hash IS NULL)
    AND (transaction_hash IS NULL) = (transaction_digest IS NULL)),
  CHECK(state IN ('claimed', 'halted') OR signed_hex IS NOT NULL),
  CHECK(state <> 'claimed' OR signed_hex IS NULL),
  CHECK((block_hash IS NULL) = (block_number IS NULL) AND (state IN ('finalized', 'failed')) = (block_hash IS NOT NULL)),
  CHECK((state = 'halted') = (halt_code IS NOT NULL)),
  CHECK(state IN ('broadcast', 'finalized', 'failed', 'halted') OR broadcast_attempts = 0),
  CHECK(state NOT IN ('broadcast', 'finalized', 'failed') OR broadcast_attempts >= 1)
) STRICT;
CREATE TABLE transfer_events (
  seq INTEGER PRIMARY KEY, transfer_id TEXT NOT NULL, state TEXT NOT NULL, code TEXT NOT NULL,
  epoch INTEGER NOT NULL, at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER binding_permanent BEFORE UPDATE ON ledger_binding BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER binding_no_delete BEFORE DELETE ON ledger_binding BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER lease_no_delete BEFORE DELETE ON worker_lease BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER lease_fencing BEFORE UPDATE ON worker_lease
  WHEN new.epoch < old.epoch OR new.epoch > old.epoch + 1 OR (new.epoch = old.epoch AND new.owner IS NOT old.owner)
  BEGIN SELECT RAISE(ABORT, 'fencing'); END;
CREATE TRIGGER nonce_no_delete BEFORE DELETE ON account_nonce BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER nonce_sequential BEFORE UPDATE ON account_nonce
  WHEN new.next_nonce IS NOT old.next_nonce + 1 BEGIN SELECT RAISE(ABORT, 'sequential'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON transfer_events BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON transfer_events BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER transfers_no_delete BEFORE DELETE ON transfers BEGIN SELECT RAISE(ABORT, 'permanent'); END;
CREATE TRIGGER transfers_insert BEFORE INSERT ON transfers
  WHEN new.state NOT IN ('claimed', 'halted') OR new.signed_hex IS NOT NULL OR new.broadcast_attempts <> 0
  BEGIN SELECT RAISE(ABORT, 'insert'); END;
CREATE TRIGGER transfers_terminal BEFORE UPDATE ON transfers
  WHEN old.state IN ('finalized', 'failed', 'halted') BEGIN SELECT RAISE(ABORT, 'terminal'); END;
CREATE TRIGGER transfers_progress BEFORE UPDATE ON transfers
  WHEN NOT ((old.state = 'claimed' AND new.state IN ('claimed', 'signed', 'halted'))
    OR (old.state = 'signed' AND new.state IN ('broadcast', 'halted'))
    OR (old.state = 'broadcast' AND new.state IN ('broadcast', 'finalized', 'failed', 'halted')))
  BEGIN SELECT RAISE(ABORT, 'transition'); END;
CREATE TRIGGER transfers_immutable BEFORE UPDATE ON transfers
  WHEN new.transfer_id IS NOT old.transfer_id OR new.claim_epoch IS NOT old.claim_epoch
    OR new.created_at IS NOT old.created_at
    OR new.broadcast_attempts < old.broadcast_attempts OR new.broadcast_attempts > old.broadcast_attempts + 1
    OR (old.signed_hex IS NOT NULL AND (new.signed_hex IS NOT old.signed_hex OR new.nonce IS NOT old.nonce
      OR new.transaction_hash IS NOT old.transaction_hash OR new.transaction_digest IS NOT old.transaction_digest
      OR new.approval_digest IS NOT old.approval_digest OR new.request_hash IS NOT old.request_hash))
  BEGIN SELECT RAISE(ABORT, 'immutable'); END;`;
const SCHEMA_QUERY = "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name";
const reference = new DatabaseSync(":memory:");
reference.exec(SCHEMA);
const EXPECTED_SCHEMA = JSON.stringify(reference.prepare(SCHEMA_QUERY).all());
reference.close();

const hash = (value) => typeof value === "string" && HASH.test(value) && value !== ZERO_HASH;
const sha256 = (hex) => `0x${createHash("sha256").update(Buffer.from(hex.slice(2), "hex")).digest("hex")}`;
function plain(value, fields) {
  if (!value || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw failure();
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) throw failure();
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) throw failure();
  }
  return value;
}
function evmAccount(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw failure();
  const normalized = getAddress(value);
  if (value !== normalized || /^0x0{40}$/.test(value) || value.toLowerCase() === "0x000000000000000000000000000000000000dead") throw failure();
  return normalized;
}
function bech32Account(value) {
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  if (typeof value !== "string" || !/^xtc1[02-9ac-hj-np-z]{38}$/.test(value)) throw failure();
  let accumulator = 0, bits = 0;
  const bytes = [];
  for (const character of value.slice(4, -6)) {
    accumulator = (accumulator << 5) | charset.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 0xff); }
  }
  if (bytes.length !== 20 || bech32Encode("xtc", bytes) !== value) throw failure();
  return value;
}

// The binding is the destination deployment identity, NOT the release: an
// upgraded release may reopen pending state only with the identical schema.
export function ledgerBinding(input) {
  try {
    const value = plain(input, ["destination", "chainId", "routeId", "target", "targetIdentity", "account"]);
    if (value.routeId !== "cronos-testnet-xitcoin-testnet") throw failure();
    if (value.destination === "cronos") {
      if (value.chainId !== "338" || !hash(value.targetIdentity) || value.targetIdentity === EMPTY_CODE_HASH
          || evmAccount(value.target) === evmAccount(value.account)) throw failure();
    } else if (value.destination === "xitcoin") {
      if (value.chainId !== "xitcoin-testnet-v2-1" || value.target !== "x/bridge"
          || typeof value.targetIdentity !== "string" || !/^[0-9a-f]{40}$/.test(value.targetIdentity)) throw failure();
      bech32Account(value.account);
    } else throw failure();
    return JSON.stringify({ schemaVersion: 1, kind: "destination_broadcast_ledger",
      destination: value.destination, chainId: value.chainId, routeId: value.routeId,
      target: value.target, targetIdentity: value.targetIdentity, account: value.account });
  } catch { throw failure(); }
}

export class BroadcastLedger {
  #database;
  #binding;
  #path;
  #destination;

  constructor(path, binding, { identity = userInfo, stat = lstatSync } = {}) {
    try {
      this.#binding = ledgerBinding(binding);
      this.#destination = binding.destination;
      const owner = identity();
      if (owner.username !== `xitcoin-bridge-submitter-${this.#destination}`
          || !Number.isSafeInteger(owner.uid) || owner.uid <= 0 || owner.uid !== process.geteuid()) throw failure();
      this.#path = new PrivateJournalPath(path, owner.uid, stat);
      this.#database = new DatabaseSync(this.#path.path, { timeout: 1000 });
      this.#path.verify();
      this.#database.exec("PRAGMA trusted_schema = OFF; PRAGMA busy_timeout = 1000; PRAGMA synchronous = FULL; PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE");
      if (this.#path.fresh) {
        if (this.#database.prepare("SELECT count(*) AS n FROM sqlite_schema").get().n !== 0) throw failure();
        this.#database.exec(SCHEMA);
        this.#database.exec("PRAGMA user_version = 1");
        this.#database.prepare("INSERT INTO ledger_binding VALUES (1, ?)").run(this.#binding);
      }
      this.#validate();
      this.#database.exec("COMMIT");
      if (this.#database.prepare("PRAGMA journal_mode = WAL").get().journal_mode !== "wal") throw failure();
      this.#path.verify();
      if (this.#path.fresh) this.#path.syncCreation();
    } catch {
      try { this.#database?.exec("ROLLBACK"); } catch { /* No active transaction. */ }
      try { this.#database?.close(); } catch { /* Preserve sanitized failure. */ }
      this.#path?.close();
      throw failure();
    }
  }

  get destination() { return this.#destination; }

  #validate() {
    // Exact DDL covers columns, CHECK constraints, uniqueness and every trigger.
    // There is no migration: an unknown or partial schema requires offline review.
    if (this.#database.prepare("PRAGMA user_version").get().user_version !== 1
        || JSON.stringify(this.#database.prepare(SCHEMA_QUERY).all()) !== EXPECTED_SCHEMA) throw failure();
    const rows = this.#database.prepare("SELECT * FROM ledger_binding").all();
    if (rows.length !== 1 || rows[0].id !== 1 || rows[0].binding !== this.#binding) throw failure();
    if (this.#database.prepare("PRAGMA quick_check").get().quick_check !== "ok") throw failure();
  }

  assertBinding(binding) {
    try { if (ledgerBinding(binding) !== this.#binding) throw failure(); } catch { throw failure(); }
  }

  #transaction(operation, lease) {
    try {
      this.#path.verify();
      this.#database.exec("BEGIN IMMEDIATE");
      if (lease !== undefined) {
        plain(lease, ["owner", "epoch", "expiresAt"]);
        const current = this.#database.prepare("SELECT owner, epoch FROM worker_lease WHERE id = 1").get();
        if (!current || current.owner !== lease.owner || current.epoch !== lease.epoch) throw failure();
      }
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch {
      try { this.#database.exec("ROLLBACK"); } catch { /* No active transaction. */ }
      throw failure();
    }
  }

  // A lease is a fencing token. Takeover is possible only after expiry and
  // increments the epoch, after which every write by the previous holder fails.
  acquireLease(owner, { nowMs = Date.now(), ttlMs = 60_000 } = {}) {
    if (typeof owner !== "string" || !OWNER.test(owner) || !Number.isSafeInteger(nowMs) || nowMs < 0
        || !Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 600_000) throw failure();
    return this.#transaction(() => {
      const current = this.#database.prepare("SELECT owner, epoch, expires_at FROM worker_lease WHERE id = 1").get();
      const expiresAt = nowMs + ttlMs;
      let epoch;
      if (!current) {
        epoch = 1;
        this.#database.prepare("INSERT INTO worker_lease VALUES (1, ?, 1, ?)").run(owner, expiresAt);
      } else if (current.owner === owner) {
        epoch = current.epoch;
        this.#database.prepare("UPDATE worker_lease SET expires_at = ? WHERE id = 1").run(expiresAt);
      } else if (current.expires_at <= nowMs) {
        epoch = current.epoch + 1;
        this.#database.prepare("UPDATE worker_lease SET owner = ?, epoch = ?, expires_at = ? WHERE id = 1").run(owner, epoch, expiresAt);
      } else throw failure();
      return Object.freeze({ owner, epoch, expiresAt });
    });
  }

  releaseLease(lease) {
    return this.#transaction(() => {
      this.#database.prepare("UPDATE worker_lease SET expires_at = 0 WHERE id = 1").run();
      return Object.freeze({ released: true });
    }, lease);
  }

  #event(transferId, state, code, epoch) {
    this.#database.prepare("INSERT INTO transfer_events (transfer_id, state, code, epoch, at) VALUES (?, ?, ?, ?, ?)")
      .run(transferId, state, code, epoch, Math.floor(Date.now() / 1000));
  }

  #raw(transferId) {
    return this.#database.prepare("SELECT * FROM transfers WHERE transfer_id = ?").get(transferId);
  }

  #snapshot(row) {
    if (!row || !hash(row.transfer_id) || !hash(row.approval_digest) || !hash(row.request_hash)
        || !["claimed", "signed", "broadcast", ...TERMINAL].includes(row.state)
        || !Number.isSafeInteger(row.claim_epoch) || row.claim_epoch < 1
        || !Number.isSafeInteger(row.broadcast_attempts) || row.broadcast_attempts < 0
        || row.broadcast_attempts > LEDGER_MAX_BROADCAST_ATTEMPTS) throw failure();
    if (row.signed_hex !== null) {
      if (typeof row.signed_hex !== "string" || row.signed_hex.length > MAX_SIGNED_HEX
          || !/^0x(?:[0-9a-f]{2})+$/.test(row.signed_hex) || !hash(row.transaction_hash)
          || !Number.isSafeInteger(row.nonce) || row.nonce < 0
          || sha256(row.signed_hex) !== row.transaction_digest) throw failure();
    } else if (row.nonce !== null || row.transaction_hash !== null || row.transaction_digest !== null) throw failure();
    if (row.block_hash !== null && (!hash(row.block_hash) || !Number.isSafeInteger(row.block_number))) throw failure();
    if (row.halt_code !== null && (typeof row.halt_code !== "string" || !CODE.test(row.halt_code))) throw failure();
    return Object.freeze({ found: true, transferId: row.transfer_id, approvalDigest: row.approval_digest,
      requestHash: row.request_hash, state: row.state, claimEpoch: row.claim_epoch, nonce: row.nonce,
      signedHex: row.signed_hex, transactionDigest: row.transaction_digest, transactionHash: row.transaction_hash,
      broadcastAttempts: row.broadcast_attempts, blockNumber: row.block_number, blockHash: row.block_hash,
      haltCode: row.halt_code, mayRetry: false });
  }

  inspect(transferId) {
    try {
      if (!hash(transferId)) throw failure();
      this.#path.verify();
      const row = this.#raw(transferId);
      return row ? this.#snapshot(row) : Object.freeze({ found: false, mayRetry: false });
    } catch { throw failure(); }
  }

  // Unfinished rows (at most one by construction) and rows requiring review.
  active() {
    try {
      this.#path.verify();
      return Object.freeze(this.#database.prepare("SELECT * FROM transfers WHERE state IN ('claimed', 'signed', 'broadcast') ORDER BY created_at, transfer_id LIMIT 2")
        .all().map((row) => this.#snapshot(row)));
    } catch { throw failure(); }
  }

  blocking() {
    try {
      this.#path.verify();
      return Object.freeze(this.#database.prepare("SELECT * FROM transfers WHERE state IN ('failed', 'halted') ORDER BY created_at, transfer_id LIMIT 16")
        .all().map((row) => this.#snapshot(row)));
    } catch { throw failure(); }
  }

  nextNonce() {
    try {
      this.#path.verify();
      const row = this.#database.prepare("SELECT next_nonce FROM account_nonce WHERE id = 1").get();
      if (row && (!Number.isSafeInteger(row.next_nonce) || row.next_nonce < 1)) throw failure();
      return row ? row.next_nonce : null;
    } catch { throw failure(); }
  }

  // Exclusive claim. A claimed row has no bytes and was never sent, so it may be
  // rebound to a re-issued approval; once bytes exist the approval is permanent.
  claim(lease, input) {
    const { transferId, approvalDigest, requestHash } = plain(input, ["transferId", "approvalDigest", "requestHash"]);
    if (![transferId, approvalDigest, requestHash].every(hash)) throw failure();
    return this.#transaction(() => {
      const existing = this.#raw(transferId);
      if (existing) {
        if (existing.approval_digest === approvalDigest && existing.request_hash === requestHash) return this.#snapshot(existing);
        if (existing.state !== "claimed") throw failure();
        this.#database.prepare("UPDATE transfers SET approval_digest = ?, request_hash = ?, updated_at = ? WHERE transfer_id = ? AND state = 'claimed'")
          .run(approvalDigest, requestHash, Math.floor(Date.now() / 1000), transferId);
        this.#event(transferId, "claimed", "rebound", lease.epoch);
        return this.#snapshot(this.#raw(transferId));
      }
      const open = this.#database.prepare("SELECT count(*) AS n FROM transfers WHERE state <> 'finalized'").get().n;
      if (open !== 0) throw failure();
      const now = Math.floor(Date.now() / 1000);
      this.#database.prepare(`INSERT INTO transfers (transfer_id, approval_digest, request_hash, state, claim_epoch,
        broadcast_attempts, created_at, updated_at) VALUES (?, ?, ?, 'claimed', ?, 0, ?, ?)`)
        .run(transferId, approvalDigest, requestHash, lease.epoch, now, now);
      this.#event(transferId, "claimed", "claimed", lease.epoch);
      return this.#snapshot(this.#raw(transferId));
    }, lease);
  }

  // Commit exact bytes, transaction hash and the next account nonce BEFORE send.
  // The first nonce comes from verified chain state; later nonces are sequential.
  recordSigned(lease, input) {
    const { transferId, nonce, signedHex, transactionHash } = plain(input, ["transferId", "nonce", "signedHex", "transactionHash"]);
    if (!hash(transferId) || !hash(transactionHash) || !Number.isSafeInteger(nonce) || nonce < 0
        || typeof signedHex !== "string" || signedHex.length > MAX_SIGNED_HEX || !/^0x(?:[0-9a-f]{2})+$/.test(signedHex)) throw failure();
    const transactionDigest = sha256(signedHex);
    return this.#transaction(() => {
      const existing = this.#raw(transferId);
      if (!existing) throw failure();
      if (existing.state !== "claimed") {
        if (existing.signed_hex !== signedHex || existing.transaction_hash !== transactionHash || existing.nonce !== nonce) throw failure();
        return this.#snapshot(existing);
      }
      const account = this.#database.prepare("SELECT next_nonce FROM account_nonce WHERE id = 1").get();
      if (account && account.next_nonce !== nonce) throw failure();
      if (account) this.#database.prepare("UPDATE account_nonce SET next_nonce = ? WHERE id = 1").run(nonce + 1);
      else this.#database.prepare("INSERT INTO account_nonce VALUES (1, ?)").run(nonce + 1);
      const result = this.#database.prepare(`UPDATE transfers SET state = 'signed', nonce = ?, signed_hex = ?,
        transaction_digest = ?, transaction_hash = ?, updated_at = ? WHERE transfer_id = ? AND state = 'claimed'`)
        .run(nonce, signedHex, transactionDigest, transactionHash, Math.floor(Date.now() / 1000), transferId);
      if (result.changes !== 1) throw failure();
      this.#event(transferId, "signed", "signed", lease.epoch);
      return this.#snapshot(this.#raw(transferId));
    }, lease);
  }

  // Write-ahead marker: committed BEFORE each send of the identical bytes.
  markBroadcast(lease, transferId, { maxAttempts } = {}) {
    if (!hash(transferId) || !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > LEDGER_MAX_BROADCAST_ATTEMPTS) throw failure();
    return this.#transaction(() => {
      const existing = this.#raw(transferId);
      if (!existing || !["signed", "broadcast"].includes(existing.state) || existing.broadcast_attempts >= maxAttempts) throw failure();
      this.#database.prepare(`UPDATE transfers SET state = 'broadcast', broadcast_attempts = broadcast_attempts + 1,
        updated_at = ? WHERE transfer_id = ? AND state IN ('signed', 'broadcast')`).run(Math.floor(Date.now() / 1000), transferId);
      this.#event(transferId, "broadcast", "broadcast", lease.epoch);
      return this.#snapshot(this.#raw(transferId));
    }, lease);
  }

  #conclude(lease, transferId, state, { blockNumber, blockHash } = {}) {
    if (!hash(transferId) || !hash(blockHash) || !Number.isSafeInteger(blockNumber) || blockNumber < 0) throw failure();
    return this.#transaction(() => {
      const existing = this.#raw(transferId);
      if (existing?.state === state && existing.block_hash === blockHash && existing.block_number === blockNumber) return this.#snapshot(existing);
      if (existing?.state !== "broadcast") throw failure();
      this.#database.prepare("UPDATE transfers SET state = ?, block_number = ?, block_hash = ?, updated_at = ? WHERE transfer_id = ? AND state = 'broadcast'")
        .run(state, blockNumber, blockHash, Math.floor(Date.now() / 1000), transferId);
      this.#event(transferId, state, state, lease.epoch);
      return this.#snapshot(this.#raw(transferId));
    }, lease);
  }

  finalize(lease, transferId, inclusion) { return this.#conclude(lease, transferId, "finalized", inclusion); }

  markFailed(lease, transferId, inclusion) { return this.#conclude(lease, transferId, "failed", inclusion); }

  // Halting is permanent. Without a row, a halted row is created so restart
  // never resumes automatically (for example, replay processed elsewhere).
  halt(lease, input) {
    const { transferId, approvalDigest, requestHash, code } = plain(input, ["transferId", "approvalDigest", "requestHash", "code"]);
    if (![transferId, approvalDigest, requestHash].every(hash) || typeof code !== "string" || !CODE.test(code)) throw failure();
    return this.#transaction(() => {
      const existing = this.#raw(transferId);
      const now = Math.floor(Date.now() / 1000);
      if (!existing) {
        this.#database.prepare(`INSERT INTO transfers (transfer_id, approval_digest, request_hash, state, claim_epoch,
          broadcast_attempts, halt_code, created_at, updated_at) VALUES (?, ?, ?, 'halted', ?, 0, ?, ?, ?)`)
          .run(transferId, approvalDigest, requestHash, lease.epoch, code, now, now);
      } else if (existing.state === "halted") {
        return this.#snapshot(existing);
      } else {
        if (TERMINAL.includes(existing.state)) throw failure();
        this.#database.prepare("UPDATE transfers SET state = 'halted', halt_code = ?, updated_at = ? WHERE transfer_id = ?")
          .run(code, now, transferId);
      }
      this.#event(transferId, "halted", code, lease.epoch);
      return this.#snapshot(this.#raw(transferId));
    }, lease);
  }

  close() { try { this.#database.close(); } finally { this.#path.close(); } }
}
