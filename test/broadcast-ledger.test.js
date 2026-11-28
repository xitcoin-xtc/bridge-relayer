import assert from "node:assert/strict";
import test from "node:test";
import { closeSync, mkdtempSync, openSync, rmSync, symlinkSync, chmodSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { keccak256, sha256 } from "ethers";
import { BroadcastLedger, ledgerBinding, LEDGER_MAX_BROADCAST_ATTEMPTS, LEDGER_SCHEMA_V1, LEDGER_SCHEMA_V2, LEDGER_SCHEMA_VERSION } from "../src/broadcast-ledger.js";
import { evmAddressToBech32 } from "../src/address.js";
import { journalOptions } from "./journal-fixture.js";
import { signers } from "./fixtures/destination.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "../src/protocol.js";

const failure = { message: "broadcast ledger unavailable or conflicting" };
const hash = (letter) => `0x${letter.repeat(64)}`;
const bindings = {
  cronos: { destination: "cronos", chainId: "338", routeId: XITCOIN_TESTNET_ROUTE_ID,
    target: "0x1c94273C0b199b139D82da3786C9eCbE189D5919", targetIdentity: hash("c"), account: signers[2] },
  xitcoin: { destination: "xitcoin", chainId: "xitcoin-testnet-v2-1", routeId: XITCOIN_TESTNET_ROUTE_ID,
    target: "x/bridge", targetIdentity: "5ec8692e8fc1813d0892ee535af1a73953a1c4fb", account: evmAddressToBech32(signers[2]) },
};
const owner = (n) => n.toString(16).padStart(32, "0");
const bytes = (seed) => `0x${Buffer.from(`synthetic signed transaction ${seed}`).toString("hex")}`;
const signed = (transferId, nonce, seed = transferId) => ({ transferId, nonce, signedHex: bytes(seed), transactionHash: keccak256(bytes(seed)) });
const claimOf = (transferId, approval = "b") => ({ transferId, sourceRef: transferId, approvalDigest: hash(approval), requestHash: hash("d") });

function fixture(run) {
  const directory = mkdtempSync(join(tmpdir(), "ledger-test-"));
  return Promise.resolve().then(() => run(join(directory, "ledger.sqlite"), directory))
    .finally(() => rmSync(directory, { recursive: true, force: true }));
}
const open = (path, destination) => new BroadcastLedger(path, bindings[destination], journalOptions(destination));

function child(path, destination, script) {
  const base = new URL("../", import.meta.url).href;
  const code = `import { BroadcastLedger } from '${base}src/broadcast-ledger.js';
    import { journalOptions } from '${base}test/journal-fixture.js';
    const ledger = new BroadcastLedger(${JSON.stringify(path)}, ${JSON.stringify(bindings[destination])}, journalOptions(${JSON.stringify(destination)}));
    const out = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
    ${script}
    ledger.close();`;
  return new Promise((resolve, reject) => {
    const processHandle = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "", errors = "";
    processHandle.stdout.on("data", (data) => { output += data; });
    processHandle.stderr.on("data", (data) => { errors += data; });
    processHandle.on("error", reject);
    processHandle.on("close", (status, signal) => status === 0 || signal === "SIGKILL"
      ? resolve(output.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)))
      : reject(new Error(errors)));
  });
}

for (const destination of ["cronos", "xitcoin"]) {
  test(`${destination}: exact bytes and sequential nonces are committed before send and never replaced`, () => fixture((path) => {
    let ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    assert.equal(ledger.nextNonce(), null);
    const claimed = ledger.claim(lease, claimOf(hash("1")));
    assert.equal(claimed.state, "claimed"); assert.equal(claimed.signedHex, null); assert.equal(claimed.mayRetry, false);
    assert.deepEqual(ledger.claim(lease, claimOf(hash("1"))), claimed);
    const first = ledger.recordSigned(lease, signed(hash("1"), 7));
    assert.equal(first.state, "signed"); assert.equal(first.nonce, 7); assert.equal(ledger.nextNonce(), 8);
    assert.deepEqual(ledger.recordSigned(lease, signed(hash("1"), 7)), first);
    for (const patch of [{ nonce: 8 }, { signedHex: bytes("other") }, { transactionHash: hash("e") }]) {
      assert.throws(() => ledger.recordSigned(lease, { ...signed(hash("1"), 7), ...patch }), failure);
    }
    assert.throws(() => ledger.claim(lease, claimOf(hash("1"), "e")), failure); // approval is bound once bytes exist
    assert.throws(() => ledger.finalize(lease, hash("1"), { blockNumber: 1, blockHash: hash("f") }), failure);
    assert.equal(ledger.markBroadcast(lease, hash("1"), { maxAttempts: 2 }).broadcastAttempts, 1);
    assert.equal(ledger.markBroadcast(lease, hash("1"), { maxAttempts: 2 }).broadcastAttempts, 2);
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: 2 }), failure);
    assert.throws(() => ledger.claim(lease, claimOf(hash("2"))), failure); // one unfinished transfer only
    const final = ledger.finalize(lease, hash("1"), { blockNumber: 12, blockHash: hash("f") });
    assert.equal(final.state, "finalized");
    assert.deepEqual(ledger.finalize(lease, hash("1"), { blockNumber: 12, blockHash: hash("f") }), final);
    assert.throws(() => ledger.finalize(lease, hash("1"), { blockNumber: 13, blockHash: hash("f") }), failure);
    assert.throws(() => ledger.halt(lease, { ...claimOf(hash("1")), code: "late_halt" }), failure);
    ledger.close();
    ledger = open(path, destination);
    assert.deepEqual(ledger.inspect(hash("1")), final);
    const next = ledger.acquireLease(owner(1));
    ledger.claim(next, claimOf(hash("2")));
    for (const nonce of [7, 9]) assert.throws(() => ledger.recordSigned(next, signed(hash("2"), nonce)), failure);
    assert.throws(() => ledger.recordSigned(next, { ...signed(hash("2"), 8), signedHex: bytes(hash("1")), transactionHash: keccak256(bytes(hash("1"))) }), failure);
    assert.throws(() => ledger.recordSigned(next, { ...signed(hash("2"), 8), transactionHash: final.transactionHash }), failure);
    assert.equal(ledger.recordSigned(next, signed(hash("2"), 8)).nonce, 8);
    assert.deepEqual(ledger.active().map((row) => row.transferId), [hash("2")]);
    assert.equal(ledger.inspect(hash("3")).found, false);
    ledger.close();
  }));

  test(`${destination}: failed and halted rows block every later claim, permanently`, () => fixture((path) => {
    let ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    ledger.recordSigned(lease, signed(hash("1"), 0));
    ledger.markBroadcast(lease, hash("1"), { maxAttempts: 1 });
    const failed = ledger.markFailed(lease, hash("1"), { blockNumber: 3, blockHash: hash("f") });
    assert.equal(failed.state, "failed");
    assert.throws(() => ledger.claim(lease, claimOf(hash("2"))), failure);
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: 5 }), failure);
    assert.throws(() => ledger.finalize(lease, hash("1"), { blockNumber: 3, blockHash: hash("f") }), failure);
    const halted = ledger.halt(lease, { ...claimOf(hash("2")), code: "processed_without_local_transaction" });
    assert.equal(halted.state, "halted"); assert.equal(halted.signedHex, null);
    assert.deepEqual(ledger.halt(lease, { ...claimOf(hash("2")), code: "other_code" }), halted);
    assert.deepEqual(ledger.blocking().map((row) => row.state), ["failed", "halted"]);
    ledger.close();
    ledger = open(path, destination);
    const next = ledger.acquireLease(owner(2), { nowMs: Date.now() + 3_600_000 });
    assert.throws(() => ledger.claim(next, claimOf(hash("3"))), failure);
    assert.equal(ledger.blocking().length, 2);
    ledger.close();
  }));

  test(`${destination}: a claimed row without bytes may be rebound; halting it keeps it unsendable`, () => fixture((path) => {
    const ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    const rebound = ledger.claim(lease, claimOf(hash("1"), "e"));
    assert.equal(rebound.approvalDigest, hash("e")); assert.equal(rebound.state, "claimed");
    const halted = ledger.halt(lease, { ...claimOf(hash("1"), "e"), code: "nonce_owned_by_other_program" });
    assert.equal(halted.signedHex, null);
    assert.throws(() => ledger.recordSigned(lease, signed(hash("1"), 0)), failure);
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: 1 }), failure);
    ledger.close();
  }));

  test(`${destination}: released elsewhere and rejected rows are permanent but never block the queue`, () => fixture((path) => {
    let ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    const release = { releaseHash: hash("e"), blockNumber: 40, blockHash: hash("f") };
    // Without bytes (released before any claim) and from a claimed row.
    const early = ledger.releasedElsewhere(lease, { ...claimOf(hash("1")), ...release });
    assert.equal(early.state, "released_elsewhere"); assert.equal(early.signedHex, null); assert.equal(early.releaseHash, hash("e"));
    assert.deepEqual(ledger.releasedElsewhere(lease, { ...claimOf(hash("1")), ...release }), early);
    assert.throws(() => ledger.releasedElsewhere(lease, { ...claimOf(hash("1")), ...release, blockNumber: 41 }), failure);
    ledger.claim(lease, claimOf(hash("2")));
    assert.equal(ledger.releasedElsewhere(lease, { ...claimOf(hash("2")), ...release }).state, "released_elsewhere");
    // Never from `signed`: those bytes were never sent and their nonce is unused.
    ledger.claim(lease, claimOf(hash("3")));
    ledger.recordSigned(lease, signed(hash("3"), 0));
    assert.throws(() => ledger.releasedElsewhere(lease, { ...claimOf(hash("3")), ...release }), failure);
    assert.throws(() => ledger.reject(lease, { ...claimOf(hash("3")), code: "invalid_recipient" }), failure);
    // After the identical bytes were sent (nonce consumed by their revert).
    ledger.markBroadcast(lease, hash("3"), { maxAttempts: 2 });
    assert.throws(() => ledger.releasedElsewhere(lease, { ...claimOf(hash("3")), ...release, releaseHash: signed(hash("3"), 0).transactionHash }), failure);
    const front = ledger.releasedElsewhere(lease, { ...claimOf(hash("3")), ...release });
    assert.equal(front.transactionHash, signed(hash("3"), 0).transactionHash); assert.equal(front.nonce, 0);
    assert.throws(() => ledger.markBroadcast(lease, hash("3"), { maxAttempts: 5 }), failure);
    const rejected = ledger.reject(lease, { ...claimOf(hash("4")), code: "invalid_recipient" });
    assert.equal(rejected.state, "rejected"); assert.equal(rejected.reasonCode, "invalid_recipient");
    assert.deepEqual(ledger.reject(lease, { ...claimOf(hash("4")), code: "invalid_recipient" }), rejected);
    assert.throws(() => ledger.claim(lease, claimOf(hash("4"), "c")), failure);
    assert.throws(() => ledger.halt(lease, { ...claimOf(hash("4")), code: "late" }), failure);
    assert.equal(ledger.blocking().length, 0);
    ledger.close();
    ledger = open(path, destination);
    const next = ledger.acquireLease(owner(1));
    assert.equal(ledger.claim(next, claimOf(hash("5"))).state, "claimed");
    assert.equal(ledger.recordSigned(next, signed(hash("5"), 1)).nonce, 1);
    ledger.close();
  }));

  test(`${destination}: a source reference belongs to exactly one transfer`, () => fixture((path) => {
    const ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    assert.throws(() => ledger.claim(lease, { ...claimOf(hash("2")), sourceRef: hash("1") }), failure);
    assert.throws(() => ledger.halt(lease, { ...claimOf(hash("1")), sourceRef: hash("2"), code: "x" }), failure);
    assert.throws(() => ledger.reject(lease, { ...claimOf(hash("9")), sourceRef: hash("1"), code: "x" }), failure);
    for (const sourceRef of ["0x01", hash("A"), "a".repeat(63), 1]) {
      assert.throws(() => ledger.claim(lease, { ...claimOf(hash("3")), sourceRef }), failure);
    }
    assert.equal(ledger.scheduling(hash("1")).state, "claimed");
    assert.equal(ledger.scheduling("a".repeat(64)).state, null);
    ledger.close();
  }));

  test(`${destination}: deferrals are durable scheduling hints with bounded backoff`, () => fixture((path) => {
    let ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    const item = { transferId: hash("1"), sourceRef: hash("1"), code: "approval_expired_awaiting_reissue" };
    assert.equal(ledger.defer(lease, item, { nowMs: 0 }).untilMs, 60_000);
    assert.equal(ledger.defer(lease, item, { nowMs: 0 }).untilMs, 120_000);
    for (let i = 0; i < 10; i++) ledger.defer(lease, item, { nowMs: 0 });
    assert.equal(ledger.defer(lease, item, { nowMs: 0 }).untilMs, 3_600_000);
    assert.throws(() => ledger.defer(lease, { ...item, transferId: hash("2") }), failure);
    for (const patch of [{ code: "Bad" }, { sourceRef: "x" }, { extra: 1 }]) assert.throws(() => ledger.defer(lease, { ...item, ...patch }), failure);
    ledger.close();
    ledger = open(path, destination);
    assert.deepEqual({ ...ledger.scheduling(hash("1")) }, { transferId: hash("1"), state: null,
      deferredUntilMs: 3_600_000, deferralCode: "approval_expired_awaiting_reissue" });
    assert.equal(ledger.deferrals()[0].count, 13);
    // A deferral is never permission to send and never changes transfer rows.
    assert.equal(ledger.inspect(hash("1")).found, false);
    assert.throws(() => ledger.defer({ owner: owner(2), epoch: 1, expiresAt: 0 }, item), failure);
    ledger.close();
  }));

  test(`${destination}: an unclaimed row has no bytes or nonce, frees the queue and can be claimed again`, () => fixture((path) => {
    const ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    const released = ledger.unclaim(lease, hash("1"));
    assert.equal(released.state, "unclaimed"); assert.equal(released.nonce, null);
    assert.deepEqual(ledger.unclaim(lease, hash("1")), released);
    assert.deepEqual(ledger.active(), []); assert.equal(ledger.blocking().length, 0);
    ledger.claim(lease, claimOf(hash("2")));
    assert.throws(() => ledger.claim(lease, claimOf(hash("1"), "e")), failure); // still one unfinished transfer at a time
    ledger.recordSigned(lease, signed(hash("2"), 0));
    assert.throws(() => ledger.unclaim(lease, hash("2")), failure); // bytes exist: never released
    ledger.markBroadcast(lease, hash("2"), { maxAttempts: 1 });
    ledger.finalize(lease, hash("2"), { blockNumber: 3, blockHash: hash("f") });
    const again = ledger.claim(lease, claimOf(hash("1"), "e")); // re-issued approval
    assert.equal(again.state, "claimed"); assert.equal(again.approvalDigest, hash("e"));
    assert.equal(ledger.recordSigned(lease, signed(hash("1"), 1)).nonce, 1);
    ledger.close();
  }));

  test(`${destination}: expired and unverified-release rows are permanent, non-blocking and reported for attention`, () => fixture((path) => {
    const ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    ledger.recordSigned(lease, signed(hash("1"), 0));
    assert.throws(() => ledger.markExpired(lease, hash("1"), { blockNumber: 2, blockHash: hash("f") }), failure); // never sent
    ledger.markBroadcast(lease, hash("1"), { maxAttempts: 1 });
    const expired = ledger.markExpired(lease, hash("1"), { blockNumber: 2, blockHash: hash("f") });
    assert.equal(expired.state, "expired"); assert.equal(expired.nonce, 0);
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: 5 }), failure);
    const unverified = ledger.releaseUnverified(lease, { ...claimOf(hash("2")), blockNumber: null, blockHash: null });
    assert.equal(unverified.state, "release_unverified"); assert.equal(unverified.signedHex, null);
    ledger.claim(lease, claimOf(hash("3")));
    ledger.recordSigned(lease, signed(hash("3"), 1));
    assert.throws(() => ledger.releaseUnverified(lease, { ...claimOf(hash("3")), blockNumber: null, blockHash: null }), failure);
    ledger.markBroadcast(lease, hash("3"), { maxAttempts: 1 });
    assert.throws(() => ledger.releaseUnverified(lease, { ...claimOf(hash("3")), blockNumber: null, blockHash: null }), failure);
    assert.equal(ledger.releaseUnverified(lease, { ...claimOf(hash("3")), blockNumber: 5, blockHash: hash("e") }).blockNumber, 5);
    ledger.reject(lease, { ...claimOf(hash("4")), code: "invalid_recipient" });
    assert.deepEqual({ ...ledger.attention() }, { rejected: 1, expired: 1, releaseUnverified: 2, reverted: 0 });
    assert.equal(ledger.blocking().length, 0);
    assert.equal(ledger.claim(lease, claimOf(hash("5"))).state, "claimed");
    assert.equal(ledger.recordSigned(lease, signed(hash("5"), 2)).nonce, 2);
    ledger.close();
  }));

  test(`${destination}: an unverified outcome keeps its reason in the transfer history, never in a blocking state`, () => fixture((path) => {
    const ledger = open(path, destination);
    const lease = ledger.acquireLease(owner(1));
    ledger.claim(lease, claimOf(hash("1")));
    ledger.recordSigned(lease, signed(hash("1"), 0));
    ledger.markBroadcast(lease, hash("1"), { maxAttempts: 1 });
    for (const code of ["", "Upper", "x".repeat(65), 5, "a b"]) {
      assert.throws(() => ledger.releaseUnverified(lease, { ...claimOf(hash("1")), blockNumber: 7, blockHash: hash("e"), code }), failure);
    }
    assert.throws(() => ledger.releaseUnverified(lease, { ...claimOf(hash("1")), blockNumber: 7, blockHash: hash("e"), code: "x", extra: 1 }), failure);
    const row = ledger.releaseUnverified(lease, { ...claimOf(hash("1")), blockNumber: 7, blockHash: hash("e"), code: "receipt_history_unserved" });
    assert.equal(row.state, "release_unverified"); assert.equal(row.reasonCode, null); assert.equal(row.blockNumber, 7);
    ledger.releaseUnverified(lease, { ...claimOf(hash("2")), blockNumber: null, blockHash: null, code: null });
    assert.deepEqual({ ...ledger.attention() }, { rejected: 0, expired: 0, releaseUnverified: 2, reverted: 0 });
    assert.equal(ledger.blocking().length, 0);
    ledger.close();
    const raw = new DatabaseSync(path, { readOnly: true });
    try {
      const events = raw.prepare("SELECT transfer_id, code FROM transfer_events WHERE state = 'release_unverified' ORDER BY seq").all();
      assert.deepEqual(events.map((event) => [event.transfer_id, event.code]),
        [[hash("1"), "receipt_history_unserved"], [hash("2"), "release_unverified"]]);
    } finally { raw.close(); }
  }));

  test(`${destination}: lease fencing rejects every write from a previous holder`, () => fixture((path) => {
    const first = open(path, destination), second = open(path, destination);
    const now = 1_000_000;
    const a = first.acquireLease(owner(1), { nowMs: now, ttlMs: 10_000 });
    assert.equal(a.epoch, 1);
    assert.throws(() => second.acquireLease(owner(2), { nowMs: now + 9_999, ttlMs: 10_000 }), failure);
    first.claim(a, claimOf(hash("1")));
    assert.equal(first.acquireLease(owner(1), { nowMs: now + 5_000, ttlMs: 10_000 }).epoch, 1); // renewal
    const b = second.acquireLease(owner(2), { nowMs: now + 15_000, ttlMs: 10_000 });
    assert.equal(b.epoch, 2);
    for (const write of [() => first.claim(a, claimOf(hash("1"))), () => first.recordSigned(a, signed(hash("1"), 0)),
      () => first.markBroadcast(a, hash("1"), { maxAttempts: 3 }), () => first.halt(a, { ...claimOf(hash("1")), code: "stale" }),
      () => first.releaseLease(a), () => first.acquireLease(owner(1), { nowMs: now + 16_000 }),
      () => first.claim({ ...a, epoch: 2 }, claimOf(hash("1"))), () => first.claim({ owner: owner(2), epoch: 2 }, claimOf(hash("1"))),
      () => first.claim(Object.assign(Object.create({ owner: owner(2) }), { epoch: 2, expiresAt: 0 }), claimOf(hash("1")))]) {
      assert.throws(write, failure);
    }
    assert.equal(second.recordSigned(b, signed(hash("1"), 0)).state, "signed");
    assert.equal(second.inspect(hash("1")).claimEpoch, 1);
    second.releaseLease(b);
    assert.equal(first.acquireLease(owner(3), { nowMs: now + 16_000 }).epoch, 3);
    for (const [name, ttl] of [[owner(4), 999], [owner(4), 600_001], ["A".repeat(32), 10_000], ["short", 10_000]]) {
      assert.throws(() => first.acquireLease(name, { nowMs: now, ttlMs: ttl }), failure);
    }
    first.close(); second.close();
  }));

  test(`${destination}: expired-lease takeovers by competing processes cannot replace committed bytes`, () => fixture(async (path) => {
    open(path, destination).close();
    const base = Date.now();
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) => child(path, destination, `
      let result = "rejected";
      try {
        const lease = ledger.acquireLease("${owner(index + 1)}", { nowMs: ${base} + ${index} * 120000, ttlMs: 60000 });
        ledger.claim(lease, ${JSON.stringify(claimOf(hash("1")))});
        result = ledger.recordSigned(lease, ${JSON.stringify(signed(hash("1"), 0, `takeover ${index}`))}).transactionHash;
      } catch {}
      out(result);`)));
    const winners = results.flat().filter((result) => result !== "rejected");
    assert.equal(winners.length, 1);
    const ledger = open(path, destination);
    assert.equal(ledger.inspect(hash("1")).transactionHash, winners[0]);
    assert.equal(ledger.nextNonce(), 1);
    ledger.close();
  }));

  test(`${destination}: competing processes produce exactly one claim and one signed transaction`, () => fixture(async (path) => {
    open(path, destination).close();
    const results = await Promise.all(Array.from({ length: 6 }, (_, index) => child(path, destination, `
      let result = "rejected";
      try {
        const lease = ledger.acquireLease("${owner(index + 1)}");
        ledger.claim(lease, ${JSON.stringify(claimOf(hash("1")))});
        result = ledger.recordSigned(lease, ${JSON.stringify(signed(hash("1"), 0, `worker ${index}`))}).transactionHash;
      } catch {}
      out(result);`)));
    const winners = results.flat().filter((result) => result !== "rejected");
    assert.equal(winners.length, 1);
    const ledger = open(path, destination);
    assert.equal(ledger.inspect(hash("1")).transactionHash, winners[0]);
    assert.equal(ledger.nextNonce(), 1);
    ledger.close();
  }));

  for (const boundary of ["claim", "signed", "broadcast", "uncommitted-signature", "finalized"]) {
    test(`${destination}: SIGKILL at ${boundary} keeps only committed state and never permits replacement`, () => fixture(async (path) => {
      open(path, destination).close();
      await child(path, destination, `
        const lease = ledger.acquireLease("${owner(1)}", { nowMs: 1000, ttlMs: 60000 });
        const kill = (stage) => { if (stage === "${boundary}") process.kill(process.pid, "SIGKILL"); };
        ledger.claim(lease, ${JSON.stringify(claimOf(hash("1")))}); kill("claim");
        if ("${boundary}" === "uncommitted-signature") {
          // Kill inside an immediate transaction holding the complete signed write.
          const { DatabaseSync } = await import("node:sqlite");
          const raw = new DatabaseSync(${JSON.stringify(path)});
          raw.exec(\`BEGIN IMMEDIATE; INSERT INTO account_nonce VALUES (1, 5);
            UPDATE transfers SET state = 'signed', nonce = 4, signed_hex = '${bytes(hash("1"))}',
            transaction_digest = '${sha256(bytes(hash("1")))}', transaction_hash = '${keccak256(bytes(hash("1")))}'\`);
          process.kill(process.pid, "SIGKILL");
        }
        ledger.recordSigned(lease, ${JSON.stringify(signed(hash("1"), 4))}); kill("signed");
        ledger.markBroadcast(lease, "${hash("1")}", { maxAttempts: 3 }); kill("broadcast");
        ledger.finalize(lease, "${hash("1")}", { blockNumber: 9, blockHash: "${hash("f")}" }); kill("finalized");`);
      const ledger = open(path, destination);
      const expected = { claim: "claimed", signed: "signed", broadcast: "broadcast", "uncommitted-signature": "claimed", finalized: "finalized" }[boundary];
      assert.equal(ledger.inspect(hash("1")).state, expected);
      // The dead worker's lease must expire; recovery then continues with a new epoch.
      assert.throws(() => ledger.acquireLease(owner(2), { nowMs: 2000 }), failure);
      const lease = ledger.acquireLease(owner(2), { nowMs: 1000 + 60_001 });
      assert.equal(lease.epoch, 2);
      if (expected === "claimed") {
        assert.equal(ledger.nextNonce(), null);
        assert.equal(ledger.recordSigned(lease, signed(hash("1"), 4, "after restart")).state, "signed");
      } else {
        assert.throws(() => ledger.recordSigned(lease, signed(hash("1"), 4, "replacement")), failure);
        assert.equal(ledger.recordSigned(lease, signed(hash("1"), 4)).signedHex, bytes(hash("1")));
        assert.equal(ledger.nextNonce(), 5);
      }
      if (expected === "broadcast") assert.equal(ledger.markBroadcast(lease, hash("1"), { maxAttempts: 3 }).broadcastAttempts, 2);
      if (expected === "finalized") assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: 3 }), failure);
      ledger.close();
    }));
  }
}

test("binding pins destination identity and rejects mainnet, empty code and malformed accounts", () => {
  assert.match(ledgerBinding(bindings.cronos), /"destination":"cronos"/);
  assert.match(ledgerBinding(bindings.xitcoin), /"destination":"xitcoin"/);
  for (const patch of [{ chainId: "25" }, { chainId: 338 }, { routeId: "other" }, { destination: "ethereum" },
    { targetIdentity: `0x${"0".repeat(64)}` }, { targetIdentity: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
    { targetIdentity: hash("C") }, { account: bindings.cronos.target }, { account: bindings.cronos.account.toLowerCase() },
    { account: "0x0000000000000000000000000000000000000000" }, { target: "0x000000000000000000000000000000000000dEaD" },
    { extra: true }]) {
    assert.throws(() => ledgerBinding({ ...bindings.cronos, ...patch }), failure);
  }
  const account = bindings.xitcoin.account;
  for (const patch of [{ chainId: "xitcoin" }, { target: "bridge" }, { targetIdentity: "main" },
    { account: `${account.slice(0, -1)}${account.endsWith("q") ? "p" : "q"}` }, { account: account.toUpperCase() },
    { account: evmAddressToBech32(signers[2], "cosmos") }, { account: signers[2] }]) {
    assert.throws(() => ledgerBinding({ ...bindings.xitcoin, ...patch }), failure);
  }
  for (const input of [null, [], {}, Object.create(null), new Proxy({ ...bindings.cronos }, {})]) {
    assert.throws(() => ledgerBinding(input), failure);
  }
  let touched = false;
  assert.throws(() => ledgerBinding({ ...bindings.cronos, get account() { touched = true; return signers[2]; } }), failure);
  assert.equal(touched, false);
});

test("reopening requires the identical binding, schema, triggers and version", () => fixture(async (path) => {
  open(path, "cronos").close();
  for (const patch of [{ target: signers[0] }, { targetIdentity: hash("e") }, { account: signers[1] }]) {
    assert.throws(() => new BroadcastLedger(path, { ...bindings.cronos, ...patch }, journalOptions("cronos")), failure);
  }
  assert.throws(() => new BroadcastLedger(path, bindings.xitcoin, journalOptions("xitcoin")), failure);
  assert.throws(() => new BroadcastLedger(path, bindings.cronos, journalOptions("xitcoin")), failure);
  const ledger = open(path, "cronos");
  assert.throws(() => ledger.assertBinding({ ...bindings.cronos, targetIdentity: hash("e") }), failure);
  ledger.assertBinding(bindings.cronos);
  ledger.close();
  for (const sql of ["DROP TRIGGER transfers_no_delete", "PRAGMA user_version = 1", "PRAGMA user_version = 2", "PRAGMA user_version = 4",
    "DROP TRIGGER transfers_reopen", "DROP TRIGGER superseded_no_delete", "DROP TABLE superseded_attempts",
    "CREATE INDEX unexpected ON transfers(state)", "DROP TABLE transfer_events",
    "CREATE TABLE extra (id INTEGER) STRICT"]) {
    await fixture((copy) => {
      open(copy, "cronos").close();
      const raw = new DatabaseSync(copy);
      try { raw.exec(sql); } finally { raw.close(); }
      assert.throws(() => open(copy, "cronos"), failure);
    });
  }
}));

test("schema triggers reject raw deletion, regression, replacement and nonce reuse", () => fixture((path) => {
  const ledger = open(path, "cronos");
  const lease = ledger.acquireLease(owner(1));
  ledger.claim(lease, claimOf(hash("1")));
  ledger.recordSigned(lease, signed(hash("1"), 5));
  ledger.markBroadcast(lease, hash("1"), { maxAttempts: 3 });
  ledger.close();
  const raw = new DatabaseSync(path);
  try {
    for (const sql of ["DELETE FROM transfers", "DELETE FROM transfer_events", "UPDATE transfer_events SET code = 'x'",
      "DELETE FROM account_nonce", "UPDATE account_nonce SET next_nonce = 5", "UPDATE account_nonce SET next_nonce = 9",
      "UPDATE transfers SET state = 'signed'", "UPDATE transfers SET state = 'claimed'",
      `UPDATE transfers SET signed_hex = '${bytes("other")}'`, `UPDATE transfers SET transaction_hash = '${hash("e")}'`,
      "UPDATE transfers SET nonce = 6", `UPDATE transfers SET approval_digest = '${hash("e")}'`,
      "UPDATE transfers SET broadcast_attempts = 0", "UPDATE transfers SET broadcast_attempts = 3",
      "UPDATE transfers SET claim_epoch = 2", "DELETE FROM worker_lease", "UPDATE worker_lease SET epoch = 3",
      `UPDATE worker_lease SET owner = '${owner(9)}'`, "UPDATE ledger_binding SET binding = '{}'", "DELETE FROM ledger_binding",
      `UPDATE transfers SET source_ref = '${hash("9")}'`, "UPDATE transfers SET state = 'rejected', reason_code = 'x'",
      "UPDATE transfers SET state = 'unclaimed'", "UPDATE transfers SET state = 'expired', block_number = NULL, block_hash = NULL",
      `INSERT INTO transfers (transfer_id, approval_digest, request_hash, state, claim_epoch, nonce, signed_hex, transaction_digest,
        transaction_hash, broadcast_attempts, created_at, updated_at) VALUES ('${hash("2")}', '${hash("b")}', '${hash("d")}',
        'signed', 1, 6, '0x00', '${hash("3")}', '${hash("4")}', 0, 0, 0)`]) {
      assert.throws(() => raw.exec(sql), Error, sql);
    }
    assert.throws(() => raw.exec(`INSERT INTO transfers (transfer_id, source_ref, approval_digest, request_hash, state, claim_epoch,
      nonce, signed_hex, transaction_digest, transaction_hash, broadcast_attempts, release_hash, block_number, block_hash, created_at, updated_at)
      VALUES ('${hash("6")}', '${hash("6")}', '${hash("b")}', '${hash("d")}', 'released_elsewhere', 1, 9, '0x00', '${hash("7")}',
      '${hash("8")}', 0, '${hash("9")}', 1, '${hash("f")}', 0, 0)`), Error);
    raw.exec(`UPDATE transfers SET state = 'finalized', block_number = 1, block_hash = '${hash("f")}'`);
    for (const sql of ["UPDATE transfers SET state = 'halted', reason_code = 'x', block_number = NULL, block_hash = NULL",
      `UPDATE transfers SET block_hash = '${hash("e")}'`]) assert.throws(() => raw.exec(sql), Error, sql);
  } finally { raw.close(); }
}));

test("inputs never coerce and malformed state is not reported as found", () => fixture((path) => {
  const ledger = open(path, "cronos");
  const lease = ledger.acquireLease(owner(1));
  for (const input of [null, {}, [], { ...claimOf(hash("1")), extra: 1 }, { ...claimOf(hash("1")), transferId: hash("A") },
    { ...claimOf(hash("1")), transferId: `0x${"0".repeat(64)}` }, { ...claimOf(hash("1")), requestHash: "0x01" }]) {
    assert.throws(() => ledger.claim(lease, input), failure);
  }
  ledger.claim(lease, claimOf(hash("1")));
  for (const patch of [{ nonce: -1 }, { nonce: 1.5 }, { nonce: "1" }, { nonce: 2 ** 53 }, { signedHex: "0x" },
    { signedHex: "0xABCD" }, { signedHex: "0xabc" }, { signedHex: `0x${"00".repeat(32_768)}` }, { transactionHash: "0x00" }]) {
    assert.throws(() => ledger.recordSigned(lease, { ...signed(hash("1"), 1), ...patch }), failure);
  }
  for (const maxAttempts of [0, LEDGER_MAX_BROADCAST_ATTEMPTS + 1, "1", undefined]) {
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts }), failure);
  }
  for (const code of ["", "Upper", "x".repeat(65), "with space", 1]) {
    assert.throws(() => ledger.halt(lease, { ...claimOf(hash("1")), code }), failure);
  }
  assert.throws(() => ledger.inspect("0x01"), failure);
  ledger.close();
  const raw = new DatabaseSync(path);
  try { raw.exec(`UPDATE transfers SET request_hash = '0x${"A".repeat(64)}'`); }
  finally { raw.close(); }
  const reopened = open(path, "cronos");
  assert.throws(() => reopened.inspect(hash("1")), failure);
  assert.throws(() => reopened.active(), failure);
  reopened.close();
}));

test("stored bytes are rehashed on every read", () => fixture((path) => {
  const ledger = open(path, "cronos");
  const lease = ledger.acquireLease(owner(1));
  ledger.claim(lease, claimOf(hash("1")));
  ledger.recordSigned(lease, signed(hash("1"), 1));
  ledger.close();
  const raw = new DatabaseSync(path);
  try {
    // Simulate local tampering that restores the exact schema afterwards.
    const triggers = raw.prepare("SELECT name, sql FROM sqlite_schema WHERE name IN ('transfers_immutable', 'transfers_progress')").all();
    raw.exec(`${triggers.map(({ name }) => `DROP TRIGGER ${name};`).join(" ")}
      UPDATE transfers SET signed_hex = '${bytes("tampered")}'; ${triggers.map(({ sql }) => `${sql};`).join(" ")}`);
  } finally { raw.close(); }
  const reopened = open(path, "cronos");
  assert.throws(() => reopened.inspect(hash("1")), failure);
  assert.throws(() => reopened.active(), failure);
  reopened.close();
}));

test("ledger filesystem rejects symlinks, shared parents and foreign identities", () => fixture((path, directory) => {
  const target = join(directory, "real.sqlite");
  open(target, "cronos").close();
  symlinkSync(target, join(directory, "link.sqlite"));
  assert.throws(() => open(join(directory, "link.sqlite"), "cronos"), failure);
  const shared = join(directory, "shared");
  mkdirSync(shared); chmodSync(shared, 0o750);
  assert.throws(() => open(join(shared, "ledger.sqlite"), "cronos"), failure);
  assert.throws(() => new BroadcastLedger(path, bindings.cronos, { ...journalOptions("cronos"),
    identity: () => ({ username: "xitcoin-bridge-submitter-cronos", uid: process.geteuid() + 1 }) }), failure);
  assert.throws(() => new BroadcastLedger(path, bindings.cronos, journalOptions("xitcoin")), failure);
  assert.throws(() => new BroadcastLedger("relative.sqlite", bindings.cronos, journalOptions("cronos")), failure);
}));

// A version 1 (or 2) ledger as an earlier release created it: exact DDL,
// binding, rows in every state that can exist (and, in version 1, the
// 32-attempt cap in a CHECK).
function versionOneLedger(path, destination, populate, { version = 1 } = {}) {
  closeSync(openSync(path, "wx", 0o600));
  const raw = new DatabaseSync(path);
  try {
    raw.exec("BEGIN IMMEDIATE");
    raw.exec(version === 1 ? LEDGER_SCHEMA_V1 : LEDGER_SCHEMA_V2);
    raw.exec(`PRAGMA user_version = ${version}`);
    raw.prepare("INSERT INTO ledger_binding VALUES (1, ?)").run(ledgerBinding(bindings[destination]));
    populate?.(raw);
    raw.exec("COMMIT");
  } finally { raw.close(); }
}
const insert = (raw, values) => raw.prepare(`INSERT INTO transfers (transfer_id, source_ref, approval_digest, request_hash, state,
  claim_epoch, broadcast_attempts, reason_code, release_hash, block_number, block_hash, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, 10, 10)`).run(...values);

test("a version 1 ledger is migrated forward once, keeping every row and rule; attempts are no longer capped at 32", () => fixture((path) => {
  assert.equal(LEDGER_SCHEMA_VERSION, 3);
  versionOneLedger(path, "xitcoin", (raw) => {
    raw.prepare("INSERT INTO worker_lease VALUES (1, ?, 3, 0)").run(owner(1));
    raw.prepare("INSERT INTO account_nonce VALUES (1, 8)").run();
    insert(raw, [hash("1"), hash("1"), hash("b"), hash("d"), "claimed", null, null, null, null]);
    raw.exec(`UPDATE transfers SET state = 'signed', nonce = 7, signed_hex = '${bytes("1")}', transaction_digest = '${sha256(bytes("1"))}',
      transaction_hash = '${keccak256(bytes("1"))}' WHERE transfer_id = '${hash("1")}'`);
    for (let attempt = 0; attempt < 32; attempt++) {
      raw.exec(`UPDATE transfers SET state = 'broadcast', broadcast_attempts = broadcast_attempts + 1 WHERE transfer_id = '${hash("1")}'`);
    }
    // The cap the migration lifts: a 33rd attempt is impossible in version 1.
    assert.throws(() => raw.exec(`UPDATE transfers SET broadcast_attempts = 33 WHERE transfer_id = '${hash("1")}'`));
    insert(raw, [hash("2"), hash("2"), hash("b"), hash("d"), "rejected", "invalid_recipient", null, null, null]);
    insert(raw, [hash("3"), hash("3"), hash("b"), hash("d"), "released_elsewhere", null, hash("e"), 4, hash("f")]);
    insert(raw, [hash("4"), hash("4"), hash("b"), hash("d"), "halted", "stale", null, null, null]);
    raw.exec(`INSERT INTO transfer_events (transfer_id, state, code, epoch, at) VALUES ('${hash("1")}', 'signed', 'signed', 3, 5)`);
    raw.exec(`INSERT INTO deferrals VALUES ('${hash("5")}', '${hash("5")}', 'waiting', 99, 2)`);
  });
  const before = new DatabaseSync(path);
  const rows = (db) => ({ transfers: db.prepare("SELECT * FROM transfers ORDER BY transfer_id").all(),
    events: db.prepare("SELECT * FROM transfer_events ORDER BY seq").all(), deferrals: db.prepare("SELECT * FROM deferrals").all(),
    nonce: db.prepare("SELECT * FROM account_nonce").all(), lease: db.prepare("SELECT * FROM worker_lease").all(),
    binding: db.prepare("SELECT * FROM ledger_binding").all() });
  const original = JSON.stringify(rows(before));
  before.close();
  // A ledger bound to another deployment is never migrated.
  assert.throws(() => open(path, "cronos"), failure);
  assert.throws(() => new BroadcastLedger(path, { ...bindings.xitcoin, targetIdentity: "a".repeat(40) }, journalOptions("xitcoin")), failure);
  let ledger = open(path, "xitcoin");
  ledger.close();
  const after = new DatabaseSync(path);
  try {
    assert.equal(after.prepare("PRAGMA user_version").get().user_version, 3);
    assert.equal(JSON.stringify(rows(after)), original); // every row unchanged
    assert.equal(after.prepare("SELECT count(*) AS n FROM superseded_attempts").get().n, 0);
  } finally { after.close(); }
  ledger = open(path, "xitcoin"); // reopening a migrated ledger is idempotent
  try {
    const row = ledger.inspect(hash("1"));
    assert.deepEqual([row.state, row.broadcastAttempts, row.nonce], ["broadcast", 32, 7]);
    assert.equal(ledger.blocking().length, 1); // the halted row still blocks
    const lease = ledger.acquireLease(owner(1));
    // A capped destination still stops at its cap; an uncapped one keeps recording sends.
    assert.throws(() => ledger.markBroadcast(lease, hash("1"), { maxAttempts: LEDGER_MAX_BROADCAST_ATTEMPTS }), failure);
    for (let attempt = 33; attempt <= 40; attempt++) {
      assert.equal(ledger.markBroadcast(lease, hash("1"), { maxAttempts: null }).broadcastAttempts, attempt);
    }
  } finally { ledger.close(); }
  // The migrated schema keeps every trigger of version 2 (and 3).
  const raw = new DatabaseSync(path);
  try {
    for (const sql of ["DELETE FROM transfers", "UPDATE transfers SET broadcast_attempts = 0", "UPDATE transfers SET broadcast_attempts = 50",
      "UPDATE transfers SET state = 'signed'", `UPDATE transfers SET signed_hex = '${bytes("x")}' WHERE transfer_id = '${hash("1")}'`,
      "UPDATE transfers SET broadcast_attempts = -1"]) {
      assert.throws(() => raw.exec(sql), Error, sql);
    }
  } finally { raw.close(); }
}));

test("only the exact version 1 schema is migrated; anything else is refused unchanged", async () => {
  for (const sql of ["DROP TRIGGER transfers_no_delete", "CREATE INDEX unexpected ON transfers(state)", "DROP TABLE deferrals",
    "PRAGMA user_version = 0"]) {
    await fixture((path) => {
      versionOneLedger(path, "cronos", (raw) => raw.exec(sql));
      assert.throws(() => open(path, "cronos"), failure, sql);
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        assert.ok([0, 1].includes(raw.prepare("PRAGMA user_version").get().user_version));
        assert.ok(raw.prepare("SELECT sql FROM sqlite_schema WHERE name = 'transfers'").get().sql.includes("BETWEEN 0 AND 32"));
      } finally { raw.close(); }
    });
  }
});

test("uncapped destinations record every send; stalled unfinished rows are counted for attention", () => fixture((path) => {
  const ledger = open(path, "xitcoin");
  const lease = ledger.acquireLease(owner(1));
  ledger.claim(lease, claimOf(hash("1")));
  ledger.recordSigned(lease, signed(hash("1"), 0));
  for (let attempt = 1; attempt <= 40; attempt++) {
    assert.equal(ledger.markBroadcast(lease, hash("1"), { maxAttempts: null }).broadcastAttempts, attempt);
  }
  assert.ok(Number.isSafeInteger(ledger.inspect(hash("1")).updatedAt));
  const now = Date.now();
  assert.deepEqual({ ...ledger.attention() }, { rejected: 0, expired: 0, releaseUnverified: 0, reverted: 0 });
  assert.equal(ledger.attention({ nowMs: now, stalledAfterSeconds: 3_600 }).stalled, 0);
  assert.equal(ledger.attention({ nowMs: now + 3_601_000, stalledAfterSeconds: 3_600 }).stalled, 1);
  for (const options of [{ nowMs: now, stalledAfterSeconds: 0 }, { stalledAfterSeconds: 60 }, { nowMs: -1, stalledAfterSeconds: 60 }]) {
    assert.throws(() => ledger.attention(options), failure);
  }
  ledger.finalize(lease, hash("1"), { blockNumber: 3, blockHash: hash("f") });
  assert.equal(ledger.attention({ nowMs: now + 3_601_000, stalledAfterSeconds: 3_600 }).stalled, 0);
  ledger.close();
}));

// An expired row as the engine leaves it: our bytes mined after the approval
// deadline and reverted.
function expiredRow(ledger, lease, transferId, nonce, approval = "b") {
  ledger.claim(lease, claimOf(transferId, approval));
  ledger.recordSigned(lease, signed(transferId, nonce));
  ledger.markBroadcast(lease, transferId, { maxAttempts: null });
  return ledger.markExpired(lease, transferId, { blockNumber: 9, blockHash: hash("9") });
}

test("a version 2 ledger is migrated forward to version 3 without touching a row; an expired row may then reopen", () => fixture((path) => {
  versionOneLedger(path, "cronos", (raw) => {
    raw.prepare("INSERT INTO worker_lease VALUES (1, ?, 2, 0)").run(owner(1));
    raw.prepare("INSERT INTO account_nonce VALUES (1, 8)").run();
    insert(raw, [hash("1"), hash("1"), hash("b"), hash("d"), "claimed", null, null, null, null]);
    raw.exec(`UPDATE transfers SET state = 'signed', nonce = 7, signed_hex = '${bytes("1")}', transaction_digest = '${sha256(bytes("1"))}',
      transaction_hash = '${keccak256(bytes("1"))}' WHERE transfer_id = '${hash("1")}'`);
    for (let attempt = 0; attempt < 40; attempt++) {
      raw.exec(`UPDATE transfers SET state = 'broadcast', broadcast_attempts = broadcast_attempts + 1 WHERE transfer_id = '${hash("1")}'`);
    }
    raw.exec(`UPDATE transfers SET state = 'expired', block_number = 9, block_hash = '${hash("9")}' WHERE transfer_id = '${hash("1")}'`);
    // Version 2 never lets an expired row change.
    assert.throws(() => raw.exec(`UPDATE transfers SET state = 'unclaimed' WHERE transfer_id = '${hash("1")}'`));
    insert(raw, [hash("2"), hash("2"), hash("b"), hash("d"), "rejected", "invalid_recipient", null, null, null]);
  }, { version: 2 });
  const snapshot = (db) => JSON.stringify(db.prepare("SELECT * FROM transfers ORDER BY transfer_id").all());
  const before = new DatabaseSync(path);
  const original = snapshot(before);
  before.close();
  assert.throws(() => new BroadcastLedger(path, { ...bindings.cronos, targetIdentity: hash("e") }, journalOptions("cronos")), failure);
  let ledger = open(path, "cronos");
  ledger.close();
  const after = new DatabaseSync(path);
  try {
    assert.equal(after.prepare("PRAGMA user_version").get().user_version, 3);
    assert.equal(snapshot(after), original);
  } finally { after.close(); }
  ledger = open(path, "cronos");
  try {
    const lease = ledger.acquireLease(owner(1));
    assert.equal(ledger.attention().expired, 1);
    const reopened = ledger.reopenExpired(lease, claimOf(hash("1"), "e"));
    assert.deepEqual([reopened.state, reopened.nonce, reopened.signedHex, reopened.broadcastAttempts, reopened.approvalDigest],
      ["unclaimed", null, null, 0, hash("e")]);
    assert.equal(ledger.attention().expired, 0);
    assert.deepEqual(ledger.superseded(hash("1")).map((row) => [row.nonce, row.transactionHash, row.approvalDigest, row.supersededBy]),
      [[7, keccak256(bytes("1")), hash("b"), hash("e")]]);
    // A rejected row never reopens.
    assert.throws(() => ledger.reopenExpired(lease, claimOf(hash("2"), "e")), failure);
  } finally { ledger.close(); }
}));

test("only an expired row reopens, only under a new approval, and archived bytes, nonces and hashes are never used again", () => fixture((path) => {
  const ledger = open(path, "xitcoin");
  const lease = ledger.acquireLease(owner(1));
  ledger.claim(lease, claimOf(hash("1")));
  ledger.recordSigned(lease, signed(hash("1"), 0));
  ledger.markBroadcast(lease, hash("1"), { maxAttempts: null });
  // Unfinished, finalized, failed, reverted or released rows never reopen.
  assert.throws(() => ledger.reopenExpired(lease, claimOf(hash("1"), "e")), failure);
  ledger.markExpired(lease, hash("1"), { blockNumber: 9, blockHash: hash("9") });
  // The same approval digest cannot reopen it, nor can a stale lease.
  assert.throws(() => ledger.reopenExpired(lease, claimOf(hash("1"), "b")), failure);
  assert.throws(() => ledger.reopenExpired({ ...lease, epoch: lease.epoch + 1 }, claimOf(hash("1"), "e")), failure);
  assert.throws(() => ledger.reopenExpired(lease, { ...claimOf(hash("1"), "e"), sourceRef: hash("2") }), failure);
  const reopened = ledger.reopenExpired(lease, claimOf(hash("1"), "e"));
  assert.equal(reopened.state, "unclaimed");
  assert.equal(ledger.reopenExpired(lease, claimOf(hash("1"), "e")).state, "unclaimed"); // idempotent
  assert.throws(() => ledger.reopenExpired(lease, claimOf(hash("1"), "f")), failure);
  // The new attempt follows every rule of a new claim and takes the next nonce.
  assert.equal(ledger.claim(lease, claimOf(hash("1"), "e")).state, "claimed");
  assert.throws(() => ledger.recordSigned(lease, signed(hash("1"), 0, "second")), failure);
  const second = ledger.recordSigned(lease, signed(hash("1"), 1, "second"));
  assert.deepEqual([second.nonce, second.approvalDigest], [1, hash("e")]);
  ledger.markBroadcast(lease, hash("1"), { maxAttempts: null });
  ledger.finalize(lease, hash("1"), { blockNumber: 12, blockHash: hash("c") });
  assert.throws(() => ledger.reopenExpired(lease, claimOf(hash("1"), "f")), failure);
  const events = ledger.superseded(hash("1"));
  assert.equal(events.length, 1);
  ledger.close();

  const raw = new DatabaseSync(path);
  try {
    // The archive is append-only and only ever copies an expired row exactly.
    for (const sql of ["DELETE FROM superseded_attempts", "UPDATE superseded_attempts SET superseded_by = '" + hash("a") + "'",
      `INSERT INTO superseded_attempts (transfer_id, source_ref, approval_digest, request_hash, claim_epoch, nonce, signed_hex,
        transaction_digest, transaction_hash, broadcast_attempts, block_number, block_hash, superseded_by, superseded_at)
        VALUES ('${hash("3")}', '${hash("3")}', '${hash("b")}', '${hash("d")}', 1, 5, '${bytes("3")}', '${sha256(bytes("3"))}',
        '${keccak256(bytes("3"))}', 1, 1, '${hash("9")}', '${hash("e")}', 1)`,
      // A finalized row can never be turned back into a new attempt, even raw.
      `UPDATE transfers SET state = 'unclaimed', approval_digest = '${hash("f")}', nonce = NULL, signed_hex = NULL, transaction_digest = NULL,
        transaction_hash = NULL, broadcast_attempts = 0, block_number = NULL, block_hash = NULL WHERE transfer_id = '${hash("1")}'`]) {
      assert.throws(() => raw.exec(sql), Error, sql);
    }
  } finally { raw.close(); }
}));

test("a raw reopen without the exact archived attempt, or reusing an archived nonce, is refused by the schema", () => fixture((path) => {
  let ledger = open(path, "cronos");
  const lease = ledger.acquireLease(owner(1));
  expiredRow(ledger, lease, hash("1"), 4);
  ledger.close();
  const raw = new DatabaseSync(path);
  const reset = (digest) => `UPDATE transfers SET state = 'unclaimed', approval_digest = '${digest}', nonce = NULL, signed_hex = NULL,
    transaction_digest = NULL, transaction_hash = NULL, broadcast_attempts = 0, block_number = NULL, block_hash = NULL
    WHERE transfer_id = '${hash("1")}'`;
  try {
    assert.throws(() => raw.exec(reset(hash("e"))), /reopen/); // nothing archived
    raw.exec(`INSERT INTO superseded_attempts (transfer_id, source_ref, approval_digest, request_hash, claim_epoch, nonce, signed_hex,
      transaction_digest, transaction_hash, broadcast_attempts, block_number, block_hash, superseded_by, superseded_at)
      SELECT transfer_id, source_ref, approval_digest, request_hash, claim_epoch, nonce, signed_hex, transaction_digest, transaction_hash,
        broadcast_attempts, block_number, block_hash, '${hash("e")}', 1 FROM transfers WHERE transfer_id = '${hash("1")}'`);
    assert.throws(() => raw.exec(reset(hash("f"))), /reopen/); // archived for another approval
    assert.throws(() => raw.exec(reset(hash("b"))), /reopen|superseded/); // same approval
    assert.throws(() => raw.exec(`UPDATE transfers SET state = 'unclaimed', approval_digest = '${hash("e")}', broadcast_attempts = 0,
      block_number = NULL, block_hash = NULL WHERE transfer_id = '${hash("1")}'`)); // bytes kept
    raw.exec(reset(hash("e")));
    raw.exec(`UPDATE transfers SET state = 'claimed' WHERE transfer_id = '${hash("1")}'`);
    // Neither the archived nonce nor its bytes or hash can be recorded again.
    assert.throws(() => raw.exec(`UPDATE transfers SET state = 'signed', nonce = 4, signed_hex = '${bytes("other")}',
      transaction_digest = '${sha256(bytes("other"))}', transaction_hash = '${keccak256(bytes("other"))}' WHERE transfer_id = '${hash("1")}'`), /superseded/);
    assert.throws(() => raw.exec(`UPDATE transfers SET state = 'signed', nonce = 5, signed_hex = '${bytes(hash("1"))}',
      transaction_digest = '${sha256(bytes(hash("1")))}', transaction_hash = '${keccak256(bytes(hash("1")))}' WHERE transfer_id = '${hash("1")}'`), /superseded/);
  } finally { raw.close(); }
  ledger = open(path, "cronos");
  ledger.close();
}));

test("stalled counts the current attempt and a cleared deferral lets a re-issued approval proceed at once", () => fixture((path) => {
  const ledger = open(path, "xitcoin");
  const lease = ledger.acquireLease(owner(1));
  expiredRow(ledger, lease, hash("1"), 0);
  const now = Date.now();
  ledger.reopenExpired(lease, claimOf(hash("1"), "e"));
  ledger.claim(lease, claimOf(hash("1"), "e"));
  ledger.recordSigned(lease, signed(hash("1"), 1, "second"));
  assert.equal(ledger.attention({ nowMs: now, stalledAfterSeconds: 60 }).stalled, 0);
  assert.equal(ledger.attention({ nowMs: now + 61_000, stalledAfterSeconds: 60 }).stalled, 1);
  ledger.defer(lease, { transferId: hash("2"), sourceRef: hash("2"), code: "approval_expired_awaiting_reissue" }, { nowMs: now });
  assert.ok(ledger.scheduling(hash("2")).deferredUntilMs > now);
  assert.throws(() => ledger.clearDeferral(lease, { transferId: hash("3"), sourceRef: hash("2") }), failure);
  assert.equal(ledger.clearDeferral(lease, { transferId: hash("2"), sourceRef: hash("2") }).cleared, true);
  assert.equal(ledger.scheduling(hash("2")).deferredUntilMs, null);
  assert.equal(ledger.clearDeferral(lease, { transferId: hash("2"), sourceRef: hash("2") }).cleared, false);
  ledger.close();
}));
