import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, symlinkSync, chmodSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { keccak256, sha256 } from "ethers";
import { BroadcastLedger, ledgerBinding, LEDGER_MAX_BROADCAST_ATTEMPTS } from "../src/broadcast-ledger.js";
import { evmAddressToBech32 } from "../src/address.js";
import { journalOptions } from "./journal-fixture.js";
import { signers } from "./fixtures/destination.js";

const failure = { message: "broadcast ledger unavailable or conflicting" };
const hash = (letter) => `0x${letter.repeat(64)}`;
const bindings = {
  cronos: { destination: "cronos", chainId: "338", routeId: "cronos-testnet-xitcoin-testnet",
    target: "0x1c94273C0b199b139D82da3786C9eCbE189D5919", targetIdentity: hash("c"), account: signers[2] },
  xitcoin: { destination: "xitcoin", chainId: "xitcoin-testnet-v2-1", routeId: "cronos-testnet-xitcoin-testnet",
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
  for (const sql of ["DROP TRIGGER transfers_no_delete", "PRAGMA user_version = 2",
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
