import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BroadcastLedger } from "../src/broadcast-ledger.js";
import { runDurableSubmissionCycle, SubmissionHalt, SubmissionUnavailable } from "../src/durable-broadcast.js";
import { evmAddressToBech32 } from "../src/address.js";
import { keccak256 } from "ethers";
import { journalOptions } from "./journal-fixture.js";
import { signers } from "./fixtures/destination.js";
import { ModelChain, modelAdapter, approvedTransfer, openStore } from "./fixtures/durable-adapter.js";

const bindings = {
  cronos: { destination: "cronos", chainId: "338", routeId: "cronos-testnet-xitcoin-testnet",
    target: "0x1c94273C0b199b139D82da3786C9eCbE189D5919", targetIdentity: `0x${"c".repeat(64)}`, account: signers[2] },
  xitcoin: { destination: "xitcoin", chainId: "xitcoin-testnet-v2-1", routeId: "cronos-testnet-xitcoin-testnet",
    target: "x/bridge", targetIdentity: "5ec8692e8fc1813d0892ee535af1a73953a1c4fb", account: evmAddressToBech32(signers[2]) },
};
const NOW = 1_900_000_000_000;
const owner = (n) => n.toString(16).padStart(32, "0");
class Crash extends Error {}
const BOUNDARIES = ["claimed", "signed", "relay-submitted", "broadcast-recorded", "sent", "ledger-finalized", "relay-completed"];

// A "process" is a fresh pair of durable connections; the chain model survives restarts.
function harness(destination, run) {
  const directory = mkdtempSync(join(tmpdir(), "durable-engine-"));
  const paths = { store: join(directory, "relay.sqlite"), ledger: join(directory, "ledger.sqlite") };
  const chain = new ModelChain();
  const open = [];
  let current;
  const processHandle = () => {
    const ledger = new BroadcastLedger(paths.ledger, bindings[destination], journalOptions(destination));
    const store = openStore(paths.store);
    open.push(ledger, store);
    current = ledger;
    return { ledger, store };
  };
  const adapterOptions = { ledger: () => current };
  const cycle = async ({ worker = 1, nowMs = NOW, crashAt, adapter, fresh = true, handle } = {}) => {
    const { ledger, store } = handle ?? (fresh ? processHandle() : processHandle());
    return runDurableSubmissionCycle({ store, ledger, owner: owner(worker), nowMs,
      adapter: adapter ?? modelAdapter(destination, chain, adapterOptions),
      boundary: async (name) => { if (name === crashAt) throw new Crash(name); } });
  };
  const setup = processHandle();
  return Promise.resolve().then(() => run({ chain, cycle, setup, paths, processHandle, adapterOptions }))
    .finally(() => { for (const item of open) try { item.close(); } catch {} rmSync(directory, { recursive: true, force: true }); });
}

async function until(cycle, chain, predicate, limit = 12) {
  for (let i = 0; i < limit; i++) {
    const result = await cycle({ nowMs: NOW + i * 60_000 });
    chain.mine(); chain.confirm(1);
    if (predicate(result)) return result;
  }
  throw new Error("cycle did not converge");
}

for (const destination of ["cronos", "xitcoin"]) {
  test(`${destination}: approved transfer is signed, persisted, sent once and completed only after finality`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
    const first = await cycle();
    assert.equal(first.action, "submitted");
    const relay = setup.store.get(sourceChain, sourceRef);
    assert.equal(relay.state, "submitted"); assert.equal(relay.destination_ref, first.transactionHash);
    assert.equal(chain.deliveries.length, 1);
    chain.mine();
    assert.equal((await cycle()).action, "pending"); // included, finality depth not reached
    assert.equal(setup.store.get(sourceChain, sourceRef).state, "submitted");
    chain.confirm(2);
    const final = await cycle();
    assert.equal(final.action, "finalized"); assert.equal(final.transactionHash, first.transactionHash);
    assert.equal(setup.store.get(sourceChain, sourceRef).state, "completed");
    assert.equal(setup.store.get(sourceChain, sourceRef).release_ref, first.transactionHash);
    assert.equal(setup.ledger.inspect(final.transferId).state, "finalized");
    assert.equal((await cycle()).action, "idle");
    assert.equal(chain.distinctDeliveries(), 1); assert.equal(chain.deliveries.length, 1);
  }));

  for (const crashAt of BOUNDARIES) {
    test(`${destination}: crash at ${crashAt} recovers without a second transaction`, () => harness(destination, async ({ chain, cycle, setup }) => {
      const { sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
      let crashed = false;
      for (let i = 0; i < 8 && !crashed; i++) {
        try { await cycle({ crashAt }); } catch (error) { if (!(error instanceof Crash)) throw error; crashed = true; }
        chain.mine(); chain.confirm(1);
      }
      assert.ok(crashed);
      await until(cycle, chain, (value) => ["finalized", "idle"].includes(value.action));
      const relay = setup.store.get(sourceChain, sourceRef);
      assert.equal(relay.state, "completed");
      assert.equal(chain.distinctDeliveries(), 1);
      assert.equal(relay.destination_ref, chain.deliveries[0]);
      assert.equal(setup.ledger.blocking().length, 0); assert.equal(setup.ledger.active().length, 0);
      if (crashAt !== "broadcast-recorded") assert.equal(chain.deliveries.length, 1);
    }));
  }

  test(`${destination}: reorganization resends only the identical persisted bytes`, () => harness(destination, async ({ chain, cycle, setup }) => {
    approvedTransfer(setup.store, destination);
    const first = await cycle();
    chain.mine(); chain.confirm(1);
    assert.equal((await cycle()).action, "pending");
    chain.reorg(first.transactionHash);
    const resent = await cycle();
    assert.equal(resent.action, "rebroadcast"); assert.equal(resent.transactionHash, first.transactionHash);
    assert.equal(resent.attempts, 2);
    const final = await until(cycle, chain, (value) => value.action === "finalized");
    assert.equal(final.transactionHash, first.transactionHash);
    assert.equal(chain.distinctDeliveries(), 1); assert.equal(chain.deliveries.length, 2);
  }));

  test(`${destination}: ambiguous and lost sends are reconciled from chain state`, () => harness(destination, async ({ chain, cycle, setup }) => {
    approvedTransfer(setup.store, destination);
    chain.sendMode = "ambiguous";
    const first = await cycle();
    assert.equal(first.action, "submitted"); // accepted despite the timeout
    assert.equal((await cycle()).action, "pending");
    chain.sendMode = "lost";
    chain.mempool.clear();
    assert.equal((await cycle()).action, "rebroadcast");
    chain.sendMode = "deliver";
    assert.equal((await cycle()).action, "rebroadcast");
    await until(cycle, chain, (value) => value.action === "finalized");
    assert.equal(chain.distinctDeliveries(), 1);
    assert.equal(setup.ledger.inspect(first.transferId).broadcastAttempts, 3);
  }));

  test(`${destination}: repeated drops exhaust the bounded attempts and halt permanently`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
    chain.sendMode = "lost";
    await cycle();
    await cycle(); await cycle();
    await assert.rejects(cycle(), (error) => error instanceof SubmissionHalt && error.code === "broadcast_attempts_exhausted");
    await assert.rejects(cycle(), (error) => error.code === "ledger_requires_review");
    assert.equal(setup.store.get(sourceChain, sourceRef).state, "submitted");
    assert.equal(chain.deliveries.length, 0);
  }));

  test(`${destination}: finalized failed execution is terminal and blocks all later work`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
    approvedTransfer(setup.store, destination, 2);
    await cycle();
    chain.failNext = true; chain.mine();
    assert.equal((await cycle()).action, "pending");
    chain.confirm(2);
    await assert.rejects(cycle(), (error) => error instanceof SubmissionHalt && error.code === "destination_execution_failed");
    await assert.rejects(cycle(), (error) => error.code === "ledger_requires_review");
    assert.equal(setup.store.get(sourceChain, sourceRef).state, "submitted");
    assert.equal(chain.distinctDeliveries(), 1);
  }));

  test(`${destination}: a nonce consumed elsewhere halts instead of signing replacement bytes`, () => harness(destination, async ({ chain, cycle, setup }) => {
    approvedTransfer(setup.store, destination);
    await assert.rejects(cycle({ crashAt: "signed" }), Crash);
    chain.foreignTransaction();
    await assert.rejects(cycle(), (error) => error.code === "nonce_consumed_before_send");
    assert.equal(chain.deliveries.length, 0);
    await assert.rejects(cycle(), (error) => error.code === "ledger_requires_review");
  }));

  test(`${destination}: an included transaction removed while its nonce advanced halts`, () => harness(destination, async ({ chain, cycle, setup }) => {
    approvedTransfer(setup.store, destination);
    const first = await cycle();
    chain.mine();
    chain.reorg(first.transactionHash); chain.foreignTransaction();
    await assert.rejects(cycle(), (error) => error.code === "nonce_consumed_without_receipt");
    assert.equal(chain.distinctDeliveries(), 1);
  }));

  test(`${destination}: a finalized release by another transaction before any claim completes the transfer and frees the queue`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request, sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
    const second = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(request);
    const releaseHash = chain.foreignRelease(transferId);
    const early = await cycle(); // not final yet: deferred, and the next transfer proceeds
    assert.equal(early.action, "submitted"); assert.notEqual(early.transferId, transferId);
    assert.equal(setup.ledger.inspect(transferId).found, false);
    await until(cycle, chain, () => setup.store.get(second.sourceChain, second.sourceRef).state === "completed");
    const later = await cycle({ nowMs: NOW + 3_600_000 });
    assert.equal(later.action, "released_elsewhere"); assert.equal(later.releaseHash, releaseHash);
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "released_elsewhere"); assert.equal(row.signedHex, null); assert.equal(row.releaseHash, releaseHash);
    assert.equal(setup.store.get(sourceChain, sourceRef).state, "completed");
    assert.equal(setup.store.get(sourceChain, sourceRef).destination_ref, null);
    assert.equal(setup.store.get(sourceChain, sourceRef).release_ref, releaseHash); // where a reconciler reads it
    assert.equal(setup.ledger.blocking().length, 0);
    assert.equal(chain.deliveries.filter((hash) => hash === releaseHash).length, 0);
  }));

  test(`${destination}: a front-run of our pending release is recorded as released elsewhere, not failed`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request, sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
    const next = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(request);
    const sent = await cycle();
    const releaseHash = chain.foreignRelease(transferId); // copied calldata, higher price, mined first
    chain.mine(); // our transaction reverts (already processed) and consumes its nonce
    assert.equal(chain.receipts.get(sent.transactionHash).status, 0);
    chain.confirm(3);
    const outcome = await cycle();
    assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, releaseHash);
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "released_elsewhere"); assert.equal(row.transactionHash, sent.transactionHash);
    const relay = setup.store.get(sourceChain, sourceRef);
    assert.equal(relay.state, "completed"); assert.equal(relay.destination_ref, sent.transactionHash);
    assert.equal(relay.release_ref, releaseHash); // the front-run, not our reverted transaction
    assert.equal(setup.ledger.blocking().length, 0);
    await until(cycle, chain, () => setup.store.get(next.sourceChain, next.sourceRef).state === "completed");
    assert.deepEqual([0, 1], [row.nonce, setup.ledger.inspect(modelAdapter(destination, chain).transferId(next.request)).nonce]);
  }));

  test(`${destination}: released elsewhere after signing still consumes our nonce with the identical bytes`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request } = approvedTransfer(setup.store, destination);
    const next = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(request);
    await assert.rejects(cycle({ crashAt: "signed" }), Crash);
    const releaseHash = chain.foreignRelease(transferId);
    const sent = await cycle(); // sends the persisted bytes once although they will revert
    assert.equal(sent.action, "submitted");
    chain.mine(); chain.confirm(3);
    assert.equal(chain.nonce, 1);
    assert.equal((await cycle()).action, "released_elsewhere");
    assert.equal(setup.ledger.inspect(transferId).releaseHash, releaseHash);
    await until(cycle, chain, () => setup.store.get(next.sourceChain, next.sourceRef).state === "completed");
    assert.equal(chain.distinctDeliveries(), 2);
  }));

  test(`${destination}: released elsewhere while our transaction was dropped resends identical bytes to consume the nonce`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request } = approvedTransfer(setup.store, destination);
    const transferId = modelAdapter(destination, chain).transferId(request);
    const sent = await cycle();
    chain.mempool.clear();
    chain.foreignRelease(transferId);
    chain.confirm(3);
    const resent = await cycle();
    assert.equal(resent.action, "rebroadcast"); assert.equal(resent.transactionHash, sent.transactionHash);
    chain.mine(); chain.confirm(3);
    assert.equal((await cycle()).action, "released_elsewhere");
    assert.equal(setup.ledger.blocking().length, 0);
    assert.equal(chain.distinctDeliveries(), 1);
  }));


  test(`${destination}: an expired approval on a claimed row releases the claim without a nonce and the queue moves on`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const first = approvedTransfer(setup.store, destination, 1, { deadlineUnix: 1_900_000_100 });
    setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
    approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(first.request);
    await assert.rejects(cycle({ crashAt: "claimed" }), Crash);
    assert.equal(setup.ledger.inspect(transferId).state, "claimed");
    const later = NOW + 200_000; // downtime beyond the approval deadline
    const released = await cycle({ nowMs: later });
    assert.equal(released.action, "waiting"); assert.equal(released.unclaimed, true);
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "unclaimed"); assert.equal(row.nonce, null); assert.equal(row.signedHex, null);
    assert.equal(setup.ledger.nextNonce(), null);
    const next = await cycle({ nowMs: later + 1_000 });
    assert.equal(next.action, "submitted"); assert.notEqual(next.transferId, transferId);
    assert.equal(setup.ledger.inspect(next.transferId).nonce, 0);
    assert.equal(setup.store.get(first.sourceChain, first.sourceRef).state, "approved"); // kept, deferred, retried later
    assert.equal(chain.deliveries.length, 1);
  }));

  test(`${destination}: a signed row whose approval expired sends its bytes once and records a non-blocking expiry`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const first = approvedTransfer(setup.store, destination, 1, { deadlineUnix: 1_900_000_100 });
    setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
    const second = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(first.request);
    await assert.rejects(cycle({ crashAt: "signed" }), Crash);
    chain.time = 1_900_000_500;
    const sent = await cycle({ nowMs: 1_900_000_500_000 });
    assert.equal(sent.action, "submitted"); // the stored bytes, once, so their nonce is consumed
    chain.mine(); chain.confirm(3);
    const expired = await cycle({ nowMs: 1_900_000_501_000 });
    assert.equal(expired.action, "expired"); assert.equal(expired.transactionHash, sent.transactionHash);
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "expired"); assert.equal(row.nonce, 0);
    assert.equal(setup.ledger.blocking().length, 0);
    const relay = setup.store.get(first.sourceChain, first.sourceRef);
    assert.equal(relay.state, "submitted"); assert.equal(relay.destination_ref, sent.transactionHash); assert.equal(relay.release_ref, null);
    const reports = [];
    for (let i = 0; i < 12 && setup.store.get(second.sourceChain, second.sourceRef).state !== "completed"; i++) {
      reports.push(await cycle({ nowMs: 1_900_000_502_000 + i * 1_000 }));
      chain.mine(); chain.confirm(1);
    }
    assert.equal(setup.store.get(second.sourceChain, second.sourceRef).state, "completed");
    assert.equal(setup.ledger.inspect(modelAdapter(destination, chain).transferId(second.request)).nonce, 1);
    assert.ok(reports.every((report) => report.attention.expired === 1));
  }));

  test(`${destination}: a processed transfer without verifiable release evidence is a persistent non-blocking alert`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const bad = approvedTransfer(setup.store, destination, 1);
    setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
    const good = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(bad.request);
    chain.unverified.add(transferId);
    const first = await cycle();
    assert.equal(first.action, "submitted"); assert.notEqual(first.transferId, transferId);
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "release_unverified"); assert.equal(row.signedHex, null);
    assert.equal(setup.store.get(bad.sourceChain, bad.sourceRef).state, "approved"); // never a completion
    assert.equal(setup.ledger.blocking().length, 0);
    const reports = [];
    for (let i = 0; i < 12 && setup.store.get(good.sourceChain, good.sourceRef).state !== "completed"; i++) {
      reports.push(await cycle({ nowMs: NOW + (i + 1) * 1_000 }));
      chain.mine(); chain.confirm(1);
    }
    reports.push(await cycle({ nowMs: NOW + 60_000 }));
    assert.ok(reports.length > 1 && reports.every((report) => report.attention.releaseUnverified === 1));
    assert.equal(reports.at(-1).action, "idle");
  }));

  test(`${destination}: an unsendable transfer is rejected alone and never blocks the queue`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const bad = approvedTransfer(setup.store, destination);
    const good = approvedTransfer(setup.store, destination, 2);
    const transferId = modelAdapter(destination, chain).transferId(bad.request);
    chain.invalid.add(transferId);
    const result = await cycle();
    assert.equal(result.action, "submitted");
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "rejected"); assert.equal(row.reasonCode, "invalid_recipient"); assert.equal(row.signedHex, null);
    assert.equal(setup.ledger.blocking().length, 0);
    assert.equal(setup.store.get(bad.sourceChain, bad.sourceRef).state, "approved"); // kept for the operator
    await until(cycle, chain, () => setup.store.get(good.sourceChain, good.sourceRef).state === "completed");
    assert.equal((await cycle()).action, "idle");
  }));

  test(`${destination}: paused routes, expired approvals and RPC failures wait without claiming`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request } = approvedTransfer(setup.store, destination, 1, { deadlineUnix: 1_900_000_030 });
    approvedTransfer(setup.store, destination, 2);
    chain.paused = true;
    const paused = await cycle();
    assert.equal(paused.action, "waiting"); assert.deepEqual(paused.waiting, ["route_paused"]); // route-wide: stop scanning
    chain.paused = false;
    chain.rpcFailure = true;
    await assert.rejects(cycle(), /rpc_disagreement/);
    chain.rpcFailure = false;
    const transferId = modelAdapter(destination, chain).transferId(request);
    const next = await cycle();
    assert.equal(next.action, "submitted"); assert.notEqual(next.transferId, transferId);
    assert.equal(setup.ledger.inspect(transferId).found, false);
    assert.equal(chain.deliveries.length, 1);
  }));

  test(`${destination}: pause during flight waits and resumes without new bytes`, () => harness(destination, async ({ chain, cycle, setup }) => {
    approvedTransfer(setup.store, destination);
    await assert.rejects(cycle({ crashAt: "relay-submitted" }), Crash);
    chain.paused = true;
    assert.equal((await cycle()).code, "route_paused");
    chain.paused = false;
    await until(cycle, chain, (value) => value.action === "finalized");
    assert.equal(chain.deliveries.length, 1);
  }));

  test(`${destination}: stored request, reference and custody tampering halt`, async () => {
    for (const tamper of ["request", "approval", "reference", "orphan"]) {
      await harness(destination, async ({ chain, cycle, setup }) => {
        const { sourceChain, sourceRef } = approvedTransfer(setup.store, destination);
        if (tamper === "orphan") {
          setup.store.transition(sourceChain, sourceRef, "submitted", { destinationRef: `0x${"7".repeat(64)}` });
          await assert.rejects(cycle(), (error) => error.code === "submitted_without_ledger_custody");
          return;
        }
        await cycle();
        const sql = { request: "UPDATE transfers SET approval_request = json_set(approval_request, '$.payload.amount', '11')",
          approval: "UPDATE approvals SET signature = '0x00' WHERE signer = (SELECT signer FROM approvals LIMIT 1)",
          reference: "UPDATE transfers SET destination_ref = '0x" + "8".repeat(64) + "'" }[tamper];
        setup.store.database.exec(sql);
        await assert.rejects(cycle(), (error) => error instanceof SubmissionHalt);
        assert.equal(chain.distinctDeliveries(), 1);
      });
    }
  });

  test(`${destination}: concurrent workers hold one lease and produce one transaction`, () => harness(destination, async ({ chain, cycle, setup, processHandle }) => {
    approvedTransfer(setup.store, destination);
    const results = await Promise.allSettled([1, 2, 3].map((worker) => cycle({ worker, handle: processHandle() })));
    assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
    assert.equal(chain.deliveries.length, 1);
    // A different worker can continue only after the lease expires (fencing epoch 2).
    await assert.rejects(cycle({ worker: 2, nowMs: NOW + 1_000 }));
    chain.mine(); chain.confirm(3);
    const final = await cycle({ worker: 2, nowMs: NOW + 120_000 });
    assert.equal(final.action, "finalized"); assert.equal(final.epoch, 2);
    assert.equal(chain.distinctDeliveries(), 1);
  }));

  test(`${destination}: sequential transfers use sequential nonces, one at a time`, () => harness(destination, async ({ chain, cycle, setup }) => {
    for (const index of [1, 2, 3]) approvedTransfer(setup.store, destination, index);
    const finals = [];
    for (let i = 0; i < 30 && finals.length < 3; i++) {
      const result = await cycle({ nowMs: NOW + i * 60_000 });
      if (result.action === "finalized") finals.push(result);
      chain.mine(); chain.confirm(1);
    }
    assert.equal(finals.length, 3);
    assert.deepEqual(finals.map((item) => setup.ledger.inspect(item.transferId).nonce), [0, 1, 2]);
    assert.equal(chain.distinctDeliveries(), 3);
  }));
}

test("malformed adapter decisions and dependencies fail closed without ledger writes", () => harness("cronos", async ({ chain, cycle, setup, adapterOptions }) => {
  approvedTransfer(setup.store, "cronos");
  const base = modelAdapter("cronos", chain, adapterOptions);
  for (const patch of [{ assess: async () => ({ action: "send" }) }, { assess: async () => null },
    { assess: async () => Object.create({ action: "sign" }) }, { transferId: () => "0x01" },
    { sign: async () => ({ action: "signed", nonce: 0, signedHex: "0xzz", transactionHash: "0x01" }) }]) {
    await assert.rejects(cycle({ adapter: { ...base, ...patch } }));
  }
  for (const patch of [{ destination: "xitcoin" }, { maxBroadcastAttempts: 0 }, { maxBroadcastAttempts: 33 }]) {
    await assert.rejects(cycle({ adapter: { ...base, ...patch } }), SubmissionUnavailable);
  }
  assert.equal(chain.deliveries.length, 0);
  const row = setup.ledger.active()[0];
  assert.ok(!row || row.signedHex === null);
}));

test("a backlog of more than 256 older approved transfers never hides the unfinished one", () => harness("cronos", async ({ chain, cycle, setup }) => {
  for (let index = 1; index <= 300; index++) approvedTransfer(setup.store, "cronos", index);
  setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
  const first = await cycle();
  assert.equal(first.action, "submitted");
  chain.mine(); chain.confirm(3);
  const final = await cycle({ nowMs: NOW + 1_000 });
  assert.equal(final.action, "finalized"); assert.equal(final.transferId, first.transferId);
  assert.equal((await cycle({ nowMs: NOW + 2_000 })).action, "submitted");
}));

test("transfers that cannot proceed yet are deferred durably and never starve later transfers", () => harness("cronos", async ({ chain, cycle, setup, processHandle }) => {
  for (let index = 1; index <= 12; index++) approvedTransfer(setup.store, "cronos", index, { deadlineUnix: 1_800_000_000 });
  setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
  const valid = approvedTransfer(setup.store, "cronos", 13);
  const firstCycle = await cycle();
  assert.equal(firstCycle.action, "waiting"); assert.equal(firstCycle.waiting.length, 8); // bounded assessments per cycle
  const secondCycle = await cycle({ nowMs: NOW + 1_000 }); // a new process: deferrals are durable
  assert.equal(secondCycle.action, "submitted");
  assert.equal(setup.store.get(valid.sourceChain, valid.sourceRef).state, "submitted");
  const deferred = processHandle().ledger.deferrals();
  assert.equal(deferred.length, 12);
  assert.ok(deferred.every((item) => item.code === "approval_expired_awaiting_reissue" && item.untilMs >= NOW + 60_000));
  // Deferred transfers are kept and retried after their backoff, with a longer backoff each time.
  chain.mine(); chain.confirm(3);
  assert.equal((await cycle({ nowMs: NOW + 2_000 })).action, "finalized");
  const retry = await cycle({ nowMs: NOW + 3_600_000 });
  assert.equal(retry.action, "waiting");
  assert.ok(processHandle().ledger.deferrals().some((item) => item.count === 2));
  assert.equal(chain.deliveries.length, 1);
}));

test("RelayStore waits a bounded interval for a concurrent writer instead of failing at once", async () => {
  const { spawn } = await import("node:child_process");
  const { isRelayStoreBusy, RelayStore } = await import("../src/store.js");
  const directory = mkdtempSync(join(tmpdir(), "relay-busy-"));
  try {
    const path = join(directory, "relay.sqlite");
    new RelayStore(path).close();
    const holder = (ms) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", `import { DatabaseSync } from "node:sqlite";
        const db = new DatabaseSync(${JSON.stringify(path)}); db.exec("BEGIN IMMEDIATE");
        process.stdout.write("locked"); setTimeout(() => { db.exec("COMMIT"); db.close(); }, ${ms});`], { stdio: ["ignore", "pipe", "inherit"] });
      child.stdout.once("data", () => resolve(child)); child.on("error", reject);
    });
    const finished = (child) => new Promise((resolve) => child.once("exit", resolve));
    let child = await holder(300);
    const store = new RelayStore(path, { busyTimeoutMs: 5_000 });
    const started = Date.now();
    store.advanceCheckpoint("xitcoin", 1, `0x${"aa".repeat(32)}`); // waits for the coordinator's commit
    assert.ok(Date.now() - started >= 100);
    await finished(child);
    child = await holder(3_000);
    const impatient = new RelayStore(path, { busyTimeoutMs: 200 });
    assert.throws(() => impatient.advanceCheckpoint("xitcoin", 2, `0x${"bb".repeat(32)}`), (error) => isRelayStoreBusy(error));
    await finished(child);
    assert.equal(isRelayStoreBusy(new Error("database is locked")), false);
    for (const value of [-1, 60_001, 1.5, "1000"]) assert.throws(() => new RelayStore(path, { busyTimeoutMs: value }));
    store.close(); impatient.close();
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("every submitted RelayStore row is reconciled, even behind more than 64 parked rows", () => harness("cronos", async ({ cycle, setup }) => {
  const lease = setup.ledger.acquireLease(owner(9), { nowMs: NOW - 120_000, ttlMs: 60_000 });
  let last;
  for (let index = 1; index <= 70; index++) {
    const { sourceChain, sourceRef, request } = approvedTransfer(setup.store, "cronos", index);
    const transferId = request.payload.sourceBurnId;
    setup.ledger.claim(lease, { transferId, sourceRef, approvalDigest: request.digest, requestHash: `0x${"d".repeat(64)}` });
    const signedHex = `0x${Buffer.from(`parked transfer ${index}`).toString("hex")}`;
    setup.ledger.recordSigned(lease, { transferId, nonce: index - 1, signedHex, transactionHash: keccak256(signedHex) });
    setup.ledger.markBroadcast(lease, transferId, { maxAttempts: 3 });
    const inclusion = { blockNumber: index, blockHash: `0x${index.toString(16).padStart(64, "0")}` };
    // 69 expired rows stay `submitted`; the newest finalized one crashed before RelayStore completion.
    if (index < 70) setup.ledger.markExpired(lease, transferId, inclusion); else setup.ledger.finalize(lease, transferId, inclusion);
    setup.store.transition(sourceChain, sourceRef, "submitted", { destinationRef: keccak256(signedHex) });
    last = { sourceChain, sourceRef };
  }
  setup.store.database.exec(`UPDATE transfers SET updated_at = updated_at - 100 WHERE source_ref <> '${last.sourceRef}'`);
  const result = await cycle();
  assert.equal(result.action, "finalized");
  assert.equal(setup.store.get(last.sourceChain, last.sourceRef).state, "completed");
  assert.equal(result.attention.expired, 69);
}));

for (const destination of ["cronos", "xitcoin"]) {
  test(`${destination}: a pre-deadline revert for a lasting reason is recorded as reverted and never blocks the queue`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const first = approvedTransfer(setup.store, destination, 1);
    setup.store.database.exec("UPDATE transfers SET updated_at = updated_at - 100");
    const second = approvedTransfer(setup.store, destination, 2);
    const sent = await cycle();
    chain.failNext = true; chain.lastingCause = "daily_release_limit_exhausted"; chain.mine(); chain.confirm(3);
    const reverted = await cycle();
    assert.equal(reverted.action, "reverted"); assert.equal(reverted.code, "daily_release_limit_exhausted");
    const row = setup.ledger.inspect(sent.transferId);
    assert.equal(row.state, "reverted"); assert.equal(row.reasonCode, "daily_release_limit_exhausted");
    assert.equal(setup.ledger.blocking().length, 0);
    assert.equal(setup.store.get(first.sourceChain, first.sourceRef).state, "submitted");
    await until(cycle, chain, () => setup.store.get(second.sourceChain, second.sourceRef).state === "completed");
  }));
}
