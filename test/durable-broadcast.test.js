import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BroadcastLedger } from "../src/broadcast-ledger.js";
import { runDurableSubmissionCycle, SubmissionHalt, SubmissionUnavailable } from "../src/durable-broadcast.js";
import { evmAddressToBech32 } from "../src/address.js";
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

  test(`${destination}: replay processed without a local transaction halts before any claim`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request } = approvedTransfer(setup.store, destination);
    const transferId = modelAdapter(destination, chain).transferId(request);
    chain.processed.set(transferId, `0x${"9".repeat(64)}`);
    await assert.rejects(cycle(), (error) => error.code === "processed_without_local_transaction");
    const row = setup.ledger.inspect(transferId);
    assert.equal(row.state, "halted"); assert.equal(row.signedHex, null);
    assert.equal(chain.deliveries.length, 0);
  }));

  test(`${destination}: paused routes, expired approvals and RPC failures wait without claiming`, () => harness(destination, async ({ chain, cycle, setup }) => {
    const { request } = approvedTransfer(setup.store, destination, 1, { deadlineUnix: 1_900_000_030 });
    approvedTransfer(setup.store, destination, 2);
    chain.paused = true;
    const paused = await cycle();
    assert.equal(paused.action, "waiting"); assert.deepEqual(paused.waiting, ["route_paused", "route_paused"]);
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
