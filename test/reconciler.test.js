import test from "node:test";
import assert from "node:assert/strict";

import { Reconciler, XITCOIN_OUTSTANDING_QUERY, decodeOutstandingAmount, inFlightFromStore, reconcile } from "../src/reconciler.js";
import { RelayStore } from "../src/store.js";

function source(readings) {
  let index = 0;
  return {
    async vaultLocked() { return { amount: readings[Math.min(index, readings.length - 1)].locked, height: 100 + index }; },
    async chainOutstanding() { return { amount: readings[Math.min(index, readings.length - 1)].outstanding, height: 200 + index }; },
    async inFlight() { const reading = readings[Math.min(index++, readings.length - 1)]; return { lockedNotMinted: reading.pendingIn ?? 0n, burnedNotReleased: reading.pendingOut ?? 0n }; },
  };
}

test("reconcile classifies deficit, surplus and balanced accounting", () => {
  assert.equal(reconcile({ vaultLocked: 100n, chainOutstanding: 70n, lockedNotMinted: 20n, burnedNotReleased: 10n }).status, "ok");
  assert.equal(reconcile({ vaultLocked: 99n, chainOutstanding: 70n, lockedNotMinted: 20n, burnedNotReleased: 10n }).status, "deficit");
  assert.equal(reconcile({ vaultLocked: 101n, chainOutstanding: 70n, lockedNotMinted: 20n, burnedNotReleased: 10n }).status, "surplus");
  assert.equal(reconcile({ vaultLocked: "99", chainOutstanding: "100", lockedNotMinted: "0", burnedNotReleased: "0", tolerance: 1n }).status, "ok");
  assert.throws(() => reconcile({ vaultLocked: "-1", chainOutstanding: 0n, lockedNotMinted: 0n, burnedNotReleased: 0n }), /non-negative/);
});

test("dry-run mode alerts and records a pause request without calling any pause hook", async () => {
  const alerts = [];
  const reconciler = new Reconciler({ source: source([{ locked: 90n, outstanding: 100n }]), alert: async (event) => { alerts.push(event); }, confirmations: 2 });
  assert.equal((await reconciler.runOnce({ nowUnix: 1 })).status, "deficit");
  assert.deepEqual(alerts.map((event) => event.kind), ["reconciliation_deficit"]);
  await reconciler.runOnce({ nowUnix: 2 });
  await reconciler.runOnce({ nowUnix: 3 });
  assert.deepEqual(alerts.map((event) => event.kind), ["reconciliation_deficit", "reconciliation_deficit", "pause_request_dry_run", "reconciliation_deficit"]);
});

test("request-pause mode hands one structured request to the injected hook after consecutive deficits", async () => {
  const requests = [];
  const alerts = [];
  const reconciler = new Reconciler({
    source: source([{ locked: 90n, outstanding: 100n }, { locked: 100n, outstanding: 100n }, { locked: 90n, outstanding: 100n }, { locked: 90n, outstanding: 100n }]),
    alert: async (event) => { alerts.push(event.kind); }, requestPause: async (request) => { requests.push(request); },
    mode: "request_pause", confirmations: 2,
  });
  await reconciler.runOnce();
  await reconciler.runOnce(); // balanced: resets the counter
  await reconciler.runOnce();
  assert.equal(requests.length, 0);
  await reconciler.runOnce();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].action, "guardian_pause");
  assert.equal(requests[0].report.difference, "-10");
  assert.ok(alerts.includes("pause_requested"));
  assert.throws(() => new Reconciler({ source: source([]), alert: async () => {}, mode: "request_pause" }), /hook/);
  assert.throws(() => new Reconciler({ source: source([]), alert: async () => {}, mode: "pause_now" }), /mode/);
});

test("surplus and unreadable chains alert without requesting a pause", async () => {
  const alerts = [];
  const reconciler = new Reconciler({ source: source([{ locked: 150n, outstanding: 100n }]), alert: async (event) => { alerts.push(event.kind); }, confirmations: 1 });
  assert.equal((await reconciler.runOnce()).status, "surplus");
  const broken = new Reconciler({ source: { ...source([]), async vaultLocked() { throw new Error("RPC down"); } }, alert: async (event) => { alerts.push(event.kind); }, confirmations: 1 });
  assert.equal((await broken.runOnce()).kind, "reconciliation_unavailable");
  assert.deepEqual(alerts, ["reconciliation_surplus", "reconciliation_unavailable"]);
});

test("decodes the chain outstanding store value and sums in-flight transfers from the relay store", () => {
  assert.deepEqual(XITCOIN_OUTSTANDING_QUERY, { path: "/store/bridge/key", data: "0x07" });
  assert.equal(decodeOutstandingAmount(null), 0n);
  assert.equal(decodeOutstandingAmount(Buffer.from("033b2e3c9fd0803ce8000000", "hex").toString("base64")), 10n ** 27n);
  assert.throws(() => decodeOutstandingAmount(Buffer.alloc(33)), /256 bits/);
  const store = new RelayStore();
  const blockHash = `0x${"11".repeat(32)}`;
  store.observe({ sourceChain: "cronos", sourceRef: "aa".repeat(32), routeId: "r", blockHeight: 1, blockHash, payload: { amount: "7" } });
  store.observe({ sourceChain: "cronos", sourceRef: "bb".repeat(32), routeId: "r", blockHeight: 1, blockHash, payload: { amount: "5" } });
  store.transition("cronos", "bb".repeat(32), "failed", { error: "above chain limit" });
  store.observe({ sourceChain: "xitcoin", sourceRef: `0x${"cc".repeat(32)}`, routeId: "r", blockHeight: 1, blockHash, payload: { amount: "3" } });
  store.observe({ sourceChain: "cronos", sourceRef: "dd".repeat(32), routeId: "r", blockHeight: 1, blockHash, payload: { amount: "100" } });
  store.transition("cronos", "dd".repeat(32), "reorged");
  assert.deepEqual(inFlightFromStore(store), { lockedNotMinted: 7n, burnedNotReleased: 3n });
  store.close();
});

test("chain readers accept only the bounded quorum transports and the pinned vault code and route", async () => {
  const { createCronosVaultReader, createXitcoinBridgeReader, createChainReconciliationSource } = await import("../src/reconciler-sources.js");
  const { CronosRpcQuorum } = await import("../src/cronos-rpc.js");
  const { XitcoinRpcQuorum } = await import("../src/xitcoin-rpc.js");
  const rpc = new CronosRpcQuorum({ urls: ["http://127.0.0.1:1", "http://127.0.0.1:2"], allowLoopbackHttp: true });
  const vault = "0x00000000000000000000000000000000000000aa";
  const vaultCodeHash = `0x${"12".repeat(32)}`;
  assert.throws(() => createCronosVaultReader({ rpc: { call() {} }, vault, vaultCodeHash, confirmations: 2 }), /quorum/);
  for (const hash of [`0x${"0".repeat(64)}`, "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "0x12"]) {
    assert.throws(() => createCronosVaultReader({ rpc, vault, vaultCodeHash: hash, confirmations: 2 }), /code hash/);
  }
  for (const confirmations of [0, 10_001, 1.5]) assert.throws(() => createCronosVaultReader({ rpc, vault, vaultCodeHash, confirmations }), /confirmations/);
  const xitcoin = new XitcoinRpcQuorum({ allowLoopbackHttp: true, origins: [{ rpcUrl: "http://127.0.0.1:3", restUrl: "http://127.0.0.1:4" },
    { rpcUrl: "http://127.0.0.1:5", restUrl: "http://127.0.0.1:6" }] });
  assert.throws(() => createXitcoinBridgeReader({ rpc: { get() {} } }), /quorum/);
  assert.throws(() => createXitcoinBridgeReader({ rpc: xitcoin, routeId: "another-route" }), /route/);
  const readers = { cronos: createCronosVaultReader({ rpc, vault, vaultCodeHash, confirmations: 2 }), xitcoin: createXitcoinBridgeReader({ rpc: xitcoin }) };
  assert.throws(() => createChainReconciliationSource({ ...readers, store: {} }), /store/);
  // Closed loopback ports: every origin unavailable, never a deficit.
  const store = new RelayStore(":memory:");
  const alerts = [];
  const reconciler = new Reconciler({ source: createChainReconciliationSource({ ...readers, store }), alert: async (event) => { alerts.push(event); } });
  const event = await reconciler.runOnce({ nowUnix: 9 });
  assert.equal(event.kind, "reconciliation_unavailable");
  assert.match(event.reason, /^(cronos|xitcoin)_origin_unavailable$/);
  assert.equal(reconciler.consecutiveDeficits, 0);
  store.close();
});

test("read failures map to alert kinds and severities and never touch the deficit count", async () => {
  const { ReconciliationReadError } = await import("../src/reconciler-sources.js");
  const alerts = [];
  let failure = null;
  const readings = source([{ locked: 90n, outstanding: 100n }]);
  const reconciler = new Reconciler({ alert: async (event) => { alerts.push(event); }, confirmations: 3, source: {
    ...readings, async vaultLocked() { if (failure) throw failure; return readings.vaultLocked(); } } });
  await reconciler.runOnce({ nowUnix: 1 });
  for (const [kind, expected, severity] of [["unavailable", "reconciliation_unavailable", "warning"],
    ["disagreement", "reconciliation_disagreement", "critical"], ["identity_mismatch", "reconciliation_identity_mismatch", "critical"],
    ["invented", "reconciliation_unavailable", "warning"]]) {
    failure = new ReconciliationReadError(kind, "cronos_test_code");
    const event = await reconciler.runOnce({ nowUnix: 2 });
    assert.deepEqual([event.kind, event.severity, event.reason], [expected, severity, "cronos_test_code"]);
    assert.equal(reconciler.consecutiveDeficits, 1);
  }
  failure = new ReconciliationReadError("unavailable", "Not A Code");
  assert.equal((await reconciler.runOnce({ nowUnix: 3 })).reason, "read_failed");
  failure = null;
  await reconciler.runOnce({ nowUnix: 4 });
  assert.equal(reconciler.consecutiveDeficits, 2);
  assert.ok(!alerts.some((event) => event.kind === "pause_request_dry_run"));
});
