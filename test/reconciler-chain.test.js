// Reconciler chain readers against a local anvil chain (chain ID 338) with the
// vendored reviewed vault and a local xitcoind built from the pinned pos-chain
// commit, each behind two independent fault-injecting origins. Synthetic keys
// only; no public network is contacted.
import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { randomBytes } from "node:crypto";
import { Interface, computeAddress, keccak256 } from "ethers";

import { CronosRpcQuorum } from "../src/cronos-rpc.js";
import { buildApprovalRequest } from "../src/approvals.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { DIRECTION_INBOUND } from "../src/protocol.js";
import { Reconciler } from "../src/reconciler.js";
import { ReconciliationReadError, createChainReconciliationSource, createCronosVaultReader, createXitcoinBridgeReader }
  from "../src/reconciler-sources.js";
import { RelayStore } from "../src/store.js";
import { XitcoinRpcQuorum } from "../src/xitcoin-rpc.js";
import { assembleTxRaw, buildXitcoinSignDoc, cosmosSignature, encodeSubmitAttestation } from "../src/xitcoin-transaction.js";
import { keys, sign, signers } from "./fixtures/destination.js";
import { compile, deployBridge, evmAvailability, localAddress, localKeys, rewriteResult, signedCall, startAnvil, startProxy }
  from "./evm/harness.js";
import { CHAIN_ID, DEFAULT_ROUTE, ROUTE_ID, THIRD_PARTY_KEY, chainAccount, chainKey, rewriteJson, startXitcoinNode, startXitcoinOrigin,
  xitcoindAvailability } from "./xitcoin/harness.js";

const evm = evmAvailability();
const chain = xitcoindAvailability();
const CONFIRMATIONS = 2;
const LIQUIDITY = 5n * 10n ** 18n;
const TOKEN = new Interface(["function mint(address recipient,uint256 amount)", "function approve(address spender,uint256 amount)"]);
const VAULT = new Interface(["function deposit(uint256 amount,address recipient) returns (bytes32)"]);
const word = (value) => `0x${value.toString(16).padStart(64, "0")}`;

// ---- Xitcoin: one validator, two origins in front of it ----
let node, xitcoinOrigins = [], minted = 0n, mints = 0;
before(async () => {
  if (chain.skip) return;
  node = await startXitcoinNode({ binary: chain.binary, signers: [...signers], guardian: computeAddress(keys[3].publicKey) });
  xitcoinOrigins = [await startXitcoinOrigin(node), await startXitcoinOrigin(node)];
});
after(async () => {
  await Promise.all(xitcoinOrigins.map((origin) => origin.stop()));
  await node?.stop();
});

// Mints `amount` on the local chain with a 2-of-3 attestation for a synthetic
// deposit (the chain does not read Cronos), submitted by the funded third-party
// account. This is how outstanding_amount grows.
async function mint(amount) {
  mints += 1;
  const request = buildApprovalRequest({ direction: DIRECTION_INBOUND, payload: {
    destinationChainId: CHAIN_ID, routeId: ROUTE_ID, sourceChainId: "338", sourceRef: `0x${randomBytes(32).toString("hex")}`,
    nonce: String(mints), destination: chainAccount(chainKey(0x9_000 + mints)), amount: amount.toString(),
    deadlineUnix: Math.floor(Date.now() / 1000) + 3_600,
  } });
  const account = chainAccount(THIRD_PARTY_KEY);
  const state = (await node.rest(`/cosmos/auth/v1beta1/accounts/${account}`)).body.account;
  const p = request.payload;
  const messageBytes = encodeSubmitAttestation({ submitter: account, routeId: p.routeId, direction: request.direction,
    sourceChainId: p.sourceChainId, sourceRef: p.sourceRef, nonce: p.nonce, destination: p.destination, amount: p.amount,
    deadlineUnix: String(p.deadlineUnix), signatures: sign(request).map((approval) => approval.signature) });
  const doc = buildXitcoinSignDoc({ messageBytes, publicKey: THIRD_PARTY_KEY.compressedPublicKey, accountNumber: state.account_number,
    sequence: state.sequence, gasLimit: "400000", feeAmount: (400000n * 4_000_000_000n).toString(), chainId: CHAIN_ID });
  const raw = assembleTxRaw({ ...doc, signature: cosmosSignature(THIRD_PARTY_KEY.sign(doc.signingDigest).serialized, doc.signingDigest,
    THIRD_PARTY_KEY.compressedPublicKey) });
  assert.equal((await node.broadcast(raw.signedHex)).code, 0);
  assert.equal((await node.committed(raw.transactionHash)).tx_result.code, 0);
  minted += amount;
  await node.blocks(1);
}

function xitcoinReader() {
  return createXitcoinBridgeReader({ rpc: new XitcoinRpcQuorum({ allowLoopbackHttp: true,
    origins: xitcoinOrigins.map(({ rpcUrl, restUrl }) => ({ rpcUrl, restUrl })) }) });
}

function rewriteRest(origin, prefix, transform) {
  origin.hook = async ({ kind, path, forward }) => {
    const answer = await forward();
    if (kind !== "rest" || !path.startsWith(prefix)) return answer;
    return { status: answer.status, text: rewriteJson(answer.text, transform) };
  };
}

function dropRest(origin, prefix) {
  origin.hook = async ({ kind, path, forward }) => {
    if (kind === "rest" && path.startsWith(prefix)) throw new Error("dropped");
    return forward();
  };
}

async function rejection(promise, kind, code) {
  await assert.rejects(promise, (error) => error instanceof ReconciliationReadError && error.kind === kind && error.code === code);
}

test("the Xitcoin reader returns outstanding_amount and daily usage at one height every origin serves and agrees on", { skip: chain.skip, timeout: 180_000 }, async () => {
  xitcoinOrigins.forEach((origin) => { origin.hook = null; });
  await mint(3n * 10n ** 18n);
  const reading = await xitcoinReader().chainOutstanding();
  assert.equal(reading.amount, minted);
  assert.ok(Number.isSafeInteger(reading.height) && reading.height > 1);
  assert.match(reading.blockHash, /^0x[0-9a-f]{64}$/);
  assert.equal(reading.maxOutstandingAmount, DEFAULT_ROUTE.maxOutstandingAmount);
  assert.equal(reading.dailyUsage.dailyLimit, DEFAULT_ROUTE.dailyLimit);
  assert.equal(BigInt(reading.dailyUsage.usedAmount) + BigInt(reading.dailyUsage.remainingAmount), BigInt(DEFAULT_ROUTE.dailyLimit));
  // Every REST read was pinned to the height the reader reports.
  const pinned = xitcoinOrigins.flatMap((origin) => origin.calls).filter((call) => typeof call === "string"
    && (call.startsWith("/xitcoin/bridge/v1/outstanding") || call.startsWith("/xitcoin/bridge/v1/daily_usage")));
  assert.ok(pinned.length >= 4);
});

test("the Xitcoin reader refuses an unavailable origin and origins that disagree, never returning one origin's value", { skip: chain.skip, timeout: 180_000 }, async () => {
  const reader = xitcoinReader();
  dropRest(xitcoinOrigins[1], "/xitcoin/bridge/v1/outstanding");
  await rejection(reader.chainOutstanding(), "unavailable", "xitcoin_origin_unavailable");
  dropRest(xitcoinOrigins[0], "/xitcoin/bridge/v1/daily_usage");
  xitcoinOrigins[1].hook = null;
  await rejection(reader.chainOutstanding(), "unavailable", "xitcoin_origin_unavailable");
  xitcoinOrigins[0].hook = null;
  rewriteRest(xitcoinOrigins[1], "/xitcoin/bridge/v1/outstanding", (body) => ({ ...body, outstanding_amount: (minted + 1n).toString() }));
  await rejection(reader.chainOutstanding(), "disagreement", "xitcoin_outstanding_disagreement");
  rewriteRest(xitcoinOrigins[0], "/xitcoin/bridge/v1/daily_usage", (body) => ({ ...body, used_amount: "1", remaining_amount: "1" }));
  xitcoinOrigins[1].hook = null;
  await rejection(reader.chainOutstanding(), "disagreement", "xitcoin_daily_usage_disagreement");
  // A block that differs between origins at the pinned height is a disagreement too.
  xitcoinOrigins[0].hook = async ({ kind, method, forward }) => {
    const answer = await forward();
    if (kind !== "rpc" || method !== "block") return answer;
    return { status: answer.status, text: rewriteJson(answer.text, (body) => ({ ...body,
      result: { ...body.result, block_id: { ...body.result.block_id, hash: "AB".repeat(32) } } })) };
  };
  await rejection(reader.chainOutstanding(), "disagreement", "xitcoin_origin_disagreement");
  // A route that is not the pinned one, answered identically by every origin.
  for (const origin of xitcoinOrigins) rewriteRest(origin, "/xitcoin/bridge/v1/outstanding", (body) => ({ ...body, route_id: "another-route" }));
  await rejection(reader.chainOutstanding(), "identity_mismatch", "xitcoin_route_mismatch");
  xitcoinOrigins.forEach((origin) => { origin.hook = null; });
  assert.equal((await reader.chainOutstanding()).amount, minted);
});

// ---- Cronos: anvil with the reviewed vault, two origins in front of it ----
async function cronosChain() {
  const anvil = await startAnvil(evm.anvil);
  const artifacts = { vault: compile(evm.forge, "vault-testnet").CronosBridgeVault, token: compile(evm.forge, "token").MockERC20 };
  const bridge = await deployBridge(anvil, artifacts, { routeId: TESTNET_ROUTE_ID, signers, liquidity: LIQUIDITY });
  const proxies = [await startProxy(anvil.url), await startProxy(anvil.url)];
  const codeHash = keccak256(await anvil.rpc("eth_getCode", [bridge.vault, "latest"]));
  const send = async (to, data) => anvil.rpc("eth_sendRawTransaction", [await signedCall(anvil, localKeys.deployer, { to, data })]);
  // A real deposit() through the vault: the depositor's tokens become locked.
  async function deposit(amount) {
    await send(bridge.token, TOKEN.encodeFunctionData("mint", [localAddress(localKeys.deployer), amount]));
    await send(bridge.token, TOKEN.encodeFunctionData("approve", [bridge.vault, amount]));
    await send(bridge.vault, VAULT.encodeFunctionData("deposit", [amount, signers[0]]));
    await anvil.rpc("anvil_mine", [`0x${(CONFIRMATIONS + 1).toString(16)}`]);
  }
  const reader = (hash = codeHash) => createCronosVaultReader({ rpc: new CronosRpcQuorum({ urls: proxies.map((proxy) => proxy.url),
    allowLoopbackHttp: true }), vault: bridge.vault, vaultCodeHash: hash, confirmations: CONFIRMATIONS });
  await anvil.rpc("anvil_mine", [`0x${(CONFIRMATIONS + 1).toString(16)}`]);
  return { anvil, bridge, proxies, codeHash, deposit, reader,
    async stop() { await Promise.all(proxies.map((proxy) => proxy.stop())); await anvil.stop(); } };
}

test("the Cronos reader returns the vault's locked balance at the finalized height every origin agrees on", { skip: evm.skip, timeout: 240_000 }, async () => {
  const cronos = await cronosChain();
  try {
    const first = await cronos.reader().vaultLocked();
    assert.equal(first.amount, LIQUIDITY);
    const tip = Number(await cronos.anvil.rpc("eth_blockNumber"));
    assert.equal(first.height, tip - CONFIRMATIONS);
    await cronos.deposit(10n ** 18n);
    // A deposit inside the confirmation window is not counted yet.
    await cronos.anvil.rpc("anvil_mine", ["0x1"]);
    const second = await cronos.reader().vaultLocked();
    assert.equal(second.amount, LIQUIDITY + 10n ** 18n);
    assert.ok(second.height > first.height);
    for (const proxy of cronos.proxies) assert.ok(proxy.calls.includes("eth_call") && proxy.calls.includes("eth_getCode"));
  } finally { await cronos.stop(); }
});

test("the Cronos reader refuses an unavailable origin, disagreeing origins and a vault that is not the pinned code", { skip: evm.skip, timeout: 240_000 }, async () => {
  const cronos = await cronosChain();
  try {
    const reader = cronos.reader();
    cronos.proxies[1].hook = async ({ message, forward }) => {
      if (message.method === "eth_call") throw new Error("dropped");
      return forward();
    };
    await rejection(reader.vaultLocked(), "unavailable", "cronos_origin_unavailable");
    cronos.proxies[1].hook = async ({ message, forward }) => {
      const text = await forward();
      return message.method === "eth_call" ? rewriteResult(text, () => word(LIQUIDITY + 1n)) : text;
    };
    await rejection(reader.vaultLocked(), "disagreement", "cronos_origin_disagreement");
    cronos.proxies[1].hook = async ({ message, forward }) => {
      const text = await forward();
      return message.method === "eth_blockNumber" ? rewriteResult(text, () => "0x0") : text;
    };
    await rejection(reader.vaultLocked(), "unavailable", "cronos_history_too_short");
    cronos.proxies[1].hook = null;
    await rejection(cronos.reader(`0x${"12".repeat(32)}`).vaultLocked(), "identity_mismatch", "vault_code_mismatch");
    assert.equal((await reader.vaultLocked()).amount, LIQUIDITY);
  } finally { await cronos.stop(); }
});

// ---- Both chains: the reconciler in its default dry-run mode ----
test("the dry-run reconciler on both chains reports balance, surplus and deficit, and only alerts on origin faults", { skip: evm.skip || chain.skip, timeout: 300_000 }, async () => {
  xitcoinOrigins.forEach((origin) => { origin.hook = null; });
  const cronos = await cronosChain();
  const store = new RelayStore(":memory:");
  try {
    // Back the vault's initial liquidity with an equal mint, then check balance.
    await mint(LIQUIDITY - minted);
    assert.equal(minted, LIQUIDITY);
    const alerts = [];
    const reconciler = new Reconciler({ source: createChainReconciliationSource({ cronos: cronos.reader(), xitcoin: xitcoinReader(), store }),
      alert: async (event) => { alerts.push(event); }, confirmations: 2 });
    assert.equal(reconciler.mode, "dry_run");
    const balanced = await reconciler.runOnce({ nowUnix: 1 });
    assert.equal(balanced.status, "ok");
    assert.equal(balanced.vaultLocked, LIQUIDITY.toString());
    assert.equal(balanced.chainOutstanding, LIQUIDITY.toString());
    assert.equal(balanced.xitcoinDailyUsage.dailyLimit, DEFAULT_ROUTE.dailyLimit);
    assert.deepEqual(alerts, []);

    // A deposit the relayer has not observed is a surplus (warning only);
    // once it is in flight in the store, the books balance again.
    const deposited = 2n * 10n ** 18n;
    await cronos.deposit(deposited);
    const surplus = await reconciler.runOnce({ nowUnix: 2 });
    assert.equal(surplus.status, "surplus");
    assert.equal(surplus.difference, deposited.toString());
    assert.deepEqual(alerts.map((event) => [event.severity, event.kind]), [["warning", "reconciliation_surplus"]]);
    store.observe({ sourceChain: "cronos", sourceRef: `0x${"d1".repeat(32)}`, routeId: TESTNET_ROUTE_ID, blockHeight: 10,
      blockHash: `0x${"11".repeat(32)}`, transactionHash: `0x${"22".repeat(32)}`, logIndex: 0,
      payload: { depositId: `0x${"d1".repeat(32)}`, amount: deposited.toString() } });
    assert.equal((await reconciler.runOnce({ nowUnix: 3 })).status, "ok");

    // An unbacked mint is a deficit. Two in a row produce a dry-run pause
    // request alert; no pause hook exists and nothing is sent anywhere.
    const unbacked = 10n ** 17n;
    await mint(unbacked);
    alerts.length = 0;
    const deficit = await reconciler.runOnce({ nowUnix: 4 });
    assert.equal(deficit.status, "deficit");
    assert.equal(deficit.difference, (-unbacked).toString());

    // Origin faults alert without counting as a deficit or resetting the count.
    dropRest(xitcoinOrigins[0], "/xitcoin/bridge/v1/outstanding");
    const unavailable = await reconciler.runOnce({ nowUnix: 5 });
    assert.deepEqual([unavailable.severity, unavailable.kind, unavailable.reason], ["warning", "reconciliation_unavailable", "xitcoin_origin_unavailable"]);
    xitcoinOrigins[0].hook = null;
    cronos.proxies[0].hook = async ({ message, forward }) => {
      const text = await forward();
      return message.method === "eth_call" ? rewriteResult(text, () => word(1n)) : text;
    };
    const disagreement = await reconciler.runOnce({ nowUnix: 6 });
    assert.deepEqual([disagreement.severity, disagreement.kind, disagreement.reason], ["critical", "reconciliation_disagreement", "cronos_origin_disagreement"]);
    assert.equal(reconciler.consecutiveDeficits, 1);
    cronos.proxies[0].hook = null;

    assert.equal((await reconciler.runOnce({ nowUnix: 7 })).status, "deficit");
    assert.equal(reconciler.consecutiveDeficits, 2);
    assert.deepEqual(alerts.map((event) => event.kind), ["reconciliation_deficit", "reconciliation_unavailable",
      "reconciliation_disagreement", "reconciliation_deficit", "pause_request_dry_run"]);
    const request = alerts.at(-1).request;
    assert.equal(request.action, "guardian_pause");
    assert.equal(request.report.difference, (-unbacked).toString());
  } finally {
    xitcoinOrigins.forEach((origin) => { origin.hook = null; });
    store.close();
    await cronos.stop();
  }
});
