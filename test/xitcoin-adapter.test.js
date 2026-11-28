// Xitcoin adapter decisions against a deterministic model of independent
// origins (test/fixtures/xitcoin-model.js). The end-to-end behaviour on a real
// chain is covered by test/xitcoin-submitter-chain.test.js.
import assert from "node:assert/strict";
import test from "node:test";
import { computeAddress } from "ethers";
import { evmAddressToBech32 } from "../src/address.js";
import { buildTransferApprovalRequest } from "../src/coordinator.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { XITCOIN_TESTNET_ROUTE_ID, attestationId } from "../src/protocol.js";
import { validateXitcoinTestnetManifest } from "../src/submitter-manifest.js";
import { createXitcoinAdapter, isTemporaryStop, xitcoinLedgerBinding } from "../src/xitcoin-submitter.js";
import { XitcoinRpcQuorum } from "../src/xitcoin-rpc.js";
import { XITCOIN_CHAIN_SCHEMA_COMMIT } from "../src/xitcoin-transaction.js";
import { keys, sign, signers } from "./fixtures/destination.js";
import { SUBMITTER, SUBMITTER_KEY, recordFor, xitcoinModel } from "./fixtures/xitcoin-model.js";

const VAULT = "0x1c94273C0b199b139D82da3786C9eCbE189D5919";
const RECIPIENT = evmAddressToBech32(computeAddress(keys[3].publicKey));
const nowUnix = () => Math.floor(Date.now() / 1000);

function manifest(model, patch = {}) {
  return validateXitcoinTestnetManifest({ version: 1, mode: "testnet", destination: "xitcoin", releaseCommit: "a".repeat(40),
    routeId: XITCOIN_TESTNET_ROUTE_ID, cronosChainId: 338, xitcoinChainId: "xitcoin-testnet-v2-1",
    relayStorePath: "/var/lib/xitcoin-bridge/coordinator/relay.sqlite", ledgerPath: "/var/lib/xitcoin-bridge/submitter-xitcoin/ledger.sqlite",
    keystorePath: "/var/lib/xitcoin-bridge/submitter-xitcoin-keystore/keystore.json", cycleIntervalMs: 5_000,
    xitcoin: { origins: model.urls, allowLoopbackHttp: false, chainSchemaCommit: XITCOIN_CHAIN_SCHEMA_COMMIT, signerSetVersion: "1",
      authorizedSigners: [...signers], submitter: SUBMITTER, confirmations: 2, historyBlocks: 1_000, maxAmount: (10n ** 21n).toString(),
      maxGas: "600000", gasAdjustmentPercent: 130, gasHeadroom: 30_000, feeMultiplierPercent: 200, maxGasPrice: "100000000000",
      maxFee: "60000000000000000", minDeadlineMarginSeconds: 60, maxBroadcastAttempts: 3, ...patch },
    cronos: { rpcUrls: ["https://cronos-a.example", "https://cronos-b.example"], allowLoopbackHttp: false, vault: VAULT,
      cronosRouteId: TESTNET_ROUTE_ID, confirmations: 12 } });
}

function setup({ origins = 2, patch, recipient = RECIPIENT, deadlineUnix = nowUnix() + 3_600, verifySource = async () => {} } = {}) {
  const model = xitcoinModel({ origins });
  const config = manifest(model, patch);
  const rpc = new XitcoinRpcQuorum({ origins: model.urls, fetchImpl: model.fetchImpl, timeoutMs: 1_000 });
  const signer = { signerAddress: computeAddress(SUBMITTER_KEY.publicKey), compressedPublicKey: SUBMITTER_KEY.compressedPublicKey,
    signDigest: async (digest) => SUBMITTER_KEY.sign(digest).serialized };
  const adapter = createXitcoinAdapter({ manifest: config, rpc, signer, verifySource });
  const depositId = `0x${"ab".repeat(32)}`;
  const transfer = { source_chain: "cronos", source_ref: depositId.slice(2), route_id: TESTNET_ROUTE_ID, state: "approved", block_height: 40,
    block_hash: `0x${"cd".repeat(32)}`, transaction_hash: `0x${"ef".repeat(32)}`, event_index: 1,
    payload: JSON.stringify({ depositId, depositor: signers[0], recipient: computeAddress(keys[3].publicKey), destination: recipient,
      amount: "1000000000000000000", nonce: "7" }) };
  const request = JSON.parse(JSON.stringify(buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" },
    routeId: XITCOIN_TESTNET_ROUTE_ID, cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: VAULT,
    xitcoinChainId: "xitcoin-testnet-v2-1", deadlineUnix })));
  const approvals = sign(request);
  const transferId = attestationId({ ...request.payload, direction: request.direction });
  const stored = { transfer, request, approvals, transferId, nowUnix: nowUnix() };
  return { model, rpc, adapter, config, stored, transfer, request, approvals, transferId };
}

async function signed(context) {
  const assessed = await context.adapter.assess(context.stored);
  assert.equal(assessed.action, "sign", JSON.stringify(assessed));
  const result = await context.adapter.sign({ ...context.stored, context: assessed.context, expectedNonce: null });
  assert.equal(result.action, "signed");
  return { assessed, result, row: { transferId: context.transferId, sourceRef: context.transfer.source_ref, state: "broadcast",
    nonce: result.nonce, signedHex: result.signedHex, transactionHash: result.transactionHash, broadcastAttempts: 1 } };
}
const observe = (context, row) => context.adapter.observe({ ...context.stored, row });

test("assess, sign, first send and finality on the attestation record", async () => {
  const context = setup();
  const { assessed, result, row } = await signed(context);
  // Gas from simulation plus headroom; fee from the highest required price times the multiplier.
  assert.equal(assessed.context.gasLimit, String((180_000n * 130n + 99n) / 100n + 30_000n));
  assert.equal(assessed.context.feeAmount, String(BigInt(assessed.context.gasLimit) * 2_000_000_000n));
  assert.equal(result.nonce, 0);
  assert.deepEqual(await context.adapter.verifyStored({ ...context.stored, row }), { action: "valid" });
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: { ...row, state: "signed" } }), { action: "send" });
  await context.adapter.send({ row });
  assert.deepEqual(context.model.state.broadcasts, [row.signedHex, row.signedHex]); // identical bytes to every origin
  context.model.state.mempool = [row.signedHex];
  assert.deepEqual(await observe(context, row), { action: "pending" });
  context.model.state.mempool = [];
  assert.deepEqual(await observe(context, row), { action: "rebroadcast" });
  const hash = context.model.commit(row.signedHex, { accSeq: [`${SUBMITTER}/0`] });
  assert.equal(hash, row.transactionHash);
  context.model.state.account.sequence = 1;
  context.model.state.attestations.set(context.transferId, { status: "processed",
    record: recordFor(context.request, context.approvals, { txHash: hash, height: 100 }) });
  context.model.state.height = 101;
  assert.deepEqual(await observe(context, row), { action: "pending" }); // confirmations not reached
  context.model.state.height = 102;
  assert.deepEqual(await observe(context, row), { action: "finalized", blockNumber: 100, blockHash: context.model.blockHash(100) });
  assert.deepEqual(xitcoinLedgerBinding(context.config), { destination: "xitcoin", chainId: "xitcoin-testnet-v2-1",
    routeId: XITCOIN_TESTNET_ROUTE_ID, target: "x/bridge", targetIdentity: XITCOIN_CHAIN_SCHEMA_COMMIT, account: SUBMITTER });
});

test("a successful transaction whose record names another transaction or approval halts", async () => {
  for (const overrides of [{ tx_hash: "AB".repeat(32) }, { deadline_unix: "1" }, { signing_digest: `0x${"22".repeat(32)}` }]) {
    const context = setup();
    const { row } = await signed(context);
    context.model.commit(row.signedHex, { accSeq: [`${SUBMITTER}/0`] });
    context.model.state.account.sequence = 1;
    context.model.state.height = 105;
    context.model.state.attestations.set(context.transferId, { status: "processed",
      record: recordFor(context.request, context.approvals, { txHash: row.transactionHash, height: 100, overrides }) });
    assert.deepEqual(await observe(context, row), { action: "halt", code: "record_mismatch_after_success" });
  }
});

test("our sequence consumed without our transaction anywhere halts; a regression halts", async () => {
  const context = setup();
  const { row } = await signed(context);
  context.model.state.account.sequence = 1;
  assert.deepEqual(await observe(context, row), { action: "halt", code: "nonce_consumed_without_inclusion" });
  // Visible again (committed or gossiped meanwhile): pending, never a halt.
  context.model.state.mempool = [row.signedHex];
  assert.deepEqual(await observe(context, row), { action: "pending" });
  context.model.state.mempool = [];
  // The transaction index lags: our sequence was consumed in block 97 and that
  // block (consensus data) contains our transaction: pending, never a halt.
  context.model.state.account.sequenceAt = (height) => (height >= 97 ? 1 : 0);
  context.model.commit(row.signedHex, { height: 97, accSeq: [`${SUBMITTER}/0`] });
  const indexed = context.model.state.txs.get(row.transactionHash);
  context.model.state.txs.delete(row.transactionHash);
  context.model.faults[0] = context.model.faults[1] = ({ kind, method, params, body }) => (kind === "rpc" && method === "block" && params.height === "97"
    ? { ...body, result: { ...body.result, block: { ...body.result.block, data: { txs: [Buffer.from(indexed.txHex.slice(2), "hex").toString("base64")] } } } }
    : undefined);
  assert.deepEqual(await observe(context, row), { action: "pending" });
  // Block 97 holds another transaction: our sequence was used without ours.
  context.model.faults[0] = context.model.faults[1] = null;
  assert.deepEqual(await observe(context, row), { action: "halt", code: "nonce_consumed_without_inclusion" });
  // Consumed above the lowest origin height only: wait.
  context.model.state.account.sequenceAt = () => 0;
  assert.deepEqual(await observe(context, row), { action: "pending" });
  const regressed = setup();
  regressed.model.state.account.sequence = 2;
  const second = await signed(regressed);
  assert.equal(second.row.nonce, 2);
  regressed.model.state.account.sequence = 1;
  assert.deepEqual(await observe(regressed, second.row), { action: "halt", code: "account_sequence_regressed" });
  // Stored bytes that do not match the row are never observed or sent.
  await assert.rejects(observe(regressed, { ...second.row, nonce: 3 }), (error) => error.code === "stored_transaction_mismatch");
});

test("a failure in the ante handler leaves the sequence unused: identical bytes only, bounded attempts", async () => {
  const context = setup();
  const { row } = await signed(context);
  context.model.commit(row.signedHex, { code: 13, gasUsed: 20_000, accSeq: [] });
  context.model.state.height = 105;
  assert.deepEqual(await observe(context, row), { action: "rebroadcast" });
  assert.deepEqual(await observe(context, { ...row, broadcastAttempts: 3 }), { action: "halt", code: "broadcast_attempts_exhausted" });
  context.model.state.account.sequence = 1; // something else used our sequence
  assert.deepEqual(await observe(context, row), { action: "halt", code: "nonce_consumed_without_inclusion" });
});

test("failed executions are classified from state every origin agrees on at both heights", async () => {
  const committedFailure = async ({ gasUsed = 90_000, gasWanted = 300_000, configure = () => {}, deadlineUnix } = {}) => {
    const context = setup({ deadlineUnix });
    const { row } = await signed(context);
    context.model.commit(row.signedHex, { code: 1, gasUsed, gasWanted, accSeq: [`${SUBMITTER}/0`] });
    context.model.state.account.sequence = 1;
    context.model.state.height = 105;
    configure(context);
    return observe(context, row);
  };
  const inclusion = () => ({ blockNumber: 100 });
  let result = await committedFailure({ gasUsed: 300_000 });
  assert.equal(result.action, "failed"); // out of gas: a gas policy problem
  result = await committedFailure({ configure: (c) => { c.model.state.routeAt = (height) => ({ ...c.model.state.route, paused: height >= 99 }); } });
  assert.deepEqual([result.action, result.code], ["reverted", "route_paused"]);
  result = await committedFailure({ configure: (c) => { c.model.state.routeAt = (height) => ({ ...c.model.state.route, paused: height >= 100 }); } });
  assert.equal(result.action, "failed"); // paused by another transaction in the same block: not taken as the cause
  result = await committedFailure({ configure: (c) => { c.model.state.usage = { used: (10n ** 23n).toString() }; } });
  assert.deepEqual([result.action, result.code], ["reverted", "daily_limit_exhausted"]);
  result = await committedFailure({ configure: (c) => { c.model.state.routeAt = (height) => ({ ...c.model.state.route,
    bridge_signers: [signers[2], signers[1], computeAddress(keys[3].publicKey)] }); } });
  assert.deepEqual([result.action, result.code], ["reverted", "signer_set_rotated"]);
  result = await committedFailure({ configure: (c) => { c.model.state.blockTimes.set(100, c.request.deadlineUnix + 1); } });
  assert.equal(result.action, "expired");
  // Another transaction processed the attestation first: our failure consumed
  // our sequence and the transfer was released elsewhere.
  let foreign;
  result = await committedFailure({ configure: (c) => {
    foreign = c.model.commit("0x0a02aaaa", { height: 99 });
    c.model.state.attestations.set(c.transferId, { status: "processed", record: recordFor(c.request, c.approvals, { txHash: foreign, height: 99 }) });
  } });
  assert.deepEqual(result, { action: "released_elsewhere", releaseHash: foreign, blockNumber: 99, blockHash: xitcoinModel().blockHash(99) });
  // Recent history that one origin refuses is never a cause: a temporary stop.
  await assert.rejects(committedFailure({ configure: (c) => { c.model.faults[1] = ({ kind, height }) => (kind === "rest" && height === "99"
    ? { httpStatus: 400, body: { code: 3, message: "height is not available" } } : undefined); } }), (error) => isTemporaryStop(error));
  // Old history an origin explicitly no longer serves: a non-blocking alert.
  const old = await committedFailure({ configure: (c) => { c.model.state.height = 2_000;
    c.model.faults[1] = ({ kind, height }) => (kind === "rest" && height === "99" ? { httpStatus: 400, body: { code: 3 } } : undefined); } });
  assert.deepEqual(old, { action: "release_unverified", code: "failure_history_unserved", ...inclusion(), blockHash: old.blockHash });
  assert.equal(old.blockHash, xitcoinModel().blockHash(100));
});

test("a release by another transaction with every approved field completes; any mismatching record halts", async () => {
  const context = setup();
  const foreign = context.model.commit(`0x${"0a02".repeat(1)}${"aa".repeat(2)}`, { height: 90 });
  context.model.state.attestations.set(context.transferId, { status: "processed",
    record: recordFor(context.request, context.approvals, { txHash: foreign, height: 90, overrides: { deadline_unix: "1999999999" } }) });
  assert.deepEqual(await context.adapter.assess(context.stored), { action: "released_elsewhere", releaseHash: foreign,
    blockNumber: 90, blockHash: context.model.blockHash(90) });
  for (const overrides of [{ amount: "2" }, { recipient: evmAddressToBech32(signers[0]) }, { nonce: "8" }, { route_id: "other-route" }]) {
    const mismatch = setup();
    // A single origin returning such a record is enough: a halt is preferred to an alert.
    mismatch.model.faults[1] = ({ kind, path, body }) => (kind === "rest" && path.includes("/attestations/") ? { ...body,
      status: "ATTESTATION_STATE_PROCESSED", processed: true,
      record: recordFor(mismatch.request, mismatch.approvals, { txHash: `0x${"99".repeat(32)}`, height: 90, overrides }) } : undefined);
    assert.deepEqual(await mismatch.adapter.assess(mismatch.stored), { action: "halt", code: "processed_with_mismatching_record" });
  }
  const unsettled = setup();
  unsettled.model.faults[0] = ({ kind, path, body }) => (kind === "rest" && path.includes("/attestations/")
    ? { ...body, status: "ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD", processed: true } : undefined);
  assert.deepEqual(await unsettled.adapter.assess(unsettled.stored), { action: "wait", code: "replay_state_unsettled", defer: true });
  const legacy = setup();
  legacy.model.state.attestations.set(legacy.transferId, { status: "processed_without_record", record: null });
  assert.deepEqual(await legacy.adapter.assess(legacy.stored), { action: "release_unverified", code: "processed_without_record" });
});

test("transfer-specific conditions defer, route conditions wait, identity mismatches stop", async () => {
  const cases = [
    [{ recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111").toUpperCase() }, null, { action: "reject", code: "invalid_recipient" }],
    [{ deadlineUnix: nowUnix() + 30 }, null, { action: "wait", code: "approval_expired_awaiting_reissue", defer: true }],
    [{}, (m) => { m.state.route = { ...m.state.route, paused: true }; }, { action: "wait", code: "route_paused" }],
    [{}, (m) => { m.state.route = { ...m.state.route, enabled: false }; }, { action: "wait", code: "route_paused" }],
    [{}, (m) => { m.state.route = { ...m.state.route, max_transfer_amount: "1" }; }, { action: "wait", code: "amount_above_transfer_limit", defer: true }],
    [{}, (m) => { m.state.usage = { used: (10n ** 23n).toString() }; }, { action: "wait", code: "daily_limit_exhausted", defer: true }],
    [{}, (m) => { m.state.outstanding = { amount: (10n ** 24n).toString() }; }, { action: "wait", code: "outstanding_limit_reached", defer: true }],
    [{}, (m) => { m.state.baseFee = "60000000000.000000000000000000"; }, { action: "wait", code: "gas_price_above_cap" }],
    [{}, (m) => { m.state.simulation = { code: 6 }; }, { action: "wait", code: "attestation_simulation_failed", defer: true }],
    [{}, (m) => { m.state.simulation = { code: 0, gasUsed: 500_000n }; }, { action: "wait", code: "gas_estimate_above_limit", defer: true }],
    [{}, (m) => { m.state.balance = 1n; }, { action: "wait", code: "submitter_balance_insufficient" }],
  ];
  for (const [options, configure, expected] of cases) {
    const context = setup(options);
    configure?.(context.model);
    assert.deepEqual(await context.adapter.assess(context.stored), expected, JSON.stringify(expected));
  }
  const rotated = setup();
  rotated.model.state.route = { ...rotated.model.state.route, bridge_signers: [signers[0], signers[1], computeAddress(keys[3].publicKey)] };
  await assert.rejects(rotated.adapter.assess(rotated.stored), (error) => error.code === "signer_set_mismatch" && !isTemporaryStop(error));
  const lying = setup();
  lying.model.faults[0] = ({ kind, path, body }) => (kind === "rest" && path.includes("/routes/")
    ? { ...body, route: { ...body.route, bridge_signers: [signers[0], signers[1], computeAddress(keys[3].publicKey)] } } : undefined);
  await assert.rejects(lying.adapter.assess(lying.stored), (error) => isTemporaryStop(error) && error.code === "rpc_disagreement");
  const mixed = setup();
  mixed.model.faults[1] = ({ kind, method, body }) => (kind === "rpc" && method === "abci_query"
    ? { ...body, result: { response: { code: 6, log: "failed" } } } : undefined);
  await assert.rejects(mixed.adapter.assess(mixed.stored), (error) => isTemporaryStop(error));
  for (const [network, code] of [["xitcoin", "xitcoin_mainnet_rejected"], ["xitcoin-testnet-v2-2", "unexpected_chain_id"]]) {
    const other = setup();
    other.model.faults[1] = ({ kind, method, body }) => (kind === "rpc" && method === "status"
      ? { ...body, result: { ...body.result, node_info: { network } } } : undefined);
    await assert.rejects(other.adapter.assess(other.stored), (error) => error.code === code && !isTemporaryStop(error));
  }
  const source = setup({ verifySource: async () => { throw new Error("not final"); } });
  await assert.rejects(source.adapter.assess(source.stored), (error) => error.code === "source_finality_unverified" && isTemporaryStop(error));
  const tampered = setup();
  assert.deepEqual(await tampered.adapter.assess({ ...tampered.stored, request: { ...tampered.request, deadlineUnix: tampered.request.deadlineUnix + 1 } }),
    { action: "halt", code: "stored_request_mismatch" });
});

test("sequence ownership: the chain's sequence must equal the ledger's next nonce after the first transaction", async () => {
  const context = setup();
  const assessed = await context.adapter.assess(context.stored);
  context.model.state.account.sequence = 4;
  assert.deepEqual(await context.adapter.sign({ ...context.stored, context: assessed.context, expectedNonce: 3 }),
    { action: "halt", code: "account_sequence_not_owned" });
  const lagging = setup();
  const lag = await lagging.adapter.assess(lagging.stored);
  lagging.model.faults[1] = ({ kind, path, body }) => (kind === "rest" && path.includes("/auth/")
    ? { account: { ...body.account, sequence: "1" } } : undefined);
  assert.deepEqual(await lagging.adapter.sign({ ...lagging.stored, context: lag.context, expectedNonce: null }),
    { action: "wait", code: "account_sequence_unsettled" });
});

test("before the first send: strict-majority reads decide send or wait, halts need every origin", async () => {
  const context = setup({ origins: 3 });
  const { row } = await signed(context);
  const first = { ...row, state: "signed", broadcastAttempts: 0 };
  // One faulty origin of three cannot hold the row.
  context.model.faults[2] = () => "hang";
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: first }), { action: "send" });
  context.model.faults[2] = null;
  context.model.state.account.sequence = 1;
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: first }), { action: "halt", code: "nonce_consumed_before_send" });
  context.model.state.account.sequence = 0;
  context.model.state.route = { ...context.model.state.route, paused: true };
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: first }), { action: "wait", code: "route_paused" });
  context.model.state.route = { ...context.model.state.route, paused: false };
  context.model.state.simulation = { code: 6 };
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: first }), { action: "wait", code: "attestation_simulation_failed" });
  // Processed elsewhere after our bytes were committed: send them once anyway.
  context.model.state.attestations.set(context.transferId, { status: "processed_without_record", record: null });
  assert.deepEqual(await context.adapter.beforeFirstSend({ ...context.stored, row: first }), { action: "send" });
  // Once the local deadline margin is lost, every origin failing still sends.
  const late = setup({ deadlineUnix: nowUnix() + 3_600 });
  const lateRow = (await signed(late)).row;
  late.model.faults[0] = () => "hang"; late.model.faults[1] = () => "hang";
  assert.deepEqual(await late.adapter.beforeFirstSend({ ...late.stored, nowUnix: late.request.deadlineUnix,
    row: { ...lateRow, state: "signed", broadcastAttempts: 0 } }), { action: "send" });
});

test("stored bytes are revalidated against the request, key, sequence and caps on every use", async () => {
  const context = setup();
  const { row } = await signed(context);
  const flipped = `${row.signedHex.slice(0, -2)}${row.signedHex.slice(-2) === "00" ? "01" : "00"}`;
  for (const bad of [{ ...row, signedHex: flipped }, { ...row, nonce: row.nonce + 1 }, { ...row, transactionHash: `0x${"00".repeat(31)}01` }]) {
    assert.deepEqual(await context.adapter.verifyStored({ ...context.stored, row: bad }), { action: "halt", code: "stored_transaction_mismatch" });
  }
  const tighter = setup({ patch: { maxFee: "1000" } });
  assert.deepEqual(await tighter.adapter.verifyStored({ ...tighter.stored, row }), { action: "halt", code: "stored_transaction_mismatch" });
});
