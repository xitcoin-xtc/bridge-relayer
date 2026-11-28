import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { boundedRequest } from "../src/bounded-transport.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "../src/protocol.js";
import { XitcoinRpcQuorum, cometTime, normalizeAccount, normalizeAttestation, normalizeBlock, normalizeFeeMarket, normalizeMempool,
  normalizeRoute, normalizeSimulation, normalizeStatus, normalizeTxSearch } from "../src/xitcoin-rpc.js";
import { signers } from "./fixtures/destination.js";
import { SUBMITTER, xitcoinModel } from "./fixtures/xitcoin-model.js";

const invalid = { code: "rpc_invalid_response" };
const status = (sync = {}) => ({ node_info: { network: "xitcoin-testnet-v2-1" }, sync_info: { latest_block_height: "12",
  latest_block_hash: "AB".repeat(32), latest_block_time: "2026-11-28T09:28:41.022249Z", catching_up: false, ...sync } });

test("CometBFT status, block time and blocks are read only in their canonical form", () => {
  assert.deepEqual(normalizeStatus(status()), { chainId: "xitcoin-testnet-v2-1", height: 12, blockHash: `0x${"ab".repeat(32)}`,
    time: 1795858121, catchingUp: false });
  assert.equal(cometTime("2026-11-28T09:28:41Z"), 1795858121);
  assert.equal(cometTime("2026-11-28T09:28:41.999999999Z"), 1795858121); // floor, as ctx.BlockTime().Unix()
  for (const value of ["2026-11-28T09:28:41.0222491234Z", "2026-11-28 09:28:41Z", "2026-02-30T00:00:00Z", "2026-11-28T09:28:41+00:00", 1795858121]) {
    assert.throws(() => cometTime(value), invalid);
  }
  for (const sync of [{ latest_block_height: 12 }, { latest_block_height: "012" }, { latest_block_hash: "ab".repeat(32) },
    { catching_up: "false" }, { latest_block_height: "9007199254740993" }]) assert.throws(() => normalizeStatus(status(sync)), invalid);
  const tx = Buffer.from("payload");
  const block = { block_id: { hash: "CD".repeat(32) }, block: { header: { chain_id: "xitcoin-testnet-v2-1", height: "7",
    time: "2026-11-28T09:28:41Z" }, data: { txs: [tx.toString("base64")] } } };
  assert.deepEqual(normalizeBlock(block, 7).txHashes, [`0x${createHash("sha256").update(tx).digest("hex")}`]);
  assert.throws(() => normalizeBlock(block, 8), invalid);
  assert.throws(() => normalizeBlock({ ...block, block: { ...block.block, data: { txs: ["not base64!"] } } }, 7), invalid);
});

test("transaction lookups are explicit about absence and bind the bytes to the hash", () => {
  const bytes = Buffer.from("signed transaction");
  const hash = `0x${createHash("sha256").update(bytes).digest("hex")}`;
  const found = { txs: [{ hash: hash.slice(2).toUpperCase(), height: "40", index: 0, tx: bytes.toString("base64"),
    tx_result: { code: 1, codespace: "undefined", gas_wanted: "300000", gas_used: "90000", log: "upstream text",
      events: [{ type: "tx", attributes: [{ key: "acc_seq", value: `${SUBMITTER}/3` }] }, { type: "message", attributes: [{ key: "acc_seq", value: "x" }] }] } }],
  total_count: "1" };
  assert.equal(normalizeTxSearch({ txs: [], total_count: "0" }, hash), null);
  const result = normalizeTxSearch(found, hash);
  assert.deepEqual([result.height, result.code, result.gasUsed, result.accountSequences], [40, 1, "90000", [`${SUBMITTER}/3`]]);
  assert.equal(Object.hasOwn(result, "log"), false); // upstream text is never kept
  for (const bad of [{ ...found, total_count: "2" }, { ...found, total_count: "0" },
    { txs: [{ ...found.txs[0], tx: Buffer.from("other").toString("base64") }], total_count: "1" },
    { txs: [{ ...found.txs[0], hash: hash.slice(2) }], total_count: "1" },
    { txs: [{ ...found.txs[0], tx_result: { ...found.txs[0].tx_result, code: -1 } }], total_count: "1" }]) {
    assert.throws(() => normalizeTxSearch(bad, hash), invalid);
  }
  assert.deepEqual(normalizeMempool({ n_txs: "0", total: "0", total_bytes: "0", txs: null }), { complete: true, hashes: [] });
  assert.equal(normalizeMempool({ n_txs: "1", total: "5", total_bytes: "0", txs: [bytes.toString("base64")] }).complete, false);
  assert.throws(() => normalizeMempool({ n_txs: "2", total: "2", txs: [bytes.toString("base64")] }), invalid);
  assert.deepEqual(normalizeSimulation({ response: { code: 6, log: "failed" } }), { failed: true });
  assert.throws(() => normalizeSimulation({ response: { code: 0, value: "" } }), invalid);
});

test("typed bridge queries must be internally consistent and exactly shaped", () => {
  const id = `0x${"12".repeat(32)}`;
  assert.deepEqual(normalizeAttestation({ attestation_id: id, status: "ATTESTATION_STATE_ABSENT", processed: false, record: null, height: "9" }, id),
    { status: "absent", record: null, height: 9 });
  for (const bad of [
    { attestation_id: id, status: "ATTESTATION_STATE_ABSENT", processed: true, record: null, height: "9" },
    { attestation_id: id, status: "ATTESTATION_STATE_PROCESSED", processed: true, record: null, height: "9" },
    { attestation_id: id, status: "ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD", processed: false, record: null, height: "9" },
    { attestation_id: id, status: "ATTESTATION_STATE_UNSPECIFIED", processed: false, record: null, height: "9" },
    { attestation_id: id.toUpperCase(), status: "ATTESTATION_STATE_ABSENT", processed: false, record: null, height: "9" },
    { attestation_id: `0x${"13".repeat(32)}`, status: "ATTESTATION_STATE_ABSENT", processed: false, record: null, height: "9" },
    { attestation_id: id, status: "ATTESTATION_STATE_ABSENT", processed: false, record: null },
    { attestation_id: id, status: "ATTESTATION_STATE_ABSENT", processed: false, record: null, height: "9", extra: 1 },
  ]) assert.throws(() => normalizeAttestation(bad, id), invalid);
  const route = { route_id: XITCOIN_TESTNET_ROUTE_ID, source_chain_id: "338", bridge_signers: [...signers], guardian: signers[0],
    max_transfer_amount: "10", daily_limit: "100", max_outstanding_amount: "1000", enabled: true, paused: false,
    signer_set_version: "1", control_nonce: "0", outbound_nonce: "0" };
  assert.equal(normalizeRoute({ route, height: "5" }).routeId, XITCOIN_TESTNET_ROUTE_ID);
  for (const patch of [{ bridge_signers: [signers[0].toLowerCase(), signers[1], signers[2]] }, { bridge_signers: [signers[0], signers[1]] },
    { max_transfer_amount: "010" }, { max_transfer_amount: "0" }, { paused: "false" }, { signer_set_version: 1 }]) {
    assert.throws(() => normalizeRoute({ route: { ...route, ...patch }, height: "5" }), invalid);
  }
  const account = { account: { "@type": "/cosmos.auth.v1beta1.BaseAccount", address: SUBMITTER, pub_key: null, account_number: "4", sequence: "9" } };
  assert.deepEqual(normalizeAccount(account, SUBMITTER), { accountNumber: "4", sequence: 9, publicKey: null });
  for (const patch of [{ "@type": "/cosmos.auth.v1beta1.ModuleAccount" }, { address: "xtc1other" }, { sequence: "09" },
    { pub_key: { "@type": "/cosmos.crypto.secp256k1.PubKey", key: Buffer.alloc(33, 2).toString("base64") } },
    { pub_key: { "@type": "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey", key: Buffer.alloc(32, 2).toString("base64") } }]) {
    assert.throws(() => normalizeAccount({ account: { ...account.account, ...patch } }, SUBMITTER), invalid);
  }
  const fees = { params: { no_base_fee: false, base_fee_change_denominator: 8, elasticity_multiplier: 2, enable_height: "0",
    base_fee: "765625000.000000000000000000", min_gas_price: "0.000000000000000000", min_gas_multiplier: "0.500000000000000000" } };
  assert.equal(normalizeFeeMarket(fees).baseFee, 765625000n * 10n ** 18n);
  for (const base of ["765625000", "765625000.00", "-1.000000000000000000", "1e9.000000000000000000"]) {
    assert.throws(() => normalizeFeeMarket({ params: { ...fees.params, base_fee: base } }), invalid);
  }
});

test("origins must be independent and complete; quorum helpers never skip a failing origin", async () => {
  const model = xitcoinModel({ origins: 3 });
  for (const origins of [[model.urls[0]], [model.urls[0], model.urls[0]], [model.urls[0], { ...model.urls[1], rpcUrl: model.urls[0].rpcUrl }],
    [model.urls[0], { rpcUrl: "http://rpc.example", restUrl: "https://rest9.example" }],
    [model.urls[0], { rpcUrl: "https://user:pass@rpc9.example", restUrl: "https://rest9.example" }],
    [model.urls[0], { ...model.urls[1], extra: true }], [...model.urls, model.urls[0], model.urls[1]]]) {
    assert.throws(() => new XitcoinRpcQuorum({ origins, fetchImpl: model.fetchImpl }));
  }
  const rpc = new XitcoinRpcQuorum({ origins: model.urls, fetchImpl: model.fetchImpl, timeoutMs: 500 });
  assert.equal(rpc.majoritySize, 2);
  assert.equal((await rpc.chainId()).length, 3);
  model.faults[2] = () => "hang";
  await assert.rejects(rpc.params(), { code: "timeout" });
  assert.equal((await rpc.chainIdMajority()).length, 2);
  model.faults[2] = ({ kind, path, body }) => (kind === "rest" && path.includes("/auth/") ? { account: { ...body.account, sequence: "7" } } : undefined);
  const majority = await rpc.accountMajority(SUBMITTER);
  assert.deepEqual([majority.value.sequence, majority.unanimous], [0, false]);
  model.faults[1] = model.faults[2];
  assert.equal((await rpc.accountMajority(SUBMITTER)).value.sequence, 7);
  model.faults[1] = model.faults[2] = null;
  model.faults[0] = ({ kind, method, body }) => (kind === "rpc" && method === "status" ? { ...body, result: { ...body.result,
    sync_info: { ...body.result.sync_info, catching_up: true } } } : undefined);
  await assert.rejects(rpc.chainId(), { code: "rpc_disagreement" });
});

test("the only request header a caller may add is a decimal Cosmos block height", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => { seen.push(init.headers); return new Response("{}", { status: 200 }); };
  const url = new URL("https://rest.example/xitcoin/bridge/v1/params");
  await boundedRequest(url, { fetchImpl, headers: { "x-cosmos-block-height": "42" } });
  assert.equal(seen[0]["x-cosmos-block-height"], "42");
  assert.equal(seen[0].accept, "application/json");
  for (const headers of [{ authorization: "Bearer x" }, { "x-cosmos-block-height": "042" }, { "x-cosmos-block-height": "0" },
    { "x-cosmos-block-height": 42 }, { accept: "text/html" }, null, []]) {
    await assert.rejects(boundedRequest(url, { fetchImpl, headers }), { code: "invalid_request" });
  }
  await assert.rejects(boundedRequest(url, { fetchImpl: async () => new Response("{}", { status: 404 }) }),
    (error) => error.code === "http_status" && error.httpStatus === 404);
});
