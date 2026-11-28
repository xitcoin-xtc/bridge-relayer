import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  CometBftHttpClient,
  connectCronosProviders,
  connectXitcoinClients,
  decodeXitcoinOutboundBlock,
  decodeXitcoinOutboundTransaction,
} from "../src/network.js";

const blockHash = `0x${"11".repeat(32)}`;
const txHash = `0x${"22".repeat(32)}`;

function json(result, status = 200, headers = {}) {
  return new Response(JSON.stringify(result), { status, headers: { "content-type": "application/json", ...headers } });
}

function rpcFetch(calls, overrides = {}) {
  return async (target, options) => {
    const url = new URL(target);
    calls.push({ path: url.pathname, search: url.search, options });
    if (overrides[url.pathname]) return overrides[url.pathname](url);
    if (url.pathname === "/status") return json({ result: {
      node_info: { network: "xitcoin-testnet-v2-1" },
      sync_info: { latest_block_height: "102", catching_up: false },
    } });
    if (url.pathname === "/block") return json({ result: {
      block_id: { hash: blockHash.slice(2).toUpperCase() },
      block: { header: { height: url.searchParams.get("height") } },
    } });
    if (url.pathname === "/block_results") return json({ result: {
      height: url.searchParams.get("height"),
      txs_results: [],
    } });
    if (url.pathname === "/tx") return json({ result: { height: "90", tx_result: { events: [] } } });
    throw new Error(`unexpected path ${url.pathname}`);
  };
}

function client(fetchImpl = rpcFetch([])) {
  return new CometBftHttpClient({
    url: "https://rpc-a.example.test",
    chainId: "xitcoin-testnet-v2-1",
    decodeBlock: ({ height }) => height === 90 ? [{
      routeId: "route", transactionHash: txHash, messageIndex: 0, requestId: blockHash,
      sender: "xtc1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z97g2qj", destination: "0x3333333333333333333333333333333333333333",
      amount: "10", nonce: "1",
    }] : [],
    decodeTransaction: () => [{
      routeId: "route", messageIndex: 0, requestId: blockHash,
      sender: "xtc1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z97g2qj", destination: "0x3333333333333333333333333333333333333333",
      amount: "10", nonce: "1",
    }],
    fetchImpl,
  });
}

test("connects only independent Cronos providers on the pinned chain", async () => {
  const created = [];
  const providers = await connectCronosProviders({
    urls: ["https://rpc-a.example.test", "https://rpc-b.example.test"],
    chainId: 25,
    providerFactory(url) {
      created.push(url);
      return { async getNetwork() { return { chainId: 25n }; } };
    },
  });
  assert.equal(providers.length, 2);
  assert.equal(created.length, 2);
  await assert.rejects(() => connectCronosProviders({
    urls: ["https://rpc-a.example.test/one", "https://rpc-a.example.test/two"],
    providerFactory() { return { async getNetwork() { return { chainId: 25n }; } }; },
  }), /independent origins/);
  await assert.rejects(() => connectCronosProviders({
    urls: ["https://rpc-a.example.test", "https://rpc-b.example.test"],
    providerFactory() { return { async getNetwork() { return { chainId: 1n }; } }; },
  }), /unexpected Cronos chain ID/);
});

test("CometBFT client verifies identity and produces watcher-compatible records", async () => {
  const calls = [];
  const adapter = client(rpcFetch(calls));
  assert.deepEqual(await adapter.status(), { chainId: "xitcoin-testnet-v2-1", height: 102 });
  assert.deepEqual(await adapter.block(90), { height: 90, hash: blockHash, transactionHashes: [] });
  const events = await adapter.outboundTransfers(90, 91);
  assert.equal(events.length, 1);
  assert.equal(events[0].blockHeight, 90);
  assert.equal(events[0].blockHash, blockHash);
  const event = await adapter.outboundTransfer(txHash, 0);
  assert.equal(event.transactionHash, txHash);
  assert.equal(event.blockHeight, 90);
  assert.ok(calls.every((call) => call.options.redirect === "error"));
});

test("CometBFT client rejects wrong networks, oversized responses and embedded credentials", async () => {
  const wrong = client(rpcFetch([], {
    "/status": () => json({ result: {
      node_info: { network: "wrong" }, sync_info: { latest_block_height: "10", catching_up: false },
    } }),
  }));
  await assert.rejects(() => wrong.status(), /unexpected Xitcoin chain ID/);

  const oversized = new CometBftHttpClient({
    url: "https://rpc-a.example.test",
    chainId: "xitcoin-testnet-v2-1",
    decodeBlock: () => [],
    decodeTransaction: () => [],
    maxResponseBytes: 10,
    fetchImpl: async () => json({ result: {} }, 200, { "content-length": "100" }),
  });
  await assert.rejects(() => oversized.status(), /size limit/);

  assert.throws(() => new CometBftHttpClient({
    url: "https://user:password@rpc.example.test",
    chainId: "chain",
    decodeBlock: () => [],
    decodeTransaction: () => [],
  }), /credentials/);
});

test("default CometBFT transport does not depend on global fetch", () => {
  const adapter = new CometBftHttpClient({
    url: "https://rpc-a.example.test",
    chainId: "xitcoin-testnet-v2-1",
    decodeBlock: () => [],
    decodeTransaction: () => [],
  });

  assert.equal(typeof adapter.fetch, "function");
  assert.notEqual(adapter.fetch, globalThis.fetch);
});

test("Xitcoin client collection requires independent HTTPS origins", () => {
  const options = {
    chainId: "xitcoin-testnet-v2-1",
    decodeBlock: () => [],
    decodeTransaction: () => [],
    fetchImpl: rpcFetch([]),
  };
  assert.equal(connectXitcoinClients({
    ...options, urls: ["https://rpc-a.example.test", "https://rpc-b.example.test"],
  }).length, 2);
  assert.throws(() => connectXitcoinClients({
    ...options, urls: ["http://rpc-a.example.test", "https://rpc-b.example.test"],
  }), /HTTPS/);
});

test("canonical decoder reads only successful bridge_outbound_burned events", () => {
  const transaction = Buffer.from("canonical transaction");
  const transactionHash = `0x${createHash("sha256").update(transaction).digest("hex")}`;
  const event = {
    type: "bridge_outbound_burned",
    attributes: [
      { key: "request_id", value: blockHash.slice(2) },
      { key: "route_id", value: "cronos-xitcoin-xtc-v1" },
      { key: "sender", value: "xtc1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z97g2qj" },
      { key: "destination", value: "0x3333333333333333333333333333333333333333" },
      { key: "amount", value: "900" },
      { key: "nonce", value: "4" },
      { key: "msg_index", value: "2" },
    ],
  };
  const [record] = decodeXitcoinOutboundBlock({
    transactionHashes: [transactionHash],
    results: { txs_results: [{ code: 0, events: [event] }] },
  });
  assert.equal(record.requestId, blockHash);
  assert.equal(record.transactionHash, transactionHash);
  assert.equal(record.messageIndex, 2);
  assert.equal(record.amount, "900");
  assert.deepEqual(decodeXitcoinOutboundBlock({
    transactionHashes: [transactionHash],
    results: { txs_results: [{ code: 1, events: [event] }] },
  }), []);
  assert.equal(decodeXitcoinOutboundTransaction({
    transactionHash,
    result: { tx_result: { code: 0, events: [event] } },
  })[0].nonce, "4");
});

test("canonical decoder rejects incomplete, duplicate and unbound results", () => {
  const base = {
    type: "bridge_outbound_burned",
    attributes: [
      { key: "request_id", value: blockHash.slice(2) },
      { key: "route_id", value: "route" },
    ],
  };
  assert.throws(() => decodeXitcoinOutboundBlock({
    transactionHashes: [txHash], results: { txs_results: [{ code: 0, events: [base] }] },
  }), /incomplete/);
  assert.throws(() => decodeXitcoinOutboundBlock({
    transactionHashes: [], results: { txs_results: [{ code: 0, events: [] }] },
  }), /counts disagree/);
  assert.throws(() => decodeXitcoinOutboundTransaction({
    transactionHash: txHash,
    result: { tx_result: { code: 0, events: [{
      ...base,
      attributes: [...base.attributes, { key: "route_id", value: "duplicate" }],
    }] } },
  }), /duplicate/);
});

test("non-canonical outbound values are skipped and reported without stalling the block", async () => {
  const event = (overrides = {}) => ({ type: "bridge_outbound_burned", attributes: Object.entries({
    request_id: blockHash.slice(2), route_id: "route", sender: "xtc1yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z97g2qj",
    destination: "0x3333333333333333333333333333333333333333", amount: "900", nonce: "4", ...overrides,
  }).map(([key, value]) => ({ key, value })) });
  const alerts = [];
  const other = `0x${"cd".repeat(32)}`;
  const records = decodeXitcoinOutboundBlock({ height: 7, transactionHashes: [txHash, other], onSkip: (alert) => alerts.push(alert),
    results: { txs_results: [
      { code: 0, events: [event({ amount: "010" }), event({ msg_index: "1", nonce: "5" })] },
      { code: 0, events: [event({ nonce: "0" }), event({ destination: "0x123" }), event({ request_id: "zz" }),
        event({ msg_index: "01" }), event({ amount: "1".repeat(79) }), event({ destination: "0x0000000000000000000000000000000000000000" })] },
    ] } });
  assert.equal(records.length, 1);
  assert.equal(records[0].nonce, "5"); assert.equal(records[0].messageIndex, 1);
  assert.deepEqual(alerts.map((alert) => alert.reason), ["noncanonical_amount", "noncanonical_nonce", "noncanonical_destination",
    "noncanonical_request_id", "noncanonical_message_index", "noncanonical_amount", "noncanonical_destination"]);
  assert.ok(alerts.every((alert) => alert.alert === "xitcoin_outbound_event_skipped" && alert.height === 7 && Object.isFrozen(alert)));
  assert.deepEqual([alerts[0].transactionHash, alerts[0].messageIndex], [txHash, 0]);
  assert.deepEqual([alerts[1].transactionHash, alerts[1].messageIndex], [other, 0]);
  const fromTransaction = [];
  assert.deepEqual(decodeXitcoinOutboundTransaction({ transactionHash: txHash, onSkip: (alert) => fromTransaction.push(alert),
    result: { tx_result: { code: 0, events: [event({ amount: "010" })] } } }), []);
  assert.equal(fromTransaction[0].reason, "noncanonical_amount");
  // Structural problems still stop the scan.
  assert.throws(() => decodeXitcoinOutboundBlock({ transactionHashes: [txHash], onSkip: () => {},
    results: { txs_results: [{ code: 0, events: [{ type: "bridge_outbound_burned", attributes: [{ key: "amount", value: "010" }] }] }] } }), /incomplete/);
  // Without a handler the alert is still written, never dropped.
  const written = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try { decodeXitcoinOutboundBlock({ transactionHashes: [txHash], results: { txs_results: [{ code: 0, events: [event({ amount: "010" })] }] } }); }
  finally { process.stderr.write = original; }
  assert.match(written.join(""), /"alert":"xitcoin_outbound_event_skipped".*"reason":"noncanonical_amount"/);
});

test("CometBFT client passes its skipped-event handler to the canonical decoders", async () => {
  const seen = [];
  const decode = (input) => { seen.push(input.onSkip); return []; };
  const onSkip = () => {};
  const client = new CometBftHttpClient({ url: "https://xitcoin.example", chainId: "xitcoin-testnet-v2-1", decodeBlock: decode,
    decodeTransaction: decode, onSkip, fetchImpl: async (target) => {
      const path = new URL(target).pathname;
      const result = path === "/block" ? { block: { header: { height: "3" }, data: { txs: [] } }, block_id: { hash: "AB".repeat(32) } }
        : path === "/block_results" ? { height: "3", txs_results: [] } : { height: "3", tx_result: { code: 0, events: [] } };
      return { ok: true, status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ jsonrpc: "2.0", id: -1, result }) };
    } });
  await client.outboundTransfers(3, 3);
  await client.outboundTransfer(txHash, 0);
  assert.deepEqual(seen, [onSkip, onSkip]);
  assert.throws(() => new CometBftHttpClient({ url: "https://x.example", chainId: "c", decodeBlock: decode, decodeTransaction: decode, onSkip: 1 }));
});
