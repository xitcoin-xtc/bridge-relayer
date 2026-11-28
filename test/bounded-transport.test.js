import assert from "node:assert/strict";
import test from "node:test";
import { BoundedJsonRpcClient, TransportError, boundedRequest, createBoundedGetFetch, endpoint, independentEndpoints,
  parseBoundedJson } from "../src/bounded-transport.js";
import { CronosRpcQuorum, normalizeReceipt, normalizeTransaction, normalizeBlock, safeQuantity } from "../src/cronos-rpc.js";
import { CometBftHttpClient, decodeXitcoinOutboundBlock, decodeXitcoinOutboundTransaction } from "../src/network.js";

const code = (expected) => (error) => error instanceof TransportError && error.code === expected
  && error.message === "bounded transport unavailable";
const url = new URL("https://rpc.example/path");
const json = (value, init = {}) => new Response(JSON.stringify(value), { status: 200, ...init });
function stream(chunks, { stall = false } = {}) {
  let index = 0;
  return new Response(new ReadableStream({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else if (!stall) controller.close();
      else return new Promise(() => {});
    },
  }));
}

test("endpoints require HTTPS or explicit loopback HTTP, independent origins and no embedded secrets", () => {
  assert.equal(endpoint("https://rpc.example/v1").origin, "https://rpc.example");
  assert.equal(endpoint("http://127.0.0.1:8545", { allowLoopbackHttp: true }).port, "8545");
  for (const [value, options] of [["http://rpc.example", {}], ["http://127.0.0.1:8545", {}], ["http://10.0.0.1", { allowLoopbackHttp: true }],
    ["https://user:secret@rpc.example", {}], ["https://rpc.example/?apikey=secret", {}], ["https://rpc.example/#key", {}],
    ["ftp://rpc.example", {}], ["not a url", {}], [7, {}], [`https://rpc.example/${"a".repeat(2050)}`, {}],
    ["https://rpc.example", { allowLoopbackHttp: "yes" }]]) {
    assert.throws(() => endpoint(value, options), code("invalid_endpoint"));
  }
  assert.equal(independentEndpoints(["http://127.0.0.1:1", "http://127.0.0.1:2"], { allowLoopbackHttp: true }).length, 2);
  assert.throws(() => independentEndpoints(["https://a.example/x", "https://a.example/y"]), code("endpoints_not_independent"));
  for (const values of [["https://a.example"], [], "https://a.example", Array.from({ length: 5 }, (_, i) => `https://${i}.example`)]) {
    assert.throws(() => independentEndpoints(values), code("invalid_endpoint"));
  }
});

test("requests forbid redirects, bound bytes before parsing and sanitize upstream failures", async () => {
  let seen;
  const text = await boundedRequest(url, { method: "POST", body: "{}", fetchImpl: async (target, init) => { seen = { target, init }; return json({ ok: 1 }); } });
  assert.equal(text, '{"ok":1}');
  assert.equal(seen.init.redirect, "error"); assert.equal(seen.init.method, "POST"); assert.ok(seen.init.signal instanceof AbortSignal);
  assert.equal(seen.init.credentials, "omit"); assert.equal(seen.init.headers["content-type"], "application/json");
  for (const response of [json({}, { status: 500 }), json({}, { status: 302 }),
    { status: 200, redirected: true, body: new Response("{}").body, headers: new Headers() }]) {
    await assert.rejects(boundedRequest(url, { fetchImpl: async () => response }), code("http_status"));
  }
  await assert.rejects(boundedRequest(url, { maxBytes: 8, fetchImpl: async () => new Response("x".repeat(9), { headers: { "content-length": "9" } }) }),
    code("response_too_large"));
  await assert.rejects(boundedRequest(url, { maxBytes: 8, fetchImpl: async () => stream([new Uint8Array(5), new Uint8Array(5)]) }), code("response_too_large"));
  await assert.rejects(boundedRequest(url, { fetchImpl: async () => new Response(new Uint8Array([0xff, 0xfe])) }), code("invalid_encoding"));
  await assert.rejects(boundedRequest(url, { fetchImpl: async () => ({ status: 200, body: null }) }), code("invalid_response"));
  await assert.rejects(boundedRequest(url, { fetchImpl: async () => null }), code("invalid_response"));
  let touched = false;
  const hostile = { get code() { touched = true; return "SIGNER_TIMEOUT"; }, message: "secret https://key@rpc" };
  await assert.rejects(boundedRequest(url, { fetchImpl: async () => { throw hostile; } }), (error) => code("unavailable")(error) && !/secret/.test(error.message));
  assert.equal(touched, false);
});

test("one overall deadline covers stalled headers and stalled bodies", async () => {
  const started = Date.now();
  await assert.rejects(boundedRequest(url, { timeoutMs: 50, fetchImpl: () => new Promise(() => {}) }), code("timeout"));
  await assert.rejects(boundedRequest(url, { timeoutMs: 50, fetchImpl: async () => stream([new Uint8Array([123])], { stall: true }) }), code("timeout"));
  assert.ok(Date.now() - started < 2_000);
  const outer = new AbortController();
  const pending = boundedRequest(url, { timeoutMs: 10_000, signal: outer.signal, fetchImpl: () => new Promise(() => {}) });
  outer.abort();
  await assert.rejects(pending, code("timeout"));
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: 60_001 }, { maxBytes: 0 }, { maxBytes: 16 * 1024 * 1024 + 1 }]) {
    await assert.rejects(boundedRequest(url, { ...options, fetchImpl: async () => json({}) }), code("invalid_limits"));
  }
  for (const request of [{ method: "PUT" }, { method: "POST" }, { method: "GET", body: "x" }, { method: "POST", body: "x".repeat(131_073) }]) {
    await assert.rejects(boundedRequest(url, { ...request, fetchImpl: async () => json({}) }), code("invalid_request"));
  }
  await assert.rejects(boundedRequest("https://rpc.example", { fetchImpl: async () => json({}) }), code("invalid_request"));
});

test("JSON is parsed only after byte bounds and then bounded in depth and node count", () => {
  assert.deepEqual(parseBoundedJson('{"a":[1,2]}'), { a: [1, 2] });
  assert.throws(() => parseBoundedJson("{"), code("invalid_json"));
  assert.throws(() => parseBoundedJson(`${"[".repeat(30)}${"]".repeat(30)}`), code("invalid_json_shape"));
  assert.throws(() => parseBoundedJson(JSON.stringify(Array.from({ length: 300_000 }, () => 0))), code("invalid_json_shape"));
  assert.equal(Object.getPrototypeOf(parseBoundedJson('{"__proto__":{"polluted":true}}')).polluted, undefined);
});

test("JSON-RPC responses must match id and version and carry exactly one result or error", async () => {
  const client = (response) => new BoundedJsonRpcClient({ url: "https://rpc.example", fetchImpl: async (_url, init) => {
    const { id } = JSON.parse(init.body);
    return new Response(JSON.stringify(typeof response === "function" ? response(id) : response));
  } });
  assert.equal(await client((id) => ({ jsonrpc: "2.0", id, result: "0x1" })).call("eth_chainId"), "0x1");
  assert.equal(await client((id) => ({ jsonrpc: "2.0", id, result: null })).call("eth_getTransactionReceipt", ["0x"]), null);
  await assert.rejects(client((id) => ({ jsonrpc: "2.0", id, error: { code: -32000, message: "secret upstream text" } })).call("eth_call"),
    (error) => code("rpc_error")(error) && error.rpcCode === -32000 && !/secret/.test(error.message));
  for (const response of [(id) => ({ jsonrpc: "2.0", id: id + 1, result: 1 }), (id) => ({ id, result: 1 }),
    (id) => ({ jsonrpc: "2.0", id, result: 1, error: {} }), (id) => ({ jsonrpc: "2.0", id }), (id) => ({ jsonrpc: "2.0", id, result: 1, extra: 1 }),
    () => [], () => "text"]) {
    await assert.rejects(client(response).call("eth_chainId"), code("invalid_response"));
  }
  for (const [method, params] of [["chainId", []], ["eth_chainId", {}], ["eth_chain id", []], [1, []]]) {
    await assert.rejects(client(() => ({})).call(method, params), code("invalid_request"));
  }
  assert.throws(() => new BoundedJsonRpcClient({ url: "http://rpc.example" }), code("invalid_endpoint"));
});

test("CometBFT client receives only byte-bounded bodies through the injected fetch", async () => {
  const body = { jsonrpc: "2.0", id: -1, result: { node_info: { network: "xitcoin-testnet-v2-1" }, sync_info: { latest_block_height: "9", catching_up: false } } };
  const make = (fetchImpl, maxBytes = 4096) => new CometBftHttpClient({ url: "https://xitcoin.example", chainId: "xitcoin-testnet-v2-1",
    decodeBlock: decodeXitcoinOutboundBlock, decodeTransaction: decodeXitcoinOutboundTransaction,
    fetchImpl: createBoundedGetFetch({ maxBytes, fetchImpl }) });
  let redirect;
  assert.deepEqual(await make(async (_url, init) => { redirect = init.redirect; return json(body); }).status(), { chainId: "xitcoin-testnet-v2-1", height: 9 });
  assert.equal(redirect, "error");
  await assert.rejects(make(async () => stream([new Uint8Array(4097)]), 4096).status(), code("response_too_large"));
  await assert.rejects(make(async () => json(body, { status: 503 })).status(), code("http_status"));
});

test("Cronos RPC quorum requires every origin, agreement and testnet chain identity", async () => {
  const origins = ["https://a.example", "https://b.example"];
  const quorum = (answers) => new CronosRpcQuorum({ urls: origins, fetchImpl: async (target, init) => {
    const { id, method } = JSON.parse(init.body);
    const answer = answers[new URL(target).host]?.[method];
    if (answer instanceof Error) throw answer;
    return json({ jsonrpc: "2.0", id, result: answer });
  } });
  const both = (method, value) => ({ "a.example": { [method]: value }, "b.example": { [method]: value } });
  assert.equal(await quorum(both("eth_chainId", "0x152")).chainId(), 338n);
  await assert.rejects(quorum(both("eth_chainId", "0x19")).chainId(), (error) => error.code === "cronos_mainnet_rejected");
  await assert.rejects(quorum(both("eth_chainId", "0x1")).chainId(), (error) => error.code === "unexpected_chain_id");
  await assert.rejects(quorum({ "a.example": { eth_chainId: "0x152" }, "b.example": { eth_chainId: "0x19" } }).chainId(),
    (error) => error.code === "rpc_disagreement");
  await assert.rejects(quorum({ "a.example": { eth_chainId: "0x152" }, "b.example": { eth_chainId: new Error("down") } }).chainId(),
    code("unavailable"));
  await assert.rejects(quorum(both("eth_chainId", "0x0152")).chainId(), (error) => error.code === "rpc_invalid_response");
  assert.equal(await quorum({ "a.example": { eth_blockNumber: "0x10" }, "b.example": { eth_blockNumber: "0xf" } }).tip(), 15);
  await assert.rejects(quorum(both("eth_blockNumber", "0x0f")).tip(), (error) => error.code === "rpc_invalid_response");
  assert.throws(() => new CronosRpcQuorum({ urls: ["https://a.example", "https://a.example/other"] }), code("endpoints_not_independent"));
});

test("receipt, transaction and block normalizers accept only exact bounded shapes", () => {
  const h = (byte) => `0x${byte.repeat(64)}`;
  const log = { address: `0x${"1".repeat(40)}`, topics: [h("a")], data: "0x", removed: false, logIndex: "0x0", transactionIndex: "0x0",
    transactionHash: h("b"), blockHash: h("c"), blockNumber: "0x5" };
  const receipt = { transactionHash: h("b"), blockHash: h("c"), blockNumber: "0x5", transactionIndex: "0x0", status: "0x1", from: `0x${"2".repeat(40)}`,
    to: `0x${"1".repeat(40)}`, contractAddress: null, gasUsed: "0x5208", logs: [log] };
  assert.equal(normalizeReceipt(receipt).logs.length, 1);
  assert.equal(normalizeReceipt(null), null);
  for (const patch of [{ status: "0x2" }, { status: 1 }, { blockHash: "0x00" }, { logs: Array.from({ length: 65 }, () => log) },
    { logs: [{ ...log, topics: [h("a"), h("a"), h("a"), h("a"), h("a")] }] }, { logs: [{ ...log, removed: "false" }] },
    { blockNumber: "0x01" }, { blockNumber: `0x${"f".repeat(15)}` }, { from: "0x12" }, { transactionIndex: undefined },
    { logs: [{ ...log, transactionIndex: null }] }]) {
    assert.throws(() => normalizeReceipt({ ...receipt, ...patch }), (error) => error.code === "rpc_invalid_response");
  }
  assert.throws(() => normalizeReceipt(Object.assign(Object.create({ polluted: 1 }), receipt)));
  const tx = { hash: h("b"), from: `0x${"2".repeat(40)}`, to: `0x${"1".repeat(40)}`, input: "0xabcd", nonce: "0x0", value: "0x0",
    gas: "0x5208", gasPrice: "0x1", type: "0x0", chainId: "0x152", v: "0x2c7", r: `0x${"0".repeat(63)}1`, s: "0x2", blockHash: null, blockNumber: null };
  assert.equal(normalizeTransaction(tx).r, "1");
  assert.throws(() => normalizeTransaction({ ...tx, input: "0xabc" }));
  assert.throws(() => normalizeTransaction({ ...tx, r: `0x${"1".repeat(65)}` }));
  assert.deepEqual(normalizeBlock({ number: "0x5", hash: h("c"), parentHash: h("d"), timestamp: "0x10", transactions: [] }),
    { number: 5, hash: h("c"), parentHash: h("d"), timestamp: 16 });
});

test("a revert counts only when every origin reports an execution error; rate limits and mixed answers are temporary", async () => {
  const origins = ["https://a.example", "https://b.example"];
  const quorum = (answers) => new CronosRpcQuorum({ urls: origins, fetchImpl: async (target, init) => {
    const { id } = JSON.parse(init.body);
    const answer = answers[new URL(target).host];
    return json({ jsonrpc: "2.0", id, ...answer });
  } });
  const revert = { error: { code: 3, message: "execution reverted" } };
  const ok = { result: "0x" };
  assert.deepEqual({ ...await quorum({ "a.example": ok, "b.example": ok }).callVerdict({ to: `0x${"1".repeat(40)}` }) },
    { reverted: false, values: ["0x", "0x"] });
  assert.equal((await quorum({ "a.example": revert, "b.example": revert }).callVerdict({})).reverted, true);
  assert.equal((await quorum({ "a.example": { error: { code: -32000 } }, "b.example": revert }).estimateVerdict({})).reverted, true);
  await assert.rejects(quorum({ "a.example": revert, "b.example": ok }).callVerdict({}), (error) => error.code === "rpc_disagreement");
  for (const fault of [{ error: { code: -32005, message: "limit exceeded" } }, { error: { code: -32603 } }, { error: { message: "no code" } }]) {
    await assert.rejects(quorum({ "a.example": fault, "b.example": revert }).callVerdict({}), (error) => error instanceof TransportError);
    await assert.rejects(quorum({ "a.example": { result: "0x5208" }, "b.example": fault }).estimateVerdict({}), (error) => error instanceof TransportError);
  }
});

test("strict-majority reads tolerate one faulty origin among three, never among two", async () => {
  const build = (answers) => new CronosRpcQuorum({ urls: Object.keys(answers).map((host) => `https://${host}`), fetchImpl: async (target, init) => {
    const { id } = JSON.parse(init.body);
    const answer = answers[new URL(target).host];
    if (answer === "down") throw new Error("connection refused");
    return json({ jsonrpc: "2.0", id, ...answer });
  } });
  const three = (a, b, c) => build({ "a.example": a, "b.example": b, "c.example": c });
  const n = (value) => ({ result: value });
  const revert = { error: { code: 3, message: "execution reverted" } }, limited = { error: { code: -32005 } };
  assert.deepEqual({ ...await three(n("0x5"), n("0x5"), n("0x7")).majority("eth_getTransactionCount", [], safeQuantity) }, { value: 5, unanimous: false });
  assert.deepEqual({ ...await three(n("0x5"), n("0x5"), "down").majority("eth_getTransactionCount", [], safeQuantity) }, { value: 5, unanimous: false });
  assert.deepEqual({ ...await three(n("0x5"), n("0x5"), n("0x5")).majority("eth_getTransactionCount", [], safeQuantity) }, { value: 5, unanimous: true });
  await assert.rejects(three(n("0x5"), n("0x6"), n("0x7")).majority("eth_getTransactionCount", [], safeQuantity), (error) => error.code === "rpc_disagreement");
  await assert.rejects(build({ "a.example": n("0x5"), "b.example": "down" }).majority("eth_getTransactionCount", [], safeQuantity),
    (error) => error.code === "rpc_disagreement");
  assert.equal((await three(n("0x"), n("0x"), limited).callMajorityVerdict({})).reverted, false);
  assert.equal((await three(revert, revert, n("0x")).callMajorityVerdict({})).reverted, true);
  await assert.rejects(three(revert, n("0x"), limited).callMajorityVerdict({}), (error) => error.code === "rpc_disagreement");
  assert.equal(await three(n("0x152"), n("0x152"), "down").chainIdMajority(), 338n);
  await assert.rejects(three(n("0x152"), n("0x152"), n("0x19")).chainIdMajority(), (error) => error.code === "cronos_mainnet_rejected");
  await assert.rejects(build({ "a.example": n("0x152"), "b.example": "down" }).chainIdMajority(), (error) => error.code === "rpc_disagreement");
  assert.deepEqual(await three(n("0x5"), n("0x6"), "down").majorityAnswers("eth_blockNumber", [], safeQuantity), [5, 6]);
});
