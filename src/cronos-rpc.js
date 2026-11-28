import { types } from "node:util";
import { BoundedJsonRpcClient, TransportError, independentEndpoints } from "./bounded-transport.js";

// Independent Cronos JSON-RPC origins. `agree` requires identical normalized
// answers from every origin; `each` returns every answer for callers that must
// distinguish propagation lag (absent) from conflicting content. Normalizers
// accept only the exact shapes needed and never pass raw provider objects on.
export class RpcDisagreement extends Error {
  constructor() { super("Cronos RPC disagreement"); this.code = "rpc_disagreement"; }
}
export class RpcInvalid extends Error {
  constructor() { super("Cronos RPC response invalid"); this.code = "rpc_invalid_response"; }
}
export const CRONOS_TESTNET_CHAIN_ID = 338n;
export const CRONOS_MAINNET_CHAIN_ID = 25n;

const invalid = () => new RpcInvalid();
const HEX = /^0x(?:[0-9a-f]{2})*$/;
function object(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw invalid();
  return value;
}
export function quantity(value) {
  if (typeof value !== "string" || value.length > 66 || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value.toLowerCase())) throw invalid();
  return BigInt(value.toLowerCase());
}
// Signature scalars: some providers zero-pad them to 32 bytes.
function scalar(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{1,64}$/.test(value.toLowerCase())) throw invalid();
  return BigInt(value.toLowerCase());
}
export function safeQuantity(value) {
  const number = quantity(value);
  if (number > BigInt(Number.MAX_SAFE_INTEGER)) throw invalid();
  return Number(number);
}
export function data(value, maxLength = 262_144) {
  if (typeof value !== "string" || value.length > maxLength) throw invalid();
  const normalized = value.toLowerCase();
  if (!HEX.test(normalized)) throw invalid();
  return normalized;
}
export function hash32(value) {
  const normalized = data(value, 66);
  if (normalized.length !== 66) throw invalid();
  return normalized;
}
export function address(value) {
  const normalized = data(value, 42);
  if (normalized.length !== 42) throw invalid();
  return normalized;
}
const optional = (value, parse) => (value === null || value === undefined ? null : parse(value));

export function normalizeBlock(value) {
  const block = object(value);
  return Object.freeze({ number: safeQuantity(block.number), hash: hash32(block.hash),
    parentHash: hash32(block.parentHash), timestamp: safeQuantity(block.timestamp) });
}

export function normalizeLog(value) {
  const log = object(value);
  if (!Array.isArray(log.topics) || log.topics.length > 4 || typeof log.removed !== "boolean") throw invalid();
  return Object.freeze({ address: address(log.address), topics: Object.freeze(log.topics.map(hash32)),
    data: data(log.data, 65_536), removed: log.removed, logIndex: safeQuantity(log.logIndex),
    transactionHash: hash32(log.transactionHash), blockHash: hash32(log.blockHash), blockNumber: safeQuantity(log.blockNumber) });
}

export function normalizeReceipt(value) {
  if (value === null) return null;
  const receipt = object(value);
  if (!Array.isArray(receipt.logs) || receipt.logs.length > 64 || !["0x0", "0x1"].includes(receipt.status)) throw invalid();
  return Object.freeze({ transactionHash: hash32(receipt.transactionHash), blockHash: hash32(receipt.blockHash),
    blockNumber: safeQuantity(receipt.blockNumber), status: receipt.status, from: address(receipt.from),
    to: optional(receipt.to, address), contractAddress: optional(receipt.contractAddress, address),
    gasUsed: quantity(receipt.gasUsed).toString(), logs: Object.freeze(receipt.logs.map(normalizeLog)) });
}

export function normalizeTransaction(value) {
  if (value === null) return null;
  const tx = object(value);
  const type = optional(tx.type, safeQuantity) ?? 0;
  return Object.freeze({ hash: hash32(tx.hash), from: address(tx.from), to: optional(tx.to, address),
    input: data(tx.input), nonce: safeQuantity(tx.nonce), value: quantity(tx.value).toString(),
    gas: quantity(tx.gas).toString(), gasPrice: quantity(tx.gasPrice).toString(), type,
    chainId: optional(tx.chainId, quantity)?.toString() ?? null, v: scalar(tx.v).toString(),
    r: scalar(tx.r).toString(), s: scalar(tx.s).toString(),
    blockHash: optional(tx.blockHash, hash32), blockNumber: optional(tx.blockNumber, safeQuantity) });
}

function stable(value) {
  return JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item));
}
const hex = (number) => `0x${BigInt(number).toString(16)}`;

export class CronosRpcQuorum {
  #clients;

  constructor({ urls, allowLoopbackHttp = false, timeoutMs = 10_000, maxBytes = 2 * 1024 * 1024, fetchImpl = globalThis.fetch }) {
    this.#clients = Object.freeze(independentEndpoints(urls, { allowLoopbackHttp })
      .map((url) => new BoundedJsonRpcClient({ url: url.href, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl })));
  }

  get size() { return this.#clients.length; }

  // Every origin must answer; a transport or provider error is never skipped.
  async each(method, params, normalize) {
    const settled = await Promise.allSettled(this.#clients.map((client) => client.call(method, params)));
    return settled.map((result) => {
      if (result.status !== "fulfilled") throw result.reason instanceof TransportError ? result.reason : new TransportError("unavailable");
      return normalize(result.value);
    });
  }

  // Like `each`, but reports JSON-RPC errors (for example an execution revert)
  // separately from transport failures, which still throw.
  async eachOrRpcError(method, params, normalize) {
    const settled = await Promise.allSettled(this.#clients.map((client) => client.call(method, params)));
    return settled.map((result) => {
      if (result.status === "fulfilled") return { ok: true, value: normalize(result.value) };
      if (result.reason instanceof TransportError && result.reason.code === "rpc_error") return { ok: false };
      throw result.reason instanceof TransportError ? result.reason : new TransportError("unavailable");
    });
  }

  async agree(method, params, normalize) {
    const values = await this.each(method, params, normalize);
    if (values.some((value) => stable(value) !== stable(values[0]))) throw new RpcDisagreement();
    return values[0];
  }

  // Chain identity on every origin. Cronos mainnet is rejected in this release.
  async chainId() {
    const chain = await this.agree("eth_chainId", [], quantity);
    if (chain === CRONOS_MAINNET_CHAIN_ID || chain !== CRONOS_TESTNET_CHAIN_ID) {
      const error = new Error("unexpected Cronos chain");
      error.code = chain === CRONOS_MAINNET_CHAIN_ID ? "cronos_mainnet_rejected" : "unexpected_chain_id";
      throw error;
    }
    return chain;
  }

  async tip() { return Math.min(...await this.each("eth_blockNumber", [], safeQuantity)); }

  async block(number) {
    if (!Number.isSafeInteger(number) || number < 0) throw invalid();
    const values = await this.each("eth_getBlockByNumber", [hex(number), false], (value) => (value === null ? null : normalizeBlock(value)));
    if (values.some((value) => value === null)) throw new RpcDisagreement();
    if (values.some((value) => stable(value) !== stable(values[0])) || values[0].number !== number) throw new RpcDisagreement();
    return values[0];
  }

  latestBlocks() { return this.each("eth_getBlockByNumber", ["latest", false], normalizeBlock); }

  code(account, number) { return this.agree("eth_getCode", [account, hex(number)], (value) => data(value, 1_048_576)); }

  call(request, blockTag) {
    return this.agree("eth_call", [request, typeof blockTag === "number" ? hex(blockTag) : blockTag], data);
  }

  callEach(request, blockTag = "latest") { return this.eachOrRpcError("eth_call", [request, blockTag], data); }

  estimateEach(request) { return this.eachOrRpcError("eth_estimateGas", [request], quantity); }

  gasPrices() { return this.each("eth_gasPrice", [], quantity); }

  balances(account) { return this.each("eth_getBalance", [account, "latest"], quantity); }

  nonces(account, tag) { return this.each("eth_getTransactionCount", [account, tag], safeQuantity); }

  receipts(transactionHash) { return this.each("eth_getTransactionReceipt", [transactionHash], normalizeReceipt); }

  // Bounded log query (one vault event topic pair); every origin must agree.
  logs(filter) {
    return this.agree("eth_getLogs", [filter], (value) => {
      if (!Array.isArray(value) || value.length > 16) throw invalid();
      return Object.freeze(value.map(normalizeLog));
    });
  }

  transactions(transactionHash) { return this.each("eth_getTransactionByHash", [transactionHash], normalizeTransaction); }

  // Identical bytes to every origin. Results are not decision inputs.
  async sendRaw(signedHex) {
    const settled = await Promise.allSettled(this.#clients.map((client) => client.call("eth_sendRawTransaction", [signedHex])));
    return Object.freeze(settled.map((result) => (result.status === "fulfilled" ? "accepted" : "rejected")));
  }
}
