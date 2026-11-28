import { createHash } from "node:crypto";
import { types } from "node:util";
import { getAddress } from "ethers";
import { TransportError, boundedRequest, endpoint, parseBoundedJson, TRANSPORT_LIMITS } from "./bounded-transport.js";
import { ETH_SECP256K1_PUBKEY, FEE_DENOM, XITCOIN_MAINNET_CHAIN_ID, XITCOIN_TESTNET_CHAIN_ID, decodeSimulateGasUsed,
  encodeSimulateRequest } from "./xitcoin-transaction.js";

// Independent Xitcoin origins. Each origin is one node operator's CometBFT RPC
// (JSON-RPC over POST) and Cosmos SDK REST API. Every read is bounded by the
// shared transport (deadline, streamed byte limit, JSON depth and node limits,
// no redirects, sanitized errors) and every answer is normalized to the exact
// canonical shape this adapter needs; anything else is rejected, never
// coerced. Decision helpers mirror the Cronos quorum: `each`/`agree` need
// every origin, `majority` a strict majority (only to decide send or wait).
export class XitcoinRpcDisagreement extends Error {
  constructor() { super("Xitcoin RPC disagreement"); this.code = "rpc_disagreement"; }
}
export class XitcoinRpcInvalid extends Error {
  constructor() { super("Xitcoin RPC response invalid"); this.code = "rpc_invalid_response"; }
}
const invalid = () => new XitcoinRpcInvalid();
const COMET_METHODS = new Set(["status", "block", "tx_search", "broadcast_tx_sync", "unconfirmed_txs", "abci_query"]);
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;
const U64 = (1n << 64n) - 1n;
const I64 = (1n << 63n) - 1n;

function plain(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype) throw invalid();
  return value;
}
function exact(value, fields) {
  plain(value);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) throw invalid();
  return value;
}
// Keys a response must contain; extra keys are tolerated only where the
// upstream schema is open (CometBFT result objects carry more fields).
function has(value, fields) {
  plain(value);
  if (fields.some((key) => !Object.hasOwn(value, key))) throw invalid();
  return value;
}
function text(value, max = 256) {
  if (typeof value !== "string" || value.length > max) throw invalid();
  return value;
}
function decimal(value, maximum = (1n << 256n) - 1n) {
  if (typeof value !== "string" || !DECIMAL.test(value) || BigInt(value) > maximum) throw invalid();
  return value;
}
function safeDecimal(value) {
  const number = Number(decimal(value, BigInt(Number.MAX_SAFE_INTEGER)));
  return number;
}
function positiveAmount(value) {
  decimal(value);
  if (value === "0") throw invalid();
  return value;
}
function bool(value) { if (typeof value !== "boolean") throw invalid(); return value; }
function upperHash(value) {
  if (typeof value !== "string" || !/^[0-9A-F]{64}$/.test(value)) throw invalid();
  return `0x${value.toLowerCase()}`;
}
function lowerHash(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) throw invalid();
  return value;
}
function base64(value, maxBytes) {
  if (typeof value !== "string" || value.length > Math.ceil(maxBytes / 3) * 4 + 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw invalid();
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || bytes.length > maxBytes) throw invalid();
  return bytes;
}
function checksummed(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw invalid();
  let normalized;
  try { normalized = getAddress(value); } catch { throw invalid(); }
  if (normalized !== value) throw invalid();
  return value;
}
// RFC 3339 UTC time as CometBFT prints it, to whole Unix seconds (floor), the
// value the bridge module compares with deadlines (ctx.BlockTime().Unix()).
export function cometTime(value) {
  const match = typeof value === "string" ? value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/) : null;
  if (!match) throw invalid();
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(ms);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day
      || date.getUTCHours() !== hour || date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) throw invalid();
  return Math.floor(ms / 1000);
}
// Cosmos LegacyDec with exactly 18 fractional digits, as atto-units.
function legacyDec(value) {
  if (typeof value !== "string" || value.length > 100 || !/^(0|[1-9][0-9]*)\.[0-9]{18}$/.test(value)) throw invalid();
  return BigInt(value.replace(".", ""));
}
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
const stable = (value) => JSON.stringify(value);

export function normalizeStatus(value) {
  const result = has(value, ["node_info", "sync_info"]);
  const node = has(result.node_info, ["network"]), sync = has(result.sync_info, ["latest_block_height", "latest_block_hash",
    "latest_block_time", "catching_up"]);
  return Object.freeze({ chainId: text(node.network, 64), height: safeDecimal(sync.latest_block_height),
    blockHash: upperHash(sync.latest_block_hash), time: cometTime(sync.latest_block_time), catchingUp: bool(sync.catching_up) });
}

export function normalizeBlock(value, expectedHeight) {
  const result = has(value, ["block_id", "block"]);
  const header = has(has(result.block, ["header", "data"]).header, ["chain_id", "height", "time"]);
  const data = has(result.block.data, ["txs"]);
  const txs = data.txs === null ? [] : data.txs;
  if (!Array.isArray(txs) || txs.length > 100_000) throw invalid();
  const height = safeDecimal(header.height);
  if (height !== expectedHeight) throw invalid();
  return Object.freeze({ height, hash: upperHash(has(result.block_id, ["hash"]).hash), chainId: text(header.chain_id, 64),
    time: cometTime(header.time), txHashes: Object.freeze(txs.map((tx) => `0x${sha256(base64(tx, 1_048_576)).toString("hex")}`)) });
}

// tx_search for one hash: absent (null) is explicit (total_count "0").
export function normalizeTxSearch(value, transactionHash) {
  const result = has(value, ["txs", "total_count"]);
  const total = safeDecimal(result.total_count);
  if (!Array.isArray(result.txs) || result.txs.length !== total || total > 1) throw invalid();
  if (total === 0) return null;
  const item = has(result.txs[0], ["hash", "height", "index", "tx_result", "tx"]);
  const outcome = has(item.tx_result, ["code", "gas_wanted", "gas_used"]);
  const bytes = base64(item.tx, 65_536);
  const hash = upperHash(item.hash);
  if (hash !== transactionHash || `0x${sha256(bytes).toString("hex")}` !== hash
      || !Number.isSafeInteger(item.index) || item.index < 0
      || !Number.isSafeInteger(outcome.code) || outcome.code < 0 || outcome.code > 0xffffffff) throw invalid();
  const codespace = outcome.codespace === undefined ? "" : text(outcome.codespace, 64);
  // `tx` events with `acc_seq` (address/sequence) are emitted by the ante
  // handler, which consumed that sequence; a transaction rejected by the ante
  // handler itself carries none.
  const events = outcome.events === undefined || outcome.events === null ? [] : outcome.events;
  if (!Array.isArray(events) || events.length > 1_024) throw invalid();
  const accountSequences = [];
  for (const event of events) {
    const item = has(event, ["type"]);
    if (item.type !== "tx") continue;
    if (!Array.isArray(item.attributes) || item.attributes.length > 64) throw invalid();
    for (const attribute of item.attributes) {
      const pair = has(attribute, ["key", "value"]);
      if (pair.key === "acc_seq") accountSequences.push(text(pair.value, 128));
    }
  }
  return Object.freeze({ hash, height: safeDecimal(item.height), index: item.index, txHex: `0x${bytes.toString("hex")}`,
    code: outcome.code, codespace, gasWanted: decimal(outcome.gas_wanted, U64), gasUsed: decimal(outcome.gas_used, U64),
    accountSequences: Object.freeze(accountSequences.sort()) });
}

export function normalizeMempool(value) {
  const result = has(value, ["n_txs", "total", "txs"]);
  const txs = result.txs === null ? [] : result.txs;
  if (!Array.isArray(txs) || txs.length > 1_000 || txs.length !== safeDecimal(result.n_txs)) throw invalid();
  const total = safeDecimal(result.total);
  if (total < txs.length) throw invalid();
  return Object.freeze({ complete: total === txs.length,
    hashes: Object.freeze(txs.map((tx) => `0x${sha256(base64(tx, 1_048_576)).toString("hex")}`)) });
}

// ABCI query response of the tx service's Simulate: code 0 with the gas used,
// or an execution failure (any nonzero code) without upstream text.
export function normalizeSimulation(value) {
  const response = has(has(value, ["response"]).response, ["code"]);
  if (!Number.isSafeInteger(response.code) || response.code < 0) throw invalid();
  if (response.code !== 0) return Object.freeze({ failed: true });
  let gasUsed;
  try { gasUsed = decodeSimulateGasUsed(base64(response.value, 1_048_576)); } catch { throw invalid(); }
  if (gasUsed > U64) throw invalid();
  return Object.freeze({ failed: false, gasUsed: gasUsed.toString() });
}

const PARAMS = ["authority", "native_denom", "max_supply", "required_approvals", "signer_set_size", "chain_id",
  "attestation_domain", "control_domain", "guardian_pause_domain", "source_deposit_domain"];
export function normalizeParams(value) {
  const params = exact(exact(value, ["params"]).params, PARAMS);
  return Object.freeze({ authority: text(params.authority, 128), nativeDenom: text(params.native_denom, 64),
    maxSupply: positiveAmount(params.max_supply), requiredApprovals: params.required_approvals, signerSetSize: params.signer_set_size,
    chainId: text(params.chain_id, 64), attestationDomain: text(params.attestation_domain, 128),
    controlDomain: text(params.control_domain, 128), guardianPauseDomain: text(params.guardian_pause_domain, 128),
    sourceDepositDomain: text(params.source_deposit_domain, 128) });
}

const ROUTE = ["route_id", "source_chain_id", "bridge_signers", "guardian", "max_transfer_amount", "daily_limit",
  "max_outstanding_amount", "enabled", "paused", "signer_set_version", "control_nonce", "outbound_nonce"];
export function normalizeRoute(value) {
  const body = exact(value, ["route", "height"]);
  const route = exact(body.route, ROUTE);
  if (!Array.isArray(route.bridge_signers) || route.bridge_signers.length !== 3) throw invalid();
  return Object.freeze({ routeId: text(route.route_id, 96), sourceChainId: decimal(route.source_chain_id, U64),
    bridgeSigners: Object.freeze(route.bridge_signers.map(checksummed)), guardian: checksummed(route.guardian),
    maxTransferAmount: positiveAmount(route.max_transfer_amount), dailyLimit: positiveAmount(route.daily_limit),
    maxOutstandingAmount: positiveAmount(route.max_outstanding_amount), enabled: bool(route.enabled), paused: bool(route.paused),
    signerSetVersion: decimal(route.signer_set_version, U64), controlNonce: decimal(route.control_nonce, U64),
    outboundNonce: decimal(route.outbound_nonce, U64), height: safeDecimal(body.height) });
}

const RECORD = ["attestation_id", "route_id", "direction", "source_chain_id", "source_ref", "nonce", "recipient", "amount",
  "deadline_unix", "signer_set_version", "approvers", "destination_chain_id", "payload_hash", "signing_digest", "height", "tx_hash"];
const STATES = Object.freeze({ ATTESTATION_STATE_ABSENT: "absent", ATTESTATION_STATE_PROCESSED: "processed",
  ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD: "processed_without_record" });
export function normalizeAttestation(value, attestationId) {
  const body = exact(value, ["attestation_id", "status", "processed", "record", "height"]);
  if (lowerHash(body.attestation_id) !== attestationId || !Object.hasOwn(STATES, body.status)) throw invalid();
  const status = STATES[body.status];
  if (bool(body.processed) !== (status !== "absent") || (body.record === null) !== (status !== "processed")) throw invalid();
  let record = null;
  if (body.record !== null) {
    const raw = exact(body.record, RECORD);
    if (lowerHash(raw.attestation_id) !== attestationId || !Array.isArray(raw.approvers)
        || raw.approvers.length < 2 || raw.approvers.length > 3
        || typeof raw.source_ref !== "string" || !/^[0-9a-f]{64}$/.test(raw.source_ref)) throw invalid();
    record = Object.freeze({ routeId: text(raw.route_id, 96), direction: text(raw.direction, 32),
      sourceChainId: decimal(raw.source_chain_id, U64), sourceRef: raw.source_ref, nonce: decimal(raw.nonce, U64),
      recipient: text(raw.recipient, 256), amount: positiveAmount(raw.amount), deadlineUnix: decimal(raw.deadline_unix, I64),
      signerSetVersion: decimal(raw.signer_set_version, U64), approvers: Object.freeze(raw.approvers.map(checksummed)),
      destinationChainId: text(raw.destination_chain_id, 64), payloadHash: lowerHash(raw.payload_hash),
      signingDigest: lowerHash(raw.signing_digest), height: safeDecimal(raw.height), txHash: upperHash(raw.tx_hash) });
  }
  return Object.freeze({ status, record, height: safeDecimal(body.height) });
}

export function normalizeDailyUsage(value) {
  const body = exact(value, ["route_id", "utc_day", "utc_date", "used_amount", "daily_limit", "remaining_amount",
    "block_time_unix", "height"]);
  return Object.freeze({ routeId: text(body.route_id, 96), utcDay: decimal(body.utc_day, U64), usedAmount: decimal(body.used_amount),
    dailyLimit: positiveAmount(body.daily_limit), remainingAmount: decimal(body.remaining_amount),
    blockTime: safeDecimal(body.block_time_unix), height: safeDecimal(body.height) });
}

export function normalizeOutstanding(value) {
  const body = exact(value, ["route_id", "outstanding_amount", "max_outstanding_amount", "remaining_amount", "height"]);
  return Object.freeze({ routeId: text(body.route_id, 96), outstandingAmount: decimal(body.outstanding_amount),
    maxOutstandingAmount: positiveAmount(body.max_outstanding_amount), remainingAmount: decimal(body.remaining_amount),
    height: safeDecimal(body.height) });
}

export function normalizeAccount(value, address) {
  const account = exact(exact(value, ["account"]).account, ["@type", "address", "pub_key", "account_number", "sequence"]);
  if (account["@type"] !== "/cosmos.auth.v1beta1.BaseAccount" || account.address !== address) throw invalid();
  let publicKey = null;
  if (account.pub_key !== null) {
    const key = exact(account.pub_key, ["@type", "key"]);
    if (key["@type"] !== ETH_SECP256K1_PUBKEY) throw invalid();
    publicKey = `0x${base64(key.key, 33).toString("hex")}`;
    if (publicKey.length !== 68) throw invalid();
  }
  return Object.freeze({ accountNumber: decimal(account.account_number, U64), sequence: safeDecimal(account.sequence), publicKey });
}

export function normalizeBalance(value) {
  const balance = exact(exact(value, ["balance"]).balance, ["denom", "amount"]);
  if (balance.denom !== FEE_DENOM) throw invalid();
  return BigInt(decimal(balance.amount));
}

const FEE_PARAMS = ["no_base_fee", "base_fee_change_denominator", "elasticity_multiplier", "enable_height", "base_fee",
  "min_gas_price", "min_gas_multiplier"];
// The price per gas a Cosmos transaction must pay at least, in atto-axtc
// (1e-18 axtc): max(base fee when enabled, min_gas_price).
export function normalizeFeeMarket(value) {
  const params = exact(exact(value, ["params"]).params, FEE_PARAMS);
  bool(params.no_base_fee);
  const enableHeight = decimal(params.enable_height, I64);
  const baseFee = legacyDec(params.base_fee), minGasPrice = legacyDec(params.min_gas_price);
  legacyDec(params.min_gas_multiplier);
  return Object.freeze({ noBaseFee: params.no_base_fee, enableHeight, baseFee, minGasPrice });
}

class CometClient {
  #url; #timeoutMs; #maxBytes; #fetch; #id = 0;
  constructor({ url, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl }) {
    this.#url = endpoint(url, { allowLoopbackHttp });
    this.#timeoutMs = timeoutMs; this.#maxBytes = maxBytes; this.#fetch = fetchImpl;
  }
  get origin() { return this.#url.origin; }
  async call(method, params) {
    if (!COMET_METHODS.has(method) || !params || typeof params !== "object" || Array.isArray(params)) throw new TransportError("invalid_request");
    const id = (this.#id = (this.#id % 1_000_000_000) + 1);
    const text = await boundedRequest(this.#url, { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      timeoutMs: this.#timeoutMs, maxBytes: this.#maxBytes, fetchImpl: this.#fetch });
    const response = parseBoundedJson(text);
    if (!response || typeof response !== "object" || Array.isArray(response) || types.isProxy(response)
        || Object.getPrototypeOf(response) !== Object.prototype || response.jsonrpc !== "2.0" || response.id !== id) {
      throw new TransportError("invalid_response");
    }
    const keys = Object.keys(response).filter((key) => key !== "jsonrpc" && key !== "id");
    if (keys.length !== 1 || !["result", "error"].includes(keys[0])) throw new TransportError("invalid_response");
    if (keys[0] === "error") {
      const code = response.error && typeof response.error === "object" ? response.error.code : undefined;
      throw new TransportError("rpc_error", Number.isSafeInteger(code) ? code : undefined);
    }
    return response.result;
  }
}

class RestClient {
  #url; #timeoutMs; #maxBytes; #fetch;
  constructor({ url, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl }) {
    this.#url = endpoint(url, { allowLoopbackHttp });
    this.#timeoutMs = timeoutMs; this.#maxBytes = maxBytes; this.#fetch = fetchImpl;
  }
  get origin() { return this.#url.origin; }
  async get(path, { height } = {}) {
    if (typeof path !== "string" || !/^\/[A-Za-z0-9_/.-]{1,200}(?:\?denom=[a-z]{1,16})?$/.test(path) || path.includes(".."))
      throw new TransportError("invalid_request");
    const base = this.#url.href.endsWith("/") ? this.#url.href.slice(0, -1) : this.#url.href;
    const headers = height === undefined ? {} : { "x-cosmos-block-height": String(height) };
    const text = await boundedRequest(new URL(`${base}${path}`), { method: "GET", headers, timeoutMs: this.#timeoutMs,
      maxBytes: this.#maxBytes, fetchImpl: this.#fetch });
    return parseBoundedJson(text);
  }
}

function origins(values, allowLoopbackHttp) {
  if (!Array.isArray(values) || values.length < 2 || values.length > 4 || typeof allowLoopbackHttp !== "boolean") {
    throw new TransportError("invalid_endpoint");
  }
  const rpc = new Set(), rest = new Set();
  for (const value of values) {
    if (!value || typeof value !== "object" || Object.keys(value).length !== 2 || typeof value.rpcUrl !== "string"
        || typeof value.restUrl !== "string") throw new TransportError("invalid_endpoint");
    rpc.add(endpoint(value.rpcUrl, { allowLoopbackHttp }).origin);
    rest.add(endpoint(value.restUrl, { allowLoopbackHttp }).origin);
  }
  if (rpc.size !== values.length || rest.size !== values.length) throw new TransportError("endpoints_not_independent");
  return values;
}

export class XitcoinRpcQuorum {
  #origins;

  constructor({ origins: values, allowLoopbackHttp = false, timeoutMs = 10_000, maxBytes = 4 * 1024 * 1024, fetchImpl = globalThis.fetch }) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TRANSPORT_LIMITS.maxTimeoutMs || typeof fetchImpl !== "function") {
      throw new TransportError("invalid_limits");
    }
    this.#origins = Object.freeze(origins(values, allowLoopbackHttp).map(({ rpcUrl, restUrl }) => Object.freeze({
      comet: new CometClient({ url: rpcUrl, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl }),
      rest: new RestClient({ url: restUrl, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl }) })));
  }

  get size() { return this.#origins.length; }
  get majoritySize() { return Math.floor(this.#origins.length / 2) + 1; }

  // One answer per origin: { ok: true, value } or { ok: false, explicit, error }
  // where `explicit` marks a provider-side refusal (JSON-RPC error, HTTP 4xx)
  // as opposed to a transport failure or an invalid response.
  async settled(read, normalize) {
    const settled = await Promise.allSettled(this.#origins.map((origin) => read(origin)));
    return Object.freeze(settled.map((result) => {
      if (result.status !== "fulfilled") {
        const error = result.reason instanceof TransportError ? result.reason : new TransportError("unavailable");
        const explicit = error.code === "rpc_error" || (error.code === "http_status" && error.httpStatus >= 400 && error.httpStatus < 500);
        return Object.freeze({ ok: false, explicit, error });
      }
      try { return Object.freeze({ ok: true, value: normalize(result.value) }); }
      catch (error) { return Object.freeze({ ok: false, explicit: false, error: error instanceof XitcoinRpcInvalid ? error : invalid() }); }
    }));
  }

  // Every origin must answer; a failure is never skipped.
  async each(read, normalize) {
    return (await this.settled(read, normalize)).map((answer) => {
      if (!answer.ok) throw answer.error;
      return answer.value;
    });
  }

  async agree(read, normalize) {
    const values = await this.each(read, normalize);
    if (values.some((value) => stable(value) !== stable(values[0]))) throw new XitcoinRpcDisagreement();
    return values[0];
  }

  // The value a strict majority returns identically, and whether every origin
  // did. Only ever used to decide whether to send or wait.
  async majority(read, normalize) {
    const counts = new Map();
    for (const answer of await this.settled(read, normalize)) {
      if (!answer.ok) continue;
      const key = stable(answer.value);
      counts.set(key, { value: answer.value, count: (counts.get(key)?.count ?? 0) + 1 });
    }
    const best = [...counts.values()].sort((a, b) => b.count - a.count)[0];
    if (!best || best.count < this.majoritySize) throw new XitcoinRpcDisagreement();
    return Object.freeze({ value: best.value, unanimous: best.count === this.#origins.length });
  }

  // ---- CometBFT ----
  statuses() { return this.each((origin) => origin.comet.call("status", {}), normalizeStatus); }

  // Chain identity on every origin; never a catching-up node. Xitcoin mainnet
  // is rejected in this release.
  async chainId() {
    const statuses = await this.statuses();
    if (statuses.some((status) => status.chainId !== XITCOIN_TESTNET_CHAIN_ID)) {
      const error = new Error("unexpected Xitcoin chain");
      error.code = statuses.some((status) => status.chainId === XITCOIN_MAINNET_CHAIN_ID) ? "xitcoin_mainnet_rejected" : "unexpected_chain_id";
      throw error;
    }
    if (statuses.some((status) => status.catchingUp)) throw new XitcoinRpcDisagreement();
    return statuses;
  }

  async chainIdMajority() {
    const answers = await this.settled((origin) => origin.comet.call("status", {}), normalizeStatus);
    if (answers.some((answer) => answer.ok && answer.value.chainId !== XITCOIN_TESTNET_CHAIN_ID)) {
      const error = new Error("unexpected Xitcoin chain");
      error.code = answers.some((answer) => answer.ok && answer.value.chainId === XITCOIN_MAINNET_CHAIN_ID)
        ? "xitcoin_mainnet_rejected" : "unexpected_chain_id";
      throw error;
    }
    const live = answers.filter((answer) => answer.ok && !answer.value.catchingUp).map((answer) => answer.value);
    if (live.length < this.majoritySize) throw new XitcoinRpcDisagreement();
    return Object.freeze(live);
  }

  // Lowest committed height across origins.
  async tip() { return Math.min(...(await this.chainId()).map((status) => status.height)); }

  async block(height) {
    if (!Number.isSafeInteger(height) || height < 1) throw invalid();
    const block = await this.agree((origin) => origin.comet.call("block", { height: String(height) }),
      (value) => normalizeBlock(value, height));
    if (block.chainId !== XITCOIN_TESTNET_CHAIN_ID) throw invalid();
    return block;
  }

  txSettled(transactionHash) {
    const hash = lowerHash(transactionHash);
    return this.settled((origin) => origin.comet.call("tx_search", { query: `tx.hash='${hash.slice(2).toUpperCase()}'`,
      prove: false, page: "1", per_page: "2" }), (value) => normalizeTxSearch(value, hash));
  }

  mempools() {
    return this.each((origin) => origin.comet.call("unconfirmed_txs", { limit: "100" }), normalizeMempool);
  }

  // Identical bytes to every origin. Results are never decision inputs.
  async broadcast(signedHex) {
    if (typeof signedHex !== "string" || !/^0x(?:[0-9a-f]{2})+$/.test(signedHex)) throw invalid();
    const tx = Buffer.from(signedHex.slice(2), "hex").toString("base64");
    const settled = await Promise.allSettled(this.#origins.map((origin) => origin.comet.call("broadcast_tx_sync", { tx })));
    return Object.freeze(settled.map((result) => (result.status === "fulfilled" ? "accepted" : "rejected")));
  }

  #simulate(txBytes) {
    const data = encodeSimulateRequest(txBytes).toString("hex");
    return (origin) => origin.comet.call("abci_query", { path: "/cosmos.tx.v1beta1.Service/Simulate", data, prove: false });
  }

  // Execution verdict from every origin: failed only when every origin reports
  // an execution failure; mixed answers or any transport failure are temporary.
  async simulateEach(txBytes) {
    const values = await this.each(this.#simulate(txBytes), normalizeSimulation);
    if (values.every((value) => value.failed)) return Object.freeze({ failed: true, gasUsed: [] });
    if (values.some((value) => value.failed)) throw new XitcoinRpcDisagreement();
    return Object.freeze({ failed: false, gasUsed: Object.freeze(values.map((value) => BigInt(value.gasUsed))) });
  }

  // Execution verdict decided by a strict majority of origins.
  async simulateMajority(txBytes) {
    const answers = (await this.settled(this.#simulate(txBytes), normalizeSimulation)).filter((answer) => answer.ok);
    const failed = answers.filter((answer) => answer.value.failed), succeeded = answers.filter((answer) => !answer.value.failed);
    if (succeeded.length >= this.majoritySize) return Object.freeze({ failed: false });
    if (failed.length >= this.majoritySize) return Object.freeze({ failed: true });
    throw new XitcoinRpcDisagreement();
  }

  // ---- REST ----
  params() { return this.agree((origin) => origin.rest.get("/xitcoin/bridge/v1/params"), normalizeParams); }

  routes(routeId, height) {
    return this.each((origin) => origin.rest.get(`/xitcoin/bridge/v1/routes/${routeId}`, { height }), (value) => {
      const route = normalizeRoute(value);
      if (route.routeId !== routeId || (height !== undefined && route.height !== height)) throw invalid();
      return route;
    });
  }

  routeMajority(routeId) {
    return this.majority((origin) => origin.rest.get(`/xitcoin/bridge/v1/routes/${routeId}`), (value) => {
      const route = normalizeRoute(value);
      if (route.routeId !== routeId) throw invalid();
      const { height, controlNonce, outboundNonce, ...config } = route;
      return Object.freeze(config);
    });
  }

  #attestation(attestationId, height) {
    lowerHash(attestationId);
    return [(origin) => origin.rest.get(`/xitcoin/bridge/v1/attestations/${attestationId}`, { height }), (value) => {
      const answer = normalizeAttestation(value, attestationId);
      if (height !== undefined && answer.height !== height) throw invalid();
      return answer;
    }];
  }

  attestations(attestationId, height) { return this.each(...this.#attestation(attestationId, height)); }

  attestationsSettled(attestationId, height) { return this.settled(...this.#attestation(attestationId, height)); }

  attestationMajority(attestationId) {
    const [read, normalize] = this.#attestation(attestationId);
    return this.majority(read, (value) => {
      const { status, record } = normalize(value);
      return Object.freeze({ status, record });
    });
  }

  dailyUsages(height) {
    return this.each((origin) => origin.rest.get("/xitcoin/bridge/v1/daily_usage", { height }), (value) => {
      const usage = normalizeDailyUsage(value);
      if (height !== undefined && usage.height !== height) throw invalid();
      return usage;
    });
  }

  outstandings(height) {
    return this.each((origin) => origin.rest.get("/xitcoin/bridge/v1/outstanding", { height }), (value) => {
      const outstanding = normalizeOutstanding(value);
      if (height !== undefined && outstanding.height !== height) throw invalid();
      return outstanding;
    });
  }

  accounts(address) {
    return this.each((origin) => origin.rest.get(`/cosmos/auth/v1beta1/accounts/${address}`), (value) => normalizeAccount(value, address));
  }

  // The account sequence at one committed height on every origin, 0 when every
  // origin reports that the account did not exist yet (HTTP 404).
  async sequenceAt(address, height) {
    if (!Number.isSafeInteger(height) || height < 1) throw invalid();
    const answers = await this.settled((origin) => origin.rest.get(`/cosmos/auth/v1beta1/accounts/${address}`, { height }),
      (value) => normalizeAccount(value, address).sequence);
    if (answers.every((answer) => !answer.ok && answer.error.code === "http_status" && answer.error.httpStatus === 404)) return 0;
    const failure = answers.find((answer) => !answer.ok);
    if (failure) throw failure.error;
    if (answers.some((answer) => answer.value !== answers[0].value)) throw new XitcoinRpcDisagreement();
    return answers[0].value;
  }

  accountMajority(address) {
    return this.majority((origin) => origin.rest.get(`/cosmos/auth/v1beta1/accounts/${address}`), (value) => normalizeAccount(value, address));
  }

  balances(address) {
    return this.each((origin) => origin.rest.get(`/cosmos/bank/v1beta1/balances/${address}/by_denom?denom=${FEE_DENOM}`), normalizeBalance);
  }

  feeMarkets() { return this.each((origin) => origin.rest.get("/cosmos/evm/feemarket/v1/params"), normalizeFeeMarket); }
}
