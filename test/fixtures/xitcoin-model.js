// Deterministic in-memory model of Xitcoin origins (CometBFT JSON-RPC and
// Cosmos SDK REST) served through an injected fetch, for adapter decision
// tests. It is not a chain: integration tests use a real xitcoind node.
import { createHash } from "node:crypto";
import { SigningKey, computeAddress } from "ethers";
import { evmAddressToBech32 } from "../../src/address.js";
import { XITCOIN_TESTNET_ROUTE_ID, attestationId, attestationPayloadHash } from "../../src/protocol.js";
import { keys, signers } from "./destination.js";

export const SUBMITTER_KEY = new SigningKey(`0x${"05".padStart(64, "0")}`);
export const SUBMITTER = evmAddressToBech32(computeAddress(SUBMITTER_KEY.publicKey));
const upper = (hash) => hash.slice(2).toUpperCase();
const sha = (bytes) => `0x${createHash("sha256").update(bytes).digest("hex")}`;
const time = (unix) => new Date(unix * 1000).toISOString().replace(".000Z", ".123456789Z");

export function recordFor(request, approvals, { txHash, height, overrides = {} }) {
  const p = request.payload;
  return { attestation_id: attestationId({ ...p, direction: request.direction }), route_id: p.routeId, direction: request.direction,
    source_chain_id: p.sourceChainId, source_ref: p.sourceRef.slice(2), nonce: p.nonce, recipient: p.destination, amount: p.amount,
    deadline_unix: String(p.deadlineUnix), signer_set_version: "1", approvers: approvals.map((approval) => approval.signer),
    destination_chain_id: "xitcoin-testnet-v2-1", payload_hash: attestationPayloadHash({ ...p, direction: request.direction }), signing_digest: request.digest,
    height: String(height), tx_hash: upper(txHash), ...overrides };
}

// `state` is shared by every origin; `faults[origin]` may rewrite answers:
// return a replacement body, "hang", or { httpStatus, body } for REST.
export function xitcoinModel({ origins = 2 } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const state = {
    height: 100, time: now, chainId: "xitcoin-testnet-v2-1",
    route: { route_id: XITCOIN_TESTNET_ROUTE_ID, source_chain_id: "338", bridge_signers: [...signers], guardian: computeAddress(keys[3].publicKey),
      max_transfer_amount: (10n ** 22n).toString(), daily_limit: (10n ** 23n).toString(), max_outstanding_amount: (10n ** 24n).toString(),
      enabled: true, paused: false, signer_set_version: "1", control_nonce: "0", outbound_nonce: "0" },
    routeAt: null, // (height) => route override for height-pinned reads
    usageAt: null, outstandingAt: null,
    usage: { used: "0" }, outstanding: { amount: "0" },
    attestations: new Map(), // id -> { status, record }
    account: { number: "5", sequence: 0, publicKey: null },
    balance: 10n ** 24n,
    baseFee: "1000000000.000000000000000000", minGasPrice: "0.000000000000000000",
    simulation: { code: 0, gasUsed: 180_000n },
    txs: new Map(), // hash -> { height, code, txHex, gasWanted, gasUsed, accSeq }
    blockTimes: new Map(), // height -> unix
    mempool: [], broadcasts: [],
  };
  const faults = Array.from({ length: origins }, () => null);
  const urls = Array.from({ length: origins }, (_, index) => ({ rpcUrl: `https://rpc${index}.example`, restUrl: `https://rest${index}.example` }));
  const blockHash = (height) => sha(Buffer.from(`block ${height}`));

  function comet(method, params) {
    switch (method) {
      case "status": return { node_info: { network: state.chainId }, sync_info: { latest_block_height: String(state.height),
        latest_block_hash: upper(blockHash(state.height)), latest_block_time: time(state.time), catching_up: false } };
      case "block": {
        const height = Number(params.height);
        const txs = [...state.txs.values()].filter((tx) => tx.height === height).map((tx) => Buffer.from(tx.txHex.slice(2), "hex").toString("base64"));
        return { block_id: { hash: upper(blockHash(height)) }, block: { header: { chain_id: state.chainId, height: String(height),
          time: time(state.blockTimes.get(height) ?? state.time) }, data: { txs } } };
      }
      case "tx_search": {
        const hash = `0x${params.query.match(/tx\.hash='([0-9A-F]{64})'/)[1].toLowerCase()}`;
        const tx = state.txs.get(hash);
        if (!tx) return { txs: [], total_count: "0" };
        return { txs: [{ hash: upper(hash), height: String(tx.height), index: 0, tx: Buffer.from(tx.txHex.slice(2), "hex").toString("base64"),
          tx_result: { code: tx.code, data: null, log: "", info: "", gas_wanted: String(tx.gasWanted), gas_used: String(tx.gasUsed),
            codespace: tx.code ? "undefined" : "", events: tx.accSeq.map((value) => ({ type: "tx", attributes: [{ key: "acc_seq", value, index: true }] })) } }],
        total_count: "1" };
      }
      case "unconfirmed_txs": return { n_txs: String(state.mempool.length), total: String(state.mempool.length), total_bytes: "0",
        txs: state.mempool.length ? state.mempool.map((hex) => Buffer.from(hex.slice(2), "hex").toString("base64")) : null };
      case "broadcast_tx_sync": state.broadcasts.push(`0x${Buffer.from(params.tx, "base64").toString("hex")}`); return { code: 0 };
      case "abci_query": {
        if (state.simulation.code) return { response: { code: state.simulation.code, log: "failed", value: null, height: String(state.height) } };
        const gas = state.simulation.gasUsed;
        const varint = (value) => { const out = []; do { out.push(Number(value & 127n) | (value > 127n ? 128 : 0)); value >>= 7n; } while (value); return out; };
        const info = Buffer.from([0x08, 0x01, 0x10, ...varint(gas)]);
        return { response: { code: 0, value: Buffer.concat([Buffer.from([0x0a, info.length]), info]).toString("base64"), height: String(state.height) } };
      }
      default: throw new Error(`unexpected method ${method}`);
    }
  }

  function rest(path, height) {
    const at = height === undefined ? state.height : Number(height);
    if (path === "/xitcoin/bridge/v1/params") return { params: { authority: "xtc1vza8zsgvrfwmve084ytd8xqdkkm7u9e5csctc2", native_denom: "axtc",
      max_supply: "5250000000000000000000000000", required_approvals: 2, signer_set_size: 3, chain_id: state.chainId,
      attestation_domain: `xitcoin-bridge-attestation-v2/${state.chainId}`, control_domain: `xitcoin-bridge-control-v2/${state.chainId}`,
      guardian_pause_domain: `xitcoin-bridge-guardian-pause-v2/${state.chainId}`, source_deposit_domain: "xitcoin-bridge-source-deposit-v1" } };
    if (path.startsWith("/xitcoin/bridge/v1/routes/")) return { route: { ...(state.routeAt?.(at) ?? state.route) }, height: String(at) };
    if (path.startsWith("/xitcoin/bridge/v1/attestations/")) {
      const id = path.split("/").pop();
      const entry = state.attestations.get(id) ?? { status: "absent", record: null };
      const status = { absent: "ATTESTATION_STATE_ABSENT", processed: "ATTESTATION_STATE_PROCESSED",
        processed_without_record: "ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD" }[entry.status];
      return { attestation_id: id, status, processed: entry.status !== "absent", record: entry.record, height: String(at) };
    }
    if (path === "/xitcoin/bridge/v1/daily_usage") {
      const usage = state.usageAt?.(at) ?? state.usage;
      const limit = BigInt((state.routeAt?.(at) ?? state.route).daily_limit), used = BigInt(usage.used);
      return { route_id: XITCOIN_TESTNET_ROUTE_ID, utc_day: String(Math.floor((usage.time ?? state.time) / 86_400)), utc_date: "2026-11-28",
        used_amount: usage.used, daily_limit: limit.toString(), remaining_amount: (used > limit ? 0n : limit - used).toString(),
        block_time_unix: String(state.time), height: String(at) };
    }
    if (path === "/xitcoin/bridge/v1/outstanding") {
      const outstanding = state.outstandingAt?.(at) ?? state.outstanding;
      const cap = BigInt((state.routeAt?.(at) ?? state.route).max_outstanding_amount);
      return { route_id: XITCOIN_TESTNET_ROUTE_ID, outstanding_amount: outstanding.amount, max_outstanding_amount: cap.toString(),
        remaining_amount: (cap - BigInt(outstanding.amount)).toString(), height: String(at) };
    }
    if (path === `/cosmos/auth/v1beta1/accounts/${SUBMITTER}`) return { account: { "@type": "/cosmos.auth.v1beta1.BaseAccount", address: SUBMITTER,
      pub_key: state.account.publicKey ? { "@type": "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey",
        key: Buffer.from(state.account.publicKey.slice(2), "hex").toString("base64") } : null,
      account_number: state.account.number,
      sequence: String(height !== undefined && state.account.sequenceAt ? state.account.sequenceAt(at) : state.account.sequence) } };
    if (path.startsWith(`/cosmos/bank/v1beta1/balances/${SUBMITTER}/by_denom`)) return { balance: { denom: "axtc", amount: state.balance.toString() } };
    if (path === "/cosmos/evm/feemarket/v1/params") return { params: { no_base_fee: false, base_fee_change_denominator: 8, elasticity_multiplier: 2,
      enable_height: "0", base_fee: state.baseFee, min_gas_price: state.minGasPrice, min_gas_multiplier: "0.500000000000000000" } };
    return undefined;
  }

  async function fetchImpl(url, init) {
    const target = new URL(url);
    const index = urls.findIndex((origin) => target.origin === new URL(origin.rpcUrl).origin || target.origin === new URL(origin.restUrl).origin);
    const kind = target.origin === new URL(urls[index].rpcUrl).origin ? "rpc" : "rest";
    let status = 200, body;
    if (kind === "rpc") {
      const request = JSON.parse(init.body);
      const result = comet(request.method, request.params);
      body = { jsonrpc: "2.0", id: request.id, result };
      const fault = faults[index]?.({ kind, method: request.method, params: request.params, body });
      if (fault !== undefined) body = fault;
    } else {
      const path = `${target.pathname}${target.search}`;
      const result = rest(path, init.headers?.["x-cosmos-block-height"]);
      if (result === undefined) { status = 404; body = { code: 5, message: "not found" }; } else body = result;
      const fault = faults[index]?.({ kind, path, height: init.headers?.["x-cosmos-block-height"], body });
      if (fault !== undefined) {
        if (fault === "hang") return new Promise(() => {});
        if (fault?.httpStatus) { status = fault.httpStatus; body = fault.body ?? {}; } else body = fault;
      }
    }
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }

  // Commits a transaction in a block at the current height.
  function commit(txHex, { code = 0, gasWanted = 300_000, gasUsed = 180_000, accSeq = [], height = state.height } = {}) {
    const hash = sha(Buffer.from(txHex.slice(2), "hex"));
    state.txs.set(hash, { height, code, txHex, gasWanted, gasUsed, accSeq });
    return hash;
  }

  return { state, faults, urls, fetchImpl, commit, blockHash, upper };
}
