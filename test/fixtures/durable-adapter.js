// Deterministic destination model for engine tests only. It is NOT a chain
// adapter: production adapters derive every decision from independent,
// bounded canonical observations. The model lives outside the "process" so
// a restarted engine sees the same simulated chain.
import { keccak256 } from "ethers";
import { attestationId, DIRECTION_OUTBOUND } from "../../src/protocol.js";
import { RelayStore } from "../../src/store.js";
import { buildTransferApprovalRequest } from "../../src/coordinator.js";
import { evmAddressToBech32 } from "../../src/address.js";
import { cronosRouteId } from "../../src/protocol.js";
import { sign, signers } from "./destination.js";

const encode = (value) => `0x${Buffer.from(JSON.stringify(value)).toString("hex")}`;
const decode = (hex) => JSON.parse(Buffer.from(hex.slice(2), "hex").toString());

export class ModelChain {
  constructor() {
    Object.assign(this, { height: 100, nonce: 0, paused: false, mempool: new Map(), receipts: new Map(),
      processed: new Map(), deliveries: [], foreign: 0, failNext: false, sendMode: "deliver" });
  }
  receive(signedHex) {
    const hash = keccak256(signedHex);
    this.deliveries.push(hash);
    if (!this.receipts.has(hash)) this.mempool.set(hash, signedHex);
    return hash;
  }
  mine() {
    for (const [hash, hex] of [...this.mempool]) {
      const tx = decode(hex);
      if (tx.nonce !== this.nonce) continue;
      this.height += 1;
      const status = this.failNext || this.paused || this.processed.has(tx.transferId) ? 0 : 1;
      this.failNext = false;
      this.receipts.set(hash, { blockNumber: this.height, blockHash: `0x${this.height.toString(16).padStart(64, "0")}`, status });
      if (status === 1) this.processed.set(tx.transferId, hash);
      this.nonce += 1;
      this.mempool.delete(hash);
    }
  }
  confirm(blocks) { this.height += blocks; }
  reorg(hash) {
    const receipt = this.receipts.get(hash);
    if (!receipt) return;
    this.receipts.delete(hash);
    const tx = [...this.processed].find(([, value]) => value === hash);
    if (tx) this.processed.delete(tx[0]);
    this.nonce -= 1;
  }
  foreignTransaction() { this.nonce += 1; this.foreign += 1; }
  distinctDeliveries() { return new Set(this.deliveries).size; }
}

export function modelAdapter(destination, chain, { maxBroadcastAttempts = 3, confirmations = 3, marginSeconds = 60, ledger } = {}) {
  const transferId = (request) => request.direction === DIRECTION_OUTBOUND ? request.payload.sourceBurnId : attestationId(request.payload);
  return {
    destination, maxBroadcastAttempts,
    transferId,
    async assess({ request, transferId: id, nowUnix }) {
      if (chain.rpcFailure) throw new Error("rpc_disagreement");
      if (chain.paused) return { action: "wait", code: "route_paused" };
      if (chain.processed.has(id)) return { action: "halt", code: "processed_without_local_transaction" };
      if (request.deadlineUnix < nowUnix + marginSeconds) return { action: "wait", code: "approval_expired_awaiting_reissue" };
      return { action: "sign", context: { ok: true } };
    },
    async sign({ request, transferId: id, expectedNonce, context }) {
      if (!context?.ok) throw new Error("missing context");
      if (expectedNonce !== null && expectedNonce !== chain.nonce) return { action: "halt", code: "account_nonce_not_owned" };
      if (chain.mempool.size) return { action: "halt", code: "foreign_pending_transaction" };
      const signedHex = encode({ transferId: id, nonce: chain.nonce, approvalDigest: request.digest, destination });
      return { action: "signed", nonce: chain.nonce, signedHex, transactionHash: keccak256(signedHex) };
    },
    async verifyStored({ row, request }) {
      const tx = decode(row.signedHex);
      if (tx.transferId !== row.transferId || tx.approvalDigest !== request.digest || tx.nonce !== row.nonce
          || keccak256(row.signedHex) !== row.transactionHash) return { action: "halt", code: "stored_transaction_mismatch" };
      return { action: "valid" };
    },
    async beforeFirstSend({ row }) {
      if (chain.nonce !== row.nonce) return { action: "halt", code: "nonce_consumed_before_send" };
      if (chain.processed.has(row.transferId)) return { action: "halt", code: "processed_by_foreign_transaction" };
      if (chain.paused) return { action: "wait", code: "route_paused" };
      return { action: "send" };
    },
    async send({ row }) {
      // Every send must carry bytes already committed with a write-ahead marker.
      const stored = ledger?.().inspect(row.transferId);
      if (ledger && (stored.state !== "broadcast" || stored.signedHex !== row.signedHex
          || stored.broadcastAttempts !== row.broadcastAttempts)) throw new Error("UNPERSISTED SEND");
      if (chain.sendMode === "lost") throw new Error("timeout before delivery");
      chain.receive(row.signedHex);
      if (chain.sendMode === "ambiguous") throw new Error("timeout after delivery");
    },
    async observe({ row }) {
      if (chain.rpcFailure) throw new Error("rpc_disagreement");
      const receipt = chain.receipts.get(row.transactionHash);
      if (receipt) {
        if (chain.height - receipt.blockNumber + 1 < confirmations) return { action: "pending" };
        return { action: receipt.status === 1 ? "finalized" : "failed", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
      }
      if (chain.mempool.has(row.transactionHash)) return { action: "pending" };
      if (chain.nonce > row.nonce) return { action: "halt", code: "nonce_consumed_without_receipt" };
      if (chain.processed.has(row.transferId)) return { action: "halt", code: "processed_by_foreign_transaction" };
      if (chain.paused) return { action: "wait", code: "route_paused" };
      if (row.broadcastAttempts >= maxBroadcastAttempts) return { action: "halt", code: "broadcast_attempts_exhausted" };
      return { action: "rebroadcast" };
    },
  };
}

// Persist an approved transfer exactly as the approval-only coordinator does.
export function approvedTransfer(store, destination, index = 1, { deadlineUnix = 2_000_000_000 } = {}) {
  const ref = `0x${index.toString(16).padStart(64, "0")}`;
  const vault = "0x1c94273C0b199b139D82da3786C9eCbE189D5919";
  const common = { blockHeight: 10 + index, blockHash: `0x${"aa".repeat(32)}`, transactionHash: `0x${"bb".repeat(32)}` };
  if (destination === "cronos") {
    store.observe({ sourceChain: "xitcoin", sourceRef: ref, routeId: "cronos-testnet-xitcoin-testnet", ...common, messageIndex: 0,
      payload: { requestId: ref, sender: "xtc1sender", destination: signers[0], amount: "10", nonce: String(index) } });
  } else {
    store.observe({ sourceChain: "cronos", sourceRef: ref.slice(2), routeId: cronosRouteId("cronos-testnet-xitcoin-testnet"), ...common, logIndex: 0,
      payload: { depositId: ref, depositor: signers[1], recipient: signers[0], destination: evmAddressToBech32(signers[0]),
        amount: "10", nonce: String(index) } });
  }
  const sourceChain = destination === "cronos" ? "xitcoin" : "cronos";
  const sourceRef = destination === "cronos" ? ref : ref.slice(2);
  const transfer = store.transition(sourceChain, sourceRef, "finalized");
  const request = buildTransferApprovalRequest({ transfer, routeId: "cronos-testnet-xitcoin-testnet",
    cronosRouteId: cronosRouteId("cronos-testnet-xitcoin-testnet"), cronosChainId: 338, cronosVault: vault,
    xitcoinChainId: "xitcoin-testnet-v2-1", signerSetVersion: 1, deadlineUnix });
  store.persistApprovalRequest(sourceChain, sourceRef, request);
  for (const approval of sign(request)) store.recordApproval(sourceChain, sourceRef, approval);
  store.transition(sourceChain, sourceRef, "approved");
  return { sourceChain, sourceRef, request };
}

export function openStore(path) { return new RelayStore(path); }
