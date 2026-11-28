// Deterministic destination model for engine tests only. It is NOT a chain
// adapter: production adapters derive every decision from independent,
// bounded canonical observations. The model lives outside the "process" so
// a restarted engine sees the same simulated chain.
import { keccak256 } from "ethers";
import { XITCOIN_TESTNET_ROUTE_ID, attestationId, DIRECTION_OUTBOUND } from "../../src/protocol.js";
import { RelayStore } from "../../src/store.js";
import { buildTransferApprovalRequest } from "../../src/coordinator.js";
import { evmAddressToBech32 } from "../../src/address.js";
import { TESTNET_ROUTE_ID } from "../../src/preflight.js";
import { sign, signers } from "./destination.js";

const encode = (value) => `0x${Buffer.from(JSON.stringify(value)).toString("hex")}`;
const decode = (hex) => JSON.parse(Buffer.from(hex.slice(2), "hex").toString());

export class ModelChain {
  constructor() {
    Object.assign(this, { height: 100, nonce: 0, paused: false, mempool: new Map(), receipts: new Map(),
      processed: new Map(), deliveries: [], foreign: 0, failNext: false, sendMode: "deliver", invalid: new Set(),
      time: 1_900_000_000, unverified: new Set(), short: new Set() });
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
      const expired = this.time > tx.deadline;
      const status = this.failNext || this.paused || this.processed.has(tx.transferId) || expired ? 0 : 1;
      this.failNext = false;
      this.receipts.set(hash, { blockNumber: this.height, blockHash: `0x${this.height.toString(16).padStart(64, "0")}`, status,
        timestamp: this.time });
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
  // Anyone may call the vault with valid approvals, e.g. by copying pending calldata.
  foreignRelease(transferId) {
    this.height += 1;
    const hash = keccak256(Buffer.from(`foreign release ${transferId} ${this.height}`));
    this.receipts.set(hash, { blockNumber: this.height, blockHash: `0x${this.height.toString(16).padStart(64, "0")}`, status: 1 });
    this.processed.set(transferId, hash);
    return hash;
  }
  distinctDeliveries() { return new Set(this.deliveries).size; }
}

export function modelAdapter(destination, chain, { maxBroadcastAttempts = 3, confirmations = 3, marginSeconds = 60, ledger } = {}) {
  const transferId = (request) => request.direction === DIRECTION_OUTBOUND ? request.payload.sourceBurnId : attestationId(request.payload);
  const final = (receipt) => chain.height - receipt.blockNumber + 1 >= confirmations;
  // A release by another transaction, proven by its finalized receipt.
  const elsewhere = (id, ours) => {
    const hash = chain.processed.get(id);
    if (!hash || hash === ours) return null;
    const receipt = chain.receipts.get(hash);
    return final(receipt) ? { action: "released_elsewhere", releaseHash: hash, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash }
      : { action: "wait", code: "release_elsewhere_not_final", defer: true };
  };
  return {
    destination, maxBroadcastAttempts,
    transferId,
    async assess({ request, transferId: id, nowUnix }) {
      if (chain.rpcFailure) throw new Error("rpc_disagreement");
      if (chain.paused) return { action: "wait", code: "route_paused" };
      if (chain.invalid.has(id)) return { action: "reject", code: "invalid_recipient" };
      if (chain.unverified.has(id)) return { action: "release_unverified" };
      if (chain.processed.has(id)) return elsewhere(id, null);
      if (request.deadlineUnix < nowUnix + marginSeconds) return { action: "wait", code: "approval_expired_awaiting_reissue", defer: true };
      if (chain.short.has(id)) return { action: "wait", code: "insufficient_vault_liquidity", defer: true };
      return { action: "sign", context: { ok: true } };
    },
    async sign({ request, transferId: id, expectedNonce, context }) {
      if (!context?.ok) throw new Error("missing context");
      if (expectedNonce !== null && expectedNonce !== chain.nonce) return { action: "halt", code: "account_nonce_not_owned" };
      if (chain.mempool.size) return { action: "halt", code: "foreign_pending_transaction" };
      const signedHex = encode({ transferId: id, nonce: chain.nonce, approvalDigest: request.digest, destination, deadline: request.deadlineUnix });
      return { action: "signed", nonce: chain.nonce, signedHex, transactionHash: keccak256(signedHex) };
    },
    async verifyStored({ row, request }) {
      const tx = decode(row.signedHex);
      if (tx.transferId !== row.transferId || tx.approvalDigest !== request.digest || tx.nonce !== row.nonce
          || keccak256(row.signedHex) !== row.transactionHash) return { action: "halt", code: "stored_transaction_mismatch" };
      return { action: "valid" };
    },
    async beforeFirstSend({ row, request, nowUnix }) {
      if (chain.nonce !== row.nonce) return { action: "halt", code: "nonce_consumed_before_send" };
      // Approval no longer usable: send the identical bytes once to consume the nonce.
      if (request.deadlineUnix < Math.max(nowUnix, chain.time) + marginSeconds) return { action: "send" };
      if (chain.paused) return { action: "wait", code: "route_paused" };
      // Released elsewhere: still send the identical bytes once so their
      // reserved nonce is consumed (they revert); then observe the release.
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
        if (!final(receipt)) return { action: "pending" };
        if (receipt.status === 0 && chain.processed.has(row.transferId)) {
          const released = elsewhere(row.transferId, row.transactionHash);
          return released?.action === "released_elsewhere" ? released : { action: "pending" };
        }
        if (receipt.status === 0 && receipt.timestamp > decode(row.signedHex).deadline) {
          return { action: "expired", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
        }
        if (receipt.status === 0 && chain.lastingCause) {
          return { action: "reverted", code: chain.lastingCause, blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
        }
        return { action: receipt.status === 1 ? "finalized" : "failed", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
      }
      if (chain.mempool.has(row.transactionHash)) return { action: "pending" };
      if (chain.nonce > row.nonce) return { action: "halt", code: "nonce_consumed_without_receipt" };
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
    store.observe({ sourceChain: "xitcoin", sourceRef: ref, routeId: XITCOIN_TESTNET_ROUTE_ID, ...common, messageIndex: 0,
      payload: { requestId: ref, sender: "xtc1sender", destination: signers[0], amount: "10", nonce: String(index) } });
  } else {
    store.observe({ sourceChain: "cronos", sourceRef: ref.slice(2), routeId: TESTNET_ROUTE_ID, ...common, logIndex: 0,
      payload: { depositId: ref, depositor: signers[1], recipient: signers[0], destination: evmAddressToBech32(signers[0]),
        amount: "10", nonce: String(index) } });
  }
  const sourceChain = destination === "cronos" ? "xitcoin" : "cronos";
  const sourceRef = destination === "cronos" ? ref : ref.slice(2);
  const transfer = store.transition(sourceChain, sourceRef, "finalized");
  const request = buildTransferApprovalRequest({ transfer, routeId: XITCOIN_TESTNET_ROUTE_ID,
    cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: vault,
    xitcoinChainId: "xitcoin-testnet-v2-1", signerSetVersion: 1, deadlineUnix });
  store.persistApprovalRequest(sourceChain, sourceRef, request);
  for (const approval of sign(request)) store.recordApproval(sourceChain, sourceRef, approval);
  store.transition(sourceChain, sourceRef, "approved");
  return { sourceChain, sourceRef, request };
}

// The coordinator side of an approved-transfer re-issue, after its
// destination proof: the transfer returns to finalized with a re-issued
// request for the same source event and is approved again.
export function reapproveTransfer(store, sourceChain, sourceRef, { deadlineUnix, nowUnix }) {
  const previous = store.approvalRequest(sourceChain, sourceRef);
  const transfer = store.get(sourceChain, sourceRef);
  const next = buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" }, routeId: XITCOIN_TESTNET_ROUTE_ID,
    cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: "0x1c94273C0b199b139D82da3786C9eCbE189D5919",
    xitcoinChainId: "xitcoin-testnet-v2-1", signerSetVersion: 1, deadlineUnix });
  store.returnForReissue(sourceChain, sourceRef, previous, next, { nowUnix });
  for (const approval of sign(next)) store.recordApproval(sourceChain, sourceRef, approval);
  store.transition(sourceChain, sourceRef, "approved");
  return next;
}

export function openStore(path) { return new RelayStore(path); }
