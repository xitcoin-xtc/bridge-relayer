import { Interface, getAddress, keccak256 } from "ethers";

import { CronosRpcQuorum } from "./cronos-rpc.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "./protocol.js";
import { inFlightFromStore } from "./reconciler.js";
import { RelayStore } from "./store.js";
import { XitcoinRpcQuorum } from "./xitcoin-rpc.js";

// Read-only chain readers behind ReconciliationSource (src/reconciler.js).
// They hold no key, build no transaction and send nothing. Every value is read
// at one pinned height that every origin serves, and every origin must return
// the identical normalized answer:
//   - Cronos: the vault's locked balance (`availableLiquidity()`, which is
//     `asset.balanceOf(vault)`) at the finalized height `tip - confirmations`
//     (tip = the lowest head across origins), with the block hash agreed by
//     every origin before and after the read and the vault's runtime code
//     checked against the pinned hash at that height;
//   - Xitcoin: the bridge module's `outstanding_amount` and the route's daily
//     usage (`/xitcoin/bridge/v1/outstanding`, `/xitcoin/bridge/v1/daily_usage`)
//     at the lowest committed height across origins (CometBFT commits are
//     final), pinned with `x-cosmos-block-height`, with that block agreed by
//     every origin.
// A missing, failing or invalid origin answer is `unavailable`; different
// valid answers are a `disagreement`; a vault code or route that is not the
// pinned one is an `identity_mismatch`. None of them is evidence of a deficit.
export const RECONCILIATION_READ_FAILURES = Object.freeze(["unavailable", "disagreement", "identity_mismatch"]);

export class ReconciliationReadError extends Error {
  constructor(kind, code) {
    super(`reconciliation read ${kind}`);
    this.name = "ReconciliationReadError";
    this.kind = RECONCILIATION_READ_FAILURES.includes(kind) ? kind : "unavailable";
    this.code = typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "read_failed";
  }
}

const HASH = /^0x[0-9a-f]{64}$/;
const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const VAULT = new Interface(["function availableLiquidity() view returns (uint256)"]);
const LIQUIDITY = Object.freeze({ data: VAULT.encodeFunctionData("availableLiquidity") });
const stable = (value) => JSON.stringify(value);

function classify(error, chain) {
  if (error instanceof ReconciliationReadError) return error;
  // Both quorum transports name a disagreement `rpc_disagreement`; everything
  // else (transport failure, provider error, invalid response) is unavailable.
  if (error?.code === "rpc_disagreement") return new ReconciliationReadError("disagreement", `${chain}_origin_disagreement`);
  if (error?.code === "unexpected_chain_id" || error?.code === "cronos_mainnet_rejected" || error?.code === "xitcoin_mainnet_rejected") {
    return new ReconciliationReadError("identity_mismatch", `${chain}_chain_mismatch`);
  }
  return new ReconciliationReadError("unavailable", `${chain}_origin_unavailable`);
}

function agreed(values, chain, what) {
  if (!Array.isArray(values) || values.length < 2) throw new ReconciliationReadError("unavailable", `${chain}_origin_unavailable`);
  if (values.some((value) => stable(value) !== stable(values[0]))) {
    throw new ReconciliationReadError("disagreement", `${chain}_${what}_disagreement`);
  }
  return values[0];
}

function uint256(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) throw new ReconciliationReadError("unavailable", "cronos_invalid_balance");
  return BigInt(value);
}

export function createCronosVaultReader({ rpc, vault, vaultCodeHash, confirmations }) {
  if (!(rpc instanceof CronosRpcQuorum)) throw new Error("a bounded Cronos quorum transport is required");
  const target = getAddress(vault);
  if (typeof vaultCodeHash !== "string" || !HASH.test(vaultCodeHash) || vaultCodeHash === EMPTY_CODE_HASH
      || /^0x0{64}$/.test(vaultCodeHash)) throw new Error("vault runtime code hash is invalid");
  if (!Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 10_000) throw new Error("Cronos confirmations are invalid");
  return Object.freeze({
    async vaultLocked() {
      try {
        await rpc.chainId();
        const height = (await rpc.tip()) - confirmations;
        if (height < 1) throw new ReconciliationReadError("unavailable", "cronos_history_too_short");
        const block = await rpc.block(height);
        if (keccak256(await rpc.code(target, height)) !== vaultCodeHash) {
          throw new ReconciliationReadError("identity_mismatch", "vault_code_mismatch");
        }
        const amount = uint256(await rpc.call({ to: target, data: LIQUIDITY.data }, height));
        // The finalized block must not have changed while it was being read.
        if ((await rpc.block(height)).hash !== block.hash) throw new ReconciliationReadError("disagreement", "cronos_block_changed");
        return Object.freeze({ amount, height, blockHash: block.hash, blockTime: block.timestamp });
      } catch (error) { throw classify(error, "cronos"); }
    },
  });
}

export function createXitcoinBridgeReader({ rpc, routeId = XITCOIN_TESTNET_ROUTE_ID }) {
  if (!(rpc instanceof XitcoinRpcQuorum)) throw new Error("a bounded Xitcoin quorum transport is required");
  if (routeId !== XITCOIN_TESTNET_ROUTE_ID) throw new Error("Xitcoin route is not the pinned testnet route");
  return Object.freeze({
    async chainOutstanding() {
      try {
        const height = Math.min(...(await rpc.chainId()).map((status) => status.height));
        if (!Number.isSafeInteger(height) || height < 1) throw new ReconciliationReadError("unavailable", "xitcoin_history_too_short");
        const block = await rpc.block(height);
        const outstanding = agreed(await rpc.outstandings(height), "xitcoin", "outstanding");
        const usage = agreed(await rpc.dailyUsages(height), "xitcoin", "daily_usage");
        if (outstanding.routeId !== routeId || usage.routeId !== routeId) throw new ReconciliationReadError("identity_mismatch", "xitcoin_route_mismatch");
        if (usage.blockTime !== block.time) throw new ReconciliationReadError("unavailable", "xitcoin_inconsistent_height");
        return Object.freeze({
          amount: BigInt(outstanding.outstandingAmount), height, blockHash: block.hash, blockTime: block.time,
          maxOutstandingAmount: outstanding.maxOutstandingAmount,
          dailyUsage: Object.freeze({ utcDay: usage.utcDay, usedAmount: usage.usedAmount, dailyLimit: usage.dailyLimit,
            remainingAmount: usage.remainingAmount }),
        });
      } catch (error) { throw classify(error, "xitcoin"); }
    },
  });
}

// A complete ReconciliationSource: the two chain readers above and the
// in-flight totals of the coordinator store.
export function createChainReconciliationSource({ cronos, xitcoin, store }) {
  if (!cronos || typeof cronos.vaultLocked !== "function" || !xitcoin || typeof xitcoin.chainOutstanding !== "function") {
    throw new Error("Cronos and Xitcoin readers are required");
  }
  if (!(store instanceof RelayStore)) throw new Error("the coordinator store is required");
  return Object.freeze({
    vaultLocked: () => cronos.vaultLocked(),
    chainOutstanding: () => xitcoin.chainOutstanding(),
    async inFlight() { return inFlightFromStore(store); },
  });
}

// Builds both readers on the bounded quorum transports from independent
// origins (at least two per chain; Xitcoin origins pair one operator's
// CometBFT RPC with its REST API).
export function connectReconciliationSource({ cronosRpcUrls, xitcoinOrigins, vault, vaultCodeHash, confirmations, routeId,
  store, allowLoopbackHttp = false, fetchImpl = globalThis.fetch }) {
  return createChainReconciliationSource({
    cronos: createCronosVaultReader({ rpc: new CronosRpcQuorum({ urls: cronosRpcUrls, allowLoopbackHttp, fetchImpl }),
      vault, vaultCodeHash, confirmations }),
    xitcoin: createXitcoinBridgeReader({ rpc: new XitcoinRpcQuorum({ origins: xitcoinOrigins, allowLoopbackHttp, fetchImpl }), routeId }),
    store,
  });
}
