import { BoundedJsonRpcClient, independentEndpoints } from "./bounded-transport.js";
import { RpcInvalid, normalizeBlock, normalizeLog, normalizeReceipt, safeQuantity } from "./cronos-rpc.js";

// Read-only Cronos providers for CronosFinalizedWatcher over the bounded
// JSON-RPC transport: one per independent origin, exposing only the four reads
// the watcher performs, each answer normalized to the exact fields it uses.
// Removed (reorganized) logs are never returned as events.
const hex = (number) => {
  if (!Number.isSafeInteger(number) || number < 0) throw new RpcInvalid();
  return `0x${number.toString(16)}`;
};

export function boundedCronosProviders({ urls, allowLoopbackHttp = false, timeoutMs = 10_000, maxBytes = 2 * 1024 * 1024,
  fetchImpl = globalThis.fetch }) {
  return Object.freeze(independentEndpoints(urls, { allowLoopbackHttp }).map((url) => {
    const client = new BoundedJsonRpcClient({ url: url.href, allowLoopbackHttp, timeoutMs, maxBytes, fetchImpl });
    return Object.freeze({
      async getBlockNumber() { return safeQuantity(await client.call("eth_blockNumber", [])); },
      async getBlock(height) {
        const value = await client.call("eth_getBlockByNumber", [hex(height), false]);
        if (value === null) return null;
        const block = normalizeBlock(value);
        if (block.number !== height) throw new RpcInvalid();
        return block;
      },
      async getLogs({ address, topics, fromBlock, toBlock }) {
        const value = await client.call("eth_getLogs", [{ address, topics, fromBlock: hex(fromBlock), toBlock: hex(toBlock) }]);
        if (!Array.isArray(value) || value.length > 10_000) throw new RpcInvalid();
        const logs = value.map(normalizeLog);
        if (logs.some((log) => log.removed)) throw new RpcInvalid();
        return logs;
      },
      async getTransactionReceipt(transactionHash) {
        return normalizeReceipt(await client.call("eth_getTransactionReceipt", [transactionHash]));
      },
    });
  }));
}
