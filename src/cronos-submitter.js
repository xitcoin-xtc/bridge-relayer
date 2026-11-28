import { randomBytes } from "node:crypto";
import { lstatSync } from "node:fs";
import { isAbsolute, join, normalize } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { Interface, Signature, Transaction, getAddress, keccak256 } from "ethers";
import { BroadcastLedger } from "./broadcast-ledger.js";
import { createBoundedGetFetch } from "./bounded-transport.js";
import { buildTransferApprovalRequest } from "./coordinator.js";
import { inspectCronosSignedTransaction, prepareCronosRelease } from "./cronos-destination.js";
import { CronosRpcQuorum, RpcDisagreement } from "./cronos-rpc.js";
import { verifiedDestinationQuorum } from "./destination-validation.js";
import { runDurableSubmissionCycle, SubmissionUnavailable } from "./durable-broadcast.js";
import { CometBftHttpClient, decodeXitcoinOutboundBlock, decodeXitcoinOutboundTransaction } from "./network.js";
import { TESTNET_ROUTE_ID } from "./preflight.js";
import { DIRECTION_OUTBOUND } from "./protocol.js";
import { createEncryptedKeystoreDigestSigner } from "./secure-keystore.js";
import { createOutboundSourceVerifier } from "./source-verification.js";
import { RelayStore } from "./store.js";
import { validateCronosTestnetManifest } from "./submitter-manifest.js";
import { XitcoinFinalizedWatcher } from "./watchers.js";

// Cronos testnet (chain ID 338) destination adapter for the durable engine.
// Every decision comes from bounded reads that must agree across independent
// origins. Identity (code hash, route, signer set and version) is read at a
// finalized height; live conditions (pause, replay, liquidity, simulation) must
// be acceptable on every origin at the latest block. The adapter never retries
// with new bytes: the engine may only resend the identical persisted transaction.
const VAULT = new Interface([
  "function release(bytes32 sourceBurnId,address recipient,uint256 amount,uint64 signerSetVersion,uint256 deadline,bytes[] signatures)",
  "event Released(bytes32 indexed sourceBurnId,address indexed recipient,uint256 amount,uint64 signerSetVersion)",
  "function paused() view returns (bool)",
  "function routeId() view returns (bytes32)",
  "function signerSetVersion() view returns (uint64)",
  "function signers() view returns (address[3])",
  "function processedBurns(bytes32) view returns (bool)",
  "function maxReleaseAmount() view returns (uint256)",
  "function availableLiquidity() view returns (uint256)",
]);
const RELEASED_TOPIC = VAULT.getEvent("Released").topicHash;
const ZERO_WORD = "0".repeat(64);
const halt = (code) => ({ action: "halt", code });
const wait = (code) => ({ action: "wait", code });
const unavailable = (code) => new SubmissionUnavailable(code);

function words(value, count) {
  if (typeof value !== "string" || value.length !== 2 + 64 * count) throw unavailable("vault_read_invalid");
  return Array.from({ length: count }, (_, index) => value.slice(2 + 64 * index, 66 + 64 * index));
}
function boolean(value) {
  const [word] = words(value, 1);
  if (word === ZERO_WORD) return false;
  if (word === `${"0".repeat(63)}1`) return true;
  throw unavailable("vault_read_invalid");
}
const uint = (value) => BigInt(`0x${words(value, 1)[0]}`);
const bytes32 = (value) => `0x${words(value, 1)[0]}`;
function addresses(value) {
  return words(value, 3).map((word) => {
    if (!word.startsWith("0".repeat(24))) throw unavailable("vault_read_invalid");
    return getAddress(`0x${word.slice(24)}`);
  });
}
const max = (values) => values.reduce((a, b) => (b > a ? b : a));
const min = (values) => values.reduce((a, b) => (b < a ? b : a));
const stable = (value) => JSON.stringify(value);
const sorted = (values) => values.map((value) => value.toLowerCase()).sort();

export function createCronosAdapter({ manifest, rpc, signer, verifySource }) {
  const config = validateCronosTestnetManifest(manifest);
  const cronos = config.cronos;
  if (!(rpc instanceof CronosRpcQuorum) || !signer || typeof signer.signDigest !== "function"
      || signer.signerAddress !== cronos.submitter || typeof verifySource !== "function") {
    throw unavailable("invalid_adapter_dependencies");
  }
  const vault = cronos.vault, submitter = cronos.submitter;
  const gasLimit = BigInt(cronos.gasLimit), maxGasPrice = BigInt(cronos.maxGasPrice), maxFee = BigInt(cronos.maxFee);
  const margin = cronos.minDeadlineMarginSeconds;
  const encode = (name, args = []) => VAULT.encodeFunctionData(name, args);
  const view = (name, args = []) => ({ to: vault, data: encode(name, args) });

  function calldata(request, approvals) {
    const p = request.payload;
    return VAULT.encodeFunctionData("release", [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion, p.deadline,
      approvals.map((approval) => approval.signature)]);
  }

  // The persisted request must be exactly what the coordinator derives from the
  // stored finalized source transfer for this route, vault and signer version.
  function storedRequestMatches(transfer, request, approvals) {
    try {
      if (transfer.source_chain !== "xitcoin" || request.direction !== DIRECTION_OUTBOUND
          || request.payload.chainId !== 338 || getAddress(request.payload.vault) !== vault
          || request.payload.routeId !== config.routeId
          || String(request.payload.signerSetVersion) !== cronos.signerSetVersion) return false;
      const rebuilt = buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" }, routeId: config.routeId,
        cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: vault,
        signerSetVersion: request.payload.signerSetVersion, deadlineUnix: request.deadlineUnix });
      return isDeepStrictEqual(request, JSON.parse(JSON.stringify(rebuilt)))
        && approvals.length >= 2 && approvals.length <= 3 && approvals.every((approval) => approval.digest === request.digest);
    } catch { return false; }
  }

  async function identityAt(height) {
    const block = await rpc.block(height);
    if (keccak256(await rpc.code(vault, height)) !== cronos.vaultCodeHash) throw unavailable("vault_code_mismatch");
    const [route, version, signerList, maxRelease] = await Promise.all([
      rpc.call(view("routeId"), height), rpc.call(view("signerSetVersion"), height),
      rpc.call(view("signers"), height), rpc.call(view("maxReleaseAmount"), height)]);
    if (bytes32(route) !== cronos.cronosRouteId) throw unavailable("vault_route_mismatch");
    const chainVersion = uint(version);
    if (chainVersion >= 1n << 64n || chainVersion.toString() !== cronos.signerSetVersion) throw unavailable("signer_set_version_mismatch");
    if (!isDeepStrictEqual(sorted(addresses(signerList)), sorted(cronos.authorizedSigners))) throw unavailable("signer_set_mismatch");
    return { blockHash: block.hash, maxReleaseAmount: uint(maxRelease) };
  }

  async function viewEach(name, args, parse) {
    const results = await rpc.callEach(view(name, args), "latest");
    if (results.some((result) => !result.ok)) throw unavailable("vault_read_reverted");
    return results.map((result) => parse(result.value));
  }

  async function live(transferId) {
    const [paused, processed, liquidity, blocks] = await Promise.all([viewEach("paused", [], boolean),
      viewEach("processedBurns", [transferId], boolean), viewEach("availableLiquidity", [], uint), rpc.latestBlocks()]);
    return { paused: paused.some(Boolean), processedAll: processed.every(Boolean), processedAny: processed.some(Boolean),
      liquidity: min(liquidity), chainTime: Math.max(...blocks.map((block) => block.timestamp)) };
  }

  async function simulate(request) {
    const results = await rpc.callEach(request, "latest");
    if (results.some((result) => !result.ok)) return false;
    if (results.some((result) => result.value !== "0x")) throw unavailable("simulation_invalid");
    return true;
  }

  async function accountNonces() {
    const [latest, pending] = await Promise.all([rpc.nonces(submitter, "latest"), rpc.nonces(submitter, "pending")]);
    if (new Set(latest).size !== 1 || new Set(pending).size !== 1) return null; // propagation lag
    return { latest: latest[0], pending: pending[0] };
  }

  function parseStored(row) {
    const tx = Transaction.from(row.signedHex);
    if (tx.serialized !== row.signedHex || !tx.isSigned() || tx.type !== 0 || tx.chainId !== 338n || tx.from !== submitter
        || tx.to !== vault || tx.value !== 0n || tx.nonce !== row.nonce || tx.gasLimit > gasLimit || tx.gasPrice > maxGasPrice
        || tx.gasLimit * tx.gasPrice > maxFee || keccak256(row.signedHex) !== row.transactionHash) throw unavailable("stored_transaction_mismatch");
    return tx;
  }

  function matchesProvider(observed, tx) {
    return observed.hash === keccak256(tx.serialized) && observed.from === tx.from.toLowerCase()
      && observed.to === tx.to.toLowerCase() && observed.input === tx.data.toLowerCase() && observed.nonce === tx.nonce
      && observed.value === "0" && observed.gas === tx.gasLimit.toString() && observed.gasPrice === tx.gasPrice.toString()
      && observed.type === 0 && [null, "338"].includes(observed.chainId)
      && observed.v === (338n * 2n + 35n + BigInt(tx.signature.yParity)).toString()
      && observed.r === BigInt(tx.signature.r).toString() && observed.s === BigInt(tx.signature.s).toString();
  }

  function releasedMatches(receipt, request) {
    const p = request.payload;
    const expected = VAULT.encodeEventLog(VAULT.getEvent("Released"), [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion]);
    let matches = 0;
    for (const log of receipt.logs) {
      if (log.removed || log.transactionHash !== receipt.transactionHash || log.blockHash !== receipt.blockHash) return false;
      if (log.address === vault.toLowerCase() && log.topics[0] === RELEASED_TOPIC) {
        if (stable(log.topics) !== stable(expected.topics.map((topic) => topic.toLowerCase()))
            || log.data !== expected.data.toLowerCase()) return false;
        matches += 1;
      }
    }
    return matches === 1;
  }

  return Object.freeze({
    destination: "cronos",
    maxBroadcastAttempts: cronos.maxBroadcastAttempts,

    transferId(request) { return String(request?.payload?.sourceBurnId).toLowerCase(); },

    async assess({ transfer, request, approvals, transferId, nowUnix }) {
      await rpc.chainId();
      if (!storedRequestMatches(transfer, request, approvals) || transferId !== transfer.source_ref) return halt("stored_request_mismatch");
      const recipient = String(request.payload.recipient).toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(recipient) || /^0x0{40}$/.test(recipient) || recipient === "0x000000000000000000000000000000000000dead"
          || recipient === vault.toLowerCase()) return halt("invalid_recipient");
      if (request.deadlineUnix < nowUnix + margin) return wait("approval_expired_awaiting_reissue");
      const identity = await identityAt(Math.max(0, await rpc.tip() - cronos.confirmations));
      try {
        const quorum = verifiedDestinationQuorum(request, approvals, cronos.authorizedSigners, nowUnix);
        if (quorum.some(({ signature }) => ![27, 28].includes(Number.parseInt(signature.slice(130, 132), 16)))) throw new Error();
      } catch { return halt("stored_quorum_invalid"); }
      const amount = BigInt(request.payload.amount);
      if (amount > BigInt(cronos.maxAmount) || amount > identity.maxReleaseAmount) return wait("amount_above_release_limit");
      const state = await live(transferId);
      if (state.paused) return wait("route_paused");
      if (state.processedAll) return halt("processed_without_local_transaction");
      if (state.processedAny) return wait("replay_state_unsettled");
      if (request.deadlineUnix < Math.max(nowUnix, state.chainTime) + margin) return wait("approval_expired_awaiting_reissue");
      if (state.liquidity < amount) return wait("insufficient_vault_liquidity");
      try { await verifySource(request); } catch { throw unavailable("source_finality_unverified"); }
      const data = calldata(request, approvals);
      const gasPrice = max(await rpc.gasPrices());
      if (gasPrice < 1n || gasPrice > maxGasPrice) return wait("gas_price_above_cap");
      const estimates = await rpc.estimateEach({ from: submitter, to: vault, data });
      if (estimates.some((estimate) => !estimate.ok)) return wait("release_simulation_reverted");
      if (estimates.some((estimate) => estimate.value > gasLimit)) return wait("gas_estimate_above_limit");
      if (!await simulate({ from: submitter, to: vault, data })) return wait("release_simulation_reverted");
      if (min(await rpc.balances(submitter)) < gasLimit * gasPrice) return wait("submitter_balance_insufficient");
      return { action: "sign", context: Object.freeze({ gasPrice: gasPrice.toString(), blockHash: identity.blockHash }) };
    },

    async sign({ request, approvals, nowUnix, context, expectedNonce }) {
      await rpc.chainId();
      const nonces = await accountNonces();
      if (!nonces) return wait("account_nonce_unsettled");
      if (nonces.pending !== nonces.latest) return halt("foreign_pending_transaction");
      if (expectedNonce !== null && nonces.latest !== expectedNonce) return halt("account_nonce_not_owned");
      let plan, custody;
      try {
        plan = prepareCronosRelease({ request, approvals, authorizedSigners: [...cronos.authorizedSigners], nowUnix,
          identity: { chainId: 338, vault, codeHash: cronos.vaultCodeHash, routeId: cronos.cronosRouteId, submitter },
          state: { chainId: 338, vault, codeHash: cronos.vaultCodeHash, routeId: cronos.cronosRouteId, paused: false,
            processed: false, signerSetVersion: cronos.signerSetVersion, blockHash: context.blockHash },
          transaction: { nonce: String(nonces.latest), gasLimit: cronos.gasLimit, gasPrice: context.gasPrice },
          limits: { maxGas: cronos.gasLimit, maxGasPrice: cronos.maxGasPrice, maxFee: cronos.maxFee } });
      } catch { throw unavailable("release_plan_rejected"); }
      const tx = Transaction.from({ type: 0, chainId: 338, to: plan.to, data: plan.data, value: 0,
        nonce: Number(plan.nonce), gasLimit: plan.gasLimit, gasPrice: plan.gasPrice });
      try {
        tx.signature = Signature.from(await signer.signDigest(tx.unsignedHash));
        custody = inspectCronosSignedTransaction(plan, tx.serialized);
      } catch { throw unavailable("submitter_signature_rejected"); }
      return { action: "signed", nonce: nonces.latest, signedHex: custody.signedHex, transactionHash: custody.transactionHash };
    },

    async verifyStored({ row, request, approvals }) {
      try {
        const tx = parseStored(row);
        if (tx.data !== calldata(request, approvals) || row.transferId !== String(request.payload.sourceBurnId).toLowerCase()) throw new Error();
        return { action: "valid" };
      } catch { return halt("stored_transaction_mismatch"); }
    },

    async beforeFirstSend({ row, request, nowUnix }) {
      await rpc.chainId();
      const tx = parseStored(row);
      const nonces = await accountNonces();
      if (!nonces) return wait("account_nonce_unsettled");
      if (nonces.latest > row.nonce) return halt("nonce_consumed_before_send");
      if (nonces.latest < row.nonce) return halt("account_nonce_regressed");
      if (nonces.pending !== nonces.latest) return halt("foreign_pending_transaction");
      const state = await live(row.transferId);
      if (state.paused) return wait("route_paused");
      if (state.processedAll) return halt("processed_by_foreign_transaction");
      if (state.processedAny) return wait("replay_state_unsettled");
      if (request.deadlineUnix < Math.max(nowUnix, state.chainTime) + margin) return halt("approval_expired_before_broadcast");
      const exact = { from: submitter, to: vault, data: tx.data, gas: `0x${tx.gasLimit.toString(16)}`, gasPrice: `0x${tx.gasPrice.toString(16)}` };
      if (!await simulate(exact)) return wait("release_simulation_reverted");
      return { action: "send" };
    },

    async send({ row }) { await rpc.sendRaw(row.signedHex); },

    async observe({ row, request, nowUnix }) {
      await rpc.chainId();
      const tx = parseStored(row);
      const receipts = await rpc.receipts(row.transactionHash);
      if (receipts.every((receipt) => receipt === null)) {
        const seen = await rpc.transactions(row.transactionHash);
        if (seen.some((observed) => observed && !matchesProvider(observed, tx))) throw unavailable("rpc_transaction_mismatch");
        if (seen.some(Boolean)) return { action: "pending" };
        // Re-observe before every halt: the transaction may have been included
        // or gossiped to an origin between the reads above and below.
        const visible = async () => {
          const [again, seenAgain] = await Promise.all([rpc.receipts(row.transactionHash), rpc.transactions(row.transactionHash)]);
          return again.some(Boolean) || seenAgain.some(Boolean);
        };
        const nonces = await accountNonces();
        if (!nonces) return { action: "pending" };
        if (nonces.latest > row.nonce) return await visible() ? { action: "pending" } : halt("nonce_consumed_without_receipt");
        if (nonces.latest < row.nonce) return halt("account_nonce_regressed");
        if (nonces.pending !== nonces.latest) return await visible() ? { action: "pending" } : halt("foreign_pending_transaction");
        const state = await live(row.transferId);
        if (state.processedAny) {
          if (!state.processedAll || await visible()) return { action: "pending" };
          const again = await accountNonces();
          // Still unknown with our nonce unused: another transaction released it.
          return again?.latest === row.nonce ? halt("processed_by_foreign_transaction") : { action: "pending" };
        }
        if (state.paused) return wait("route_paused");
        if (request.deadlineUnix < Math.max(nowUnix, state.chainTime) + margin) return halt("approval_expired_before_inclusion");
        if (row.broadcastAttempts >= cronos.maxBroadcastAttempts) return halt("broadcast_attempts_exhausted");
        return { action: "rebroadcast" };
      }
      const present = receipts.filter(Boolean);
      if (present.some((receipt) => stable(receipt) !== stable(present[0]))) throw new RpcDisagreement();
      if (present.length !== receipts.length) return { action: "pending" }; // indexing lag
      const receipt = present[0];
      if (receipt.transactionHash !== row.transactionHash || receipt.from !== submitter.toLowerCase()
          || receipt.to !== vault.toLowerCase() || receipt.contractAddress !== null) return halt("receipt_mismatch");
      const included = await rpc.transactions(row.transactionHash);
      if (included.some((observed) => observed === null)) return { action: "pending" };
      if (included.some((observed) => !matchesProvider(observed, tx))) return halt("included_transaction_mismatch");
      if (included.some((observed) => observed.blockHash !== receipt.blockHash || observed.blockNumber !== receipt.blockNumber)) {
        return { action: "pending" };
      }
      const tip = await rpc.tip();
      if ((await rpc.block(receipt.blockNumber)).hash !== receipt.blockHash) return { action: "pending" }; // reorganizing
      if (receipt.status === "0x1" && !releasedMatches(receipt, request)) return halt("release_event_mismatch");
      const finalizedHeight = tip - cronos.confirmations;
      if (receipt.blockNumber > finalizedHeight) return { action: "pending" };
      const inclusion = { blockNumber: receipt.blockNumber, blockHash: receipt.blockHash };
      if (receipt.status === "0x0") return { action: "failed", ...inclusion };
      if (!boolean(await rpc.call(view("processedBurns", [row.transferId]), finalizedHeight))) return halt("replay_flag_missing_after_release");
      return { action: "finalized", ...inclusion };
    },
  });
}

export function cronosLedgerBinding(manifest) {
  const config = validateCronosTestnetManifest(manifest);
  return Object.freeze({ destination: "cronos", chainId: "338", routeId: config.routeId, target: config.cronos.vault,
    targetIdentity: config.cronos.vaultCodeHash, account: config.cronos.submitter });
}

// RelayStore is created by the coordinator. Never create an empty one here.
export function openExistingRelayStore(path) {
  if (typeof path !== "string" || !isAbsolute(path) || normalize(path) !== path) throw unavailable("relay_store_unavailable");
  const info = lstatSync(path, { throwIfNoEntry: false });
  if (!info || !info.isFile() || info.isSymbolicLink()) throw unavailable("relay_store_unavailable");
  return new RelayStore(path);
}

const delay = (ms, signal) => new Promise((resolve) => {
  if (signal?.aborted) return resolve();
  const timer = setTimeout(done, ms);
  function done() { clearTimeout(timer); signal?.removeEventListener?.("abort", done); resolve(); }
  signal?.addEventListener?.("abort", done, { once: true });
});

export async function buildCronosSubmitterRuntime(manifest, { credentialsDirectory, fetchImpl = globalThis.fetch,
  loadSigner = createEncryptedKeystoreDigestSigner, makeLedger = (path, binding) => new BroadcastLedger(path, binding),
  makeStore = openExistingRelayStore, boundary = async () => {}, now = Date.now,
  log = (report) => process.stdout.write(`${JSON.stringify(report)}\n`) } = {}) {
  const config = validateCronosTestnetManifest(manifest);
  if (typeof credentialsDirectory !== "string" || !isAbsolute(credentialsDirectory)) throw unavailable("credentials_directory_required");
  const rpc = new CronosRpcQuorum({ urls: [...config.cronos.rpcUrls], allowLoopbackHttp: config.cronos.allowLoopbackHttp, fetchImpl });
  await rpc.chainId();
  const boundedGet = createBoundedGetFetch({ fetchImpl });
  const clients = config.xitcoin.rpcUrls.map((url) => new CometBftHttpClient({ url, chainId: config.xitcoinChainId,
    decodeBlock: decodeXitcoinOutboundBlock, decodeTransaction: decodeXitcoinOutboundTransaction,
    allowHttp: config.xitcoin.allowLoopbackHttp, fetchImpl: boundedGet }));
  const xitcoinWatcher = new XitcoinFinalizedWatcher({ clients, chainId: config.xitcoinChainId, routeId: config.routeId,
    safetyLag: config.xitcoin.safetyLag, maxBatch: 1 });
  let signer;
  try {
    signer = await loadSigner({ keystorePath: config.keystorePath,
      credentialPath: join(credentialsDirectory, "keystore-password"), expectedAddress: config.cronos.submitter });
  } catch { throw unavailable("submitter_key_unavailable"); }
  let ledger, store;
  try {
    ledger = makeLedger(config.ledgerPath, cronosLedgerBinding(config));
    store = makeStore(config.relayStorePath);
    const adapter = createCronosAdapter({ manifest: config, rpc, signer, verifySource: createOutboundSourceVerifier({ xitcoinWatcher }) });
    const owner = randomBytes(16).toString("hex");
    const runOnce = () => runDurableSubmissionCycle({ store, ledger, adapter, owner, nowMs: now(), boundary,
      leaseTtlMs: Math.max(60_000, config.cycleIntervalMs * 6) });
    return Object.freeze({
      manifest: config,
      runOnce,
      async run({ signal } = {}) {
        while (!signal?.aborted) {
          const report = await runOnce();
          log(report);
          await delay(config.cycleIntervalMs, signal);
        }
      },
      close() {
        // Release this worker's lease on clean shutdown; a takeover after a
        // crash still waits for expiry and increments the fencing epoch.
        try { ledger.releaseLease(ledger.acquireLease(owner, { nowMs: now(), ttlMs: 1_000 })); } catch { /* Not held. */ }
        try { ledger.close(); } finally { store.close(); }
      },
    });
  } catch (error) {
    try { ledger?.close(); } catch { /* Preserve the original failure. */ }
    try { store?.close(); } catch { /* Preserve the original failure. */ }
    throw error instanceof SubmissionUnavailable ? error : unavailable("submitter_state_unavailable");
  }
}
