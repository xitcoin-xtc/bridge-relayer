// Full Cronos submitter flow against a local anvil chain (chain ID 338) and the
// vendored reviewed vault. Synthetic keys only; no public network is contacted.
import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AbiCoder, Interface, JsonRpcProvider, TypedDataEncoder, ZeroAddress, ZeroHash, encryptKeystoreJsonSync, keccak256 } from "ethers";
import { BroadcastLedger } from "../src/broadcast-ledger.js";
import { approveFinalizedTransfer, buildTransferApprovalRequest } from "../src/coordinator.js";
import { CometBftHttpClient, decodeXitcoinOutboundBlock, decodeXitcoinOutboundTransaction } from "../src/network.js";
import { SignerApprovalJournal } from "../src/signer-journal.js";
import { IsolatedSignerService, createSignerPolicy } from "../src/signer-service.js";
import { createCanonicalSourceVerifier } from "../src/source-verification.js";
import { CronosFinalizedWatcher, XitcoinFinalizedWatcher } from "../src/watchers.js";
import { buildCronosSubmitterRuntime, cronosLedgerBinding, isTemporaryStop, openExistingRelayStore } from "../src/cronos-submitter.js";
import { SubmissionHalt } from "../src/durable-broadcast.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { createEncryptedKeystoreDigestSigner } from "../src/secure-keystore.js";
import { RelayStore } from "../src/store.js";
import { validateCronosTestnetManifest } from "../src/submitter-manifest.js";
import { journalOptions } from "./journal-fixture.js";
import { keys, sign, signers } from "./fixtures/destination.js";
import { blockHash, compile, controlSignatures, deployBridge, evmAvailability, gitBlob, localAddress, localKeys,
  rewriteResult, rpcCall, signedCall, startAnvil, startCometBft, startProxy, xitcoinBurn } from "./evm/harness.js";
import provenance from "./evm/provenance.json" with { type: "json" };

const evm = evmAvailability();
const options = { skip: evm.skip, timeout: 240_000 };
const VAULT = new Interface(["function processedBurns(bytes32) view returns (bool)", "function pause()", "function paused() view returns (bool)",
  "function resume(uint256 nonce,uint256 deadline,bytes[] signatures)", "function balanceOf(address) view returns (uint256)",
  "function updateLimits(uint256 newMaxReleaseAmount,uint256 newDailyReleaseLimit,uint256 nonce,uint256 deadline,bytes[] signatures)"]);
const TOKEN = new Interface(["function configure(uint8 mode,address target,bytes data)"]);
const RELEASE = new Interface(["function release(bytes32,address,uint256,uint64,uint256,bytes[])"]);
const AMOUNT = 10n ** 18n;
const recipient = signers[0];
const SUBMITTER = localAddress(localKeys.submitter);

function artifacts(version, token = "mock") {
  return { vault: compile(evm.forge, version === "main" ? "vault-main" : "vault-testnet").CronosBridgeVault,
    token: token === "adversarial" ? compile(evm.forge, "adversarial-token").AdversarialERC20 : compile(evm.forge, "token").MockERC20 };
}

// Coordinator-side persistence of a finalized Xitcoin burn and its approval
// request. Approvals come from three isolated signer services that each verify
// the burn on the Xitcoin origins and keep their own durable journal, unless a
// scenario deliberately bypasses them to test the submitter's own checks.
async function approve(store, burn, vault, deadlineUnix, signerServices) {
  store.observe({ sourceChain: "xitcoin", sourceRef: burn.requestId, routeId: "cronos-testnet-xitcoin-testnet",
    blockHeight: burn.height, blockHash: blockHash(burn.height), transactionHash: burn.transactionHash, messageIndex: 0,
    payload: { requestId: burn.requestId, sender: "xtc1sender", destination: burn.recipient, amount: burn.amount, nonce: burn.nonce } });
  const transfer = store.transition("xitcoin", burn.requestId, "finalized");
  const request = buildTransferApprovalRequest({ transfer, routeId: "cronos-testnet-xitcoin-testnet", cronosRouteId: TESTNET_ROUTE_ID,
    cronosChainId: 338, cronosVault: vault, signerSetVersion: 1, deadlineUnix });
  if (signerServices) {
    const clients = signerServices.map((service) => ({ identity: service.identity, approve: (value) => service.approve(value) }));
    await approveFinalizedTransfer({ store, sourceChain: "xitcoin", sourceRef: burn.requestId, request, clients,
      authorizedSigners: [...signers], threshold: 2, nowUnix: Math.floor(Date.now() / 1000) });
    return;
  }
  store.persistApprovalRequest("xitcoin", burn.requestId, request);
  for (const approval of sign(request)) store.recordApproval("xitcoin", burn.requestId, approval);
  store.transition("xitcoin", burn.requestId, "approved");
}

function isolatedSigners({ vault, proxies, comets }) {
  const providers = proxies.map((proxy) => new JsonRpcProvider(proxy.url, 338, { staticNetwork: true }));
  const clients = comets.map((comet) => new CometBftHttpClient({ url: comet.url, chainId: "xitcoin-testnet-v2-1", allowHttp: true,
    decodeBlock: decodeXitcoinOutboundBlock, decodeTransaction: decodeXitcoinOutboundTransaction }));
  const verifySource = createCanonicalSourceVerifier({ cronosRouteId: TESTNET_ROUTE_ID,
    cronosWatcher: new CronosFinalizedWatcher({ providers, vault, routeId: TESTNET_ROUTE_ID, confirmations: 3 }),
    xitcoinWatcher: new XitcoinFinalizedWatcher({ clients, chainId: "xitcoin-testnet-v2-1", routeId: "cronos-testnet-xitcoin-testnet", safetyLag: 2 }) });
  const policy = createSignerPolicy({ routeIds: ["cronos-testnet-xitcoin-testnet"], cronosChainIds: [338],
    xitcoinChainIds: ["xitcoin-testnet-v2-1"], cronosVaults: [vault], maximumAmount: (10n ** 21n).toString(), maximumDeadlineSeconds: 7_200 });
  const journals = [0, 1, 2].map(() => new SignerApprovalJournal());
  const services = [0, 1, 2].map((index) => new IsolatedSignerService({ identity: `signer-${index + 1}`, signerAddress: signers[index],
    policy, verifySource, journal: journals[index], signDigest: async (digest) => keys[index].sign(digest).serialized }));
  return { services, close: () => { for (const provider of providers) provider.destroy(); for (const journal of journals) journal.close?.(); } };
}

async function scenario(run, { version = "testnet", chainId = 338, burns = 1, approved = burns, deadlineOffset = 3_600,
  patch = {}, cronosPatch = {}, cometBurns = (items) => [items, items], approvals = "signers", recipientFor = () => recipient,
  origins = 2, bridgeOptions = {}, history = 0, token = "mock" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "cronos-submitter-"));
  const cleanup = [];
  try {
    const chain = await startAnvil(evm.anvil, { chainId });
    cleanup.push(chain.stop);
    const proxies = [];
    for (let index = 0; index < origins; index++) proxies.push(await startProxy(chain.url));
    if (history) await chain.rpc("anvil_mine", [`0x${history.toString(16)}`]); // older history than the lookback window
    cleanup.push(...proxies.map((proxy) => proxy.stop));
    const bridge = await deployBridge(chain, artifacts(version, token), { routeId: TESTNET_ROUTE_ID, signers, version, ...bridgeOptions });
    await chain.rpc("anvil_mine", ["0xa"]); // vault identity is read at a finalized height
    const allBurns = Array.from({ length: burns }, (_, index) => xitcoinBurn({ index: index + 1,
      recipient: recipientFor(index + 1, bridge), amount: AMOUNT.toString() }));
    const [firstComet, secondComet] = cometBurns(allBurns);
    const comets = [await startCometBft(firstComet), await startCometBft(secondComet)];
    cleanup.push(...comets.map((comet) => comet.stop));
    const paths = { store: join(directory, "relay.sqlite"), ledger: join(directory, "ledger.sqlite"),
      keystore: join(directory, "keystore.json"), credentials: join(directory, "credentials") };
    const store = new RelayStore(paths.store);
    cleanup.push(() => store.close());
    const deadlineUnix = Math.floor(Date.now() / 1000) + deadlineOffset;
    const signerSet = approvals === "signers" ? isolatedSigners({ vault: bridge.vault, proxies, comets }) : null;
    if (signerSet) cleanup.push(signerSet.close);
    for (const burn of allBurns.slice(0, approved)) await approve(store, burn, bridge.vault, deadlineUnix, signerSet?.services);
    writeFileSync(paths.keystore, encryptKeystoreJsonSync({ address: SUBMITTER, privateKey: localKeys.submitter.privateKey },
      "synthetic-local-test-password", { scrypt: { N: 1 << 10 } }), { mode: 0o600 });
    mkdirSync(paths.credentials, { mode: 0o700 });
    writeFileSync(join(paths.credentials, "keystore-password"), "synthetic-local-test-password\n", { mode: 0o600 });
    chmodSync(paths.keystore, 0o600);
    const manifest = validateCronosTestnetManifest({ version: 1, mode: "testnet", destination: "cronos", releaseCommit: "a".repeat(40),
      routeId: "cronos-testnet-xitcoin-testnet", cronosChainId: 338, xitcoinChainId: "xitcoin-testnet-v2-1",
      relayStorePath: paths.store, ledgerPath: paths.ledger, keystorePath: paths.keystore, cycleIntervalMs: 1_000,
      cronos: { rpcUrls: proxies.map((proxy) => proxy.url), allowLoopbackHttp: true, vault: bridge.vault,
        vaultCodeHash: keccak256(await chain.rpc("eth_getCode", [bridge.vault, "latest"])), cronosRouteId: TESTNET_ROUTE_ID,
        signerSetVersion: "1", authorizedSigners: [...signers], submitter: SUBMITTER, confirmations: 3,
        maxAmount: (10n ** 21n).toString(), gasLimit: "400000", maxGasPrice: "100000000000", maxFee: "40000000000000000",
        minDeadlineMarginSeconds: 60, maxBroadcastAttempts: 5,
        releaseLookbackBlocks: 1_000, logRangeBlocks: 100, ...cronosPatch },
      xitcoin: { rpcUrls: comets.map((comet) => comet.url), allowLoopbackHttp: true, safetyLag: 2 }, ...patch });
    const runtimes = [];
    cleanup.push(() => { for (const runtime of runtimes) runtime.close(); });
    const runtime = async ({ offsetMs = 0, manifestOverride = manifest, boundary } = {}) => {
      const built = await buildCronosSubmitterRuntime(manifestOverride, { credentialsDirectory: paths.credentials,
        makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("cronos")),
        loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }),
        now: () => Date.now() + offsetMs, log: () => {}, boundary });
      runtimes.push(built);
      return built;
    };
    const view = async (data, to = bridge.vault) => chain.rpc("eth_call", [{ to, data }, "latest"]);
    const facts = {
      nonce: async () => Number(await chain.rpc("eth_getTransactionCount", [SUBMITTER, "latest"])),
      processed: async (burn = allBurns[0]) => BigInt(await view(VAULT.encodeFunctionData("processedBurns", [burn.requestId]))) === 1n,
      balance: async () => BigInt(await view(VAULT.encodeFunctionData("balanceOf", [recipient]), bridge.token)),
      relay: (burn = allBurns[0]) => store.get("xitcoin", burn.requestId),
      // Automine includes a sent transaction asynchronously; wait until no
      // submitter transaction is pending before asserting or mining.
      settle: async () => {
        for (let i = 0; i < 100; i++) {
          const [latest, pending] = await Promise.all([chain.rpc("eth_getTransactionCount", [SUBMITTER, "latest"]),
            chain.rpc("eth_getTransactionCount", [SUBMITTER, "pending"])]);
          if (latest === pending) return;
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        throw new Error("submitter transaction did not settle");
      },
      mine: async (blocks = 3) => { await facts.settle(); await chain.rpc("anvil_mine", [`0x${blocks.toString(16)}`]); },
      ledger: () => new BroadcastLedger(paths.ledger, cronosLedgerBinding(manifest), journalOptions("cronos")),
    };
    await run({ chain, proxies, bridge, burns: allBurns, store, manifest, paths, runtime, facts, directory,
      approve: (burn, deadline = deadlineUnix) => approve(store, burn, bridge.vault, deadline, signerSet?.services) });
  } finally {
    for (const step of cleanup.reverse()) { try { await step(); } catch { /* best effort */ } }
    rmSync(directory, { recursive: true, force: true });
  }
}

async function completes(rt, facts, burn) {
  for (let i = 0; i < 8; i++) {
    const report = await rt.runOnce();
    if (facts.relay(burn).state === "completed") return report;
    await facts.mine(3);
  }
  throw new Error("transfer did not complete");
}

async function assertSingleRelease(facts, burn) {
  const relay = facts.relay(burn);
  assert.equal(relay.state, "completed");
  assert.equal(await facts.processed(burn), true);
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burn.requestId);
    assert.equal(row.state, "finalized"); assert.equal(row.transactionHash, relay.destination_ref);
  } finally { ledger.close(); }
}

test("vendored vault sources match their pinned contracts commits", options, () => {
  for (const file of provenance.files) {
    assert.equal(gitBlob(new URL(`./evm/${file.path}`, import.meta.url)), file.blob, file.path);
  }
});

for (const version of ["testnet", "main"]) {
  test(`${version} vault: signers approve, submitter releases once, status completed only after finality`, options, () => scenario(async ({ runtime, facts, burns, chain }) => {
    const rt = await runtime();
    const first = await rt.runOnce();
    assert.equal(first.action, "submitted");
    assert.equal(facts.relay().state, "submitted"); assert.equal(facts.relay().destination_ref, first.transactionHash);
    await facts.settle();
    const receipt = await chain.rpc("eth_getTransactionReceipt", [first.transactionHash]);
    assert.equal(receipt.status, "0x1");
    assert.equal((await rt.runOnce()).action, "pending"); // included, finality depth not reached
    assert.equal(facts.relay().state, "submitted");
    await facts.mine(3);
    const final = await rt.runOnce();
    assert.equal(final.action, "finalized"); assert.equal(final.transactionHash, first.transactionHash);
    await assertSingleRelease(facts, burns[0]);
    assert.equal(facts.relay().release_ref, first.transactionHash);
    assert.equal(await facts.balance(), AMOUNT);
    assert.equal(await facts.nonce(), 1);
    for (let i = 0; i < 3; i++) assert.equal((await rt.runOnce()).action, "idle");
    assert.equal(await facts.nonce(), 1);
  }, { version }));
}

test("duplicate attempts: concurrent workers, a later worker and an independent ledger never release twice", options, () => scenario(async ({ runtime, facts, burns, paths, manifest, directory, store }) => {
  const copy = join(directory, "relay-copy.sqlite");
  store.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  copyFileSync(paths.store, copy);
  const [a, b] = [await runtime(), await runtime()];
  const results = await Promise.allSettled([a.runOnce(), b.runOnce()]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  await facts.settle();
  assert.equal(await facts.nonce(), 1);
  await assert.rejects(b.runOnce()); // lease still held
  await facts.mine(3);
  const takeover = await runtime({ offsetMs: 10 * 60_000 });
  assert.equal((await takeover.runOnce()).action, "finalized");
  await assertSingleRelease(facts, burns[0]);
  // An independent ledger and RelayStore copy find the finalized release by
  // our transaction, record it as released elsewhere and never send.
  mkdirSync(join(directory, "second"), { mode: 0o700 });
  const independent = await runtime({ manifestOverride: { ...manifest, relayStorePath: copy, ledgerPath: join(directory, "second", "ledger.sqlite") } });
  const outcome = await independent.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, facts.relay().destination_ref);
  assert.equal(await facts.nonce(), 1);
}));

for (const boundary of ["claimed", "signed", "relay-submitted", "broadcast-recorded", "sent", "ledger-finalized", "relay-completed"]) {
  test(`process killed at ${boundary} recovers with exactly one transaction`, options, () => scenario(async ({ chain, runtime, facts, burns, manifest, paths }) => {
    const context = { manifest, credentials: paths.credentials, anvil: chain.url, boundary };
    const base = new URL("../", import.meta.url).href;
    const code = `import { buildCronosSubmitterRuntime } from '${base}src/cronos-submitter.js';
      import { BroadcastLedger } from '${base}src/broadcast-ledger.js';
      import { createEncryptedKeystoreDigestSigner } from '${base}src/secure-keystore.js';
      import { journalOptions } from '${base}test/journal-fixture.js';
      import { rpcCall } from '${base}test/evm/harness.js';
      const context = JSON.parse(process.env.SUBMITTER_TEST_CONTEXT);
      const runtime = await buildCronosSubmitterRuntime(context.manifest, { credentialsDirectory: context.credentials,
        makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("cronos")),
        loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }),
        log: () => {}, boundary: async (name) => { if (name === context.boundary) process.kill(process.pid, "SIGKILL"); } });
      for (let i = 0; i < 6; i++) { await runtime.runOnce(); await rpcCall(context.anvil, "anvil_mine", ["0x3"]); }
      process.exit(3);`;
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", code],
        { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, SUBMITTER_TEST_CONTEXT: JSON.stringify(context) } });
      let errors = "";
      child.stderr.on("data", (data) => { errors += data; });
      child.on("close", (status, signal) => (signal === "SIGKILL" ? resolve() : reject(new Error(`child ${status}: ${errors}`))));
    });
    const recovered = await runtime({ offsetMs: 10 * 60_000 });
    await completes(recovered, facts, burns[0]);
    await assertSingleRelease(facts, burns[0]);
    assert.equal(await facts.nonce(), 1);
    assert.equal(await facts.balance(), AMOUNT);
  }));
}

test("reorganization removing the release resends only the identical persisted bytes", options, () => scenario(async ({ chain, runtime, facts, burns }) => {
  const rt = await runtime();
  const first = await rt.runOnce();
  await facts.settle();
  assert.equal(await facts.processed(), true);
  await chain.rpc("anvil_reorg", [1, []]);
  assert.equal(await chain.rpc("eth_getTransactionReceipt", [first.transactionHash]), null);
  assert.equal(await facts.processed(), false);
  const resent = await rt.runOnce();
  assert.equal(resent.action, "rebroadcast"); assert.equal(resent.transactionHash, first.transactionHash);
  await facts.mine(3);
  assert.equal((await rt.runOnce()).transactionHash, first.transactionHash);
  await assertSingleRelease(facts, burns[0]);
  assert.equal(await facts.nonce(), 1);
}));

test("reorganization replacing the release with a foreign use of its nonce halts permanently", options, () => scenario(async ({ chain, runtime, facts }) => {
  const rt = await runtime();
  await rt.runOnce();
  await facts.settle();
  const foreign = await signedCall(chain, localKeys.submitter, { to: localAddress(localKeys.deployer), data: "0x", nonce: 0, gasLimit: 21_000n });
  await chain.rpc("anvil_reorg", [1, [[foreign, 0]]]);
  await assert.rejects(rt.runOnce(), (error) => error.code === "nonce_consumed_without_receipt");
  await assert.rejects(rt.runOnce(), (error) => error.code === "ledger_requires_review");
  assert.equal(await facts.processed(), false);
  assert.equal(facts.relay().state, "submitted");
}));

test("paused route: nothing is claimed or sent until a quorum-signed resume", options, () => scenario(async ({ chain, bridge, runtime, facts, burns }) => {
  await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault, data: VAULT.encodeFunctionData("pause") })]);
  const rt = await runtime();
  const paused = await rt.runOnce();
  assert.equal(paused.action, "waiting"); assert.deepEqual(paused.waiting, ["route_paused"]);
  const ledger = facts.ledger();
  try { assert.equal(ledger.inspect(burns[0].requestId).found, false); } finally { ledger.close(); }
  assert.equal(await facts.nonce(), 0);
  const deadline = Math.floor(Date.now() / 1000) + 600;
  const signatures = controlSignatures({ vault: bridge.vault, action: "RESUME", payloadHash: ZeroHash, nonce: 0, deadline, keys: [keys[0], keys[1]] });
  await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.deployer, { to: bridge.vault,
    data: VAULT.encodeFunctionData("resume", [0, deadline, signatures]) })]);
  await completes(rt, facts, burns[0]);
  await assertSingleRelease(facts, burns[0]);
}));

// Sends a raw transaction and waits until automine includes it.
async function included(chain, raw) {
  const hash = await chain.rpc("eth_sendRawTransaction", [raw]);
  for (let i = 0; i < 100 && !(await chain.rpc("eth_getTransactionReceipt", [hash])); i++) await new Promise((resolve) => setTimeout(resolve, 20));
  return hash;
}
const receiptsOf = (chain, hashes) => Promise.all(hashes.map((hash) => chain.rpc("eth_getTransactionReceipt", [hash])));
// From the next transaction on, the asset refuses every transfer (returns false).
const refuseTransfers = async (chain, bridge, options = {}) => chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.deployer,
  { to: bridge.token, data: TOKEN.encodeFunctionData("configure", [4, ZeroAddress, "0x"]), ...options })]);

test("an unexplained execution failure (the asset refuses the transfer) is recorded, halts and is never retried", options, () => scenario(async ({ chain, bridge, runtime, facts }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await refuseTransfers(chain, bridge, { gasPrice: 50_000_000_000n });
  await chain.rpc("evm_mine", []);
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  assert.equal((await rt.runOnce()).action, "pending");
  await facts.mine(3);
  await assert.rejects(rt.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "destination_execution_failed");
  await assert.rejects(rt.runOnce(), (error) => error.code === "ledger_requires_review");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking()[0].state, "failed"); } finally { ledger.close(); }
  assert.equal(facts.relay().state, "submitted");
  assert.equal(await facts.nonce(), 1);
}, { token: "adversarial" }));

test("a guardian pause mined just before our transaction in its block makes the revert non-blocking, never failed", options, () => scenario(async ({ chain, bridge, runtime, facts }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  const pause = await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: VAULT.encodeFunctionData("pause"), gasPrice: 50_000_000_000n })]);
  await chain.rpc("evm_mine", []);
  const [ours, paused] = await receiptsOf(chain, [sent.transactionHash, pause]);
  assert.equal(ours.status, "0x0"); assert.equal(ours.blockHash, paused.blockHash);
  assert.ok(Number(paused.transactionIndex) < Number(ours.transactionIndex));
  assert.equal((await rt.runOnce()).action, "pending");
  await facts.mine(3);
  const reverted = await rt.runOnce();
  assert.equal(reverted.action, "reverted"); assert.equal(reverted.code, "vault_paused");
  const ledger = facts.ledger();
  try {
    assert.equal(ledger.inspect(reverted.transferId).reasonCode, "vault_paused"); assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  assert.equal(facts.relay().state, "submitted");
  assert.equal(await facts.nonce(), 1);
  const next = await rt.runOnce(); // never ledger_requires_review
  assert.equal(next.attention.reverted, 1);
}));

test("RPC disagreement on chain, code or vault state stops before any claim", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  const rt = await runtime();
  for (const [method, transform] of [["eth_getCode", (value) => `${value}00`], ["eth_chainId", () => "0x19"],
    ["eth_getBlockByNumber", (value) => ({ ...value, hash: `0x${"ab".repeat(32)}` })]]) {
    proxies[1].hook = async ({ message, forward }) => (message.method === method ? rewriteResult(await forward(), transform) : forward());
    await assert.rejects(rt.runOnce(), (error) => ["rpc_disagreement", "rpc_invalid_response"].includes(error.code));
  }
  proxies[1].hook = null;
  const ledger = facts.ledger();
  try { assert.equal(ledger.inspect(burns[0].requestId).found, false); } finally { ledger.close(); }
  assert.equal(await facts.nonce(), 0);
  await completes(rt, facts, burns[0]);
  assert.equal(await facts.nonce(), 1);
}));

test("timeouts and dropped send responses are reconciled from chain state, never re-signed", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  // Delivered but every response lost (ambiguous outcome).
  for (const proxy of proxies) proxy.hook = async ({ message, forward, response }) => {
    if (message.method !== "eth_sendRawTransaction") return forward();
    await forward(); response.destroy(); return undefined;
  };
  const rt = await runtime();
  const first = await rt.runOnce();
  assert.equal(first.action, "submitted");
  for (const proxy of proxies) proxy.hook = null;
  await facts.mine(3);
  assert.equal((await rt.runOnce()).action, "finalized");
  assert.equal(await facts.nonce(), 1);
  await assertSingleRelease(facts, burns[0]);
}, {}));

test("a send that never reached the chain is resent as identical bytes", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  for (const proxy of proxies) proxy.hook = async ({ message, forward, response }) => {
    if (message.method === "eth_sendRawTransaction") { response.destroy(); return undefined; }
    return forward();
  };
  const rt = await runtime();
  const first = await rt.runOnce();
  assert.equal(await facts.nonce(), 0);
  for (const proxy of proxies) proxy.hook = null;
  const resent = await rt.runOnce();
  assert.equal(resent.action, "rebroadcast"); assert.equal(resent.transactionHash, first.transactionHash);
  await facts.mine(3);
  await completes(rt, facts, burns[0]);
  await assertSingleRelease(facts, burns[0]);
  assert.equal(await facts.nonce(), 1);
}));

test("forged receipt event or transaction input from every origin halts instead of completing", options, async () => {
  for (const forgery of ["event", "input"]) {
    await scenario(async ({ proxies, runtime, facts }) => {
      const rt = await runtime();
      await rt.runOnce();
      await facts.mine(3);
      for (const proxy of proxies) proxy.hook = async ({ message, forward }) => {
        if (forgery === "event" && message.method === "eth_getTransactionReceipt") {
          return rewriteResult(await forward(), (receipt) => ({ ...receipt, logs: receipt.logs.map((log) => ({ ...log,
            data: `${log.data.slice(0, 2)}${"0".repeat(63)}2${log.data.slice(66)}` })) }));
        }
        if (forgery === "input" && message.method === "eth_getTransactionByHash") {
          return rewriteResult(await forward(), (tx) => ({ ...tx, input: `${tx.input.slice(0, -2)}${tx.input.endsWith("ff") ? "00" : "ff"}` }));
        }
        return forward();
      };
      await assert.rejects(rt.runOnce(), (error) => ["release_event_mismatch", "included_transaction_mismatch"].includes(error.code));
      assert.equal(facts.relay().state, "submitted");
    });
  }
});

test("a foreign use of the submitter account nonce halts the next transfer before signing", options, () => scenario(async ({ chain, runtime, facts, burns, approve }) => {
  const rt = await runtime();
  await completes(rt, facts, burns[0]);
  await approve(burns[1]);
  await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.submitter, { to: localAddress(localKeys.deployer), data: "0x", gasLimit: 21_000n })]);
  await assert.rejects(rt.runOnce(), (error) => error.code === "account_nonce_not_owned");
  assert.equal(await facts.processed(burns[1]), false);
  assert.equal(facts.relay(burns[1]).state, "approved");
}, { burns: 2, approved: 1 }));

test("killed after signing, then a foreign transaction takes the nonce: no send, permanent halt", options, () => scenario(async ({ chain, runtime, facts }) => {
  await assert.rejects((await runtime({ boundary: async (name) => { if (name === "signed") throw new Error("stop"); } })).runOnce(), /stop/);
  await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.submitter, { to: localAddress(localKeys.deployer), data: "0x", gasLimit: 21_000n })]);
  const recovered = await runtime({ offsetMs: 10 * 60_000 });
  await assert.rejects(recovered.runOnce(), (error) => error.code === "nonce_consumed_before_send");
  assert.equal(await facts.processed(), false);
  assert.equal(await facts.nonce(), 1);
}));

test("expired approvals wait for re-issue without claiming", options, () => scenario(async ({ runtime, facts, burns }) => {
  const report = await (await runtime()).runOnce();
  assert.deepEqual(report.waiting, ["approval_expired_awaiting_reissue"]);
  const ledger = facts.ledger();
  try { assert.equal(ledger.inspect(burns[0].requestId).found, false); } finally { ledger.close(); }
  assert.equal(await facts.nonce(), 0);
}, { deadlineOffset: 30 }));

test("pinned identity mismatches and Cronos mainnet stop before any claim", options, async () => {
  await scenario(async ({ runtime, facts }) => {
    await assert.rejects((await runtime()).runOnce(), (error) => error.code === "vault_code_mismatch");
    assert.equal(await facts.nonce(), 0);
  }, { cronosPatch: { vaultCodeHash: `0x${"12".repeat(32)}` } });
  await scenario(async ({ runtime, facts }) => {
    await assert.rejects((await runtime()).runOnce(), (error) => error.code === "signer_set_mismatch");
    assert.equal(await facts.nonce(), 0);
  }, { cronosPatch: { authorizedSigners: [signers[0], signers[1], localAddress(localKeys.guardian)] } });
  await scenario(async ({ runtime }) => {
    await assert.rejects(runtime(), (error) => error.code === "cronos_mainnet_rejected");
  }, { chainId: 25 });
});

test("source finality is re-verified on independent Xitcoin origins before signing", options, async () => {
  for (const cometBurns of [(items) => [items.map((burn) => ({ ...burn, amount: "1" })), items.map((burn) => ({ ...burn, amount: "1" }))],
    (items) => [items, []]]) {
    await scenario(async ({ runtime, facts, burns }) => {
      await assert.rejects((await runtime()).runOnce(), (error) => error.code === "source_finality_unverified");
      assert.equal(await facts.nonce(), 0);
      assert.equal(facts.relay(burns[0]).state, "approved");
      const ledger = facts.ledger();
      try { assert.equal(ledger.inspect(burns[0].requestId).found, false); } finally { ledger.close(); }
    }, { cometBurns, approvals: "direct" });
  }
});

test("a stored request that no longer matches its finalized source transfer halts", options, () => scenario(async ({ runtime, facts, store, burns }) => {
  store.database.exec(`UPDATE transfers SET block_hash = '0x${"9".repeat(64)}'`);
  await assert.rejects((await runtime()).runOnce(), (error) => error instanceof SubmissionHalt && error.code === "stored_request_mismatch");
  assert.equal(await facts.nonce(), 0);
  assert.equal(facts.relay(burns[0]).state, "approved");
}));

// Anyone may call release() with valid approvals, e.g. by copying our pending
// calldata or reading the public approvals. Such releases must not block us.
function thirdPartyRelease(chain, bridge, store, burn, options = {}) {
  const request = store.approvalRequest("xitcoin", burn.requestId);
  const signatures = store.approvals("xitcoin", burn.requestId).map((approval) => approval.signature);
  const p = request.payload;
  const data = RELEASE.encodeFunctionData("release", [p.sourceBurnId, p.recipient, p.amount, p.signerSetVersion, p.deadline, signatures]);
  return signedCall(chain, localKeys.guardian, { to: bridge.vault, data, gasLimit: 400_000n, ...options })
    .then((raw) => chain.rpc("eth_sendRawTransaction", [raw]))
    .then(async (hash) => {
      for (let i = 0; i < 100 && !(await chain.rpc("eth_getTransactionReceipt", [hash])); i++) await new Promise((resolve) => setTimeout(resolve, 20));
      return hash;
    });
}

test("a front-run copying our pending calldata is recorded as released elsewhere and the queue moves on", options, () => scenario(async ({ chain, bridge, runtime, facts, burns, approve }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  const ours = await chain.rpc("eth_getTransactionByHash", [sent.transactionHash]);
  const attacker = await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: ours.input, gasPrice: 50_000_000_000n, gasLimit: 400_000n })]);
  await chain.rpc("evm_mine", []);
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  assert.equal(await facts.processed(burns[0]), true);
  await chain.rpc("evm_setAutomine", [true]);
  await facts.mine(3);
  const outcome = await rt.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, attacker);
  assert.equal(facts.relay(burns[0]).state, "completed");
  assert.equal(facts.relay(burns[0]).destination_ref, sent.transactionHash);
  assert.equal(facts.relay(burns[0]).release_ref, attacker); // the real release, where a reconciler reads it
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burns[0].requestId);
    assert.equal(row.state, "released_elsewhere"); assert.equal(row.releaseHash, attacker); assert.equal(row.nonce, 0);
    assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  await approve(burns[1]);
  await completes(rt, facts, burns[1]);
  await assertSingleRelease(facts, burns[1]);
  assert.equal(await facts.nonce(), 2);
}, { burns: 2, approved: 1 }));

test("a third-party release before any claim completes the transfer without any submitter transaction", options, () => scenario(async ({ chain, bridge, store, runtime, facts, burns, approve }) => {
  const release = await thirdPartyRelease(chain, bridge, store, burns[0]);
  await facts.mine(3);
  const rt = await runtime();
  const outcome = await rt.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, release);
  assert.equal(facts.relay(burns[0]).state, "completed"); assert.equal(facts.relay(burns[0]).destination_ref, null);
  assert.equal(facts.relay(burns[0]).release_ref, release);
  assert.equal(await facts.nonce(), 0);
  await approve(burns[1]);
  await completes(rt, facts, burns[1]);
  assert.equal(await facts.nonce(), 1);
}, { burns: 2, approved: 1 }));

test("a third-party release after we signed still consumes our nonce once, then the queue moves on", options, () => scenario(async ({ chain, bridge, store, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime({ boundary: async (name) => { if (name === "signed") throw new Error("stop"); } })).runOnce(), /stop/);
  const release = await thirdPartyRelease(chain, bridge, store, burns[0]);
  await facts.mine(3);
  const recovered = await runtime({ offsetMs: 10 * 60_000 });
  const sent = await recovered.runOnce();
  assert.equal(sent.action, "submitted"); // identical bytes; they revert but consume nonce 0
  await facts.mine(3);
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  const outcome = await recovered.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, release);
  await approve(burns[1]);
  await completes(recovered, facts, burns[1]);
  assert.equal(await facts.nonce(), 2);
}, { burns: 2, approved: 1 }));

test("an invalid recipient is rejected for that transfer only and never blocks the next", options, () => scenario(async ({ runtime, facts, burns, bridge }) => {
  const rt = await runtime();
  await completes(rt, facts, burns[1]);
  await rt.runOnce();
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burns[0].requestId);
    assert.equal(row.state, "rejected"); assert.equal(row.reasonCode, "invalid_recipient");
    assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  assert.equal(facts.relay(burns[0]).state, "approved"); // kept for the operator
  assert.equal(burns[0].recipient, bridge.vault);
  assert.equal(await facts.nonce(), 1);
  assert.equal((await rt.runOnce()).action, "idle");
}, { burns: 2, approvals: "direct", recipientFor: (index, bridge) => (index === 1 ? bridge.vault : recipient) }));

test("one origin with a far-future timestamp never persists a halt: the identical bytes are sent and complete", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  await assert.rejects((await runtime({ boundary: async (name) => { if (name === "signed") throw new Error("stop"); } })).runOnce(), /stop/);
  proxies[1].hook = async ({ message, forward }) => (message.method === "eth_getBlockByNumber" && message.params[0] === "latest"
    ? rewriteResult(await forward(), (block) => ({ ...block, timestamp: `0x${(Math.floor(Date.now() / 1000) + 365 * 86400).toString(16)}` }))
    : forward());
  const rt = await runtime({ offsetMs: 10 * 60_000 });
  // Sending our own committed bytes is never unsafe; no halt is recorded.
  assert.equal((await rt.runOnce()).action, "submitted");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking().length, 0); } finally { ledger.close(); }
  proxies[1].hook = null;
  await completes(rt, facts, burns[0]);
  await assertSingleRelease(facts, burns[0]);
}));

test("one origin returning a different included transaction stops temporarily and never persists a halt", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  const rt = await runtime();
  await rt.runOnce();
  await facts.mine(3);
  proxies[1].hook = async ({ message, forward }) => (message.method === "eth_getTransactionByHash"
    ? rewriteResult(await forward(), (tx) => ({ ...tx, gasPrice: "0x1" })) : forward());
  await assert.rejects(rt.runOnce(), (error) => error.code === "rpc_disagreement" && isTemporaryStop(error));
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking().length, 0); } finally { ledger.close(); }
  proxies[1].hook = null;
  assert.equal((await rt.runOnce()).action, "finalized");
  await assertSingleRelease(facts, burns[0]);
}));

test("two submitter processes contest the lease: exactly one sends", options, () => scenario(async ({ chain, runtime, facts, burns, manifest, paths }) => {
  const base = new URL("../", import.meta.url).href;
  const code = `import { buildCronosSubmitterRuntime } from '${base}src/cronos-submitter.js';
    import { BroadcastLedger } from '${base}src/broadcast-ledger.js';
    import { createEncryptedKeystoreDigestSigner } from '${base}src/secure-keystore.js';
    import { journalOptions } from '${base}test/journal-fixture.js';
    const context = JSON.parse(process.env.SUBMITTER_TEST_CONTEXT);
    const runtime = await buildCronosSubmitterRuntime(context.manifest, { credentialsDirectory: context.credentials,
      makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("cronos")),
      loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }), log: () => {} });
    const startAt = context.startAt; while (Date.now() < startAt) await new Promise((resolve) => setTimeout(resolve, 5));
    let result;
    try { result = (await runtime.runOnce()).action; } catch { result = "refused"; }
    process.stdout.write(result);`;
  const context = { manifest, credentials: paths.credentials, startAt: Date.now() + 1_500 };
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", code],
      { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, SUBMITTER_TEST_CONTEXT: JSON.stringify(context) } });
    let output = "", errors = "";
    child.stdout.on("data", (data) => { output += data; }); child.stderr.on("data", (data) => { errors += data; });
    child.on("close", (status) => (status === 0 ? resolve(output) : reject(new Error(errors))));
  });
  const results = await Promise.all([run(), run()]);
  assert.deepEqual(results.sort(), ["refused", "submitted"]);
  await facts.settle();
  assert.equal(await facts.nonce(), 1);
  const recovered = await runtime({ offsetMs: 10 * 60_000 });
  await completes(recovered, facts, burns[0]);
  assert.equal(await facts.nonce(), 1);
  assert.equal(chain.url.startsWith("http://127.0.0.1"), true);
}));

test("a RelayStore locked by the coordinator pauses run() temporarily instead of ending it", options, () => scenario(async ({ runtime, facts, burns, paths }) => {
  // The coordinator holds a write lock until the submitter has visibly paused,
  // so the scenario does not depend on how long the runtime takes to start.
  const holder = spawn(process.execPath, ["--input-type=module", "-e", `import { DatabaseSync } from "node:sqlite";
    const db = new DatabaseSync(${JSON.stringify(paths.store)}); db.exec("BEGIN IMMEDIATE"); process.stdout.write("locked");
    process.stdin.once("data", () => { db.exec("COMMIT"); db.close(); process.exit(0); });`], { stdio: ["pipe", "pipe", "inherit"] });
  await new Promise((resolve) => holder.stdout.once("data", resolve));
  const logs = [];
  const controller = new AbortController();
  const rt = await buildCronosSubmitterRuntime((await runtime()).manifest, { credentialsDirectory: paths.credentials,
    makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("cronos")),
    makeStore: (path) => openExistingRelayStore(path, { busyTimeoutMs: 100 }),
    loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }),
    now: () => Date.now() + 10 * 60_000,
    log: (report) => {
      logs.push(report);
      if (report.action === "temporarily_stopped" && !holder.stdin.writableEnded) holder.stdin.end("release\n");
      if (report.action === "submitted") controller.abort();
    } });
  try { await rt.run({ signal: controller.signal }); } finally { rt.close(); }
  assert.ok(logs.some((report) => report.action === "temporarily_stopped" && report.code === "relay_store_busy"));
  assert.equal(logs.at(-1).action, "submitted");
  assert.equal(facts.relay(burns[0]).state, "submitted");
  await facts.settle();
  assert.equal(await facts.nonce(), 1);
}));

const warp = async (chain, seconds) => { await chain.rpc("evm_increaseTime", [seconds]); await chain.rpc("evm_mine", []); };
const PROCESSED_SELECTOR = VAULT.getFunction("processedBurns").selector;
const stopAtSigned = { boundary: async (name) => { if (name === "signed") throw new Error("stop"); } };

for (const fault of ["rate-limited simulation", "false replay flag"]) {
  test(`one origin with a ${fault} cannot block the queue: the expired signed bytes are sent once and recorded as expired`, options, () => scenario(async ({ chain, proxies, runtime, facts, burns, approve }) => {
    await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
    proxies[1].hook = async ({ message, forward }) => {
      const call = message.method === "eth_call" ? message.params[0] : null;
      if (fault === "rate-limited simulation" && call?.from) {
        return JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32005, message: "limit exceeded" } });
      }
      if (fault === "false replay flag" && call?.data?.startsWith(PROCESSED_SELECTOR)) return rewriteResult(await forward(), () => `0x${"0".repeat(63)}1`);
      return forward();
    };
    const before = await runtime({ offsetMs: 10 * 60_000 });
    if (fault === "rate-limited simulation") await assert.rejects(before.runOnce(), (error) => ["rpc_error", "rpc_disagreement"].includes(error.code) && isTemporaryStop(error));
    // Origins disagreeing on the replay flag: the row is not sent (a temporary stop).
    else await assert.rejects(before.runOnce(), (error) => error.code === "rpc_disagreement" && isTemporaryStop(error));
    assert.equal(await facts.nonce(), 0);
    // The provider fault outlasts the approval: the deadline passes on chain and locally.
    await warp(chain, 1_300);
    const after = await runtime({ offsetMs: 10 * 60_000 + 1_300_000 });
    const sent = await after.runOnce();
    assert.equal(sent.action, "submitted"); // stored bytes, no simulation
    proxies[1].hook = null;
    await facts.mine(3);
    assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
    const expired = await after.runOnce();
    assert.equal(expired.action, "expired");
    const ledger = facts.ledger();
    try {
      assert.equal(ledger.inspect(burns[0].requestId).state, "expired"); assert.equal(ledger.blocking().length, 0);
    } finally { ledger.close(); }
    assert.equal(facts.relay(burns[0]).state, "submitted"); // still in flight: the burn awaits a new approval
    assert.equal(await facts.processed(burns[0]), false);
    await approve(burns[1], Math.floor(Date.now() / 1000) + 1_300 + 600 + 1_800);
    await completes(after, facts, burns[1]);
    await assertSingleRelease(facts, burns[1]);
    assert.equal(await facts.nonce(), 2);
  }, { burns: 2, approved: 1, deadlineOffset: 1_200 }));
}

test("a claimed row whose approval expires during downtime is released without a nonce and the queue moves on", options, () => scenario(async ({ chain, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime({ boundary: async (name) => { if (name === "claimed") throw new Error("stop"); } })).runOnce(), /stop/);
  await warp(chain, 1_300);
  const rt = await runtime({ offsetMs: 10 * 60_000 + 1_300_000 });
  const released = await rt.runOnce();
  assert.equal(released.action, "waiting"); assert.equal(released.unclaimed, true);
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burns[0].requestId);
    assert.equal(row.state, "unclaimed"); assert.equal(row.nonce, null); assert.equal(ledger.nextNonce(), null);
  } finally { ledger.close(); }
  await approve(burns[1], Math.floor(Date.now() / 1000) + 1_300 + 600 + 1_800);
  await completes(rt, facts, burns[1]);
  assert.equal(await facts.nonce(), 1);
  assert.equal(facts.relay(burns[0]).state, "approved");
}, { burns: 2, approved: 1, deadlineOffset: 1_200 }));

test("release evidence after a front-run is found from the deadline and our receipt, even after long downtime", options, () => scenario(async ({ chain, bridge, runtime, facts, burns }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  const ours = await chain.rpc("eth_getTransactionByHash", [sent.transactionHash]);
  const attacker = await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: ours.input, gasPrice: 50_000_000_000n, gasLimit: 400_000n })]);
  await chain.rpc("evm_mine", []);
  await chain.rpc("evm_setAutomine", [true]);
  // Downtime: past the approval deadline and far beyond releaseLookbackBlocks (1000).
  await warp(chain, 4_000);
  await chain.rpc("anvil_mine", ["0x514"]);
  const later = await runtime({ offsetMs: 4_000_000 + 10 * 60_000 });
  const outcome = await later.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, attacker);
  assert.equal(facts.relay(burns[0]).release_ref, attacker);
}));

test("processed without findable release evidence is a persistent non-blocking alert, never a completion", options, () => scenario(async ({ chain, bridge, store, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  await thirdPartyRelease(chain, bridge, store, burns[0]);
  await chain.rpc("anvil_mine", ["0x514"]); // the release falls outside every search window
  const rt = await runtime({ offsetMs: 10 * 60_000 });
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted"); // consumes the reserved nonce; it reverts
  await facts.mine(3);
  const alert = await rt.runOnce();
  assert.equal(alert.action, "release_unverified");
  assert.equal(facts.relay(burns[0]).state, "submitted"); assert.equal(facts.relay(burns[0]).release_ref, null);
  await approve(burns[1]);
  const reports = [];
  for (let i = 0; i < 8 && facts.relay(burns[1]).state !== "completed"; i++) { reports.push(await rt.runOnce()); await facts.mine(3); }
  assert.equal(facts.relay(burns[1]).state, "completed");
  assert.ok(reports.every((report) => report.attention.releaseUnverified === 1));
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking().length, 0); } finally { ledger.close(); }
  assert.equal(await facts.nonce(), 2);
}, { burns: 2, approved: 1 }));

// Pruned or state-synced origin: no block (null) or log (JSON-RPC error)
// older than `oldest`; recent history is served normally.
function pruneHistory(proxy, oldest, { blocks = true, logs = true } = {}) {
  proxy.hook = async ({ message, forward }) => {
    const number = (value) => (typeof value === "string" && value.startsWith("0x") ? Number.parseInt(value, 16) : Number.POSITIVE_INFINITY);
    if (blocks && message.method === "eth_getBlockByNumber" && number(message.params[0]) < oldest) {
      return JSON.stringify({ jsonrpc: "2.0", id: message.id, result: null });
    }
    if (logs && message.method === "eth_getLogs" && number(message.params[0].fromBlock) < oldest) {
      return JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32000, message: "history pruned" } });
    }
    return forward();
  };
}

async function frontRun(chain, bridge, rt) {
  await chain.rpc("evm_setAutomine", [false]);
  const sent = await rt.runOnce();
  const ours = await chain.rpc("eth_getTransactionByHash", [sent.transactionHash]);
  const attacker = await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: ours.input, gasPrice: 50_000_000_000n, gasLimit: 400_000n })]);
  await chain.rpc("evm_mine", []);
  await chain.rpc("evm_setAutomine", [true]);
  return { sent, attacker };
}

test("a pruned origin cannot stall release evidence after the deadline: our receipt is searched first, within recent history", options, () => scenario(async ({ chain, bridge, proxies, runtime, facts, burns }) => {
  const rt = await runtime();
  const { attacker } = await frontRun(chain, bridge, rt);
  await warp(chain, 4_000); // the deadline has passed; our receipt is still recent
  await chain.rpc("anvil_mine", ["0x5"]);
  pruneHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000);
  const later = await runtime({ offsetMs: 4_000_000 + 10 * 60_000 });
  const outcome = await later.runOnce();
  assert.equal(outcome.action, "released_elsewhere"); assert.equal(outcome.releaseHash, attacker);
  assert.equal(facts.relay(burns[0]).release_ref, attacker);
}, { history: 1_500 }));

test("history an origin no longer serves ends the search in a non-blocking alert, never an endless temporary stop", options, () => scenario(async ({ chain, bridge, proxies, runtime, facts, burns, approve }) => {
  const rt = await runtime();
  await frontRun(chain, bridge, rt);
  await warp(chain, 4_000);
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  pruneHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000, { blocks: false });
  const later = await runtime({ offsetMs: 4_000_000 + 10 * 60_000 });
  const alert = await later.runOnce();
  assert.equal(alert.action, "release_unverified");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking().length, 0); } finally { ledger.close(); }
  await approve(burns[1], Math.floor(Date.now() / 1000) + 4_000 + 600 + 1_800);
  const reports = [];
  for (let i = 0; i < 8 && facts.relay(burns[1]).state !== "completed"; i++) { reports.push(await later.runOnce()); await facts.mine(3); }
  assert.equal(facts.relay(burns[1]).state, "completed");
  assert.ok(reports.every((report) => report.attention.releaseUnverified === 1));
}, { burns: 2, approved: 1, history: 100, approvals: "direct" }));

test("with three origins one origin's wrong nonce cannot hold a signed row: a strict majority sends it", options, () => scenario(async ({ proxies, runtime, facts, burns }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  proxies[2].hook = async ({ message, forward }) => (message.method === "eth_getTransactionCount"
    ? rewriteResult(await forward(), () => "0x7") : forward());
  const rt = await runtime({ offsetMs: 10 * 60_000 });
  assert.equal((await rt.runOnce()).action, "submitted");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking().length, 0); } finally { ledger.close(); }
  await completes(rt, facts, burns[0]);
  await assertSingleRelease(facts, burns[0]);
}, { origins: 3 }));

test("an origin outage cannot keep a signed row from consuming its nonce once the local deadline margin is lost", options, () => scenario(async ({ chain, proxies, runtime, facts, burns }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  const rt = await runtime({ offsetMs: 10 * 60_000 + 1_300_000 }); // running before the outage starts
  proxies[1].hook = async ({ response }) => { response.destroy(); return undefined; }; // origin down
  await warp(chain, 1_300);
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted"); // no origin read needed to send our own bytes
  proxies[1].hook = null;
  await facts.mine(3);
  assert.equal((await rt.runOnce()).action, "expired");
  const ledger = facts.ledger();
  try { assert.equal(ledger.inspect(burns[0].requestId).state, "expired"); } finally { ledger.close(); }
}, { deadlineOffset: 1_200 }));

test("an early send that reverts before the deadline for a lasting reason is transfer-specific, not a queue-wide failure", options, () => scenario(async ({ chain, bridge, store, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  await approve(burns[1], Math.floor(Date.now() / 1000) + 7_000);
  await thirdPartyRelease(chain, bridge, store, burns[1]); // exhausts the daily release limit
  // Locally the deadline margin is lost, on chain the deadline has not passed.
  const rt = await runtime({ offsetMs: (1_200 - 30) * 1_000 });
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await facts.mine(3);
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  const reverted = await rt.runOnce();
  assert.equal(reverted.action, "reverted"); assert.equal(reverted.code, "daily_release_limit_exhausted");
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burns[0].requestId);
    assert.equal(row.state, "reverted"); assert.equal(row.reasonCode, "daily_release_limit_exhausted");
    assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  assert.equal(facts.relay(burns[0]).state, "submitted");
  const next = await rt.runOnce(); // the queue moves on
  assert.equal(next.action, "released_elsewhere");
  assert.equal(next.attention.reverted, 1);
}, { burns: 2, approved: 1, deadlineOffset: 1_200, bridgeOptions: { maxRelease: AMOUNT, dailyLimit: (AMOUNT * 3n) / 2n } }));

const PAUSED_SELECTOR = VAULT.getFunction("paused").selector;
const resumeVault = async (chain, bridge, deadline) => included(chain, await signedCall(chain, localKeys.deployer, { to: bridge.vault,
  data: VAULT.encodeFunctionData("resume", [0, deadline, controlSignatures({ vault: bridge.vault, action: "RESUME", payloadHash: ZeroHash,
    nonce: 0, deadline, keys: [keys[0], keys[1]] })]) }));

test("a known guardian pause still holds a signed row once the local deadline margin is lost; after the resume it ends expired, never failed", options, () => scenario(async ({ chain, bridge, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  await included(chain, await signedCall(chain, localKeys.guardian, { to: bridge.vault, data: VAULT.encodeFunctionData("pause") }));
  // Locally the deadline margin is lost, on chain the deadline has not passed.
  const rt = await runtime({ offsetMs: (1_200 - 30) * 1_000 });
  const held = await rt.runOnce();
  assert.equal(held.action, "waiting"); assert.equal(held.code, "route_paused");
  assert.equal(await facts.nonce(), 0); // nothing is sent into the pause
  // The pause outlasts the approval; a quorum-signed resume follows.
  await warp(chain, 1_300);
  await resumeVault(chain, bridge, Math.floor(Date.now() / 1000) + 1_300 + 600);
  const later = await runtime({ offsetMs: 1_300_000 + 10 * 60_000 });
  assert.equal((await later.runOnce()).action, "submitted"); // the identical bytes, now past the deadline
  await facts.mine(3);
  assert.equal((await later.runOnce()).action, "expired");
  const ledger = facts.ledger();
  try {
    assert.equal(ledger.inspect(burns[0].requestId).state, "expired"); assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  await approve(burns[1], Math.floor(Date.now() / 1000) + 1_300 + 600 + 1_800);
  await completes(later, facts, burns[1]);
  await assertSingleRelease(facts, burns[1]);
  assert.equal(await facts.nonce(), 2);
}, { burns: 2, approved: 1, deadlineOffset: 1_200 }));

test("bytes sent without a readable pause flag that revert under the pause are non-blocking (vault_paused), never failed", options, () => scenario(async ({ chain, bridge, proxies, runtime, facts, burns }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  await included(chain, await signedCall(chain, localKeys.guardian, { to: bridge.vault, data: VAULT.encodeFunctionData("pause") }));
  for (const proxy of proxies) {
    proxy.hook = async ({ message, forward }) => (message.method === "eth_call" && message.params[0]?.data?.startsWith(PAUSED_SELECTOR)
      ? JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32005, message: "limit exceeded" } }) : forward());
  }
  const rt = await runtime({ offsetMs: (1_200 - 30) * 1_000 });
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted"); // the pause read failed on every origin: our bytes are sent
  for (const proxy of proxies) proxy.hook = null;
  await facts.mine(3);
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  const reverted = await rt.runOnce();
  assert.equal(reverted.action, "reverted"); assert.equal(reverted.code, "vault_paused");
  const ledger = facts.ledger();
  try {
    assert.equal(ledger.inspect(burns[0].requestId).state, "reverted"); assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
}, { deadlineOffset: 1_200 }));

test("a vault condition that only appears after our transaction in its block is not taken as the revert cause", options, () => scenario(async ({ chain, bridge, runtime, facts }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  const ours = await chain.rpc("eth_getTransactionByHash", [sent.transactionHash]);
  await refuseTransfers(chain, bridge, { gasPrice: 50_000_000_000n }); // before ours: the real, unexplained cause
  // After ours in the same block: governance lowers the release limit below the amount.
  const limits = [AMOUNT / 2n, 5n * 10n ** 20n], deadline = Math.floor(Date.now() / 1000) + 600;
  const signatures = controlSignatures({ vault: bridge.vault, action: "UPDATE_LIMITS", nonce: 0, deadline, keys: [keys[0], keys[1]],
    payloadHash: keccak256(AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], limits)) });
  const lowered = await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: VAULT.encodeFunctionData("updateLimits", [...limits, 0, deadline, signatures]), gasPrice: BigInt(ours.gasPrice) - 1n })]);
  await chain.rpc("evm_mine", []);
  const [mine, theirs] = await receiptsOf(chain, [sent.transactionHash, lowered]);
  assert.equal(mine.status, "0x0"); assert.equal(theirs.status, "0x1"); assert.equal(mine.blockHash, theirs.blockHash);
  assert.ok(Number(mine.transactionIndex) < Number(theirs.transactionIndex));
  assert.equal((await rt.runOnce()).action, "pending");
  await facts.mine(3);
  await assert.rejects(rt.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "destination_execution_failed");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking()[0].state, "failed"); } finally { ledger.close(); }
}, { token: "adversarial" }));

// Pruned origin for our own history: receipts and transactions mined before
// `oldest` are no longer returned (null, a pruned transaction index), with
// `blocks` neither are such blocks, and with `state` state reads at such
// heights fail (JSON-RPC error). Recent history is served normally.
function pruneOwnHistory(proxy, oldest, { receipts = true, blocks = false, state = false } = {}) {
  const number = (value) => (typeof value === "string" && value.startsWith("0x") ? Number.parseInt(value, 16) : Number.POSITIVE_INFINITY);
  proxy.hook = async ({ message, forward }) => {
    if (blocks && message.method === "eth_getBlockByNumber" && number(message.params[0]) < oldest) {
      return JSON.stringify({ jsonrpc: "2.0", id: message.id, result: null });
    }
    if (state && message.method === "eth_call" && number(message.params[1]) < oldest) {
      return JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32000, message: "missing trie node" } });
    }
    if (receipts && ["eth_getTransactionReceipt", "eth_getTransactionByHash"].includes(message.method)) {
      return rewriteResult(await forward(), (result) => (result && number(result.blockNumber) < oldest ? null : result));
    }
    return forward();
  };
}

for (const [pruned, origins] of [["its transaction index", 2], ["its transaction index and blocks", 3]]) {
test(`our own receipt that one of ${origins} origins no longer serves after long downtime (${pruned} pruned) is a non-blocking alert, never pending forever`, options, () => scenario(async ({ chain, proxies, runtime, facts, burns, approve }) => {
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await facts.settle();
  const mined = await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash]);
  assert.equal(mined.status, "0x1");
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  pruneOwnHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000, { blocks: pruned.endsWith("blocks") });
  const alert = await rt.runOnce();
  assert.equal(alert.action, "release_unverified"); assert.equal(alert.code, "receipt_history_unserved");
  const ledger = facts.ledger();
  try {
    const row = ledger.inspect(burns[0].requestId);
    assert.equal(row.state, "release_unverified"); assert.equal(row.blockHash, mined.blockHash);
    assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  assert.equal(facts.relay(burns[0]).state, "submitted"); // never completed without every origin's evidence
  await approve(burns[1]);
  const reports = [];
  for (let i = 0; i < 8 && facts.relay(burns[1]).state !== "completed"; i++) { reports.push(await rt.runOnce()); await facts.mine(3); }
  assert.equal(facts.relay(burns[1]).state, "completed");
  assert.ok(reports.every((report) => report.attention.releaseUnverified === 1));
  assert.equal(await facts.nonce(), 2);
}, { burns: 2, approved: 1, origins }));
}

test("with two origins, an old receipt that one origin no longer serves at all, block included, fails closed with the halt", options, () => scenario(async ({ chain, proxies, runtime, facts }) => {
  const rt = await runtime();
  assert.equal((await rt.runOnce()).action, "submitted");
  await facts.settle();
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  pruneOwnHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000, { blocks: true });
  // One origin shows the block with our transaction, the other refuses it: no strict majority.
  await assert.rejects(rt.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "nonce_consumed_without_receipt");
  const ledger = facts.ledger();
  try { assert.equal(ledger.blocking()[0].reasonCode, "nonce_consumed_without_receipt"); } finally { ledger.close(); }
}));

// Rewrites the transaction list of one block in an origin's answers.
const rewriteBlock = (number, transform) => async ({ message, forward }) => (message.method === "eth_getBlockByNumber" && message.params[0] === number
  ? rewriteResult(await forward(), (block) => ({ ...block, transactions: transform(block.transactions) })) : undefined);

for (const origins of [2, 3]) {
  test(`one of ${origins} origins fabricating an old receipt and block for a send that never landed cannot turn a foreign use of our nonce into an alert`, options, () => scenario(async ({ chain, bridge, proxies, runtime, facts, burns, approve }) => {
    for (const proxy of proxies) proxy.hook = async ({ message, forward, response }) => {
      if (message.method === "eth_sendRawTransaction") { response.destroy(); return undefined; }
      return forward();
    };
    const rt = await runtime();
    const sent = await rt.runOnce();
    assert.equal(sent.action, "submitted"); // our bytes never reach the chain
    for (const proxy of proxies) proxy.hook = null;
    // Our key is used elsewhere at the reserved nonce.
    await included(chain, await signedCall(chain, localKeys.submitter, { to: localAddress(localKeys.deployer), data: "0x", gasLimit: 21_000n, nonce: 0 }));
    assert.equal(await facts.nonce(), 1);
    // One origin claims our hash was mined in an old block and shows that block
    // with it; the honest origins still serve the block, without it.
    const claimed = await chain.rpc("eth_getBlockByNumber", ["0x64", false]);
    assert.ok(!claimed.transactions.includes(sent.transactionHash));
    const fabricated = { transactionHash: sent.transactionHash, transactionIndex: "0x0", blockHash: claimed.hash, blockNumber: claimed.number,
      from: SUBMITTER.toLowerCase(), to: bridge.vault.toLowerCase(), contractAddress: null, cumulativeGasUsed: "0x186a0", gasUsed: "0x186a0",
      effectiveGasPrice: "0x3b9aca00", logs: [], logsBloom: `0x${"0".repeat(512)}`, status: "0x1", type: "0x0" };
    const forged = rewriteBlock(claimed.number, (transactions) => [...transactions, sent.transactionHash]);
    proxies.at(-1).hook = async (call) => (call.message.method === "eth_getTransactionReceipt" && call.message.params[0] === sent.transactionHash
      ? JSON.stringify({ jsonrpc: "2.0", id: call.message.id, result: fabricated }) : (await forged(call)) ?? call.forward());
    await assert.rejects(rt.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "nonce_consumed_without_receipt");
    const ledger = facts.ledger();
    try {
      const [row] = ledger.blocking();
      assert.equal(row.state, "halted"); assert.equal(row.reasonCode, "nonce_consumed_without_receipt");
      assert.equal(ledger.attention().releaseUnverified, 0);
    } finally { ledger.close(); }
    await approve(burns[1]);
    await assert.rejects(rt.runOnce(), (error) => error.code === "ledger_requires_review"); // the next transfer is never signed
    assert.equal(await facts.nonce(), 1);
    assert.equal(facts.relay(burns[1]).state, "approved");
  }, { burns: 2, approved: 1, history: 1_500, origins }));
}

test("with three origins one origin hiding our old transaction from its block cannot force the halt: the receipt stays a non-blocking alert", options, () => scenario(async ({ chain, proxies, runtime, facts, burns }) => {
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await facts.settle();
  const mined = await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash]);
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  // An honest origin with a pruned transaction index still serves the block with our transaction.
  pruneOwnHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000);
  // The lying origin denies our receipt and serves the block without our transaction.
  const hidden = rewriteBlock(mined.blockNumber, (transactions) => transactions.filter((hash) => hash !== sent.transactionHash));
  proxies[2].hook = async (call) => (["eth_getTransactionReceipt", "eth_getTransactionByHash"].includes(call.message.method)
    && call.message.params[0] === sent.transactionHash
    ? JSON.stringify({ jsonrpc: "2.0", id: call.message.id, result: null }) : (await hidden(call)) ?? call.forward());
  const alert = await rt.runOnce();
  assert.equal(alert.action, "release_unverified"); assert.equal(alert.code, "receipt_history_unserved");
  const ledger = facts.ledger();
  try {
    assert.equal(ledger.inspect(burns[0].requestId).state, "release_unverified"); assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
}, { origins: 3 }));

test("a revert whose cause an origin can no longer read after long downtime is a non-blocking alert, never an endless temporary stop", options, () => scenario(async ({ chain, bridge, store, proxies, runtime, facts, burns, approve }) => {
  await assert.rejects((await runtime(stopAtSigned)).runOnce(), /stop/);
  await approve(burns[1], Math.floor(Date.now() / 1000) + 7_000);
  await thirdPartyRelease(chain, bridge, store, burns[1]); // exhausts the daily release limit
  const rt = await runtime({ offsetMs: (1_200 - 30) * 1_000 });
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await facts.settle();
  assert.equal((await chain.rpc("eth_getTransactionReceipt", [sent.transactionHash])).status, "0x0");
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  pruneOwnHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000, { receipts: false, state: true });
  const alert = await rt.runOnce();
  assert.equal(alert.action, "release_unverified"); assert.equal(alert.code, "revert_history_unserved");
  const ledger = facts.ledger();
  try {
    assert.equal(ledger.inspect(burns[0].requestId).state, "release_unverified"); assert.equal(ledger.blocking().length, 0);
  } finally { ledger.close(); }
  await rt.runOnce(); // the queue moves on: no ledger_requires_review
  assert.equal(facts.relay(burns[0]).state, "submitted");
}, { burns: 2, approved: 1, deadlineOffset: 1_200, bridgeOptions: { maxRelease: AMOUNT, dailyLimit: (AMOUNT * 3n) / 2n } }));

// A release of the burn to another recipient, signed by two of the three
// signer keys (the signer-compromise case).
async function compromisedRelease(chain, bridge, store, burn, otherRecipient, options = {}) {
  const p = store.approvalRequest("xitcoin", burn.requestId).payload;
  const digest = TypedDataEncoder.hash({ name: "Xitcoin Cronos Bridge Vault", version: "1", chainId: 338, verifyingContract: bridge.vault },
    { Release: [{ name: "sourceBurnId", type: "bytes32" }, { name: "recipient", type: "address" }, { name: "amount", type: "uint256" },
      { name: "signerSetVersion", type: "uint64" }, { name: "deadline", type: "uint256" }] },
    { sourceBurnId: p.sourceBurnId, recipient: otherRecipient, amount: p.amount, signerSetVersion: p.signerSetVersion, deadline: p.deadline });
  const signatures = [keys[0], keys[1]].map((key) => key.sign(digest).serialized);
  return chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault, gasLimit: 400_000n,
    data: RELEASE.encodeFunctionData("release", [p.sourceBurnId, otherRecipient, p.amount, p.signerSetVersion, p.deadline, signatures]), ...options })]);
}

test("a release with other fields than the approval halts even when an origin no longer serves that history", options, () => scenario(async ({ chain, bridge, store, proxies, runtime, facts, burns }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  const foreign = await compromisedRelease(chain, bridge, store, burns[0], signers[1], { gasPrice: 50_000_000_000n });
  await chain.rpc("evm_mine", []);
  await chain.rpc("evm_setAutomine", [true]);
  const [ours, theirs] = await receiptsOf(chain, [sent.transactionHash, foreign]);
  assert.equal(ours.status, "0x0"); assert.equal(theirs.status, "0x1");
  await warp(chain, 4_000);
  await chain.rpc("anvil_mine", ["0x514"]); // downtime beyond releaseLookbackBlocks
  pruneHistory(proxies[1], Number.parseInt(await chain.rpc("eth_blockNumber"), 16) - 1_000, { blocks: false });
  const later = await runtime({ offsetMs: 4_000_000 + 10 * 60_000 });
  await assert.rejects(later.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "processed_with_mismatching_release");
  await assert.rejects(later.runOnce(), (error) => error.code === "ledger_requires_review");
  const ledger = facts.ledger();
  try {
    const [row] = ledger.blocking();
    assert.equal(row.state, "halted"); assert.equal(row.reasonCode, "processed_with_mismatching_release");
  } finally { ledger.close(); }
  assert.equal(facts.relay(burns[0]).state, "submitted");
}));
