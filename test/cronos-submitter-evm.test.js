// Full Cronos submitter flow against a local anvil chain (chain ID 338) and the
// vendored reviewed vault. Synthetic keys only; no public network is contacted.
import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Interface, ZeroHash, encryptKeystoreJsonSync, keccak256 } from "ethers";
import { BroadcastLedger } from "../src/broadcast-ledger.js";
import { buildTransferApprovalRequest } from "../src/coordinator.js";
import { buildCronosSubmitterRuntime, cronosLedgerBinding } from "../src/cronos-submitter.js";
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
const VAULT = new Interface(["function processedBurns(bytes32) view returns (bool)", "function pause()",
  "function resume(uint256 nonce,uint256 deadline,bytes[] signatures)", "function balanceOf(address) view returns (uint256)"]);
const AMOUNT = 10n ** 18n;
const recipient = signers[0];
const SUBMITTER = localAddress(localKeys.submitter);

function artifacts(version) {
  return { vault: compile(evm.forge, version === "main" ? "vault-main" : "vault-testnet").CronosBridgeVault,
    token: compile(evm.forge, "token").MockERC20 };
}

function approve(store, burn, vault, deadlineUnix) {
  store.observe({ sourceChain: "xitcoin", sourceRef: burn.requestId, routeId: "cronos-testnet-xitcoin-testnet",
    blockHeight: burn.height, blockHash: blockHash(burn.height), transactionHash: burn.transactionHash, messageIndex: 0,
    payload: { requestId: burn.requestId, sender: "xtc1sender", destination: burn.recipient, amount: burn.amount, nonce: burn.nonce } });
  const transfer = store.transition("xitcoin", burn.requestId, "finalized");
  const request = buildTransferApprovalRequest({ transfer, routeId: "cronos-testnet-xitcoin-testnet", cronosRouteId: TESTNET_ROUTE_ID,
    cronosChainId: 338, cronosVault: vault, signerSetVersion: 1, deadlineUnix });
  store.persistApprovalRequest("xitcoin", burn.requestId, request);
  for (const approval of sign(request)) store.recordApproval("xitcoin", burn.requestId, approval);
  store.transition("xitcoin", burn.requestId, "approved");
}

async function scenario(run, { version = "testnet", chainId = 338, burns = 1, approved = burns, deadlineOffset = 3_600,
  patch = {}, cronosPatch = {}, cometBurns = (items) => [items, items] } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "cronos-submitter-"));
  const cleanup = [];
  try {
    const chain = await startAnvil(evm.anvil, { chainId });
    cleanup.push(chain.stop);
    const proxies = [await startProxy(chain.url), await startProxy(chain.url)];
    cleanup.push(...proxies.map((proxy) => proxy.stop));
    const bridge = await deployBridge(chain, artifacts(version), { routeId: TESTNET_ROUTE_ID, signers, version });
    await chain.rpc("anvil_mine", ["0xa"]); // vault identity is read at a finalized height
    const allBurns = Array.from({ length: burns }, (_, index) => xitcoinBurn({ index: index + 1, recipient, amount: AMOUNT.toString() }));
    const [firstComet, secondComet] = cometBurns(allBurns);
    const comets = [await startCometBft(firstComet), await startCometBft(secondComet)];
    cleanup.push(...comets.map((comet) => comet.stop));
    const paths = { store: join(directory, "relay.sqlite"), ledger: join(directory, "ledger.sqlite"),
      keystore: join(directory, "keystore.json"), credentials: join(directory, "credentials") };
    const store = new RelayStore(paths.store);
    cleanup.push(() => store.close());
    const deadlineUnix = Math.floor(Date.now() / 1000) + deadlineOffset;
    for (const burn of allBurns.slice(0, approved)) approve(store, burn, bridge.vault, deadlineUnix);
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
        minDeadlineMarginSeconds: 60, maxBroadcastAttempts: 5, ...cronosPatch },
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
      approve: (burn) => approve(store, burn, bridge.vault, deadlineUnix) });
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
  // An independent ledger and RelayStore copy see the vault replay flag and halt.
  mkdirSync(join(directory, "second"), { mode: 0o700 });
  const independent = await runtime({ manifestOverride: { ...manifest, relayStorePath: copy, ledgerPath: join(directory, "second", "ledger.sqlite") } });
  await assert.rejects(independent.runOnce(), (error) => error instanceof SubmissionHalt && error.code === "processed_without_local_transaction");
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

test("finalized failed execution is recorded, halts and is never retried", options, () => scenario(async ({ chain, bridge, runtime, facts }) => {
  await chain.rpc("evm_setAutomine", [false]);
  const rt = await runtime();
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  await chain.rpc("eth_sendRawTransaction", [await signedCall(chain, localKeys.guardian, { to: bridge.vault,
    data: VAULT.encodeFunctionData("pause"), gasPrice: 50_000_000_000n })]);
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
  approve(burns[1]);
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
    }, { cometBurns });
  }
});

test("a stored request that no longer matches its finalized source transfer halts", options, () => scenario(async ({ runtime, facts, store, burns }) => {
  store.database.exec(`UPDATE transfers SET block_hash = '0x${"9".repeat(64)}'`);
  await assert.rejects((await runtime()).runOnce(), (error) => error instanceof SubmissionHalt && error.code === "stored_request_mismatch");
  assert.equal(await facts.nonce(), 0);
  assert.equal(facts.relay(burns[0]).state, "approved");
}));
