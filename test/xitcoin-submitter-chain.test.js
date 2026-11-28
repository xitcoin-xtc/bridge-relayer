// Full Xitcoin submitter flow against a local xitcoind (chain ID
// xitcoin-testnet-v2-1) built from the pinned pos-chain commit, with the
// bridge route initialised in genesis with synthetic signer keys, and a Cronos
// source on a local anvil chain with the vendored reviewed vault. Approvals
// come from three isolated signer services that verify each deposit on the
// Cronos origins. Synthetic keys only; no public network is contacted.
import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Interface, JsonRpcProvider, computeAddress, encryptKeystoreJsonSync } from "ethers";
import { evmAddressToBech32 } from "../src/address.js";
import { BroadcastLedger } from "../src/broadcast-ledger.js";
import { approveFinalizedTransfer, buildTransferApprovalRequest, returnExpiredApprovals } from "../src/coordinator.js";
import { createApprovalRetirementVerifier } from "../src/approval-retirement.js";
import { APPROVAL_REISSUE_GRACE_SECONDS } from "../src/approvals.js";
import { CronosRpcQuorum } from "../src/cronos-rpc.js";
import { XitcoinRpcQuorum } from "../src/xitcoin-rpc.js";
import { CometBftHttpClient, decodeXitcoinOutboundBlock, decodeXitcoinOutboundTransaction } from "../src/network.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { XITCOIN_TESTNET_ROUTE_ID, attestationId } from "../src/protocol.js";
import { createEncryptedKeystoreDigestSigner } from "../src/secure-keystore.js";
import { SignerApprovalJournal } from "../src/signer-journal.js";
import { IsolatedSignerService, createSignerPolicy } from "../src/signer-service.js";
import { createCanonicalSourceVerifier } from "../src/source-verification.js";
import { RelayStore } from "../src/store.js";
import { validateXitcoinTestnetManifest } from "../src/submitter-manifest.js";
import { CronosFinalizedWatcher, XitcoinFinalizedWatcher } from "../src/watchers.js";
import { buildXitcoinSubmitterRuntime, isTemporaryStop, xitcoinLedgerBinding } from "../src/xitcoin-submitter.js";
import { XITCOIN_CHAIN_SCHEMA_COMMIT, assembleTxRaw, buildXitcoinSignDoc, cosmosSignature, decodeXitcoinTransaction,
  encodeSubmitAttestation } from "../src/xitcoin-transaction.js";
import { journalOptions } from "./journal-fixture.js";
import { keys, signers } from "./fixtures/destination.js";
import { compile, deployBridge, evmAvailability, localAddress, localKeys, signedCall, startAnvil, startProxy } from "./evm/harness.js";
import { CHAIN_ID, THIRD_PARTY_KEY, VECTOR_KEY, chainAccount, chainKey, guardianPauseSignature, resumeSignatures, rewriteJson,
  startXitcoinNode, startXitcoinOrigin, submitterKey, xitcoindAvailability } from "./xitcoin/harness.js";

const evm = evmAvailability();
const chain = xitcoindAvailability();
const skip = evm.skip || chain.skip;
const options = { skip, timeout: 300_000 };
const vectors = JSON.parse(readFileSync(new URL("./fixtures/xitcoin-chain-vectors.json", import.meta.url), "utf8"));
const TOKEN = new Interface(["function mint(address recipient,uint256 amount)", "function approve(address spender,uint256 amount)"]);
const VAULT = new Interface(["function deposit(uint256 amount,address recipient) returns (bytes32)"]);
const AMOUNT = 10n ** 18n;
const GUARDIAN = computeAddress(keys[3].publicKey);
const SUBMITTERS = 40;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let node;
let nextSubmitter = 0;
before(async () => {
  if (skip) return;
  node = await startXitcoinNode({ binary: chain.binary, signers: [...signers], guardian: GUARDIAN,
    accounts: [chainAccount(VECTOR_KEY), ...Array.from({ length: SUBMITTERS }, (_, index) => chainAccount(submitterKey(index)))] });
});
after(async () => { await node?.stop(); });

// Third-party transaction carrying MsgSubmitAttestation for the given request
// and approvals, signed by another funded account.
async function foreignSubmission(key, request, approvals, { routeId = request.payload.routeId } = {}) {
  const account = chainAccount(key);
  const state = (await node.rest(`/cosmos/auth/v1beta1/accounts/${account}`)).body.account;
  const p = request.payload;
  const messageBytes = encodeSubmitAttestation({ submitter: account, routeId, direction: request.direction, sourceChainId: p.sourceChainId,
    sourceRef: p.sourceRef, nonce: p.nonce, destination: p.destination, amount: p.amount, deadlineUnix: String(p.deadlineUnix),
    signatures: approvals.map((approval) => approval.signature) });
  const doc = buildXitcoinSignDoc({ messageBytes, publicKey: key.compressedPublicKey, accountNumber: state.account_number,
    sequence: state.sequence, gasLimit: "400000", feeAmount: (400000n * 4_000_000_000n).toString(), chainId: CHAIN_ID });
  const signature = cosmosSignature(key.sign(doc.signingDigest).serialized, doc.signingDigest, key.compressedPublicKey);
  const raw = assembleTxRaw({ ...doc, signature });
  const accepted = await node.broadcast(raw.signedHex);
  assert.equal(accepted.code, 0);
  return { hash: raw.transactionHash, result: await node.committed(raw.transactionHash) };
}

function isolatedSigners({ vault, proxies }) {
  const providers = proxies.map((proxy) => new JsonRpcProvider(proxy.url, 338, { staticNetwork: true }));
  const clients = [new CometBftHttpClient({ url: node.rpcUrl, chainId: CHAIN_ID, allowHttp: true, decodeBlock: decodeXitcoinOutboundBlock,
    decodeTransaction: decodeXitcoinOutboundTransaction }), new CometBftHttpClient({ url: node.rpcUrl.replace("127.0.0.1", "localhost"),
    chainId: CHAIN_ID, allowHttp: true, decodeBlock: decodeXitcoinOutboundBlock, decodeTransaction: decodeXitcoinOutboundTransaction })];
  const verifySource = createCanonicalSourceVerifier({ cronosRouteId: TESTNET_ROUTE_ID,
    cronosWatcher: new CronosFinalizedWatcher({ providers, vault, routeId: TESTNET_ROUTE_ID, confirmations: 3 }),
    xitcoinWatcher: new XitcoinFinalizedWatcher({ clients, chainId: CHAIN_ID, routeId: XITCOIN_TESTNET_ROUTE_ID, safetyLag: 2 }) });
  const policy = createSignerPolicy({ routeIds: [XITCOIN_TESTNET_ROUTE_ID], cronosChainIds: [338], xitcoinChainIds: [CHAIN_ID],
    cronosVaults: [vault], maximumAmount: (10n ** 21n).toString(), maximumDeadlineSeconds: 7_200 });
  const journals = [0, 1, 2].map(() => new SignerApprovalJournal());
  // Each signer checks an explicit re-issue on the chain itself, through two
  // origins of its own (the Cronos quorum is never contacted for a mint).
  const verifyRetirement = createApprovalRetirementVerifier({ cronos: new CronosRpcQuorum({ urls: proxies.map((proxy) => proxy.url),
    allowLoopbackHttp: true }), cronosVault: vault, cronosConfirmations: 3, xitcoin: new XitcoinRpcQuorum({ allowLoopbackHttp: true,
    origins: [{ rpcUrl: node.rpcUrl, restUrl: node.restUrl },
      { rpcUrl: node.rpcUrl.replace("127.0.0.1", "localhost"), restUrl: node.restUrl.replace("127.0.0.1", "localhost") }] }) });
  const services = [0, 1, 2].map((index) => new IsolatedSignerService({ identity: `signer-${index + 1}`, signerAddress: signers[index],
    policy, verifySource, journal: journals[index], verifyRetirement, signDigest: async (digest) => keys[index].sign(digest).serialized }));
  return { services, verifyRetirement,
    close: () => { for (const provider of providers) provider.destroy(); for (const journal of journals) journal.close?.(); } };
}

async function scenario(run, { deposits = 1, approved = deposits, deadlineOffset = 3_600, xitcoinPatch = {}, origins = 2, manifestPatch = {} } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "xitcoin-submitter-"));
  const cleanup = [];
  try {
    assert.ok(nextSubmitter < SUBMITTERS, "funded submitter accounts exhausted");
    const key = submitterKey(nextSubmitter++);
    const submitter = chainAccount(key);
    const anvil = await startAnvil(evm.anvil);
    cleanup.push(anvil.stop);
    const cronosProxies = [await startProxy(anvil.url), await startProxy(anvil.url)];
    cleanup.push(...cronosProxies.map((proxy) => proxy.stop));
    const artifacts = { vault: compile(evm.forge, "vault-testnet").CronosBridgeVault, token: compile(evm.forge, "token").MockERC20 };
    const bridge = await deployBridge(anvil, artifacts, { routeId: TESTNET_ROUTE_ID, signers });
    const depositor = localKeys.deployer;
    const send = async (to, data) => anvil.rpc("eth_sendRawTransaction", [await signedCall(anvil, depositor, { to, data })]);
    const evmRecipients = Array.from({ length: deposits }, (_, index) => computeAddress(chainKey(0x10_000 + nextSubmitter * 16 + index).publicKey));
    const recipients = evmRecipients.map((address) => evmAddressToBech32(address));
    await send(bridge.token, TOKEN.encodeFunctionData("mint", [localAddress(depositor), AMOUNT * BigInt(deposits)]));
    await send(bridge.token, TOKEN.encodeFunctionData("approve", [bridge.vault, AMOUNT * BigInt(deposits)]));
    for (const recipient of evmRecipients) await send(bridge.vault, VAULT.encodeFunctionData("deposit", [AMOUNT, recipient]));
    await anvil.rpc("anvil_mine", ["0x6"]);
    const providers = cronosProxies.map((proxy) => new JsonRpcProvider(proxy.url, 338, { staticNetwork: true }));
    cleanup.push(() => { for (const provider of providers) provider.destroy(); });
    const watcher = new CronosFinalizedWatcher({ providers, vault: bridge.vault, routeId: TESTNET_ROUTE_ID, confirmations: 3 });
    const records = await watcher.events(1, await watcher.latestFinalizedHeight());
    assert.equal(records.length, deposits);

    const paths = { store: join(directory, "relay.sqlite"), ledger: join(directory, "ledger.sqlite"),
      keystore: join(directory, "keystore.json"), credentials: join(directory, "credentials") };
    const store = new RelayStore(paths.store);
    cleanup.push(() => store.close());
    const signerSet = isolatedSigners({ vault: bridge.vault, proxies: cronosProxies });
    cleanup.push(signerSet.close);
    const requests = [];
    const approve = async (record, deadlineUnix = Math.floor(Date.now() / 1000) + deadlineOffset) => {
      store.observe(record);
      const transfer = store.transition("cronos", record.sourceRef, "finalized");
      const request = buildTransferApprovalRequest({ transfer, routeId: XITCOIN_TESTNET_ROUTE_ID, cronosRouteId: TESTNET_ROUTE_ID,
        cronosChainId: 338, cronosVault: bridge.vault, xitcoinChainId: CHAIN_ID, deadlineUnix });
      const clients = signerSet.services.map((service) => ({ identity: service.identity, approve: (value) => service.approve(value) }));
      await approveFinalizedTransfer({ store, sourceChain: "cronos", sourceRef: record.sourceRef, request, clients,
        authorizedSigners: [...signers], threshold: 2, nowUnix: Math.floor(Date.now() / 1000) });
      requests.push(request);
      return request;
    };
    for (const record of records.slice(0, approved)) await approve(record);

    const xitcoinOrigins = [];
    for (let index = 0; index < origins; index++) xitcoinOrigins.push(await startXitcoinOrigin(node));
    cleanup.push(...xitcoinOrigins.map((origin) => origin.stop));
    writeFileSync(paths.keystore, encryptKeystoreJsonSync({ address: computeAddress(key.publicKey), privateKey: key.privateKey },
      "synthetic-local-test-password", { scrypt: { N: 1 << 10 } }), { mode: 0o600 });
    chmodSync(paths.keystore, 0o600);
    mkdirSync(paths.credentials, { mode: 0o700 });
    writeFileSync(join(paths.credentials, "keystore-password"), "synthetic-local-test-password\n", { mode: 0o600 });
    const manifest = validateXitcoinTestnetManifest({ version: 1, mode: "testnet", destination: "xitcoin", releaseCommit: "a".repeat(40),
      routeId: XITCOIN_TESTNET_ROUTE_ID, cronosChainId: 338, xitcoinChainId: CHAIN_ID,
      relayStorePath: paths.store, ledgerPath: paths.ledger, keystorePath: paths.keystore, cycleIntervalMs: 1_000,
      xitcoin: { origins: xitcoinOrigins.map(({ rpcUrl, restUrl }) => ({ rpcUrl, restUrl })), allowLoopbackHttp: true,
        chainSchemaCommit: XITCOIN_CHAIN_SCHEMA_COMMIT, signerSetVersion: "1", authorizedSigners: [...signers], submitter,
        confirmations: 2, historyBlocks: 1_000, maxAmount: (10n ** 21n).toString(), maxGas: "600000", gasAdjustmentPercent: 130,
        gasHeadroom: 30_000, feeMultiplierPercent: 200, maxGasPrice: "100000000000", maxFee: "60000000000000000",
        minDeadlineMarginSeconds: 30, maxResendIntervalSeconds: 600, stalledAlertSeconds: 3_600, ...xitcoinPatch },
      cronos: { rpcUrls: cronosProxies.map((proxy) => proxy.url), allowLoopbackHttp: true, vault: bridge.vault,
        cronosRouteId: TESTNET_ROUTE_ID, confirmations: 3 }, ...manifestPatch });
    const runtimes = [];
    cleanup.push(() => { for (const runtime of runtimes) runtime.close(); });
    const runtime = async ({ offsetMs = 0, manifestOverride = manifest, boundary } = {}) => {
      const built = await buildXitcoinSubmitterRuntime(manifestOverride, { credentialsDirectory: paths.credentials,
        makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("xitcoin")),
        loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }),
        now: () => Date.now() + offsetMs, log: () => {}, boundary });
      runtimes.push(built);
      return built;
    };
    const idOf = (request) => attestationId({ ...request.payload, direction: request.direction });
    const facts = {
      sequence: () => node.sequence(submitter),
      relay: (record = records[0]) => store.get("cronos", record.sourceRef),
      balance: (index = 0) => node.balance(recipients[index]),
      attestation: (index = 0) => node.attestation(idOf(requests[index])),
      ledger: () => new BroadcastLedger(paths.ledger, xitcoinLedgerBinding(manifest), journalOptions("xitcoin")),
      row: (index = 0) => {
        const ledger = facts.ledger();
        try { return ledger.inspect(idOf(requests[index])); } finally { ledger.close(); }
      },
    };
    await run({ anvil, node, bridge, records, requests, store, manifest, paths, runtime, facts, directory, submitter, key,
      origins: xitcoinOrigins, cronosProxies, approve, idOf, signerSet });
  } finally {
    for (const step of cleanup.reverse()) { try { await step(); } catch { /* best effort */ } }
    rmSync(directory, { recursive: true, force: true });
  }
}

// Runs cycles (one block apart) until the transfer completes in RelayStore.
async function completes(rt, facts, record, { cycles = 40 } = {}) {
  const reports = [];
  for (let i = 0; i < cycles; i++) {
    reports.push(await rt.runOnce());
    if (facts.relay(record).state === "completed") return reports;
    await node.blocks(1);
  }
  throw new Error(`transfer did not complete: ${JSON.stringify(reports.slice(-3))}`);
}

async function assertSingleMint(facts, { index = 0, sequence = 1 } = {}) {
  const relay = facts.relay();
  const row = facts.row(index);
  assert.equal(relay.state, "completed");
  assert.equal(row.state, "finalized");
  assert.equal(relay.destination_ref, row.transactionHash);
  assert.equal(relay.release_ref, row.transactionHash);
  const attestation = await facts.attestation(index);
  assert.equal(attestation.status, "ATTESTATION_STATE_PROCESSED");
  assert.equal(`0x${attestation.record.tx_hash.toLowerCase()}`, row.transactionHash);
  assert.equal(attestation.record.route_id, XITCOIN_TESTNET_ROUTE_ID);
  assert.equal(await facts.balance(index), AMOUNT);
  assert.equal(await facts.sequence(), sequence);
}

test("the chain accepts its own golden transaction and the relayer reproduces it byte for byte", options, async () => {
  const vector = vectors.transactions[0];
  assert.equal(vector.accountNumber, "0");
  assert.equal(vector.submitter, chainAccount(VECTOR_KEY));
  const doc = buildXitcoinSignDoc({ messageBytes: Buffer.from(vector.message.slice(2), "hex"), publicKey: VECTOR_KEY.compressedPublicKey,
    accountNumber: vector.accountNumber, sequence: vector.sequence, gasLimit: vector.gasLimit, feeAmount: vector.feeAmount, chainId: CHAIN_ID });
  const raw = assembleTxRaw({ ...doc, signature: cosmosSignature(VECTOR_KEY.sign(doc.signingDigest).serialized, doc.signingDigest,
    VECTOR_KEY.compressedPublicKey) });
  assert.equal(raw.signedHex, vector.txRaw);
  assert.equal((await node.broadcast(vector.txRaw)).code, 0);
  const committed = await node.committed(vector.txHash);
  assert.equal(committed.tx_result.code, 0, committed.tx_result.log);
  const attestation = await node.attestation(vectors.attestation.attestationId);
  assert.equal(attestation.status, "ATTESTATION_STATE_PROCESSED");
  assert.equal(`0x${attestation.record.tx_hash.toLowerCase()}`, vector.txHash);
  assert.equal(attestation.record.signing_digest, vectors.attestation.signingDigest);
  assert.equal(attestation.record.payload_hash, vectors.attestation.payloadHash);
  assert.equal(attestation.record.route_id, XITCOIN_TESTNET_ROUTE_ID);
});

test("happy path: signers approve, the submitter mints once, completed only after the record and confirmations", options, () => scenario(async ({ runtime, facts, requests }) => {
  const rt = await runtime();
  const first = await rt.runOnce();
  assert.equal(first.action, "submitted", JSON.stringify(first));
  assert.equal(facts.relay().state, "submitted");
  assert.equal(facts.relay().destination_ref, first.transactionHash);
  assert.equal(facts.row().state, "broadcast");
  const reports = await completes(rt, facts, undefined);
  assert.ok(reports.some((report) => report.action === "pending"), "completion waits for confirmations");
  assert.equal(reports.at(-1).action, "finalized");
  assert.equal(reports.at(-1).transactionHash, first.transactionHash);
  await assertSingleMint(facts);
  const record = (await facts.attestation()).record;
  assert.equal(record.signing_digest, requests[0].digest);
  assert.equal(record.deadline_unix, String(requests[0].deadlineUnix));
  // The gas limit came from simulation plus headroom, never a fixed tight limit.
  const committed = await node.committed(first.transactionHash);
  assert.ok(BigInt(committed.tx_result.gas_used) < BigInt(committed.tx_result.gas_wanted));
  assert.ok(BigInt(committed.tx_result.gas_wanted) > BigInt(committed.tx_result.gas_used) + 30_000n);
  for (let i = 0; i < 3; i++) assert.equal((await rt.runOnce()).action, "idle");
  assert.equal(await facts.sequence(), 1);
}));

test("duplicate attempts: concurrent workers, a later worker and an independent ledger never mint twice", options, () => scenario(async ({ runtime, facts, paths, manifest, directory, store }) => {
  const copy = join(directory, "relay-copy.sqlite");
  store.database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  copyFileSync(paths.store, copy);
  const [a, b] = [await runtime(), await runtime()];
  const results = await Promise.allSettled([a.runOnce(), b.runOnce()]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  await assert.rejects(b.runOnce()); // lease still held by the other worker
  const takeover = await runtime({ offsetMs: 10 * 60_000 });
  await completes(takeover, facts);
  await assertSingleMint(facts);
  // An independent ledger and RelayStore copy find the attestation processed
  // by our transaction, record it as released elsewhere and never send.
  mkdirSync(join(directory, "second"), { mode: 0o700 });
  const independent = await runtime({ manifestOverride: { ...manifest, relayStorePath: copy, ledgerPath: join(directory, "second", "ledger.sqlite") } });
  const outcome = await independent.runOnce();
  assert.equal(outcome.action, "released_elsewhere");
  assert.equal(outcome.releaseHash, facts.relay().destination_ref);
  assert.equal(await facts.sequence(), 1);
  assert.equal(await facts.balance(), AMOUNT);
}));

for (const boundary of ["claimed", "signed", "relay-submitted", "broadcast-recorded", "sent", "ledger-finalized", "relay-completed"]) {
  test(`process killed at ${boundary} recovers with exactly one transaction`, options, () => scenario(async ({ runtime, facts, manifest, paths }) => {
    await killedAt(boundary, manifest, paths);
    const recovered = await runtime({ offsetMs: 10 * 60_000 });
    await completes(recovered, facts);
    await assertSingleMint(facts);
  }));
}

// Runs the submitter in a child process that SIGKILLs itself at a boundary.
async function killedAt(boundary, manifest, paths) {
  const base = new URL("../", import.meta.url).href;
  const code = `import { buildXitcoinSubmitterRuntime } from '${base}src/xitcoin-submitter.js';
    import { BroadcastLedger } from '${base}src/broadcast-ledger.js';
    import { createEncryptedKeystoreDigestSigner } from '${base}src/secure-keystore.js';
    import { journalOptions } from '${base}test/journal-fixture.js';
    const context = JSON.parse(process.env.SUBMITTER_TEST_CONTEXT);
    const runtime = await buildXitcoinSubmitterRuntime(context.manifest, { credentialsDirectory: context.credentials,
      makeLedger: (path, binding) => new BroadcastLedger(path, binding, journalOptions("xitcoin")),
      loadSigner: (input) => createEncryptedKeystoreDigestSigner({ ...input, expectedCredentialOwnerUid: process.geteuid() }),
      log: () => {}, boundary: async (name) => { if (name === context.boundary) process.kill(process.pid, "SIGKILL"); } });
    for (let i = 0; i < 40; i++) { await runtime.runOnce(); await new Promise((resolve) => setTimeout(resolve, 400)); }
    process.exit(3);`;
  await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, SUBMITTER_TEST_CONTEXT: JSON.stringify({ manifest, credentials: paths.credentials, boundary }) } });
    let errors = "";
    child.stderr.on("data", (data) => { errors += data; });
    child.on("close", (status, signal) => (signal === "SIGKILL" ? resolve() : reject(new Error(`child ${status}: ${errors}`))));
  });
}

test("the chain rejects the display label route and mints with the stored route ID", options, () => scenario(async ({ requests, store, records }) => {
  const approvals = store.approvals("cronos", records[0].sourceRef).map(({ signer, digest, signature }) => ({ signer, digest, signature }));
  const label = await foreignSubmission(THIRD_PARTY_KEY, requests[0], approvals, { routeId: "cronos-testnet-xitcoin-testnet" });
  assert.equal(label.result.tx_result.code, 1);
  assert.match(label.result.tx_result.log, /route does not match configuration/);
  const stored = await foreignSubmission(THIRD_PARTY_KEY, requests[0], approvals);
  assert.equal(stored.result.tx_result.code, 0);
}));

test("wrong chain, mainnet, route or signer set stops before any claim", options, () => scenario(async ({ runtime, facts, manifest, origins }) => {
  for (const patch of [{ routeId: "cronos-testnet-xitcoin-testnet" }, { xitcoinChainId: "xitcoin" }, { xitcoinChainId: "xitcoin-testnet-v2-2" },
    { cronosChainId: 25 }]) {
    assert.throws(() => validateXitcoinTestnetManifest({ ...manifest, ...patch }));
  }
  for (const [network, code] of [["xitcoin", "xitcoin_mainnet_rejected"], ["xitcoin-testnet-v2-2", "unexpected_chain_id"]]) {
    origins[1].hook = async ({ kind, method, forward }) => {
      const result = await forward();
      return kind === "rpc" && method === "status" ? rewriteJson(result.text, (body) => {
        body.result.node_info.network = network; return body;
      }) : result;
    };
    await assert.rejects(runtime(), (error) => error.code === code);
  }
  origins[1].hook = null;
  // The chain's signer set differs from the pinned one.
  const rt = await runtime({ manifestOverride: { ...manifest, xitcoin: { ...manifest.xitcoin,
    authorizedSigners: [signers[0], signers[1], computeAddress(keys[3].publicKey)] } } });
  await assert.rejects(rt.runOnce(), (error) => error.code === "signer_set_mismatch" && !isTemporaryStop(error));
  assert.equal(facts.row().found, false);
  assert.equal(await facts.sequence(), 0);
}));

test("RPC disagreement stops temporarily and claims nothing until the origins agree", options, () => scenario(async ({ runtime, facts, origins }) => {
  const rt = await runtime();
  // One origin reports another signer set for the route.
  origins[0].hook = async ({ kind, path, forward }) => {
    const result = await forward();
    if (kind !== "rest" || !path.startsWith("/xitcoin/bridge/v1/routes/")) return result;
    return { status: result.status, text: rewriteJson(result.text, (body) => {
      body.route.bridge_signers = [body.route.bridge_signers[1], body.route.bridge_signers[0], computeAddress(keys[3].publicKey)]; return body;
    }) };
  };
  await assert.rejects(rt.runOnce(), (error) => isTemporaryStop(error) && error.code === "rpc_disagreement");
  // One origin reports the deposit processed without a record, the other absent.
  origins[0].hook = async ({ kind, path, forward }) => {
    const result = await forward();
    if (kind !== "rest" || !path.startsWith("/xitcoin/bridge/v1/attestations/")) return result;
    return { status: result.status, text: rewriteJson(result.text, (body) => ({ ...body, status: "ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD",
      processed: true })) };
  };
  const unsettled = await rt.runOnce();
  assert.equal(unsettled.action, "waiting");
  assert.deepEqual(unsettled.waiting, ["replay_state_unsettled"]);
  // One origin never answers the simulation (the transfer is deferred above,
  // so a later clock is used to assess it again).
  origins[0].hook = async ({ kind, method, forward }) => (kind === "rpc" && method === "abci_query" ? new Promise(() => {}) : forward());
  const stalled = await runtime({ offsetMs: 2 * 60_000 });
  await assert.rejects(stalled.runOnce(), (error) => isTemporaryStop(error) && error.code === "timeout");
  assert.equal(facts.row().found, false);
  assert.equal(await facts.sequence(), 0);
  origins[0].hook = null;
  const later = await runtime({ offsetMs: 10 * 60_000 });
  await completes(later, facts);
  await assertSingleMint(facts);
}));

test("paused route: nothing is claimed or sent until a quorum-signed resume", options, () => scenario(async ({ runtime, facts }) => {
  const route = await node.route();
  const expiresUnix = Math.floor(Date.now() / 1000) + 600;
  const pauseNonce = Number(route.control_nonce) + 1000 + nextSubmitter;
  node.bridgeTx(["pause-route", XITCOIN_TESTNET_ROUTE_ID, String(pauseNonce), String(expiresUnix),
    guardianPauseSignature(keys[3], { nonce: pauseNonce, expiresUnix }).slice(2)]);
  for (let i = 0; i < 50 && !(await node.route()).paused; i++) await sleep(100);
  assert.equal((await node.route()).paused, true);
  const rt = await runtime();
  const paused = await rt.runOnce();
  assert.equal(paused.action, "waiting");
  assert.deepEqual(paused.waiting, ["route_paused"]);
  assert.equal(facts.row().found, false);
  assert.equal(await facts.sequence(), 0);
  const current = await node.route();
  const nonce = Number(current.control_nonce) + 1, notBeforeUnix = Math.floor(Date.now() / 1000) - 60;
  const [first, second] = resumeSignatures([keys[0], keys[1]], { route: current, nonce, notBeforeUnix, expiresUnix });
  node.bridgeTx(["resume-route", XITCOIN_TESTNET_ROUTE_ID, String(nonce), String(notBeforeUnix), String(expiresUnix), first.slice(2), second.slice(2)]);
  for (let i = 0; i < 50 && (await node.route()).paused; i++) await sleep(100);
  await completes(rt, facts);
  await assertSingleMint(facts);
}));

test("an approval too close to its deadline is handed back, re-issued only after the chain shows it dead, then minted once", options, () => scenario(async ({ runtime, facts, store, records, bridge, signerSet, requests }) => {
  const rt = await runtime();
  const report = await rt.runOnce();
  assert.equal(report.action, "waiting");
  assert.deepEqual(report.waiting, ["approval_expired_awaiting_reissue"]);
  assert.equal(facts.row().found, false);
  assert.equal(facts.relay().state, "approved");
  assert.equal(await facts.sequence(), 0);
  const original = requests[0];
  assert.deepEqual({ ...store.reissueRequested("cronos", records[0].sourceRef) }, { digest: original.digest, destinationRef: null });

  // Coordinator: the local grace has passed, but not the chain's block time.
  const now = original.deadlineUnix + APPROVAL_REISSUE_GRACE_SECONDS + 1;
  const build = (transfer, deadlineUnix) => buildTransferApprovalRequest({ transfer: { ...transfer, state: "finalized" },
    routeId: XITCOIN_TESTNET_ROUTE_ID, cronosRouteId: TESTNET_ROUTE_ID, cronosChainId: 338, cronosVault: bridge.vault,
    xitcoinChainId: CHAIN_ID, deadlineUnix });
  const coordinator = () => returnExpiredApprovals({ store, build, nowUnix: now, windowSeconds: 1_800, verifyRetired: signerSet.verifyRetirement });
  assert.deepEqual(await coordinator(), { returned: 0, waiting: ["deadline_not_passed"] });
  for (let i = 0; i < 600 && Date.parse((await node.rpc("status")).sync_info.latest_block_time) / 1000 <= original.deadlineUnix + 1; i++) await sleep(100);
  assert.deepEqual(await coordinator(), { returned: 1, waiting: [] });
  assert.equal(facts.relay().state, "finalized");
  // Signers sign the explicit re-issue only after their own check on the chain.
  const request = store.approvalRequest("cronos", records[0].sourceRef);
  const clients = signerSet.services.map((service) => ({ identity: service.identity, approve: (value) => service.approve(value, { nowUnix: now }) }));
  await approveFinalizedTransfer({ store, sourceChain: "cronos", sourceRef: records[0].sourceRef, request, clients,
    authorizedSigners: [...signers], threshold: 2, nowUnix: now });
  assert.equal(facts.relay().state, "approved");
  requests[0] = request;
  await completes(rt, facts);
  await assertSingleMint(facts);
  assert.equal(facts.row().approvalDigest, request.digest);
  assert.equal((await facts.attestation()).record.deadline_unix, String(request.deadlineUnix));
  // Inside the 30-second deadline margin from the start, with as much time as
  // possible before the chain's block time passes the deadline.
}, { deadlineOffset: 28 }));

test("signed bytes first sent after the deadline end expired and the next transfer proceeds", options, () => scenario(async ({ runtime, facts, manifest, paths, records, approve, requests }) => {
  // Kill after the bytes are committed, before the first send, then let the
  // approval deadline pass.
  await killedAt("signed", manifest, paths);
  assert.equal(facts.row().state, "signed");
  const deadline = requests[0].deadlineUnix;
  while (Math.floor(Date.now() / 1000) <= deadline + 2) await sleep(500);
  await node.blocks(2);
  const rt = await runtime({ offsetMs: 2 * 60_000 }); // the killed worker's lease has expired
  const sent = await rt.runOnce();
  assert.equal(sent.action, "submitted");
  let report;
  for (let i = 0; i < 30 && report?.action !== "expired"; i++) { await node.blocks(1); report = await rt.runOnce(); }
  assert.equal(report.action, "expired");
  assert.equal(facts.row().state, "expired");
  assert.equal(facts.relay().state, "submitted");
  assert.equal(await facts.sequence(), 1);
  assert.equal((await facts.attestation()).status, "ATTESTATION_STATE_ABSENT");
  // The queue is not blocked: the second deposit (a fresh approval) mints.
  await approve(records[1], Math.floor(Date.now() / 1000) + 3_600);
  await completes(rt, facts, records[1]);
  const row = facts.row(1);
  assert.equal(row.state, "finalized");
  assert.equal(await facts.balance(1), AMOUNT);
  assert.equal(await facts.sequence(), 2);
}, { deposits: 2, approved: 1, deadlineOffset: 45 }));

test("a third-party submission before any claim completes the transfer without a submitter transaction", options, () => scenario(async ({ runtime, facts, requests, store, records }) => {
  const approvals = store.approvals("cronos", records[0].sourceRef).map(({ signer, digest, signature }) => ({ signer, digest, signature }));
  const foreign = await foreignSubmission(THIRD_PARTY_KEY, requests[0], approvals);
  assert.equal(foreign.result.tx_result.code, 0);
  await node.blocks(3);
  const rt = await runtime();
  const report = await rt.runOnce();
  assert.equal(report.action, "released_elsewhere");
  assert.equal(report.releaseHash, foreign.hash);
  assert.equal(facts.relay().state, "completed");
  assert.equal(facts.relay().destination_ref, null);
  assert.equal(facts.relay().release_ref, foreign.hash);
  assert.equal(facts.row().state, "released_elsewhere");
  assert.equal(await facts.sequence(), 0);
  assert.equal(await facts.balance(), AMOUNT);
}));

test("a third-party submission after we signed still consumes our sequence once, then the queue moves on", options, () => scenario(async ({ runtime, facts, manifest, paths, requests, store, records }) => {
  await killedAt("signed", manifest, paths);
  const approvals = store.approvals("cronos", records[0].sourceRef).map(({ signer, digest, signature }) => ({ signer, digest, signature }));
  const foreign = await foreignSubmission(THIRD_PARTY_KEY, requests[0], approvals);
  assert.equal(foreign.result.tx_result.code, 0);
  const rt = await runtime({ offsetMs: 2 * 60_000 }); // the killed worker's lease has expired
  const reports = await completes(rt, facts);
  assert.equal(reports.at(-1).action, "released_elsewhere");
  assert.equal(reports.at(-1).releaseHash, foreign.hash);
  const row = facts.row();
  assert.equal(row.state, "released_elsewhere");
  assert.equal(row.releaseHash, foreign.hash);
  // Our identical bytes were sent once, failed as already processed and
  // consumed the reserved sequence.
  const ours = await node.committed(row.transactionHash);
  assert.equal(ours.tx_result.code, 1);
  assert.match(ours.tx_result.log, /already processed/);
  assert.equal(await facts.sequence(), 1);
  assert.equal(facts.relay().destination_ref, row.transactionHash);
  assert.equal(facts.relay().release_ref, foreign.hash);
  assert.equal(await facts.balance(), AMOUNT);
}));

test("a re-encoding of our signed bytes that lands first is our inclusion, recorded by its hash, never a halt", options, () => scenario(async ({ runtime, facts, manifest, paths }) => {
  // Killed after the broadcast marker, before our bytes were sent.
  await killedAt("broadcast-recorded", manifest, paths);
  const row = facts.row();
  assert.equal(row.state, "broadcast");
  // Anyone who has seen our bytes can re-wrap the same signed content: the
  // chain's eth_secp256k1 verifier drops the 65th signature byte unchecked.
  const decoded = decodeXitcoinTransaction(row.signedHex);
  const signature = Buffer.from(decoded.signatureHex.slice(2), "hex");
  signature[64] += 27;
  const field = (n, bytes) => Buffer.concat([Buffer.from([n * 8 + 2]), varint(bytes.length), bytes]);
  const variant = Buffer.concat([field(1, decoded.bodyBytes), field(2, decoded.authInfoBytes), field(3, signature)]);
  const variantHash = `0x${createHash("sha256").update(variant).digest("hex")}`;
  assert.notEqual(variantHash, row.transactionHash);
  assert.equal((await node.broadcast(`0x${variant.toString("hex")}`)).code, 0);
  assert.equal((await node.committed(variantHash)).tx_result.code, 0);
  const rt = await runtime({ offsetMs: 2 * 60_000 }); // the killed worker's lease has expired
  const reports = await completes(rt, facts);
  assert.deepEqual([reports.at(-1).action, reports.at(-1).releaseHash], ["released_elsewhere", variantHash]);
  assert.equal(facts.row().state, "released_elsewhere");
  assert.equal(facts.row().releaseHash, variantHash);
  assert.equal(facts.relay().destination_ref, row.transactionHash);
  assert.equal(facts.relay().release_ref, variantHash);
  assert.equal(`0x${(await facts.attestation()).record.tx_hash.toLowerCase()}`, variantHash);
  assert.equal(await facts.sequence(), 1);
  assert.equal(await facts.balance(), AMOUNT);
}));

function varint(value) {
  const bytes = [];
  do { bytes.push((value & 127) | (value > 127 ? 128 : 0)); value >>>= 7; } while (value);
  return Buffer.from(bytes);
}
