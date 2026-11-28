// Destination proof that an approval is dead, against a local anvil chain with
// the vendored reviewed vault and a local xitcoind built from the pinned
// pos-chain commit, each behind two fault-injecting origins. Synthetic keys
// only; no public network is contacted.
import assert from "node:assert/strict";
import test, { after, before } from "node:test";
import { randomBytes } from "node:crypto";
import { computeAddress } from "ethers";

import { RetirementUnproven, createApprovalRetirementVerifier, retirementEvidence } from "../src/approval-retirement.js";
import { buildApprovalRequest } from "../src/approvals.js";
import { CronosRpcQuorum } from "../src/cronos-rpc.js";
import { buildCronosSubmission } from "../src/submission.js";
import { DIRECTION_INBOUND, DIRECTION_OUTBOUND } from "../src/protocol.js";
import { XitcoinRpcQuorum } from "../src/xitcoin-rpc.js";
import { assembleTxRaw, buildXitcoinSignDoc, cosmosSignature, encodeSubmitAttestation } from "../src/xitcoin-transaction.js";
import { keys, sign, signers } from "./fixtures/destination.js";
import { compile, deployBridge, evmAvailability, localKeys, rewriteResult, signedCall, startAnvil, startProxy } from "./evm/harness.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { CHAIN_ID, ROUTE_ID, THIRD_PARTY_KEY, chainAccount, chainKey, rewriteJson, startXitcoinNode, startXitcoinOrigin,
  xitcoindAvailability } from "./xitcoin/harness.js";

const evm = evmAvailability();
const chain = xitcoindAvailability();
const CONFIRMATIONS = 3;
const unused = () => new XitcoinRpcQuorum({ allowLoopbackHttp: true, origins: [{ rpcUrl: "http://127.0.0.1:9", restUrl: "http://127.0.0.1:10" },
  { rpcUrl: "http://127.0.0.1:11", restUrl: "http://127.0.0.1:12" }] });
const unusedCronos = () => new CronosRpcQuorum({ urls: ["http://127.0.0.1:13", "http://127.0.0.1:14"], allowLoopbackHttp: true });

async function unproven(promise, code) {
  await assert.rejects(promise, (error) => error instanceof RetirementUnproven && error.code === code);
}

test("a retirement verifier needs both bounded quorum transports and accepts only explicit evidence", () => {
  const options = { cronos: unusedCronos(), xitcoin: unused(), cronosVault: signers[0], cronosConfirmations: 3 };
  assert.equal(typeof createApprovalRetirementVerifier(options), "function");
  assert.throws(() => createApprovalRetirementVerifier({ ...options, cronos: {} }), /quorum/);
  assert.throws(() => createApprovalRetirementVerifier({ ...options, xitcoin: {} }), /quorum/);
  assert.throws(() => createApprovalRetirementVerifier({ ...options, cronosChainId: 25 }), /testnet/);
  for (const cronosConfirmations of [0, 10_001, 2.5]) assert.throws(() => createApprovalRetirementVerifier({ ...options, cronosConfirmations }), /confirmations/);
  assert.deepEqual({ ...retirementEvidence({ retired: true, destination: "cronos", height: 4, blockTime: 11 }, 10) },
    { destination: "cronos", height: 4, blockTime: 11 });
  for (const value of [null, { retired: true, destination: "cronos", height: 4, blockTime: 10 }, { retired: "yes", destination: "cronos", height: 4, blockTime: 11 },
    { retired: true, destination: "other", height: 4, blockTime: 11 }, { retired: true, destination: "cronos", height: 0, blockTime: 11 }]) {
    assert.throws(() => retirementEvidence(value, 10), (error) => error.code === "invalid_retirement_evidence");
  }
});

// ---- Cronos destination (outbound releases) ----
async function cronosDestination() {
  const anvil = await startAnvil(evm.anvil);
  const artifacts = { vault: compile(evm.forge, "vault-testnet").CronosBridgeVault, token: compile(evm.forge, "token").MockERC20 };
  const bridge = await deployBridge(anvil, artifacts, { routeId: TESTNET_ROUTE_ID, signers });
  const proxies = [await startProxy(anvil.url), await startProxy(anvil.url)];
  await anvil.rpc("anvil_mine", ["0xa"]);
  const verify = createApprovalRetirementVerifier({ cronos: new CronosRpcQuorum({ urls: proxies.map((proxy) => proxy.url), allowLoopbackHttp: true }),
    xitcoin: unused(), cronosVault: bridge.vault, cronosConfirmations: CONFIRMATIONS });
  const finalizedTime = async () => {
    const tip = Number(await anvil.rpc("eth_blockNumber"));
    return Number((await anvil.rpc("eth_getBlockByNumber", [`0x${(tip - CONFIRMATIONS).toString(16)}`, false])).timestamp);
  };
  const release = (deadline, overrides = {}) => buildApprovalRequest({ direction: DIRECTION_OUTBOUND, payload: {
    routeId: ROUTE_ID, chainId: 338, vault: bridge.vault, sourceBurnId: `0x${randomBytes(32).toString("hex")}`,
    recipient: computeAddress(chainKey(0x7_000).publicKey), amount: (10n ** 18n).toString(), signerSetVersion: 1, deadline, ...overrides } });
  return { anvil, bridge, proxies, verify, finalizedTime, release,
    async stop() { await Promise.all(proxies.map((proxy) => proxy.stop())); await anvil.stop(); } };
}

test("Cronos: an approval is retired only once a finalized block is past its deadline and the burn is unprocessed", { skip: evm.skip, timeout: 240_000 }, async () => {
  const cronos = await cronosDestination();
  try {
    const time = await cronos.finalizedTime();
    const request = cronos.release(time + 600);
    // The deadline is still ahead of the finalized block time.
    await unproven(cronos.verify({ request, previousDeadlineUnix: time + 600 }), "deadline_not_passed");
    await unproven(cronos.verify({ request, previousDeadlineUnix: time }), "deadline_not_passed"); // equal is still usable
    const retired = await cronos.verify({ request, previousDeadlineUnix: time - 1 });
    assert.deepEqual([retired.retired, retired.destination, retired.blockTime], [true, "cronos", time]);
    const tip = Number(await cronos.anvil.rpc("eth_blockNumber"));
    assert.equal(retired.height, tip - CONFIRMATIONS);
    // Blocks inside the confirmation window never count.
    await cronos.anvil.rpc("evm_increaseTime", [900]);
    await cronos.anvil.rpc("anvil_mine", ["0x1"]);
    await unproven(cronos.verify({ request, previousDeadlineUnix: time + 600 }), "deadline_not_passed");
    await cronos.anvil.rpc("anvil_mine", [`0x${CONFIRMATIONS.toString(16)}`]);
    assert.equal((await cronos.verify({ request, previousDeadlineUnix: time + 600 })).retired, true);
  } finally { await cronos.stop(); }
});

test("Cronos: a released burn, disagreeing or unavailable origins and another vault are never proof", { skip: evm.skip, timeout: 240_000 }, async () => {
  const cronos = await cronosDestination();
  try {
    const time = await cronos.finalizedTime();
    // A real release through the vault with two of the three fixture signers.
    const used = cronos.release(time + 3_600);
    const submission = buildCronosSubmission({ request: used, approvals: sign(used), vault: cronos.bridge.vault });
    await cronos.anvil.rpc("eth_sendRawTransaction", [await signedCall(cronos.anvil, localKeys.deployer, { to: submission.to, data: submission.data,
      gasLimit: 400_000n })]);
    await cronos.anvil.rpc("evm_increaseTime", [10]);
    await cronos.anvil.rpc("anvil_mine", [`0x${(CONFIRMATIONS + 1).toString(16)}`]);
    const later = await cronos.finalizedTime();
    await unproven(cronos.verify({ request: used, previousDeadlineUnix: later - 1 }), "transfer_processed");
    const request = cronos.release(later + 600);
    cronos.proxies[1].hook = async ({ message, forward }) => {
      const text = await forward();
      return message.method === "eth_call" ? rewriteResult(text, () => `0x${"0".repeat(63)}1`) : text;
    };
    await unproven(cronos.verify({ request, previousDeadlineUnix: later - 1 }), "destination_disagreement");
    cronos.proxies[1].hook = async ({ message, forward }) => {
      const text = await forward();
      return message.method === "eth_getBlockByNumber" ? rewriteResult(text, (block) => ({ ...block, hash: `0x${"ab".repeat(32)}` })) : text;
    };
    await unproven(cronos.verify({ request, previousDeadlineUnix: later - 1 }), "destination_disagreement");
    cronos.proxies[1].hook = async ({ message, forward }) => {
      if (message.method === "eth_call") throw new Error("dropped");
      return forward();
    };
    await unproven(cronos.verify({ request, previousDeadlineUnix: later - 1 }), "destination_unavailable");
    cronos.proxies[1].hook = null;
    await unproven(cronos.verify({ request: cronos.release(later + 600, { vault: signers[0] }), previousDeadlineUnix: later - 1 }), "destination_mismatch");
    await unproven(cronos.verify({ request, previousDeadlineUnix: 0 }), "invalid_previous_deadline");
    assert.equal((await cronos.verify({ request, previousDeadlineUnix: later - 1 })).retired, true);
  } finally { await cronos.stop(); }
});

// ---- Xitcoin destination (inbound attestations) ----
let node, origins = [], mints = 0;
before(async () => {
  if (chain.skip) return;
  node = await startXitcoinNode({ binary: chain.binary, signers: [...signers], guardian: computeAddress(keys[3].publicKey) });
  origins = [await startXitcoinOrigin(node), await startXitcoinOrigin(node)];
});
after(async () => {
  await Promise.all(origins.map((origin) => origin.stop()));
  await node?.stop();
});

const attestationRequest = (deadlineUnix, overrides = {}) => buildApprovalRequest({ direction: DIRECTION_INBOUND, payload: {
  destinationChainId: CHAIN_ID, routeId: ROUTE_ID, sourceChainId: "338", sourceRef: `0x${randomBytes(32).toString("hex")}`,
  nonce: String(++mints), destination: chainAccount(chainKey(0x8_000 + mints)), amount: (10n ** 18n).toString(), deadlineUnix, ...overrides } });

async function submitAttestation(request) {
  const account = chainAccount(THIRD_PARTY_KEY);
  const state = (await node.rest(`/cosmos/auth/v1beta1/accounts/${account}`)).body.account;
  const p = request.payload;
  const messageBytes = encodeSubmitAttestation({ submitter: account, routeId: p.routeId, direction: request.direction,
    sourceChainId: p.sourceChainId, sourceRef: p.sourceRef, nonce: p.nonce, destination: p.destination, amount: p.amount,
    deadlineUnix: String(p.deadlineUnix), signatures: sign(request).map((approval) => approval.signature) });
  const doc = buildXitcoinSignDoc({ messageBytes, publicKey: THIRD_PARTY_KEY.compressedPublicKey, accountNumber: state.account_number,
    sequence: state.sequence, gasLimit: "400000", feeAmount: (400000n * 4_000_000_000n).toString(), chainId: CHAIN_ID });
  const raw = assembleTxRaw({ ...doc, signature: cosmosSignature(THIRD_PARTY_KEY.sign(doc.signingDigest).serialized, doc.signingDigest,
    THIRD_PARTY_KEY.compressedPublicKey) });
  assert.equal((await node.broadcast(raw.signedHex)).code, 0);
  assert.equal((await node.committed(raw.transactionHash)).tx_result.code, 0);
}

function xitcoinVerifier() {
  return createApprovalRetirementVerifier({ cronos: unusedCronos(), cronosVault: signers[0], cronosConfirmations: 3,
    xitcoin: new XitcoinRpcQuorum({ allowLoopbackHttp: true, origins: origins.map(({ rpcUrl, restUrl }) => ({ rpcUrl, restUrl })) }) });
}
const blockTime = async () => Math.floor(Date.parse((await node.rpc("status")).sync_info.latest_block_time) / 1000);

test("Xitcoin: an attestation is retired only once a committed block is past its deadline and its replay key is unused", { skip: chain.skip, timeout: 180_000 }, async () => {
  origins.forEach((origin) => { origin.hook = null; });
  const verify = xitcoinVerifier();
  const now = await blockTime();
  const request = attestationRequest(now + 3_600);
  await unproven(verify({ request, previousDeadlineUnix: now + 3_600 }), "deadline_not_passed");
  // The proof height is one block below the lowest reported height.
  const retired = await verify({ request, previousDeadlineUnix: now - 5 });
  assert.deepEqual([retired.retired, retired.destination], [true, "xitcoin"]);
  assert.ok(retired.blockTime > now - 5 && retired.height > 1);
  // Every attestation read was pinned to the height of the proof.
  assert.ok(origins.every((origin) => origin.calls.some((call) => typeof call === "string" && call.startsWith("/xitcoin/bridge/v1/attestations/"))));
});

test("Xitcoin: a processed attestation, disagreeing or unavailable origins and another chain are never proof", { skip: chain.skip, timeout: 180_000 }, async () => {
  origins.forEach((origin) => { origin.hook = null; });
  const verify = xitcoinVerifier();
  const now = await blockTime();
  const used = attestationRequest(now + 3_600);
  await submitAttestation(used);
  await node.blocks(1);
  await unproven(verify({ request: used, previousDeadlineUnix: now - 1 }), "transfer_processed");
  const request = attestationRequest(now + 3_600);
  const rewrite = (transform) => async ({ kind, path, forward }) => {
    const answer = await forward();
    if (kind !== "rest" || !path.startsWith("/xitcoin/bridge/v1/attestations/")) return answer;
    return { status: answer.status, text: rewriteJson(answer.text, transform) };
  };
  origins[1].hook = rewrite((body) => ({ ...body, status: "ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD", processed: true }));
  await unproven(verify({ request, previousDeadlineUnix: now - 5 }), "destination_disagreement");
  origins[1].hook = async ({ kind, path, forward }) => {
    if (kind === "rest" && path.startsWith("/xitcoin/bridge/v1/attestations/")) throw new Error("dropped");
    return forward();
  };
  await unproven(verify({ request, previousDeadlineUnix: now - 5 }), "destination_unavailable");
  origins[1].hook = async ({ kind, method, forward }) => {
    const answer = await forward();
    if (kind !== "rpc" || method !== "block") return answer;
    return { status: answer.status, text: rewriteJson(answer.text, (body) => ({ ...body,
      result: { ...body.result, block_id: { ...body.result.block_id, hash: "CD".repeat(32) } } })) };
  };
  await unproven(verify({ request, previousDeadlineUnix: now - 5 }), "destination_disagreement");
  origins[1].hook = null;
  await unproven(verify({ request: attestationRequest(now + 3_600, { destinationChainId: "xitcoin" }), previousDeadlineUnix: now - 5 }),
    "destination_mismatch");
  assert.equal((await verify({ request, previousDeadlineUnix: now - 5 })).retired, true);
});
