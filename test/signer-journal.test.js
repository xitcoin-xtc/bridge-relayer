import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SigningKey, computeAddress } from "ethers";

import { APPROVAL_REISSUE_GRACE_SECONDS, approvalContentHash, approvalSourceKey, buildApprovalRequest } from "../src/approvals.js";
import { DIRECTION_INBOUND, DIRECTION_OUTBOUND } from "../src/protocol.js";
import { SignerApprovalJournal } from "../src/signer-journal.js";
import { IsolatedSignerService, createSignerPolicy } from "../src/signer-service.js";

const KEY = new SigningKey(`0x${"33".repeat(32)}`);
const ADDRESS = computeAddress(KEY.publicKey);
const VAULT = "0x1111111111111111111111111111111111111111";
const NOW = 1_900_000_000;

function inbound(overrides = {}) {
  return buildApprovalRequest({ direction: DIRECTION_INBOUND, payload: {
    destinationChainId: "xitcoin", routeId: "cronos-xitcoin-xtc-v1", sourceChainId: "25",
    sourceRef: `0x${"aa".repeat(32)}`, nonce: "7", destination: "xtc1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg32rdvg9",
    amount: "1000", deadlineUnix: NOW + 300, ...overrides,
  } });
}

function outbound(overrides = {}) {
  return buildApprovalRequest({ direction: DIRECTION_OUTBOUND, payload: {
    routeId: "cronos-xitcoin-xtc-v1", chainId: 25, vault: VAULT, sourceBurnId: `0x${"bb".repeat(32)}`,
    recipient: "0x2222222222222222222222222222222222222222", amount: "1000", signerSetVersion: 1,
    deadline: NOW + 300, ...overrides,
  } });
}

function service(journal) {
  return new IsolatedSignerService({
    identity: "signer-1", signerAddress: ADDRESS, journal,
    policy: createSignerPolicy({ routeIds: ["cronos-xitcoin-xtc-v1"], cronosChainIds: [25], xitcoinChainIds: ["xitcoin"], cronosVaults: [VAULT], maximumAmount: "100000", maximumDeadlineSeconds: 900 }),
    // A compromised coordinator and a lying source verifier: the journal
    // alone must stop conflicting approvals.
    verifySource: async () => ({ canonical: true, finalized: true }),
    signDigest: async (digest) => KEY.sign(digest).serialized,
  });
}

test("source key and content hash ignore only the deadline (and release signer-set version)", () => {
  assert.equal(approvalSourceKey(inbound()), approvalSourceKey(inbound({ deadlineUnix: NOW + 900, destination: "xtc1other", amount: "5" })));
  assert.notEqual(approvalSourceKey(inbound()), approvalSourceKey(inbound({ sourceRef: `0x${"ab".repeat(32)}` })));
  assert.equal(approvalContentHash(inbound()), approvalContentHash(inbound({ deadlineUnix: NOW + 900 })));
  for (const change of [{ destination: "xtc1other" }, { amount: "5" }, { nonce: "8" }, { destinationChainId: "xitcoin-testnet-v2-1" }]) {
    assert.notEqual(approvalContentHash(inbound()), approvalContentHash(inbound(change)));
  }
  assert.equal(approvalSourceKey(outbound()), approvalSourceKey(outbound({ recipient: "0x3333333333333333333333333333333333333333" })));
  assert.equal(approvalContentHash(outbound()), approvalContentHash(outbound({ deadline: NOW + 900, signerSetVersion: 2 })));
  assert.notEqual(approvalContentHash(outbound()), approvalContentHash(outbound({ recipient: "0x3333333333333333333333333333333333333333" })));
  assert.notEqual(approvalSourceKey(outbound()), approvalSourceKey(outbound({ vault: "0x4444444444444444444444444444444444444444" })));
});

test("a signer never signs two different requests for one source deposit", async () => {
  const signer = service(new SignerApprovalJournal());
  const first = await signer.approve(inbound(), { nowUnix: NOW });
  assert.deepEqual(await signer.approve(inbound(), { nowUnix: NOW }), first);
  for (const change of [{ destination: "xtc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" }, { amount: "999" }, { nonce: "8" }]) {
    await assert.rejects(() => signer.approve(inbound(change), { nowUnix: NOW }), /conflicting request/);
    await assert.rejects(() => signer.approve(inbound({ ...change, deadlineUnix: NOW + 1300 }), { nowUnix: NOW + 1000 }), /conflicting request/);
  }
  // Same deposit, new deadline: refused while the first approval can still be used.
  await assert.rejects(() => signer.approve(inbound({ deadlineUnix: NOW + 600 }), { nowUnix: NOW }), /unexpired approval/);
  const graceEnd = NOW + 300 + APPROVAL_REISSUE_GRACE_SECONDS;
  await assert.rejects(() => signer.approve(inbound({ deadlineUnix: graceEnd + 300 }), { nowUnix: graceEnd }), /unexpired approval/);
  const reissued = await signer.approve(inbound({ deadlineUnix: graceEnd + 301 }), { nowUnix: graceEnd + 1 });
  assert.notEqual(reissued.digest, first.digest);
  assert.equal(reissued.signer, ADDRESS);
});

test("the journal survives restarts and closed source events are never signed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "xitcoin-signer-journal-"));
  const path = join(dir, "approvals.sqlite");
  try {
    let journal = new SignerApprovalJournal(path);
    await service(journal).approve(inbound(), { nowUnix: NOW });
    journal.shutdown();
    journal = new SignerApprovalJournal(path);
    await assert.rejects(() => service(journal).approve(inbound({ amount: "999" }), { nowUnix: NOW }), /conflicting request/);
    const refundKey = approvalSourceKey(inbound({ sourceRef: `0x${"cd".repeat(32)}` }));
    journal.closeSourceEvent(refundKey, "refunded on Cronos after operator approval", { nowUnix: NOW });
    journal.shutdown();
    journal = new SignerApprovalJournal(path);
    await assert.rejects(() => service(journal).approve(inbound({ sourceRef: `0x${"cd".repeat(32)}` }), { nowUnix: NOW }), /closed/);
    assert.equal(journal.get(refundKey).state, "closed");
    journal.shutdown();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("concurrent conflicting requests produce at most one signature", async () => {
  const signer = service(new SignerApprovalJournal());
  const results = await Promise.allSettled([
    signer.approve(inbound(), { nowUnix: NOW }),
    signer.approve(inbound({ destination: "xtc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" }), { nowUnix: NOW }),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const fresh = service(new SignerApprovalJournal());
  const identical = await Promise.all([fresh.approve(inbound(), { nowUnix: NOW }), fresh.approve(inbound(), { nowUnix: NOW })]);
  assert.equal(identical[0].signature, identical[1].signature);
});

test("a signer service cannot be built without a durable journal", () => {
  assert.throws(() => new IsolatedSignerService({ identity: "signer-1", signerAddress: ADDRESS,
    policy: createSignerPolicy({ routeIds: ["cronos-xitcoin-xtc-v1"], xitcoinChainIds: ["xitcoin"], cronosVaults: [VAULT], maximumAmount: "1" }),
    verifySource: async () => ({}), signDigest: async () => "0x" }), /journal/);
});

test("operator CLI shows and closes a source event without signing", async () => {
  const { runSignerJournalCli } = await import("../src/signer-journal-cli.js");
  const dir = await mkdtemp(join(tmpdir(), "xitcoin-signer-journal-cli-"));
  const path = join(dir, "approvals.sqlite");
  const output = [];
  const io = { stdout: { write: (text) => output.push(text) }, stderr: { write: (text) => output.push(text) } };
  try {
    const key = approvalSourceKey(inbound());
    assert.equal(runSignerJournalCli(["close", path, key, "refund", "approved"], io), 0);
    assert.equal(JSON.parse(output.at(-1)).close_reason, "refund approved");
    assert.equal(runSignerJournalCli(["show", path, key], io), 0);
    assert.equal(JSON.parse(output.at(-1)).state, "closed");
    assert.equal(runSignerJournalCli(["close", "relative.sqlite", key, "x"], io), 1);
    assert.equal(runSignerJournalCli(["close", path, "0x1234", "x"], io), 1);
    const journal = new SignerApprovalJournal(path);
    await assert.rejects(() => service(journal).approve(inbound(), { nowUnix: NOW }), /closed/);
    journal.shutdown();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
