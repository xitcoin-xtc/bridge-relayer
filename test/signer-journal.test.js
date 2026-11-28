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

function service(journal, { verifyRetirement } = {}) {
  return new IsolatedSignerService({
    identity: "signer-1", signerAddress: ADDRESS, journal, verifyRetirement,
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
  // Same deposit, new deadline, without an explicit re-issue: refused, even
  // long after the first approval expired.
  await assert.rejects(() => signer.approve(inbound({ deadlineUnix: NOW + 600 }), { nowUnix: NOW }), /only an explicit re-issue/);
  await assert.rejects(() => signer.approve(inbound({ deadlineUnix: NOW + 90_300 }), { nowUnix: NOW + 90_000 }), /only an explicit re-issue/);
  assert.equal(first.digest, inbound().digest);
});

// A destination check that records what it was asked and answers as told.
function destination(answer) {
  const calls = [];
  const verify = async (input) => {
    calls.push(input);
    if (answer instanceof Error) throw answer;
    return typeof answer === "function" ? answer(input) : answer;
  };
  return Object.assign(verify, { calls });
}
const reissueOf = (request) => ({ previousDigest: request.digest, previousDeadlineUnix: request.deadlineUnix });

test("an explicit re-issue is signed only with a strictly later deadline and after the destination shows the old approval dead", async () => {
  const journal = new SignerApprovalJournal();
  const graceEnd = NOW + 300 + APPROVAL_REISSUE_GRACE_SECONDS;
  const retired = destination(({ previousDeadlineUnix }) => ({ retired: true, destination: "xitcoin", height: 77, blockTime: previousDeadlineUnix + 1 }));
  const first = await service(journal, { verifyRetirement: retired }).approve(inbound(), { nowUnix: NOW });
  const next = (deadlineUnix, declared = reissueOf(inbound())) => ({ ...inbound({ deadlineUnix }), reissue: declared });
  // Without a destination verifier a re-issue is never signed.
  await assert.rejects(() => service(journal).approve(next(graceEnd + 301), { nowUnix: graceEnd + 1 }), /retirement verifier/);
  // Local grace, strictly later deadline and a well-formed declaration first.
  await assert.rejects(() => service(journal, { verifyRetirement: retired }).approve(next(graceEnd + 300), { nowUnix: graceEnd }), /unexpired approval/);
  await assert.rejects(() => service(journal, { verifyRetirement: retired }).approve(next(graceEnd + 301, { previousDigest: first.digest, previousDeadlineUnix: graceEnd + 301 }),
    { nowUnix: graceEnd + 1 }), /strictly later/);
  for (const declared of [{ previousDigest: first.digest }, { previousDigest: "0x12", previousDeadlineUnix: NOW + 300 },
    { ...reissueOf(inbound()), extra: 1 }, "yes"]) {
    await assert.rejects(() => service(journal, { verifyRetirement: retired }).approve(next(graceEnd + 301, declared), { nowUnix: graceEnd + 1 }),
      /declaration is invalid/);
  }
  // The destination does not (yet) show the old approval dead: refused.
  const { RetirementUnproven } = await import("../src/approval-retirement.js");
  for (const answer of [new RetirementUnproven("deadline_not_passed"), new RetirementUnproven("transfer_processed"),
    { retired: true, destination: "xitcoin", height: 77, blockTime: NOW + 300 }, { retired: false }, null]) {
    await assert.rejects(() => service(journal, { verifyRetirement: destination(answer) }).approve(next(graceEnd + 301), { nowUnix: graceEnd + 1 }));
  }
  assert.equal(journal.get(approvalSourceKey(inbound())).digest, first.digest);
  assert.deepEqual(journal.reissues(approvalSourceKey(inbound())), []);
  // Proven dead: signed and journaled with its evidence.
  const reissued = await service(journal, { verifyRetirement: retired }).approve(next(graceEnd + 301), { nowUnix: graceEnd + 1 });
  assert.notEqual(reissued.digest, first.digest);
  assert.deepEqual(retired.calls.at(-1).previousDeadlineUnix, NOW + 300);
  const [record] = journal.reissues(approvalSourceKey(inbound()));
  assert.deepEqual([record.replaced_digest, record.declared_digest, record.retired_after, record.digest, record.deadline,
    record.destination, record.destination_height, record.destination_block_time],
  [first.digest, first.digest, NOW + 300, reissued.digest, graceEnd + 301, "xitcoin", 77, NOW + 301]);
  // The identical re-issued request is idempotent; the replaced one is never signed again.
  assert.deepEqual(await service(journal).approve(next(graceEnd + 301), { nowUnix: graceEnd + 2 }), reissued);
  await assert.rejects(() => service(journal, { verifyRetirement: retired }).approve(inbound(), { nowUnix: NOW }), /only an explicit re-issue/);
  await assert.rejects(() => service(journal, { verifyRetirement: retired }).approve(next(graceEnd + 700, reissueOf(inbound())),
    { nowUnix: graceEnd + 400 }), /unexpired approval/);
  // A declaration naming an older deadline than the signer's own never lowers
  // what must be proven dead: the signer checks its own, later deadline.
  const third = graceEnd + 301 + APPROVAL_REISSUE_GRACE_SECONDS + 1;
  await service(journal, { verifyRetirement: retired }).approve(next(third + 300, reissueOf(inbound())), { nowUnix: third });
  assert.equal(retired.calls.at(-1).previousDeadlineUnix, graceEnd + 301);
  assert.equal(journal.reissues(approvalSourceKey(inbound())).length, 2);
  // Re-issue records are permanent.
  assert.throws(() => journal.database.exec("DELETE FROM approval_reissues"), /permanent/);
  assert.throws(() => journal.database.exec("UPDATE approval_reissues SET deadline = 1"), /permanent/);
});

test("a signer that never signed the replaced approval still checks the declared one on the destination", async () => {
  const journal = new SignerApprovalJournal();
  const retired = destination(({ previousDeadlineUnix }) => ({ retired: true, destination: "cronos", height: 5, blockTime: previousDeadlineUnix + 9 }));
  const request = { ...outbound({ deadline: NOW + 600 }), reissue: reissueOf(outbound()) };
  await assert.rejects(() => service(journal).approve(request, { nowUnix: NOW + 400 }), /retirement verifier/);
  const signed = await service(journal, { verifyRetirement: retired }).approve(request, { nowUnix: NOW + 400 });
  assert.equal(retired.calls[0].previousDeadlineUnix, NOW + 300);
  assert.equal(journal.reissues(approvalSourceKey(outbound()))[0].replaced_digest, null);
  assert.equal(signed.digest, outbound({ deadline: NOW + 600 }).digest);
  // A declared deadline that is not earlier than the new one is refused.
  await assert.rejects(() => service(new SignerApprovalJournal(), { verifyRetirement: retired }).approve(
    { ...outbound({ deadline: NOW + 600 }), reissue: { previousDigest: outbound().digest, previousDeadlineUnix: NOW + 600 } }, { nowUnix: NOW }),
  /strictly later/);
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
