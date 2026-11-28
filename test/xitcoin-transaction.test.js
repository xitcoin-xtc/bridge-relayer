// Signed Cosmos transaction encoding for MsgSubmitAttestation, checked byte
// for byte against vectors produced by the chain's own Go encoder
// (test/fixtures/xitcoin-chain-vectors.json), and strict decoding.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { SigningKey, keccak256 } from "ethers";
import { accountOfPublicKey, assembleSimulationTx, assembleTxRaw, buildXitcoinSignDoc, cosmosSignature, decodeSimulateGasUsed,
  decodeSubmitAttestation, decodeXitcoinTransaction, encodeSimulateRequest, encodeSubmitAttestation, sameSignedContent, signedContent,
  verifyXitcoinSignature, XITCOIN_CHAIN_SCHEMA_COMMIT } from "../src/xitcoin-transaction.js";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/xitcoin-chain-vectors.json", import.meta.url), "utf8"));
const key = (n) => new SigningKey(`0x${n.toString(16).padStart(64, "0")}`);
const a = vectors.attestation;
const failure = { message: "invalid Xitcoin transaction" };
const message = (submitter) => ({ submitter, routeId: a.routeId, direction: a.direction, sourceChainId: a.sourceChainId,
  sourceRef: a.sourceRef, nonce: a.nonce, destination: a.destination, amount: a.amount, deadlineUnix: a.deadlineUnix,
  signatures: a.approvalSignatures });
const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
function build(t, overrides = {}) {
  const signer = key(t.submitterKeyNumber);
  const doc = buildXitcoinSignDoc({ messageBytes: encodeSubmitAttestation(message(t.submitter)), publicKey: signer.compressedPublicKey,
    accountNumber: t.accountNumber, sequence: t.sequence, gasLimit: t.gasLimit, feeAmount: t.feeAmount, chainId: vectors.chainId, ...overrides });
  const signature = cosmosSignature(signer.sign(doc.signingDigest).serialized, doc.signingDigest, signer.compressedPublicKey);
  return { doc, signature, raw: assembleTxRaw({ ...doc, signature }), signer };
}

test("the pinned schema commit is the commit the chain vectors were generated from", () => {
  assert.equal(XITCOIN_CHAIN_SCHEMA_COMMIT, vectors.posChainCommit);
});

for (const t of vectors.transactions) {
  test(`chain vector, ${t.name}: message, TxBody, AuthInfo, SignDoc, signature, TxRaw and hash are identical`, () => {
    assert.equal(hex(encodeSubmitAttestation(message(t.submitter))), t.message);
    const { doc, signature, raw, signer } = build(t);
    assert.equal(hex(doc.bodyBytes), t.txBody);
    assert.equal(hex(doc.authInfoBytes), t.txSignerAndFee);
    assert.equal(hex(doc.signDocBytes), t.signDoc);
    assert.equal(doc.signingDigest, t.signingDigest);
    assert.equal(doc.signingDigest, keccak256(t.signDoc)); // eth_secp256k1 signs Keccak-256 of the SignDoc
    assert.equal(hex(signature), t.signature);
    assert.equal(raw.signedHex, t.txRaw);
    assert.equal(raw.transactionHash, t.txHash); // SHA-256 of TxRaw, the CometBFT hash
    assert.equal(hex(encodeSimulateRequest(Buffer.from(t.txRaw.slice(2), "hex"))), t.simulateRequest);
    assert.equal(accountOfPublicKey(signer.compressedPublicKey), t.submitter);
    const decoded = decodeXitcoinTransaction(t.txRaw);
    assert.deepEqual({ ...decoded.message, signatures: [...decoded.message.signatures] }, message(t.submitter));
    assert.equal(decoded.publicKey, signer.compressedPublicKey);
    assert.equal(decoded.sequence, t.sequence); assert.equal(decoded.gasLimit, t.gasLimit); assert.equal(decoded.feeAmount, t.feeAmount);
    assert.equal(decoded.transactionHash, t.txHash);
    assert.equal(verifyXitcoinSignature({ ...decoded, chainId: vectors.chainId, accountNumber: t.accountNumber }), true);
    assert.equal(verifyXitcoinSignature({ ...decoded, chainId: vectors.chainId, accountNumber: String(BigInt(t.accountNumber) + 1n) }), false);
  });
}

test("signatures are normalized to R || S || V with V in {0, 1} and must match the key", () => {
  const t = vectors.transactions[1];
  const { doc, signer } = build(t);
  const serialized = signer.sign(doc.signingDigest).serialized;
  const normalized = cosmosSignature(serialized, doc.signingDigest, signer.compressedPublicKey);
  assert.ok([0, 1].includes(normalized[64]));
  assert.equal(hex(normalized.subarray(0, 64)), serialized.slice(0, 130));
  assert.throws(() => cosmosSignature(serialized, doc.signingDigest, key(7).compressedPublicKey), failure);
  // High-s (malleated) signatures are refused.
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const s = BigInt(`0x${serialized.slice(66, 130)}`);
  const high = `${serialized.slice(0, 66)}${(n - s).toString(16).padStart(64, "0")}${serialized.slice(130)}`;
  assert.throws(() => cosmosSignature(high, doc.signingDigest, signer.compressedPublicKey), failure);
  assert.throws(() => cosmosSignature(`${serialized.slice(0, 130)}1d`, doc.signingDigest, signer.compressedPublicKey), failure);
});

test("only the supported subset is built: testnet chain, positive gas, canonical fee, curve point keys", () => {
  const t = vectors.transactions[1];
  for (const overrides of [{ chainId: "xitcoin" }, { chainId: "xitcoin-testnet-v2-2" }, { gasLimit: "0" }, { gasLimit: "01" },
    { feeAmount: "0" }, { feeAmount: "010" }, { sequence: "-1" }, { accountNumber: (1n << 64n).toString() },
    { publicKey: `0x04${"11".repeat(32)}` }, { publicKey: `0x02${"ff".repeat(32)}` }]) {
    assert.throws(() => build(t, overrides), failure, JSON.stringify(overrides));
  }
  for (const patch of [{ signatures: [a.approvalSignatures[0]] }, { nonce: "18446744073709551616" }, { deadlineUnix: (1n << 63n).toString() },
    { destination: "with space" }, { routeId: "" }]) {
    assert.throws(() => encodeSubmitAttestation({ ...message(vectors.transactions[0].submitter), ...patch }), failure);
  }
});

test("decoding rejects every non-canonical or unsupported encoding", () => {
  const t = vectors.transactions[1];
  const raw = Buffer.from(t.txRaw.slice(2), "hex");
  const { doc, signature } = build(t);
  const reassemble = (body, auth, sig = signature) => `0x${Buffer.concat([Buffer.from([0x0a]), varint(body.length), body,
    Buffer.from([0x12]), varint(auth.length), auth, Buffer.from([0x1a, sig.length]), sig]).toString("hex")}`;
  assert.equal(reassemble(doc.bodyBytes, doc.authInfoBytes), t.txRaw);
  const memo = Buffer.concat([doc.bodyBytes, Buffer.from([0x12, 0x02]), Buffer.from("hi")]);
  const timeout = Buffer.concat([doc.bodyBytes, Buffer.from([0x18, 0x05])]);
  const extension = Buffer.concat([doc.bodyBytes, Buffer.from([0xfa, 0x3f, 0x00])]);
  for (const bad of [
    reassemble(memo, doc.authInfoBytes), reassemble(timeout, doc.authInfoBytes), reassemble(extension, doc.authInfoBytes),
    reassemble(Buffer.concat([doc.bodyBytes, doc.bodyBytes]), doc.authInfoBytes), // two messages
    reassemble(doc.bodyBytes, Buffer.concat([doc.authInfoBytes, Buffer.from([0x1a, 0x00])])), // tip
    `0x${Buffer.concat([raw, Buffer.from([0x1a, 0x41]), signature]).toString("hex")}`, // two signatures
    `0x${Buffer.concat([raw, Buffer.from([0x20, 0x01])]).toString("hex")}`, // unknown field
    `0x${raw.subarray(0, raw.length - 1).toString("hex")}`, // truncated
    reassemble(doc.bodyBytes, doc.authInfoBytes, signature.subarray(0, 64)), // 64-byte signature
    `0x${Buffer.concat([Buffer.from([0x0a, 0x80 | (doc.bodyBytes.length & 0x7f), 0x80 | (doc.bodyBytes.length >> 7), 0x00]),
      doc.bodyBytes, raw.subarray(3 + doc.bodyBytes.length)]).toString("hex")}`, // overlong length varint
    reassemble(Buffer.from(doc.bodyBytes.toString("hex").replace(Buffer.from("MsgSubmitAttestation").toString("hex"),
      Buffer.from("MsgSubmitAttestatioN").toString("hex")), "hex"), doc.authInfoBytes), // another type URL
    reassemble(doc.bodyBytes, Buffer.from(doc.authInfoBytes.toString("hex").replace(Buffer.from("axtc").toString("hex"),
      Buffer.from("aatm").toString("hex")), "hex")), // fee denom
    reassemble(doc.bodyBytes, Buffer.from(doc.authInfoBytes.toString("hex").replace(Buffer.from("ethsecp256k1").toString("hex"),
      Buffer.from("secp256k1aa1").toString("hex")), "hex")), // key type
    "0x", "0x0", t.txRaw.toUpperCase(), `0x${"00".repeat(20_000)}`,
  ]) assert.throws(() => decodeXitcoinTransaction(bad), failure);
  assert.throws(() => decodeSubmitAttestation(Buffer.concat([Buffer.from(t.message.slice(2), "hex"), Buffer.from([0x30, 0x01])])), failure);
  // SIGN_MODE_TEXTUAL (2) instead of DIRECT (1).
  const textual = Buffer.from(doc.authInfoBytes.toString("hex").replace("12040a020801", "12040a020802"), "hex");
  assert.notDeepEqual(textual, doc.authInfoBytes);
  assert.throws(() => decodeXitcoinTransaction(reassemble(doc.bodyBytes, textual)), failure);
});

function varint(value) {
  const bytes = [];
  do { bytes.push((value & 127) | (value > 127 ? 128 : 0)); value >>>= 7; } while (value);
  return Buffer.from(bytes);
}

test("simulation uses an empty signature and its gas is read from GasInfo.gas_used", () => {
  const { doc } = build(vectors.transactions[1]);
  const simulation = assembleSimulationTx(doc);
  assert.deepEqual(simulation.subarray(simulation.length - 2), Buffer.from([0x1a, 0x00]));
  const response = Buffer.from([0x0a, 0x05, 0x08, 0x01, 0x10, 0xf9, 0x0b, 0x12, 0x00]);
  assert.equal(decodeSimulateGasUsed(response), 1529n);
  assert.throws(() => decodeSimulateGasUsed(Buffer.from([0x0a, 0x02, 0x08, 0x01])), failure); // no gas used
  assert.throws(() => decodeSimulateGasUsed(Buffer.from([0x0a, 0x03, 0x18, 0x01, 0x00])), failure);
});

test("re-encodings of the same signed content are recognised; any other signed content is not", () => {
  const t = vectors.transactions[1];
  const { doc, signature } = build(t);
  const ours = signedContent(t.txRaw);
  assert.deepEqual(ours, { bodyHex: hex(doc.bodyBytes), authInfoHex: hex(doc.authInfoBytes), signatureRs: hex(signature.subarray(0, 64)) });
  const tagged = (tag, bytes) => Buffer.concat([tag, varint(bytes.length), bytes]);
  const raw = (sig, { prefix = Buffer.alloc(0), bodyTag = Buffer.from([0x0a]) } = {}) => hex(Buffer.concat([prefix,
    tagged(bodyTag, doc.bodyBytes), tagged(Buffer.from([0x12]), doc.authInfoBytes), tagged(Buffer.from([0x1a]), sig)]));
  const rs = signature.subarray(0, 64);
  // What pos-chain's verifier and the SDK decoder accept for the same content:
  // any 65th byte, a 64-byte R || S, a repeated body field (the last wins) and
  // an overlong field tag. Each is another TxRaw with another hash.
  for (const variant of [raw(Buffer.concat([rs, Buffer.from([27])])), raw(Buffer.concat([rs, Buffer.from([255])])), raw(rs),
    raw(signature, { prefix: tagged(Buffer.from([0x0a]), Buffer.from("other body")) }), raw(signature, { bodyTag: Buffer.from([0x8a, 0x00]) })]) {
    assert.notEqual(variant, t.txRaw);
    assert.equal(sameSignedContent(signedContent(variant), ours), true, variant.slice(0, 20));
  }
  const otherS = Buffer.from(signature); otherS[40] ^= 1;
  for (const other of [raw(otherS), raw(Buffer.concat([signature, signature])), raw(signature.subarray(0, 63)),
    hex(Buffer.concat([tagged(Buffer.from([0x0a]), Buffer.from("x")), tagged(Buffer.from([0x12]), doc.authInfoBytes), tagged(Buffer.from([0x1a]), signature)])),
    hex(Buffer.concat([Buffer.from(t.txRaw.slice(2), "hex"), tagged(Buffer.from([0x1a]), signature)])), // two signatures
    hex(Buffer.concat([Buffer.from(t.txRaw.slice(2), "hex"), Buffer.from([0x20, 0x01])])), "0x", "0x00"]) {
    assert.equal(sameSignedContent(signedContent(other), ours), false, other.slice(0, 20));
  }
});
