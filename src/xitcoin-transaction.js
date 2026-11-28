import { createHash } from "node:crypto";
import { SigningKey, computeAddress, keccak256 } from "ethers";
import { evmAddressToBech32 } from "./address.js";

// Signed Cosmos SDK transaction carrying exactly one MsgSubmitAttestation for
// the Xitcoin chain, in the encoding the chain itself produces (gogoproto,
// fields in number order, proto3 defaults omitted):
//   - message: test/fixtures/proto/xitcoin-tx.proto MsgSubmitAttestation;
//   - envelope: test/fixtures/proto/cosmos-sdk-tx.proto TxBody, AuthInfo,
//     SignerInfo, ModeInfo.Single (SIGN_MODE_DIRECT = 1), Fee, SignDoc, TxRaw;
//   - signer key: /cosmos.evm.crypto.v1.ethsecp256k1.PubKey (compressed, 33
//     bytes), signature over keccak256(SignDoc) as R || S || V with V in {0, 1}
//     and low S, as the chain's eth_secp256k1 keyring signs.
// The transaction hash is SHA-256 of the TxRaw bytes (the CometBFT hash).
// Golden vectors produced by the chain's own Go encoder are checked in
// test/fixtures/xitcoin-chain-vectors.json; CI regenerates them from the
// pinned pos-chain commit.
export const XITCOIN_TESTNET_CHAIN_ID = "xitcoin-testnet-v2-1";
// The pos-chain commit whose encoders and queries this release was verified
// against (test/fixtures/xitcoin-chain-vectors.json). It binds the broadcast
// ledger and must equal the submitter manifest's chainSchemaCommit.
export const XITCOIN_CHAIN_SCHEMA_COMMIT = "c006842b4f02c68055b47690ef144df408b7f962";
export const XITCOIN_MAINNET_CHAIN_ID = "xitcoin";
export const MSG_SUBMIT_ATTESTATION = "/cosmos.evm.bridge.v1.MsgSubmitAttestation";
export const ETH_SECP256K1_PUBKEY = "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey";
export const FEE_DENOM = "axtc";
export const SIGN_MODE_DIRECT = 1n;
export const MAX_TRANSACTION_BYTES = 16_384;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const U64 = (1n << 64n) - 1n;
const I64 = (1n << 63n) - 1n;
const failure = () => new Error("invalid Xitcoin transaction");

function varint(value) {
  if (typeof value !== "bigint" || value < 0n || value > U64) throw failure();
  const bytes = [];
  do { bytes.push(Number(value & 127n) | (value > 127n ? 128 : 0)); value >>= 7n; } while (value);
  return Buffer.from(bytes);
}
const tag = (field, wire) => varint(BigInt(field * 8 + wire));
function bytesField(field, value) {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  if (!Buffer.isBuffer(bytes)) throw failure();
  return bytes.length ? Buffer.concat([tag(field, 2), varint(BigInt(bytes.length)), bytes]) : Buffer.alloc(0);
}
// Always emitted, even when empty (repeated bytes and embedded messages).
function bytesAlways(field, value) {
  return Buffer.concat([tag(field, 2), varint(BigInt(value.length)), value]);
}
const uintField = (field, value) => (value === 0n ? Buffer.alloc(0) : Buffer.concat([tag(field, 0), varint(value)]));

const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
function unhex(value, length) {
  if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(value)) throw failure();
  const bytes = Buffer.from(value.slice(2), "hex");
  if (length !== undefined && bytes.length !== length) throw failure();
  return bytes;
}
function uint(value, maximum = U64) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) throw failure();
  const number = BigInt(value);
  if (number > maximum) throw failure();
  return number;
}
function canonicalAmount(value) {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value) >= 1n << 256n) throw failure();
  return value;
}

// MsgSubmitAttestation fields 1-10 (strings verbatim, as the chain hashes them).
export function encodeSubmitAttestation(message) {
  const { submitter, routeId, direction, sourceChainId, sourceRef, nonce, destination, amount, deadlineUnix, signatures } = message;
  if (!Array.isArray(signatures) || signatures.length < 2 || signatures.length > 3) throw failure();
  for (const text of [submitter, routeId, direction, sourceChainId, sourceRef, destination, amount]) {
    if (typeof text !== "string" || !text.length || text.length > 256 || !/^[\x21-\x7e]+$/.test(text)) throw failure();
  }
  return Buffer.concat([
    bytesField(1, submitter), bytesField(2, routeId), bytesField(3, direction), bytesField(4, sourceChainId),
    bytesField(5, sourceRef), uintField(6, uint(nonce)), bytesField(7, destination), bytesField(8, amount),
    uintField(9, uint(deadlineUnix, I64)),
    ...signatures.map((signature) => bytesAlways(10, unhex(signature, 65))),
  ]);
}

function any(typeUrl, value) { return Buffer.concat([bytesField(1, typeUrl), bytesField(2, value)]); }

export function compressedPublicKey(value) {
  const bytes = unhex(value, 33);
  if (![2, 3].includes(bytes[0])) throw failure();
  // Only a point on the curve, in its canonical compressed form.
  let canonical;
  try { canonical = SigningKey.computePublicKey(bytes, true); } catch { throw failure(); }
  if (canonical !== hex(bytes)) throw failure();
  return bytes;
}

// TxBody, AuthInfo and SignDoc for one signer, SIGN_MODE_DIRECT, one fee coin.
export function buildXitcoinSignDoc({ messageBytes, publicKey, accountNumber, sequence, gasLimit, feeAmount, chainId }) {
  if (!Buffer.isBuffer(messageBytes) || !messageBytes.length || messageBytes.length > 8_192) throw failure();
  if (chainId !== XITCOIN_TESTNET_CHAIN_ID) throw failure();
  const key = compressedPublicKey(publicKey);
  const gas = uint(gasLimit);
  if (gas === 0n) throw failure();
  const body = bytesAlways(1, any(MSG_SUBMIT_ATTESTATION, messageBytes));
  const signerInfo = Buffer.concat([
    bytesAlways(1, any(ETH_SECP256K1_PUBKEY, bytesField(1, key))),
    bytesAlways(2, bytesAlways(1, uintField(1, SIGN_MODE_DIRECT))),
    uintField(3, uint(sequence)),
  ]);
  const fee = Buffer.concat([bytesAlways(1, Buffer.concat([bytesField(1, FEE_DENOM), bytesField(2, canonicalAmount(feeAmount))])),
    uintField(2, gas)]);
  const authInfo = Buffer.concat([bytesAlways(1, signerInfo), bytesAlways(2, fee)]);
  const signDoc = Buffer.concat([bytesField(1, body), bytesField(2, authInfo), bytesField(3, chainId), uintField(4, uint(accountNumber))]);
  return Object.freeze({ bodyBytes: body, authInfoBytes: authInfo, signDocBytes: signDoc, signingDigest: keccak256(signDoc) });
}

// Low-S R || S || V (V in {0, 1}) from an Ethereum-style 65-byte signature.
export function cosmosSignature(serialized, digest, publicKey) {
  const bytes = unhex(serialized, 65);
  const r = BigInt(hex(bytes.subarray(0, 32))), s = BigInt(hex(bytes.subarray(32, 64)));
  let v = bytes[64];
  if (v === 27 || v === 28) v -= 27;
  if (v > 1 || r < 1n || r >= N || s < 1n || s > N / 2n) throw failure();
  const normalized = Buffer.concat([bytes.subarray(0, 64), Buffer.from([v])]);
  if (SigningKey.recoverPublicKey(digest, hex(Buffer.concat([bytes.subarray(0, 64), Buffer.from([v + 27])])))
      !== SigningKey.computePublicKey(compressedPublicKey(publicKey), false)) throw failure();
  return normalized;
}

export function assembleTxRaw({ bodyBytes, authInfoBytes, signature }) {
  if (!Buffer.isBuffer(signature) || signature.length !== 65) throw failure();
  const raw = Buffer.concat([bytesField(1, bodyBytes), bytesField(2, authInfoBytes), bytesAlways(3, signature)]);
  if (raw.length > MAX_TRANSACTION_BYTES) throw failure();
  return Object.freeze({ signedHex: hex(raw), transactionHash: hex(sha256(raw)) });
}

// Simulation only: the SDK accepts an empty signature in simulate mode and
// charges the gas of the signer's key type.
export function assembleSimulationTx({ bodyBytes, authInfoBytes }) {
  return Buffer.concat([bytesField(1, bodyBytes), bytesField(2, authInfoBytes), bytesAlways(3, Buffer.alloc(0))]);
}

// ---------------------------------------------------------------------------
// Strict decoding. Every structure is re-encoded and compared with the input,
// so a non-canonical encoding (field order, overlong varint, explicit default,
// unknown field, duplicate field) is rejected.
function read(bytes) {
  const fields = [];
  let offset = 0;
  const readVarint = () => {
    let value = 0n, shift = 0n, start = offset;
    for (;;) {
      if (offset >= bytes.length || shift > 63n) throw failure();
      const byte = bytes[offset++];
      value |= BigInt(byte & 127) << shift;
      if (!(byte & 128)) break;
      shift += 7n;
    }
    if (value > U64 || !varint(value).equals(bytes.subarray(start, offset))) throw failure();
    return value;
  };
  while (offset < bytes.length) {
    const key = readVarint();
    const field = Number(key >> 3n), wire = Number(key & 7n);
    if (field < 1) throw failure();
    if (wire === 0) fields.push({ field, wire, value: readVarint() });
    else if (wire === 2) {
      const length = Number(readVarint());
      if (offset + length > bytes.length) throw failure();
      fields.push({ field, wire, value: bytes.subarray(offset, offset + length) });
      offset += length;
    } else throw failure();
  }
  return fields;
}
function only(fields, allowed) {
  for (const item of fields) if (!Object.hasOwn(allowed, item.field) || allowed[item.field] !== item.wire) throw failure();
}
function single(fields, number) {
  const found = fields.filter((item) => item.field === number);
  if (found.length > 1) throw failure();
  return found[0]?.value;
}
const text = (value) => {
  if (value === undefined) return "";
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(value);
  return decoded;
};

export function decodeSubmitAttestation(bytes) {
  const fields = read(bytes);
  only(fields, { 1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 0, 7: 2, 8: 2, 9: 0, 10: 2 });
  const message = {
    submitter: text(single(fields, 1)), routeId: text(single(fields, 2)), direction: text(single(fields, 3)),
    sourceChainId: text(single(fields, 4)), sourceRef: text(single(fields, 5)), nonce: String(single(fields, 6) ?? 0n),
    destination: text(single(fields, 7)), amount: text(single(fields, 8)), deadlineUnix: String(single(fields, 9) ?? 0n),
    signatures: fields.filter((item) => item.field === 10).map((item) => hex(item.value)),
  };
  if (BigInt(message.deadlineUnix) > I64 || !encodeSubmitAttestation(message).equals(bytes)) throw failure();
  return Object.freeze({ ...message, signatures: Object.freeze(message.signatures) });
}

// Exactly the supported subset: one MsgSubmitAttestation, no memo, timeout,
// extension options or unordered flag; one eth_secp256k1 signer in
// SIGN_MODE_DIRECT; one axtc fee coin, no payer or granter; one 65-byte
// signature. Returns the decoded fields; the caller compares them with what
// it expects and verifies the signature against the SignDoc.
export function decodeXitcoinTransaction(signedHex) {
  try {
    const raw = unhex(signedHex);
    if (!raw.length || raw.length > MAX_TRANSACTION_BYTES) throw failure();
    const top = read(raw);
    only(top, { 1: 2, 2: 2, 3: 2 });
    const bodyBytes = single(top, 1), authInfoBytes = single(top, 2);
    const signatures = top.filter((item) => item.field === 3);
    if (!bodyBytes || !authInfoBytes || signatures.length !== 1 || signatures[0].value.length !== 65) throw failure();
    const body = read(bodyBytes);
    only(body, { 1: 2 });
    const messages = body.filter((item) => item.field === 1);
    if (messages.length !== 1) throw failure();
    const anyFields = read(messages[0].value);
    only(anyFields, { 1: 2, 2: 2 });
    if (text(single(anyFields, 1)) !== MSG_SUBMIT_ATTESTATION) throw failure();
    const message = decodeSubmitAttestation(single(anyFields, 2) ?? Buffer.alloc(0));
    const auth = read(authInfoBytes);
    only(auth, { 1: 2, 2: 2 });
    const signerInfos = auth.filter((item) => item.field === 1);
    if (signerInfos.length !== 1) throw failure();
    const signer = read(signerInfos[0].value);
    only(signer, { 1: 2, 2: 2, 3: 0 });
    const keyAny = read(single(signer, 1) ?? Buffer.alloc(0));
    only(keyAny, { 1: 2, 2: 2 });
    if (text(single(keyAny, 1)) !== ETH_SECP256K1_PUBKEY) throw failure();
    const keyFields = read(single(keyAny, 2) ?? Buffer.alloc(0));
    only(keyFields, { 1: 2 });
    const publicKey = hex(single(keyFields, 1) ?? Buffer.alloc(0));
    compressedPublicKey(publicKey);
    const modeInfo = read(single(signer, 2) ?? Buffer.alloc(0));
    only(modeInfo, { 1: 2 });
    const singleMode = read(single(modeInfo, 1) ?? Buffer.alloc(0));
    only(singleMode, { 1: 0 });
    if (single(singleMode, 1) !== SIGN_MODE_DIRECT) throw failure();
    const sequence = single(signer, 3) ?? 0n;
    const fee = read(single(auth, 2) ?? Buffer.alloc(0));
    only(fee, { 1: 2, 2: 0 });
    const coins = fee.filter((item) => item.field === 1);
    if (coins.length !== 1) throw failure();
    const coin = read(coins[0].value);
    only(coin, { 1: 2, 2: 2 });
    if (text(single(coin, 1)) !== FEE_DENOM) throw failure();
    const feeAmount = canonicalAmount(text(single(coin, 2)));
    const gasLimit = single(fee, 2) ?? 0n;
    if (gasLimit === 0n) throw failure();
    const rebuilt = Buffer.concat([bytesField(1, bodyBytes), bytesField(2, authInfoBytes), bytesAlways(3, signatures[0].value)]);
    if (!rebuilt.equals(raw)) throw failure();
    return Object.freeze({ message, publicKey, sequence: sequence.toString(), gasLimit: gasLimit.toString(), feeAmount,
      signatureHex: hex(signatures[0].value), bodyBytes: Buffer.from(bodyBytes), authInfoBytes: Buffer.from(authInfoBytes),
      transactionHash: hex(sha256(raw)) });
  } catch { throw failure(); }
}

// The signed content of a transaction as the chain reads it: the last
// body_bytes and auth_info_bytes fields and R || S of a single 64- or 65-byte
// signature. pos-chain's eth_secp256k1 verifier (crypto/ethsecp256k1,
// verifySignatureECDSA) drops a 65th byte without checking it and also accepts
// 64-byte R || S, and the SDK's TxRaw decoder accepts a repeated body_bytes or
// auth_info_bytes field (the last wins) and overlong field tags. So anyone who
// sees our broadcast bytes can re-wrap the same signed content into another
// TxRaw with another hash, which spends our sequence and fee exactly as ours
// would. Our inclusion is therefore recognised by signed content, never only
// by hash. Returns null for anything that cannot carry exactly one signature.
export function signedContent(tx) {
  try {
    const raw = typeof tx === "string" ? unhex(tx) : tx;
    if (!Buffer.isBuffer(raw) || !raw.length || raw.length > 1_048_576) return null;
    let offset = 0, body = null, auth = null;
    const signatures = [];
    const readVarint = () => {
      let value = 0n, shift = 0n;
      for (;;) {
        if (offset >= raw.length || shift > 63n) throw failure();
        const byte = raw[offset++];
        value |= BigInt(byte & 127) << shift;
        if (!(byte & 128)) return value;
        shift += 7n;
      }
    };
    while (offset < raw.length) {
      const key = readVarint();
      if ((key & 7n) !== 2n) return null;
      const length = Number(readVarint());
      if (offset + length > raw.length) return null;
      const value = raw.subarray(offset, offset + length);
      offset += length;
      const field = key >> 3n;
      if (field === 1n) body = value;
      else if (field === 2n) auth = value;
      else if (field === 3n) signatures.push(value);
      else return null;
    }
    if (!body || !auth || signatures.length !== 1 || ![64, 65].includes(signatures[0].length)) return null;
    return Object.freeze({ bodyHex: hex(body), authInfoHex: hex(auth), signatureRs: hex(signatures[0].subarray(0, 64)) });
  } catch { return null; }
}

export function sameSignedContent(a, b) {
  return a !== null && b !== null && a.bodyHex === b.bodyHex && a.authInfoHex === b.authInfoHex && a.signatureRs === b.signatureRs;
}

// The compressed key's EVM address in Xitcoin bech32 form.
export function accountOfPublicKey(publicKey) {
  return evmAddressToBech32(computeAddress(hex(compressedPublicKey(publicKey))));
}

// True only when the signature is the low-S, V in {0, 1} signature of this
// key over the SignDoc for this chain and account number.
export function verifyXitcoinSignature({ bodyBytes, authInfoBytes, chainId, accountNumber, signatureHex, publicKey }) {
  try {
    const signingDigest = keccak256(Buffer.concat([bytesField(1, bodyBytes), bytesField(2, authInfoBytes), bytesField(3, chainId),
      uintField(4, uint(accountNumber))]));
    const signature = unhex(signatureHex, 65);
    return cosmosSignature(hex(signature), signingDigest, publicKey).equals(signature);
  } catch { return false; }
}

// SimulateRequest{tx_bytes = 2} and the gas of SimulateResponse{gas_info = 1
// {gas_wanted = 1, gas_used = 2}}, for an ABCI query of the tx service.
export function encodeSimulateRequest(txBytes) { return bytesField(2, txBytes); }
export function decodeSimulateGasUsed(bytes) {
  const response = read(bytes);
  only(response, { 1: 2, 2: 2 });
  const gasInfo = read(single(response, 1) ?? Buffer.alloc(0));
  only(gasInfo, { 1: 0, 2: 0 });
  const used = single(gasInfo, 2) ?? 0n;
  if (used === 0n) throw failure();
  return used;
}
