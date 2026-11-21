import { signerTransportError, sanitizeSignerTransportError } from "./signer-transport-error.js";
import { readBoundedText, withDeadline } from "./bounded-response.js";
import { createHash } from "node:crypto";
import {
  getAddress,
  isHexString,
  recoverAddress,
} from "ethers";

import {
  DIRECTION_INBOUND,
  DIRECTION_OUTBOUND,
  attestationDigest,
  normalizeBytes32,
  releaseDigest,
  sourceDepositKey,
  validateChainId,
  validateEvmChainId,
  validateRouteId,
} from "./protocol.js";

export const APPROVAL_PROTOCOL_VERSION = 1;
// An expired approval request is re-issued (new deadline, same source event)
// only this long after its deadline, so destination block time that lags the
// relayer clock cannot still accept the previous approval.
export const APPROVAL_REISSUE_GRACE_SECONDS = 120;

function positiveInteger(value, label, minimum = 1) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return number;
}

function signerSet(values) {
  if (!Array.isArray(values) || values.length !== 3) {
    throw new Error("exactly three authorized signers are required");
  }
  const normalized = values.map((value) => getAddress(value));
  if (new Set(normalized.map((value) => value.toLowerCase())).size !== 3) {
    throw new Error("authorized signers must be distinct");
  }
  return normalized;
}

function deadlineOf(direction, payload) {
  return positiveInteger(
    direction === DIRECTION_INBOUND ? payload.deadlineUnix : payload.deadline,
    "approval deadline",
  );
}

export function buildApprovalRequest({ direction, payload }) {
  if (![DIRECTION_INBOUND, DIRECTION_OUTBOUND].includes(direction)) {
    throw new Error("invalid approval direction");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("approval payload is required");
  }
  const digest = direction === DIRECTION_INBOUND
    ? attestationDigest({ ...payload, direction })
    : releaseDigest(payload);
  return Object.freeze({
    version: APPROVAL_PROTOCOL_VERSION,
    direction,
    digest: digest.toLowerCase(),
    deadlineUnix: deadlineOf(direction, payload),
    payload: structuredClone(payload),
  });
}

function sha256Hex(fields) {
  return `0x${createHash("sha256").update(fields.join("\0"), "utf8").digest("hex")}`;
}

// Identity of the source event an approval spends. Inbound: the chain's
// source-deposit replay key. Outbound: the vault's replay key (sourceBurnId)
// scoped to the Cronos chain and vault. Deadlines never change it.
export function approvalSourceKey(request) {
  const { direction, payload } = buildApprovalRequest(request);
  if (direction === DIRECTION_INBOUND) return sourceDepositKey(payload);
  return sha256Hex([
    "xitcoin-bridge-release-source-v1",
    validateEvmChainId(String(payload.chainId)),
    getAddress(payload.vault).toLowerCase(),
    normalizeBytes32(payload.sourceBurnId),
  ]);
}

// Commitment to everything an approval authorizes except the fields that a
// safe re-issue may change: the deadline (both directions) and, for releases,
// the vault signer-set version (a rotation invalidates older signatures on
// the vault). Two requests for one source event with different content hashes
// are conflicting and must never both be signed.
export function approvalContentHash(request) {
  const { direction, payload } = buildApprovalRequest(request);
  if (direction === DIRECTION_INBOUND) {
    return sha256Hex([
      direction,
      validateChainId(payload.destinationChainId),
      validateRouteId(payload.routeId),
      validateEvmChainId(payload.sourceChainId),
      normalizeBytes32(payload.sourceRef),
      String(payload.nonce),
      String(payload.destination).trim(),
      String(payload.amount),
    ]);
  }
  return sha256Hex([
    direction,
    validateEvmChainId(String(payload.chainId)),
    getAddress(payload.vault).toLowerCase(),
    normalizeBytes32(payload.sourceBurnId),
    getAddress(payload.recipient).toLowerCase(),
    String(payload.amount),
  ]);
}

export function verifyApproval({ request, response, authorizedSigners, nowUnix = Math.floor(Date.now() / 1000) }) {
  const expected = buildApprovalRequest(request);
  if (expected.deadlineUnix < positiveInteger(nowUnix, "current time", 0)) {
    throw new Error("approval request has expired");
  }
  if (!response || typeof response !== "object") throw new Error("invalid approval response");
  if (String(response.digest).toLowerCase() !== expected.digest) {
    throw new Error("approval digest mismatch");
  }
  if (!isHexString(response.signature, 65)) throw new Error("approval signature must contain 65 bytes");
  // pos-chain 5ec8692e8fc1813d0892ee535af1a73953a1c4fb:
  // x/bridge/types/signatures.go recoverSigner + ValidateSignatureValues(..., true).
  // Inspect original r || s || v before ethers can normalize v (including EIP-155).
  const signature = response.signature;
  const recovery = Number.parseInt(signature.slice(130, 132), 16);
  if (![0, 1, 27, 28].includes(recovery)) throw new Error("invalid signature recovery ID");
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  if (r < 1n || r >= order || s < 1n || s > order / 2n) throw new Error("invalid signature values");
  const recovered = getAddress(recoverAddress(expected.digest, signature));
  const allowed = signerSet(authorizedSigners);
  if (!allowed.some((signer) => signer === recovered)) throw new Error("approval is not from an authorized signer");
  if (response.signer && getAddress(response.signer) !== recovered) {
    throw new Error("approval signer does not match the signature");
  }
  return Object.freeze({ signer: recovered, digest: expected.digest, signature });
}

export async function collectApprovalQuorum({
  clients,
  request,
  authorizedSigners,
  threshold = 2,
  nowUnix = Math.floor(Date.now() / 1000),
}) {
  const allowed = signerSet(authorizedSigners);
  const required = positiveInteger(threshold, "approval threshold");
  if (required > allowed.length) throw new Error("approval threshold exceeds signer set");
  if (!Array.isArray(clients) || clients.length < required) {
    throw new Error("insufficient independent signer clients");
  }
  const identities = clients.map((client) => String(client.identity ?? "").trim());
  if (identities.some((identity) => !identity) || new Set(identities).size !== identities.length) {
    throw new Error("signer clients must have distinct identities");
  }
  const expected = buildApprovalRequest(request);
  if (expected.deadlineUnix < positiveInteger(nowUnix, "current time", 0)) {
    throw new Error("approval request has expired");
  }
  const responses = await Promise.allSettled(clients.map((client) => client.approve(expected)));
  // One unavailable, malformed, unauthorized or duplicate response must not
  // sink the round: each response is verified on its own and only distinct
  // valid signers count toward the threshold.
  const unique = new Map();
  const rejected = [];
  for (const response of responses) {
    if (response.status !== "fulfilled") { rejected.push("signer unavailable"); continue; }
    let approval;
    try {
      approval = verifyApproval({ request: expected, response: response.value, authorizedSigners: allowed, nowUnix });
    } catch (error) {
      rejected.push(String(error?.message ?? "invalid approval").slice(0, 120));
      continue;
    }
    const key = approval.signer.toLowerCase();
    if (unique.has(key)) { rejected.push("duplicate signer approval"); continue; }
    unique.set(key, approval);
  }
  if (unique.size < required) {
    const reasons = [...new Set(rejected)].join("; ");
    throw new Error(`approval quorum not reached (${unique.size} of ${required} valid${reasons ? `; rejected: ${reasons}` : ""})`);
  }
  return [...unique.values()]
    .sort((left, right) => left.signer.toLowerCase().localeCompare(right.signer.toLowerCase()))
    .slice(0, required);
}

function approvalUrl(value, allowHttp) {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (url.username || url.password) throw new Error("signer credentials must not be embedded in URLs");
  if (url.protocol !== "https:" && !(allowHttp && loopback && url.protocol === "http:")) {
    throw new Error("signer URL must use HTTPS");
  }
  url.hash = "";
  return url;
}

export class RemoteSignerClient {
  constructor({ url, identity, timeoutMs = 10_000, maxResponseBytes = 16_384, allowHttp = false,
    authorizationHeader, fetchImpl = globalThis.fetch }) {
    this.url = approvalUrl(url, allowHttp);
    this.identity = String(identity ?? this.url.origin).trim();
    if (!this.identity) throw new Error("signer identity is required");
    if (typeof fetchImpl !== "function") throw new Error("fetch implementation is required");
    if (typeof authorizationHeader !== "function") throw new Error("signer transport authentication is required");
    this.timeoutMs = positiveInteger(timeoutMs, "signer timeout");
    this.maxResponseBytes = positiveInteger(maxResponseBytes, "maximum signer response size");
    this.fetch = fetchImpl;
    this.authorizationHeader = authorizationHeader;
  }

  async approve(request) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    let reading = false;
    try {
      const authorization = String(await withDeadline(() => this.authorizationHeader(), controller.signal));
      if (!authorization.startsWith("Bearer ") || authorization.length < 39 || /[\r\n]/.test(authorization)) {
        throw signerTransportError("AUTHENTICATION");
      }
      response = await withDeadline(() => this.fetch(this.url, {
        method: "POST",
        headers: { accept: "application/json", authorization, "content-type": "application/json" },
        body: JSON.stringify(request),
        redirect: "error",
        signal: controller.signal,
      }), controller.signal);
      if (!response.ok) throw signerTransportError("HTTP");
      reading = true;
      const body = await readBoundedText(response, { maxBytes: this.maxResponseBytes, signal: controller.signal });
      try {
        return JSON.parse(body);
      } catch {
        throw signerTransportError("JSON");
      }
    } catch (error) {
      throw sanitizeSignerTransportError(error);
    } finally {
      // HTTP failures have not acquired a reader. Cancel without trusting
      // injected cleanup to settle or to throw safe errors.
      if (response && !reading) {
        try { Promise.resolve(response.body?.cancel()).catch(() => {}); } catch {}
      }
      controller.abort();
      clearTimeout(timer);
    }
  }
}
