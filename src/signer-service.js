import { Buffer } from "node:buffer";
import { ZeroAddress, getAddress, isHexString, recoverAddress, Signature } from "ethers";

import { approvalContentHash, approvalSourceKey, buildApprovalRequest } from "./approvals.js";
import { DIRECTION_INBOUND, DIRECTION_OUTBOUND, validateChainId, validateRouteId } from "./protocol.js";

function positiveInteger(value, label, minimum = 1) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return number;
}

function exactString(value, label) {
  const text = String(value ?? "").trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function allowedSet(values, normalize, label) {
  if (!Array.isArray(values) || values.length < 1) throw new Error(`${label} are required`);
  return new Set(values.map(normalize));
}

export function createSignerPolicy({ routeIds, cronosChainIds = [25], xitcoinChainIds, cronosVaults, maximumAmount, maximumDeadlineSeconds = 900 }) {
  const routes = allowedSet(routeIds, validateRouteId, "allowed route IDs");
  const chains = allowedSet(cronosChainIds, (value) => positiveInteger(value, "Cronos chain ID"), "Cronos chain IDs");
  const destinations = allowedSet(xitcoinChainIds, validateChainId, "Xitcoin chain IDs");
  const vaults = allowedSet(cronosVaults, (value) => getAddress(value).toLowerCase(), "Cronos vaults");
  const amountLimit = BigInt(exactString(maximumAmount, "maximum amount"));
  if (amountLimit < 1n) throw new Error("maximum amount must be positive");
  const deadlineWindow = positiveInteger(maximumDeadlineSeconds, "maximum deadline window");
  return Object.freeze({ routes, chains, destinations, vaults, amountLimit, deadlineWindow });
}

export function authorizeSignerRequest({ request, policy, nowUnix = Math.floor(Date.now() / 1000) }) {
  if (!policy) throw new Error("signer policy is required");
  const canonical = buildApprovalRequest(request);
  const now = positiveInteger(nowUnix, "current time", 0);
  if (canonical.deadlineUnix < now) throw new Error("approval request has expired");
  if (canonical.deadlineUnix > now + policy.deadlineWindow) throw new Error("approval deadline exceeds signer policy");
  const amount = BigInt(exactString(canonical.payload.amount, "approval amount"));
  if (amount < 1n || amount > policy.amountLimit) throw new Error("approval amount exceeds signer policy");
  if (canonical.direction === DIRECTION_INBOUND) {
    if (!policy.routes.has(validateRouteId(canonical.payload.routeId))) throw new Error("route is not authorized");
    if (!policy.chains.has(positiveInteger(canonical.payload.sourceChainId, "source chain ID"))) throw new Error("source chain is not authorized");
    if (!policy.destinations.has(validateChainId(canonical.payload.destinationChainId))) throw new Error("destination chain is not authorized");
  } else if (canonical.direction === DIRECTION_OUTBOUND) {
    if (!policy.routes.has(validateRouteId(canonical.payload.routeId))) throw new Error("route is not authorized");
    if (!policy.chains.has(positiveInteger(canonical.payload.chainId, "destination chain ID"))) throw new Error("destination chain is not authorized");
    if (!policy.vaults.has(getAddress(canonical.payload.vault).toLowerCase())) throw new Error("destination vault is not authorized");
    // The vault refuses these recipients forever; never sign an unreleasable approval.
    const recipient = getAddress(canonical.payload.recipient).toLowerCase();
    if (recipient === ZeroAddress || recipient === "0x000000000000000000000000000000000000dead"
        || recipient === getAddress(canonical.payload.vault).toLowerCase()) throw new Error("release recipient is not allowed");
  } else {
    throw new Error("approval direction is not authorized");
  }
  return canonical;
}

export class IsolatedSignerService {
  // journal: a SignerApprovalJournal (signer-journal.js). It is mandatory: a
  // signer that keeps no record of what it signed can be asked to sign two
  // different requests for one source event.
  constructor({ identity, signerAddress, policy, verifySource, signDigest, journal }) {
    this.identity = exactString(identity, "signer identity");
    this.signerAddress = getAddress(signerAddress);
    if (!policy) throw new Error("signer policy is required");
    if (typeof verifySource !== "function") throw new Error("source verifier is required");
    if (typeof signDigest !== "function") throw new Error("external digest signer is required");
    if (!journal || typeof journal.plan !== "function" || typeof journal.record !== "function") {
      throw new Error("durable signer approval journal is required");
    }
    this.journal = journal;
    this.policy = policy;
    this.verifySource = verifySource;
    this.signDigest = signDigest;
  }

  async approve(request, { nowUnix = Math.floor(Date.now() / 1000) } = {}) {
    const canonical = authorizeSignerRequest({ request, policy: this.policy, nowUnix });
    const sourceKey = approvalSourceKey(canonical);
    const contentHash = approvalContentHash(canonical);
    const plan = this.journal.plan({ sourceKey, contentHash, digest: canonical.digest, nowUnix });
    if (plan.action === "reuse") {
      return Object.freeze({ signer: this.signerAddress, digest: canonical.digest, signature: plan.signature });
    }
    const verification = await this.verifySource(canonical);
    if (!verification || verification.canonical !== true || verification.finalized !== true) {
      throw new Error("source transfer is not canonical and finalized");
    }
    if (verification.digest && String(verification.digest).toLowerCase() !== canonical.digest) {
      throw new Error("source verification digest mismatch");
    }
    const raw = await this.signDigest(canonical.digest, Object.freeze({ identity: this.identity, direction: canonical.direction }));
    if (!isHexString(raw, 65)) throw new Error("external signer returned an invalid signature");
    const signature = Signature.from(raw).serialized;
    if (getAddress(recoverAddress(canonical.digest, signature)) !== this.signerAddress) {
      throw new Error("external signer returned a signature for the wrong account");
    }
    // Persist before release; a failed conditional write discards the signature.
    this.journal.record({
      sourceKey, direction: canonical.direction, contentHash, digest: canonical.digest,
      deadline: canonical.deadlineUnix, signature, nowUnix, reissueOf: plan.reissueOf,
    });
    return Object.freeze({ signer: this.signerAddress, digest: canonical.digest, signature });
  }
}

function statusFor(error) {
  return /authorization/i.test(error.message) ? 401 : 400;
}

export function createSignerHttpHandler({ service, authorize, path = "/v1/approve", maximumRequestBytes = 16_384 }) {
  if (!service || typeof service.approve !== "function") throw new Error("signer service is required");
  if (typeof authorize !== "function") throw new Error("transport authorization is required");
  const limit = positiveInteger(maximumRequestBytes, "maximum request size");
  return async function signerHttpHandler(request, response) {
    try {
      if (request.method !== "POST" || request.url !== path) { response.writeHead(404).end(); return; }
      if (await authorize(request) !== true) throw new Error("transport authorization failed");
      const declared = Number(request.headers["content-length"] ?? 0);
      if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) throw new Error("request exceeds size limit");
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += Buffer.byteLength(chunk);
        if (size > limit) throw new Error("request exceeds size limit");
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new Error("request contains invalid JSON"); }
      const approval = await service.approve(body);
      const encoded = JSON.stringify(approval);
      response.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(encoded) });
      response.end(encoded);
    } catch (error) {
      const encoded = JSON.stringify({ error: "request_rejected" });
      response.writeHead(statusFor(error), { "content-type": "application/json", "content-length": Buffer.byteLength(encoded) });
      response.end(encoded);
    }
  };
}
