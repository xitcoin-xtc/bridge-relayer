// Relayer encodings checked against vectors produced by the chain's own Go
// code (test/reference/xitcoin-chain-vectors/main.go at the pinned pos-chain
// commit; CI regenerates them with scripts/check-chain-fixtures.sh).
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { SigningKey, computeAddress } from "ethers";
import { buildApprovalRequest } from "../src/approvals.js";
import { TESTNET_ROUTE_ID } from "../src/preflight.js";
import { XITCOIN_TESTNET_ROUTE_ID, attestationDigest, attestationId, attestationPayloadHash, cronosRouteId } from "../src/protocol.js";
import { prepareXitcoinAttestation } from "../src/xitcoin-destination.js";

const vectors = JSON.parse(readFileSync(new URL("./fixtures/xitcoin-chain-vectors.json", import.meta.url), "utf8"));
const key = (n) => new SigningKey(`0x${n.toString(16).padStart(64, "0")}`);
const signers = [1, 2, 3].map((n) => computeAddress(key(n).publicKey));
const attestation = (routeId = vectors.attestation.routeId) => ({ destinationChainId: vectors.chainId, routeId,
  direction: vectors.attestation.direction, sourceChainId: vectors.attestation.sourceChainId, sourceRef: vectors.attestation.sourceRef,
  nonce: vectors.attestation.nonce, destination: vectors.attestation.destination, amount: vectors.attestation.amount,
  deadlineUnix: vectors.attestation.deadlineUnix });

test("the relayer route is the route ID the chain stores and signs, never the display label", () => {
  assert.equal(vectors.chainId, "xitcoin-testnet-v2-1");
  assert.equal(vectors.attestation.routeId, XITCOIN_TESTNET_ROUTE_ID);
  assert.equal(XITCOIN_TESTNET_ROUTE_ID, "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9");
  // A deployment fact on testnet, pinned on both sides independently.
  assert.equal(XITCOIN_TESTNET_ROUTE_ID, TESTNET_ROUTE_ID.toLowerCase());
  assert.notEqual(cronosRouteId("cronos-testnet-xitcoin-testnet"), TESTNET_ROUTE_ID);
});

test("replay key, payload hash and approval digest equal the chain's for the stored route ID", () => {
  assert.equal(attestationId(attestation()), vectors.attestation.attestationId);
  assert.equal(attestationPayloadHash(attestation()), vectors.attestation.payloadHash);
  assert.equal(attestationDigest(attestation()), vectors.attestation.signingDigest);
  // The route ID is hashed verbatim: the label (what the relayer used to sign)
  // yields another digest, which the chain rejects with ErrAttestationRouteMismatch
  // before it would even verify the approvals.
  assert.notEqual(attestationDigest(attestation("cronos-testnet-xitcoin-testnet")), vectors.attestation.signingDigest);
  assert.equal(attestationId(attestation("cronos-testnet-xitcoin-testnet")), vectors.attestation.attestationId);
});

test("approvals and the MsgSubmitAttestation bytes equal the chain's encoding", () => {
  // RFC 6979 signatures are deterministic in both implementations.
  vectors.attestation.approverKeyNumbers.forEach((n, index) => {
    assert.equal(key(n).sign(vectors.attestation.signingDigest).serialized, vectors.attestation.approvalSignatures[index]);
  });
  const payload = attestation();
  delete payload.direction;
  const request = buildApprovalRequest({ direction: vectors.attestation.direction, payload });
  assert.equal(request.digest, vectors.attestation.signingDigest);
  const approvals = vectors.attestation.approverKeyNumbers.map((n, index) => ({ signer: computeAddress(key(n).publicKey),
    digest: request.digest, signature: vectors.attestation.approvalSignatures[index] }));
  for (const transaction of vectors.transactions) {
    const message = prepareXitcoinAttestation({ chainId: vectors.chainId, request, approvals, authorizedSigners: signers,
      submitter: transaction.submitter, nowUnix: 1_900_000_000 });
    assert.equal(message.messageHex, transaction.message);
    assert.equal(message.attestationId, vectors.attestation.attestationId);
  }
});
