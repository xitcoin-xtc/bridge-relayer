import { createHash } from "node:crypto";
import {
  AbiCoder,
  TypedDataEncoder,
  concat,
  getAddress,
  getBytes,
  hexlify,
  id,
  isHexString,
  keccak256,
  toUtf8Bytes,
} from "ethers";

// Network-specific signing domain (pos-chain x/bridge/types/domain.go):
// the verifying Xitcoin chain ID is appended, so an approval for
// xitcoin-testnet-v2-1 can never be replayed on xitcoin. v1 used the fixed
// string "xitcoin-bridge-testnet-attestation-v1" on every network.
export const ATTESTATION_DOMAIN_PREFIX = "xitcoin-bridge-attestation-v2";
export const SOURCE_DEPOSIT_DOMAIN = "xitcoin-bridge-source-deposit-v1";
export const DIRECTION_INBOUND = "cronos_to_xitcoin";
export const DIRECTION_OUTBOUND = "xitcoin_to_cronos";

// Route ID stored by the Xitcoin bridge module on xitcoin-testnet-v2-1, as
// observed on the live chain: the route was initialised with the Cronos vault
// bytes32 route ID in 0x-prefixed lower-case hex (it satisfies the chain's
// route-ID rule, 1 to 96 bytes of [a-z0-9_-]). The chain compares it byte for
// byte with the route ID of every MsgSubmitAttestation, hashes it into every
// approval digest and emits it in every outbound burn event, so it is the
// only Xitcoin route ID the relayer signs, submits or compares. It happens to
// equal the Cronos route (TESTNET_ROUTE_ID); both are pinned independently,
// never derived from each other or from a display label.
export const XITCOIN_TESTNET_ROUTE_ID = "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9";

function positiveDecimal(value, label) {
  const text = String(value);
  if (!/^[1-9][0-9]*$/.test(text)) throw new Error(`${label} must be a positive decimal integer`);
  return text;
}

function sourceReference(value) {
  const normalized = String(value).trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("source reference must contain 32 bytes");
  return normalized;
}

function sha256Hex(fields) {
  return `0x${createHash("sha256").update(fields.join("\0"), "utf8").digest("hex")}`;
}

export function validateRouteId(routeId) {
  if (!/^[a-z0-9_-]{1,96}$/.test(routeId)) throw new Error("invalid route ID");
  return routeId;
}

// Same rule as pos-chain types.ValidateChainID.
export function validateChainId(chainId) {
  const text = String(chainId ?? "");
  if (text.length < 1 || text.length > 64 || /[\0/ \t\r\n]/.test(text)) throw new Error("invalid chain ID");
  return text;
}

// Canonical decimal EVM chain ID, as pos-chain types.ValidateEVMChainID.
export function validateEvmChainId(chainId) {
  const text = String(chainId ?? "");
  if (!/^[1-9][0-9]{0,19}$/.test(text)) throw new Error("source chain ID must be a canonical decimal EVM chain ID");
  return text;
}

export function cronosRouteId(routeId) {
  return id(validateRouteId(routeId));
}

export function attestationDomain(chainId) {
  return `${ATTESTATION_DOMAIN_PREFIX}/${validateChainId(chainId)}`;
}

// Replay key of one Cronos deposit, identical to pos-chain
// types.SourceDepositKey: sha256(domain \0 sourceChainId \0 sourceRef).
// It excludes the deadline and every other signed field, so re-issuing an
// approval with a new deadline keeps the same key on the chain, in the
// coordinator store and in every signer journal.
export function sourceDepositKey({ sourceChainId, sourceRef }) {
  return sha256Hex([SOURCE_DEPOSIT_DOMAIN, validateEvmChainId(sourceChainId), sourceReference(sourceRef)]);
}

// The chain's attestation ID is the source-deposit replay key
// (pos-chain types.Attestation.ID, query `attestation-status`).
export function attestationId(attestation) {
  return sourceDepositKey(attestation);
}

// pos-chain types.Attestation.PayloadHash(destinationChainId).
export function attestationPayloadHash(attestation) {
  const fields = [
    validateChainId(attestation.destinationChainId),
    validateRouteId(attestation.routeId),
    attestation.direction,
    validateEvmChainId(attestation.sourceChainId),
    sourceReference(attestation.sourceRef),
    positiveDecimal(attestation.nonce, "nonce"),
    String(attestation.destination).trim(),
    positiveDecimal(attestation.amount, "amount"),
    positiveDecimal(attestation.deadlineUnix, "deadline"),
  ];
  if (![DIRECTION_INBOUND, DIRECTION_OUTBOUND].includes(fields[2])) throw new Error("invalid direction");
  if (!fields[6]) throw new Error("missing attestation field");
  return sha256Hex(fields);
}

// pos-chain types.SigningDigest: keccak256(domain || payloadHash).
export function attestationDigest(attestation) {
  return keccak256(concat([
    toUtf8Bytes(attestationDomain(attestation.destinationChainId)),
    getBytes(attestationPayloadHash(attestation)),
  ]));
}

export function depositId({ chainId, vault, routeId, depositor, recipient, amount, nonce }) {
  const encoded = AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "bytes32", "address", "address", "uint256", "uint256"],
    [BigInt(chainId), getAddress(vault), routeId, getAddress(depositor), getAddress(recipient), BigInt(amount), BigInt(nonce)],
  );
  return keccak256(encoded);
}

export function releaseDigest({ chainId, vault, sourceBurnId, recipient, amount, signerSetVersion, deadline }) {
  if (!isHexString(sourceBurnId, 32)) throw new Error("invalid source burn ID");
  return TypedDataEncoder.hash(
    {
      name: "Xitcoin Cronos Bridge Vault",
      version: "1",
      chainId: BigInt(chainId),
      verifyingContract: getAddress(vault),
    },
    {
      Release: [
        { name: "sourceBurnId", type: "bytes32" },
        { name: "recipient", type: "address" },
        { name: "amount", type: "uint256" },
        { name: "signerSetVersion", type: "uint64" },
        { name: "deadline", type: "uint256" },
      ],
    },
    {
      sourceBurnId,
      recipient: getAddress(recipient),
      amount: BigInt(amount),
      signerSetVersion: BigInt(signerSetVersion),
      deadline: BigInt(deadline),
    },
  );
}

export function normalizeBytes32(value) {
  if (!isHexString(value, 32)) throw new Error("expected bytes32");
  return hexlify(value).toLowerCase();
}
