import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, normalize } from "node:path";
import { types } from "node:util";
import { getAddress } from "ethers";
import { independentEndpoints } from "./bounded-transport.js";
import { TESTNET_ROUTE_ID } from "./preflight.js";
import { bech32Encode } from "./address.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "./protocol.js";
import { XITCOIN_CHAIN_SCHEMA_COMMIT, XITCOIN_MAINNET_CHAIN_ID, XITCOIN_TESTNET_CHAIN_ID } from "./xitcoin-transaction.js";

const FIELDS = ["version", "mode", "destination", "releaseCommit", "routeId", "cronosChainId", "xitcoinChainId"];
const TESTNET_FIELDS = [...FIELDS, "relayStorePath", "ledgerPath", "keystorePath", "cycleIntervalMs", "cronos", "xitcoin"];
const CRONOS_FIELDS = ["rpcUrls", "allowLoopbackHttp", "vault", "vaultCodeHash", "cronosRouteId", "signerSetVersion",
  "authorizedSigners", "submitter", "confirmations", "maxAmount", "gasLimit", "maxGasPrice", "maxFee",
  "minDeadlineMarginSeconds", "maxBroadcastAttempts", "releaseLookbackBlocks", "logRangeBlocks"];
const XITCOIN_FIELDS = ["rpcUrls", "allowLoopbackHttp", "safetyLag"];
const XITCOIN_TESTNET_FIELDS = [...FIELDS, "relayStorePath", "ledgerPath", "keystorePath", "cycleIntervalMs", "xitcoin", "cronos"];
const XITCOIN_DESTINATION_FIELDS = ["origins", "allowLoopbackHttp", "chainSchemaCommit", "signerSetVersion", "authorizedSigners",
  "submitter", "confirmations", "historyBlocks", "maxAmount", "maxGas", "gasAdjustmentPercent", "gasHeadroom",
  "feeMultiplierPercent", "maxGasPrice", "maxFee", "minDeadlineMarginSeconds", "maxBroadcastAttempts"];
const CRONOS_SOURCE_FIELDS = ["rpcUrls", "allowLoopbackHttp", "vault", "cronosRouteId", "confirmations"];
const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
const MAX_BYTES = 16_384;

function absolute(path) {
  if (typeof path !== "string" || !isAbsolute(path) || normalize(path) !== path || path.includes("\0")) {
    throw new Error("path must be absolute and normalized");
  }
  return path;
}

export function validateSubmitterManifest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
      || Object.keys(input).length !== FIELDS.length
      || Object.keys(input).some((key) => !FIELDS.includes(key))) throw new Error("unsupported submitter manifest fields");
  if (input.version !== 1 || input.mode !== "disabled") throw new Error("only disabled phase-one submitters are supported");
  if (!["xitcoin", "cronos"].includes(input.destination)) throw new Error("destination is not canonical");
  if (typeof input.releaseCommit !== "string" || !/^[0-9a-f]{40}$/.test(input.releaseCommit)) throw new Error("release must be an immutable Git commit");
  if (input.routeId !== XITCOIN_TESTNET_ROUTE_ID || input.cronosChainId !== 338
      || input.xitcoinChainId !== "xitcoin-testnet-v2-1") throw new Error("only the canonical testnet route is supported");
  return Object.freeze(Object.fromEntries(FIELDS.map((key) => [key, input[key]])));
}

function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== fields.length
      || fields.some((key) => !Object.hasOwn(value, key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"))) {
    throw new Error("unsupported submitter manifest fields");
  }
  return value;
}
function integer(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("submitter manifest integer is out of range");
  return value;
}
function decimalString(value, minimum, maximum) {
  if (typeof value !== "string" || value.length > 78 || !/^(0|[1-9][0-9]*)$/.test(value)
      || BigInt(value) < minimum || BigInt(value) > maximum) throw new Error("submitter manifest decimal is out of range");
  return value;
}
function checksummed(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value) || getAddress(value) !== value
      || /^0x0{40}$/.test(value) || value.toLowerCase() === "0x000000000000000000000000000000000000dead") {
    throw new Error("submitter manifest address must be a nonzero EIP-55 address");
  }
  return value;
}
function urls(value, allowLoopbackHttp) {
  if (!Array.isArray(value) || typeof allowLoopbackHttp !== "boolean") throw new Error("submitter manifest endpoints are invalid");
  try { independentEndpoints(value, { allowLoopbackHttp }); }
  catch { throw new Error("submitter manifest endpoints must be independent HTTPS origins"); }
  return Object.freeze([...value]);
}

// Explicit Cronos testnet submission mode. Every value that binds a transaction
// is pinned here, in a root-owned file; nothing is discovered or defaulted.
// Credentials are never accepted: the keystore password is a systemd credential.
export function validateCronosTestnetManifest(input) {
  const value = exact(input, TESTNET_FIELDS);
  if (value.version !== 1 || value.mode !== "testnet") throw new Error("unsupported submitter manifest mode");
  if (value.destination !== "cronos") throw new Error("only the Cronos destination supports testnet submission");
  if (typeof value.releaseCommit !== "string" || !/^[0-9a-f]{40}$/.test(value.releaseCommit)) throw new Error("release must be an immutable Git commit");
  if (value.routeId !== XITCOIN_TESTNET_ROUTE_ID || value.cronosChainId !== 338
      || value.xitcoinChainId !== "xitcoin-testnet-v2-1") throw new Error("only the canonical testnet route is supported");
  const paths = [value.relayStorePath, value.ledgerPath, value.keystorePath].map((path) => absolute(path));
  if (new Set(paths).size !== 3) throw new Error("submitter manifest paths must be distinct");
  const cronos = exact(value.cronos, CRONOS_FIELDS);
  const xitcoin = exact(value.xitcoin, XITCOIN_FIELDS);
  if (typeof cronos.vaultCodeHash !== "string" || !/^0x[0-9a-f]{64}$/.test(cronos.vaultCodeHash)
      || /^0x0{64}$/.test(cronos.vaultCodeHash) || cronos.vaultCodeHash === EMPTY_CODE_HASH) throw new Error("vault runtime code hash is invalid");
  if (cronos.cronosRouteId !== TESTNET_ROUTE_ID.toLowerCase()) throw new Error("Cronos vault route is not the deployed testnet route");
  if (!Array.isArray(cronos.authorizedSigners) || cronos.authorizedSigners.length !== 3) throw new Error("exactly three authorized signers are required");
  const signers = cronos.authorizedSigners.map(checksummed);
  const accounts = [checksummed(cronos.vault), checksummed(cronos.submitter), ...signers].map((item) => item.toLowerCase());
  if (new Set(accounts).size !== accounts.length) throw new Error("vault, submitter and signers must be distinct");
  const gasLimit = decimalString(cronos.gasLimit, 21_000n, 10_000_000n);
  const maxGasPrice = decimalString(cronos.maxGasPrice, 1n, 10n ** 13n);
  const maxFee = decimalString(cronos.maxFee, 1n, 10n ** 21n);
  if (BigInt(gasLimit) * BigInt(maxGasPrice) > BigInt(maxFee)) throw new Error("fee cap must cover the gas limit at the maximum gas price");
  return Object.freeze({
    version: 1, mode: "testnet", destination: "cronos", releaseCommit: value.releaseCommit,
    routeId: value.routeId, cronosChainId: 338, xitcoinChainId: value.xitcoinChainId,
    relayStorePath: paths[0], ledgerPath: paths[1], keystorePath: paths[2],
    cycleIntervalMs: integer(value.cycleIntervalMs, 1_000, 60_000),
    cronos: Object.freeze({
      rpcUrls: urls(cronos.rpcUrls, cronos.allowLoopbackHttp), allowLoopbackHttp: cronos.allowLoopbackHttp,
      vault: cronos.vault, vaultCodeHash: cronos.vaultCodeHash, cronosRouteId: cronos.cronosRouteId,
      signerSetVersion: decimalString(cronos.signerSetVersion, 1n, (1n << 64n) - 1n),
      authorizedSigners: Object.freeze(signers), submitter: cronos.submitter,
      confirmations: integer(cronos.confirmations, 2, 10_000),
      maxAmount: decimalString(cronos.maxAmount, 1n, (1n << 256n) - 1n),
      gasLimit, maxGasPrice, maxFee,
      minDeadlineMarginSeconds: integer(cronos.minDeadlineMarginSeconds, 30, 3_600),
      maxBroadcastAttempts: integer(cronos.maxBroadcastAttempts, 1, 32),
      // Bounded search for a release of a burn by another transaction.
      releaseLookbackBlocks: integer(cronos.releaseLookbackBlocks, 1_000, 1_000_000),
      logRangeBlocks: integer(cronos.logRangeBlocks, 100, 10_000),
    }),
    xitcoin: Object.freeze({ rpcUrls: urls(xitcoin.rpcUrls, xitcoin.allowLoopbackHttp),
      allowLoopbackHttp: xitcoin.allowLoopbackHttp, safetyLag: integer(xitcoin.safetyLag, 0, 1_000) }),
  });
}

function bech32Account(value) {
  if (typeof value !== "string" || !/^xtc1[02-9ac-hj-np-z]{38}$/.test(value)) throw new Error("submitter account must be a canonical xtc address");
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  let accumulator = 0, bits = 0;
  const bytes = [];
  for (const character of value.slice(4, -6)) {
    accumulator = (accumulator << 5) | charset.indexOf(character);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 0xff); }
  }
  if (bytes.length !== 20 || bech32Encode("xtc", bytes) !== value || bytes.every((byte) => byte === 0)) {
    throw new Error("submitter account must be a canonical xtc address");
  }
  return value;
}
function xitcoinOrigins(value, allowLoopbackHttp) {
  if (!Array.isArray(value) || value.length < 2 || value.length > 4 || typeof allowLoopbackHttp !== "boolean") {
    throw new Error("submitter manifest endpoints are invalid");
  }
  const origins = value.map((origin) => exact(origin, ["rpcUrl", "restUrl"]));
  try {
    independentEndpoints(origins.map((origin) => origin.rpcUrl), { allowLoopbackHttp });
    independentEndpoints(origins.map((origin) => origin.restUrl), { allowLoopbackHttp });
  } catch { throw new Error("submitter manifest endpoints must be independent HTTPS origins"); }
  return Object.freeze(origins.map((origin) => Object.freeze({ rpcUrl: origin.rpcUrl, restUrl: origin.restUrl })));
}

// Explicit Xitcoin testnet submission mode (chain ID xitcoin-testnet-v2-1;
// mainnet `xitcoin` is rejected in this release). Every value that binds a
// transaction is pinned here, in a root-owned file; nothing is discovered or
// defaulted, and no key, password or credential is accepted.
export function validateXitcoinTestnetManifest(input) {
  const value = exact(input, XITCOIN_TESTNET_FIELDS);
  if (value.version !== 1 || value.mode !== "testnet") throw new Error("unsupported submitter manifest mode");
  if (value.destination !== "xitcoin") throw new Error("only the Xitcoin destination uses this schema");
  if (typeof value.releaseCommit !== "string" || !/^[0-9a-f]{40}$/.test(value.releaseCommit)) throw new Error("release must be an immutable Git commit");
  if (value.xitcoinChainId === XITCOIN_MAINNET_CHAIN_ID) throw new Error("Xitcoin mainnet is not supported in this release");
  if (value.routeId !== XITCOIN_TESTNET_ROUTE_ID || value.cronosChainId !== 338
      || value.xitcoinChainId !== XITCOIN_TESTNET_CHAIN_ID) throw new Error("only the canonical testnet route is supported");
  const paths = [value.relayStorePath, value.ledgerPath, value.keystorePath].map((path) => absolute(path));
  if (new Set(paths).size !== 3) throw new Error("submitter manifest paths must be distinct");
  const xitcoin = exact(value.xitcoin, XITCOIN_DESTINATION_FIELDS);
  const cronos = exact(value.cronos, CRONOS_SOURCE_FIELDS);
  if (xitcoin.chainSchemaCommit !== XITCOIN_CHAIN_SCHEMA_COMMIT) throw new Error("chain schema commit is not the one this release was verified against");
  if (!Array.isArray(xitcoin.authorizedSigners) || xitcoin.authorizedSigners.length !== 3) throw new Error("exactly three authorized signers are required");
  const signers = xitcoin.authorizedSigners.map(checksummed);
  if (new Set(signers.map((item) => item.toLowerCase())).size !== 3) throw new Error("authorized signers must be distinct");
  if (cronos.cronosRouteId !== TESTNET_ROUTE_ID.toLowerCase()) throw new Error("Cronos vault route is not the deployed testnet route");
  const maxGas = decimalString(xitcoin.maxGas, 100_000n, 5_000_000n);
  const maxGasPrice = decimalString(xitcoin.maxGasPrice, 1n, 10n ** 15n);
  const maxFee = decimalString(xitcoin.maxFee, 1n, 10n ** 24n);
  return Object.freeze({
    version: 1, mode: "testnet", destination: "xitcoin", releaseCommit: value.releaseCommit,
    routeId: value.routeId, cronosChainId: 338, xitcoinChainId: value.xitcoinChainId,
    relayStorePath: paths[0], ledgerPath: paths[1], keystorePath: paths[2],
    cycleIntervalMs: integer(value.cycleIntervalMs, 1_000, 60_000),
    xitcoin: Object.freeze({
      origins: xitcoinOrigins(xitcoin.origins, xitcoin.allowLoopbackHttp), allowLoopbackHttp: xitcoin.allowLoopbackHttp,
      chainSchemaCommit: xitcoin.chainSchemaCommit,
      signerSetVersion: decimalString(xitcoin.signerSetVersion, 1n, (1n << 64n) - 1n),
      authorizedSigners: Object.freeze(signers), submitter: bech32Account(xitcoin.submitter),
      // CometBFT commits are final; confirmations add a safety margin on top.
      confirmations: integer(xitcoin.confirmations, 1, 1_000),
      // Every origin must serve state, blocks and the transaction index for
      // at least this many recent blocks.
      historyBlocks: integer(xitcoin.historyBlocks, 1_000, 10_000_000),
      maxAmount: decimalString(xitcoin.maxAmount, 1n, (1n << 256n) - 1n),
      maxGas,
      // Gas limit = ceil(simulated gas * gasAdjustmentPercent / 100) + gasHeadroom.
      gasAdjustmentPercent: integer(xitcoin.gasAdjustmentPercent, 110, 300),
      gasHeadroom: integer(xitcoin.gasHeadroom, 10_000, 1_000_000),
      // Price per gas = ceil(max(base fee, min gas price) * feeMultiplierPercent / 100), in axtc.
      feeMultiplierPercent: integer(xitcoin.feeMultiplierPercent, 100, 1_000),
      maxGasPrice, maxFee,
      minDeadlineMarginSeconds: integer(xitcoin.minDeadlineMarginSeconds, 30, 3_600),
      maxBroadcastAttempts: integer(xitcoin.maxBroadcastAttempts, 1, 32),
    }),
    cronos: Object.freeze({ rpcUrls: urls(cronos.rpcUrls, cronos.allowLoopbackHttp), allowLoopbackHttp: cronos.allowLoopbackHttp,
      vault: checksummed(cronos.vault), cronosRouteId: cronos.cronosRouteId, confirmations: integer(cronos.confirmations, 2, 10_000) }),
  });
}

// Disabled phase-one manifests keep their exact schema; only an explicit
// `testnet` mode selects a transaction-capable schema, chosen by destination.
export function parseSubmitterManifest(input) {
  if (!(input && typeof input === "object" && !Array.isArray(input) && Object.hasOwn(input, "mode")
      && Object.getOwnPropertyDescriptor(input, "mode").value === "testnet")) return validateSubmitterManifest(input);
  const destination = Object.hasOwn(input, "destination") ? Object.getOwnPropertyDescriptor(input, "destination").value : undefined;
  return destination === "xitcoin" ? validateXitcoinTestnetManifest(input) : validateCronosTestnetManifest(input);
}

// Trust root, but never a service-writable ancestor or a symlink in the manifest path.
async function trustedParents(path, stat) {
  let parent = dirname(path);
  while (true) {
    const metadata = await stat(parent);
    if (!metadata.isDirectory() || metadata.uid !== 0 || (metadata.mode & 0o022)) throw new Error("unsafe parent directory");
    if (parent === "/") break;
    parent = dirname(parent);
  }
}

export async function loadSubmitterManifest(path, { openFile = open, stat = lstat } = {}) {
  let handle;
  try {
    absolute(path);
    await trustedParents(path, stat);
    handle = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.uid !== 0 || (metadata.mode & 0o022)
        || metadata.size < 1 || metadata.size > MAX_BYTES) throw new Error("unsafe manifest");
    // Bound the actual read even if a root-owned file changes after fstat.
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (!length || length > MAX_BYTES) throw new Error("invalid manifest size");
    return parseSubmitterManifest(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, length))));
  } catch {
    throw new Error("submitter manifest could not be loaded");
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export async function verifySubmitterRelease(config, modulePath, { resolve = realpath, stat = lstat } = {}) {
  const manifest = parseSubmitterManifest(config);
  const resolved = absolute(await resolve(absolute(modulePath)));
  const expected = `/opt/xitcoin-bridge-relayer/${manifest.releaseCommit}/src/submitter-cli.js`;
  if (resolved !== expected) throw new Error("submitter release does not match its pinned manifest");
  await trustedParents(resolved, stat);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || metadata.uid !== 0 || (metadata.mode & 0o022)) throw new Error("unsafe submitter release");
  return manifest.releaseCommit;
}
