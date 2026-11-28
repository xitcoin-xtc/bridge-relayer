// Local Xitcoin chain harness for integration tests only: a single xitcoind
// validator built from pos-chain, started on loopback ports with the testnet
// chain ID and a bridge route initialised in genesis with synthetic signer
// keys. P2P is bound to 127.0.0.1 with no seeds, peers or peer exchange, so
// the node never joins or contacts a public network.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SigningKey, computeAddress, concat, getBytes, keccak256, toUtf8Bytes } from "ethers";
import { evmAddressToBech32 } from "../../src/address.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "../../src/protocol.js";

export const CHAIN_ID = "xitcoin-testnet-v2-1";
export const ROUTE_ID = XITCOIN_TESTNET_ROUTE_ID;
export const DENOM = "axtc";

// Synthetic local keys only: never fund or use these accounts on a network.
// Keys 1-3 are the bridge signers of test/fixtures/destination.js, key 4 the
// guardian, key 0x100 the submitter of the chain-generated vectors (funded
// first so that its account number is 0, as in the vectors).
export const chainKey = (n) => new SigningKey(`0x${n.toString(16).padStart(64, "0")}`);
export const chainAccount = (key) => evmAddressToBech32(computeAddress(key.publicKey));
export const VECTOR_KEY = chainKey(0x100);
export const VALIDATOR_KEY = chainKey(0x70);
export const THIRD_PARTY_KEY = chainKey(0x71);
export const submitterKey = (index) => chainKey(0x300 + index);

// Integration tests are mandatory in CI; locally they are skipped only when no
// xitcoind binary is configured (XITCOIND_BIN).
export function xitcoindAvailability() {
  const binary = process.env.XITCOIND_BIN;
  if (binary && existsSync(binary)) return { binary, skip: false };
  if (process.env.CI) throw new Error("CI requires XITCOIND_BIN for the Xitcoin chain integration tests");
  return { skip: "xitcoind is not configured (XITCOIND_BIN)" };
}

export async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function run(binary, args, { input } = {}) {
  const result = spawnSync(binary, args, { encoding: "utf8", input, timeout: 120_000 });
  if (result.status !== 0) throw new Error(`xitcoind ${args[0]} ${args[1] ?? ""} failed: ${result.stderr || result.stdout}`);
  return result.stdout;
}

function setToml(text, section, key, value) {
  let current = "", done = false;
  const out = text.split("\n").map((line) => {
    const header = line.match(/^\[([^\]]+)\]\s*$/);
    if (header) current = header[1];
    if (!done && current === section && new RegExp(`^${key}\\s*=`).test(line)) { done = true; return `${key} = ${value}`; }
    return line;
  });
  if (!done) throw new Error(`missing ${section}.${key}`);
  return out.join("\n");
}

export const DEFAULT_ROUTE = Object.freeze({
  maxTransferAmount: (10n ** 22n).toString(),
  dailyLimit: (10n ** 24n).toString(),
  maxOutstandingAmount: (10n ** 25n).toString(),
});

// Starts one validator. `accounts` are funded in genesis in this order, before
// the validator, so the first account has account number 0.
export async function startXitcoinNode({ binary, signers, guardian, accounts = [], paused = false, enabled = true,
  route = DEFAULT_ROUTE, routeId = ROUTE_ID, baseFee = "1000000000", minGasPrice = "0", blockTime = "300ms" }) {
  const home = mkdtempSync(join(tmpdir(), "xitcoind-"));
  const x = (...args) => run(binary, [...args, "--home", home]);
  x("init", "relayer-test", "--chain-id", CHAIN_ID);
  for (const [name, key] of [["validator", VALIDATOR_KEY], ["thirdparty", THIRD_PARTY_KEY]]) {
    run(binary, ["keys", "unsafe-import-eth-key", name, key.privateKey.slice(2), "--keyring-backend", "test", "--home", home],
      { input: "relayer-local-test\nrelayer-local-test\n" });
  }
  const validator = chainAccount(VALIDATOR_KEY);
  const genesisPath = join(home, "config", "genesis.json");
  // Well below the XTC maximum supply, which every mint is checked against.
  for (const account of [...accounts, chainAccount(THIRD_PARTY_KEY)]) x("genesis", "add-genesis-account", account, `${10n ** 24n}${DENOM}`);
  x("genesis", "add-genesis-account", validator, `${10n ** 26n}${DENOM}`);
  let genesis = JSON.parse(readFileSync(genesisPath, "utf8"));
  const app = genesis.app_state;
  app.staking.params.bond_denom = DENOM;
  app.gov.params.min_deposit = [{ denom: DENOM, amount: "10000000" }];
  app.gov.params.expedited_min_deposit = [{ denom: DENOM, amount: "50000000" }];
  app.evm.params.evm_denom = DENOM;
  app.evm.params.extended_denom_options = { extended_denom: DENOM };
  app.mint.params.mint_denom = DENOM;
  app.bank.denom_metadata = [{ description: "Xitcoin", denom_units: [{ denom: DENOM, exponent: 0, aliases: [] },
    { denom: "xtc", exponent: 18, aliases: [] }], base: DENOM, display: "xtc", name: "Xitcoin", symbol: "XTC", uri: "", uri_hash: "" }];
  app.feemarket.params.base_fee = `${baseFee}.000000000000000000`;
  app.feemarket.params.min_gas_price = `${minGasPrice}.000000000000000000`;
  app.bridge = {
    route_config: { route_id: routeId, bridge_signers: signers, guardian, max_transfer_amount: route.maxTransferAmount,
      daily_limit: route.dailyLimit, max_outstanding_amount: route.maxOutstandingAmount, enabled, source_chain_id: "338" },
    paused,
  };
  writeFileSync(genesisPath, JSON.stringify(genesis, null, 2));
  x("genesis", "gentx", "validator", `${10n ** 25n}${DENOM}`, "--chain-id", CHAIN_ID, "--keyring-backend", "test",
    "--gas-prices", `${baseFee}${DENOM}`);
  x("genesis", "collect-gentxs");
  genesis = JSON.parse(readFileSync(genesisPath, "utf8"));
  const valoper = run(binary, ["keys", "show", "validator", "-a", "--bech", "val", "--keyring-backend", "test", "--home", home]).trim();
  genesis.app_state.validator_admission = { authority: validator, approved_validators: [valoper], max_approved_validators: 4,
    minimum_self_delegation: `${10n ** 18n}${DENOM}` };
  writeFileSync(genesisPath, JSON.stringify(genesis, null, 2));
  x("genesis", "validate");

  const ports = { rpc: await freePort(), p2p: await freePort(), api: await freePort(), grpc: await freePort() };
  const configPath = join(home, "config", "config.toml");
  let config = readFileSync(configPath, "utf8");
  config = setToml(config, "rpc", "laddr", `"tcp://127.0.0.1:${ports.rpc}"`);
  config = setToml(config, "rpc", "pprof_laddr", `""`);
  config = setToml(config, "p2p", "laddr", `"tcp://127.0.0.1:${ports.p2p}"`);
  config = setToml(config, "p2p", "seeds", `""`);
  config = setToml(config, "p2p", "persistent_peers", `""`);
  config = setToml(config, "p2p", "pex", "false");
  config = setToml(config, "consensus", "timeout_commit", `"${blockTime}"`);
  config = setToml(config, "consensus", "timeout_propose", `"1s"`);
  writeFileSync(configPath, config);
  const appPath = join(home, "config", "app.toml");
  let appToml = readFileSync(appPath, "utf8");
  appToml = setToml(appToml, "api", "enable", "true");
  appToml = setToml(appToml, "api", "address", `"tcp://127.0.0.1:${ports.api}"`);
  appToml = setToml(appToml, "grpc", "address", `"127.0.0.1:${ports.grpc}"`);
  appToml = setToml(appToml, "", "minimum-gas-prices", `"0${DENOM}"`);
  writeFileSync(appPath, appToml);

  const child = spawn(binary, ["start", "--home", home, "--chain-id", CHAIN_ID, "--log_level", "error", "--pruning", "nothing",
    "--json-rpc.enable=false"], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr = (stderr + chunk).slice(-8_000); });
  const node = {
    home, binary, validator,
    rpcUrl: `http://127.0.0.1:${ports.rpc}`,
    restUrl: `http://127.0.0.1:${ports.api}`,
    get log() { return stderr; },
    async rpc(method, params = {}) {
      const response = await fetch(node.rpcUrl, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
      const body = await response.json();
      if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
      return body.result;
    },
    async rest(path) {
      const response = await fetch(`${node.restUrl}${path}`);
      return { status: response.status, body: await response.json().catch(() => null) };
    },
    async height() { return Number((await node.rpc("status")).sync_info.latest_block_height); },
    async waitHeight(height, timeoutMs = 60_000) {
      const end = Date.now() + timeoutMs;
      while (Date.now() < end) {
        try { if (await node.height() >= height) return; } catch { /* starting */ }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error(`xitcoind did not reach height ${height}: ${stderr}`);
    },
    async blocks(count) { await node.waitHeight(await node.height() + count); },
    async sequence(account) {
      const { status, body } = await node.rest(`/cosmos/auth/v1beta1/accounts/${account}`);
      return status === 200 ? Number(body.account.sequence) : 0;
    },
    async balance(account) {
      return BigInt((await node.rest(`/cosmos/bank/v1beta1/balances/${account}/by_denom?denom=${DENOM}`)).body.balance.amount);
    },
    async attestation(id) { return (await node.rest(`/xitcoin/bridge/v1/attestations/${id}`)).body; },
    async route() { return (await node.rest(`/xitcoin/bridge/v1/routes/${routeId}`)).body.route; },
    async broadcast(signedHex) {
      return node.rpc("broadcast_tx_sync", { tx: Buffer.from(signedHex.slice(2), "hex").toString("base64") });
    },
    async committed(hash, timeoutMs = 30_000) {
      const end = Date.now() + timeoutMs;
      while (Date.now() < end) {
        const result = await node.rpc("tx_search", { query: `tx.hash='${hash.slice(2).toUpperCase()}'`, prove: false });
        if (result.txs.length) return result.txs[0];
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      throw new Error("transaction not committed");
    },
    // A bridge control transaction signed by the third-party key through the CLI.
    bridgeTx(args) {
      const out = run(binary, ["tx", "bridge", ...args, "--from", "thirdparty", "--keyring-backend", "test", "--chain-id", CHAIN_ID,
        "--node", `tcp://127.0.0.1:${ports.rpc}`, "--gas", "400000", "--fees", `${400000n * 4_000_000_000n}${DENOM}`, "-y", "-o", "json",
        "--home", home]);
      const result = JSON.parse(out);
      if (result.code !== 0) throw new Error(`bridge tx rejected: ${result.raw_log}`);
      return `0x${result.txhash.toLowerCase()}`;
    },
    stop() {
      return new Promise((resolve) => {
        const done = () => { rmSync(home, { recursive: true, force: true }); resolve(); };
        if (child.exitCode !== null) return done();
        child.once("exit", done);
        child.kill("SIGKILL");
      });
    },
  };
  try {
    await node.waitHeight(2);
    for (let i = 0; i < 300; i++) {
      try { if ((await node.rest("/xitcoin/bridge/v1/params")).status === 200) break; } catch { /* starting */ }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  } catch (error) {
    await node.stop();
    throw error;
  }
  return node;
}

const sha256 = (text) => createHash("sha256").update(text).digest();

// Guardian pause and 2-of-3 resume signatures (pos-chain x/bridge/types
// pause.go and control.go; the resume payload hash is keeper.RouteStatePayloadHash).
export function guardianPauseSignature(key, { nonce, expiresUnix, routeId = ROUTE_ID }) {
  const domain = `xitcoin-bridge-guardian-pause-v2/${CHAIN_ID}`;
  const id = sha256([domain, routeId, String(nonce), String(expiresUnix)].join("\0"));
  return key.sign(keccak256(concat([toUtf8Bytes(domain), id]))).serialized;
}
export function resumeSignatures(keys, { route, nonce, notBeforeUnix, expiresUnix }) {
  const config = { route_id: route.route_id, bridge_signers: route.bridge_signers, guardian: route.guardian,
    max_transfer_amount: route.max_transfer_amount, daily_limit: route.daily_limit, max_outstanding_amount: route.max_outstanding_amount,
    enabled: route.enabled, source_chain_id: route.source_chain_id };
  const payloadHash = `0x${sha256(JSON.stringify({ config, state: { paused: false } })).toString("hex")}`;
  const domain = `xitcoin-bridge-control-v2/${CHAIN_ID}`;
  const id = sha256([domain, route.route_id, "resume_route", payloadHash, String(nonce), String(notBeforeUnix), String(expiresUnix)].join("\0"));
  const digest = keccak256(concat([toUtf8Bytes(domain), getBytes(`0x${id.toString("hex")}`)]));
  return keys.map((key) => key.sign(digest).serialized);
}

// One independent origin in front of the node (a CometBFT RPC proxy and a REST
// proxy on their own ports). `hook({ kind, method, path, body, forward })` may
// rewrite (return text), drop (throw) or pass (return forward()).
export async function startXitcoinOrigin(node) {
  const origin = { hook: null, calls: [] };
  async function serve(kind, target, port) {
    const server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => { body += chunk; });
      request.on("end", async () => {
        const method = kind === "rpc" && body ? (() => { try { return JSON.parse(body).method; } catch { return null; } })() : null;
        const path = request.url;
        origin.calls.push(kind === "rpc" ? method : path);
        const forward = async () => {
          const headers = { "content-type": "application/json" };
          if (request.headers["x-cosmos-block-height"]) headers["x-cosmos-block-height"] = request.headers["x-cosmos-block-height"];
          const upstream = await fetch(`${target}${kind === "rest" ? path : ""}`, { method: request.method, headers,
            body: request.method === "POST" ? body : undefined });
          return { status: upstream.status, text: await upstream.text() };
        };
        try {
          const result = origin.hook ? await origin.hook({ kind, method, path, body, forward }) : await forward();
          if (result === undefined) return;
          const { status, text } = typeof result === "string" ? { status: 200, text: result } : result;
          response.writeHead(status, { "content-type": "application/json" }).end(text);
        } catch { response.destroy(); }
      });
    });
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    return server;
  }
  const rpcPort = await freePort(), restPort = await freePort();
  const servers = [await serve("rpc", node.rpcUrl, rpcPort), await serve("rest", node.restUrl, restPort)];
  origin.rpcUrl = `http://127.0.0.1:${rpcPort}`;
  origin.restUrl = `http://127.0.0.1:${restPort}`;
  origin.stop = () => Promise.all(servers.map((server) => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); })));
  return origin;
}

export function rewriteJson(text, transform) {
  return JSON.stringify(transform(JSON.parse(text)));
}
