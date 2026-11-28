// Local EVM harness for integration tests only: anvil, two fault-injecting
// JSON-RPC origins in front of it, fake CometBFT origins for Xitcoin source
// finality, and the vendored reviewed vault. Never points at a real network.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ContractFactory, JsonRpcProvider, SigningKey, Transaction, Wallet, computeAddress, id, TypedDataEncoder } from "ethers";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("../../", import.meta.url));

export function foundryTool(name) {
  const directories = [...String(process.env.PATH ?? "").split(delimiter).filter(Boolean), join(homedir(), ".foundry", "bin")];
  return directories.map((directory) => join(directory, name)).find((path) => existsSync(path)) ?? null;
}

// Integration tests are mandatory in CI; locally they are skipped only when
// the Foundry toolchain is not installed.
export function evmAvailability() {
  const anvil = foundryTool("anvil"), forge = foundryTool("forge");
  if (anvil && forge) return { anvil, forge, skip: false };
  if (process.env.CI) throw new Error("CI requires anvil and forge for the Cronos EVM integration tests");
  return { skip: "Foundry (anvil, forge) is not installed" };
}

export function gitBlob(path) {
  const body = readFileSync(path);
  return createHash("sha1").update(`blob ${body.length}\0`).update(body).digest("hex");
}

const compiled = new Map();
export function compile(forge, folder) {
  if (compiled.has(folder)) return compiled.get(folder);
  const work = mkdtempSync(join(tmpdir(), "relayer-forge-"));
  try {
    const result = spawnSync(forge, ["build", "--root", work, "--contracts", join(here, folder), "--out", join(work, "out"),
      "--cache-path", join(work, "cache"), "--use", "0.8.30", "--optimize", "--optimizer-runs", "200", "--evm-version", "paris",
      "--remappings", `@openzeppelin/=${join(root, "node_modules", "@openzeppelin")}/`], { encoding: "utf8", timeout: 240_000 });
    if (result.status !== 0) throw new Error(`forge build failed: ${result.stderr}`);
    const artifacts = {};
    for (const name of ["CronosBridgeVault", "MockERC20"]) {
      const path = join(work, "out", `${name}.sol`, `${name}.json`);
      if (existsSync(path)) {
        const artifact = JSON.parse(readFileSync(path, "utf8"));
        artifacts[name] = { abi: artifact.abi, bytecode: artifact.bytecode.object };
      }
    }
    compiled.set(folder, artifacts);
    return artifacts;
  } finally { rmSync(work, { recursive: true, force: true }); }
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

export async function rpcCall(url, method, params = []) {
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

export async function startAnvil(anvil, { chainId = 338 } = {}) {
  const port = await freePort();
  const child = spawn(anvil, ["--chain-id", String(chainId), "--port", String(port), "--host", "127.0.0.1", "--silent",
    "--accounts", "1"], { stdio: "ignore" });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    try { await rpcCall(url, "eth_chainId"); break; } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
    if (i === 99) throw new Error("anvil did not start");
  }
  return { url, rpc: (method, params) => rpcCall(url, method, params),
    stop: () => new Promise((resolve) => { child.once("exit", resolve); child.kill("SIGKILL"); }) };
}

// Each proxy is an independent origin. `hook` may rewrite, stall or drop a call.
export async function startProxy(target) {
  const proxy = { hook: null, calls: [] };
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", async () => {
      const message = JSON.parse(body);
      proxy.calls.push(message.method);
      const forward = async () => (await fetch(target, { method: "POST", headers: { "content-type": "application/json" }, body })).text();
      try {
        const result = proxy.hook ? await proxy.hook({ message, forward, request, response }) : await forward();
        if (result === undefined) return;
        response.writeHead(200, { "content-type": "application/json" }).end(result);
      } catch { response.destroy(); }
    });
  });
  const port = await freePort();
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  proxy.url = `http://127.0.0.1:${port}`;
  proxy.stop = () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); });
  return proxy;
}

export function rewriteResult(text, transform) {
  const body = JSON.parse(text);
  body.result = transform(body.result);
  return JSON.stringify(body);
}

// Minimal CometBFT surface used by XitcoinFinalizedWatcher for one finalized burn.
export async function startCometBft(burns, { chainId = "xitcoin-testnet-v2-1", latest = 100 } = {}) {
  const block = (height) => burns.filter((burn) => burn.height === height);
  const event = (burn) => ({ type: "bridge_outbound_burned", attributes: [
    ["request_id", burn.requestId], ["route_id", "cronos-testnet-xitcoin-testnet"], ["sender", "xtc1sender"],
    ["destination", burn.recipient], ["amount", burn.amount], ["nonce", burn.nonce], ["msg_index", "0"],
  ].map(([key, value]) => ({ key, value })) });
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://localhost");
    const height = Number(url.searchParams.get("height"));
    let result;
    if (url.pathname === "/status") result = { node_info: { network: chainId }, sync_info: { latest_block_height: String(latest), catching_up: false } };
    else if (url.pathname === "/block") result = { block: { header: { height: String(height) }, data: { txs: block(height).map((burn) => burn.txBase64) } },
      block_id: { hash: blockHash(height).slice(2).toUpperCase() } };
    else if (url.pathname === "/block_results") result = { height: String(height), txs_results: block(height).map((burn) => ({ code: 0, events: [event(burn)] })) };
    else if (url.pathname === "/tx") {
      const burn = burns.find((item) => item.transactionHash === url.searchParams.get("hash"));
      result = burn && { height: String(burn.height), tx_result: { code: 0, events: [event(burn)] } };
    }
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(result ? { jsonrpc: "2.0", id: -1, result } : { jsonrpc: "2.0", id: -1, error: { message: "not found" } }));
  });
  const port = await freePort();
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${port}`, stop: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }) };
}
export const blockHash = (height) => `0x${createHash("sha256").update(`xitcoin block ${height}`).digest("hex")}`;
export function xitcoinBurn({ index, recipient, amount, height = 50 }) {
  const tx = Buffer.from(`synthetic xitcoin burn ${index}`);
  return { requestId: `0x${createHash("sha256").update(`burn ${index}`).digest("hex")}`, recipient, amount, nonce: String(index), height,
    txBase64: tx.toString("base64"), transactionHash: `0x${createHash("sha256").update(tx).digest("hex")}` };
}

// Synthetic local keys only: never fund or use these accounts on a network.
export const localKeys = Object.freeze({
  deployer: new SigningKey(`0x${"06".padStart(64, "0")}`), submitter: new SigningKey(`0x${"05".padStart(64, "0")}`),
  guardian: new SigningKey(`0x${"04".padStart(64, "0")}`),
});
export const localAddress = (key) => computeAddress(key.publicKey);

export async function deployBridge(chain, artifacts, { routeId, signers, version = "testnet", liquidity = 10n ** 21n,
  maxRelease = 10n ** 20n, dailyLimit = 5n * 10n ** 20n }) {
  const provider = new JsonRpcProvider(chain.url, undefined, { staticNetwork: true, cacheTimeout: -1 });
  for (const key of Object.values(localKeys)) await chain.rpc("anvil_setBalance", [localAddress(key), "0x56bc75e2d63100000"]);
  const deployer = new Wallet(localKeys.deployer.privateKey, provider);
  const token = await new ContractFactory(artifacts.token.abi, artifacts.token.bytecode, deployer).deploy("Test XTC", "tXTC");
  await token.waitForDeployment();
  const args = [await token.getAddress(), routeId, signers, localAddress(localKeys.guardian), maxRelease, dailyLimit];
  if (version === "main") args.push(maxRelease, dailyLimit, liquidity * 2n);
  args.push(false);
  const vault = await new ContractFactory(artifacts.vault.abi, artifacts.vault.bytecode, deployer).deploy(...args);
  await vault.waitForDeployment();
  await (await token.mint(await vault.getAddress(), liquidity)).wait();
  provider.destroy();
  return { token: await token.getAddress(), vault: await vault.getAddress(), vaultAbi: artifacts.vault.abi, tokenAbi: artifacts.token.abi };
}

export async function signedCall(chain, key, { to, data, gasPrice = 2_000_000_000n, gasLimit = 300_000n, nonce } = {}) {
  const from = localAddress(key);
  const tx = Transaction.from({ type: 0, chainId: Number(await chain.rpc("eth_chainId")), to, data, value: 0,
    nonce: nonce ?? Number(await chain.rpc("eth_getTransactionCount", [from, "pending"])), gasLimit, gasPrice });
  tx.signature = key.sign(tx.unsignedHash);
  return tx.serialized;
}

export function controlSignatures({ vault, chainId = 338, action, payloadHash, nonce, signerSetVersion = 1, deadline, keys }) {
  const digest = TypedDataEncoder.hash({ name: "Xitcoin Cronos Bridge Vault", version: "1", chainId, verifyingContract: vault },
    { Control: [{ name: "action", type: "bytes32" }, { name: "payloadHash", type: "bytes32" }, { name: "nonce", type: "uint256" },
      { name: "signerSetVersion", type: "uint64" }, { name: "deadline", type: "uint256" }] },
    { action: id(action), payloadHash, nonce, signerSetVersion, deadline });
  return keys.map((key) => key.sign(digest).serialized);
}
