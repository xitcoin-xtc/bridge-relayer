import assert from "node:assert/strict";
import { constants } from "node:fs";
import { mkdtemp, writeFile, symlink, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { loadSubmitterManifest, validateSubmitterManifest, verifySubmitterRelease } from "../src/submitter-manifest.js";
import { buildSubmitterRuntime, inspectSubmitter } from "../src/submitter-bootstrap.js";
import { runSubmitterCli } from "../src/submitter-cli.js";
import { XITCOIN_TESTNET_ROUTE_ID } from "../src/protocol.js";
import { XITCOIN_CHAIN_SCHEMA_COMMIT } from "../src/xitcoin-transaction.js";

const manifest = (destination = "xitcoin") => ({ version: 1, mode: "disabled", destination,
  releaseCommit: "a".repeat(40), routeId: XITCOIN_TESTNET_ROUTE_ID, cronosChainId: 338, xitcoinChainId: "xitcoin-testnet-v2-1" });
const modulePath = `/opt/xitcoin-bridge-relayer/${"a".repeat(40)}/src/submitter-cli.js`;
const metadata = (overrides = {}) => ({ uid: 0, mode: 0o100644, size: 300, isFile: () => true, isDirectory: () => true, ...overrides });
const trustedStat = async () => metadata();

function reader(body = JSON.stringify(manifest()), properties = {}, { readError = false, chunk = 31 } = {}) {
  const bytes = Buffer.from(body);
  let offset = 0;
  const calls = { closed: 0, reads: 0, flags: undefined };
  return { calls, dependencies: { stat: trustedStat, openFile: async (_path, flags) => {
    calls.flags = flags;
    return { stat: async () => metadata({ size: bytes.length, ...properties }),
      read: async (buffer, start, length) => {
        calls.reads++;
        if (readError) throw new Error("sensitive internal detail");
        const count = Math.min(length, chunk, bytes.length - offset);
        bytes.copy(buffer, start, offset, offset + count); offset += count;
        return { bytesRead: count };
      }, close: async () => { calls.closed++; } };
  } } };
}

for (const destination of ["xitcoin", "cronos"]) {
  test(`${destination}: accepts a frozen disabled canonical manifest`, () => {
    const input = manifest(destination);
    const result = validateSubmitterManifest(input);
    input.mode = "live";
    assert.equal(result.mode, "disabled");
    assert.ok(Object.isFrozen(result));
  });
  test(`${destination}: inspection is explicitly unready and startup always refuses`, async () => {
    const options = { destination, manifestPath: "/etc/xitcoin-bridge/submitter.json", modulePath };
    const dependencies = { loadManifest: async () => manifest(destination),
      verifyRelease: (config, path) => verifySubmitterRelease(config, path, { resolve: async (x) => x, stat: trustedStat }) };
    const first = await inspectSubmitter(options, dependencies);
    assert.equal(first.ready, false);
    assert.equal(first.submissions, 0);
    assert.match(first.blocker, new RegExp(`^${destination}_`));
    assert.deepEqual(await inspectSubmitter(options, dependencies), first);
    for (let i = 0; i < 2; i++) await assert.rejects(buildSubmitterRuntime(options, dependencies), { code: "SUBMITTER_UNAVAILABLE" });
    await assert.rejects(inspectSubmitter({ ...options, destination: destination === "xitcoin" ? "cronos" : "xitcoin" }, dependencies), /does not match/);
  });
}

test("rejects unknown/missing fields, coercion, aliases, mainnet and moving releases", () => {
  const invalid = [null, [], {}, ...Object.keys(manifest()).map((field) => {
    const value = manifest(); delete value[field]; return value;
  }), ...[
    { version: "1" }, { mode: "submit" }, { mode: "dry_run" }, { destination: "Cronos" },
    { destination: "ethereum" }, { destination: "xitcoin-mainnet" }, { cronosChainId: 25 },
    { cronosChainId: "338" }, { xitcoinChainId: "xitcoin-mainnet" }, { routeId: "other" },
    { releaseCommit: "main" }, { releaseCommit: "A".repeat(40) }, { releaseCommit: "a".repeat(39) },
    { rpcUrls: [] }, { credentials: {} }, { adapter: "private.mjs" }, { statePath: "/tmp/state" },
  ].map((patch) => ({ ...manifest(), ...patch }))];
  for (const input of invalid) assert.throws(() => validateSubmitterManifest(input));
});

test("root manifest loader bounds reads, rejects symlinks, and closes the descriptor", async () => {
  const { calls, dependencies } = reader();
  assert.deepEqual(await loadSubmitterManifest("/etc/bridge/submitter.json", dependencies), manifest());
  assert.equal(calls.closed, 1);
  assert.ok(calls.reads > 1);
  assert.ok(calls.flags & constants.O_NOFOLLOW);
  assert.ok(calls.flags & constants.O_NONBLOCK);
});

test("rejects unsafe metadata before reading and sanitizes every failure", async () => {
  for (const properties of [{ uid: 1000 }, { mode: 0o100664 }, { mode: 0o100646 },
    { isFile: () => false }, { size: 0 }, { size: 16_385 }]) {
    const { calls, dependencies } = reader(undefined, properties);
    await assert.rejects(loadSubmitterManifest("/etc/bridge/submitter.json", dependencies), { message: "submitter manifest could not be loaded" });
    assert.equal(calls.reads, 0);
    assert.equal(calls.closed, 1);
  }
  for (const body of ["{invalid", "null", Buffer.from([0xff]), " ".repeat(16_385)]) {
    const { calls, dependencies } = reader(body, { size: 1 });
    await assert.rejects(loadSubmitterManifest("/etc/bridge/submitter.json", dependencies), /could not be loaded/);
    assert.equal(calls.closed, 1);
  }
  const { calls, dependencies } = reader(undefined, {}, { readError: true });
  await assert.rejects(loadSubmitterManifest("/etc/bridge/submitter.json", dependencies), { message: "submitter manifest could not be loaded" });
  assert.equal(calls.closed, 1);
});

test("rejects relative, unnormalized and untrusted ancestor paths before opening", async () => {
  for (const path of ["relative.json", "/etc/../tmp/config", "/etc//config", "/etc/./config", "/etc/config\0"]) {
    await assert.rejects(loadSubmitterManifest(path, { openFile: () => assert.fail("opened"), stat: trustedStat }));
  }
  for (const properties of [{ uid: 1000 }, { mode: 0o40777 }, { isDirectory: () => false }]) {
    await assert.rejects(loadSubmitterManifest("/etc/bridge/config", {
      openFile: () => assert.fail("opened"), stat: async () => metadata(properties),
    }));
  }
});

test("real filesystem rejects a symlink manifest and a writable parent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "submitter-test-"));
  try {
    const path = join(directory, "manifest.json");
    await writeFile(path, JSON.stringify(manifest()));
    await symlink(path, join(directory, "link.json"));
    await assert.rejects(loadSubmitterManifest(join(directory, "link.json"), { stat: trustedStat }));
    await assert.rejects(loadSubmitterManifest(path)); // /tmp is writable, even for a root-owned fixture.
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("release resolves current to the pinned root-owned immutable layout", async () => {
  assert.equal(await verifySubmitterRelease(manifest(), "/opt/xitcoin-bridge-relayer/current/src/submitter-cli.js", {
    resolve: async () => modulePath, stat: trustedStat,
  }), manifest().releaseCommit);
  for (const path of [modulePath.replace("a".repeat(40), "b".repeat(40)),
    modulePath.replace("a".repeat(40), "current"), modulePath.replace("/opt/", "/tmp/"),
    modulePath.replace("submitter-cli.js", "other.js")]) {
    await assert.rejects(verifySubmitterRelease(manifest(), path, { resolve: async (x) => x, stat: trustedStat }));
  }
  for (const properties of [{ uid: 1000 }, { mode: 0o100666 }, { isFile: () => false }]) {
    await assert.rejects(verifySubmitterRelease(manifest(), modulePath, {
      resolve: async (x) => x, stat: async (path) => path === modulePath ? metadata(properties) : metadata(),
    }));
  }
  await assert.rejects(verifySubmitterRelease(manifest(), modulePath, {
    resolve: async (x) => x, stat: async () => metadata({ mode: 0o40777 }),
  }));
});

test("CLI checks are distinct from startup and failures disclose no supplied input", async () => {
  let output = "", errors = "", builds = 0;
  const dependencies = { stdout: { write: (x) => { output += x; } }, stderr: { write: (x) => { errors += x; } },
    inspect: async () => ({ ready: false, submissions: 0 }), build: async () => { builds++; throw new Error("sensitive detail"); } };
  assert.equal(await runSubmitterCli(["check", "cronos", "/etc/config"], dependencies), 0);
  assert.deepEqual(JSON.parse(output), { ready: false, submissions: 0 });
  assert.equal(builds, 0);
  assert.equal(await runSubmitterCli(["start", "cronos", "/etc/config"], dependencies), 1);
  assert.equal(builds, 1);
  for (const args of [[], ["check", "mainnet", "/secret/path"], ["start", "cronos", "/etc/config", "extra"]]) {
    assert.equal(await runSubmitterCli(args, dependencies), 1);
  }
  assert.doesNotMatch(errors, /sensitive detail|secret\/path/);
});

test("public CLI executes both directly and via a release-style symlink", async () => {
  const directory = await mkdtemp(join(tmpdir(), "submitter-cli-"));
  try {
    const cli = new URL("../src/submitter-cli.js", import.meta.url);
    const linked = join(directory, "submitter.mjs");
    await symlink(cli, linked);
    for (const path of [cli.pathname, linked]) {
      const result = spawnSync(process.execPath, [path, "start", "cronos", "/nonexistent/manifest.json"], { encoding: "utf8" });
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /submitter stopped/);
      assert.doesNotMatch(result.stderr, /nonexistent/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("systemd phase one uses public CLI, denies networking and does not restart", async () => {
  const unit = await readFile(new URL("../ops/systemd/xitcoin-bridge-submitter@.service", import.meta.url), "utf8");
  assert.match(unit, /src\/submitter-cli.js start %i \/etc\/xitcoin-bridge\/submitter-%i.json/);
  assert.match(unit, /^Restart=no$/m);
  assert.match(unit, /^IPAddressDeny=any$/m);
  assert.match(unit, /^LimitCORE=0$/m);
  assert.doesNotMatch(unit, /LoadCredential|ReadWritePaths|submitter.mjs/);
});


test("manifest traversal rejects higher unsafe ancestors after a trusted parent", async () => {
  for (const ancestor of ["/etc", "/"]) {
    for (const properties of [{ uid: 1000 }, { mode: 0o40775 }, { mode: 0o40757 },
      { isDirectory: () => false, isSymbolicLink: () => true }]) {
      const visited = [];
      await assert.rejects(loadSubmitterManifest("/etc/bridge/config", {
        openFile: () => assert.fail("opened before ancestor validation"),
        stat: async (path) => { visited.push(path); return metadata(path === ancestor ? properties : {}); },
      }), { message: "submitter manifest could not be loaded" });
      assert.deepEqual(visited, ancestor === "/etc" ? ["/etc/bridge", "/etc"] : ["/etc/bridge", "/etc", "/"]);
    }
  }
});

test("release traversal rejects every higher unsafe ancestor after a trusted src parent", async () => {
  const parents = [modulePath.slice(0, -"/submitter-cli.js".length),
    `/opt/xitcoin-bridge-relayer/${"a".repeat(40)}`, "/opt/xitcoin-bridge-relayer", "/opt", "/"];
  for (const ancestor of parents.slice(1)) {
    for (const properties of [{ uid: 1000 }, { mode: 0o40775 }, { mode: 0o40757 },
      { isDirectory: () => false, isSymbolicLink: () => true }]) {
      const visited = [];
      await assert.rejects(verifySubmitterRelease(manifest(), modulePath, {
        resolve: async (path) => path,
        stat: async (path) => { visited.push(path); return metadata(path === ancestor ? properties : {}); },
      }), /unsafe parent directory/);
      assert.deepEqual(visited, parents.slice(0, parents.indexOf(ancestor) + 1));
    }
  }
});

// Cronos testnet submission mode.
const testnetSigners = ["0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF",
  "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"];
const testnet = (patch = {}, cronosPatch = {}, xitcoinPatch = {}) => ({ version: 1, mode: "testnet", destination: "cronos",
  releaseCommit: "a".repeat(40), routeId: XITCOIN_TESTNET_ROUTE_ID, cronosChainId: 338, xitcoinChainId: "xitcoin-testnet-v2-1",
  relayStorePath: "/var/lib/xitcoin-bridge/coordinator/relay.sqlite", ledgerPath: "/var/lib/xitcoin-bridge/submitter-cronos/ledger.sqlite",
  keystorePath: "/var/lib/xitcoin-bridge/submitter-cronos-keystore/keystore.json", cycleIntervalMs: 5000,
  cronos: { rpcUrls: ["https://cronos-a.example/rpc", "https://cronos-b.example/rpc"], allowLoopbackHttp: false,
    vault: "0x1c94273C0b199b139D82da3786C9eCbE189D5919", vaultCodeHash: `0x${"ab".repeat(32)}`,
    cronosRouteId: "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9", signerSetVersion: "1",
    authorizedSigners: [...testnetSigners], submitter: "0xe1AB8145F7E55DC933d51a18c793F901A3A0b276", confirmations: 12,
    maxAmount: "100000000000000000000", gasLimit: "400000", maxGasPrice: "5000000000000", maxFee: "2000000000000000000",
    minDeadlineMarginSeconds: 120, maxBroadcastAttempts: 5,
    releaseLookbackBlocks: 50_000, logRangeBlocks: 2_000, ...cronosPatch },
  xitcoin: { rpcUrls: ["https://xitcoin-a.example", "https://xitcoin-b.example"], allowLoopbackHttp: false, safetyLag: 2, ...xitcoinPatch },
  ...patch });

test("Cronos testnet mode requires every pinned value and rejects mainnet, Xitcoin and coercion", async () => {
  const { validateCronosTestnetManifest, parseSubmitterManifest } = await import("../src/submitter-manifest.js");
  const accepted = validateCronosTestnetManifest(testnet());
  assert.ok(Object.isFrozen(accepted) && Object.isFrozen(accepted.cronos) && Object.isFrozen(accepted.cronos.authorizedSigners));
  assert.deepEqual(parseSubmitterManifest(testnet()), accepted);
  assert.deepEqual(parseSubmitterManifest(manifest("cronos")), validateSubmitterManifest(manifest("cronos")));
  assert.equal(validateCronosTestnetManifest(testnet({}, { rpcUrls: ["http://127.0.0.1:8545", "http://127.0.0.1:8546"], allowLoopbackHttp: true })).cronos.allowLoopbackHttp, true);
  const top = [{ destination: "xitcoin" }, { mode: "live" }, { mode: "disabled" }, { cronosChainId: 25 }, { cronosChainId: "338" },
    { version: 2 }, { routeId: "other" }, { xitcoinChainId: "xitcoin" }, { releaseCommit: "main" }, { cycleIntervalMs: 999 },
    { cycleIntervalMs: 60_001 }, { relayStorePath: "relative.sqlite" }, { ledgerPath: "/var/lib/a/../b" },
    { keystorePath: "/var/lib/xitcoin-bridge/coordinator/relay.sqlite" }, { extra: true }, { password: "x" }];
  const cronos = [{ chainId: 25 }, { rpcUrls: ["https://a.example"] }, { rpcUrls: ["https://a.example/x", "https://a.example/y"] },
    { rpcUrls: ["http://cronos-a.example", "https://cronos-b.example"] }, { rpcUrls: ["https://k:s@a.example", "https://b.example"] },
    { rpcUrls: ["https://a.example/?key=1", "https://b.example"] }, { rpcUrls: ["http://127.0.0.1:1", "http://127.0.0.1:2"] },
    { allowLoopbackHttp: "true" }, { vault: "0x1c94273c0b199b139d82da3786c9ecbe189d5919" }, { vault: "0x000000000000000000000000000000000000dEaD" },
    { vaultCodeHash: `0x${"0".repeat(64)}` }, { vaultCodeHash: "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
    { vaultCodeHash: `0x${"AB".repeat(32)}` }, { cronosRouteId: "0xb9ae829d654d824b9046d969c96822a479b9eac3488642b4092928d65e07df5b" },
    { signerSetVersion: 1 }, { signerSetVersion: "0" }, { signerSetVersion: "18446744073709551616" },
    { authorizedSigners: testnetSigners.slice(0, 2) }, { authorizedSigners: [testnetSigners[0], testnetSigners[0], testnetSigners[1]] },
    { submitter: testnetSigners[0] }, { submitter: "0x1c94273C0b199b139D82da3786C9eCbE189D5919" }, { confirmations: 1 },
    { confirmations: 10_001 }, { maxAmount: "0" }, { maxAmount: 1 }, { gasLimit: "20999" }, { gasLimit: "10000001" },
    { maxGasPrice: "0" }, { maxGasPrice: "10000000000001" }, { maxFee: "1" }, { minDeadlineMarginSeconds: 29 },
    { minDeadlineMarginSeconds: 3_601 }, { maxBroadcastAttempts: 0 }, { maxBroadcastAttempts: 33 }, { extra: 1 }, { privateKey: "0x1" },
    { releaseLookbackBlocks: 999 }, { releaseLookbackBlocks: 1_000_001 }, { logRangeBlocks: 99 }, { logRangeBlocks: 10_001 },
    { logRangeBlocks: "2000" }];
  const xitcoin = [{ rpcUrls: ["https://x.example"] }, { safetyLag: -1 }, { safetyLag: 1_001 }, { allowLoopbackHttp: 1 }, { extra: 1 }];
  for (const patch of top) assert.throws(() => validateCronosTestnetManifest(testnet(patch)), undefined, JSON.stringify(patch));
  for (const patch of cronos) assert.throws(() => validateCronosTestnetManifest(testnet({}, patch)), undefined, JSON.stringify(patch));
  for (const patch of xitcoin) assert.throws(() => validateCronosTestnetManifest(testnet({}, {}, patch)), undefined, JSON.stringify(patch));
  for (const field of Object.keys(testnet())) {
    const value = testnet(); delete value[field];
    assert.throws(() => validateCronosTestnetManifest(value));
  }
  let touched = false;
  const getter = testnet();
  Object.defineProperty(getter.cronos, "vault", { enumerable: true, get() { touched = true; return testnetSigners[0]; } });
  assert.throws(() => validateCronosTestnetManifest(getter));
  assert.equal(touched, false);
  // Disabled phase-one validation keeps rejecting every testnet-only field.
  assert.throws(() => validateSubmitterManifest(testnet()));
});

test("testnet inspection is offline and unready; a Cronos testnet manifest builds the Cronos runtime", async () => {
  const options = { destination: "cronos", manifestPath: "/etc/xitcoin-bridge/submitter-cronos.json", modulePath, credentialsDirectory: "/run/credentials/x" };
  const verifyRelease = (config, path) => verifySubmitterRelease(config, path, { resolve: async (x) => x, stat: trustedStat });
  const report = await inspectSubmitter(options, { loadManifest: async () => testnet(), verifyRelease });
  assert.deepEqual(report, { version: 1, destination: "cronos", releaseCommit: "a".repeat(40), mode: "testnet", ready: false,
    submissions: 0, blocker: "cronos_live_checks_run_only_at_start" });
  let built;
  const runtime = await buildSubmitterRuntime(options, { loadManifest: async () => testnet(), verifyRelease,
    buildCronos: async (config, dependencies) => { built = { config, dependencies }; return { run: async () => {} }; } });
  assert.equal(typeof runtime.run, "function");
  assert.equal(built.config.mode, "testnet"); assert.equal(built.dependencies.credentialsDirectory, "/run/credentials/x");
  await assert.rejects(buildSubmitterRuntime(options, { loadManifest: async () => manifest("cronos"), verifyRelease,
    buildCronos: () => assert.fail("disabled manifest must not build") }), { code: "SUBMITTER_UNAVAILABLE" });
  await assert.rejects(buildSubmitterRuntime({ ...options, destination: "xitcoin" }, { loadManifest: async () => testnet(), verifyRelease,
    buildCronos: () => assert.fail("destination mismatch must not build") }), /does not match/);
  await assert.rejects(buildSubmitterRuntime(options, { loadManifest: async () => testnet({ releaseCommit: "b".repeat(40) }), verifyRelease,
    buildCronos: () => assert.fail("release mismatch must not build") }), /does not match its pinned manifest/);
  const { calls, dependencies } = reader(JSON.stringify(testnet()));
  assert.equal((await loadSubmitterManifest("/etc/bridge/submitter.json", dependencies)).mode, "testnet");
  assert.equal(calls.closed, 1);
});

// Xitcoin testnet submission mode.
const xitcoinTestnet = (patch = {}, xitcoinPatch = {}, cronosPatch = {}) => ({ version: 1, mode: "testnet", destination: "xitcoin",
  releaseCommit: "a".repeat(40), routeId: XITCOIN_TESTNET_ROUTE_ID, cronosChainId: 338, xitcoinChainId: "xitcoin-testnet-v2-1",
  relayStorePath: "/var/lib/xitcoin-bridge/coordinator/relay.sqlite", ledgerPath: "/var/lib/xitcoin-bridge/submitter-xitcoin/ledger.sqlite",
  keystorePath: "/var/lib/xitcoin-bridge/submitter-xitcoin-keystore/keystore.json", cycleIntervalMs: 5000,
  xitcoin: { origins: [{ rpcUrl: "https://xitcoin-a.example/rpc", restUrl: "https://xitcoin-a-api.example" },
    { rpcUrl: "https://xitcoin-b.example/rpc", restUrl: "https://xitcoin-b-api.example" }], allowLoopbackHttp: false,
  chainSchemaCommit: XITCOIN_CHAIN_SCHEMA_COMMIT, signerSetVersion: "1", authorizedSigners: [...testnetSigners],
  submitter: "xtc1pvxgdtncv9ttghcdrp89uzhyhacu5l6r42ahd9", confirmations: 2, historyBlocks: 100_000,
  maxAmount: "100000000000000000000", maxGas: "600000", gasAdjustmentPercent: 130, gasHeadroom: 40_000, feeMultiplierPercent: 200,
  maxGasPrice: "100000000000", maxFee: "60000000000000000", minDeadlineMarginSeconds: 120, maxResendIntervalSeconds: 3_600,
  stalledAlertSeconds: 21_600, ...xitcoinPatch },
  cronos: { rpcUrls: ["https://cronos-a.example/rpc", "https://cronos-b.example/rpc"], allowLoopbackHttp: false,
    vault: "0x1c94273C0b199b139D82da3786C9eCbE189D5919", cronosRouteId: "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9",
    confirmations: 12, ...cronosPatch },
  ...patch });

test("Xitcoin testnet mode requires every pinned value and rejects mainnet, the label route and coercion", async () => {
  const { validateXitcoinTestnetManifest, parseSubmitterManifest } = await import("../src/submitter-manifest.js");
  const accepted = validateXitcoinTestnetManifest(xitcoinTestnet());
  assert.ok(Object.isFrozen(accepted) && Object.isFrozen(accepted.xitcoin) && Object.isFrozen(accepted.xitcoin.origins)
    && Object.isFrozen(accepted.xitcoin.origins[0]) && Object.isFrozen(accepted.cronos));
  assert.deepEqual(parseSubmitterManifest(xitcoinTestnet()), accepted);
  assert.deepEqual(parseSubmitterManifest(manifest("xitcoin")), validateSubmitterManifest(manifest("xitcoin")));
  assert.equal(validateXitcoinTestnetManifest(xitcoinTestnet({}, { allowLoopbackHttp: true, origins: [
    { rpcUrl: "http://127.0.0.1:26657", restUrl: "http://127.0.0.1:1317" }, { rpcUrl: "http://127.0.0.1:26658", restUrl: "http://127.0.0.1:1318" }] }))
    .xitcoin.allowLoopbackHttp, true);
  assert.throws(() => validateXitcoinTestnetManifest(xitcoinTestnet({ xitcoinChainId: "xitcoin" })), /mainnet is not supported/);
  // Fee headroom is mandatory: without it the first base-fee rise evicts our transaction.
  assert.equal(validateXitcoinTestnetManifest(xitcoinTestnet({}, { feeMultiplierPercent: 150 })).xitcoin.feeMultiplierPercent, 150);
  assert.throws(() => validateXitcoinTestnetManifest(xitcoinTestnet({}, { feeMultiplierPercent: 100 })));
  const top = [{ destination: "cronos" }, { mode: "live" }, { mode: "disabled" }, { cronosChainId: 25 }, { version: 2 },
    { routeId: "cronos-testnet-xitcoin-testnet" }, { routeId: "0x21121C16B53A726056A6683F00C7EB4DA5501CE8A2ABC8A4677E06F1E94B5CD9" },
    { xitcoinChainId: "xitcoin-testnet-v2-2" }, { releaseCommit: "main" }, { cycleIntervalMs: 999 }, { relayStorePath: "relative.sqlite" },
    { keystorePath: "/var/lib/xitcoin-bridge/coordinator/relay.sqlite" }, { extra: true }, { password: "x" }];
  const xitcoin = [{ origins: [{ rpcUrl: "https://a.example", restUrl: "https://b.example" }] },
    { origins: [{ rpcUrl: "https://a.example", restUrl: "https://b.example" }, { rpcUrl: "https://a.example/x", restUrl: "https://c.example" }] },
    { origins: [{ rpcUrl: "https://a.example", restUrl: "https://b.example" }, { rpcUrl: "https://c.example", restUrl: "https://b.example/x" }] },
    { origins: [{ rpcUrl: "https://k:s@a.example", restUrl: "https://b.example" }, { rpcUrl: "https://c.example", restUrl: "https://d.example" }] },
    { origins: [{ rpcUrl: "https://a.example/?key=1", restUrl: "https://b.example" }, { rpcUrl: "https://c.example", restUrl: "https://d.example" }] },
    { origins: [{ rpcUrl: "http://127.0.0.1:1", restUrl: "http://127.0.0.1:2" }, { rpcUrl: "http://127.0.0.1:3", restUrl: "http://127.0.0.1:4" }] },
    { origins: [{ rpcUrl: "https://a.example", restUrl: "https://b.example", grpcUrl: "https://g.example" }, { rpcUrl: "https://c.example", restUrl: "https://d.example" }] },
    { chainSchemaCommit: "b".repeat(40) }, { chainSchemaCommit: "main" }, { signerSetVersion: 1 }, { signerSetVersion: "0" },
    { authorizedSigners: testnetSigners.slice(0, 2) }, { authorizedSigners: [testnetSigners[0], testnetSigners[0], testnetSigners[1]] },
    { authorizedSigners: [testnetSigners[0].toLowerCase(), testnetSigners[1], testnetSigners[2]] },
    { submitter: "xtc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqca63ah" }, { submitter: "XTC1PVXGDTNCV9TTGHCDRP89UZHYHACU5L6R42AHD9" },
    { submitter: "cosmos1pvxgdtncv9ttghcdrp89uzhyhacu5l6r42ahd9" }, { submitter: "xtc1pvxgdtncv9ttghcdrp89uzhyhacu5l6r42ahd8" },
    { confirmations: 0 }, { confirmations: 1_001 }, { historyBlocks: 999 }, { maxAmount: "0" }, { maxGas: "99999" }, { maxGas: "5000001" },
    { maxGas: 600000 }, { gasAdjustmentPercent: 109 }, { gasAdjustmentPercent: 301 }, { gasHeadroom: 9_999 }, { feeMultiplierPercent: 99 }, { feeMultiplierPercent: 100 }, { feeMultiplierPercent: 149 },
    { feeMultiplierPercent: 1_001 }, { maxGasPrice: "0" }, { maxGasPrice: "1000000000000001" }, { maxFee: "0" },
    { minDeadlineMarginSeconds: 29 }, { maxBroadcastAttempts: 5 }, { maxResendIntervalSeconds: 59 }, { maxResendIntervalSeconds: 86_401 },
    { maxResendIntervalSeconds: "600" }, { stalledAlertSeconds: 299 }, { stalledAlertSeconds: 2_592_001 }, { extra: 1 }, { privateKey: "0x1" },
    { allowLoopbackHttp: "false" }];
  const cronos = [{ rpcUrls: ["https://a.example"] }, { vault: "0x1c94273c0b199b139d82da3786c9ecbe189d5919" },
    { cronosRouteId: "0xb9ae829d654d824b9046d969c96822a479b9eac3488642b4092928d65e07df5b" }, { confirmations: 1 }, { extra: 1 }];
  for (const patch of top) assert.throws(() => validateXitcoinTestnetManifest(xitcoinTestnet(patch)), undefined, JSON.stringify(patch));
  for (const patch of xitcoin) assert.throws(() => validateXitcoinTestnetManifest(xitcoinTestnet({}, patch)), undefined, JSON.stringify(patch));
  for (const patch of cronos) assert.throws(() => validateXitcoinTestnetManifest(xitcoinTestnet({}, {}, patch)), undefined, JSON.stringify(patch));
  for (const field of Object.keys(xitcoinTestnet())) {
    const value = xitcoinTestnet(); delete value[field];
    assert.throws(() => validateXitcoinTestnetManifest(value));
  }
  for (const field of Object.keys(xitcoinTestnet().xitcoin)) {
    const value = xitcoinTestnet(); delete value.xitcoin[field];
    assert.throws(() => validateXitcoinTestnetManifest(value), undefined, field);
  }
  assert.throws(() => validateSubmitterManifest(xitcoinTestnet()));
});

test("Xitcoin testnet inspection is offline and unready; start builds only the Xitcoin runtime", async () => {
  const options = { destination: "xitcoin", manifestPath: "/etc/xitcoin-bridge/submitter-xitcoin.json", modulePath, credentialsDirectory: "/run/credentials/x" };
  const verifyRelease = (config, path) => verifySubmitterRelease(config, path, { resolve: async (x) => x, stat: trustedStat });
  assert.deepEqual(await inspectSubmitter(options, { loadManifest: async () => xitcoinTestnet(), verifyRelease }),
    { version: 1, destination: "xitcoin", releaseCommit: "a".repeat(40), mode: "testnet", ready: false, submissions: 0,
      blocker: "xitcoin_live_checks_run_only_at_start" });
  let built;
  const runtime = await buildSubmitterRuntime(options, { loadManifest: async () => xitcoinTestnet(), verifyRelease,
    buildCronos: () => assert.fail("the Xitcoin manifest must not build the Cronos runtime"),
    buildXitcoin: async (config, dependencies) => { built = { config, dependencies }; return { run: async () => {} }; } });
  assert.equal(typeof runtime.run, "function");
  assert.equal(built.config.destination, "xitcoin"); assert.equal(built.dependencies.credentialsDirectory, "/run/credentials/x");
  await assert.rejects(buildSubmitterRuntime(options, { loadManifest: async () => manifest("xitcoin"), verifyRelease,
    buildXitcoin: () => assert.fail("disabled manifest must not build") }), { code: "SUBMITTER_UNAVAILABLE" });
  await assert.rejects(buildSubmitterRuntime({ ...options, destination: "cronos" }, { loadManifest: async () => xitcoinTestnet(), verifyRelease,
    buildXitcoin: () => assert.fail("destination mismatch must not build") }), /does not match/);
  const { calls, dependencies } = reader(JSON.stringify(xitcoinTestnet()));
  assert.equal((await loadSubmitterManifest("/etc/bridge/submitter.json", dependencies)).destination, "xitcoin");
  assert.equal(calls.closed, 1);
});

test("CLI start runs until SIGTERM, closes state and reports only stable error codes", async () => {
  const { EventEmitter } = await import("node:events");
  const signals = new EventEmitter();
  let closed = 0, errors = "";
  const runtime = { run: ({ signal }) => new Promise((resolve) => { signal.addEventListener("abort", resolve); setImmediate(() => signals.emit("SIGTERM")); }),
    close: () => { closed++; } };
  const common = { stdout: { write() {} }, stderr: { write: (x) => { errors += x; } }, signals, credentialsDirectory: "/run/credentials/x" };
  assert.equal(await runSubmitterCli(["start", "cronos", "/etc/config"], { ...common, build: async (options) => {
    assert.equal(options.credentialsDirectory, "/run/credentials/x"); return runtime; } }), 0);
  assert.equal(closed, 1); assert.equal(signals.listenerCount("SIGTERM"), 0);
  const failing = { run: async () => { const error = new Error("secret endpoint https://k@rpc"); error.code = "vault_code_mismatch"; throw error; }, close: () => { closed++; } };
  assert.equal(await runSubmitterCli(["start", "cronos", "/etc/config"], { ...common, build: async () => failing }), 1);
  assert.match(errors, /submitter stopped: vault_code_mismatch;/);
  assert.doesNotMatch(errors, /secret|https/);
  assert.equal(closed, 2);
  errors = "";
  const unsafe = new Error("x"); unsafe.code = "Contains Spaces https://x";
  assert.equal(await runSubmitterCli(["start", "cronos", "/etc/config"], { ...common, build: async () => { throw unsafe; } }), 1);
  assert.doesNotMatch(errors, /Contains|https/);
});

test("only conditions that persist nothing are temporary stops; halts and identity errors still stop", async () => {
  const { isTemporaryStop } = await import("../src/cronos-submitter.js");
  const { SubmissionHalt, SubmissionUnavailable } = await import("../src/durable-broadcast.js");
  const { TransportError } = await import("../src/bounded-transport.js");
  const { RpcDisagreement, RpcInvalid } = await import("../src/cronos-rpc.js");
  const busy = Object.assign(new Error("database is locked"), { errcode: 5 });
  for (const error of [new TransportError("timeout"), new RpcDisagreement(), new RpcInvalid(), busy,
    new SubmissionUnavailable("rpc_transaction_mismatch"), new SubmissionUnavailable("source_finality_unverified")]) {
    assert.equal(isTemporaryStop(error), true);
  }
  for (const error of [new SubmissionHalt("approval_expired_before_broadcast"), new SubmissionHalt("ledger_requires_review"),
    new SubmissionUnavailable("vault_code_mismatch"), new SubmissionUnavailable("signer_set_mismatch"),
    Object.assign(new Error("x"), { code: "cronos_mainnet_rejected" }), Object.assign(new Error("x"), { errcode: 19 }),
    new Error("broadcast ledger unavailable or conflicting"), null, "busy"]) {
    assert.equal(isTemporaryStop(error), false);
  }
});
