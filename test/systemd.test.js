import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const units = [
  "xitcoin-bridge-signer@.service",
  "xitcoin-bridge-coordinator.service",
  "xitcoin-bridge-submitter@.service",
  "xitcoin-bridge-submitter-cronos-testnet.service",
];

test("runs every Node runtime without JIT under executable-memory denial", async () => {
  for (const unit of units) {
    const body = await readFile(new URL(`../ops/systemd/${unit}`, import.meta.url), "utf8");
    assert.match(body, /^MemoryDenyWriteExecute=true$/m);
    const command = body.match(/^ExecStart=(.+)$/m)?.[1] ?? "";
    assert.match(command, /^\/opt\/xitcoin-bridge-node\/24\.19\.0\/bin\/node --jitless /);
    assert.doesNotMatch(command, /\/usr\/bin\/env node/);
  }
});

test("Cronos testnet submitter template is hardened, credentialed and never restarts", async () => {
  const body = await readFile(new URL("../ops/systemd/xitcoin-bridge-submitter-cronos-testnet.service", import.meta.url), "utf8");
  assert.match(body, /^ExecStart=\S+ --jitless \/opt\/xitcoin-bridge-relayer\/current\/src\/submitter-cli\.js start cronos \/etc\/xitcoin-bridge\/submitter-cronos\.json$/m);
  assert.match(body, /^User=xitcoin-bridge-submitter-cronos$/m);
  assert.match(body, /^LoadCredentialEncrypted=keystore-password:/m);
  for (const line of ["Restart=no", "LimitCORE=0", "UMask=0077", "StateDirectoryMode=0700", "IPAddressDeny=any",
    "IPAddressAllow=localhost", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet="]) {
    assert.match(body, new RegExp(`^${line}$`, "m"), line);
  }
  assert.doesNotMatch(body, /^Environment/m);
  assert.doesNotMatch(body, /PRIVATE_KEY|MNEMONIC|--password/i);
  assert.doesNotMatch(body, /start xitcoin/);
});
