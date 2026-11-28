import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/verify-actions-pinned.sh", import.meta.url));
const sha = "d23441a48e516b6c34aea4fa41551a30e30af803";
const digest = `sha256:${"69".repeat(32)}`;

function check(workflow) {
  const root = mkdtempSync(join(tmpdir(), "pinned-"));
  try {
    mkdirSync(join(root, "scripts")); mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    copyFileSync(script, join(root, "scripts", "verify-actions-pinned.sh"));
    writeFileSync(join(root, ".github", "workflows", "ci.yml"), workflow);
    return spawnSync("bash", [join(root, "scripts", "verify-actions-pinned.sh")], { encoding: "utf8" });
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const job = (steps, extra = "") => `jobs:\n  x:\n    runs-on: ubuntu-24.04\n${extra}    steps:\n${steps}`;

test("pinned actions check accepts full SHAs, local actions and digest-pinned images", () => {
  const result = check(job(`      - uses: actions/checkout@${sha} # v6\n      - uses: github/codeql-action/init@${sha}\n`
    + `      - uses: ./local\n      - uses: docker://ghcr.io/gitleaks/gitleaks@${digest} # v8\n`
    + `      - env:\n          GITLEAKS_IMAGE: ghcr.io/gitleaks/gitleaks@${digest} # v8\n        run: docker run "$GITLEAKS_IMAGE"\n`,
  `    container:\n      image: node@${digest}\n    services:\n      db:\n        image: "postgres@${digest}"\n`));
  assert.equal(result.status, 0, result.stderr);
});

test("pinned actions check rejects tags, branches, short SHAs and images without digests", () => {
  for (const [steps, extra] of [[`      - uses: actions/checkout@v6\n`, ""], [`      - uses: actions/checkout@main\n`, ""],
    [`      - uses: actions/checkout@${sha.slice(0, 12)}\n`, ""], [`      - uses: 'actions/checkout@v4' # ${sha}\n`, ""],
    [`      - uses: docker://ghcr.io/gitleaks/gitleaks:v8.30.0\n`, ""], [`      - uses: docker://alpine\n`, ""],
    [`      - uses: actions/checkout@${sha}\n`, "    container: node:24\n"],
    [`      - uses: actions/checkout@${sha}\n`, "    services:\n      db:\n        image: postgres:16\n"],
    [`      - env:\n          GITLEAKS_IMAGE: ghcr.io/gitleaks/gitleaks:v8.30.0\n        run: docker run "$GITLEAKS_IMAGE"\n`, ""]]) {
    const result = check(job(steps, extra));
    assert.equal(result.status, 1, steps + extra);
    assert.match(result.stderr, /Mutable or invalid|without an @sha256 digest/);
  }
});

test("repository workflows pass the pinned actions check", () => {
  const result = spawnSync("bash", [script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
