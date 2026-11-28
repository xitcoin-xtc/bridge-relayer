#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildSubmitterRuntime, inspectSubmitter } from "./submitter-bootstrap.js";

const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;

export async function runSubmitterCli(args, { modulePath = fileURLToPath(import.meta.url),
  inspect = inspectSubmitter, build = buildSubmitterRuntime,
  stdout = process.stdout, stderr = process.stderr,
  credentialsDirectory = process.env.CREDENTIALS_DIRECTORY, signals = process,
} = {}) {
  let runtime;
  const controller = new AbortController();
  const stop = () => controller.abort();
  try {
    const [action, destination, manifestPath] = args;
    if (args.length !== 3 || !["check", "start"].includes(action) || !["xitcoin", "cronos"].includes(destination)) {
      throw new Error("invalid arguments");
    }
    const options = { destination, manifestPath, modulePath };
    if (action === "check") {
      stdout.write(`${JSON.stringify(await inspect(options))}\n`);
      return 0;
    }
    // CREDENTIALS_DIRECTORY is the systemd credential path, never a secret.
    runtime = await build({ ...options, credentialsDirectory });
    if (runtime && typeof runtime.run === "function") {
      signals.once?.("SIGTERM", stop);
      signals.once?.("SIGINT", stop);
      await runtime.run({ signal: controller.signal });
    }
    return 0;
  } catch (error) {
    // Only stable public codes escape; never paths, endpoints or upstream text.
    let code;
    try {
      const descriptor = error && typeof error === "object" ? Object.getOwnPropertyDescriptor(error, "code") : undefined;
      code = descriptor && typeof descriptor.value === "string" && SAFE_CODE.test(descriptor.value) ? descriptor.value : undefined;
    } catch { /* Untrusted error. */ }
    stderr.write(`submitter stopped: ${code ? `${code}; ` : ""}invalid configuration, release, or unavailable destination adapter; see docs/SUBMITTERS.md\n`);
    return 1;
  } finally {
    signals.off?.("SIGTERM", stop);
    signals.off?.("SIGINT", stop);
    try { runtime?.close?.(); } catch { /* Preserve the exit status. */ }
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runSubmitterCli(process.argv.slice(2));
}
