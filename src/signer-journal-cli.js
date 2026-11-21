#!/usr/bin/env node
// Operator tool for one signer's approval journal. It never signs anything.
//   show  <journal> <source-key>
//   close <journal> <source-key> <reason>   permanently refuse further approvals
// A source key is printed by `xitcoind query bridge source-deposit-key` for
// inbound deposits (it is also the chain's attestation ID).
import { realpathSync } from "node:fs";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

import { SignerApprovalJournal } from "./signer-journal.js";

export function runSignerJournalCli(args, { stdout = process.stdout, stderr = process.stderr, open = (path) => new SignerApprovalJournal(path) } = {}) {
  let journal;
  try {
    const [action, path, sourceKey, ...reason] = args;
    if (!["show", "close"].includes(action) || !isAbsolute(String(path ?? "")) || (action === "show" && reason.length)) throw new Error("usage");
    journal = open(path);
    const row = action === "show" ? journal.get(sourceKey) : journal.closeSourceEvent(sourceKey, reason.join(" "));
    stdout.write(`${JSON.stringify(row ?? null)}\n`);
    return 0;
  } catch {
    stderr.write("usage: signer-journal-cli show|close /absolute/journal.sqlite 0x<source-key> [reason]\n");
    return 1;
  } finally {
    journal?.shutdown();
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runSignerJournalCli(process.argv.slice(2));
}
