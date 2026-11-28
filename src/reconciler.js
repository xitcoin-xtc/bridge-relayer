// Accounting reconciliation between the Cronos vault and the Xitcoin bridge
// module. It only reads and reports. It holds no key, builds no transaction
// and cannot pause anything by itself: a deficit raises an alert and, in
// "request_pause" mode, hands a structured pause request to an injected hook
// (for example paging the guardian operator). The guardian pause itself is a
// separate, manual, guardian-signed action on each chain.
//
// Invariant (all amounts in atomic units, read at finalized heights):
//
//   vaultLocked = chainOutstanding + lockedNotMinted + burnedNotReleased + surplus
//
// lockedNotMinted:  Cronos deposits observed by the relayer that are still in
//                   flight (observed, finalized, approved or submitted).
// burnedNotReleased: Xitcoin burns still in flight towards Cronos.
// surplus:          tokens sent to the vault outside deposit(), a deposit the
//                   relayer never observed, or a deposit marked failed because
//                   it can never mint (for example above the chain's limits or
//                   to a blocked module account) until it is refunded.
//
// A negative difference (deficit) means native XTC is not fully backed and is
// critical. A positive difference (surplus) is reported as a warning only.

export const RECONCILER_MODES = Object.freeze(["dry_run", "request_pause"]);

function amount(value, label) {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(`${label} must not be negative`);
    return value;
  }
  const text = String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a non-negative integer`);
  return BigInt(text);
}

// Interface for the read-only data a reconciliation needs. Implementations
// must read both chains at finalized heights and must never sign or send;
// src/reconciler-sources.js implements it on the bounded quorum transports.
export class ReconciliationSource {
  /** @returns {Promise<{ amount: bigint|string, height: number }>} asset balance of the vault */
  async vaultLocked() { throw new Error("vaultLocked must be implemented"); }
  /** @returns {Promise<{ amount: bigint|string, height: number, dailyUsage?: object }>} bridge outstanding_amount */
  async chainOutstanding() { throw new Error("chainOutstanding must be implemented"); }
  /** @returns {Promise<{ lockedNotMinted: bigint|string, burnedNotReleased: bigint|string }>} */
  async inFlight() { throw new Error("inFlight must be implemented"); }
}

// The Xitcoin bridge module stores outstanding_amount at store key 0x07 as an
// unsigned big-endian integer (pos-chain x/bridge/types/keys.go). This is the
// ABCI query a chain adapter performs (`xitcoind query bridge route` prints the
// same value).
export const XITCOIN_OUTSTANDING_QUERY = Object.freeze({ path: "/store/bridge/key", data: "0x07" });

export function decodeOutstandingAmount(value) {
  const bytes = value == null ? Buffer.alloc(0) : typeof value === "string" ? Buffer.from(value, "base64") : Buffer.from(value);
  if (bytes.length > 32) throw new Error("outstanding amount exceeds 256 bits");
  return bytes.length === 0 ? 0n : BigInt(`0x${bytes.toString("hex")}`);
}

// In-flight totals from the coordinator store. Inbound rows are keyed by the
// Cronos depositId, outbound rows by the Xitcoin burn request ID. Failed rows
// are not in flight; a failed deposit therefore shows as surplus (a warning),
// never as a deficit.
export function inFlightFromStore(store) {
  let lockedNotMinted = 0n;
  let burnedNotReleased = 0n;
  const rows = store.database.prepare(
    "SELECT source_chain, source_ref, state, payload FROM transfers WHERE state NOT IN ('completed', 'reorged', 'failed')",
  ).all();
  for (const row of rows) {
    const value = amount(JSON.parse(row.payload).amount, "stored transfer amount");
    if (row.source_chain === "cronos") lockedNotMinted += value;
    else if (row.source_chain === "xitcoin") burnedNotReleased += value;
    else throw new Error("unknown source chain in store");
  }
  return Object.freeze({ lockedNotMinted, burnedNotReleased });
}

export function reconcile({ vaultLocked, chainOutstanding, lockedNotMinted, burnedNotReleased, tolerance = 0n }) {
  const locked = amount(vaultLocked, "vault locked amount");
  const outstanding = amount(chainOutstanding, "chain outstanding amount");
  const pendingIn = amount(lockedNotMinted, "locked-not-minted amount");
  const pendingOut = amount(burnedNotReleased, "burned-not-released amount");
  const allowed = amount(tolerance, "tolerance");
  const expected = outstanding + pendingIn + pendingOut;
  const difference = locked - expected;
  let status = "ok";
  if (difference < -allowed) status = "deficit";
  else if (difference > allowed) status = "surplus";
  return Object.freeze({
    status,
    vaultLocked: locked.toString(),
    chainOutstanding: outstanding.toString(),
    lockedNotMinted: pendingIn.toString(),
    burnedNotReleased: pendingOut.toString(),
    expectedLocked: expected.toString(),
    difference: difference.toString(),
    tolerance: allowed.toString(),
  });
}

const READ_FAILURES = Object.freeze({
  unavailable: Object.freeze({ severity: "warning", kind: "reconciliation_unavailable" }),
  disagreement: Object.freeze({ severity: "critical", kind: "reconciliation_disagreement" }),
  identity_mismatch: Object.freeze({ severity: "critical", kind: "reconciliation_identity_mismatch" }),
});

function readFailure(error) {
  return error?.name === "ReconciliationReadError" && Object.hasOwn(READ_FAILURES, error.kind) ? error.kind : "unavailable";
}

function reasonOf(error) {
  if (error?.name === "ReconciliationReadError" && typeof error.code === "string") return error.code;
  return String(error?.message ?? error).slice(0, 200);
}

function dailyUsage(value) {
  return Object.freeze({ utcDay: String(value.utcDay), usedAmount: amount(value.usedAmount, "daily used amount").toString(),
    dailyLimit: amount(value.dailyLimit, "daily limit").toString(), remainingAmount: amount(value.remainingAmount, "daily remaining amount").toString() });
}

export class Reconciler {
  constructor({ source, alert, requestPause, mode = "dry_run", tolerance = 0n, confirmations = 2 } = {}) {
    if (!source || typeof source.vaultLocked !== "function" || typeof source.chainOutstanding !== "function"
        || typeof source.inFlight !== "function") throw new Error("reconciliation source is required");
    if (typeof alert !== "function") throw new Error("alert sink is required");
    if (!RECONCILER_MODES.includes(mode)) throw new Error("reconciler mode must be dry_run or request_pause");
    if (mode === "request_pause" && typeof requestPause !== "function") throw new Error("pause request hook is required");
    const rounds = Number(confirmations);
    if (!Number.isSafeInteger(rounds) || rounds < 1 || rounds > 100) throw new Error("confirmations must be between 1 and 100");
    this.source = source;
    this.alert = alert;
    this.requestPause = requestPause;
    this.mode = mode;
    this.tolerance = amount(tolerance, "tolerance");
    this.confirmations = rounds;
    this.consecutiveDeficits = 0;
    this.pauseRequested = false;
  }

  async runOnce({ nowUnix = Math.floor(Date.now() / 1000) } = {}) {
    let report;
    try {
      const [vault, chain, pending] = await Promise.all([
        this.source.vaultLocked(), this.source.chainOutstanding(), this.source.inFlight(),
      ]);
      report = reconcile({
        vaultLocked: vault.amount, chainOutstanding: chain.amount,
        lockedNotMinted: pending.lockedNotMinted, burnedNotReleased: pending.burnedNotReleased,
        tolerance: this.tolerance,
      });
      report = Object.freeze({ ...report, cronosHeight: vault.height, xitcoinHeight: chain.height,
        ...(chain.dailyUsage ? { xitcoinDailyUsage: dailyUsage(chain.dailyUsage) } : {}), checkedAt: nowUnix });
    } catch (error) {
      // An unreadable chain is not evidence of a mismatch, but it is not
      // evidence of health either: alert, keep the deficit counter unchanged.
      // Origins that disagree about a pinned height, or a vault or route that
      // is not the pinned one, are critical but still never count as a
      // deficit and never request a pause (src/reconciler-sources.js).
      const event = Object.freeze({ ...READ_FAILURES[readFailure(error)], reason: reasonOf(error), checkedAt: nowUnix });
      await this.alert(event);
      return event;
    }

    if (report.status !== "deficit") {
      this.consecutiveDeficits = 0;
      this.pauseRequested = false;
      if (report.status === "surplus") await this.alert(Object.freeze({ severity: "warning", kind: "reconciliation_surplus", report }));
      return report;
    }

    this.consecutiveDeficits += 1;
    await this.alert(Object.freeze({ severity: "critical", kind: "reconciliation_deficit", consecutive: this.consecutiveDeficits, report }));
    if (this.consecutiveDeficits >= this.confirmations && !this.pauseRequested) {
      const request = Object.freeze({ action: "guardian_pause", reason: "reconciliation_deficit", report });
      if (this.mode === "request_pause") {
        await this.requestPause(request);
        await this.alert(Object.freeze({ severity: "critical", kind: "pause_requested", request }));
      } else {
        await this.alert(Object.freeze({ severity: "critical", kind: "pause_request_dry_run", request }));
      }
      this.pauseRequested = true;
    }
    return report;
  }
}
