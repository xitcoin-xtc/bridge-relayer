# Operations

## Process separation

- Run each signer under an independent operating-system identity and preferably
  on independent infrastructure.
- Run the coordinator without access to signer private keys.
- Allow signer APIs only from authenticated coordinator networks and require
  signer-side source-chain verification.
- Keep transaction submitter keys separate from bridge signer keys.

## Required safety controls

- Pin Cronos and Xitcoin chain identities, vault address, route and asset.
- Require configurable finality depth on both chains.
- Persist observed block hash, height, transaction hash and log index.
- Re-check the canonical block hash before signing and before submission.
- Stop processing automatically on RPC disagreement, reorganization beyond the
  confirmation window, signer-set mismatch or route pause.
- Expose health and metrics without exposing payload signatures or credentials.

## Watcher checkpoints

Each watcher advances its checkpoint only after every event in the scanned
range has passed a second canonical block and transaction check. A checkpoint
at the same height with a different hash is a finality violation and stops the
process. Operators must investigate RPC disagreement or a deep reorganization;
the process must never select one provider silently.

## Network adapters

- Configure at least two independent HTTPS origins for each source chain.
- Never place API keys, usernames or passwords inside an RPC URL. Inject secret
  headers only in a private runtime wrapper outside this public repository.
- For testnet preflight and canary runs, pin Cronos EVM Testnet chain ID `338`
  and the canonical Xitcoin CometBFT chain ID `xitcoin-testnet-v2-1` before any
  scan begins. Reject Cronos mainnet chain ID `25` in the testnet profile.
- Reject catching-up Xitcoin nodes, redirects, oversized responses and malformed
  JSON instead of silently retrying a different interpretation.
- Supply the Xitcoin outbound-message decoder from the canonical chain schema.
  The transport deliberately does not guess event attribute names.
- A well-formed Xitcoin outbound event whose values are not canonical (for
  example amount `010`, a nonce of `0` or an invalid destination) is skipped,
  never turned into a transfer, and reported as an
  `xitcoin_outbound_event_skipped` alert with its height, transaction hash,
  message index and reason; the rest of the block is still processed. Every
  party using the canonical decoder skips it the same way. Investigate each
  alert: the burn may need a manual, reviewed resolution. Missing or duplicate
  attributes still stop the scan.
- Run the scan loop without signer or submitter credentials. A successful scan
  records only `observed`, `finalized` and checkpoint state.

## Recovery

The approval-only coordinator resumes non-terminal records from the local
store. The submission helper queries destination replay-protection state, but
production submission remains blocked; see [submitter phase one](SUBMITTERS.md).
Operators must never delete a pending database merely to clear an error.

## Signer transport

- Give every signer endpoint a stable, unique operator identity and an
  independent HTTPS origin.
- Never embed credentials in signer URLs; inject authentication in a private
  runtime wrapper outside this repository.
- Keep signer response limits and timeouts bounded and reject redirects. An
  invalid response is discarded and never counted toward the quorum; a round
  with fewer than two distinct valid approvals fails and records nothing.
- Rotate the configured signer set atomically with the on-chain signer-set
  version. Old-domain approvals must never be reused.
- The public coordinator stores signatures because they are transaction input,
  not secrets. Metrics and logs must nevertheless omit them.

## Isolated signer services

- Run each `IsolatedSignerService` under a distinct operating-system identity
  and preferably on independent infrastructure and RPC providers.
- Inject `verifySource` and `signDigest` from private runtime adapters. The
  public service neither loads nor stores private keys.
- Pin the Xitcoin route ID exactly as the bridge module stores it (on testnet
  `0x21121c16...5cd9`, see [PROTOCOL.md](PROTOCOL.md#route-identity)) and the
  deployed Cronos `bytes32` route ID independently; never derive either from a
  display label. Also pin
  the Cronos chain ID, the destination Xitcoin chain ID, vault, maximum amount
  and maximum deadline window on every signer. Set the maximum amount no higher
  than the chain route's `max_transfer_amount` and the vault's release limit.
- Give every signer a durable approval journal (`journalPath`, an absolute path
  in a directory writable only by that signer, for example
  `/var/lib/xitcoin-bridge/signer-1-journal/approvals.sqlite`; the systemd
  template provides it as `StateDirectory`). Never delete, copy between signers
  or restore an old copy of a journal: it is what stops a signer from signing
  two different requests for one deposit. Back it up like a key.
- Require transport authorization before reading request bodies. Terminate TLS
  and mutual authentication in a hardened private ingress; never expose the
  approval endpoint directly to the public Internet.
- A signer must independently confirm canonical source finality. Coordinator
  approval or another signer's response is never sufficient evidence.
- Treat source disagreement, a mismatched digest, a wrong signing account or an
  expired request as a hard rejection and emit no signature.
- Configure every signer's `xitcoin.restUrls`: the REST API of the same
  operator as each entry of `xitcoin.rpcUrls`, in the same order (two to four
  origins). With them and `cronos.rpcUrls`, the signer verifies on the
  destination itself that the approval an explicit re-issue replaces can never
  be used (see [PROTOCOL.md](PROTOCOL.md#expired-approvals)); without proof it
  refuses. A different digest for an already signed source event is refused
  unless it is such an explicit re-issue. Each signed re-issue is recorded in
  the journal's `approval_reissues` table with the destination height and
  block time of the proof; the table can be read with `sqlite3 -readonly`.

## Deposits that cannot mint and refunds

The Xitcoin module refuses to mint a deposit that exceeds the route's
`max_transfer_amount`, the remaining daily limit or `max_outstanding_amount`,
that would exceed the XTC maximum supply, or whose recipient is a blocked
module account. The Cronos vault has no user refund function. The future vault
rejects deposits above its own deposit limits (configure them no higher than
the chain limits), but a deposit that is already locked follows this procedure:

1. Daily limit: no action. The Xitcoin submitter defers the deposit; once its
   approval is too close to its deadline the submitter gives it up, and the
   coordinator re-issues it with a new deadline (same replay key) after the
   chain shows the old approval dead, until it mints on a later day.
2. Outstanding limit or per-transfer limit: the signer quorum may raise the
   chain limits with a 2-of-3 `update_route_config`, after which the deposit
   mints normally. This is a limit decision and needs the owner's approval.
3. Blocked recipient, or a deposit the owner decides not to mint: refund on
   Cronos. The owner approves the refund in writing with the depositId, amount
   and original depositor. Each signer operator first closes the deposit in its
   own journal (`npm run signer:journal -- close <journal> <attestation ID>
   "refund <ticket>"`), which makes later mint approvals impossible; the
   attestation ID is printed by `xitcoind query bridge source-deposit-key 25
   <depositId>`. Two signers then sign a vault `Release` to the original
   depositor with `sourceBurnId = keccak256("xitcoin-bridge-refund-v1" ||
   depositId)`, which cannot collide with a chain burn request ID. The signer
   service cannot produce this signature (it only signs releases backed by a
   finalized Xitcoin burn), so the refund is a manual, reviewed signing step
   outside the service. Mark the coordinator row `failed` with the refund
   reference. Accounting stays balanced because the deposit was never minted.
   A submitter `rejected` row (an invalid recipient) is handled the same way:
   it is never re-issued and nothing automates the refund.

Outbound burns to the zero or `0x…dEaD` address are rejected by the chain
before burning, because the vault refuses to release to them.

## Reconciliation

`src/reconciler.js` compares the vault's locked balance with the chain's
`outstanding_amount` plus in-flight transfers from the coordinator store:

```text
vault locked = chain outstanding + deposits in flight + burns in flight + surplus
```

What exists: the comparison, alerts, a pause request after a configurable
number of consecutive deficits, and the two read-only chain readers behind
`ReconciliationSource` (`src/reconciler-sources.js`). Both read through the
bounded quorum transports used by the submitters, from at least two
independent origins per chain, and hold no key:

- Cronos: the vault's locked balance, `availableLiquidity()` (the vault's
  `asset.balanceOf(vault)`), at the finalized height `tip - confirmations`,
  where `tip` is the lowest head across origins. Every origin must return the
  identical block hash (read before and after the call), the vault runtime
  code matching the pinned code hash, and the identical balance at that
  height.
- Xitcoin: `outstanding_amount` from `GET /xitcoin/bridge/v1/outstanding` and
  the route's daily usage from `GET /xitcoin/bridge/v1/daily_usage`, both
  pinned with `x-cosmos-block-height` to the lowest committed height across
  origins (CometBFT commits are final). Every origin must serve that block
  with the identical hash and return identical answers for the pinned route;
  the daily usage's block time must equal that block's time. The report
  carries the daily usage (`xitcoinDailyUsage`) for information.

In-flight amounts come from the coordinator store (`inFlightFromStore`). What
does not exist: a scheduler or service unit, and any automatic pause. The
default mode is `dry_run`, which only alerts (`pause_request_dry_run`). In
`request_pause` mode the reconciler calls an injected hook with a structured
request; the guardian must still sign and submit the pause on each chain. A
surplus (for example a donated or refunded-pending deposit) is a warning only.

A failed read is never evidence of a deficit; it neither counts towards nor
resets the consecutive-deficit count, and it never requests a pause:

| Alert | Severity | Cause (`reason`) |
| --- | --- | --- |
| `reconciliation_unavailable` | warning | an origin did not answer, answered with an error or with an invalid response, or does not serve the pinned height yet (`cronos_origin_unavailable`, `xitcoin_origin_unavailable`, `cronos_history_too_short`, `xitcoin_inconsistent_height`, ...) |
| `reconciliation_disagreement` | critical | origins returned different valid answers for the same pinned height (`cronos_origin_disagreement`, `xitcoin_outstanding_disagreement`, `xitcoin_daily_usage_disagreement`, `cronos_block_changed`, ...) |
| `reconciliation_identity_mismatch` | critical | every origin agrees, but on a vault code, route or chain that is not the pinned one (`vault_code_mismatch`, `xitcoin_route_mismatch`, `cronos_chain_mismatch`, `xitcoin_chain_mismatch`) |

A disagreement at a finalized height means at least one origin is faulty or
compromised: identify it before trusting any of them. The three readings are
taken at slightly different moments, so a transfer that completes on its
destination before the coordinator store records it can show as a short
deficit (or surplus) for one round; `confirmations` consecutive deficits are
required before a pause request.

## Encrypted signer credentials

- Pass the keystore password with `LoadCredentialEncrypted=` and read it only
  from the service's runtime credential directory. Do not pass passwords in an
  environment variable, command-line argument, unit file or persistent wrapper.
- Keep the encrypted JSON keystore and runtime credential owned by the signer
  service identity and owner-private. The secure loader opens each absolute path
  with `O_NOFOLLOW`, checks the effective owner UID, rejects non-regular files,
  group/world access, empty input and oversized input before decryption.
- Pin the expected signer address independently from the keystore. A successful
  decryption with any other account is a hard startup failure.
- Keep core dumps disabled and logs sanitized. The loader intentionally reports
  a bounded failure code instead of the keystore path, password, decrypted
  account or underlying decryption error.
- A transport bearer credential must be independent from the keystore password,
  be generated from at least 32 cryptographically random bytes and be supplied
  as a separate encrypted systemd credential. The loader enforces the resulting
  token length; comparison is constant-time for equal-length candidates.
- Loading key material does not authorize a signature. Route policy, request
  bounds and independent canonical source verification still run before every
  digest signing operation.

## Activation sequence

Protocol vectors, watcher tests, signer isolation tests, testnet deployment,
fault injection and an independent security review must all succeed before a
route configuration is proposed. Deployment alone does not authorize route
activation.

## Runtime composition

- Keep the coordinator, three signers and two destination submitters under six
  distinct operating-system identities. Each submitter additionally needs
  reviewed write access to the coordinator RelayStore for the `approved ->
  submitted -> completed` transitions of its direction (outbound transfers for
  the Cronos submitter, inbound transfers for the Xitcoin submitter).
- Require at least two independent HTTPS RPC origins for each chain and reject
  credentials embedded in URLs. The coordinator also needs `xitcoin.restUrls`
  (one REST API per `xitcoin.rpcUrls` entry, same operator and order) for the
  destination proof before any approval re-issue.
- Approval re-issue: each coordinator cycle reports `awaitingReissue` (finalized
  transfers whose expired request is not re-issued yet), `returnedForReissue`
  (approved or submitted transfers given up by their submitter and returned to
  `finalized` with a re-issued request) and `reissueWaiting`, one code per
  waiting transfer: `approval_reissue_grace` (local grace),
  `deadline_not_passed` (the destination's final block time has not passed the
  old deadline yet), `destination_unavailable`, `destination_disagreement`,
  `destination_mismatch` and `retirement_verifier_missing`. A lasting
  `transfer_processed` means the destination already shows the old approval
  used although no completion was recorded: never re-issue by hand; verify the
  destination record as in [Reviewing non-blocking rows](#reviewing-non-blocking-rows)
  and treat an unexplained use as a possible approval leak.
- A critical watcher, approval or submission worker failure halts the runtime;
  operators must investigate instead of skipping the failed stage.
- `/livez` reports process liveness. `/readyz` becomes successful only after
  every worker has completed recently and successfully. Health output contains
  no payload, signature, endpoint, credential or raw error message.
- The units under `ops/systemd` are documentation templates. Do not install,
  enable or start them until private adapters, host paths and sandbox controls
  have passed staging review.

## Staging rehearsals

- Run every scenario in [`STAGING.md`](STAGING.md) before introducing private
  adapters or operator credentials.
- Preserve only the sanitized report digest and pass/fail codes. Never persist
  test signatures, payloads, RPC responses or injected private errors.
- A failed scenario blocks activation. Do not lower quorum, skip canonical
  checks, advance checkpoints or retry a broadcast to make a rehearsal pass.
- Repeat the complete rehearsal after any protocol, watcher, signer, runtime,
  dependency or destination-contract change.

## Submission recovery

Never manually retry an approved or submitted transfer. The submission helper
can resume a persisted transaction reference or a canonically processed record.
The [durable broadcast ledger](SUBMITTERS.md#durable-broadcast-ledger) persists
exact signed bytes before any send and recovers ambiguous broadcasts by
observation or by resending only those identical bytes. Both testnet
submitters use it. Never delete,
copy between hosts or restore an old copy of a broadcast ledger: like a signer
journal, it is what prevents a second transaction. Back it up like a key. A
`failed` or `halted` ledger row stops the submitter until an offline review; no
procedure or API for resolving such a row exists yet, and a row must never be
edited to permit a retry. `rejected`, `expired`, `reverted` and
`release_unverified` rows and deferred transfers do not block other transfers;
review them as described in
[Reviewing non-blocking rows](#reviewing-non-blocking-rows). A transfer released by another
transaction is recorded as `released_elsewhere` with that transaction.
[SUBMITTERS.md](SUBMITTERS.md) lists the remaining gaps.

## Cronos testnet submitter

- Run it only from a root-owned `testnet` manifest pinned to chain ID `338`,
  the deployed vault, its runtime code hash, the signer set and version, and a
  dedicated submitter account used by no other program.
- Keep the submitter key in an encrypted keystore owned by the submitter
  identity; pass its password only as the encrypted systemd credential
  `keystore-password`.
- Prefer three or more independent Cronos RPC providers: with three, one
  faulty provider can no longer hold a signed transaction until its approval
  expires.
- History retention: every origin must retain at least the maximum expected
  submitter downtime plus `releaseLookbackBlocks` blocks of block, receipt,
  transaction, log and state history (state for `eth_call` at past heights).
  An archive node is recommended; the canary plan uses our own Cronos node as
  one of its three origins. When the submitter was down for longer than an
  origin's retention, history about its own last transaction that some
  origins no longer serve ends in a non-blocking `release_unverified` alert
  (below) instead of a stop. If every origin has lost the transaction itself,
  or a receipt only some origins return is not confirmed in its block by a
  strict majority of origins, the row halts `nonce_consumed_without_receipt`
  for review (possible key compromise: our nonce was used without our
  transaction). With only two origins, one origin that has pruned old blocks
  is enough for that halt; run three.
- Give it at least two independent RPC providers per chain (reviewed loopback
  tunnels with the provided template). It never acts on a disagreement: a
  disagreement, transport failure or a RelayStore locked by the coordinator is
  a temporary stop, retried with backoff and logged as `temporarily_stopped`.
- It stops on persisted halts, finalized failed executions and identity or
  configuration mismatches and does not restart itself. Investigate before
  restarting; never lower confirmations, remove a pinned value or reset state
  to resume.
- A paused vault, a gas price above the cap or an insufficient submitter
  balance makes it wait without claiming anything. A transfer with an approval
  too close to its deadline, an amount above the limits, insufficient vault
  liquidity or a failing simulation is deferred (1 minute, doubling, at most 1
  hour) while the next transfers proceed.
- A release of a burn by another transaction (for example a front-run) is
  recorded as `released_elsewhere` and is not an error; RelayStore
  `release_ref` names the releasing transaction.
- Every cycle report carries `attention` counts (`rejected`, `expired`,
  `releaseUnverified`, `reverted`). These rows never block other transfers and,
  except `expired` rows (re-issued automatically), each needs the review
  below.
- Logs contain only stable codes, transfer IDs and transaction hashes.

### Reviewing non-blocking rows

`reverted`, `release_unverified` and `rejected` ledger rows are permanent. The
submitter never sends anything else for those transfers, and the broadcast
ledger must never be edited, reset or replaced to retry one: its row is the
permanent record of the nonce and bytes used for that transfer.

An `expired` row resolves itself: the submitter gives its approval up, the
coordinator re-issues it after the destination shows it dead, and the row
continues as a new attempt with the re-issued approval and the next nonce. Its
expired bytes, nonce, hash and inclusion stay archived in the ledger's
append-only `superseded_attempts` table and in RelayStore `approval_history`.
Review an `expired` count that does not return to zero within a few cycles
(check `reissueWaiting` in the coordinator log).

| State | Meaning |
| --- | --- |
| `expired` | our identical bytes were mined after the approval deadline and reverted; nonce consumed; continues as a new attempt once the approval is re-issued |
| `reverted` | our bytes were mined before the deadline and reverted for the cause in `reason_code`: `vault_paused` (guardian pause), `signer_set_rotated`, `release_limit_exceeded`, `daily_release_limit_exhausted` or `insufficient_vault_liquidity`; nonce consumed |
| `release_unverified` | the outcome could not be verified; the reason is the code of its `release_unverified` event: `release_not_found` (burn processed, no matching `Released` event in the searched windows), `release_history_unserved` (that search reached history an origin no longer serves), `receipt_history_unserved` (our mined transaction's receipt, transaction or block is no longer served by some origins), `revert_history_unserved` (our transaction reverted and the state needed to classify it is no longer served) |
| `rejected` | the transfer can never be sent (`invalid_recipient`); nothing was signed |

Detect: any non-zero `attention` count in the cycle log. List the rows with a
read-only query run as the submitter service user with a private umask (a
WAL or SHM file owned by another user, or readable by others, makes the
ledger fail closed), never with a writable connection:

```sh
sudo -u xitcoin-bridge-submitter-cronos sh -c 'umask 077; exec sqlite3 -readonly "$1"' sh \
  /var/lib/xitcoin-bridge/submitter-cronos/<ledger file named by the manifest ledgerPath> <<'SQL'
SELECT transfer_id, source_ref, state, nonce, transaction_hash, block_number, block_hash, reason_code
  FROM transfers WHERE state IN ('expired', 'reverted', 'release_unverified', 'rejected');
SELECT transfer_id, state, code, at FROM transfer_events WHERE state = 'release_unverified';
SQL
```

Verify on chain, with read-only calls to an independent archive node (the
source burn ID is the `transfer_id`; the approved recipient, amount, signer
version and deadline are in the stored approval request):

1. `processedBurns(sourceBurnId)` on the vault at a finalized height.
2. The vault's `Released` logs with that burn ID as the first indexed topic,
   from the block of the first approval to the finalized height. One event
   whose recipient, amount and signer version match the approval means the
   recipient was paid. An event with any other field is a signer-quorum
   compromise: pause the vault and start incident response.
3. For our transaction, if the row has one (`transaction_hash`, `block_number`, `block_hash`):
   the receipt status, that the block hash is canonical, and the block
   timestamp against the approval deadline (`expired` rows: after it).
4. For `reverted` and `revert_history_unserved`: vault state at
   `block_number - 1` and at `block_number` (`paused`, `signerSetVersion`,
   `maxReleaseAmount`, `releaseDay`, `releasedToday`, `dailyReleaseLimit`,
   `availableLiquidity`), and the revert reason from a transaction trace on
   the archive node.
5. For `rejected`: the recipient in the approved payload (zero, `0x…dEaD` or
   the vault itself).

Resolve, by owner decision and without touching the broadcast ledger:

- Recipient paid (a matching `Released` event, ours or another transaction's,
  at a finalized height): no new transaction. The RelayStore transfer stays
  `submitted` (the reconciler reports it) until a reviewed completion
  recording the release transaction exists; no such tool exists yet.
- Not paid (`processedBurns` false at a finalized height and no `Released`
  event), for a `reverted` or `release_unverified` row: once the cause is
  cleared (resume, liquidity, limits, signer set), either a re-approval or the
  refund path on the source chain. Before either, confirm that every approval
  ever issued for the burn is past its deadline (the vault then refuses it)
  and that no signer will approve the old burn ID again, so the burn can never
  be released twice. Neither path is automated for these rows in this
  release; both need owner approval. (`expired` rows are re-issued
  automatically, as above.)

## Xitcoin testnet submitter

- Run it only from a root-owned `testnet` manifest pinned to chain ID
  `xitcoin-testnet-v2-1`, the stored route ID, the signer set and version, the
  chain schema commit of this release and a dedicated submitter account used by
  no other program, Cosmos or EVM (an EVM transaction from the same key uses
  the same sequence and halts the submitter).
- It needs pos-chain `xitcoin-security-hardening-v2` on the chain: without the
  typed attestation query it never passes a cycle (temporary stop).
- Keep the submitter key in an encrypted keystore owned by the submitter
  identity; pass its password only as the encrypted systemd credential
  `keystore-password` (`ops/systemd/xitcoin-bridge-submitter-xitcoin-testnet.service`).
- Give each Xitcoin origin a CometBFT RPC and a REST endpoint of the same
  independent operator, through reviewed loopback tunnels; three or more
  operators in production. Every origin must run the `kv` transaction indexer
  and serve state, blocks and the index for at least `historyBlocks` recent
  blocks plus the maximum expected downtime. A lagging or catching-up origin,
  a disagreement or a transport failure is a temporary stop (`temporarily_stopped`).
- Set `maxGasPrice`, `feeMultiplierPercent` (at least 150) and `maxFee` from
  the testnet fee market. The fee multiplier keeps the fee above base-fee rises
  (up to 12.5% per full block) between signing and execution. A transaction
  evicted or rejected for its fee leaves the sequence unused: the submitter
  waits (`fee_below_required`) and resends the identical bytes once they would
  be admitted. Keep CometBFT's default `keep-invalid-txs-in-cache = false` on
  every origin so that rejected bytes can be readmitted. Resends back off from
  one minute, doubling, up to `maxResendIntervalSeconds`, and are never capped.
  A row that stays unfinished longer than `stalledAlertSeconds` after signing
  is reported as `stalled` in every cycle's `attention` (also after restarts)
  while it holds the queue: investigate the fee market and the origins'
  mempools; the bytes remain valid, nothing new is ever signed for the
  transfer, and the ledger must not be edited.
- The broadcast ledger is schema version 3. A version 1 or 2 ledger (created
  by an earlier release) is migrated forward automatically on the first open,
  one version at a time, only when its schema and binding are exact; back it up
  before upgrading, like any ledger, and never restore an older copy over a
  migrated one.
- Anyone who has seen our bytes can re-wrap the same signed content with
  another signature encoding (the chain's eth_secp256k1 verifier ignores the
  65th byte and accepts 64-byte signatures). Such a copy that lands first is
  recognised by signed content and recorded as `released_elsewhere` with its
  hash.
- A paused or disabled route, a fee above the cap or an insufficient balance
  makes it wait without claiming anything. An approval too close to its
  deadline, an amount above the limits, an exhausted daily limit, a reached
  outstanding cap or a failing simulation defers that transfer while the next
  ones proceed.
- A deposit processed by another account (for example a copy of our pending
  message) is recorded as `released_elsewhere`; RelayStore `release_ref` names
  that transaction. A processing record whose approved fields differ halts
  (`processed_with_mismatching_record`): pause the route and start incident
  response.
- `reverted` and `release_unverified` rows (and `expired` rows whose re-issue
  does not happen) are reviewed as in
  [Reviewing non-blocking rows](#reviewing-non-blocking-rows) (as the
  `xitcoin-bridge-submitter-xitcoin` user),
  with the Xitcoin reads: the attestation query (status and record), CometBFT
  `tx_search` for the row's `transaction_hash`, the block at `block_number`,
  and route, daily usage and outstanding state at `block_number - 1` and
  `block_number` (header `x-cosmos-block-height`). Reason codes:
  `route_paused`, `signer_set_rotated`, `transfer_limit_exceeded`,
  `daily_limit_exhausted`, `outstanding_limit_reached` (`reverted`);
  `processed_without_record`, `failure_history_unserved`,
  `inclusion_history_unserved` (`release_unverified`).
- Logs contain only stable codes, transfer IDs (attestation IDs) and
  transaction hashes.

## Testnet preflight

- Follow [`PREFLIGHT.md`](PREFLIGHT.md) with a full immutable release commit.
- Confirm all six runtime identities are distinct, locked and non-interactive.
- Require owner-bound state directories and wrappers with mode `0700` or stricter.
- Confirm every bridge service remains inactive and disabled during preflight.
- Reject wrong chain identities, catching-up nodes and non-independent RPCs.
- A passing preflight permits review of a testnet canary plan only; it does not
  authorize service activation, key loading, deployment or a transaction.

## Controlled testnet canary

- Follow [`CANARY.md`](CANARY.md) under a separate, time-bounded authorization.
- Bind the decision to the immutable release and successful preflight digest.
- Permit exactly one small finalized transfer per canonical direction.
- Stop immediately on disagreement, quorum loss, readiness loss, finality
  failure, destination mismatch or duplicate-broadcast evidence.
- Publish only sanitized transaction hashes and the SHA-256 report digest.
- Require a separate final review before any unrestricted or live activation.
