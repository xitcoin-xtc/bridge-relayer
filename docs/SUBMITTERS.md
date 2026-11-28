# Destination submitters

Status of this release:

- `xitcoin`: offline check and fail-closed startup only, exactly as in phase
  one. `start` always exits nonzero. The Xitcoin adapter needs a canonical
  attestation-status query from the chain first (see
  [Exact gaps](#exact-gaps-before-any-transaction-capable-phase)).
- `cronos`: `disabled` remains the default and behaves as in phase one. An
  explicit, root-owned `testnet` manifest for Cronos EVM Testnet (chain ID
  `338`) enables the transaction-capable submitter described in
  [Cronos testnet submitter](#cronos-testnet-submitter). Cronos mainnet (chain
  ID `25`) is rejected by the manifest, the RPC identity check, the release
  plan and the ledger binding.

A successful `check` is offline only and always reports `ready: false` and
`submissions: 0`. Nothing in this repository deploys, provisions, enables or
starts a service.

## Disabled manifest and immutable release

Provision one root-owned regular JSON file at
`/etc/xitcoin-bridge/submitter-xitcoin.json` and one at
`/etc/xitcoin-bridge/submitter-cronos.json`. Group/world write access is rejected.
All parent directories must be root-owned, non-symlink directories without
group/world write access. Reads use `O_NOFOLLOW` and `O_NONBLOCK`, enforce a
16 KiB limit before and during reading, and reject malformed UTF-8 and JSON.
Unknown fields and type coercions are rejected. No endpoint or credential
fields are supported.

The complete manifest schema is illustrated below. Replace `RELEASE_COMMIT`
with the full lowercase 40-character Git commit of the reviewed release;
the literal placeholder is intentionally invalid. Change only `destination`
to `cronos` for the second instance.

```json
{
  "version": 1,
  "mode": "disabled",
  "destination": "xitcoin",
  "releaseCommit": "RELEASE_COMMIT",
  "routeId": "cronos-testnet-xitcoin-testnet",
  "cronosChainId": 338,
  "xitcoinChainId": "xitcoin-testnet-v2-1"
}
```

The CLI resolves its own real path and requires
`/opt/xitcoin-bridge-relayer/<releaseCommit>/src/submitter-cli.js`.
It checks root ownership and absence of group/world writes on the file and
all parent directories. A `current` symlink may select that immutable directory;
a moving name in the manifest, a different resolved commit or a checkout in a
writable directory is rejected. Source-tree checks consequently fail release
validation by design.

Root provisioning must verify the Git commit and reproducible release contents,
including dependencies, and make the entire release tree root-owned and
non-writable by service identities. The runtime trusts that provisioned tree;
a directory named after a commit is not cryptographic proof of its contents.
Never modify an installed release in place. No provisioning or activation is
performed by these modules.

From a provisioned release, the offline commands are:

```sh
npm run submitter:check -- xitcoin /etc/xitcoin-bridge/submitter-xitcoin.json
npm run submitter:check -- cronos /etc/xitcoin-bridge/submitter-cronos.json
```

With a disabled manifest, `npm run submitter:start -- <destination> <manifest>`
is blocked for both destinations. The generic systemd template uses that same
public startup path, denies IP networking, disables core dumps and does not
restart a blocked process. Keep both instances disabled. Check success is not
readiness, preflight success or authorization.

## Exact gaps before any transaction-capable phase

The Xitcoin section below is still current. The Cronos and durable-protection
sections record the phase-one gaps; see
[Cronos testnet submitter](#cronos-testnet-submitter) and
[Durable broadcast ledger](#durable-broadcast-ledger) for what now closes them
and for what remains.

### Xitcoin

Update: [phase-two evidence and offline components](ADAPTERS.md) identify the
canonical message and replay-query schemas now verified in the chain repository.
The following missing-schema statement describes the phase-one relayer tree.

`buildXitcoinSubmission` builds attestation fields, not a signed chain
transaction. The repository does not contain the canonical protobuf definition
and type URL for `MsgSubmitAttestation`, field-number/type mappings, signature
representation, transaction envelope/sign mode, account-number/sequence lookup,
or fee/gas rules. These must come from the reviewed testnet chain implementation;
no Cosmos transaction format may be inferred from the message name.

A canonical attestation-status query is also missing: its public request/response
schema must bind `attestationId` to the executed transaction and every approved
field, distinguish pending from absent, and provide canonical block and finality
evidence that independent clients can verify. Broadcast response and failed
execution semantics must be specified and tested.

### Cronos

Update: implemented for Cronos testnet by the
[Cronos testnet submitter](#cronos-testnet-submitter). The phase-one text follows.

The vault `release(bytes32,address,uint256,uint64,uint256,bytes[])` calldata and
`Released` event ABI exist in `submission.js`. The missing piece is a reviewed
production adapter binding the deployed testnet vault and code identity to
replay-status queries, independent canonical receipts/events and finality.
The event alone does not contain every approved field; transaction input must
also be verified. Chain ID 338, route/pause state, signer-set version, recovered
authorized quorum, source finality, recipient, amount and deadline must be
checked before any submission. Submitter account/nonce allocation, bounded
fee/gas policy, credential separation and ambiguous-send recovery also require
implementation and staging review. No new EVM transaction format is needed.

### Durable duplicate-broadcast protection for both destinations

Update: the durable layer described below now exists as
[`src/broadcast-ledger.js`](../src/broadcast-ledger.js) and
[`src/durable-broadcast.js`](../src/durable-broadcast.js). See
[Durable broadcast ledger](#durable-broadcast-ledger). The paragraph that
follows describes the original phase-one gap.

The existing helper checks destination status before sending, saves the returned
transaction reference and resumes submitted/completed rows without resending.
Its staging tests cover canonical processed-status recovery and normal retries.
It does not atomically claim a transfer across concurrent workers or persist a
broadcast intent before the network call. A crash after acceptance but before
saving the reference, combined with a pending transaction absent from canonical
status, is not covered by that helper alone.

Before connecting a broadcaster, persist an exclusive transfer claim and the
exact signed transaction identity before sending. Define recovery that reconciles
pending and finalized state without creating a second transaction; an ambiguous
outcome must halt rather than authorize a fresh broadcast. Test competing
processes, restarts, nonce conflicts, timeouts, RPC disagreement, reorganization,
failed execution and all crash boundaries with durable storage. Revalidate the
persisted approval request against the transfer, route and authorized quorum.
Do not mutate existing approvals, reset lifecycle state or delete pending rows
to permit retries.

Phase one leaves the store and submission helper unchanged. Source review shows
that this runtime imports only manifest validation and filesystem reads; it has
no store or broadcast dependency. Tests verify repeated inspection returns the
same disabled report and repeated startup refuses, plus CLI failure handling
and systemd network denial. These tests do not instrument network calls or
assert that an on-disk lifecycle store remains unchanged.

## Durable broadcast ledger

`BroadcastLedger` is one exact-schema SQLite database per destination
submitter account. It reuses the private-path checks of the offline journals
(Linux service identity `xitcoin-bridge-submitter-<destination>`, private
service-owned parent, `O_NOFOLLOW` traversal, inode rechecks), immediate
transactions, `synchronous=FULL` and WAL. Exclusive creation initializes it;
reopening requires the identical table DDL, constraints, triggers, version and
binding. There is no migration, repair, delete, reset, expiry or retry API.

The binding is the destination deployment identity: destination, chain ID,
route, target (Cronos vault address or the Xitcoin bridge module), target
identity (Cronos runtime code hash or the pinned chain schema commit) and the
submitter account. It deliberately excludes the release commit so that a
reviewed upgrade with the identical schema can resume pending state instead of
abandoning it. Cronos chain ID `25` and the empty-code hash are rejected.

The ledger enforces, in one fenced immediate transaction per change:

- a worker lease with a fencing epoch. Another worker may take over only after
  expiry, which increments the epoch; every later write by the previous holder
  fails;
- one row per transfer (`claimed`), created only by the lease holder, bound to
  its immutable RelayStore source reference, and at most one unfinished
  transfer per account;
- exact signed bytes, their SHA-256 digest, the destination transaction hash
  and the account nonce committed (`signed`) before any send. Nonces are
  strictly sequential; a transaction hash, digest or nonce can never be reused
  by another transfer, and bytes can never be replaced;
- a write-ahead `broadcast` marker committed before every send of those
  identical bytes, bounded to at most 32 attempts (destination policy may be
  lower);
- forward-only states `claimed -> signed -> broadcast -> finalized | failed`,
  plus `halted` from any unfinished state. `finalized`, `failed` and `halted`
  are permanent, and any `failed` or `halted` row blocks every new claim until
  an offline review;
- two permanent states that never block the queue: `released_elsewhere` (the
  destination released this transfer in another finalized transaction, which
  the adapter verified; it records that transaction and its block) and
  `rejected` (this transfer alone can never be sent, for example an invalid
  recipient). `released_elsewhere` is allowed without bytes or after our
  identical bytes were sent, never from `signed`, so a reserved nonce is never
  left unused. `rejected` is allowed only without bytes;
- durable deferrals: a transfer that cannot proceed yet (for example an expired
  approval awaiting re-issue) is skipped until a backoff expires (1 minute,
  doubling, at most 1 hour). A deferral is a scheduling hint only: it never
  changes a transfer row and is never permission to send;
- a claimed row has no bytes and was never sent, so it may be rebound to a
  re-issued approval. Once bytes exist the approval digest is permanent.

SQLite triggers repeat these rules (no delete, no regression, no replacement,
immutable source reference, sequential nonce, monotonic lease epoch) as defense in depth against
accidental raw writes. Every read rehashes stored bytes. The bytes are opaque
to the ledger; the destination adapter validates them against the approved
request on every use. As with the offline journals, a malicious local owner,
root, or a consistent restore of an older database is outside SQLite
self-consistency guarantees and is not detected.

`runDurableSubmissionCycle` composes the ledger with RelayStore and a trusted
destination adapter (chain reads, signing and byte validation). It owns the
ordering:

1. reject any blocking ledger row; reconcile RelayStore `submitted` rows,
   which must reference a transaction the ledger holds; find an unfinished
   transfer by the source reference stored in its ledger row (never by a
   bounded window over RelayStore rows);
2. otherwise walk all `approved` transfers in order with keyset pagination,
   skipping rejected and still-deferred ones, and assess at most 8 per cycle;
3. read the persisted approval request and approvals under size bounds and
   bind their exact stored text by SHA-256 (`requestHash`). The adapter
   revalidates the request against the transfer, route and authorized quorum
   and decides `sign`; `wait` scoped to the route (for example a paused vault:
   the cycle stops) or to the transfer (it is deferred and the walk moves on);
   `reject`; `released_elsewhere`; or `halt`. Nothing is claimed unless it
   decides `sign`;
4. claim, sign, and commit the bytes before anything else;
5. bind RelayStore to that single transaction hash (`approved -> submitted`);
6. commit the broadcast marker, then send the identical bytes. Send errors are
   never decision inputs, and the first observation happens in a later cycle;
7. observe: `pending`, `wait`, `rebroadcast` (identical bytes only, when the
   adapter proves the transaction is unknown and its nonce unused),
   `released_elsewhere` (our bytes reverted because another finalized
   transaction released the transfer first, for example by copying our
   pending calldata), `failed` (any other finalized failed execution;
   permanent and blocking), `finalized`, or a persisted `halt`;
8. complete RelayStore only after the ledger records finality or a verified
   release elsewhere. RelayStore keeps referencing only our own transaction
   (or none if we never signed); the ledger records the releasing transaction.

RelayStore opens with a bounded 5-second busy timeout because the coordinator
and the Cronos submitter both write it; a longer lock fails with `SQLITE_BUSY`,
which callers treat as a temporary condition (`isRelayStoreBusy`).

A changed stored request or approval, a RelayStore reference to any other
transaction, a RelayStore `submitted` row without ledger custody, or a
malformed adapter decision halts or fails closed. The RelayStore is never
ahead of the ledger, and lifecycle state is never reset.

Tests use real SQLite files: competing child processes, expired-lease
takeovers, SIGKILL at every ledger commit and inside an uncommitted signed
write, fencing, trigger enforcement, incompatible schema/binding, filesystem
attacks, and engine crash points at every boundary (claim, signed, RelayStore
submitted, broadcast marker, sent, ledger finalized, RelayStore completed) for
both destinations. Engine tests use a deterministic in-memory destination model
for reorganization, lost and ambiguous sends, bounded attempts, failed
execution, nonce conflicts, releases by another transaction (before any claim,
after signing, after a drop, and a front-run of our pending transaction),
rejected transfers, pauses, durable deferrals that do not starve later
transfers, a backlog of 300 approved transfers, RPC failures and tampering;
a child process holding a RelayStore lock covers the busy timeout. That model is not a chain adapter. These
are process-crash tests, not power-loss or storage-rollback proofs.

This change does not connect the engine to startup. Both `submitter:start`
paths still fail closed. A production adapter must still provide independent,
bounded canonical observations for every decision.

## Cronos testnet submitter

### Manifest

`submitter:start cronos` runs only with this exact schema in the root-owned
manifest (same file, ownership and release rules as the disabled manifest).
Every value is pinned; nothing is discovered or defaulted. Unknown or missing
fields, type coercions, getters, mainnet chain ID `25`, a Xitcoin destination,
non-checksummed addresses, the empty-code hash and RPC URLs with credentials,
query strings or fragments are rejected. Endpoints must be independent HTTPS
origins; loopback `http` is accepted only with `allowLoopbackHttp: true`, for
reviewed local tunnels. The manifest never contains a key or password.

```json
{
  "version": 1,
  "mode": "testnet",
  "destination": "cronos",
  "releaseCommit": "RELEASE_COMMIT",
  "routeId": "cronos-testnet-xitcoin-testnet",
  "cronosChainId": 338,
  "xitcoinChainId": "xitcoin-testnet-v2-1",
  "relayStorePath": "/var/lib/xitcoin-bridge/coordinator/relay.sqlite",
  "ledgerPath": "/var/lib/xitcoin-bridge/submitter-cronos/broadcast-ledger.sqlite",
  "keystorePath": "/var/lib/xitcoin-bridge/submitter-cronos-keystore/keystore.json",
  "cycleIntervalMs": 5000,
  "cronos": {
    "rpcUrls": ["http://127.0.0.1:18545", "http://127.0.0.1:18546"],
    "allowLoopbackHttp": true,
    "vault": "0x1c94273C0b199b139D82da3786C9eCbE189D5919",
    "vaultCodeHash": "VAULT_RUNTIME_CODE_HASH",
    "cronosRouteId": "0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9",
    "signerSetVersion": "1",
    "authorizedSigners": ["SIGNER_1", "SIGNER_2", "SIGNER_3"],
    "submitter": "SUBMITTER_ACCOUNT",
    "confirmations": 12,
    "maxAmount": "100000000000000000000",
    "gasLimit": "400000",
    "maxGasPrice": "10000000000000",
    "maxFee": "4000000000000000000",
    "minDeadlineMarginSeconds": 120,
    "maxBroadcastAttempts": 5
  },
  "xitcoin": {
    "rpcUrls": ["http://127.0.0.1:26657", "http://127.0.0.1:26658"],
    "allowLoopbackHttp": true,
    "safetyLag": 2
  }
}
```

Placeholders are intentionally invalid. Bounds: `confirmations` 2–10000,
`gasLimit` 21000–10000000, `maxGasPrice` at most 10000 gwei, `maxFee` must cover
`gasLimit * maxGasPrice`, `minDeadlineMarginSeconds` 30–3600,
`maxBroadcastAttempts` 1–32, `cycleIntervalMs` 1000–60000, 2–4 RPC origins per
chain. `cronosRouteId` must equal the deployed testnet vault route
(`TESTNET_ROUTE_ID`), never a hash of the Xitcoin route label. The signer set
and version must equal the vault's on-chain values. `vaultCodeHash` is
`keccak256(eth_getCode(vault))` of the deployed runtime code. The runtime code
embeds immutables (asset, route, EIP-712 chain and address), so the hash is
deployment-specific: compute it from the deployment on independent providers
and cross-check it against a reproducible build of the pinned contracts commit
with those immutables before pinning it.

`check` validates the manifest and release offline and reports
`mode: "testnet"`, `ready: false`, `submissions: 0`. Only `start` performs
chain, vault, keystore and durable-state checks.

### Startup and process model

`start` loads the manifest and release, then refuses unless every RPC origin
reports chain ID `338`. It loads the submitter key only through the existing
secure keystore adapter (`keystorePath` owned by the service identity, mode
`0600`, password from the systemd credential `keystore-password` in
`$CREDENTIALS_DIRECTORY`; no environment-variable or command-line secret) and
requires the decrypted account to equal `submitter`. It opens the existing
RelayStore (never creating an empty one) and the broadcast ledger bound to the
vault, code hash and submitter account, then runs one durable cycle per
`cycleIntervalMs`. Any halt, disagreement, transport failure or unavailable
dependency stops the process with a stable code; it does not restart itself.
SIGTERM finishes the current cycle and releases the worker lease.

### Transport

Each RPC origin uses a bounded JSON-RPC client: one overall deadline covers
connection, headers and every body read; streamed bytes are counted against a
fixed limit before retention and before JSON parsing; parsed JSON is bounded in
depth and node count; redirects are refused; JSON-RPC version and request ID
must match; errors are reduced to stable codes without URLs or upstream text.
Every origin must answer every query. Identity reads must agree exactly across
origins. The Xitcoin CometBFT client receives only byte-bounded bodies through
the same transport.

### Checks before signing (nothing is claimed if any fails)

- every origin reports chain ID `338`;
- at the finalized height (`tip - confirmations`, identical block hash on every
  origin): vault runtime code hash equals the pinned hash, `routeId()` equals
  the pinned route, `signerSetVersion()` equals the pinned version and
  `signers()` equals the pinned set;
- the persisted approval request is exactly what the coordinator derives from
  the stored finalized source transfer, route, vault and signer version, and the
  stored approvals form a recovered, authorized, strictly ordered 2-of-3 quorum
  with vault-compatible recovery bytes (`27`/`28`);
- the deadline leaves at least `minDeadlineMarginSeconds` against both the local
  clock and the latest block timestamp; otherwise the transfer waits for
  re-issue;
- amount within `maxAmount` and the vault's `maxReleaseAmount`; recipient is a
  valid nonzero, non-dead address;
- on every origin at the latest block: vault not paused (`route_paused` waits),
  `processedBurns(sourceBurnId)` false (all true halts permanently,
  mixed waits), liquidity at least the amount;
- the Xitcoin source burn is re-verified as canonical and finalized on
  independent CometBFT origins;
- gas price (maximum across origins) within `maxGasPrice`; `eth_estimateGas`
  within `gasLimit` and an `eth_call` simulation of the exact release succeed
  on every origin; the submitter balance covers `gasLimit * gasPrice`;
- account nonce: `latest` equals `pending` on every origin (no foreign pending
  transaction) and equals the ledger's next nonce (after the first transfer).

The submitter signs one legacy (type 0) EIP-155 transaction for chain `338` with
`gasLimit` from the manifest and the observed gas price. The reviewed release
plan and signed-byte inspector re-check every field before the ledger commits
the bytes, hash and nonce. Then RelayStore records `submitted` with that hash,
the broadcast marker is committed, and the identical bytes are sent to every
origin. Before the first send the nonce, pause, replay flag, deadline and a
simulation of the exact signed transaction are checked again.

### Confirmation

A transfer completes only when, on every origin: the receipt is identical and
names the submitter, the vault and the persisted hash; the provider transaction
equals the persisted bytes field by field (input, nonce, gas, price, value,
chain, signature); its block is canonical; exactly one non-removed `Released`
event from the vault matches source burn ID, recipient, amount and signer
version (the transaction input binds every approved field, including the
deadline and signatures); the block is at least `confirmations` deep; and
`processedBurns` is true at the finalized height. Then the ledger records
`finalized` and only afterwards RelayStore records `completed`.

Recovery decisions (all from canonical observations, never from send errors):

| Observation | Action |
| --- | --- |
| receipt absent on some origins | wait (indexing lag) |
| receipts differ between origins, or content disagrees | stop (`rpc_disagreement`) |
| transaction pending on any origin | wait |
| unknown everywhere, nonce unused, not processed, not paused, deadline margin intact, attempts left | resend the identical persisted bytes |
| unknown everywhere and the account nonce advanced | halt `nonce_consumed_without_receipt` |
| a foreign pending transaction from the account | halt `foreign_pending_transaction` |
| replay processed by another transaction | halt `processed_by_foreign_transaction` |
| deadline margin lost before inclusion | halt `approval_expired_before_inclusion` |
| receipt, event or input mismatch | halt |
| reorganized block | wait, then observe again (resend identical bytes if dropped) |
| finalized failed execution (status `0`) | ledger `failed`; stop; never retried |

### Tests

`test/cronos-submitter-evm.test.js` runs the complete flow on a local anvil
chain with chain ID `338`, two independent fault-injecting JSON-RPC origins,
two fake CometBFT origins and the vendored reviewed vault, compiled with forge
(solc 0.8.30, optimizer 200, `paris`, OpenZeppelin 5.4.0). Vendored sources are
checked against their git blob hashes in `test/evm/provenance.json`: the vault
recorded for the deployed testnet vault (`d3ae705`) and current contracts main
(`96ee420`). Scenarios: approve, release and complete on both vault versions;
concurrent workers, a later worker and an independent ledger (no second
release); SIGKILL in a child process at every boundary (claimed, signed,
RelayStore submitted, broadcast marker, sent, ledger finalized, RelayStore
completed) followed by recovery with exactly one transaction; a reorganization
that removes the release (identical bytes resent) and one that replaces it with
a foreign use of the nonce (halt); a paused route until a quorum-signed resume;
a finalized failed execution; RPC disagreement on chain ID, code and blocks;
ambiguous and lost send responses; forged receipt events and transaction input
from every origin; foreign nonce use before signing and after signing; expired
approvals; code hash, signer set and chain ID `25` mismatches; source events
that do not match or that origins disagree on; and a stored request that no
longer matches its source transfer. CI installs Foundry `v1.8.5` and runs these
tests on every change; locally they are skipped only if Foundry is missing.
Transport, manifest, CLI and systemd tests cover the bounded reads, every
manifest field and the stable error codes. Keys are synthetic and local only.

These tests do not contact Cronos testnet, use real keys or prove behaviour
under power loss. Cronos testnet support for legacy transactions, its gas price
behaviour and its RPC providers must still be confirmed in the controlled
canary.

### Deployment requirements (not performed by this repository)

- Pin `vaultCodeHash`, the signer set and version from independent observations
  of the deployed vault. The deployed testnet vault was built from contracts
  `d3ae705`, before the exact release accounting and deposit-limit changes on
  contracts main; decide whether to redeploy before the canary.
- Share the RelayStore between the coordinator and this submitter through a
  reviewed arrangement (dedicated group, permissions on the database, WAL and
  SHM files and directory); the submitter performs only the `approved ->
  submitted -> completed` transitions for outbound transfers. This is a new
  write path into coordinator state and must be reviewed as such.
- Provision a dedicated submitter account, used by no other program, funded with
  test CRO only; its encrypted keystore and the encrypted `keystore-password`
  credential; a private `StateDirectory` (mode `0700`) for the ledger; and
  loopback tunnels to independent RPC providers. See
  `ops/systemd/xitcoin-bridge-submitter-cronos-testnet.service`.
- Back up the ledger like a key; never delete, copy between hosts or restore an
  old copy. A `failed` or `halted` row stops the submitter until an offline
  review procedure (not defined in this release) resolves it.

### Remaining before the bridge can run end to end

- Xitcoin destination: adapter, transaction envelope and a canonical
  attestation-status query exposed by the chain. Until then the Cronos to
  Xitcoin direction cannot be submitted and the two-direction canary cannot run.
- Coordinator re-issue of expired approvals for transfers already `approved`
  but not submitted (the submitter waits on them).
- Reconciler chain readers (vault locked balance and chain outstanding amount).
- An offline review procedure for halted or failed ledger rows.
- Deployment, preflight extension for the submitter manifest, the controlled
  canary and an independent security review.
