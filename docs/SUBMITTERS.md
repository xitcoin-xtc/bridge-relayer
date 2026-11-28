# Destination submitters: phase one

This release provides an offline configuration check and a fail-closed startup
boundary for `xitcoin` and `cronos`. Neither destination is operational for
transactions. A successful `check` reports `ready: false`, `submissions: 0` and
a destination-specific blocker. `start` exits nonzero for both destinations.
There is no credential loader, wallet, RPC client, database access, adapter
plugin, signing path or broadcast path in this runtime.

## Manifest and immutable release

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

`npm run submitter:start -- <destination> <manifest>` is intentionally blocked.
The systemd template uses that same public startup path, denies IP networking,
disables core dumps and does not restart a blocked process. Keep both instances
disabled. Check success is not readiness, preflight success or authorization.

## Exact gaps before any transaction-capable phase

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
- one row per transfer (`claimed`), created only by the lease holder, and at
  most one unfinished transfer per account;
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
- a claimed row has no bytes and was never sent, so it may be rebound to a
  re-issued approval. Once bytes exist the approval digest is permanent.

SQLite triggers repeat these rules (no delete, no regression, no replacement,
sequential nonce, monotonic lease epoch) as defense in depth against
accidental raw writes. Every read rehashes stored bytes. The bytes are opaque
to the ledger; the destination adapter validates them against the approved
request on every use. As with the offline journals, a malicious local owner,
root, or a consistent restore of an older database is outside SQLite
self-consistency guarantees and is not detected.

`runDurableSubmissionCycle` composes the ledger with RelayStore and a trusted
destination adapter (chain reads, signing and byte validation). It owns the
ordering:

1. reject any blocking ledger row; reconcile RelayStore `submitted` rows,
   which must reference a transaction the ledger holds;
2. read the persisted approval request and approvals under size bounds and
   bind their exact stored text by SHA-256 (`requestHash`). The adapter
   revalidates the request against the transfer, route and authorized quorum
   and decides `sign`, `wait` (for example a paused route or an expired
   approval awaiting re-issue; nothing is claimed) or `halt`;
3. claim, sign, and commit the bytes before anything else;
4. bind RelayStore to that single transaction hash (`approved -> submitted`);
5. commit the broadcast marker, then send the identical bytes. Send errors are
   never decision inputs, and the first observation happens in a later cycle;
6. observe: `pending`, `wait`, `rebroadcast` (identical bytes only, when the
   adapter proves the transaction is unknown and its nonce unused), `failed`
   (finalized failed execution; permanent and blocking), `finalized`, or a
   persisted `halt`;
7. complete RelayStore only after the ledger records finality.

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
execution, nonce conflicts, replay processed elsewhere, pauses, expired
approvals, RPC failures and tampering. That model is not a chain adapter. These
are process-crash tests, not power-loss or storage-rollback proofs.

This change does not connect the engine to startup. Both `submitter:start`
paths still fail closed. A production adapter must still provide independent,
bounded canonical observations for every decision.
