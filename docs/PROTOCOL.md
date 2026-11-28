# Canonical bridge protocol

## Route identity

The Xitcoin bridge module stores one route ID: a string of 1 to 96 bytes from
`[a-z0-9_-]`. The chain compares it byte for byte with the `route_id` of every
`MsgSubmitAttestation` (otherwise `ErrAttestationRouteMismatch`), hashes it
verbatim into every approval digest (below) and emits it as `route_id` in
every `bridge_outbound_burned` event. The Cronos vault stores a
deployment-pinned `bytes32` route ID. A deployment must publish and bind both
values explicitly; the relayer never derives one from the other or from a
display label.

On `xitcoin-testnet-v2-1` the route was initialised with the Cronos `bytes32`
route ID in its stored form, `0x`-prefixed lower-case hex:

| Value | Testnet |
| --- | --- |
| Xitcoin route ID (stored by the bridge module; signed, submitted and compared by the relayer) | `0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9` |
| Cronos vault route ID (`routeId()`, chain ID `338`) | `0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9` |

The two values are equal on testnet; the relayer still pins them separately
(`XITCOIN_TESTNET_ROUTE_ID` in `src/protocol.js`, `TESTNET_ROUTE_ID` in
`src/preflight.js`). The display label `cronos-testnet-xitcoin-testnet`, which
earlier releases signed and submitted, is not a route the chain knows: every
attestation carrying it would fail with `ErrAttestationRouteMismatch`, and
every outbound event would mismatch the watcher's pinned route.
`test/fixtures/xitcoin-chain-vectors.json` records the digests and the
`MsgSubmitAttestation` bytes the chain's own Go code produces for the stored
route ID; CI regenerates it from the pinned pos-chain commit.

## Cronos to Xitcoin

1. A user calls `CronosBridgeVault.deposit(amount, recipient)`.
2. `recipient` is an EVM address representing the same 20 account bytes used by
   Xitcoin. The relayer converts those bytes to the configured Xitcoin Bech32
   prefix; it does not derive or change the account.
3. The watcher waits for the configured Cronos confirmation depth and rejects
   logs removed by a chain reorganization.
4. The canonical source reference is the emitted `depositId`, without `0x` and
   in lower case. The emitted `nonce` is the attestation nonce.
5. Signers approve the Xitcoin attestation digest only after independently
   checking the finalized receipt, vault address, route, asset and amount.
6. The coordinator submits two distinct approvals to `MsgSubmitAttestation`.

This is attestation protocol v2 (pos-chain `x/bridge/types/attestation.go`,
`signatures.go`, `domain.go`; relayer `src/protocol.js`). Both sides are
checked against the same vectors in `test/fixtures/attestation-cross-check.json`
and pos-chain `x/bridge/types/remediation_test.go`.

### Replay key (attestation ID)

The attestation ID is the replay-protection key and identifies only the source
deposit. It is SHA-256 over these UTF-8 fields joined by a zero byte:

```text
xitcoin-bridge-source-deposit-v1
source_chain_id      canonical decimal EVM chain ID, for example 338
source_ref           depositId, lower-case hex without 0x
```

`depositId` already commits to the Cronos chain ID, vault, route, depositor,
recipient, amount and deposit nonce. The deadline and every other signed field
are excluded on purpose: two approvals for one deposit (for example a
re-issued approval with a later deadline) share one replay key, so the chain
mints a deposit at most once. `xitcoind query bridge source-deposit-key` and
`attestation-status` use the same key.

### Signed payload

The approval digest is a raw digest (no Ethereum personal-sign prefix):

```text
domain        = "xitcoin-bridge-attestation-v2/" || xitcoin_chain_id
payload_hash  = SHA-256(join(0x00,
                  xitcoin_chain_id, route_id, direction, source_chain_id,
                  source_ref, nonce, destination, amount, deadline_unix))
digest        = keccak256(UTF8(domain) || payload_hash)
```

`xitcoin_chain_id` is the destination chain (`xitcoin-testnet-v2-1`, `xitcoin`).
The chain uses its own chain ID, so an approval produced for one network is
invalid on every other network. In the approval request the coordinator sends
it as `payload.destinationChainId`; it is not a field of `MsgSubmitAttestation`.

The chain additionally requires `source_chain_id` to equal the route's
`source_chain_id` (`25` on mainnet, `338` on Cronos Testnet routes).

### Migration from v1

v1 used the fixed domain `xitcoin-bridge-testnet-attestation-v1` on every
network, hashed every field including the deadline into the replay key, and did
not bind the Xitcoin chain ID. v1 approvals are rejected by a v2 chain and v2
approvals by a v1 chain, so the relayer, every signer and the chain binary must
be upgraded together. No v1 transfer was ever processed (the testnet route is
disabled and paused), so no replay state needs migrating. Guardian-pause and
route-control signatures moved to `xitcoin-bridge-guardian-pause-v2/<chain id>`
and `xitcoin-bridge-control-v2/<chain id>` in the same release.

## Xitcoin to Cronos

1. The owner submits `MsgInitiateOutboundTransfer` on Xitcoin.
2. Xitcoin transfers the owner's native `axtc` to the bridge module and performs
   a real burn.
3. The canonical `request_id` emitted by Xitcoin becomes the Cronos
   `sourceBurnId`.
4. Signers independently verify the finalized burn and approve the vault's
   EIP-712 `Release` payload.
5. Any submitter may relay the two approvals to the Cronos vault.

The EIP-712 domain is bound to the Cronos chain ID and deployed vault address.
The payload includes the current signer-set version and an expiry.

## Idempotency

Every source reference is unique within its source chain and route. The local
store rejects lifecycle regression, while both destination implementations
enforce their own replay protection: the Xitcoin module by source deposit
(attestation ID above), the Cronos vault by `sourceBurnId`. Local completion is
recorded only after a finalized destination receipt.

## Expired approvals

An approval request carries a deadline. Both destinations accept an approval
only while the executing block's time is at or before it (the vault's
`release` reverts when `block.timestamp > deadline`; the bridge module's
`Attestation.ValidateAt` fails when `ctx.BlockTime() > deadline_unix`), and
block time never decreases. The coordinator never reuses a persisted request
after its deadline and never replaces one before it. A re-issue is a new
request for the same source event with a new, strictly later deadline: same
replay key, same destination, amount, nonce and route; only the deadline (and,
for releases, the vault signer-set version) may change. Re-issue never creates
a second usable approval:

1. The previous approval must be provably dead on its destination
   (`src/approval-retirement.js`): at one final height H that every origin
   serves, with the identical block and answers from every origin, block H's
   time is strictly later than the previous deadline, and the replay key is
   unused at H (Cronos: `processedBurns(sourceBurnId)` is false at
   `tip - confirmations`; Xitcoin: the attestation query at the lowest
   committed height returns `ATTESTATION_STATE_ABSENT`). No later block can
   accept the previous approval, and it was not used before H. A processed
   replay key is never a reason to re-issue.
2. The coordinator checks this itself, after the local
   `APPROVAL_REISSUE_GRACE_SECONDS` (120 s) filter, before it asks signers.
3. Every signer checks it again itself before signing (below), and signs only
   a request that carries the explicit re-issue declaration
   `reissue: { previousDigest, previousDeadlineUnix }` next to the canonical
   request (never inside the signed payload).

Two usable 2-of-3 approvals for one source event would need a signer common to
both quorums, and that signer signs the second only after the first is dead on
the destination, so at most one usable approval per source event exists at any
time, whatever the coordinator does.

The coordinator re-issues in two situations:

- a `finalized` transfer whose persisted request expired before a quorum was
  collected: the request is replaced (the expired request and any approvals
  for it are archived in RelayStore `approval_history`);
- an `approved` or `submitted` transfer whose destination submitter gave its
  approval up (RelayStore `reissue_requested`, written only by the submitter):
  the approval reached its deadline before the submitter sent anything, or the
  submitter's identical bytes were mined after the deadline and reverted
  (`expired`). The submitter names the digest it will never send and the only
  transaction it holds for it, and never claims the transfer under that
  approval again. After the destination proof, the transfer returns to
  `finalized` with the re-issued request (the old request, approvals and
  destination transaction are archived) and is approved again through the
  normal path. The submitter then sends it, as a new attempt for an `expired`
  row (see [SUBMITTERS.md](SUBMITTERS.md#durable-broadcast-ledger)).

A transfer the submitter rejected (for example an invalid recipient) never asks
for a re-issue and stays rejected; its refund path is manual
([OPERATIONS.md](OPERATIONS.md#deposits-that-cannot-mint-and-refunds)).

## Signer approval journal

Every signer keeps a durable SQLite journal (`src/signer-journal.js`, config
field `journalPath`) of what it signed, keyed by source event: the Xitcoin
replay key for deposits, and Cronos chain ID, vault and `sourceBurnId` for
releases. Before signing it applies these rules, independently of the
coordinator:

- the identical request returns the identical stored signature;
- a request for the same source event with any different content
  (destination, amount, nonce, route, chain, vault, recipient) is refused,
  permanently;
- a request that changes only the deadline (or release signer-set version) is
  refused unless it is an explicit re-issue: it carries the re-issue
  declaration, its deadline is strictly later than both the declared and the
  signed deadline, the signed deadline plus the grace period has passed on the
  signer's clock, and the signer's own destination check (the bounded quorum
  transports over its configured Cronos RPC and Xitcoin RPC and REST origins)
  shows that no approval with a deadline up to the later of the two can still
  be used. A signer that never signed for the source event still checks the
  declared deadline. Each re-issue is appended, with that evidence
  (destination, height, block time), to the journal's append-only
  `approval_reissues` table in the same transaction as the new signature;
- a source event closed by an operator (`npm run signer:journal -- close ...`,
  used for refunds) is never signed again.

The row is committed (`synchronous=FULL`) before the signature leaves the
service; if the conditional write fails the signature is discarded.

## Approval coordinator

The coordinator never receives private keys. It sends the complete canonical
payload and its independently recomputed digest to three isolated signer
services. Every returned signature is recovered locally against the currently
authorized three-address signer set. Exactly two distinct valid approvals are
selected in deterministic address order and persisted before the lifecycle is
advanced to `approved`.

Signer services must recompute the digest and re-check the finalized source
event themselves. Each response is verified on its own: a mismatched digest,
unauthorized or duplicate signer, wrong chain/vault domain or malformed
response is discarded and never counted, and an unavailable signer is skipped.
The round succeeds only with two distinct valid approvals; otherwise it fails
with the list of rejection reasons and nothing is recorded. An expired request
or a conflicting previously persisted request stops processing. Approval
collection does not submit a transaction to either destination chain.

## Destination submission

An approved transfer is checked against the destination replay key before broadcast. Cronos uses `sourceBurnId`; Xitcoin uses `attestationId` (the source-deposit key). A recovered processed record must include a canonical transaction reference. A submission becomes completed only after the finalized receipt/event matches every bound field. RPC disagreement or a mismatched event stops processing.

On Xitcoin the replay state is read with the typed query
`GET /xitcoin/bridge/v1/attestations/{attestation_id}` (pos-chain
`xitcoin-security-hardening-v2`). `ATTESTATION_STATE_ABSENT` only means that no
committed transaction consumed the key at the answering `height`; it never
proves that no submission is pending, so the submitter decides pending sends
from its broadcast ledger, CometBFT `tx_search` and mempool lookups and the
account sequence. `ATTESTATION_STATE_PROCESSED` carries the record of the
processing transaction (every approved field, the destination chain ID, the
payload hash, the signing digest, the recovered approvers, the signer set
version, the block height and the CometBFT transaction hash); the submitter
completes its own transfer only when that record names its transaction and
approval, and records a release by another transaction when the approved
fields match. `ATTESTATION_STATE_PROCESSED_WITHOUT_RECORD` (processed before
records were kept) is treated as minted but unverified. See
[SUBMITTERS.md](SUBMITTERS.md#xitcoin-testnet-submitter).
