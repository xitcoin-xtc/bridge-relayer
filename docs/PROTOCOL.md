# Canonical bridge protocol

## Route identity

The human-readable route identifier is a lower-case string accepted by the
Xitcoin bridge module. The Cronos vault stores a deployment-pinned `bytes32`
route identifier. A deployment must publish and bind both values explicitly;
the relayer must never assume that the deployed Cronos value can be derived
from the Xitcoin display identifier.

For the canonical testnet deployment, the Xitcoin route is
`cronos-testnet-xitcoin-testnet`, while the Cronos route is
`0x21121c16b53a726056a6683f00c7eb4da5501ce8a2abc8a4677e06f1e94b5cd9`
on Cronos EVM chain ID `338`.

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

An approval request carries a deadline. The coordinator never reuses a
persisted request after its deadline and never replaces one before it. Once the
deadline plus `APPROVAL_REISSUE_GRACE_SECONDS` (120 s) has passed, it re-issues
the request for the same source event with a new deadline: same replay key,
same destination, amount, nonce and route; only the deadline (and, for
releases, the vault signer-set version) may change. Approvals collected for the
expired digest are discarded. The grace period covers destination block time
lagging the relayer clock. Re-issue is safe because the destination replay key
does not depend on the deadline.

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
- a re-issue that changes only the deadline (or release signer-set version) is
  signed only after the previously signed deadline plus the grace period;
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
