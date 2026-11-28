# Xitcoin Bridge Relayer

Public protocol and operational tooling for the canonical XTC route between
Cronos and Xitcoin.

This repository separates three responsibilities:

- watchers observe finalized source-chain events;
- a coordinator builds deterministic payloads and records their lifecycle;
- independent signers validate payloads and return approvals.

The coordinator never stores signer private keys. A threshold approval does not
replace source-chain finality checks, route limits, replay protection or the
destination-chain validation performed by the Xitcoin bridge module and the
Cronos vault.

## Current scope

The current foundation provides canonical identifiers, address conversion,
EIP-712 release digests, Xitcoin attestation digests, lifecycle persistence,
portable test vectors and finalized source watchers. Cronos observations require
agreement between independent RPC providers, a configured confirmation depth and
a canonical receipt re-check. Xitcoin observations require matching CometBFT
chain identity, block hashes and decoded outbound messages from independent
clients. Hardened network adapters pin chain identities, reject embedded RPC
credentials and require independent HTTPS origins. The restart-safe scan loop
advances checkpoints only after a second canonical event and block verification.
Xitcoin message decoding remains an explicit canonical dependency rather than a
heuristic event parser. The approval coordinator requests bounded HTTPS
responses from isolated signers, recovers each signer locally, persists an
immutable deterministic 2-of-3 quorum and remains restart-safe. The coordinator
itself never submits transactions; destination submission is a separate,
explicitly enabled process (below). The isolated
signer service enforces a pinned route, source and destination chain, vault,
amount and deadline, requires an independent canonical-finality verifier, keeps
a durable journal that refuses a second, different request for the same source
event, and delegates signing to an injected key provider. An expired
approval is re-issued with a new deadline for the same source event only after
the destination shows it dead (its deadline passed at a final height and the
transfer unprocessed, agreed by every origin); the coordinator and every
signer check this independently, and signers sign only an explicit, journaled
re-issue. An approved transfer is re-issued only after its destination
submitter gives the expired approval up. A
read-only reconciler compares the vault's locked balance at a finalized Cronos
height with the bridge module's outstanding amount at a pinned Xitcoin height
(every origin must agree) and raises alerts (dry-run by default; it never
pauses anything by itself). The optional secure keystore adapter reads bounded,
owner-private encrypted keystores and systemd credentials, verifies the expected
account and exposes only digest signing; it has no environment-variable or
command-line password fallback. Runtime
composition validates separated identities and independent RPC origins, halts
on critical worker failure, and exposes bounded liveness and readiness state.
Hardened systemd units are provided as disabled review-only templates.

The read-only live preflight is available through `npm run preflight:testnet --
/absolute/path/to/testnet-preflight.json`. It verifies the isolated host layout,
disabled services, independent RPC identities and the deployed paused Cronos
vault. It cannot load keys, sign, broadcast or start bridge services.
The deterministic staging harness composes the real public lifecycle functions
with in-memory adapters to rehearse one-signer loss, RPC disagreement, crash
recovery and duplicate-broadcast prevention without contacting a network.
The testnet preflight validates a commit-pinned release, separated locked
identities, private paths, disabled services and independently verified chain
identities before any canary is authorized. It pins Cronos EVM Testnet chain ID
`338`, Xitcoin chain ID `xitcoin-testnet-v2-1` and rejects Cronos mainnet chain
ID `25`.
The controlled-canary plan binds a short authorization window to the release
and preflight digests, permits exactly one bounded transfer in each direction,
stops on any safety violation and emits only sanitized transaction evidence.

## Validation

```bash
npm ci
npm run check
npm test
npm run vectors
bash scripts/verify-actions-pinned.sh
```

CI additionally scans the Git history for secrets (gitleaks, image pinned by
digest), reviews dependency changes for high and critical advisories, audits
production dependencies and requires every action to be pinned to a full commit
SHA and every container image to an `@sha256` digest. Dependabot proposes npm
and GitHub Actions updates weekly. A CI job checks out pos-chain at the commit
pinned in `test/fixtures/xitcoin-chain-vectors.json`, checks the proto fixtures
and the chain-generated vectors against it (`scripts/check-chain-fixtures.sh`)
and builds the `xitcoind` binary (cached) that the Xitcoin integration tests
run against (`XITCOIND_BIN`; locally they are skipped without it).

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

The public destination submitters use strict root-owned manifests, immutable
release binding and offline checks for `xitcoin` and `cronos`. `disabled` is the
default for both. An explicit `testnet` manifest enables the
[Cronos testnet submitter](docs/SUBMITTERS.md#cronos-testnet-submitter) for
Cronos EVM Testnet chain ID `338` only (mainnet `25` is rejected): pinned vault
code, route, signer set, account and fee caps; bounded independent RPC reads;
Xitcoin source finality; and receipt, `Released` event and transaction-input
verification with finality depth. Another explicit `testnet` manifest enables
the [Xitcoin testnet submitter](docs/SUBMITTERS.md#xitcoin-testnet-submitter)
for chain ID `xitcoin-testnet-v2-1` only (mainnet `xitcoin` is rejected): one
signed SIGN_MODE_DIRECT eth_secp256k1 transaction carrying
`MsgSubmitAttestation` per Cronos deposit, encoded exactly as the chain's own
Go code encodes it, with the stored route ID, sequence ownership, gas from
simulation with headroom and bounded fees; bounded independent CometBFT and
REST reads; Cronos source finality; and completion only on the typed
attestation record naming our transaction and approval (pos-chain
`xitcoin-security-hardening-v2`, not yet deployed on testnet). Both are built
on a destination-generic
[durable broadcast ledger](docs/SUBMITTERS.md#durable-broadcast-ledger) that
commits an exclusive claim and the exact signed transaction before any send and
recovers without ever creating a second transaction. Nothing here deploys or
starts a service; see
[remaining work](docs/SUBMITTERS.md#remaining-before-the-bridge-can-run-end-to-end).
