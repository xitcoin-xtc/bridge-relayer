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
immutable deterministic 2-of-3 quorum and remains restart-safe. Network
submission remains deliberately excluded. The isolated
signer service enforces a pinned route, source and destination chain, vault,
amount and deadline, requires an independent canonical-finality verifier, keeps
a durable journal that refuses a second, different request for the same source
event, and delegates signing to an injected key provider. Expired approval
requests are re-issued with a new deadline for the same source event. A
read-only reconciler compares vault and chain accounting and raises alerts
(dry-run by default; it never pauses anything by itself). The optional secure keystore adapter reads bounded,
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
```

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

The public destination submitter phase provides strict root-owned manifests,
immutable release binding and offline checks for `xitcoin` and `cronos`. Both
startup paths fail closed pending production adapters. See
[phase-one scope and exact gaps](docs/SUBMITTERS.md). A destination-generic
[durable broadcast ledger](docs/SUBMITTERS.md#durable-broadcast-ledger) commits
an exclusive claim and the exact signed transaction before any send and recovers
without ever creating a second transaction; it is not yet connected to startup.
The existing submission helper and staging adapters exercise status-first
recovery and idempotent completion; they do not provide a production broadcaster.
