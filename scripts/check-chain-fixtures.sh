#!/usr/bin/env bash
# Checks the chain-derived test fixtures against a pos-chain checkout of the
# pinned commit (test/fixtures/xitcoin-chain-vectors.json "posChainCommit"):
#   - every schema under test/fixtures/proto is byte-identical to its source in
#     pos-chain or in the Cosmos SDK module version pos-chain pins;
#   - test/fixtures/xitcoin-chain-vectors.json is exactly what the chain's own
#     Go code produces (test/reference/xitcoin-chain-vectors/main.go).
# Usage: scripts/check-chain-fixtures.sh /path/to/pos-chain
# Read-only for both repositories except a throwaway generator package that
# is created inside the given checkout and removed afterwards.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pos_chain="$(cd "${1:?usage: check-chain-fixtures.sh POS_CHAIN_DIR}" && pwd)"
vectors="$repo_root/test/fixtures/xitcoin-chain-vectors.json"
pinned="$(sed -n 's/^  "posChainCommit": "\([0-9a-f]\{40\}\)",$/\1/p' "$vectors")"
actual="$(git -C "$pos_chain" rev-parse HEAD)"
if [[ -z "$pinned" || "$pinned" != "$actual" ]]; then
  echo "pos-chain checkout $actual is not the pinned commit ${pinned:-<missing>}" >&2
  exit 1
fi

# The SDK module (pos-chain replaces it with its fork) must be in the module
# cache before its directory can be listed.
(cd "$pos_chain/evmd" && go mod download github.com/cosmos/cosmos-sdk)
sdk="$(cd "$pos_chain/evmd" && go list -m -f '{{.Dir}}' github.com/cosmos/cosmos-sdk)"
if [[ -z "$sdk" || ! -d "$sdk/proto" ]]; then
  echo "Cosmos SDK module source not found" >&2
  exit 1
fi
status=0
check() {
  if ! cmp -s "$repo_root/test/fixtures/proto/$1" "$2"; then
    echo "test/fixtures/proto/$1 differs from $2" >&2
    status=1
  fi
}
check xitcoin-tx.proto "$pos_chain/proto/cosmos/evm/bridge/v1/tx.proto"
check xitcoin-query.proto "$pos_chain/proto/cosmos/evm/bridge/v1/query.proto"
check xitcoin-bridge.proto "$pos_chain/proto/cosmos/evm/bridge/v1/bridge.proto"
check ethsecp256k1-keys.proto "$pos_chain/proto/cosmos/evm/crypto/v1/ethsecp256k1/keys.proto"
check cosmos-sdk-tx.proto "$sdk/proto/cosmos/tx/v1beta1/tx.proto"
check cosmos-sdk-tx-service.proto "$sdk/proto/cosmos/tx/v1beta1/service.proto"
check cosmos-sdk-abci.proto "$sdk/proto/cosmos/base/abci/v1beta1/abci.proto"
expected_protos=7
if [[ "$(find "$repo_root/test/fixtures/proto" -type f | wc -l | tr -d ' ')" != "$expected_protos" ]]; then
  echo "test/fixtures/proto contains an unchecked schema" >&2
  status=1
fi

generator="$pos_chain/evmd/cmd/relayervectors"
if [[ -e "$generator" ]]; then
  echo "$generator already exists" >&2
  exit 1
fi
trap 'rm -rf "$generator"' EXIT
mkdir -p "$generator"
cp "$repo_root/test/reference/xitcoin-chain-vectors/main.go" "$generator/main.go"
generated="$(mktemp)"
(cd "$pos_chain/evmd" && go run ./cmd/relayervectors "$actual") > "$generated"
if ! cmp -s "$generated" "$vectors"; then
  echo "test/fixtures/xitcoin-chain-vectors.json differs from the chain-generated vectors:" >&2
  diff "$vectors" "$generated" >&2 || true
  status=1
fi
rm -f "$generated"
exit "$status"
