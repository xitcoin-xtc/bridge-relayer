#!/usr/bin/env bash
# Every GitHub Action must be pinned to a full commit SHA, and every container
# image (docker:// action, job container or service) to an @sha256 digest.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

normalize() {
  local value="$1"
  value="${value%%[[:space:]]#*}"
  value="${value//\"/}"
  value="${value//\'/}"
  value="${value//[[:space:]]/}"
  printf '%s' "$value"
}

while IFS= read -r entry; do
  file="${entry%%:*}"
  value="$(normalize "${entry#*:}")"

  case "$value" in
    ./*) continue ;;
    docker://*)
      if [[ ! "$value" =~ ^docker://[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]]; then
        printf 'Docker action without an @sha256 digest: %s: %s\n' "$file" "$value" >&2
        status=1
      fi
      continue ;;
  esac

  if [[ ! "$value" =~ ^[^/@]+/[^@]+@[0-9a-f]{40}$ ]]; then
    printf 'Mutable or invalid GitHub Action reference: %s: %s\n' "$file" "$value" >&2
    status=1
  fi
done < <(
  grep -RHE '^[[:space:]-]*uses:[[:space:]]*' "$repo_root/.github/workflows" |
    sed -E 's/^([^:]+):[[:space:]-]*uses:[[:space:]]*/\1:/'
)

while IFS= read -r entry; do
  file="${entry%%:*}"
  value="$(normalize "${entry#*:}")"
  if [[ -n "$value" && ! "$value" =~ @sha256:[0-9a-f]{64}$ ]]; then
    printf 'Container image without an @sha256 digest: %s: %s\n' "$file" "$value" >&2
    status=1
  fi
done < <(
  grep -RHE '^[[:space:]-]*(image|container):[[:space:]]*[^[:space:]#]' "$repo_root/.github/workflows" |
    sed -E 's/^([^:]+):[[:space:]-]*(image|container):[[:space:]]*/\1:/' || true
)

exit "$status"
