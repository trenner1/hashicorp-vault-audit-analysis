#!/usr/bin/env bash
set -euo pipefail

# Helper to run counter.py against an existing Vault instance.
# It will poll VAULT_ADDR until it responds as healthy, then run the script.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
VAULT_TOKEN=${VAULT_TOKEN:-}
VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY:-1}

if [ -z "$VAULT_TOKEN" ]; then
  echo "Please set VAULT_TOKEN env or pass --token to counter.py." >&2
  exit 2
fi

echo "Waiting for Vault at $VAULT_ADDR to be healthy..."
RETRIES=60
COUNT=0
until curl -sSf --max-time 2 "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; do
  sleep 1
  COUNT=$((COUNT+1))
  if [ "$COUNT" -ge "$RETRIES" ]; then
    echo "Vault did not become healthy in time" >&2
    exit 1
  fi
done

echo "Running counter.py against $VAULT_ADDR"
if [ "$VAULT_SKIP_VERIFY" = "1" ] || [ "$VAULT_SKIP_VERIFY" = "true" ]; then
  python3 counter.py --token "$VAULT_TOKEN" --no-verify
else
  python3 counter.py --token "$VAULT_TOKEN"
fi

echo "Done."
