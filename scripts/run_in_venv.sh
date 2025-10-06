#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
VENV_DIR=${VENV_DIR:-.venv}

if [ ! -d "$VENV_DIR" ]; then
  echo "Virtualenv $VENV_DIR not found. Run ./setup_venv.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

# Export env vars from .env.example if present (do not overwrite existing vars)
if [ -f .env.example ]; then
  # load lines of the form KEY=VALUE
  set -a
  # shellcheck disable=SC1091
  . ./.env.example
  set +a
fi

# Run the run.sh helper which will wait for the external Vault and run the counter
./run.sh
