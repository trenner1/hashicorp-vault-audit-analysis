#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON=${PYTHON:-python3}
VENV_DIR=${VENV_DIR:-.venv}

if [ -d "$VENV_DIR" ]; then
  echo "Virtualenv $VENV_DIR already exists. Activate it with: source $VENV_DIR/bin/activate"
  exit 0
fi

echo "Creating virtualenv at $VENV_DIR using $PYTHON..."
$PYTHON -m venv "$VENV_DIR"

echo "Upgrading pip and installing requirements..."
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
else
  echo "No requirements.txt found; skipping pip install"
fi

echo "Virtualenv created. Activate with: source $VENV_DIR/bin/activate"
