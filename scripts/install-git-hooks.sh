#!/usr/bin/env bash
# Install local git hooks from .githooks into .git/hooks
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GITHOOKS_DIR="$ROOT_DIR/.githooks"
GIT_HOOKS_DIR="$ROOT_DIR/.git/hooks"

if [ ! -d "$GIT_HOOKS_DIR" ]; then
  echo ".git/hooks not found. Are you in a git repository?" >&2
  exit 1
fi

for hook in "$GITHOOKS_DIR"/*; do
  name=$(basename "$hook")
  cp "$hook" "$GIT_HOOKS_DIR/$name"
  chmod +x "$GIT_HOOKS_DIR/$name"
  echo "Installed $name"
done

echo "Git hooks installed. To revert, remove files from .git/hooks." 
exit 0