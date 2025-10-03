
This repository contains `counter.py`, a small script to enumerate Vault auth mounts and report unique client counts from the internal activity counters (Enterprise feature).

Quick start (connect to an existing Vault server):

1. Copy `.env.example` to `.env` and set `VAULT_ADDR` and `VAULT_TOKEN` (do NOT commit `.env`).

2. Create and activate the virtual environment and install dependencies:

```bash
chmod +x setup_venv.sh
./setup_venv.sh
source .venv/bin/activate
```

3. Run the counter (30-day window by default):

```bash
set -a && [ -f ./.env ] && . ./.env || true && set +a && . .venv/bin/activate && python counter.py --days 30
```

Files produced:
- `vault_client_counts_by_auth.csv`
- `vault_identity_alias_export.csv` (if `--include-entities` is passed)

Notes:
- The activity counters endpoint (`/v1/sys/internal/counters/activity`) is an Enterprise feature. On OSS Vault it may return empty totals and the script will write zeros. The script will still export auth mount metadata and entity alias mappings when available.
- Use `--include-entities` to export identity entity alias mappings.
- Use `--namespace` to target a specific namespace (Enterprise only).

Installing git hooks (recommended):

```bash
chmod +x scripts/install-git-hooks.sh
./scripts/install-git-hooks.sh
```

The hooks will block commits that appear to contain common secret patterns and will validate commit messages follow Conventional Commits.

Security:
- Never store tokens or secrets in the repository. Add them to `.env` and add `.env` to `.gitignore`.
