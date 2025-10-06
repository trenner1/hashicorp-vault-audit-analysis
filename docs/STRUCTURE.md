# Repository Structure

## Directory Layout

```
client_counter/
├── bin/                    # Executable Python scripts
│   ├── counter.py          # Client count by auth mount (Enterprise telemetry)
│   ├── kv_usage_analyzer.py # KV usage by client (audit log analysis)
│   └── summarize_kv_usage.py # Pretty-print KV usage reports
│
├── scripts/                # Helper shell scripts
│   ├── setup_venv.sh       # Create and configure Python venv
│   ├── run.sh              # Run counter.py with environment
│   ├── run_in_venv.sh      # Execute commands inside venv
│   └── install-git-hooks.sh # Install pre-commit hooks
│
├── examples/               # Sample files and test data
│   └── sample_audit.log.example # Sample Vault audit log format
│
├── data/                   # Output directory (gitignored)
│   ├── vault_client_counts_by_auth.csv
│   ├── vault_identity_alias_export.csv
│   └── kv_usage_by_client.csv
│
├── .githooks/              # Git hooks (pre-commit, commit-msg)
├── .env.example            # Environment variable template
└── README.md               # Main documentation
```

## Quick Reference

### Main Scripts

| Script | Purpose | Output |
|--------|---------|--------|
| `bin/counter.py` | Reports client counts by auth mount | `data/vault_client_counts_by_auth.csv`<br>`data/vault_identity_alias_export.csv` |
| `bin/kv_usage_analyzer.py` | Analyzes audit logs for KV usage patterns | `data/kv_usage_by_client.csv` |
| `bin/summarize_kv_usage.py` | Generates formatted reports | stdout |

### Helper Scripts

| Script | Purpose |
|--------|---------|
| `scripts/setup_venv.sh` | One-time setup: creates venv and installs dependencies |
| `scripts/run.sh` | Convenience wrapper to run counter.py with .env |
| `scripts/run_in_venv.sh` | Execute arbitrary commands inside the venv |
| `scripts/install-git-hooks.sh` | Install pre-commit and commit-msg hooks |

## Basic Workflow

```bash
# 1. Setup (one-time)
./scripts/setup_venv.sh
source .venv/bin/activate

# 2. Get client counts and export entities
python bin/counter.py --include-entities

# 3. Analyze KV usage from audit logs
python bin/kv_usage_analyzer.py /path/to/audit.log \
  --alias-export data/vault_identity_alias_export.csv

# 4. View formatted report
python bin/summarize_kv_usage.py data/kv_usage_by_client.csv
```

See main [README.md](../README.md) for detailed usage, configuration, and development guidelines.
