# Vault Client Counter

This repository contains tools to analyze Vault client usage:

1. **`counter.py`** - Reports unique client counts by auth mount from Enterprise activity counters
2. **`kv_usage_analyzer.py`** - Analyzes audit logs to report client usage by KV secret path

## Quick Start

### Prerequisites

```bash
# Copy environment template and set your Vault connection details
cp .env.example .env
# Edit .env with your VAULT_ADDR and VAULT_TOKEN (do NOT commit .env)

# Create and activate virtual environment
chmod +x setup_venv.sh
./setup_venv.sh
source .venv/bin/activate
```

### Option 1: Client Count by Auth Mount

Report unique clients per authentication method using Enterprise telemetry:

```bash
# Activate env and run counter
set -a && [ -f ./.env ] && . ./.env && set +a && python counter.py

# Include entity/alias export for enrichment
python counter.py --include-entities
```

**Output files:**
- `data/vault_client_counts_by_auth.csv` - Client counts per auth mount (accessor, path, type, count)
- `data/vault_identity_alias_export.csv` - Entity/alias mappings (when `--include-entities` used)

**Example output:**
```csv
namespace,auth_accessor,auth_path,auth_type,unique_clients_in_window,window_start_utc,window_end_utc,granularity
,auth_jwt_6fce7f2b,jenkins-jwt/,jwt,1,2025-09-06T20:59:57Z,2025-10-06T20:59:57Z,daily
,auth_token_a7269f86,token/,token,0,2025-09-06T20:59:57Z,2025-10-06T20:59:57Z,daily
```

### Option 2: KV Usage by Client (Audit Log Analysis)

Analyze which clients/entities are accessing which KV secret paths:

```bash
# Step 1: Export entities for enrichment
python counter.py --include-entities

# Step 2: Obtain audit logs (example: from k8s)
kubectl exec -n vault vault-0 -- cat /vault/logs/audit.log > audit.log

# Step 3: Analyze audit logs
python kv_usage_analyzer.py audit.log --alias-export data/vault_identity_alias_export.csv

# Or analyze multiple log files
python kv_usage_analyzer.py /vault/logs/audit*.log

# Step 4: View formatted report
python summarize_kv_usage.py data/kv_usage_by_client.csv
```

**Output file:**
- `data/kv_usage_by_client.csv` - KV path usage with client counts and entity details

**View formatted report:**
```bash
python summarize_kv_usage.py [kv_usage_by_client.csv]
```
This will display a pretty-printed summary with overview statistics and per-path details.

**Example output:**
```csv
kv_path,unique_clients,operations_count,entity_ids,alias_names,sample_paths_accessed
kv/app1/,2,15,"e123-app1, e456-app2","jenkins-app1, app2-svc","kv/data/app1/config, kv/data/app1/db"
kv/app2/,1,8,e456-app2,app2-svc,"kv/data/app2/secrets, kv/metadata/app2/"
kv/shared/,3,42,"e123-app1, e456-app2, e789-app3","jenkins-app1, app2-svc, app3-batch",kv/data/shared/common
```

**Use case:** Track which apps (organized by KV path) are being actively used and by which entities.

## Configuration

### Environment Variables

Set in `.env` file (copy from `.env.example`):

- `VAULT_ADDR` - Vault server address (default: `http://localhost:8200`)
- `VAULT_TOKEN` - Vault token with required permissions
- `VAULT_SKIP_VERIFY` - Set to `1` to skip TLS verification (dev/testing only)
- `VAULT_CACERT` - Path to CA certificate for TLS verification

### Required Permissions

**For `counter.py`:**
- `sys/auth` - read (list auth mounts)
- `sys/internal/counters/activity` - read (Enterprise telemetry)
- `identity/entity/id` - list, read (when using `--include-entities`)
- `sys/namespaces` - list (Enterprise, for namespace enumeration)

**For `kv_usage_analyzer.py`:**
- Read access to audit log files
- No Vault API permissions required (offline analysis)

## Advanced Usage

### Counter.py Options

```bash
python counter.py --help

# Common options:
--include-entities     # Export entity/alias mappings
--namespace <ns>       # Target specific namespace (Enterprise)
--debug                # Enable verbose HTTP debug output
```

### KV Usage Analyzer Options

```bash
python kv_usage_analyzer.py --help

# Common options:
--kv-prefix kv/                          # KV mount path to filter
--alias-export vault_identity_alias_export.csv  # Entity/alias enrichment
--output kv_usage.csv                    # Output file name
```

## Notes

- **Enterprise vs OSS**: The activity counters endpoint (`/v1/sys/internal/counters/activity`) is Enterprise-only. On OSS Vault, `counter.py` will return zero counts but still export auth mount metadata and entity aliases.
- **Billing Periods**: Enterprise telemetry returns data for the current billing period. Custom date ranges are often ignored if they don't align with billing periods.
- **Audit Logs**: The KV usage analyzer requires JSON-formatted audit logs. Ensure audit device is enabled (`vault audit list`).
- **Log Rotation**: Audit log analysis is limited to available logs. Consider log retention policies.

## Development

### Pre-commit Hooks

This repository uses `pre-commit` for linting and secret scanning:

```bash
# Install development dependencies
.venv/bin/pip install -r requirements-dev.txt

# Install git hooks
.venv/bin/pre-commit install

# Run checks manually
.venv/bin/pre-commit run --all-files
```

**Configured checks:**
- `flake8` - Python linting
- `detect-secrets` - Secret scanning (baseline: `.secrets.baseline`)
- Formatting checks (trailing whitespace, EOF, YAML)

### Conventional Commits

This repository follows [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: bug fix
chore: maintenance
docs: documentation updates
test: test additions
```

The commit-msg hook validates commit messages on every commit.

## Security

**Never commit secrets to the repository**
- Add tokens to `.env` (already in `.gitignore`)
- Pre-commit hooks scan for common secret patterns
- Review `.secrets.baseline` if detect-secrets flags false positives

## Examples

See `sample_audit.log.example` for audit log format and testing examples.

## License

Internal use only.
