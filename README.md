# Vault Audit Log Analysis Tools

This repository contains a comprehensive suite of tools for analyzing HashiCorp Vault audit logs to identify performance bottlenecks, security issues, and optimization opportunities.

## Tool Categories

### KV Secret Engine Analysis (3 tools)
- **`vault_audit_kv_analyzer.py`** - Analyze KV secret engine usage patterns by entity and path
- **`vault_audit_kv_compare.py`** - Compare usage statistics across multiple KV mounts
- **`vault_audit_kv_summary.py`** - Human-readable summary of single KV mount usage

### Token Operations Analysis (3 tools)
- **`vault_audit_token_operations.py`** - Analyze token lifecycle operations (lookup, renew, revoke)
- **`vault_audit_token_lookup_abuse.py`** - Identify excessive token lookup patterns
- **`vault_audit_token_export.py`** - Export comprehensive token lookup data to CSV

### System-Wide Analysis (1 tool)
- **`vault_audit_system_overview.py`** - Comprehensive overview of all high-volume operations

### Specialized Deep-Dive Tools (4 tools)
- **`vault_audit_airflow_polling.py`** - Analyze Airflow secret polling patterns
- **`vault_audit_entity_timeline.py`** - Time-series analysis of specific entity behavior
- **`vault_audit_entity_gaps.py`** - Investigate operations without entity IDs
- **`vault_audit_path_hotspots.py`** - Deep-dive into most-accessed paths with recommendations

### Kubernetes/OpenShift Auth Analysis (1 tool)
- **`vault_audit_k8s_auth_analysis.py`** - Multi-dimensional K8s/OpenShift authentication analysis

## Quick Start

### Prerequisites

```bash
# Install Python 3.8 or higher
python3 --version

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### Basic Usage

All tools analyze Vault audit logs (JSON format, newline-delimited). Here's a typical workflow:

```bash
# 1. Get audit logs (example: from file or kubectl)
kubectl exec -n vault vault-0 -- cat /vault/logs/audit.log > vault_audit.log

# 2. Start with system-wide overview
python bin/vault_audit_system_overview.py vault_audit.log --top 20

# 3. Analyze specific areas based on findings
python bin/vault_audit_token_lookup_abuse.py vault_audit.log --min-lookups 100
python bin/vault_audit_airflow_polling.py vault_audit.log
python bin/vault_audit_path_hotspots.py vault_audit.log 50

# 4. Deep-dive on specific entities
python bin/vault_audit_entity_timeline.py vault_audit.log <entity_id> "<display_name>"

# 5. Analyze KV mount usage
python bin/vault_audit_kv_analyzer.py vault_audit.log --kv-prefix "<kv_path>/" --output data/kv_usage_<kv_path>.csv
python bin/vault_audit_kv_compare.py  # Compares all kv_usage_*.csv files in data/
```

## Common Use Cases

### Use Case 1: "Vault is slow"
```bash
# Step 1: System overview to identify stress points
python bin/vault_audit_system_overview.py vault_audit.log --top 20

# Step 2: Analyze top paths
python bin/vault_audit_path_hotspots.py vault_audit.log 30

# Step 3: Investigate top entity behavior
python bin/vault_audit_entity_timeline.py vault_audit.log <entity_id> "<name>"
```

### Use Case 2: "Too many token lookups"
```bash
# Step 1: Identify patterns
python bin/vault_audit_token_lookup_abuse.py vault_audit.log --min-lookups 100

# Step 2: Export for analysis
python bin/vault_audit_token_export.py vault_audit.log --output data/token_abuse.csv

# Step 3: Investigate worst offender
python bin/vault_audit_entity_timeline.py vault_audit.log <top_entity> "<name>"
```

### Use Case 3: "Airflow causing high load"
```bash
# Specialized Airflow analysis with optimization recommendations
python bin/vault_audit_airflow_polling.py vault_audit.log
```

### Use Case 4: "K8s pods authenticating too frequently"
```bash
# Multi-dimensional K8s auth analysis
python bin/vault_audit_k8s_auth_analysis.py vault_audit.log
```

### Use Case 5: "Security audit - who accesses which secrets?"
```bash
# Step 1: Check for entity aliasing gaps
python bin/vault_audit_entity_gaps.py vault_audit.log

# Step 2: Analyze KV access patterns
python bin/vault_audit_kv_analyzer.py vault_audit.log --kv-prefix "sensitive/"

# Step 3: Compare across mounts
python bin/vault_audit_kv_compare.py
```


## Requirements

All tools perform **offline audit log analysis** - no Vault API access required:
- Read access to Vault audit log files (JSON format, newline-delimited)
- Python 3.8 or higher
- Dependencies: See `requirements.txt`

## Output Files

Analysis tools generate CSV and markdown reports in the `data/` directory:
- `kv_usage_*.csv` - KV mount usage data
- `token_lookups_by_entity.csv` - Token lookup patterns
- Various markdown reports with findings and recommendations

## Development

### Verify Tool Installation

```bash
# Verify all 12 tools are present
ls -1 bin/vault_audit_*.py | wc -l  # Should show: 12

# Test all tools support --help
for tool in bin/vault_audit_*.py; do
  python3 "$tool" --help >/dev/null 2>&1 && echo "Installed $(basename $tool)" || echo "Not Installed$(basename $tool)"
done
```

### Tool Usage

All tools support `--help` for detailed usage information:
```bash
# Get help for any tool
python3 bin/<tool_name>.py --help

# Examples
python3 bin/vault_audit_system_overview.py --help
python3 bin/vault_audit_kv_analyzer.py --help
python3 bin/vault_audit_entity_timeline.py --help
```

## Security

**Audit logs may contain sensitive information:**
- Entity IDs, display names, service account details
- Path names that may reveal application architecture
- Authentication metadata
- Handle audit logs according to your organization's security policies

**Best Practices:**
- Store audit logs securely
- Limit access to analysis outputs
- Sanitize data before sharing externally
- Use `.gitignore` to prevent committing sensitive data files

## Documentation

All tools include comprehensive built-in help:
```bash
python3 bin/<tool_name>.py --help
```

Each tool displays:
- Description of its purpose
- Required and optional arguments
- Usage examples
- Output format details

For workflow examples, see the "Common Use Cases" section above.

## License

Internal use only.
