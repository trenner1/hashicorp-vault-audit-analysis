# Vault Audit Tools

[![CI](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/trenner1/hashicorp-vault-audit-analysis/branch/main/graph/badge.svg)](https://codecov.io/gh/trenner1/hashicorp-vault-audit-analysis)

High-performance command-line tools for analyzing HashiCorp Vault audit logs, written in Rust.

## Features

- **Fast**: 3x faster than equivalent implementations (~17s vs 60s for 4M line logs)
- **Memory Efficient**: 10x less memory usage through streaming parser
- **Comprehensive**: 16 specialized analysis commands for different use cases
- **Production Ready**: Tested on multi-gigabyte production audit logs
- **Shell Completion**: Tab completion support for bash, zsh, fish, powershell, and elvish

## Installation

### From Source

```bash
cd vault-audit-tools
cargo install --path .
```

This installs the `vault-audit` binary to `~/.cargo/bin/`.

### Pre-built Binaries

Download from the [Releases](https://github.com/trenner1/hashicorp-vault-audit-analysis/releases) page.

### Shell Completion

After installation, enable tab completion for your shell:

```bash
# Bash
vault-audit generate-completion bash > /usr/local/etc/bash_completion.d/vault-audit

# Zsh
mkdir -p ~/.zsh/completions
vault-audit generate-completion zsh > ~/.zsh/completions/_vault-audit
# Add to ~/.zshrc: fpath=(~/.zsh/completions $fpath)

# Fish
vault-audit generate-completion fish > ~/.config/fish/completions/vault-audit.fish
```

## Commands

### System Analysis

- **`system-overview`** - High-level overview of all operations, entities, and auth methods
- **`entity-gaps`** - Identify operations without entity IDs (no-entity operations)
- **`path-hotspots`** - Find most accessed paths with optimization recommendations

### Authentication Analysis

- **`k8s-auth`** - Analyze Kubernetes/OpenShift authentication patterns and entity churn
- **`token-operations`** - Track token lifecycle operations (create, renew, revoke)
- **`token-lookup-abuse`** - Detect excessive token lookup patterns

### Entity Analysis

- **`entity-creation`** - Analyze entity creation patterns by authentication path
- **`entity-churn`** - Multi-day entity lifecycle tracking across log files
- **`entity-timeline`** - Generate detailed timeline for a specific entity
- **`preprocess-entities`** - Extract entity mappings from audit logs

### Vault API Integration

- **`client-activity`** - Query Vault for client activity metrics by mount
- **`entity-list`** - Export complete entity list from Vault (for baseline analysis)

### KV Secrets Analysis

- **`kv-summary`** - Summarize KV secret usage from CSV exports
- **`kv-analyzer`** - Analyze KV usage by path and entity (generates CSV)
- **`kv-compare`** - Compare KV usage between two time periods

### Application-Specific

- **`airflow-polling`** - Analyze Airflow secret polling patterns with burst rate detection

### Data Export

- **`token-export`** - Export token lookup patterns to CSV

### Utilities

- **`generate-completion`** - Generate shell completion scripts

## Usage Examples

### Quick Analysis

```bash
# Get system overview
vault-audit system-overview vault_audit.log

# Find authentication issues
vault-audit k8s-auth vault_audit.log

# Detect token abuse
vault-audit token-lookup-abuse vault_audit.log
```

### Deep Dive Analysis

```bash
# Analyze entity creation patterns by auth path
vault-audit entity-creation vault_audit.log

# Track entity lifecycle across multiple days (no log concatenation needed)
vault-audit entity-churn day1.log day2.log day3.log --baseline baseline_entities.csv

# Analyze specific entity behavior
vault-audit entity-timeline --entity-id <UUID> vault_audit.log

# Export token data for further analysis
vault-audit token-export vault_audit.log --output tokens.csv

# Analyze Airflow polling with burst detection
vault-audit airflow-polling vault_audit.log

# Query Vault API for client activity metrics
vault-audit client-activity --start 2025-10-01T00:00:00Z --end 2025-11-01T00:00:00Z
```

### KV Usage Analysis

```bash
# Generate KV usage report
vault-audit kv-analyzer vault_audit.log --kv-prefix "appcodes/" --output kv_usage.csv

# Compare two time periods
vault-audit kv-compare old_usage.csv new_usage.csv

# Get summary statistics
vault-audit kv-summary kv_usage.csv
```

## Performance

Tested on production audit logs:

- **Log Size**: 15.7 GB (3,986,972 lines)
- **Processing Time**: ~17 seconds
- **Memory Usage**: <100 MB
- **Throughput**: ~230,000 lines/second

## Output Formats

Most commands produce formatted text output with:
- Summary statistics
- Top N lists sorted by volume/importance
- Percentage breakdowns
- Optimization recommendations

CSV export commands generate standard CSV files for:
- Spreadsheet analysis
- Database imports
- Further processing with other tools

## Architecture

- **Streaming Parser**: Processes logs line-by-line without loading entire file into memory
- **Efficient Data Structures**: Uses HashMaps and BTreeMaps for fast aggregation
- **Parallel-Ready**: Built with Rust's zero-cost abstractions for future parallelization
- **Type Safety**: Comprehensive error handling with anyhow

## Development

### Build

```bash
cd vault-audit-tools
cargo build --release
```

### Test

```bash
cargo test
```

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Requirements

- Rust 1.70+ (2021 edition)
- Works on Linux, macOS, and Windows

## Support

For issues or questions, please open a GitHub issue.
