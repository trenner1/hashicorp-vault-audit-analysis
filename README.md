# Vault Audit Tools

[![CI](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml)
[![codecov](https://codecov.io/github/trenner1/hashicorp-vault-audit-analysis/graph/badge.svg?token=QYMT1SKDQ6)](https://codecov.io/github/trenner1/hashicorp-vault-audit-analysis)
[![Docs](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://trenner1.github.io/hashicorp-vault-audit-analysis/)
[Browse versions](https://trenner1.github.io/hashicorp-vault-audit-analysis/versions.html)


High-performance command-line tools for analyzing HashiCorp Vault audit logs, written in Rust.

## Features

- **Fast**: 3x faster than equivalent implementations (~17s vs 60s for 4M line logs)
- **Memory Efficient**: 10x less memory usage through streaming parser
- **Compressed File Support**: Direct analysis of `.gz` and `.zst` files without manual decompression
- **Multi-File Support**: Analyze weeks/months of logs without manual concatenation
- **Comprehensive**: 16 specialized analysis commands for different use cases
- **Production Ready**: Tested on 100GB+ multi-day production audit logs
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

#### Linux/macOS

```bash
# Bash (Linux) - single command
sudo mkdir -p /usr/local/etc/bash_completion.d && \
vault-audit generate-completion bash | sudo tee /usr/local/etc/bash_completion.d/vault-audit > /dev/null && \
echo "Completion installed. Restart your shell or run: source /usr/local/etc/bash_completion.d/vault-audit"

# Bash (macOS with Homebrew) - single command
mkdir -p $(brew --prefix)/etc/bash_completion.d && \
vault-audit generate-completion bash > $(brew --prefix)/etc/bash_completion.d/vault-audit && \
echo "Completion installed. Restart your shell or run: source $(brew --prefix)/etc/bash_completion.d/vault-audit"

# Zsh - single command
mkdir -p ~/.zsh/completions && \
vault-audit generate-completion zsh > ~/.zsh/completions/_vault-audit && \
grep -q 'fpath=(~/.zsh/completions $fpath)' ~/.zshrc || echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc && \
grep -q 'autoload -Uz compinit && compinit' ~/.zshrc || echo 'autoload -Uz compinit && compinit' >> ~/.zshrc && \
echo "Completion installed. Restart your shell or run: source ~/.zshrc"

# Fish - single command
mkdir -p ~/.config/fish/completions && \
vault-audit generate-completion fish > ~/.config/fish/completions/vault-audit.fish && \
echo "Completion installed. Restart your shell."

# PowerShell (Windows/Cross-platform) - single command
$profileDir = Split-Path $PROFILE; New-Item -ItemType Directory -Force -Path $profileDir | Out-Null; vault-audit generate-completion powershell | Out-File -Append -FilePath $PROFILE -Encoding utf8; Write-Host "Completion installed. Restart PowerShell or run: . `$PROFILE"

# Elvish - single command
mkdir -p ~/.config/elvish/lib && \
vault-audit generate-completion elvish > ~/.config/elvish/lib/vault-audit.elv && \
grep -q 'use vault-audit' ~/.config/elvish/rc.elv || echo 'use vault-audit' >> ~/.config/elvish/rc.elv && \
echo "Completion installed. Restart your shell."
```

#### Windows (Git Bash)

Git Bash users need special handling since `~` doesn't expand in output redirection:

```bash
# Single command installation for Git Bash
mkdir -p "$HOME/.bash_completions" && \
vault-audit generate-completion bash > "$HOME/.bash_completions/vault-audit" && \
grep -q 'source "$HOME/.bash_completions/vault-audit"' ~/.bashrc || echo 'source "$HOME/.bash_completions/vault-audit"' >> ~/.bashrc && \
echo "Completion installed. Restart Git Bash or run: source ~/.bashrc"
```

**Troubleshooting**:
- Use `$HOME` variable instead of `~` for paths in Git Bash
- If completions don't work immediately, open a new terminal window
- Verify the completion file exists: `ls -la "$HOME/.bash_completions/vault-audit"`
- Check your shell rc file sources it: `grep vault-audit ~/.bashrc`

## Commands

### System Analysis

- **`system-overview`** - High-level overview of all operations, entities, and auth methods
- **`entity-gaps`** - Identify operations without entity IDs (no-entity operations)
- **`path-hotspots`** - Find most accessed paths with optimization recommendations

### Authentication Analysis

- **`k8s-auth`** - Analyze Kubernetes/OpenShift authentication patterns and entity churn
- **`token-analysis`** - Unified token operations analysis with abuse detection and CSV export
  - Track token lifecycle operations (create, renew, revoke, lookup)
  - Detect excessive token lookup patterns
  - Export per-accessor detail to CSV

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

## Documentation

### API Documentation

View the full API documentation with detailed module and function descriptions:

```bash
# Generate and open documentation in your browser
cd vault-audit-tools
cargo doc --no-deps --open
```

The documentation includes:
- Comprehensive crate overview and architecture
- Module-level documentation for all components
- Function-level documentation with examples
- Type definitions and their usage

Once published to crates.io, the documentation will be automatically available at [docs.rs/vault-audit-tools](https://docs.rs/vault-audit-tools).

### Command Help

Get detailed help for any command:

```bash
# General help
vault-audit --help

# Command-specific help
vault-audit entity-churn --help
vault-audit kv-analyzer --help
```

### Application-Specific

- **`airflow-polling`** - Analyze Airflow secret polling patterns with burst rate detection

### Utilities

- **`generate-completion`** - Generate shell completion scripts

## Usage Examples

### Compressed File Support

All commands automatically detect and decompress `.gz` (gzip) and `.zst` (zstandard) files:

```bash
# Analyze compressed files directly - no manual decompression needed
vault-audit system-overview vault_audit.log.gz

# Mix compressed and uncompressed files
vault-audit entity-churn day1.log.gz day2.log day3.log.zst

# Glob patterns work with compressed files
vault-audit path-hotspots logs/*.log.gz

# Streaming decompression - no temp files, no extra disk space needed
vault-audit token-analysis huge_file.log.gz  # processes 1.79GB compressed → 13.8GB uncompressed
```

**Performance**: Compressed file processing maintains full speed (~57 MB/s) with no memory overhead thanks to streaming decompression.

### Understanding Entities vs Token Accessors

When analyzing token operations, it's important to understand the difference between **entities** and **accessors**:

**Entity** (User/Service Identity):
- A single identity like "fg-PIOP0SRVDEVOPS" or "approle"
- Can have multiple tokens (accessors) over time
- Summary view shows aggregated totals per entity
- Example: One service might have 233,668 total operations

**Accessor** (Individual Token):
- A unique token identifier for a single token
- Each accessor belongs to one entity
- Tokens get rotated/recreated, creating new accessors
- Example: That same service's 233k operations might be spread across 3 tokens:
  - Token 1: 113,028 operations (10/06 07:26 - 10/07 07:41, 24.3h lifespan)
  - Token 2: 79,280 operations (10/06 07:26 - 10/07 07:40, 24.2h lifespan)
  - Token 3: 41,360 operations (10/06 07:28 - 10/07 07:40, 24.2h lifespan)

**When to use each view**:
- **Summary mode** (default): Shows per-entity totals for understanding overall usage patterns
- **CSV export** (`--export`): Shows per-accessor detail for token lifecycle analysis, rotation patterns, and identifying specific problematic tokens

```bash
# See entity-level summary (6,091 entities with totals)
vault-audit token-analysis vault_audit.log

# Export accessor-level detail (907 individual tokens with timestamps)
vault-audit token-analysis vault_audit.log --export tokens.csv

# Filter to high-volume tokens only
vault-audit token-analysis vault_audit.log --export tokens.csv --min-operations 1000
```

### Quick Analysis

```bash
# Get system overview (works with plain or compressed files)
vault-audit system-overview vault_audit.log
vault-audit system-overview vault_audit.log.gz

# Analyze multiple days without concatenation
vault-audit system-overview logs/vault_audit.2025-10-*.log

# Find authentication issues
vault-audit k8s-auth vault_audit.log

# Detect token abuse across multiple compressed files
vault-audit token-analysis day1.log.gz day2.log.gz day3.log.gz --abuse-threshold 5000
```

### Multi-File Long-Term Analysis

All audit log commands support multiple files (compressed or uncompressed) for historical analysis:

```bash
# Week-long system overview with compressed files
vault-audit system-overview vault_audit.2025-10-{07,08,09,10,11,12,13}.log.gz

# Month-long entity churn tracking
vault-audit entity-churn october/*.log.gz

# Multi-day token operations analysis with mixed file types
vault-audit token-analysis logs/vault_audit.*.log --export token_ops.csv

# Path hotspot analysis across 30 days of compressed logs
vault-audit path-hotspots logs/vault_audit.2025-10-*.log.zst
```

### Deep Dive Analysis

```bash
# Analyze entity creation patterns by auth path
vault-audit entity-creation vault_audit.log

# Track entity lifecycle across multiple days
vault-audit entity-churn day1.log day2.log day3.log --baseline baseline_entities.json

# Analyze specific entity behavior
vault-audit entity-timeline day1.log day2.log --entity-id <UUID>

# Token analysis with multiple output modes
vault-audit token-analysis vault_audit.log                              # Summary view (per-entity)
vault-audit token-analysis vault_audit.log --abuse-threshold 10000      # Abuse detection
vault-audit token-analysis vault_audit.log --filter lookup,revoke       # Filter operation types
vault-audit token-analysis vault_audit.log --export tokens.csv          # Export per-accessor detail (907 tokens)
vault-audit token-analysis vault_audit.log --export tokens.csv --min-operations 1000  # High-volume tokens only

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

**Single File:**
- **Log Size**: 15.7 GB (3,986,972 lines)
- **Processing Time**: ~17 seconds
- **Memory Usage**: <100 MB
- **Throughput**: ~230,000 lines/second

**Multi-File (7 days):**
- **Total Size**: 105 GB (26,615,476 lines)
- **Processing Time**: ~2.5 minutes average per command
- **Memory Usage**: <100 MB (streaming approach)
- **Throughput**: ~175,000 lines/second sustained

**Compressed Files:**
- **File Size**: 1.79 GB compressed → 13.8 GB uncompressed
- **Processing Time**: ~31 seconds (299,958 login operations)
- **Throughput**: ~57 MB/sec compressed, ~230,000 lines/second
- **Memory Usage**: <100 MB (streaming decompression, no temp files)
- **Formats Supported**: gzip (.gz), zstandard (.zst)

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
