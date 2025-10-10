# Vault Audit Tools (Rust CLI)

A high-performance command-line tool for analyzing HashiCorp Vault audit logs.

## Quick Start

### Build
```bash
cargo build --release
```

### Run
```bash
# System overview analysis
./target/release/vault-audit system-overview /path/to/audit.log

# See all available commands
./target/release/vault-audit --help
```

## Available Commands

| Command | Status | Description |
|---------|--------|-------------|
| `system-overview` | ✅ | Identify high-volume operations and stress points |
| `kv-analyzer` | 🚧 | Analyze KV usage by path and entity |
| `kv-compare` | 🚧 | Compare KV usage between time periods |
| `kv-summary` | 🚧 | Summarize KV usage statistics |
| `token-operations` | 🚧 | Analyze token operations by entity |
| `token-export` | 🚧 | Export token lookup patterns to CSV |
| `token-lookup-abuse` | 🚧 | Detect suspicious token lookup patterns |
| `entity-gaps` | 🚧 | Analyze entity creation/deletion gaps |
| `entity-timeline` | 🚧 | Show operation timeline for specific entity |
| `path-hotspots` | 🚧 | Identify frequently accessed paths |
| `k8s-auth` | 🚧 | Analyze Kubernetes authentication patterns |
| `airflow-polling` | 🚧 | Analyze Airflow polling behavior |

✅ = Complete | 🚧 = In Progress

## Performance

Processes **~4 million audit log entries in ~20 seconds** (3x faster than Python equivalent).

## Example Usage

### System Overview
```bash
vault-audit system-overview vault_audit.log \
  --top 30 \
  --min-operations 1000
```

**Output:**
- Operation type distribution
- Top path prefixes
- Highest volume paths
- Most active entities
- System stress points

### Future Commands (After Conversion)

```bash
# KV usage analysis
vault-audit kv-analyzer vault_audit.log --kv-prefix "kv/" -o output.csv

# Token abuse detection
vault-audit token-lookup-abuse vault_audit.log --threshold 1000

# Entity timeline
vault-audit entity-timeline vault_audit.log --entity-id abc123
```

## Development

### Project Structure
```
src/
├── main.rs              # CLI entry point
├── lib.rs               # Library exports
├── audit/               # Core parsing logic
│   ├── types.rs        # Data structures
│   └── parser.rs       # Streaming parser
├── commands/            # Analysis tools
│   └── system_overview.rs
└── utils/               # Shared utilities
    └── time.rs
```

### Adding a New Command

1. Create module in `src/commands/your_command.rs`
2. Implement `pub fn run(...) -> Result<()>`
3. Add to `src/commands/mod.rs`
4. Add subcommand variant in `src/main.rs`

### Testing
```bash
# Run tests
cargo test

# Check for warnings
cargo clippy

# Format code
cargo fmt
```

## Dependencies

- **clap** - Command-line argument parsing
- **serde/serde_json** - JSON deserialization
- **chrono** - Date/time handling
- **anyhow** - Error handling
- **csv** - CSV I/O

See [Cargo.toml](Cargo.toml) for full dependency list.
