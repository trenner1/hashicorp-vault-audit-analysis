# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a high-performance Rust command-line tool for analyzing HashiCorp Vault audit logs. The project provides 16+ specialized analysis commands organized into unified interfaces for entity analysis, token operations, and KV secrets analysis.

**Key Performance Characteristics:**
- 3x faster than Python equivalents (~17s vs 60s for 4M line logs)
- 10x less memory usage through streaming parser
- Supports compressed files (.gz, .zst) with streaming decompression
- Handles multi-gigabyte production logs efficiently

## Development Commands

### Build and Test
```bash
# Build release binary
cargo build --release

# Run all tests (includes doc tests)
cargo test --all-features --verbose
cargo test --doc

# Check code formatting
cargo fmt --all -- --check

# Run linting (clippy with strict warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Generate code coverage
cargo install cargo-tarpaulin
cargo tarpaulin --out xml --all-features

# Generate and view documentation
cargo doc --no-deps --open
```

### Binary Installation
```bash
# Install from source (produces ~/.cargo/bin/vault-audit)
cargo install --path .
```

## Architecture

### Core Modules
- **`src/audit/`** - Core audit log parsing and JSON data structures (`AuditEntry` types)
- **`src/commands/`** - Individual command implementations organized by analysis domain
- **`src/utils/`** - Shared utilities (time parsing, progress display, file reading with compression support)
- **`src/vault_api.rs`** - Vault API client for entity enrichment and live data queries

### Command Organization
The project has undergone command consolidation to reduce complexity:

**Unified Commands (Current):**
- `entity-analysis` (subcommands: churn, creation, preprocess, gaps, timeline)
- `token-analysis` (unified token operations, abuse detection, export)
- `kv-analysis` (subcommands: analyze, compare, summary)

**Deprecated Commands:**
- Individual entity commands (entity-churn, entity-creation, etc.) - hidden but functional
- Individual token commands (token-operations, token-lookup-abuse, token-export) - hidden but functional
- Individual KV commands (kv-analyzer, kv-compare, kv-summary) - hidden but functional

### Key Design Patterns
- **Streaming Parser**: Processes audit logs line-by-line without loading entire files into memory
- **Auto-preprocessing**: Entity commands automatically build entity mappings in-memory, eliminating multi-step workflows
- **Compressed File Support**: Automatic detection and streaming decompression of .gz and .zst files
- **Multi-file Processing**: All commands support multiple input files for historical analysis

## Code Conventions

### General Rules
- **Never use emojis** in code, comments, error messages, or output unless explicitly requested by the user
- **Never include the following lines in commit messages:**
  ```
  🤖 Generated with [Claude Code](https://claude.ai/code)

  Co-Authored-By: Claude <noreply@anthropic.com>
  ```

### Error Handling
- Uses `anyhow::Result<()>` for command functions
- `thiserror` for custom error types
- Comprehensive error context with file paths and line numbers

### CLI Structure
- `clap` with derive macros for argument parsing
- Subcommand organization with `#[command(subcommand)]`
- Hidden deprecated commands with `#[command(hide = true)]`
- Deprecation warnings printed to stderr before executing legacy commands

### File Processing
- All commands accept `Vec<String>` for log files (supports globs and multiple files)
- Automatic format detection for compressed files
- Streaming approach using `BufReader` and line-by-line JSON parsing

### Output Formats
- Human-readable summaries to stdout
- CSV exports for data analysis
- JSON exports for programmatic processing
- Progress indicators for long-running operations

## Testing

Tests are organized by domain:
- `tests/audit_types_tests.rs` - Audit log parsing
- `tests/entity_*_tests.rs` - Entity analysis commands
- `tests/integration_tests.rs` - End-to-end command testing
- `tests/*_tests.rs` - Individual component tests

**Key Test Patterns:**
- Use `tempfile` crate for temporary files
- Mock audit log data for consistent testing
- Test both unified and deprecated command interfaces
- Validate CSV/JSON output formats

## Dependencies

**Core Dependencies:**
- `clap` - Command-line argument parsing with completion support
- `serde`/`serde_json` - JSON parsing for audit logs
- `csv` - CSV output generation
- `chrono` - Time parsing and formatting
- `anyhow`/`thiserror` - Error handling
- `reqwest`/`tokio` - Async HTTP client for Vault API
- `flate2`/`zstd` - Compression support

**Development Dependencies:**
- `tempfile` - Temporary file handling in tests

## Key Implementation Notes

### Entity Processing
- Entity IDs are UUIDs that appear in audit logs
- Display names come from entity alias mappings
- Auto-preprocessing builds entity mappings in-memory during analysis
- Baseline entity lists help identify pre-existing vs new entities

### Token Analysis
- Distinguishes between entities (user/service identities) and accessors (individual tokens)
- Tracks token lifecycle: create, renew, revoke, lookup operations
- Abuse detection based on configurable thresholds for excessive operations

### KV Secrets Analysis
- Supports both KV v1 and KV v2 engines
- Path-based analysis with mount point filtering
- Time-based usage comparison between periods
- Entity-based access pattern analysis

### Compression Support
- Automatic detection by file extension (.gz, .zst)
- Streaming decompression with no temporary files
- Maintains full processing speed with compressed inputs
