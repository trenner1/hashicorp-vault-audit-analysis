//! # Vault Audit Tools
//!
//! High-performance command-line tools for analyzing `HashiCorp Vault` audit logs with
//! automatic parallel processing and compressed file support.
//!
//! ## Overview
//!
//! This crate provides a suite of specialized tools for parsing and analyzing
//! `HashiCorp Vault` audit logs. It's designed to handle large production logs
//! (multi-gigabyte files) efficiently through streaming parsing, parallel processing,
//! and minimal memory overhead.
//!
//! ## Performance
//!
//! - **3x faster** than equivalent Python implementations (single file)
//! - **40% faster** with automatic parallel processing (multi-file workloads)
//! - **10x less memory** usage through streaming parser
//! - Processes 4M line logs in ~17 seconds (vs ~60s in Python)
//! - Near-linear CPU scaling with available cores
//!
//! ### Real-world Benchmarks
//!
//! - KV Analysis: 141s -> 85s (40.1% faster with parallel processing)
//! - Memory usage: ~77 MB with parallel workers (2x overhead)
//! - Throughput: 233 MB/s (vs 140 MB/s sequential)
//!
//! ## Features
//!
//! - **Parallel Processing** - Automatically processes multiple files concurrently
//! - **16 specialized analysis commands** for different use cases
//! - **Compressed File Support** - Direct analysis of `.gz` and `.zst` files
//! - **Streaming JSON parser** for memory-efficient processing
//! - **Entity lifecycle tracking** across multiple days
//! - **Token usage analysis** and abuse detection
//! - **KV secrets engine analysis** (v1 and v2)
//! - **Kubernetes auth analysis**
//! - **Shell completion** for bash, zsh, fish, powershell, and elvish
//!
//! ## Architecture
//!
//! The crate is organized into several key modules:
//!
//! - [`audit`] - Core audit log parsing and data structures
//! - [`commands`] - Individual analysis command implementations
//! - [`utils`] - Shared utilities (parallel processing, progress, time parsing)
//! - [`vault_api`] - Vault API client for entity enrichment
//!
//! ## Example Usage
//!
//! ```bash
//! # System overview with automatic parallel processing
//! vault-audit system-overview logs/*.log
//!
//! # Entity analysis (unified command with auto-preprocessing)
//! vault-audit entity-analysis churn day1.log day2.log day3.log
//! vault-audit entity-analysis gaps audit.log
//!
//! # Token analysis with abuse detection
//! vault-audit token-analysis audit.log --abuse-threshold 5000
//!
//! # KV secrets analysis (40% faster with parallel processing)
//! vault-audit kv-analysis analyze logs/*.log --output kv_usage.csv
//!
//! # Compressed files work seamlessly
//! vault-audit path-hotspots audit.log.gz
//! ```
//!
//! ## Command Categories
//!
//! ### System Analysis (Parallel Processing)
//! - `system-overview` - High-level audit log statistics
//! - `path-hotspots` - Identify most accessed paths
//!
//! ### Entity Analysis (Unified Commands)
//! - `entity-analysis churn` - Multi-day entity lifecycle tracking
//! - `entity-analysis creation` - Track when entities first appear
//! - `entity-analysis gaps` - Find gaps in entity activity (parallel)
//! - `entity-analysis timeline` - Individual entity activity timeline
//! - `entity-analysis preprocess` - Extract entity mappings
//!
//! ### Token Analysis (Unified Command, Parallel Processing)
//! - `token-analysis` - Token lifecycle operations with abuse detection
//!
//! ### KV Secrets Analysis (Unified Commands, Parallel Processing)
//! - `kv-analysis analyze` - Analyze KV secret access patterns
//! - `kv-analysis compare` - Compare KV usage across time periods
//! - `kv-analysis summary` - Summarize KV usage by mount point
//!
//! ### Authentication Analysis (Parallel Processing)
//! - `k8s-auth` - Analyze Kubernetes/OpenShift authentication patterns
//!
//! ### Application-Specific (Parallel Processing)
//! - `airflow-polling` - Detect Airflow polling patterns
//!
//! ## Parallel Processing
//!
//! Commands automatically detect when multiple files are provided and process them
//! concurrently using all available CPU cores. Single-file operations use sequential
//! processing for optimal performance.
//!
//! Commands with parallel processing:
//! - `system-overview`, `entity-analysis gaps`, `path-hotspots`
//! - `k8s-auth`, `airflow-polling`, `token-analysis`, `kv-analysis analyze`
//!
//! ## Installation
//!
//! From crates.io:
//! ```bash
//! cargo install vault-audit-tools
//! ```
//!
//! From source:
//! ```bash
//! git clone https://github.com/trenner1/hashicorp-vault-audit-analysis
//! cd hashicorp-vault-audit-analysis
//! cargo install --path .
//! ```

pub mod audit;
pub mod commands;
pub mod utils;
pub mod vault_api;
