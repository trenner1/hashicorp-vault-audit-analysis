//! # Vault Audit Tools
//!
//! High-performance command-line tools for analyzing `HashiCorp` Vault audit logs.
//!
//! ## Overview
//!
//! This crate provides a suite of specialized tools for parsing and analyzing
//! `HashiCorp` Vault audit logs. It's designed to handle large production logs
//! (multi-gigabyte files) efficiently through streaming parsing and minimal
//! memory overhead.
//!
//! ## Performance
//!
//! - **3x faster** than equivalent Python implementations
//! - **10x less memory** usage through streaming parser
//! - Processes 4M line logs in ~17 seconds (vs ~60s in Python)
//!
//! ## Features
//!
//! - **16 specialized analysis commands** for different use cases
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
//! - [`utils`] - Shared utilities for time parsing, progress display, etc.
//! - [`vault_api`] - Vault API client for entity enrichment
//!
//! ## Example Usage
//!
//! ```bash
//! # Analyze entity creation patterns
//! vault-audit entity-creation audit.log
//!
//! # Compare entity activity across days to detect churn
//! vault-audit entity-churn audit-today.log --baseline audit-yesterday.log
//!
//! # Analyze KV secret access patterns
//! vault-audit kv-analyzer audit.log
//!
//! # Detect token lookup abuse
//! vault-audit token-lookup-abuse audit.log
//! ```
//!
//! ## Command Categories
//!
//! ### Entity Analysis
//! - `entity-creation` - Track when entities first appear
//! - `entity-churn` - Compare activity across multiple days
//! - `entity-gaps` - Find gaps in entity activity
//! - `entity-timeline` - Visualize entity activity over time
//!
//! ### Token Analysis
//! - `token-operations` - Analyze token lifecycle operations
//! - `token-lookup-abuse` - Detect suspicious token lookup patterns
//! - `token-export` - Export token data for analysis
//!
//! ### KV Secrets Analysis
//! - `kv-analyzer` - Analyze KV secret access patterns
//! - `kv-summary` - Summarize KV usage by mount point
//! - `kv-compare` - Compare KV usage across time periods
//!
//! ### Authentication Analysis
//! - `k8s-auth` - Analyze Kubernetes authentication patterns
//!
//! ### System Analysis
//! - `system-overview` - High-level audit log statistics
//! - `path-hotspots` - Identify most accessed paths
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
//! cd hashicorp-vault-audit-analysis/vault-audit-tools
//! cargo install --path .
//! ```

pub mod audit;
pub mod commands;
pub mod utils;
pub mod vault_api;
