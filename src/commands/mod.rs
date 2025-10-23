//! Command implementations for analyzing Vault audit logs.
//!
//! Each module in this package implements a specific analysis command,
//! providing specialized insights into different aspects of Vault usage.
//!
//! ## Command Categories
//!
//! ### Entity Analysis Commands
//!
//! Track and analyze Vault identity entities across time:
//!
//! - [`entity_analysis`] - Unified entity lifecycle analysis, creation tracking, and preprocessing
//!   - `entity-analysis churn` - Compare entity activity across multiple days to detect churn
//!   - `entity-analysis creation` - Identify when entities first appear in logs
//!   - `entity-analysis gaps` - Find gaps in entity activity patterns
//!   - `entity-analysis timeline` - Visualize entity activity over time
//!   - `entity-analysis preprocess` - Extract entity data for external processing
//! - [`entity_list`] - List all entities found in audit logs
//! - [`entity_creation`] - ⚠️ DEPRECATED: Use `entity-analysis creation` instead
//! - [`entity_churn`] - ⚠️ DEPRECATED: Use `entity-analysis churn` instead
//! - [`entity_gaps`] - ⚠️ DEPRECATED: Use `entity-analysis gaps` instead
//! - [`entity_timeline`] - ⚠️ DEPRECATED: Use `entity-analysis timeline` instead
//! - [`preprocess_entities`] - ⚠️ DEPRECATED: Use `entity-analysis preprocess` instead
//!
//! ### Token Analysis Commands
//!
//! Analyze token lifecycle and usage patterns:
//!
//! - [`token_analysis`] - Unified token operations, abuse detection, and export
//! - [`token_operations`] - ⚠️ DEPRECATED: Use `token-analysis` instead
//! - [`token_lookup_abuse`] - ⚠️ DEPRECATED: Use `token-analysis --abuse-threshold` instead
//! - [`token_export`] - ⚠️ DEPRECATED: Use `token-analysis --export` instead
//!
//! ### KV Secrets Analysis Commands
//!
//! Understand KV secrets engine usage:
//!
//! - [`kv_analysis`] - Unified KV secrets analysis - usage, comparison, and summarization
//!   - `kv-analysis analyze` - Analyze KV secret access patterns and frequency
//!   - `kv-analysis compare` - Compare KV usage across different time periods
//!   - `kv-analysis summary` - Summarize KV usage by mount point
//! - [`kv_analyzer`] - ⚠️ DEPRECATED: Use `kv-analysis analyze` instead
//! - [`kv_summary`] - ⚠️ DEPRECATED: Use `kv-analysis summary` instead
//! - [`kv_compare`] - ⚠️ DEPRECATED: Use `kv-analysis compare` instead
//!
//! ### Authentication Analysis Commands
//!
//! Analyze authentication patterns:
//!
//! - [`k8s_auth`] - Analyze Kubernetes authentication patterns and service accounts
//!
//! ### System Analysis Commands
//!
//! High-level system insights:
//!
//! - [`system_overview`] - Generate high-level statistics about audit logs
//! - [`path_hotspots`] - Identify most frequently accessed paths
//! - [`client_activity`] - Analyze client access patterns
//! - [`airflow_polling`] - Detect Airflow polling behavior patterns

pub mod airflow_polling;
pub mod client_activity;
pub mod entity_analysis;
pub mod entity_churn;
pub mod entity_creation;
pub mod entity_gaps;
pub mod entity_list;
pub mod entity_timeline;
pub mod k8s_auth;
pub mod kv_analysis;
pub mod kv_analyzer;
pub mod kv_compare;
pub mod kv_summary;
pub mod path_hotspots;
pub mod preprocess_entities;
pub mod system_overview;
pub mod token_analysis;
pub mod token_export;
pub mod token_lookup_abuse;
pub mod token_operations;
