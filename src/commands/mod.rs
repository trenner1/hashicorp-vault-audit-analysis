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
//! - [`entity_creation`] - Identify when entities first appear in logs
//! - [`entity_churn`] - Compare entity activity across multiple days to detect churn
//! - [`entity_gaps`] - Find gaps in entity activity patterns
//! - [`entity_timeline`] - Visualize entity activity over time
//! - [`entity_list`] - List all entities found in audit logs
//! - [`preprocess_entities`] - Extract entity data for external processing
//!
//! ### Token Analysis Commands
//!
//! Analyze token lifecycle and usage patterns:
//!
//! - [`token_operations`] - Track token creation, renewal, and revocation
//! - [`token_lookup_abuse`] - Detect suspicious token lookup patterns
//! - [`token_export`] - Export token metadata for analysis
//!
//! ### KV Secrets Analysis Commands
//!
//! Understand KV secrets engine usage:
//!
//! - [`kv_analyzer`] - Analyze KV secret access patterns and frequency
//! - [`kv_summary`] - Summarize KV usage by mount point
//! - [`kv_compare`] - Compare KV usage across different time periods
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
pub mod entity_churn;
pub mod entity_creation;
pub mod entity_gaps;
pub mod entity_list;
pub mod entity_timeline;
pub mod k8s_auth;
pub mod kv_analyzer;
pub mod kv_compare;
pub mod kv_summary;
pub mod path_hotspots;
pub mod preprocess_entities;
pub mod system_overview;
pub mod token_export;
pub mod token_lookup_abuse;
pub mod token_operations;
