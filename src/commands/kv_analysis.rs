//! Unified KV secrets analysis command.
//!
//! Consolidates KV usage analysis, comparison, and summarization into a single
//! powerful command with consistent interface and shared logic.
//!
//! # Usage
//!
//! ```bash
//! # Analyze KV usage from audit logs
//! vault-audit kv-analysis analyze logs/*.log --output kv_usage.csv
//! vault-audit kv-analysis analyze logs/*.log --kv-prefix appcodes/ --output appcodes.csv
//!
//! # Compare KV usage between time periods
//! vault-audit kv-analysis compare old_usage.csv new_usage.csv
//!
//! # Summarize KV usage from CSV
//! vault-audit kv-analysis summary kv_usage.csv
//! ```
//!
//! # Subcommands
//!
//! ## analyze
//! Comprehensive KV usage analysis from audit logs. Processes single or multiple
//! log files (plain or compressed) to generate detailed usage statistics per path
//! and entity. Supports filtering by KV mount prefix.
//!
//! ## compare
//! Compare KV usage patterns between two time periods. Identifies changes in
//! access patterns, new secrets, abandoned secrets, and usage trends.
//!
//! ## summary
//! Quick overview of KV usage from CSV exports. Shows aggregated statistics,
//! top accessed secrets, and breakdown by mount point.

use anyhow::Result;

/// Run analyze subcommand
pub fn run_analyze(
    log_files: &[String],
    kv_prefix: &str,
    output: Option<&String>,
    entity_csv: Option<&String>,
) -> Result<()> {
    // Delegate to existing kv_analyzer implementation
    crate::commands::kv_analyzer::run(
        log_files,
        kv_prefix,
        output.map(std::string::String::as_str),
        entity_csv.map(std::string::String::as_str),
    )
}

/// Run compare subcommand
pub fn run_compare(csv1: &str, csv2: &str) -> Result<()> {
    // Delegate to existing kv_compare implementation
    crate::commands::kv_compare::run(csv1, csv2)
}

/// Run summary subcommand
pub fn run_summary(csv_file: &str) -> Result<()> {
    // Delegate to existing kv_summary implementation
    crate::commands::kv_summary::run(csv_file)
}
