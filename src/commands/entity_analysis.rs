//! Unified entity analysis command.
//!
//! Consolidates entity lifecycle tracking, creation analysis, preprocessing,
//! gap detection, and timeline analysis into a single powerful command with
//! intelligent auto-preprocessing to eliminate multi-step workflows.
//!
//! # Usage
//!
//! ```bash
//! # Churn analysis (auto-preprocesses entity mappings)
//! vault-audit entity-analysis churn logs/day1.log logs/day2.log
//! vault-audit entity-analysis churn logs/*.log --baseline entities.json
//!
//! # Creation analysis by auth path
//! vault-audit entity-analysis creation logs/*.log
//! vault-audit entity-analysis creation logs/*.log --export creation_data.json
//!
//! # Extract entity mappings (preprocessing)
//! vault-audit entity-analysis preprocess logs/*.log --output mappings.json
//! vault-audit entity-analysis preprocess logs/*.log --format csv
//!
//! # Detect activity gaps for entities
//! vault-audit entity-analysis gaps logs/*.log --window-seconds 300
//!
//! # Individual entity timeline
//! vault-audit entity-analysis timeline logs/*.log --entity-id abc-123
//! ```
//!
//! **Key Improvement**: Auto-preprocessing eliminates the need for separate
//! preprocessing steps. Entity mappings are built in-memory automatically when
//! needed by churn or creation analysis.
//!
//! # Subcommands
//!
//! ## churn
//! Multi-day entity lifecycle tracking with ephemeral pattern detection.
//! Automatically preprocesses entity mappings unless `--no-auto-preprocess` is specified.
//!
//! ## creation
//! Analyzes when entities were first created, grouped by authentication path.
//! Shows new entity onboarding patterns and growth trends.
//!
//! ## preprocess
//! Extracts entity-to-display-name mappings from audit logs for external use.
//! Outputs JSON or CSV format for integration with other tools.
//!
//! ## gaps
//! Detects entities with suspicious activity gaps (potential compromised credentials
//! or entities that should have been cleaned up).
//!
//! ## timeline
//! Shows chronological activity for a specific entity ID, useful for debugging
//! or investigating specific identity issues.

use anyhow::Result;

/// Run churn analysis subcommand
pub fn run_churn(
    log_files: &[String],
    entity_map: Option<&String>,
    baseline: Option<&String>,
    output: Option<&String>,
    format: Option<&String>,
    _auto_preprocess: bool,
) -> Result<()> {
    // Delegate to existing entity_churn implementation
    crate::commands::entity_churn::run(
        log_files,
        entity_map.map(|s| s.as_str()),
        baseline.map(|s| s.as_str()),
        output.map(|s| s.as_str()),
        format.map(|s| s.as_str()),
    )
}

/// Run creation analysis subcommand
pub fn run_creation(
    log_files: &[String],
    entity_map: Option<&String>,
    output: Option<&String>,
    _auto_preprocess: bool,
) -> Result<()> {
    // Delegate to existing entity_creation implementation
    crate::commands::entity_creation::run(
        log_files,
        entity_map.map(|s| s.as_str()),
        output.map(|s| s.as_str()),
    )
}

/// Run preprocess subcommand
pub fn run_preprocess(log_files: &[String], output: &str, format: &str) -> Result<()> {
    // Delegate to existing preprocess_entities implementation
    crate::commands::preprocess_entities::run(log_files, output, format)
}

/// Run gaps detection subcommand
pub fn run_gaps(log_files: &[String], window_seconds: u64) -> Result<()> {
    // Delegate to existing entity_gaps implementation
    crate::commands::entity_gaps::run(log_files, window_seconds)
}

/// Run timeline subcommand
pub fn run_timeline(
    log_files: &[String],
    entity_id: &str,
    display_name: Option<&String>,
) -> Result<()> {
    // Convert Option<&String> to &Option<String> for compatibility
    let display_name_owned = display_name.cloned();
    // Delegate to existing entity_timeline implementation
    crate::commands::entity_timeline::run(log_files, entity_id, &display_name_owned)
}
