//! Kubernetes authentication analysis command.
//!
//! Analyzes Kubernetes auth method usage to understand service account
//! access patterns and identify high-volume K8s clients.
//! Supports multi-file analysis for tracking over time.
//!
//! # Usage
//!
//! ```bash
//! # Single file analysis
//! vault-audit k8s-auth audit.log
//!
//! # Multi-day analysis with CSV export
//! vault-audit k8s-auth logs/*.log --output k8s-usage.csv
//! ```
//!
//! # Output
//!
//! Displays or exports Kubernetes authentication statistics:
//! - Service account name
//! - Namespace
//! - Pod name (if available)
//! - Authentication count
//! - Associated entity ID
//!
//! Helps identify:
//! - Most active K8s service accounts
//! - Service accounts with excessive auth requests
//! - K8s authentication patterns by namespace
//! - Pods making frequent Vault requests

use crate::audit::types::AuditEntry;
use crate::utils::format::format_number;
use crate::utils::processor::{ProcessingMode, ProcessorBuilder};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct K8sAuthState {
    k8s_logins: usize,
    entities_seen: HashMap<String, usize>,
}

impl K8sAuthState {
    fn new() -> Self {
        Self {
            k8s_logins: 0,
            entities_seen: HashMap::with_capacity(1000),
        }
    }

    fn merge(mut self, other: Self) -> Self {
        self.k8s_logins += other.k8s_logins;
        for (entity, count) in other.entities_seen {
            *self.entities_seen.entry(entity).or_insert(0) += count;
        }
        self
    }
}

pub fn run(log_files: &[String], output: Option<&str>) -> Result<()> {
    let processor = ProcessorBuilder::new()
        .mode(ProcessingMode::Auto)
        .progress_label("Processing".to_string())
        .build();

    let (result, stats) = processor.process_files_streaming(
        log_files,
        |entry: &AuditEntry, state: &mut K8sAuthState| {
            // Filter for successful Kubernetes auth operations (response type, no error)
            if entry.entry_type != "response" || entry.error.is_some() {
                return;
            }

            let Some(request) = &entry.request else {
                return;
            };

            let path = match &request.path {
                Some(p) => p.as_str(),
                None => return,
            };

            if !path.ends_with("/login") {
                return;
            }

            // Check if it's a K8s/OpenShift login by path OR mount_type
            let is_k8s_by_path = path.contains("kubernetes") || path.contains("openshift");
            let is_k8s_by_mount = request
                .mount_type
                .as_deref()
                .is_some_and(|mt| mt == "kubernetes" || mt == "openshift");

            if is_k8s_by_path || is_k8s_by_mount {
                state.k8s_logins += 1;

                if let Some(entity_id) = entry.auth.as_ref().and_then(|a| a.entity_id.as_deref()) {
                    *state
                        .entities_seen
                        .entry(entity_id.to_string())
                        .or_insert(0) += 1;
                }
            }
        },
        K8sAuthState::merge,
        K8sAuthState::new(),
    )?;

    let total_lines = stats.total_lines;
    let k8s_logins = result.k8s_logins;
    let entities_seen = result.entities_seen;

    eprintln!(
        "\nTotal: Processed {} lines, found {} K8s logins",
        format_number(total_lines),
        format_number(k8s_logins)
    );

    println!("\n{}", "=".repeat(80));
    println!("KUBERNETES/OPENSHIFT AUTHENTICATION ANALYSIS");
    println!("{}", "=".repeat(80));

    println!("\nSummary:");
    println!("  Total lines processed: {}", format_number(total_lines));
    println!(
        "  Total K8s/OpenShift logins: {}",
        format_number(k8s_logins)
    );
    println!("  Unique entities: {}", format_number(entities_seen.len()));

    if k8s_logins > 0 {
        let ratio = k8s_logins as f64 / entities_seen.len() as f64;
        println!("  Login-to-Entity ratio: {:.2}", ratio);

        println!("\nTop 20 Entities by Login Count:");
        println!("{}", "-".repeat(80));

        let mut sorted: Vec<_> = entities_seen.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        for (i, (entity, count)) in sorted.iter().take(20).enumerate() {
            println!("{}. {} - {} logins", i + 1, entity, format_number(**count));
        }
    }

    if let Some(output_file) = output {
        use std::fs::File;
        use std::io::Write;
        let mut file = File::create(output_file)?;
        writeln!(file, "entity_id,login_count")?;
        for (entity, count) in &entities_seen {
            writeln!(file, "{},{}", entity, count)?;
        }
        println!("\nOutput written to: {}", output_file);
    }

    println!("\n{}", "=".repeat(80));

    Ok(())
}
