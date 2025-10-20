use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

pub fn run(log_file: &str, output: Option<&str>) -> Result<()> {
    // Get file size for progress tracking
    let file_size = std::fs::metadata(log_file).ok().map(|m| m.len() as usize);
    let mut progress = if let Some(size) = file_size {
        ProgressBar::new(size, "Processing")
    } else {
        ProgressBar::new_spinner("Processing")
    };

    let file = File::open(log_file)?;
    let reader = BufReader::new(file);

    let mut k8s_logins = 0;
    let mut entities_seen: HashMap<String, usize> = HashMap::new();
    let mut total_lines = 0;
    let mut bytes_read = 0;

    for line in reader.lines() {
        total_lines += 1;
        let line = line?;
        bytes_read += line.len() + 1; // +1 for newline

        // Update progress every 10k lines for smooth animation
        if total_lines % 10_000 == 0 {
            if let Some(size) = file_size {
                progress.update(bytes_read.min(size)); // Cap at file size
            } else {
                progress.update(total_lines);
            }
        }

        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Filter for successful Kubernetes auth operations (response type, no error)
        if entry.entry_type != "response" || entry.error.is_some() {
            continue;
        }

        let request = match &entry.request {
            Some(r) => r,
            None => continue,
        };

        let path = match &request.path {
            Some(p) => p.as_str(),
            None => continue,
        };

        if !path.ends_with("/login") {
            continue;
        }

        // Check if it's a K8s/OpenShift login by path OR mount_type
        let is_k8s_by_path = path.contains("kubernetes") || path.contains("openshift");
        let is_k8s_by_mount = request
            .mount_type
            .as_deref()
            .map(|mt| mt == "kubernetes" || mt == "openshift")
            .unwrap_or(false);

        if is_k8s_by_path || is_k8s_by_mount {
            k8s_logins += 1;

            if let Some(entity_id) = entry.auth.as_ref().and_then(|a| a.entity_id.as_deref()) {
                *entities_seen.entry(entity_id.to_string()).or_insert(0) += 1;
            }
        }
    }

    // Ensure 100% progress
    if let Some(size) = file_size {
        progress.update(size);
    }

    progress.finish_with_message(&format!(
        "Processed {} lines, found {} K8s/OpenShift logins from {} entities",
        format_number(total_lines),
        format_number(k8s_logins),
        format_number(entities_seen.len())
    ));

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
