use crate::audit::parser::AuditLogReader;
use anyhow::Result;
use std::collections::HashMap;

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
    println!("Analyzing Kubernetes authentication patterns in {}...", log_file);

    let mut reader = AuditLogReader::new(log_file)?;
    let mut k8s_logins = 0;
    let mut entities_seen: HashMap<String, usize> = HashMap::new();
    let mut total_lines = 0;

    while let Some(entry) = reader.next_entry()? {
        total_lines += 1;

        if total_lines % 500_000 == 0 {
            eprintln!("  Processed {} lines...", format_number(total_lines));
        }

        // Filter for successful Kubernetes auth operations (response type, no error)
        if entry.entry_type == "response" && entry.error.is_none() {
            if let Some(path) = entry.path() {
                if path.ends_with("/login") {
                    // Check if it's a K8s/OpenShift login by path OR mount_type
                    let is_k8s_by_path = path.contains("kubernetes") || path.contains("openshift");
                    let is_k8s_by_mount = entry.mount_type()
                        .map(|mt| mt == "kubernetes" || mt == "openshift")
                        .unwrap_or(false);
                    
                    if is_k8s_by_path || is_k8s_by_mount {
                        k8s_logins += 1;

                        if let Some(entity_id) = entry.entity_id() {
                            *entities_seen.entry(entity_id.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    println!("\n{}", "=".repeat(80));
    println!("KUBERNETES/OPENSHIFT AUTHENTICATION ANALYSIS");
    println!("{}", "=".repeat(80));

    println!("\nSummary:");
    println!("  Total lines processed: {}", format_number(total_lines));
    println!("  Total K8s/OpenShift logins: {}", format_number(k8s_logins));
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
