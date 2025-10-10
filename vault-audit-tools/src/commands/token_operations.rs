use crate::audit::AuditLogReader;
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Default)]
struct TokenOps {
    lookup_self: usize,
    renew_self: usize,
    revoke_self: usize,
    create: usize,
    other: usize,
    display_name: Option<String>,
    username: Option<String>,
}

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
    eprintln!("Processing: {}", log_file);

    let mut token_ops: HashMap<String, TokenOps> = HashMap::new();
    let mut total_lines = 0;

    let mut reader = AuditLogReader::new(log_file)?;

    while let Some(entry) = reader.next_entry()? {
        total_lines += 1;

        // Filter for token operations
        let Some(path) = entry.path() else { continue };
        if !path.starts_with("auth/token/") {
            continue;
        }

        let Some(entity_id) = entry.entity_id() else {
            continue;
        };
        let operation = entry.operation().unwrap_or("");

        let ops = token_ops.entry(entity_id.to_string()).or_default();

        // Categorize operation
        if path.contains("lookup-self") {
            ops.lookup_self += 1;
        } else if path.contains("renew-self") {
            ops.renew_self += 1;
        } else if path.contains("revoke-self") {
            ops.revoke_self += 1;
        } else if path.contains("create") || operation == "create" {
            ops.create += 1;
        } else {
            ops.other += 1;
        }

        // Capture display name and metadata (first occurrence)
        if ops.display_name.is_none() {
            ops.display_name = entry.display_name().map(|s| s.to_string());
            if let Some(auth) = &entry.auth {
                if let Some(metadata) = &auth.metadata {
                    if let Some(username) = metadata.get("username") {
                        ops.username = username.as_str().map(|s| s.to_string());
                    }
                }
            }
        }
    }

    eprintln!("[INFO] Processed {} lines", format_number(total_lines));

    // Calculate totals per entity
    let mut entity_totals: Vec<_> = token_ops
        .iter()
        .map(|(entity_id, ops)| {
            let total = ops.lookup_self + ops.renew_self + ops.revoke_self + ops.create + ops.other;
            (
                entity_id.clone(),
                total,
                ops.display_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                ops.lookup_self,
                ops.renew_self,
                ops.revoke_self,
                ops.create,
                ops.other,
                ops.username.clone().unwrap_or_default(),
            )
        })
        .filter(|x| x.1 > 0)
        .collect();

    // Sort by total operations
    entity_totals.sort_by(|a, b| b.1.cmp(&a.1));

    // Display results
    let top = 50;
    println!("\n{}", "=".repeat(140));
    println!(
        "{:<30} {:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
        "Display Name", "Username", "Total", "Lookup", "Renew", "Revoke", "Create", "Other"
    );
    println!("{}", "=".repeat(140));

    let mut grand_total = 0;
    for (_, total, display_name, lookup, renew, revoke, create, other, username) in
        entity_totals.iter().take(top)
    {
        let display_name_trunc = if display_name.len() > 29 {
            &display_name[..29]
        } else {
            display_name
        };
        let username_trunc = if username.len() > 24 {
            &username[..24]
        } else {
            username
        };

        println!(
            "{:<30} {:<25} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
            display_name_trunc,
            username_trunc,
            format_number(*total),
            format_number(*lookup),
            format_number(*renew),
            format_number(*revoke),
            format_number(*create),
            format_number(*other)
        );
        grand_total += total;
    }

    println!("{}", "=".repeat(140));
    println!(
        "{:<55} {:<10}",
        format!("TOTAL (top {})", entity_totals.len().min(top)),
        format_number(grand_total)
    );
    println!(
        "{:<55} {:<10}",
        "TOTAL ENTITIES",
        format_number(entity_totals.len())
    );
    println!("{}", "=".repeat(140));

    // Summary by operation type
    let total_lookup: usize = entity_totals.iter().map(|x| x.3).sum();
    let total_renew: usize = entity_totals.iter().map(|x| x.4).sum();
    let total_revoke: usize = entity_totals.iter().map(|x| x.5).sum();
    let total_create: usize = entity_totals.iter().map(|x| x.6).sum();
    let total_other: usize = entity_totals.iter().map(|x| x.7).sum();
    let overall_total = total_lookup + total_renew + total_revoke + total_create + total_other;

    println!("\nOperation Type Breakdown:");
    println!("{}", "-".repeat(60));
    println!(
        "Lookup (lookup-self):  {:>12}  ({:>5.1}%)",
        format_number(total_lookup),
        (total_lookup as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Renew (renew-self):    {:>12}  ({:>5.1}%)",
        format_number(total_renew),
        (total_renew as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Revoke (revoke-self):  {:>12}  ({:>5.1}%)",
        format_number(total_revoke),
        (total_revoke as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Create:                {:>12}  ({:>5.1}%)",
        format_number(total_create),
        (total_create as f64 / overall_total as f64) * 100.0
    );
    println!(
        "Other:                 {:>12}  ({:>5.1}%)",
        format_number(total_other),
        (total_other as f64 / overall_total as f64) * 100.0
    );
    println!("{}", "-".repeat(60));
    println!(
        "TOTAL:                 {:>12}",
        format_number(overall_total)
    );

    // TODO: CSV output if specified
    if let Some(_output_path) = output {
        eprintln!("Note: CSV output not yet implemented");
    }

    Ok(())
}
