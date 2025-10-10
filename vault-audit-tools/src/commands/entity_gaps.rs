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

pub fn run(log_file: &str, _window_seconds: u64) -> Result<()> {
    println!("Analyzing no-entity operations in {}...", log_file);

    let mut reader = AuditLogReader::new(log_file)?;
    let mut operations_by_type: HashMap<String, usize> = HashMap::new();
    let mut paths_accessed: HashMap<String, usize> = HashMap::new();
    let mut display_names: HashMap<String, usize> = HashMap::new();

    let mut total_lines = 0;
    let mut no_entity_operations = 0;

    while let Some(entry) = reader.next_entry()? {
        total_lines += 1;

        if total_lines % 500_000 == 0 {
            eprintln!("  Processed {} lines, found {} no-entity operations...",
                format_number(total_lines), format_number(no_entity_operations));
        }

        // Check for no entity
        if entry.entity_id().is_some() {
            continue;
        }

        no_entity_operations += 1;

        // Track data
        if let Some(op) = entry.operation() {
            *operations_by_type.entry(op.to_string()).or_insert(0) += 1;
        }

        if let Some(path) = entry.path() {
            *paths_accessed.entry(path.to_string()).or_insert(0) += 1;
        }

        if let Some(name) = entry.display_name() {
            *display_names.entry(name.to_string()).or_insert(0) += 1;
        }
    }

    eprintln!("\nProcessed {} total lines", format_number(total_lines));
    eprintln!("Found {} operations with no entity ID", format_number(no_entity_operations));

    if no_entity_operations == 0 {
        println!("\nNo operations without entity ID found!");
        return Ok(());
    }

    println!("\n{}", "=".repeat(100));
    println!("NO-ENTITY OPERATIONS ANALYSIS");
    println!("{}", "=".repeat(100));

    println!("\n1. SUMMARY");
    println!("{}", "-".repeat(100));
    println!("Total no-entity operations: {}", format_number(no_entity_operations));
    println!("Percentage of all operations: {:.2}%", 
        (no_entity_operations as f64 / total_lines as f64) * 100.0);

    println!("\n2. OPERATION TYPE DISTRIBUTION");
    println!("{}", "-".repeat(100));
    println!("{:<30} {:<15} {:<15}", "Operation", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_ops: Vec<_> = operations_by_type.iter().collect();
    sorted_ops.sort_by(|a, b| b.1.cmp(a.1));

    for (op, count) in sorted_ops.iter().take(20) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        println!("{:<30} {:<15} {:<15.2}%", op, format_number(**count), percentage);
    }

    println!("\n3. TOP 30 PATHS ACCESSED");
    println!("{}", "-".repeat(100));
    println!("{:<70} {:<15} {:<15}", "Path", "Count", "% of No-Entity");
    println!("{}", "-".repeat(100));

    let mut sorted_paths: Vec<_> = paths_accessed.iter().collect();
    sorted_paths.sort_by(|a, b| b.1.cmp(a.1));

    for (path, count) in sorted_paths.iter().take(30) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        let display_path = if path.len() > 68 {
            format!("{}...", &path[..65])
        } else {
            path.to_string()
        };
        println!("{:<70} {:<15} {:<15.2}%", display_path, format_number(**count), percentage);
    }

    println!("\n4. TOP 30 DISPLAY NAMES");
    println!("{}", "-".repeat(100));
    println!("{:<60} {:<20} {:<15}", "Display Name", "Count", "Percentage");
    println!("{}", "-".repeat(100));

    let mut sorted_names: Vec<_> = display_names.iter().collect();
    sorted_names.sort_by(|a, b| b.1.cmp(a.1));

    for (name, count) in sorted_names.iter().take(30) {
        let percentage = (**count as f64 / no_entity_operations as f64) * 100.0;
        let display_name = if name.len() > 58 {
            format!("{}...", &name[..55])
        } else {
            name.to_string()
        };
        println!("{:<60} {:<20} {:<15.2}%", display_name, format_number(**count), percentage);
    }

    println!("\n{}", "=".repeat(100));

    Ok(())
}
