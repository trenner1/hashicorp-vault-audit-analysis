use crate::audit::parser::AuditLogReader;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;

#[derive(Debug, Default)]
struct TokenData {
    lookups: usize,
    first_seen: String,
    last_seen: String,
}

#[derive(Debug)]
struct EntityData {
    display_name: String,
    tokens: HashMap<String, TokenData>,
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

fn calculate_time_span_hours(first: &str, last: &str) -> f64 {
    use chrono::DateTime;

    let first_dt = DateTime::parse_from_rfc3339(first).ok();
    let last_dt = DateTime::parse_from_rfc3339(last).ok();

    if let (Some(first), Some(last)) = (first_dt, last_dt) {
        let duration = last.signed_duration_since(first);
        duration.num_seconds() as f64 / 3600.0
    } else {
        0.0
    }
}

pub fn run(log_file: &str, output: &str, min_lookups: usize) -> Result<()> {
    eprintln!("Processing: {}", log_file);

    let mut reader = AuditLogReader::new(log_file)?;
    let mut entities: HashMap<String, EntityData> = HashMap::new();
    let mut total_lines = 0;
    let mut lookup_count = 0;

    while let Some(entry) = reader.next_entry()? {
        total_lines += 1;

        if total_lines % 100_000 == 0 {
            eprintln!(
                "[INFO] Processed {} lines, found {} token lookups",
                format_number(total_lines),
                format_number(lookup_count)
            );
        }

        // Filter for token lookup operations
        if let Some(path) = entry.path() {
            if !path.starts_with("auth/token/lookup") {
                continue;
            }
        } else {
            continue;
        }

        let entity_id = match entry.entity_id() {
            Some(id) => id,
            None => continue,
        };

        lookup_count += 1;

        let entity_data = entities
            .entry(entity_id.to_string())
            .or_insert_with(|| EntityData {
                display_name: entry.display_name().unwrap_or("N/A").to_string(),
                tokens: HashMap::new(),
            });

        let accessor = entry
            .auth
            .as_ref()
            .and_then(|a| a.accessor.as_deref())
            .unwrap_or("unknown")
            .to_string();

        let timestamp = entry.time.clone();

        let token_data = entity_data.tokens.entry(accessor).or_default();
        token_data.lookups += 1;

        if token_data.first_seen.is_empty() {
            token_data.first_seen = timestamp.clone();
        }
        token_data.last_seen = timestamp;
    }

    eprintln!(
        "[INFO] Processed {} total lines",
        format_number(total_lines)
    );
    eprintln!(
        "[INFO] Found {} token lookup operations",
        format_number(lookup_count)
    );
    eprintln!(
        "[INFO] Found {} unique entities",
        format_number(entities.len())
    );

    // Prepare CSV rows
    let mut rows: Vec<_> = entities
        .iter()
        .flat_map(|(entity_id, entity_data)| {
            entity_data
                .tokens
                .iter()
                .map(move |(accessor, token_data)| {
                    let time_span =
                        calculate_time_span_hours(&token_data.first_seen, &token_data.last_seen);
                    let lookups_per_hour = if time_span > 0.0 {
                        token_data.lookups as f64 / time_span
                    } else {
                        0.0
                    };

                    (
                        entity_id.clone(),
                        entity_data.display_name.clone(),
                        accessor.clone(),
                        token_data.lookups,
                        time_span,
                        lookups_per_hour,
                        token_data.first_seen.clone(),
                        token_data.last_seen.clone(),
                    )
                })
        })
        .collect();

    // Sort by total lookups descending
    rows.sort_by(|a, b| b.3.cmp(&a.3));

    // Filter by minimum lookups
    rows.retain(|row| row.3 >= min_lookups);

    // Create output directory if needed
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Write CSV
    let file = File::create(output).context("Failed to create output file")?;
    let mut writer = csv::Writer::from_writer(file);

    writer.write_record([
        "entity_id",
        "display_name",
        "token_accessor",
        "total_lookups",
        "time_span_hours",
        "lookups_per_hour",
        "first_seen",
        "last_seen",
    ])?;

    for (entity_id, display_name, accessor, lookups, time_span, rate, first, last) in &rows {
        writer.write_record([
            entity_id,
            display_name,
            accessor,
            &lookups.to_string(),
            &format!("{:.2}", time_span),
            &format!("{:.2}", rate),
            first,
            last,
        ])?;
    }

    writer.flush()?;

    eprintln!(
        "\n[SUCCESS] Exported {} token lookup records to: {}",
        format_number(rows.len()),
        output
    );

    // Print summary
    let total_lookups: usize = rows.iter().map(|r| r.3).sum();
    let unique_entities = entities.len();
    let unique_tokens = rows.len();

    eprintln!("\n{}", "=".repeat(80));
    eprintln!("Summary Statistics:");
    eprintln!("{}", "-".repeat(80));
    eprintln!(
        "Total Token Lookup Operations: {}",
        format_number(total_lookups)
    );
    eprintln!("Unique Entities: {}", format_number(unique_entities));
    eprintln!("Unique Token Accessors: {}", format_number(unique_tokens));
    eprintln!(
        "Average Lookups per Token: {:.1}",
        total_lookups as f64 / unique_tokens as f64
    );

    // Top 5 entities by lookup count
    let mut entity_totals: HashMap<String, usize> = HashMap::new();
    let mut entity_names: HashMap<String, String> = HashMap::new();
    for (entity_id, display_name, _, lookups, _, _, _, _) in &rows {
        *entity_totals.entry(entity_id.clone()).or_insert(0) += lookups;
        entity_names.insert(entity_id.clone(), display_name.clone());
    }

    let mut top_entities: Vec<_> = entity_totals.into_iter().collect();
    top_entities.sort_by(|a, b| b.1.cmp(&a.1));

    eprintln!("\nTop 5 Entities by Lookup Count:");
    eprintln!("{}", "-".repeat(80));
    for (i, (entity_id, count)) in top_entities.iter().take(5).enumerate() {
        let name = entity_names.get(entity_id).unwrap();
        eprintln!(
            "{}. {} ({}): {} lookups",
            i + 1,
            name,
            entity_id,
            format_number(*count)
        );
    }

    eprintln!("{}", "=".repeat(80));
    eprintln!("\n✓ Token lookup data exported to: {}", output);

    Ok(())
}
