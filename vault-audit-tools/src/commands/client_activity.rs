use crate::vault_api::{extract_data, should_skip_verify, VaultClient};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize)]
struct MountInfo {
    #[serde(rename = "type")]
    mount_type: Option<String>,
    accessor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActivityRecord {
    client_id: String,
    client_type: Option<String>,
    mount_accessor: Option<String>,
    mount_path: Option<String>,
    mount_type: Option<String>,
    entity_alias_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EntityMapping {
    display_name: String,
    #[allow(dead_code)]
    mount_path: String,
    #[allow(dead_code)]
    mount_accessor: String,
    #[allow(dead_code)]
    username: Option<String>,
    #[allow(dead_code)]
    login_count: usize,
    #[allow(dead_code)]
    first_seen: String,
    #[allow(dead_code)]
    last_seen: String,
}

#[derive(Debug, Serialize)]
struct MountActivity {
    mount: String,
    #[serde(rename = "type")]
    mount_type: String,
    accessor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    total: usize,
    entity: usize,
    non_entity: usize,
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

#[allow(clippy::too_many_arguments)]
pub async fn run(
    start_time: &str,
    end_time: &str,
    vault_addr: Option<&str>,
    vault_token: Option<&str>,
    insecure: bool,
    group_by_role: bool,
    entity_map_path: Option<&str>,
    output: Option<&str>,
) -> Result<()> {
    let skip_verify = should_skip_verify(insecure);
    let client = VaultClient::from_options(vault_addr, vault_token, skip_verify)?;

    eprintln!("=== Vault Client Activity Analysis ===");
    eprintln!("Vault Address: {}", client.addr());
    eprintln!("Time Window: {} to {}", start_time, end_time);
    if skip_verify {
        eprintln!("⚠️  TLS certificate verification is DISABLED");
    }
    eprintln!();

    // Load entity mappings if provided
    let entity_map: Option<HashMap<String, EntityMapping>> = if let Some(path) = entity_map_path {
        eprintln!("Loading entity mappings from: {}", path);
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open entity map file: {}", path))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let map: HashMap<String, EntityMapping> = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse entity map JSON: {}", path))?;
        eprintln!("Loaded {} entity mappings", map.len());
        Some(map)
    } else {
        None
    };

    // Build mount lookup map
    eprintln!("Fetching mount information...");
    let mount_map = fetch_mount_map(&client).await?;
    eprintln!("Found {} mounts", mount_map.len());

    // Fetch activity export
    eprintln!("Fetching client activity data...");
    let export_path = format!(
        "/v1/sys/internal/counters/activity/export?start_time={}&end_time={}&format=json",
        start_time, end_time
    );

    let export_text = client.get_text(&export_path).await?;

    // Parse NDJSON (newline-delimited JSON) or regular JSON
    let records: Vec<ActivityRecord> = if export_text.trim().starts_with('[') {
        // Regular JSON array
        serde_json::from_str(&export_text)?
    } else {
        // NDJSON - parse line by line
        export_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    };

    if records.is_empty() {
        eprintln!("No activity data found for the specified time range.");
        return Ok(());
    }

    eprintln!(
        "Processing {} activity records...",
        format_number(records.len())
    );

    // Group by mount and count unique clients
    let mut mount_activities: HashMap<String, MountActivityData> = HashMap::new();

    for record in &records {
        let accessor = record
            .mount_accessor
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        let (mount_path, mount_type) = if let Some(info) = mount_map.get(&accessor) {
            (info.0.clone(), info.1.clone())
        } else {
            (
                record
                    .mount_path
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                record
                    .mount_type
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        };

        // Extract role/appcode if grouping by role
        let role = if group_by_role {
            // Try entity_alias_name from export first (Vault 1.20+)
            if let Some(alias_name) = &record.entity_alias_name {
                Some(alias_name.clone())
            } else if let Some(ref entity_map) = entity_map {
                // Fallback to entity map (Vault 1.16 or when alias_name is missing)
                entity_map
                    .get(&record.client_id)
                    .map(|e| e.display_name.clone())
            } else {
                None
            }
        } else {
            None
        };

        // Create unique key based on grouping mode
        let key = if group_by_role {
            format!(
                "{}|{}|{}|{}",
                mount_path,
                mount_type,
                accessor,
                role.as_deref().unwrap_or("unknown")
            )
        } else {
            format!("{}|{}|{}", mount_path, mount_type, accessor)
        };

        let activity = mount_activities
            .entry(key)
            .or_insert_with(|| MountActivityData {
                mount: mount_path,
                mount_type,
                accessor,
                role: role.clone(),
                total_clients: std::collections::HashSet::new(),
                entity_clients: std::collections::HashSet::new(),
                non_entity_clients: std::collections::HashSet::new(),
            });

        activity.total_clients.insert(record.client_id.clone());

        if record.client_type.as_deref() == Some("entity") {
            activity.entity_clients.insert(record.client_id.clone());
        } else {
            activity.non_entity_clients.insert(record.client_id.clone());
        }
    }

    // Convert to output format
    let mut results: Vec<MountActivity> = mount_activities
        .into_values()
        .map(|data| {
            // Concatenate mount + role for the mount field if role exists
            let mount_display = if let Some(ref role) = data.role {
                format!("{}{}", data.mount, role)
            } else {
                data.mount.clone()
            };

            MountActivity {
                mount: mount_display,
                mount_type: data.mount_type,
                accessor: data.accessor,
                role: None, // Don't include role as separate field anymore
                total: data.total_clients.len(),
                entity: data.entity_clients.len(),
                non_entity: data.non_entity_clients.len(),
            }
        })
        .collect();

    // Sort by mount path
    results.sort_by(|a, b| a.mount.cmp(&b.mount));

    // Calculate totals
    let total_clients: usize = results.iter().map(|r| r.total).sum();
    let total_entity: usize = results.iter().map(|r| r.entity).sum();
    let total_non_entity: usize = results.iter().map(|r| r.non_entity).sum();

    eprintln!();
    eprintln!("=== Summary ===");
    eprintln!("Total Clients: {}", format_number(total_clients));
    eprintln!("  Entity Clients: {}", format_number(total_entity));
    eprintln!("  Non-Entity Clients: {}", format_number(total_non_entity));
    eprintln!("Mounts Analyzed: {}", results.len());
    eprintln!();

    // Output results
    if let Some(output_path) = output {
        let file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;
        let mut writer = csv::Writer::from_writer(file);

        writer.write_record(["mount", "type", "accessor", "total", "entity", "non_entity"])?;
        for result in &results {
            writer.write_record([
                &result.mount,
                &result.mount_type,
                &result.accessor,
                &result.total.to_string(),
                &result.entity.to_string(),
                &result.non_entity.to_string(),
            ])?;
        }

        writer.flush()?;
        eprintln!("CSV written to: {}", output_path);
    } else {
        // JSON output to stdout
        println!("{}", serde_json::to_string_pretty(&results)?);
    }

    Ok(())
}

#[derive(Debug)]
struct MountActivityData {
    mount: String,
    mount_type: String,
    accessor: String,
    role: Option<String>,
    total_clients: std::collections::HashSet<String>,
    entity_clients: std::collections::HashSet<String>,
    non_entity_clients: std::collections::HashSet<String>,
}

async fn fetch_mount_map(client: &VaultClient) -> Result<HashMap<String, (String, String)>> {
    let mut map = HashMap::new();

    // Try /sys/mounts (secret engines)
    if let Ok(mounts_data) = client.get_json("/v1/sys/mounts").await {
        if let Ok(mounts) = extract_data::<HashMap<String, MountInfo>>(mounts_data) {
            for (path, info) in mounts {
                if let Some(accessor) = info.accessor {
                    map.insert(
                        accessor,
                        (
                            path,
                            info.mount_type.unwrap_or_else(|| "unknown".to_string()),
                        ),
                    );
                }
            }
        }
    }

    // Try /sys/auth (auth methods)
    if let Ok(auth_data) = client.get_json("/v1/sys/auth").await {
        if let Ok(auths) = extract_data::<HashMap<String, MountInfo>>(auth_data) {
            for (path, info) in auths {
                if let Some(accessor) = info.accessor {
                    map.insert(
                        accessor,
                        (
                            path,
                            info.mount_type.unwrap_or_else(|| "unknown".to_string()),
                        ),
                    );
                }
            }
        }
    }

    Ok(map)
}
