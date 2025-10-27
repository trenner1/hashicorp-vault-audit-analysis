//! Entity list export command.
//!
//! Queries the Vault API to export a complete list of entities with their
//! aliases, useful for establishing baselines for entity churn analysis.
//!
//! # Usage
//!
//! ```bash
//! # Export all entities as CSV (default)
//! vault-audit entity-list --output entities.csv
//!
//! # Export as JSON
//! vault-audit entity-list --output entities.json --format json
//!
//! # Skip TLS verification (dev/test only)
//! vault-audit entity-list --output entities.csv --insecure
//! ```
//!
//! # Requirements
//!
//! Requires environment variables:
//! - `VAULT_ADDR`: Vault server URL
//! - `VAULT_TOKEN`: Token with entity read permissions
//!
//! # Output
//!
//! Generates CSV or JSON with entity information:
//! - Entity ID
//! - Display name
//! - Alias names and mount paths
//! - Creation timestamp
//!
//! This data can be used as a baseline for the `entity-churn` and `entity-creation` commands.

use crate::utils::format::format_number;
use crate::vault_api::{extract_data, should_skip_verify, VaultClient};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;

/// Authentication mount configuration
#[derive(Debug, Deserialize)]
struct AuthMount {
    #[serde(rename = "type")]
    mount_type: Option<String>,
    accessor: Option<String>,
}

/// Response from entity list API
#[derive(Debug, Deserialize)]
struct EntityListResponse {
    keys: Vec<String>,
}

/// Entity data from Vault API
#[derive(Debug, Deserialize)]
struct EntityData {
    id: String,
    name: Option<String>,
    disabled: bool,
    creation_time: Option<String>,
    last_update_time: Option<String>,
    aliases: Option<Vec<AliasData>>,
}

#[derive(Debug, Deserialize, Clone)]
struct AliasData {
    id: String,
    name: String,
    mount_accessor: String,
    creation_time: Option<String>,
    last_update_time: Option<String>,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct EntityOutput {
    entity_id: String,
    entity_name: String,
    entity_disabled: bool,
    entity_created: String,
    entity_updated: String,
    alias_id: String,
    alias_name: String,
    mount_path: String,
    mount_type: String,
    mount_accessor: String,
    alias_created: String,
    alias_updated: String,
    alias_metadata: String,
}

pub async fn run(
    vault_addr: Option<&str>,
    vault_token: Option<&str>,
    vault_namespace: Option<&str>,
    insecure: bool,
    output: Option<&str>,
    format: &str,
    filter_mount: Option<&str>,
) -> Result<()> {
    let skip_verify = should_skip_verify(insecure);
    let client = VaultClient::from_options(vault_addr, vault_token, vault_namespace, skip_verify)?;

    eprintln!("=== Vault Entity Analysis ===");
    eprintln!("Vault Address: {}", client.addr());
    if let Some(mount) = filter_mount {
        eprintln!("Filtering by mount: {}", mount);
    }
    if skip_verify {
        eprintln!("⚠️  TLS certificate verification is DISABLED");
    }
    eprintln!();

    // Build mount lookup map
    eprintln!("Building mount map...");
    let mount_map = fetch_auth_mount_map(&client).await?;
    eprintln!("Found {} auth mounts", mount_map.len());

    // List all entity IDs
    eprintln!("Fetching entity list...");
    let entity_list: EntityListResponse =
        extract_data(client.get_json("/v1/identity/entity/id?list=true").await?)?;

    let entity_count = entity_list.keys.len();
    eprintln!("Found {} entities", format_number(entity_count));
    eprintln!();

    // Fetch each entity's details
    eprintln!("Fetching entity details...");
    let mut entities_data = Vec::new();
    let mut processed = 0;

    for entity_id in &entity_list.keys {
        processed += 1;
        if processed % 100 == 0 || processed == entity_count {
            eprint!("\rProcessing entity {}/{}...", processed, entity_count);
        }

        let entity_path = format!("/v1/identity/entity/id/{}", entity_id);
        if let Ok(entity_json) = client.get_json(&entity_path).await {
            if let Ok(entity) = extract_data::<EntityData>(entity_json) {
                entities_data.push(entity);
            }
        }
    }
    eprintln!("\n");

    // Convert to output format
    let mut output_rows = Vec::new();

    for entity in &entities_data {
        let entity_name = entity.name.clone().unwrap_or_default();
        let entity_created = entity.creation_time.clone().unwrap_or_default();
        let entity_updated = entity.last_update_time.clone().unwrap_or_default();

        if let Some(aliases) = &entity.aliases {
            let mut filtered_aliases: Vec<&AliasData> = aliases.iter().collect();

            // Apply mount filter if specified
            if let Some(filter) = filter_mount {
                filtered_aliases.retain(|alias| {
                    if let Some((path, _)) = mount_map.get(&alias.mount_accessor) {
                        path == filter
                    } else {
                        false
                    }
                });
            }

            if filtered_aliases.is_empty() && filter_mount.is_some() {
                continue; // Skip entities with no matching aliases
            }

            for alias in filtered_aliases {
                let (mount_path, mount_type) = mount_map
                    .get(&alias.mount_accessor)
                    .cloned()
                    .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

                let metadata_str = alias
                    .metadata
                    .as_ref()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();

                output_rows.push(EntityOutput {
                    entity_id: entity.id.clone(),
                    entity_name: entity_name.clone(),
                    entity_disabled: entity.disabled,
                    entity_created: entity_created.clone(),
                    entity_updated: entity_updated.clone(),
                    alias_id: alias.id.clone(),
                    alias_name: alias.name.clone(),
                    mount_path,
                    mount_type,
                    mount_accessor: alias.mount_accessor.clone(),
                    alias_created: alias.creation_time.clone().unwrap_or_default(),
                    alias_updated: alias.last_update_time.clone().unwrap_or_default(),
                    alias_metadata: metadata_str,
                });
            }
        } else if filter_mount.is_none() {
            // Include entities with no aliases only if not filtering
            output_rows.push(EntityOutput {
                entity_id: entity.id.clone(),
                entity_name,
                entity_disabled: entity.disabled,
                entity_created,
                entity_updated,
                alias_id: String::new(),
                alias_name: String::new(),
                mount_path: String::new(),
                mount_type: String::new(),
                mount_accessor: String::new(),
                alias_created: String::new(),
                alias_updated: String::new(),
                alias_metadata: String::new(),
            });
        }
    }

    // Print summary
    eprintln!("=== Summary ===");
    eprintln!("Total entities: {}", format_number(entities_data.len()));
    eprintln!("Total aliases: {}", format_number(output_rows.len()));
    eprintln!();

    // Count aliases by mount
    let mut mount_counts: HashMap<String, usize> = HashMap::new();
    for row in &output_rows {
        if !row.mount_path.is_empty() {
            *mount_counts.entry(row.mount_path.clone()).or_insert(0) += 1;
        }
    }

    if !mount_counts.is_empty() {
        eprintln!("Aliases by mount:");
        let mut counts: Vec<_> = mount_counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        for (mount, count) in counts {
            eprintln!("  {}: {}", mount, format_number(count));
        }
        eprintln!();
    }

    // Output results
    if let Some(output_path) = output {
        let file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path))?;

        match format.to_lowercase().as_str() {
            "json" => {
                serde_json::to_writer_pretty(file, &output_rows)
                    .with_context(|| format!("Failed to write JSON to: {}", output_path))?;
                eprintln!("JSON written to: {}", output_path);
            }
            "csv" => {
                let mut writer = csv::Writer::from_writer(file);

                writer.write_record([
                    "entity_id",
                    "entity_name",
                    "entity_disabled",
                    "entity_created",
                    "entity_updated",
                    "alias_id",
                    "alias_name",
                    "mount_path",
                    "mount_type",
                    "mount_accessor",
                    "alias_created",
                    "alias_updated",
                    "alias_metadata",
                ])?;

                for row in &output_rows {
                    writer.write_record([
                        &row.entity_id,
                        &row.entity_name,
                        &row.entity_disabled.to_string(),
                        &row.entity_created,
                        &row.entity_updated,
                        &row.alias_id,
                        &row.alias_name,
                        &row.mount_path,
                        &row.mount_type,
                        &row.mount_accessor,
                        &row.alias_created,
                        &row.alias_updated,
                        &row.alias_metadata,
                    ])?;
                }

                writer.flush()?;
                eprintln!("CSV written to: {}", output_path);
            }
            _ => {
                anyhow::bail!("Invalid format '{}'. Use 'csv' or 'json'", format);
            }
        }
    } else {
        // No output file specified - print to stdout based on format
        match format.to_lowercase().as_str() {
            "json" => {
                println!("{}", serde_json::to_string_pretty(&output_rows)?);
            }
            "csv" => {
                let mut writer = csv::Writer::from_writer(std::io::stdout());
                writer.write_record([
                    "entity_id",
                    "entity_name",
                    "entity_disabled",
                    "entity_created",
                    "entity_updated",
                    "alias_id",
                    "alias_name",
                    "mount_path",
                    "mount_type",
                    "mount_accessor",
                    "alias_created",
                    "alias_updated",
                    "alias_metadata",
                ])?;

                for row in &output_rows {
                    writer.write_record([
                        &row.entity_id,
                        &row.entity_name,
                        &row.entity_disabled.to_string(),
                        &row.entity_created,
                        &row.entity_updated,
                        &row.alias_id,
                        &row.alias_name,
                        &row.mount_path,
                        &row.mount_type,
                        &row.mount_accessor,
                        &row.alias_created,
                        &row.alias_updated,
                        &row.alias_metadata,
                    ])?;
                }

                writer.flush()?;
            }
            _ => {
                anyhow::bail!("Invalid format '{}'. Use 'csv' or 'json'", format);
            }
        }
    }

    Ok(())
}

async fn fetch_auth_mount_map(client: &VaultClient) -> Result<HashMap<String, (String, String)>> {
    let mut map = HashMap::new();

    if let Ok(auth_data) = client.get_json("/v1/sys/auth").await {
        if let Ok(auths) = extract_data::<HashMap<String, AuthMount>>(auth_data) {
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
