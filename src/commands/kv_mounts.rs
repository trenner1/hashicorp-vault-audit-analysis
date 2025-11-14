//! KV mount enumeration and tree listing.
//!
//! This command queries the Vault API to automatically discover and enumerate all KV secret mounts
//! (both v1 and v2) and recursively lists their contents in a hierarchical tree structure.
//!
//! # Features
//!
//! - **Automatic Discovery**: Discovers all KV mounts without needing to know mount names
//! - **Version Detection**: Automatically detects and handles both KV v1 and KV v2 mounts
//! - **Depth Control**: Optional depth parameter to control traversal (unlimited by default)
//! - **Multiple Output Formats**: CSV (flattened with depth), JSON (nested tree), or stdout (visual tree)
//!
//! # Usage Examples
//!
//! ```bash
//! # List all KV mounts with unlimited depth (default)
//! vault-audit kv-mounts --format stdout
//!
//! # List only the mounts themselves (no traversal)
//! vault-audit kv-mounts --depth 0 --format csv
//!
//! # List mounts and traverse 2 levels deep
//! vault-audit kv-mounts --depth 2 --format json
//!
//! # Save full tree to CSV file
//! vault-audit kv-mounts --format csv --output kv-inventory.csv
//! ```
//!
//! # Output Formats
//!
//! - **CSV**: Flattened paths with depth column, one row per path/secret
//! - **JSON**: Nested tree structure with parent-child relationships
//! - **stdout**: Visual tree with Unicode box-drawing characters (├──, └──, │)
//!
//! # Depth Parameter
//!
//! - `--depth 0`: Show only mount points (no traversal)
//! - `--depth 1`: Show mounts + first level folders/secrets
//! - `--depth 2`: Show mounts + two levels of traversal
//! - No flag: Unlimited depth (discovers entire tree structure)
//!
//! # API Endpoints Used
//!
//! - `/v1/sys/mounts` - Discover all secret mounts
//! - `/v1/{mount}/metadata/{path}` - List KV v2 paths (using LIST method)
//! - `/v1/{mount}/{path}` - List KV v1 paths (using LIST method)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use crate::vault_api::VaultClient;

#[derive(Debug, Serialize, Deserialize)]
struct MountInfo {
    #[serde(rename = "type")]
    mount_type: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    accessor: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    config: HashMap<String, Value>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    options: HashMap<String, Value>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Recursively list paths within a KV v2 mount up to a specified depth
#[allow(clippy::future_not_send)]
async fn list_kv_v2_paths(
    client: &VaultClient,
    mount_path: &str,
    current_depth: usize,
    max_depth: usize,
) -> Result<Vec<PathEntry>> {
    if current_depth > max_depth {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mount_trimmed = mount_path.trim_end_matches('/');

    // List the root of the mount using LIST method on metadata endpoint
    let list_path = format!("/v1/{}/metadata", mount_trimmed);

    let response: Result<Value> = client.list_json(&list_path).await;

    if let Ok(resp) = response {
        // Extract keys from the data.keys field
        if let Some(data) = resp.get("data") {
            if let Some(keys) = data.get("keys") {
                if let Some(keys_array) = keys.as_array() {
                    for key in keys_array {
                        if let Some(key_str) = key.as_str() {
                            let is_folder = key_str.ends_with('/');
                            let entry_type = if is_folder { "folder" } else { "secret" };

                            let children = if is_folder && current_depth < max_depth {
                                // Pass just the relative path, not the full mount path
                                let rel_path = key_str.trim_end_matches('/');
                                Some(
                                    list_kv_v2_subpath(
                                        client,
                                        mount_trimmed,
                                        rel_path,
                                        current_depth + 1,
                                        max_depth,
                                    )
                                    .await?,
                                )
                            } else {
                                None
                            };

                            entries.push(PathEntry {
                                path: key_str.to_string(),
                                entry_type: entry_type.to_string(),
                                children,
                            });
                        }
                    }
                }
            }
        }
    }
    // If we can't list the root, that's okay - mount might be empty or no permissions

    Ok(entries)
}

/// List paths within a KV v2 subpath (folder)
#[allow(clippy::future_not_send)]
fn list_kv_v2_subpath<'a>(
    client: &'a VaultClient,
    mount_path: &'a str,
    rel_path: &'a str,
    current_depth: usize,
    max_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathEntry>>> + 'a>> {
    Box::pin(async move {
        if current_depth > max_depth {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mount_trimmed = mount_path.trim_end_matches('/');

        // For KV v2, the metadata endpoint is /v1/{mount}/metadata/{path}
        let list_path = format!("/v1/{}/metadata/{}", mount_trimmed, rel_path);

        let response: Result<Value> = client.list_json(&list_path).await;

        if let Ok(resp) = response {
            if let Some(data) = resp.get("data") {
                if let Some(keys) = data.get("keys") {
                    if let Some(keys_array) = keys.as_array() {
                        for key in keys_array {
                            if let Some(key_str) = key.as_str() {
                                let is_folder = key_str.ends_with('/');
                                let entry_type = if is_folder { "folder" } else { "secret" };

                                let children = if is_folder && current_depth < max_depth {
                                    let new_rel_path =
                                        format!("{}/{}", rel_path, key_str.trim_end_matches('/'));
                                    Some(
                                        list_kv_v2_subpath(
                                            client,
                                            mount_path,
                                            &new_rel_path,
                                            current_depth + 1,
                                            max_depth,
                                        )
                                        .await?,
                                    )
                                } else {
                                    None
                                };

                                entries.push(PathEntry {
                                    path: key_str.to_string(),
                                    entry_type: entry_type.to_string(),
                                    children,
                                });
                            }
                        }
                    }
                }
            }
        }
        // Silently ignore list errors for subpaths

        Ok(entries)
    })
}

/// Recursively list paths within a KV v1 mount up to a specified depth
#[allow(clippy::future_not_send)]
fn list_kv_v1_paths<'a>(
    client: &'a VaultClient,
    mount_path: &'a str,
    subpath: &'a str,
    current_depth: usize,
    max_depth: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PathEntry>>> + 'a>> {
    Box::pin(async move {
        if current_depth > max_depth {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mount_trimmed = mount_path.trim_end_matches('/');

        // For KV v1, use LIST on the mount path directly
        let list_path = if subpath.is_empty() {
            format!("/v1/{}", mount_trimmed)
        } else {
            format!("/v1/{}/{}", mount_trimmed, subpath.trim_end_matches('/'))
        };

        let response: Result<Value> = client.list_json(&list_path).await;

        if let Ok(resp) = response {
            if let Some(data) = resp.get("data") {
                if let Some(keys) = data.get("keys") {
                    if let Some(keys_array) = keys.as_array() {
                        for key in keys_array {
                            if let Some(key_str) = key.as_str() {
                                let is_folder = key_str.ends_with('/');
                                let entry_type = if is_folder { "folder" } else { "secret" };

                                let children = if is_folder && current_depth < max_depth {
                                    let new_subpath = if subpath.is_empty() {
                                        key_str.trim_end_matches('/').to_string()
                                    } else {
                                        format!(
                                            "{}/{}",
                                            subpath.trim_end_matches('/'),
                                            key_str.trim_end_matches('/')
                                        )
                                    };
                                    Some(
                                        list_kv_v1_paths(
                                            client,
                                            mount_path,
                                            &new_subpath,
                                            current_depth + 1,
                                            max_depth,
                                        )
                                        .await?,
                                    )
                                } else {
                                    None
                                };

                                entries.push(PathEntry {
                                    path: key_str.to_string(),
                                    entry_type: entry_type.to_string(),
                                    children,
                                });
                            }
                        }
                    }
                }
            }
        }
        // If we can't list, that's okay - might be empty or no permissions

        Ok(entries)
    })
}

/// Helper function to flatten nested path entries to CSV format
fn flatten_paths_to_csv(output: &mut String, base_path: &str, entries: &[PathEntry], depth: usize) {
    use std::fmt::Write as _;
    for entry in entries {
        let full_path = format!("{}{}", base_path, entry.path);
        let _ = writeln!(
            output,
            "\"{}\",\"{}\",\"{}\",{}",
            full_path.replace('"', "\"\""),
            entry.entry_type,
            base_path.replace('"', "\"\""),
            depth
        );

        if let Some(children) = &entry.children {
            let new_base = format!("{}{}", base_path, entry.path);
            flatten_paths_to_csv(output, &new_base, children, depth + 1);
        }
    }
}

/// Helper function to print nested paths in tree format
#[allow(clippy::only_used_in_recursion)]
fn print_tree(base_path: &str, entries: &[PathEntry], prefix: &str, is_last_at_level: &[bool]) {
    for (i, entry) in entries.iter().enumerate() {
        let is_last = i == entries.len() - 1;
        let connector = if is_last { "└──" } else { "├──" };

        println!(
            "{}{} {} ({})",
            prefix, connector, entry.path, entry.entry_type
        );

        if let Some(children) = &entry.children {
            let mut new_prefix = prefix.to_string();
            new_prefix.push_str(if is_last { "    " } else { "│   " });

            let mut new_is_last = is_last_at_level.to_vec();
            new_is_last.push(is_last);
            print_tree(base_path, children, &new_prefix, &new_is_last);
        }
    }
}

#[derive(Debug, Serialize)]
struct KvMountOutput {
    path: String,
    mount_type: String,
    description: String,
    version: String,
    accessor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<PathEntry>>,
}

#[derive(Debug, Serialize, Clone)]
struct PathEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String, // "folder" or "secret"
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<PathEntry>>,
}

/// Run the KV mount enumeration command
#[allow(clippy::future_not_send)]
pub async fn run(
    vault_addr: Option<&str>,
    vault_token: Option<&str>,
    vault_namespace: Option<&str>,
    insecure: bool,
    output: Option<&str>,
    format: &str,
    depth: usize,
) -> Result<()> {
    let client = VaultClient::from_options(vault_addr, vault_token, vault_namespace, insecure)?;

    eprintln!("Querying Vault API for KV mounts...");
    eprintln!("   Vault Address: {}", client.addr());

    // Query /sys/mounts to get all secret mounts
    let response: Value = client
        .get("/v1/sys/mounts")
        .await
        .context("Failed to query /v1/sys/mounts")?;

    // Extract the data field which contains the actual mounts
    let mounts_data = response
        .get("data")
        .or(Some(&response)) // Fallback to root if no data field
        .context("Failed to get mounts data")?;

    let mounts = mounts_data
        .as_object()
        .context("Expected object response from /v1/sys/mounts")?;

    let mut kv_mounts = Vec::new();

    for (path, mount_data) in mounts {
        // Skip metadata fields like "request_id"
        if path == "request_id"
            || path == "lease_id"
            || path == "renewable"
            || path == "lease_duration"
            || path == "data"
            || path == "wrap_info"
            || path == "warnings"
            || path == "auth"
        {
            continue;
        }

        let mount_info: MountInfo = serde_json::from_value(mount_data.clone())
            .with_context(|| format!("Failed to parse mount info for {}", path))?;

        // Filter for ALL KV mounts (v1 and v2)
        if mount_info.mount_type == "kv" {
            let version = mount_info
                .options
                .get("version")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    mount_info
                        .options
                        .get("version")
                        .and_then(serde_json::Value::as_i64)
                        .map(|_| "2")
                })
                .unwrap_or("1");

            // Traverse paths if depth > 0
            let children = if depth > 0 {
                if version == "2" {
                    Some(list_kv_v2_paths(&client, path, 1, depth).await?)
                } else {
                    Some(list_kv_v1_paths(&client, path, "", 1, depth).await?)
                }
            } else {
                None
            };

            kv_mounts.push(KvMountOutput {
                path: path.clone(),
                mount_type: mount_info.mount_type.clone(),
                description: mount_info.description.clone(),
                version: version.to_string(),
                accessor: mount_info.accessor.clone(),
                children,
            });
        }
    }

    eprintln!("Found {} KV mounts (v1 and v2)", kv_mounts.len());

    // Output results
    match format {
        "json" => {
            let json_output =
                serde_json::to_string_pretty(&kv_mounts).context("Failed to serialize to JSON")?;

            if let Some(output_path) = output {
                let mut file = File::create(output_path).context("Failed to create output file")?;
                file.write_all(json_output.as_bytes())
                    .context("Failed to write JSON to file")?;
                eprintln!("Output written to: {}", output_path);
            } else {
                println!("{}", json_output);
            }
        }
        "csv" => {
            use std::fmt::Write as _;
            let mut csv_output = String::new();
            if depth > 0 {
                csv_output.push_str("full_path,type,mount,depth\n");
                for mount in &kv_mounts {
                    // Write mount itself
                    let _ = writeln!(
                        csv_output,
                        "\"{}\",\"mount\",\"{}\",0",
                        mount.path.replace('"', "\"\""),
                        mount.path.replace('"', "\"\"")
                    );

                    // Write nested paths
                    if let Some(children) = &mount.children {
                        flatten_paths_to_csv(&mut csv_output, &mount.path, children, 1);
                    }
                }
            } else {
                csv_output.push_str("path,type,description,version,accessor\n");
                for mount in &kv_mounts {
                    let _ = writeln!(
                        csv_output,
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
                        mount.path.replace('"', "\"\""),
                        mount.mount_type,
                        mount.description.replace('"', "\"\""),
                        mount.version,
                        mount.accessor
                    );
                }
            }

            if let Some(output_path) = output {
                let mut file = File::create(output_path).context("Failed to create output file")?;
                file.write_all(csv_output.as_bytes())
                    .context("Failed to write CSV to file")?;
                eprintln!("Output written to: {}", output_path);
            } else {
                print!("{}", csv_output);
            }
        }
        "stdout" => {
            println!("\nKV v2 Mounts:");
            println!("{}", "=".repeat(80));
            for mount in &kv_mounts {
                println!("Path: {}", mount.path);
                println!("  Type: {}", mount.mount_type);
                println!("  Version: {}", mount.version);
                println!("  Description: {}", mount.description);
                println!("  Accessor: {}", mount.accessor);

                if let Some(children) = &mount.children {
                    if !children.is_empty() {
                        println!("  Contents:");
                        print_tree(&mount.path, children, "    ", &[]);
                    }
                }
                println!();
            }
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid format: {}. Must be one of: csv, json, stdout",
                format
            ));
        }
    }

    Ok(())
}
