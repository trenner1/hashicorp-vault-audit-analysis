//! Auth mount enumeration and listing.
//!
//! This command queries the Vault API to enumerate all authentication mounts and their
//! configuration, with optional depth-based traversal to discover roles, users, and other
//! configurations within each auth method.
//!
//! # Features
//!
//! - **Automatic Discovery**: Discovers all auth mounts without needing to know mount names
//! - **Multi-Type Support**: Handles kubernetes, approle, userpass, jwt/oidc, ldap, and token auth
//! - **Role Enumeration**: Lists roles, users, and groups within each auth mount (when depth > 0)
//! - **Multiple Output Formats**: CSV (flattened with depth), JSON (nested structure), or stdout (visual tree)
//!
//! # Usage Examples
//!
//! ```bash
//! # List all auth mounts with role enumeration (default)
//! vault-audit auth-mounts --format stdout
//!
//! # List only the auth mounts themselves (no roles)
//! vault-audit auth-mounts --depth 0 --format csv
//!
//! # List mounts with roles in JSON format
//! vault-audit auth-mounts --format json --output auth-inventory.json
//! ```
//!
//! # Supported Auth Types
//!
//! - **kubernetes**: Lists roles configured for K8s service accounts
//! - **approle**: Lists `AppRole` roles for application authentication
//! - **userpass**: Lists configured users
//! - **jwt/oidc**: Lists JWT/OIDC roles
//! - **ldap**: Lists LDAP users and groups (prefixed with `user:`/`group:`)
//! - **token**: No enumerable configuration
//!
//! # Output Formats
//!
//! - **CSV**: Flattened format with mount info repeated for each role (depth column: 0=mount, 1=role)
//! - **JSON**: Nested structure with roles array within each mount object
//! - **stdout**: Visual tree with mount details and indented role list (├──, └──)
//!
//! # Depth Parameter
//!
//! - `--depth 0`: Show only mount points (no role enumeration)
//! - `--depth 1` or higher: Include roles/users within each mount
//! - No flag: Unlimited depth (enumerates all roles/users)
//!
//! # API Endpoints Used
//!
//! - `/v1/sys/auth` - Discover all auth mounts
//! - `/v1/auth/{mount}/role` - List roles (kubernetes, approle, jwt/oidc)
//! - `/v1/auth/{mount}/users` - List users (userpass, ldap)
//! - `/v1/auth/{mount}/groups` - List groups (ldap)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use crate::vault_api::VaultClient;

#[derive(Debug, Serialize, Deserialize)]
struct AuthMountInfo {
    #[serde(rename = "type")]
    auth_type: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    accessor: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    config: HashMap<String, Value>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    options: HashMap<String, Value>,
    #[serde(default)]
    local: bool,
    #[serde(default)]
    seal_wrap: bool,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Debug, Serialize, Clone)]
struct RoleEntry {
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    children: Vec<Self>,
}

#[derive(Debug, Serialize)]
struct AuthMountOutput {
    path: String,
    auth_type: String,
    description: String,
    accessor: String,
    local: bool,
    seal_wrap: bool,
    default_lease_ttl: String,
    max_lease_ttl: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    roles: Vec<RoleEntry>,
}

/// List roles for kubernetes auth mounts
async fn list_k8s_roles(client: &VaultClient, mount_path: &str) -> Result<Vec<RoleEntry>> {
    let list_path = format!("/v1/auth/{}/role", mount_path.trim_end_matches('/'));

    match client.list_json(&list_path).await {
        Ok(response) => {
            if let Some(keys) = response
                .get("data")
                .and_then(|d| d.get("keys"))
                .and_then(|k| k.as_array())
            {
                let mut roles = Vec::new();
                for key in keys {
                    if let Some(role_name) = key.as_str() {
                        roles.push(RoleEntry {
                            name: role_name.to_string(),
                            children: vec![],
                        });
                    }
                }
                Ok(roles)
            } else {
                Ok(vec![])
            }
        }
        Err(_) => Ok(vec![]), // If we can't list, just return empty
    }
}

/// List roles for approle auth mounts
async fn list_approle_roles(client: &VaultClient, mount_path: &str) -> Result<Vec<RoleEntry>> {
    let list_path = format!("/v1/auth/{}/role", mount_path.trim_end_matches('/'));

    match client.list_json(&list_path).await {
        Ok(response) => {
            if let Some(keys) = response
                .get("data")
                .and_then(|d| d.get("keys"))
                .and_then(|k| k.as_array())
            {
                let mut roles = Vec::new();
                for key in keys {
                    if let Some(role_name) = key.as_str() {
                        roles.push(RoleEntry {
                            name: role_name.to_string(),
                            children: vec![],
                        });
                    }
                }
                Ok(roles)
            } else {
                Ok(vec![])
            }
        }
        Err(_) => Ok(vec![]), // If we can't list, just return empty
    }
}

/// List users for userpass auth mounts
async fn list_userpass_users(client: &VaultClient, mount_path: &str) -> Result<Vec<RoleEntry>> {
    let list_path = format!("/v1/auth/{}/users", mount_path.trim_end_matches('/'));

    match client.list_json(&list_path).await {
        Ok(response) => {
            if let Some(keys) = response
                .get("data")
                .and_then(|d| d.get("keys"))
                .and_then(|k| k.as_array())
            {
                let mut users = Vec::new();
                for key in keys {
                    if let Some(user_name) = key.as_str() {
                        users.push(RoleEntry {
                            name: user_name.to_string(),
                            children: vec![],
                        });
                    }
                }
                Ok(users)
            } else {
                Ok(vec![])
            }
        }
        Err(_) => Ok(vec![]), // If we can't list, just return empty
    }
}

/// List roles for JWT/OIDC auth mounts
async fn list_jwt_roles(client: &VaultClient, mount_path: &str) -> Result<Vec<RoleEntry>> {
    let list_path = format!("/v1/auth/{}/role", mount_path.trim_end_matches('/'));

    match client.list_json(&list_path).await {
        Ok(response) => {
            if let Some(keys) = response
                .get("data")
                .and_then(|d| d.get("keys"))
                .and_then(|k| k.as_array())
            {
                let mut roles = Vec::new();
                for key in keys {
                    if let Some(role_name) = key.as_str() {
                        roles.push(RoleEntry {
                            name: role_name.to_string(),
                            children: vec![],
                        });
                    }
                }
                Ok(roles)
            } else {
                Ok(vec![])
            }
        }
        Err(_) => Ok(vec![]), // If we can't list, just return empty
    }
}

/// List users/groups for LDAP auth mounts
async fn list_ldap_config(client: &VaultClient, mount_path: &str) -> Result<Vec<RoleEntry>> {
    let users_path = format!("/v1/auth/{}/users", mount_path.trim_end_matches('/'));
    let groups_path = format!("/v1/auth/{}/groups", mount_path.trim_end_matches('/'));

    let mut entries = Vec::new();

    // Try to list users
    if let Ok(response) = client.list_json(&users_path).await {
        if let Some(keys) = response
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
        {
            for key in keys {
                if let Some(user_name) = key.as_str() {
                    entries.push(RoleEntry {
                        name: format!("user:{}", user_name),
                        children: vec![],
                    });
                }
            }
        }
    }

    // Try to list groups
    if let Ok(response) = client.list_json(&groups_path).await {
        if let Some(keys) = response
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
        {
            for key in keys {
                if let Some(group_name) = key.as_str() {
                    entries.push(RoleEntry {
                        name: format!("group:{}", group_name),
                        children: vec![],
                    });
                }
            }
        }
    }

    Ok(entries)
}

/// Enumerate roles/users based on auth mount type
async fn enumerate_auth_configs(
    client: &VaultClient,
    mount_path: &str,
    auth_type: &str,
    depth: usize,
) -> Result<Vec<RoleEntry>> {
    if depth == 0 {
        return Ok(vec![]);
    }

    match auth_type {
        "kubernetes" => list_k8s_roles(client, mount_path).await,
        "approle" => list_approle_roles(client, mount_path).await,
        "userpass" => list_userpass_users(client, mount_path).await,
        "jwt" | "oidc" => list_jwt_roles(client, mount_path).await,
        "ldap" => list_ldap_config(client, mount_path).await,
        _ => Ok(vec![]), // Unsupported auth types return empty
    }
}

/// Run the auth mount enumeration command
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

    eprintln!("Querying Vault API for auth mounts...");
    eprintln!("   Vault Address: {}", client.addr());

    // Query /sys/auth to get all auth mounts
    let response: Value = client
        .get("/v1/sys/auth")
        .await
        .context("Failed to query /v1/sys/auth")?;

    // Extract the data field which contains the actual mounts
    let mounts_data = response
        .get("data")
        .or(Some(&response)) // Fallback to root if no data field
        .context("Failed to get auth mounts data")?;

    let mounts = mounts_data
        .as_object()
        .context("Expected object response from /v1/sys/auth")?;

    let mut auth_mounts = Vec::new();

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

        let mount_info: AuthMountInfo = serde_json::from_value(mount_data.clone())
            .with_context(|| format!("Failed to parse auth mount info for {}", path))?;

        let default_lease_ttl = mount_info
            .config
            .get("default_lease_ttl")
            .and_then(serde_json::Value::as_i64)
            .map_or_else(|| "0s".to_string(), |v| format!("{}s", v));

        let max_lease_ttl = mount_info
            .config
            .get("max_lease_ttl")
            .and_then(serde_json::Value::as_i64)
            .map_or_else(|| "0s".to_string(), |v| format!("{}s", v));

        // Enumerate roles/users if depth > 0
        let roles = enumerate_auth_configs(&client, path, &mount_info.auth_type, depth)
            .await
            .unwrap_or_else(|_| vec![]);

        auth_mounts.push(AuthMountOutput {
            path: path.clone(),
            auth_type: mount_info.auth_type.clone(),
            description: mount_info.description.clone(),
            accessor: mount_info.accessor.clone(),
            local: mount_info.local,
            seal_wrap: mount_info.seal_wrap,
            default_lease_ttl,
            max_lease_ttl,
            roles,
        });
    }

    eprintln!("Found {} auth mounts", auth_mounts.len());

    // Output results
    match format {
        "json" => {
            let json_output = serde_json::to_string_pretty(&auth_mounts)
                .context("Failed to serialize to JSON")?;

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
            csv_output.push_str("path,type,description,accessor,role_name,depth\n");

            for mount in &auth_mounts {
                // First write the mount itself
                let _ = writeln!(
                    csv_output,
                    "\"{}\",\"{}\",\"{}\",\"{}\",\"\",0",
                    mount.path.replace('"', "\"\""),
                    mount.auth_type,
                    mount.description.replace('"', "\"\""),
                    mount.accessor,
                );

                // Then write each role/user
                for role in &mount.roles {
                    let _ = writeln!(
                        csv_output,
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",1",
                        mount.path.replace('"', "\"\""),
                        mount.auth_type,
                        mount.description.replace('"', "\"\""),
                        mount.accessor,
                        role.name.replace('"', "\"\""),
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
            println!("\nAuth Mounts:");
            println!("{}", "=".repeat(80));
            for mount in &auth_mounts {
                println!("Path: {}", mount.path);
                println!("  Type: {}", mount.auth_type);
                println!("  Description: {}", mount.description);
                println!("  Accessor: {}", mount.accessor);
                println!("  Local: {}", mount.local);
                println!("  Seal Wrap: {}", mount.seal_wrap);
                println!("  Default Lease TTL: {}", mount.default_lease_ttl);
                println!("  Max Lease TTL: {}", mount.max_lease_ttl);

                if !mount.roles.is_empty() {
                    println!("  Roles/Users ({}):", mount.roles.len());
                    for (i, role) in mount.roles.iter().enumerate() {
                        let prefix = if i == mount.roles.len() - 1 {
                            "└──"
                        } else {
                            "├──"
                        };
                        println!("    {} {}", prefix, role.name);
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
