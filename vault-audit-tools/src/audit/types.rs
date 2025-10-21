//! Data structures representing HashiCorp Vault audit log entries.
//!
//! These types closely mirror the JSON structure of Vault audit logs,
//! enabling efficient deserialization with serde.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level audit log entry.
///
/// Each line in a Vault audit log is a JSON object that deserializes
/// into this structure. Entries can be either requests or responses.
///
/// # Fields
///
/// - `entry_type`: Either "request" or "response"
/// - `time`: ISO 8601 timestamp of when the operation occurred
/// - `auth`: Authentication context (may be None for unauthenticated requests)
/// - `request`: Request details (present for request entries)
/// - `response`: Response details (present for response entries)
/// - `error`: Error message if the operation failed
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditEntry {
    #[serde(rename = "type")]
    pub entry_type: String, // "request" or "response"
    pub time: String,
    pub auth: Option<AuthInfo>,
    pub request: Option<RequestInfo>,
    pub response: Option<ResponseInfo>,
    pub error: Option<String>,
}

/// Authentication information from the audit log.
///
/// Contains details about the token used to make the request,
/// including the associated entity, policies, and metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthInfo {
    pub accessor: Option<String>,
    pub client_token: Option<String>,
    pub display_name: Option<String>,
    /// Vault identity entity ID that made this request
    pub entity_id: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub policies: Option<Vec<String>>,
    pub token_policies: Option<Vec<String>>,
    pub token_type: Option<String>,
    pub token_ttl: Option<u64>,
    pub token_issue_time: Option<String>,
}

/// Request information from the audit log.
///
/// Describes the operation being performed, including the path,
/// operation type, and mount point details.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestInfo {
    pub id: Option<String>,
    pub client_id: Option<String>,
    /// Operation type (e.g., "read", "write", "delete", "list")
    pub operation: Option<String>,
    /// Path being accessed (e.g., "secret/data/myapp/config")
    pub path: Option<String>,
    /// Type of secrets engine (e.g., "kv", "database", "pki")
    pub mount_type: Option<String>,
    /// Mount point where the secrets engine is mounted
    pub mount_point: Option<String>,
    pub mount_class: Option<String>,
    pub mount_running_version: Option<String>,
    pub namespace: Option<Namespace>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub client_token: Option<String>,
    pub client_token_accessor: Option<String>,
}

/// Response information from the audit log.
///
/// Contains the result of the operation, including any data returned
/// and metadata about the secrets engine that handled the request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseInfo {
    pub auth: Option<AuthInfo>,
    pub data: Option<HashMap<String, serde_json::Value>>,
    pub mount_type: Option<String>,
    pub redirect: Option<String>,
    pub warnings: Option<Vec<String>>,
}

/// Namespace information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Namespace {
    pub id: String,
}

impl AuditEntry {
    /// Get the entity ID from this entry
    pub fn entity_id(&self) -> Option<&str> {
        self.auth.as_ref()?.entity_id.as_deref()
    }

    /// Get the request path from this entry
    pub fn path(&self) -> Option<&str> {
        self.request.as_ref()?.path.as_deref()
    }

    /// Get the operation type from this entry
    pub fn operation(&self) -> Option<&str> {
        self.request.as_ref()?.operation.as_deref()
    }

    /// Get the display name from this entry
    pub fn display_name(&self) -> Option<&str> {
        self.auth.as_ref()?.display_name.as_deref()
    }

    // Helper methods for future use
    #[allow(dead_code)]
    pub fn mount_type(&self) -> Option<&str> {
        self.request.as_ref()?.mount_type.as_deref()
    }

    #[allow(dead_code)]
    pub fn mount_point(&self) -> Option<&str> {
        self.request.as_ref()?.mount_point.as_deref()
    }

    #[allow(dead_code)]
    pub fn is_kv_operation(&self) -> bool {
        self.mount_type().map(|mt| mt == "kv").unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_read_or_list(&self) -> bool {
        self.operation()
            .map(|op| op == "read" || op == "list")
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn path_starts_with(&self, prefix: &str) -> bool {
        self.path().map(|p| p.starts_with(prefix)).unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_token_operation(&self) -> bool {
        self.path_starts_with("auth/token/")
    }
}
