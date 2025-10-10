use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level audit log entry
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

/// Authentication information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthInfo {
    pub accessor: Option<String>,
    pub client_token: Option<String>,
    pub display_name: Option<String>,
    pub entity_id: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub policies: Option<Vec<String>>,
    pub token_policies: Option<Vec<String>>,
    pub token_type: Option<String>,
    pub token_ttl: Option<u64>,
    pub token_issue_time: Option<String>,
}

/// Request information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestInfo {
    pub id: Option<String>,
    pub client_id: Option<String>,
    pub operation: Option<String>,
    pub path: Option<String>,
    pub mount_type: Option<String>,
    pub mount_point: Option<String>,
    pub mount_class: Option<String>,
    pub mount_running_version: Option<String>,
    pub namespace: Option<Namespace>,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub client_token: Option<String>,
    pub client_token_accessor: Option<String>,
}

/// Response information
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
        self.path()
            .map(|p| p.starts_with(prefix))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn is_token_operation(&self) -> bool {
        self.path_starts_with("auth/token/")
    }
}
