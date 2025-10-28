//! Data structures representing `HashiCorp` Vault audit log entries.
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
    #[allow(dead_code)]
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
        self.mount_type().is_some_and(|mt| mt == "kv")
    }

    #[allow(dead_code)]
    pub fn is_read_or_list(&self) -> bool {
        self.operation()
            .is_some_and(|op| op == "read" || op == "list")
    }

    #[allow(dead_code)]
    pub fn path_starts_with(&self, prefix: &str) -> bool {
        self.path().is_some_and(|p| p.starts_with(prefix))
    }

    #[allow(dead_code)]
    pub fn is_token_operation(&self) -> bool {
        self.path_starts_with("auth/token/")
    }

    /// Get the namespace ID from this entry
    pub fn namespace_id(&self) -> Option<&str> {
        self.request
            .as_ref()?
            .namespace
            .as_ref()
            .map(|ns| ns.id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_login_request() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {
                "entity_id": "test-entity-123",
                "display_name": "test-user",
                "policies": ["default", "admin"],
                "token_type": "service"
            },
            "request": {
                "operation": "update",
                "path": "auth/kubernetes/login",
                "mount_type": "kubernetes",
                "mount_point": "auth/kubernetes/"
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.entry_type, "request");
        assert_eq!(entry.entity_id(), Some("test-entity-123"));
        assert_eq!(entry.path(), Some("auth/kubernetes/login"));
        assert_eq!(entry.operation(), Some("update"));
        assert_eq!(entry.display_name(), Some("test-user"));
        assert_eq!(entry.mount_type(), Some("kubernetes"));
        assert_eq!(entry.mount_point(), Some("auth/kubernetes/"));
    }

    #[test]
    fn test_parse_kv_read() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {
                "entity_id": "entity-456",
                "display_name": "app-user"
            },
            "request": {
                "operation": "read",
                "path": "kv/data/myapp/config",
                "mount_type": "kv",
                "mount_point": "kv/"
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.entity_id(), Some("entity-456"));
        assert!(entry.is_kv_operation());
        assert!(entry.is_read_or_list());
        assert!(entry.path_starts_with("kv/"));
    }

    #[test]
    fn test_parse_token_operation() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {
                "entity_id": "entity-789"
            },
            "request": {
                "operation": "update",
                "path": "auth/token/lookup-self"
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert!(entry.is_token_operation());
        assert!(!entry.is_kv_operation());
    }

    #[test]
    fn test_parse_no_auth() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "request": {
                "operation": "read",
                "path": "sys/health"
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.entity_id(), None);
        assert_eq!(entry.display_name(), None);
        assert_eq!(entry.path(), Some("sys/health"));
    }

    #[test]
    fn test_parse_response() {
        let json = r#"{
            "type": "response",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {
                "entity_id": "entity-999"
            },
            "request": {
                "operation": "read",
                "path": "secret/data/test"
            },
            "response": {
                "mount_type": "kv",
                "data": {"foo": "bar"}
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.entry_type, "response");
        assert!(entry.response.is_some());
        assert_eq!(entry.response.unwrap().mount_type, Some("kv".to_string()));
    }

    #[test]
    fn test_parse_with_error() {
        let json = r#"{
            "type": "response",
            "time": "2025-10-07T12:00:00.000Z",
            "error": "permission denied"
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.error, Some("permission denied".to_string()));
    }

    #[test]
    fn test_parse_list_operation() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {"entity_id": "test"},
            "request": {
                "operation": "list",
                "path": "kv/metadata/",
                "mount_type": "kv"
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert!(entry.is_read_or_list());
        assert_eq!(entry.operation(), Some("list"));
    }

    #[test]
    fn test_namespace_parsing() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "request": {
                "operation": "read",
                "path": "test",
                "namespace": {"id": "root"}
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert!(entry.request.unwrap().namespace.is_some());
    }

    #[test]
    fn test_metadata_parsing() {
        let json = r#"{
            "type": "request",
            "time": "2025-10-07T12:00:00.000Z",
            "auth": {
                "entity_id": "test",
                "metadata": {
                    "service_account_name": "my-app",
                    "service_account_namespace": "production"
                }
            }
        }"#;

        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        let metadata = entry.auth.unwrap().metadata.unwrap();
        assert!(metadata.contains_key("service_account_name"));
    }
}
