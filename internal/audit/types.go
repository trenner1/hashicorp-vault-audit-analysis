// Package audit provides data structures representing HashiCorp Vault audit log entries.
//
// These types mirror the JSON structure of Vault audit logs,
// enabling efficient deserialization with encoding/json.
package audit

import "encoding/json"

// AuditEntry is the top-level structure for a single Vault audit log line.
// Each line in a Vault audit log is a JSON object that deserializes into this type.
// Entries can be either requests or responses.
type AuditEntry struct {
	EntryType string        `json:"type"` // "request" or "response"
	Time      string        `json:"time"`
	Auth      *AuthInfo     `json:"auth,omitempty"`
	Request   *RequestInfo  `json:"request,omitempty"`
	Response  *ResponseInfo `json:"response,omitempty"`
	Error     *string       `json:"error,omitempty"`
}

// AuthInfo contains authentication details from the audit log.
// Describes the token used to make the request, including the associated
// entity, policies, and metadata.
type AuthInfo struct {
	Accessor       *string                    `json:"accessor,omitempty"`
	ClientToken    *string                    `json:"client_token,omitempty"`
	DisplayName    *string                    `json:"display_name,omitempty"`
	EntityID       *string                    `json:"entity_id,omitempty"`
	Metadata       map[string]json.RawMessage `json:"metadata,omitempty"`
	Policies       []string                   `json:"policies,omitempty"`
	TokenPolicies  []string                   `json:"token_policies,omitempty"`
	TokenType      *string                    `json:"token_type,omitempty"`
	TokenTTL       *uint64                    `json:"token_ttl,omitempty"`
	TokenIssueTime *string                    `json:"token_issue_time,omitempty"`
}

// RequestInfo describes the Vault operation being performed.
type RequestInfo struct {
	ID                  *string    `json:"id,omitempty"`
	ClientID            *string    `json:"client_id,omitempty"`
	Operation           *string    `json:"operation,omitempty"`
	Path                *string    `json:"path,omitempty"`
	MountType           *string    `json:"mount_type,omitempty"`
	MountPoint          *string    `json:"mount_point,omitempty"`
	MountClass          *string    `json:"mount_class,omitempty"`
	MountRunningVersion *string    `json:"mount_running_version,omitempty"`
	Namespace           *Namespace `json:"namespace,omitempty"`
	RemoteAddress       *string    `json:"remote_address,omitempty"`
	RemotePort          *uint16    `json:"remote_port,omitempty"`
	ClientToken         *string    `json:"client_token,omitempty"`
	ClientTokenAccessor *string    `json:"client_token_accessor,omitempty"`
}

// ResponseInfo contains the result of a Vault operation.
type ResponseInfo struct {
	Auth      *AuthInfo                  `json:"auth,omitempty"`
	Data      map[string]json.RawMessage `json:"data,omitempty"`
	MountType *string                    `json:"mount_type,omitempty"`
	Redirect  *string                    `json:"redirect,omitempty"`
	Warnings  []string                   `json:"warnings,omitempty"`
}

// Namespace contains Vault namespace information.
type Namespace struct {
	ID string `json:"id"`
}

// ---------- Convenience methods ----------

// EntityID returns the entity ID from the auth block, or empty string.
func (e *AuditEntry) EntityID() string {
	if e.Auth == nil || e.Auth.EntityID == nil {
		return ""
	}
	return *e.Auth.EntityID
}

// Path returns the request path, or empty string.
func (e *AuditEntry) Path() string {
	if e.Request == nil || e.Request.Path == nil {
		return ""
	}
	return *e.Request.Path
}

// Operation returns the request operation type (read, write, list, delete…), or empty string.
func (e *AuditEntry) Operation() string {
	if e.Request == nil || e.Request.Operation == nil {
		return ""
	}
	return *e.Request.Operation
}

// DisplayName returns the auth display name, or empty string.
func (e *AuditEntry) DisplayName() string {
	if e.Auth == nil || e.Auth.DisplayName == nil {
		return ""
	}
	return *e.Auth.DisplayName
}

// Accessor returns the auth accessor (token identifier), or empty string.
func (e *AuditEntry) Accessor() string {
	if e.Auth == nil || e.Auth.Accessor == nil {
		return ""
	}
	return *e.Auth.Accessor
}

// MountType returns the mount type (kv, kubernetes, …), or empty string.
func (e *AuditEntry) MountType() string {
	if e.Request == nil || e.Request.MountType == nil {
		return ""
	}
	return *e.Request.MountType
}

// MountPoint returns the mount point path, or empty string.
func (e *AuditEntry) MountPoint() string {
	if e.Request == nil || e.Request.MountPoint == nil {
		return ""
	}
	return *e.Request.MountPoint
}

// NamespaceID returns the request namespace ID, or empty string.
func (e *AuditEntry) NamespaceID() string {
	if e.Request == nil || e.Request.Namespace == nil {
		return ""
	}
	return e.Request.Namespace.ID
}

// RemoteAddress returns the client IP address, or empty string.
func (e *AuditEntry) RemoteAddress() string {
	if e.Request == nil || e.Request.RemoteAddress == nil {
		return ""
	}
	return *e.Request.RemoteAddress
}

// IsKVOperation reports whether this entry is a KV secrets engine operation.
func (e *AuditEntry) IsKVOperation() bool {
	return e.MountType() == "kv"
}

// IsReadOrList reports whether the operation is a read or list.
func (e *AuditEntry) IsReadOrList() bool {
	op := e.Operation()
	return op == "read" || op == "list"
}

// PathStartsWith reports whether the request path has the given prefix.
func (e *AuditEntry) PathStartsWith(prefix string) bool {
	p := e.Path()
	return len(p) >= len(prefix) && p[:len(prefix)] == prefix
}

// IsTokenOperation reports whether this is an auth/token/* path operation.
func (e *AuditEntry) IsTokenOperation() bool {
	return e.PathStartsWith("auth/token/")
}

// MetadataString extracts a string value from auth metadata by key.
// Returns empty string if the key does not exist or is not a string.
func (e *AuditEntry) MetadataString(key string) string {
	if e.Auth == nil || e.Auth.Metadata == nil {
		return ""
	}
	raw, ok := e.Auth.Metadata[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// HasError reports whether this audit entry contains an error.
func (e *AuditEntry) HasError() bool {
	return e.Error != nil && *e.Error != ""
}

// ErrorString returns the error string, or empty string.
func (e *AuditEntry) ErrorString() string {
	if e.Error == nil {
		return ""
	}
	return *e.Error
}
