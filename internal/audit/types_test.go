package audit

import (
	"encoding/json"
	"testing"
)

// helpers for building pointer fields inline.
func sp(s string) *string { return &s }

// newEntry builds a minimal AuditEntry for testing.
func newEntry(entryType string) *AuditEntry {
	return &AuditEntry{EntryType: entryType}
}

func withAuth(e *AuditEntry, entityID, displayName, accessor string) *AuditEntry {
	e.Auth = &AuthInfo{
		EntityID:    sp(entityID),
		DisplayName: sp(displayName),
		Accessor:    sp(accessor),
	}
	return e
}

func withRequest(e *AuditEntry, op, path, mountType, mountPoint, ns, ip string) *AuditEntry {
	e.Request = &RequestInfo{
		Operation:     sp(op),
		Path:          sp(path),
		MountType:     sp(mountType),
		MountPoint:    sp(mountPoint),
		Namespace:     &Namespace{ID: ns},
		RemoteAddress: sp(ip),
	}
	return e
}

func withError(e *AuditEntry, msg string) *AuditEntry {
	e.Error = sp(msg)
	return e
}

// ── EntityID ─────────────────────────────────────────────────────────────────

func TestEntityID(t *testing.T) {
	t.Run("nil auth", func(t *testing.T) {
		e := newEntry("request")
		if got := e.EntityID(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("nil entity_id", func(t *testing.T) {
		e := &AuditEntry{Auth: &AuthInfo{}}
		if got := e.EntityID(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("populated", func(t *testing.T) {
		e := withAuth(newEntry("request"), "abc-123", "web", "acc-1")
		if got := e.EntityID(); got != "abc-123" {
			t.Errorf("got %q, want abc-123", got)
		}
	})
}

// ── Path / Operation ─────────────────────────────────────────────────────────

func TestPath(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		if got := newEntry("request").Path(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("nil path", func(t *testing.T) {
		e := &AuditEntry{Request: &RequestInfo{}}
		if got := e.Path(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("populated", func(t *testing.T) {
		e := withRequest(newEntry("request"), "read", "kv/data/web/config", "kv", "kv/", "root", "10.0.0.1")
		if got := e.Path(); got != "kv/data/web/config" {
			t.Errorf("got %q, want kv/data/web/config", got)
		}
	})
}

func TestOperation(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		if got := newEntry("request").Operation(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("read", func(t *testing.T) {
		e := withRequest(newEntry("request"), "read", "kv/data/foo", "kv", "kv/", "root", "")
		if got := e.Operation(); got != "read" {
			t.Errorf("got %q, want read", got)
		}
	})
}

// ── DisplayName / Accessor ────────────────────────────────────────────────────

func TestDisplayName(t *testing.T) {
	t.Run("nil auth", func(t *testing.T) {
		if got := newEntry("request").DisplayName(); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("populated", func(t *testing.T) {
		e := withAuth(newEntry("request"), "", "kubernetes-default-web", "")
		if got := e.DisplayName(); got != "kubernetes-default-web" {
			t.Errorf("got %q, want kubernetes-default-web", got)
		}
	})
}

func TestAccessor(t *testing.T) {
	e := withAuth(newEntry("request"), "", "", "hvs.ACC001")
	if got := e.Accessor(); got != "hvs.ACC001" {
		t.Errorf("got %q, want hvs.ACC001", got)
	}
}

// ── MountType / MountPoint / NamespaceID / RemoteAddress ─────────────────────

func TestMountFields(t *testing.T) {
	e := withRequest(newEntry("request"), "read", "kv/data/x", "kv", "kv/", "ns-platform", "192.168.1.1")

	if got := e.MountType(); got != "kv" {
		t.Errorf("MountType = %q, want kv", got)
	}
	if got := e.MountPoint(); got != "kv/" {
		t.Errorf("MountPoint = %q, want kv/", got)
	}
	if got := e.NamespaceID(); got != "ns-platform" {
		t.Errorf("NamespaceID = %q, want ns-platform", got)
	}
	if got := e.RemoteAddress(); got != "192.168.1.1" {
		t.Errorf("RemoteAddress = %q, want 192.168.1.1", got)
	}
}

func TestMountFieldsNilRequest(t *testing.T) {
	e := newEntry("request")
	if got := e.MountType(); got != "" {
		t.Errorf("MountType (nil request) = %q, want empty", got)
	}
	if got := e.MountPoint(); got != "" {
		t.Errorf("MountPoint (nil request) = %q, want empty", got)
	}
	if got := e.NamespaceID(); got != "" {
		t.Errorf("NamespaceID (nil request) = %q, want empty", got)
	}
	if got := e.RemoteAddress(); got != "" {
		t.Errorf("RemoteAddress (nil request) = %q, want empty", got)
	}
}

// ── IsKVOperation ─────────────────────────────────────────────────────────────

func TestIsKVOperation(t *testing.T) {
	cases := []struct {
		mountType string
		want      bool
	}{
		{"kv", true},
		{"kubernetes", false},
		{"token", false},
		{"", false},
	}
	for _, tc := range cases {
		e := withRequest(newEntry("request"), "read", "some/path", tc.mountType, "", "", "")
		if got := e.IsKVOperation(); got != tc.want {
			t.Errorf("IsKVOperation (mount=%q) = %v, want %v", tc.mountType, got, tc.want)
		}
	}
}

// ── IsReadOrList ─────────────────────────────────────────────────────────────

func TestIsReadOrList(t *testing.T) {
	cases := []struct {
		op   string
		want bool
	}{
		{"read", true},
		{"list", true},
		{"create", false},
		{"update", false},
		{"delete", false},
		{"", false},
	}
	for _, tc := range cases {
		e := withRequest(newEntry("request"), tc.op, "", "", "", "", "")
		if got := e.IsReadOrList(); got != tc.want {
			t.Errorf("IsReadOrList (op=%q) = %v, want %v", tc.op, got, tc.want)
		}
	}
}

// ── PathStartsWith / IsTokenOperation ─────────────────────────────────────────

func TestPathStartsWith(t *testing.T) {
	e := withRequest(newEntry("request"), "read", "auth/token/lookup-self", "", "", "", "")
	if !e.PathStartsWith("auth/token/") {
		t.Error("expected PathStartsWith(auth/token/) = true")
	}
	if e.PathStartsWith("kv/") {
		t.Error("expected PathStartsWith(kv/) = false")
	}
	// Prefix longer than path.
	if e.PathStartsWith("auth/token/lookup-self/extra") {
		t.Error("expected prefix-longer-than-path = false")
	}
}

func TestIsTokenOperation(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"auth/token/lookup-self", true},
		{"auth/token/renew-self", true},
		{"auth/token/create", true},
		{"kv/data/foo", false},
		{"auth/kubernetes/login", false},
	}
	for _, tc := range cases {
		e := withRequest(newEntry("request"), "read", tc.path, "", "", "", "")
		if got := e.IsTokenOperation(); got != tc.want {
			t.Errorf("IsTokenOperation(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// ── MetadataString ────────────────────────────────────────────────────────────

func TestMetadataString(t *testing.T) {
	t.Run("nil auth", func(t *testing.T) {
		if got := newEntry("request").MetadataString("k"); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("key absent", func(t *testing.T) {
		e := &AuditEntry{Auth: &AuthInfo{Metadata: map[string]json.RawMessage{}}}
		if got := e.MetadataString("missing"); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("string value", func(t *testing.T) {
		raw, _ := json.Marshal("my-namespace")
		e := &AuditEntry{Auth: &AuthInfo{
			Metadata: map[string]json.RawMessage{
				"service_account_namespace": raw,
			},
		}}
		if got := e.MetadataString("service_account_namespace"); got != "my-namespace" {
			t.Errorf("got %q, want my-namespace", got)
		}
	})
	t.Run("non-string value (number)", func(t *testing.T) {
		raw := json.RawMessage(`42`)
		e := &AuditEntry{Auth: &AuthInfo{
			Metadata: map[string]json.RawMessage{"num": raw},
		}}
		if got := e.MetadataString("num"); got != "" {
			t.Errorf("got %q, want empty for non-string", got)
		}
	})
}

// ── HasError / ErrorString ────────────────────────────────────────────────────

func TestError(t *testing.T) {
	t.Run("no error field", func(t *testing.T) {
		e := newEntry("response")
		if e.HasError() {
			t.Error("HasError() should be false when Error is nil")
		}
		if got := e.ErrorString(); got != "" {
			t.Errorf("ErrorString() = %q, want empty", got)
		}
	})
	t.Run("empty error string", func(t *testing.T) {
		e := withError(newEntry("response"), "")
		if e.HasError() {
			t.Error("HasError() should be false for empty string")
		}
	})
	t.Run("populated error", func(t *testing.T) {
		e := withError(newEntry("response"), "permission denied")
		if !e.HasError() {
			t.Error("HasError() should be true")
		}
		if got := e.ErrorString(); got != "permission denied" {
			t.Errorf("ErrorString() = %q, want permission denied", got)
		}
	})
}

// ── JSON round-trip ───────────────────────────────────────────────────────────

func TestJSONRoundTrip(t *testing.T) {
	raw := `{"type":"request","time":"2025-01-01T10:00:00.000Z","auth":{"accessor":"hvs.ACC001","display_name":"kubernetes-default-web","entity_id":"e001-web","token_type":"service","metadata":{"service_account_namespace":"\"default\"","service_account_name":"\"web-svc\""}},"request":{"id":"req-000001","operation":"read","path":"kv/data/web/config","mount_type":"kv","mount_point":"kv/","namespace":{"id":"root"},"remote_address":"10.0.0.10"}}`

	var e AuditEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if e.EntryType != "request" {
		t.Errorf("EntryType = %q, want request", e.EntryType)
	}
	if e.EntityID() != "e001-web" {
		t.Errorf("EntityID = %q, want e001-web", e.EntityID())
	}
	if e.Path() != "kv/data/web/config" {
		t.Errorf("Path = %q, want kv/data/web/config", e.Path())
	}
	if e.Operation() != "read" {
		t.Errorf("Operation = %q, want read", e.Operation())
	}
	if !e.IsKVOperation() {
		t.Error("IsKVOperation should be true")
	}
	if !e.IsReadOrList() {
		t.Error("IsReadOrList should be true")
	}
	if e.NamespaceID() != "root" {
		t.Errorf("NamespaceID = %q, want root", e.NamespaceID())
	}
}
