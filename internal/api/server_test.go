package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/jobs"
)

// newTestServer creates a Server wired to an in-memory queue/broker.
// uploadDir is set to a temp directory so file upload tests work without
// touching the real filesystem.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	broker := jobs.NewBroker()
	queue := jobs.NewQueue(broker)
	srv := New(queue, broker)
	srv.SetUploadDir(t.TempDir())
	return srv
}

// do fires a request against the server and returns the response recorder.
func do(t *testing.T, srv *Server, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

// ── /healthz ─────────────────────────────────────────────────────────────────

func TestHandleHealthz(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodGet, "/healthz", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200", rr.Code)
	}
	var body map[string]string
	json.Unmarshal(rr.Body.Bytes(), &body) //nolint:errcheck
	if body["status"] != "ok" {
		t.Errorf("healthz status = %q, want ok", body["status"])
	}
}

// ── /api/v1/commands ─────────────────────────────────────────────────────────

func TestHandleListCommands(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodGet, "/api/v1/commands", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/commands = %d, want 200", rr.Code)
	}
	var cmds []CommandInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &cmds); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(cmds) == 0 {
		t.Error("expected at least one command")
	}
	// Spot-check a few expected commands.
	names := make(map[string]bool)
	for _, c := range cmds {
		names[c.Name] = true
	}
	for _, want := range []string{"system-overview", "entity-analysis", "token-analysis"} {
		if !names[want] {
			t.Errorf("command %q missing from list", want)
		}
	}
}

// ── /api/v1/jobs (submit) ─────────────────────────────────────────────────────

func TestHandleSubmitJob_UnknownCommand(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(SubmitJobRequest{Command: "does-not-exist"})
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown command: got %d, want 400", rr.Code)
	}
}

func TestHandleSubmitJob_UnknownSubcommand(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(SubmitJobRequest{
		Command:    "entity-analysis",
		Subcommand: "no-such-sub",
	})
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown subcommand: got %d, want 400", rr.Code)
	}
}

func TestHandleSubmitJob_EmptyCommand(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(SubmitJobRequest{})
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty command: got %d, want 400", rr.Code)
	}
}

func TestHandleSubmitJob_ValidCommand(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(SubmitJobRequest{
		Command: "system-overview",
		Files:   []string{"/some/file.log"},
	})
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	if rr.Code != http.StatusAccepted {
		t.Errorf("valid submit: got %d, want 202", rr.Code)
	}
	var job jobs.Job
	if err := json.Unmarshal(rr.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if job.ID == "" {
		t.Error("returned job has empty ID")
	}
	if job.Command != "system-overview" {
		t.Errorf("job.Command = %q, want system-overview", job.Command)
	}
}

func TestHandleSubmitJob_ValidSubcommand(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(SubmitJobRequest{
		Command:    "entity-analysis",
		Subcommand: "preprocess",
		Files:      []string{"file.log"},
	})
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	if rr.Code != http.StatusAccepted {
		t.Errorf("valid subcommand: got %d, want 202", rr.Code)
	}
}

func TestHandleSubmitJob_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodPost, "/api/v1/jobs", []byte("{bad json"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: got %d, want 400", rr.Code)
	}
}

// ── /api/v1/jobs (list / get) ─────────────────────────────────────────────────

func TestHandleListJobs(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodGet, "/api/v1/jobs", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/jobs = %d, want 200", rr.Code)
	}
	// Should return an array (possibly empty).
	var list []json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
}

func TestHandleGetJob_NotFound(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodGet, "/api/v1/jobs/no-such-id", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /jobs/missing = %d, want 404", rr.Code)
	}
}

func TestHandleGetJob_Found(t *testing.T) {
	srv := newTestServer(t)

	// Submit a job so we have a real ID.
	body, _ := json.Marshal(SubmitJobRequest{Command: "system-overview", Files: []string{"f.log"}})
	postRR := do(t, srv, http.MethodPost, "/api/v1/jobs", body)
	var submitted jobs.Job
	json.Unmarshal(postRR.Body.Bytes(), &submitted) //nolint:errcheck

	rr := do(t, srv, http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s", submitted.ID), nil)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /jobs/<id> = %d, want 200", rr.Code)
	}
}

// ── /api/v1/clusters ─────────────────────────────────────────────────────────

func TestHandleListClusters_Empty(t *testing.T) {
	srv := newTestServer(t)
	rr := do(t, srv, http.MethodGet, "/api/v1/clusters", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /clusters = %d, want 200", rr.Code)
	}
	var clusters []clusterView
	json.Unmarshal(rr.Body.Bytes(), &clusters) //nolint:errcheck
	if len(clusters) != 0 {
		t.Errorf("expected empty cluster list, got %d", len(clusters))
	}
}

func TestHandleCreateCluster(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(CreateClusterRequest{
		Name:      "prod",
		VaultAddr: "https://vault.example.com",
		Namespace: "infra",
		Token:     "hvs.mysecret",
	})
	rr := do(t, srv, http.MethodPost, "/api/v1/clusters", body)
	if rr.Code != http.StatusCreated {
		t.Errorf("POST /clusters = %d, want 201\nbody: %s", rr.Code, rr.Body.String())
	}
	var view clusterView
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode cluster: %v", err)
	}
	if view.ID == "" {
		t.Error("created cluster has empty ID")
	}
	if view.Name != "prod" {
		t.Errorf("cluster Name = %q, want prod", view.Name)
	}
	// Token must never be echoed.
	if strings.Contains(rr.Body.String(), "hvs.mysecret") {
		t.Error("response body contains plaintext token — must be masked")
	}
	if !view.TokenSet {
		t.Error("token_set should be true when a token was provided")
	}
}

func TestHandleCreateCluster_MissingName(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(CreateClusterRequest{VaultAddr: "https://vault.example.com"})
	rr := do(t, srv, http.MethodPost, "/api/v1/clusters", body)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing name: got %d, want 400", rr.Code)
	}
}

func TestHandleDeleteCluster(t *testing.T) {
	srv := newTestServer(t)

	// Create first.
	body, _ := json.Marshal(CreateClusterRequest{Name: "tmp", VaultAddr: "http://vault"})
	postRR := do(t, srv, http.MethodPost, "/api/v1/clusters", body)
	var created clusterView
	json.Unmarshal(postRR.Body.Bytes(), &created) //nolint:errcheck

	// Delete.
	rr := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/v1/clusters/%s", created.ID), nil)
	if rr.Code != http.StatusNoContent {
		t.Errorf("DELETE /clusters/<id> = %d, want 204", rr.Code)
	}

	// Verify gone.
	listRR := do(t, srv, http.MethodGet, "/api/v1/clusters", nil)
	var clusters []clusterView
	json.Unmarshal(listRR.Body.Bytes(), &clusters) //nolint:errcheck
	if len(clusters) != 0 {
		t.Errorf("cluster still in list after delete")
	}
}

// ── /api/v1/ingest/upload ─────────────────────────────────────────────────────

func TestHandleUpload(t *testing.T) {
	srv := newTestServer(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "test.log")
	fmt.Fprintf(fw, "log line 1\nlog line 2\n")
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("upload: got %d, want 200\nbody: %s", rr.Code, rr.Body.String())
	}
	var resp UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if resp.Filename == "" {
		t.Error("upload response has empty filename")
	}
	if resp.Size <= 0 {
		t.Error("upload response size should be > 0")
	}
	// Verify the file actually landed on disk.
	if _, err := os.Stat(resp.Path); os.IsNotExist(err) {
		t.Errorf("uploaded file not found at path %q", resp.Path)
	}
}

func TestHandleUpload_NoFile(t *testing.T) {
	srv := newTestServer(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("no file upload: got %d, want 400", rr.Code)
	}
}

// ── injectUniqueOutput ────────────────────────────────────────────────────────

func TestInjectUniqueOutput_EntityAnalysisPreprocess(t *testing.T) {
	args := []string{"file.log"}
	result := injectUniqueOutput("entity-analysis", "preprocess", args, "abcdef12-0000-0000-0000-000000000000")
	// Should have appended --output <generated-filename>
	if len(result) < 3 {
		t.Fatalf("expected at least 3 args, got %v", result)
	}
	flagIdx := -1
	for i, a := range result {
		if a == "--output" {
			flagIdx = i
			break
		}
	}
	if flagIdx == -1 {
		t.Fatalf("--output flag not injected: %v", result)
	}
	filename := result[flagIdx+1]
	if !strings.HasPrefix(filename, "entity_mappings_") {
		t.Errorf("filename %q should start with entity_mappings_", filename)
	}
	if !strings.HasSuffix(filename, ".json") {
		t.Errorf("filename %q should end with .json", filename)
	}
	// Short job ID (8 chars) should be embedded.
	if !strings.Contains(filename, "abcdef12") {
		t.Errorf("filename %q should contain short job ID abcdef12", filename)
	}
}

func TestInjectUniqueOutput_SkipsIfOutputAlreadyPresent(t *testing.T) {
	args := []string{"file.log", "--output", "custom.json"}
	result := injectUniqueOutput("entity-analysis", "preprocess", args, "job-id-here")
	if len(result) != 3 {
		t.Errorf("expected args unchanged (%d), got %d: %v", len(args), len(result), result)
	}
}

func TestInjectUniqueOutput_NoRuleForCommand(t *testing.T) {
	args := []string{"file.log"}
	result := injectUniqueOutput("system-overview", "", args, "job-id")
	if len(result) != 1 {
		t.Errorf("no-rule command should return args unchanged, got %v", result)
	}
}

// ── injectClusterArgs ─────────────────────────────────────────────────────────

func TestInjectClusterArgs(t *testing.T) {
	c := &Cluster{
		VaultAddr: "https://vault.prod",
		Token:     "hvs.tok",
		Namespace: "ns-infra",
	}
	args := injectClusterArgs([]string{}, c)
	has := func(flag, val string) bool {
		for i, a := range args {
			if a == flag && i+1 < len(args) && args[i+1] == val {
				return true
			}
		}
		return false
	}
	if !has("--vault-addr", "https://vault.prod") {
		t.Errorf("--vault-addr not injected: %v", args)
	}
	if !has("--token", "hvs.tok") {
		t.Errorf("--token not injected: %v", args)
	}
	if !has("--namespace", "ns-infra") {
		t.Errorf("--namespace not injected: %v", args)
	}
}

func TestInjectClusterArgs_SkipsIfAlreadyPresent(t *testing.T) {
	c := &Cluster{VaultAddr: "https://vault.prod", Token: "tok"}
	args := injectClusterArgs([]string{"--vault-addr", "https://override", "--token", "user-tok"}, c)
	count := 0
	for _, a := range args {
		if a == "--vault-addr" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("--vault-addr appears %d times, want 1: %v", count, args)
	}
}
