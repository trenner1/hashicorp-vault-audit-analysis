package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/jobs"
)

// CommandInfo describes a vault-audit command for the UI.
type CommandInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Subcommands []string `json:"subcommands,omitempty"`
}

// handleListCommands returns all available vault-audit commands.
func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	commands := []CommandInfo{
		{Name: "system-overview", Description: "High-level overview of all operations, entities, and auth methods"},
		{Name: "path-hotspots", Description: "Find most accessed paths with optimization recommendations"},
		{Name: "token-analysis", Description: "Token operations analysis with abuse detection and CSV export"},
		{Name: "kv-analysis", Description: "KV secrets analysis — usage, comparison, and summarization",
			Subcommands: []string{"analyze", "compare", "summary"}},
		{Name: "entity-analysis", Description: "Entity lifecycle analysis, creation tracking, and preprocessing",
			Subcommands: []string{"churn", "creation", "preprocess", "gaps", "timeline"}},
		{Name: "k8s-auth", Description: "Kubernetes/OpenShift authentication patterns and entity churn"},
		{Name: "airflow-polling", Description: "Airflow secret polling patterns with burst rate detection"},
		{Name: "client-traffic-analysis", Description: "Client traffic patterns from aggregated audit logs"},
		{Name: "client-activity", Description: "Query Vault for client activity metrics by mount (requires Vault API)"},
		{Name: "entity-list", Description: "List Vault entities and aliases (requires Vault API)"},
		{Name: "kv-mounts", Description: "List KV secret mounts (requires Vault API)"},
		{Name: "auth-mounts", Description: "List authentication mounts (requires Vault API)"},
	}
	writeJSON(w, http.StatusOK, commands)
}

// SubmitJobRequest is the body for POST /api/v1/jobs.
type SubmitJobRequest struct {
	Command    string   `json:"command"`
	Subcommand string   `json:"subcommand,omitempty"`
	Files      []string `json:"files,omitempty"`
	Args       []string `json:"args,omitempty"`
	ClusterID  string   `json:"cluster_id,omitempty"`
}

// handleSubmitJob queues a new vault-audit command and returns the job immediately.
func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	var req SubmitJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	// Build full arg list: [subcommand] [files...] [flags...]
	allArgs := []string{}
	if req.Subcommand != "" {
		allArgs = append(allArgs, req.Subcommand)
	}
	allArgs = append(allArgs, req.Files...)
	allArgs = append(allArgs, req.Args...)

	// Inject cluster flags if a cluster_id was provided.
	if req.ClusterID != "" {
		s.clustersMu.RLock()
		cluster, ok := s.clusters[req.ClusterID]
		s.clustersMu.RUnlock()
		if ok {
			allArgs = injectClusterArgs(allArgs, cluster)
		}
	}

	job := s.queue.Submit(req.Command, allArgs)
	writeJSON(w, http.StatusAccepted, job)
}

// handleListJobs returns all jobs.
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.queue.List())
}

// handleGetJob returns a single job by ID.
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, ok := s.queue.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleCancelJob kills a running or pending job.
func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if ok := s.queue.Cancel(id); !ok {
		writeError(w, http.StatusConflict, "job is not running or does not exist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// handleStreamJob streams a job's live output via Server-Sent Events.
func (s *Server) handleStreamJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := s.queue.Get(id); !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	jobs.ServeSSE(w, r, id, s.broker)
}
