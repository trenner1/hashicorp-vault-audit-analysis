package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

	// Pre-generate the job ID so we can embed it in output filenames for
	// lineage tracking.  Commands that would otherwise silently write to a
	// fixed default path (e.g. entity_mappings.json) get a unique name that
	// encodes when it was produced and which job produced it.
	jobID := uuid.New().String()
	allArgs = injectUniqueOutput(req.Command, req.Subcommand, allArgs, jobID)

	job := s.queue.SubmitWithID(jobID, req.Command, allArgs)
	writeJSON(w, http.StatusAccepted, job)
}

// injectUniqueOutput rewrites or adds the --output flag for commands whose
// defaults would silently overwrite previous results.
//
// The generated filename embeds:
//   - the command type  (e.g. "entity_mappings")
//   - a UTC timestamp   (YYYYMMDD_HHMMSS)
//   - the first 8 chars of the job UUID
//
// This triple lets the file be sorted chronologically, unambiguously traced
// to a specific job, and understood at a glance in the Files tab.
//
// If the caller already passed an explicit --output / -o flag, that value is
// left untouched — we only intervene on the default-overwrite case.
func injectUniqueOutput(command, subcommand string, args []string, jobID string) []string {
	type outputRule struct {
		prefix string // e.g. "entity_mappings"
		ext    string // e.g. "json"
		flag   string // e.g. "--output"
	}

	// Commands whose defaults always write (and therefore silently overwrite).
	rules := map[string]outputRule{
		"entity-analysis/preprocess": {prefix: "entity_mappings", ext: "json", flag: "--output"},
	}

	key := command
	if subcommand != "" {
		key = command + "/" + subcommand
	}
	rule, ok := rules[key]
	if !ok {
		return args // nothing to do for this command
	}

	// Check whether an output flag is already present.
	for _, a := range args {
		if a == rule.flag || a == "-o" {
			return args // caller is explicit — leave it alone
		}
	}

	ts := time.Now().UTC().Format("20060102_150405")
	short := jobID[:8]
	filename := fmt.Sprintf("%s_%s_%s.%s", rule.prefix, ts, short, rule.ext)
	return append(args, rule.flag, filename)
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
