package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── System info ───────────────────────────────────────────────────────────────

// SystemInfo is the response from GET /api/v1/system.
type SystemInfo struct {
	UptimeSeconds    float64        `json:"uptime_seconds"`
	AnthropicEnabled bool           `json:"anthropic_enabled"`
	AuthEnabled      bool           `json:"auth_enabled"`
	UploadDir        string         `json:"upload_dir"`
	MaxConcurrent    int            `json:"max_concurrent"` // 0 = unlimited
	Jobs             map[string]int `json:"jobs"`           // counts by status
	Version          string         `json:"version"`
}

// handleSystemInfo returns server configuration and live job stats.
// GET /api/v1/system
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	version := os.Getenv("APP_VERSION")
	if version == "" {
		version = "dev"
	}

	info := SystemInfo{
		UptimeSeconds:    time.Since(s.startTime).Seconds(),
		AnthropicEnabled: s.anthropicKey != "",
		AuthEnabled:      s.apiKey != "",
		UploadDir:        s.uploadDir,
		MaxConcurrent:    s.queue.MaxConcurrent(),
		Jobs:             s.queue.Stats(),
		Version:          version,
	}

	writeJSON(w, http.StatusOK, info)
}

// ── Job retention ─────────────────────────────────────────────────────────────

// handleDeleteJob deletes a single terminal job.
// DELETE /api/v1/jobs/{id}
func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if ok := s.queue.Delete(id); !ok {
		writeError(w, http.StatusConflict, "job not found or still running")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// PruneRequest is the optional body for POST /api/v1/jobs/prune.
type PruneRequest struct {
	OlderThanHours int `json:"older_than_hours"` // default: 24
}

// handlePruneJobs removes terminal jobs older than a threshold.
// POST /api/v1/jobs/prune
func (s *Server) handlePruneJobs(w http.ResponseWriter, r *http.Request) {
	var req PruneRequest
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if req.OlderThanHours <= 0 {
		// Also accept the older_than_hours query param for convenience.
		if v := r.URL.Query().Get("older_than_hours"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				req.OlderThanHours = n
			}
		}
	}
	if req.OlderThanHours <= 0 {
		req.OlderThanHours = 24
	}

	maxAge := time.Duration(req.OlderThanHours) * time.Hour
	deleted := s.queue.Prune(maxAge)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":           deleted,
		"older_than_hours":  req.OlderThanHours,
	})
}
