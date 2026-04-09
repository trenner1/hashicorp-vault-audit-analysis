package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// setupRoutes configures all API routes.
func (s *Server) setupRoutes() {
	// Middleware
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(s.corsMiddleware())
	s.router.Use(authMiddleware(func() string { return s.apiKey }))

	// Health check
	s.router.Get("/healthz", s.handleHealthz)

	// API v1 routes
	s.router.Route("/api/v1", func(r chi.Router) {
		// Commands
		r.Get("/commands", s.handleListCommands)

		// Jobs
		r.Post("/jobs", s.handleSubmitJob)
		r.Get("/jobs", s.handleListJobs)
		r.Post("/jobs/prune", s.handlePruneJobs)
		r.Get("/jobs/{id}", s.handleGetJob)
		r.Delete("/jobs/{id}", s.handleDeleteJob)
		r.Get("/jobs/{id}/stream", s.handleStreamJob)
		r.Post("/jobs/{id}/cancel", s.handleCancelJob)
		r.Post("/jobs/{id}/summarize", s.handleSummarizeJob)

		// Clusters
		r.Get("/clusters", s.handleListClusters)
		r.Post("/clusters", s.handleCreateCluster)
		r.Patch("/clusters/{id}", s.handleUpdateCluster)
		r.Delete("/clusters/{id}", s.handleDeleteCluster)

		// Ingest
		r.Post("/ingest/upload", s.handleUpload)
		r.Get("/ingest/files", s.handleListFiles)
		r.Delete("/ingest/files/{filename}", s.handleDeleteFile)

		// Agentic query
		r.Post("/query", s.handleQuery)

		// System info
		r.Get("/system", s.handleSystemInfo)
	})
}

// corsMiddleware returns a CORS middleware that only reflects origins present in
// s.corsOrigins.  When the wildcard "*" is in the list every origin is reflected
// but Access-Control-Allow-Credentials is NOT set (browsers reject credentials
// with a wildcard origin anyway).  For explicit non-wildcard origins credentials
// are allowed.
func (s *Server) corsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			allowedOrigin := ""
			credentialsOK := false

			for _, o := range s.corsOrigins {
				if o == "*" {
					// Wildcard: reflect origin or fall back to "*"
					if origin != "" {
						allowedOrigin = origin
					} else {
						allowedOrigin = "*"
					}
					// credentials must NOT be combined with "*"
					credentialsOK = false
					break
				}
				if o == origin {
					allowedOrigin = origin
					credentialsOK = true
					break
				}
			}

			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				if credentialsOK {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleHealthz returns a health check response.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
