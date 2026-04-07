package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/trenner1/hashicorp-vault-audit-analysis/internal/jobs"
)

// Cluster represents a Vault cluster connection.
type Cluster struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	VaultAddr string    `json:"vault_addr"`
	Namespace string    `json:"namespace"`
	Token     string    `json:"token,omitempty"` // Vault token — stored server-side, never echoed in full
	CreatedAt time.Time `json:"created_at"`
}

// Server encapsulates the API server and its dependencies.
type Server struct {
	router        *chi.Mux
	queue         *jobs.Queue
	broker        *jobs.Broker
	clusters      map[string]*Cluster
	clustersMu    sync.RWMutex
	clusterStore  *clusterStore // nil = no persistence
	uploadDir     string
	anthropicKey  string
	apiKey        string
	startTime     time.Time
}

// New creates a new API server with the given queue and broker.
func New(queue *jobs.Queue, broker *jobs.Broker) *Server {
	s := &Server{
		router:    chi.NewMux(),
		queue:     queue,
		broker:    broker,
		clusters:  make(map[string]*Cluster),
		uploadDir: "./uploads",
		startTime: time.Now(),
	}

	// Setup routes
	s.setupRoutes()

	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// GetRouter returns the chi router for testing or advanced usage.
func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

// SetUploadDir sets the upload directory (defaults to ./uploads).
func (s *Server) SetUploadDir(dir string) {
	s.uploadDir = dir
}

// SetDataDir attaches a cluster store rooted at dir and loads any saved clusters.
func (s *Server) SetDataDir(dir string) error {
	cs, err := newClusterStore(dir)
	if err != nil {
		return err
	}
	clusters, err := cs.load()
	if err != nil {
		return err
	}
	s.clustersMu.Lock()
	s.clusterStore = cs
	s.clusters = clusters
	s.clustersMu.Unlock()
	return nil
}

// SetAnthropicKey sets the Anthropic API key for agentic query support.
func (s *Server) SetAnthropicKey(key string) {
	s.anthropicKey = key
}

// SetAPIKey sets the API key required to access all endpoints.
// If empty, authentication is disabled.
func (s *Server) SetAPIKey(key string) {
	s.apiKey = key
}
