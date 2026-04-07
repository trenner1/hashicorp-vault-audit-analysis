package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// clusterView is the safe API representation of a cluster.
// The token is masked so it is never returned in full to clients.
type clusterView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	VaultAddr  string    `json:"vault_addr"`
	Namespace  string    `json:"namespace"`
	TokenSet   bool      `json:"token_set"`
	CreatedAt  time.Time `json:"created_at"`
}

func toView(c *Cluster) clusterView {
	return clusterView{
		ID:        c.ID,
		Name:      c.Name,
		VaultAddr: c.VaultAddr,
		Namespace: c.Namespace,
		TokenSet:  c.Token != "",
		CreatedAt: c.CreatedAt,
	}
}

// injectClusterArgs appends --vault-addr, --token, and --namespace to args
// if they are not already present and the cluster has the respective values set.
func injectClusterArgs(args []string, c *Cluster) []string {
	has := func(flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	if c.VaultAddr != "" && !has("--vault-addr") {
		args = append(args, "--vault-addr", c.VaultAddr)
	}
	if c.Token != "" && !has("--token") {
		args = append(args, "--token", c.Token)
	}
	if c.Namespace != "" && !has("--namespace") {
		args = append(args, "--namespace", c.Namespace)
	}
	return args
}

// persistClusters saves the current cluster map to disk (call with clustersMu held).
func (s *Server) persistClusters() {
	if s.clusterStore != nil {
		_ = s.clusterStore.save(s.clusters)
	}
}

// handleListClusters returns all clusters (token masked).
func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	s.clustersMu.RLock()
	defer s.clustersMu.RUnlock()

	views := make([]clusterView, 0, len(s.clusters))
	for _, c := range s.clusters {
		views = append(views, toView(c))
	}
	writeJSON(w, http.StatusOK, views)
}

// CreateClusterRequest is the request body for creating or updating a cluster.
type CreateClusterRequest struct {
	Name      string `json:"name"`
	VaultAddr string `json:"vault_addr"`
	Namespace string `json:"namespace"`
	Token     string `json:"token"` // optional; empty = keep existing on update
}

// handleCreateCluster creates a new cluster and persists it.
func (s *Server) handleCreateCluster(w http.ResponseWriter, r *http.Request) {
	var req CreateClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.VaultAddr == "" {
		writeError(w, http.StatusBadRequest, "vault_addr is required")
		return
	}

	cluster := &Cluster{
		ID:        uuid.New().String(),
		Name:      req.Name,
		VaultAddr: req.VaultAddr,
		Namespace: req.Namespace,
		Token:     req.Token,
		CreatedAt: time.Now(),
	}

	s.clustersMu.Lock()
	s.clusters[cluster.ID] = cluster
	s.persistClusters()
	s.clustersMu.Unlock()

	writeJSON(w, http.StatusCreated, toView(cluster))
}

// handleUpdateCluster updates mutable fields of an existing cluster.
// PATCH /api/v1/clusters/{id}
func (s *Server) handleUpdateCluster(w http.ResponseWriter, r *http.Request) {
	clusterID := chi.URLParam(r, "id")

	var req CreateClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.VaultAddr == "" {
		writeError(w, http.StatusBadRequest, "vault_addr is required")
		return
	}

	s.clustersMu.Lock()
	defer s.clustersMu.Unlock()

	cluster, ok := s.clusters[clusterID]
	if !ok {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}

	cluster.Name = req.Name
	cluster.VaultAddr = req.VaultAddr
	cluster.Namespace = req.Namespace
	// Only update the token if one was provided; empty string = leave unchanged.
	if req.Token != "" {
		cluster.Token = req.Token
	}
	s.persistClusters()

	writeJSON(w, http.StatusOK, toView(cluster))
}

// handleDeleteCluster deletes a cluster by ID.
func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	clusterID := chi.URLParam(r, "id")

	s.clustersMu.Lock()
	defer s.clustersMu.Unlock()

	if _, exists := s.clusters[clusterID]; !exists {
		writeError(w, http.StatusNotFound, "cluster not found")
		return
	}

	delete(s.clusters, clusterID)
	s.persistClusters()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
