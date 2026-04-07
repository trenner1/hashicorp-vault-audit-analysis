package api

import (
	"net/http"
	"strings"
)

// authMiddleware returns a middleware that enforces API key authentication.
// If apiKey is empty the middleware is a no-op (auth disabled).
// The key is accepted via:
//   - X-API-Key: <key>
//   - Authorization: Bearer <key>
//
// /healthz is always allowed without authentication.
func authMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Auth disabled — pass through.
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Health check is always public.
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			provided := r.Header.Get("X-API-Key")
			if provided == "" {
				// Also accept Authorization: Bearer <key>
				if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
					provided = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			// SSE streams can't send headers — also accept ?api_key=<key>
			if provided == "" {
				provided = r.URL.Query().Get("api_key")
			}

			if provided != apiKey {
				writeError(w, http.StatusUnauthorized, "invalid or missing API key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
