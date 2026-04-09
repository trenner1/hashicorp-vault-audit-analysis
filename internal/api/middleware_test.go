package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler returns 200 OK for any request.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// ── authMiddleware ────────────────────────────────────────────────────────────

func TestAuthMiddleware_Disabled(t *testing.T) {
	// Empty apiKey = auth disabled, all requests pass through.
	h := authMiddleware("")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("disabled auth: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_HealthzAlwaysAllowed(t *testing.T) {
	h := authMiddleware("secret")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/healthz without key: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_XAPIKeyHeader(t *testing.T) {
	h := authMiddleware("mysecret")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("X-API-Key", "mysecret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("X-API-Key: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_BearerToken(t *testing.T) {
	h := authMiddleware("tok")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Bearer: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_QueryParam(t *testing.T) {
	h := authMiddleware("qkey")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/abc/stream?api_key=qkey", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("query param: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	h := authMiddleware("secret")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing key: got %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	h := authMiddleware("correct")(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("X-API-Key", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d, want 401", rr.Code)
	}
}

// ── corsMiddleware ────────────────────────────────────────────────────────────

func TestCORSMiddleware_SetsHeaders(t *testing.T) {
	h := corsMiddleware(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("Allow-Origin = %q, want http://localhost:3000", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods header missing")
	}
}

func TestCORSMiddleware_Options(t *testing.T) {
	h := corsMiddleware(okHandler)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("OPTIONS: got %d, want 200", rr.Code)
	}
}
