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
	h := authMiddleware(func() string { return "" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("disabled auth: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_HealthzAlwaysAllowed(t *testing.T) {
	h := authMiddleware(func() string { return "secret" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/healthz without key: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_XAPIKeyHeader(t *testing.T) {
	h := authMiddleware(func() string { return "mysecret" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("X-API-Key", "mysecret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("X-API-Key: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_BearerToken(t *testing.T) {
	h := authMiddleware(func() string { return "tok" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Bearer: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_QueryParam(t *testing.T) {
	h := authMiddleware(func() string { return "qkey" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/abc/stream?api_key=qkey", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("query param: got %d, want 200", rr.Code)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	h := authMiddleware(func() string { return "secret" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("missing key: got %d, want 401", rr.Code)
	}
}

func TestAuthMiddleware_WrongKey(t *testing.T) {
	h := authMiddleware(func() string { return "correct" })(okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("X-API-Key", "wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: got %d, want 401", rr.Code)
	}
}

// TestAuthMiddleware_DynamicKey verifies that changing the key after middleware
// construction is reflected on the next request (the fix for the static-capture bug).
func TestAuthMiddleware_DynamicKey(t *testing.T) {
	key := ""
	h := authMiddleware(func() string { return key })(okHandler)

	// Initially no key set → auth disabled, request passes.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("before SetAPIKey: got %d, want 200", rr.Code)
	}

	// Simulate SetAPIKey being called after route setup.
	key = "latekey"

	// Now the same handler should require the key.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("after SetAPIKey (no creds): got %d, want 401", rr2.Code)
	}

	// And accept the correct key.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	req3.Header.Set("X-API-Key", "latekey")
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("after SetAPIKey (correct key): got %d, want 200", rr3.Code)
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
