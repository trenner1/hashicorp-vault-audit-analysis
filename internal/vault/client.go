// Package vault provides an HTTP client for the HashiCorp Vault API.
//
// The client respects standard Vault environment variables:
//   - VAULT_ADDR        – server address (default: http://127.0.0.1:8200)
//   - VAULT_TOKEN       – authentication token
//   - VAULT_TOKEN_FILE  – path to file containing the token
//   - VAULT_NAMESPACE   – Vault namespace (Enterprise)
//   - VAULT_SKIP_VERIFY – skip TLS certificate verification ("1", "true", "yes")
//   - VAULT_CACERT      – path to CA certificate (not yet implemented)
package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client wraps net/http.Client with Vault-specific auth headers.
type Client struct {
	addr      string
	token     string
	namespace string
	http      *http.Client
}

// Options controls Client creation.
type Options struct {
	Addr       string // Vault server address
	Token      string // Vault token
	Namespace  string // Vault namespace (may be empty)
	SkipVerify bool   // disable TLS certificate verification
}

// NewFromOptions creates a Client from explicit options.
// Empty string options fall back to environment variables.
func NewFromOptions(opts Options) (*Client, error) {
	addr := firstNonEmpty(opts.Addr, os.Getenv("VAULT_ADDR"), "http://127.0.0.1:8200")
	ns := firstNonEmpty(opts.Namespace, os.Getenv("VAULT_NAMESPACE"))

	token := opts.Token
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		if tf := os.Getenv("VAULT_TOKEN_FILE"); tf != "" {
			b, err := os.ReadFile(tf)
			if err != nil {
				return nil, fmt.Errorf("read VAULT_TOKEN_FILE %s: %w", tf, err)
			}
			token = strings.TrimSpace(string(b))
		}
	}
	if token == "" {
		return nil, fmt.Errorf(
			"Vault token is required — provide via --vault-token, VAULT_TOKEN, or VAULT_TOKEN_FILE")
	}

	skipVerify := opts.SkipVerify || shouldSkipVerify()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ //nolint:gosec
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	return &Client{
		addr:      strings.TrimRight(addr, "/"),
		token:     token,
		namespace: ns,
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: transport,
		},
	}, nil
}

// Addr returns the configured Vault address.
func (c *Client) Addr() string { return c.addr }

// ---------- HTTP helpers ----------

// Get performs a GET to the given Vault API path and decodes JSON into out.
func (c *Client) Get(path string, out interface{}) error {
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// GetRaw performs a GET and returns the raw response body text.
// Used for NDJSON endpoints like sys/internal/counters/activity/export.
func (c *Client) GetRaw(path string) (string, error) {
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body from %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET %s returned %d: %s", path, resp.StatusCode, body)
	}
	return string(body), nil
}

// List performs a Vault LIST request (custom HTTP method) and decodes JSON into out.
func (c *Client) List(path string, out interface{}) error {
	req, err := c.newRequest("LIST", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

// ---------- Internal ----------

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	url := c.addr + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, url, err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *Client) do(req *http.Request, out interface{}) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body from %s: %w", req.URL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL, resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode response from %s: %w", req.URL, err)
		}
	}
	return nil
}

// ExtractData extracts the "data" field from a standard Vault API response envelope
// and unmarshals it into out.
func ExtractData(envelope map[string]json.RawMessage, out interface{}) error {
	raw, ok := envelope["data"]
	if !ok {
		return fmt.Errorf("no 'data' field in Vault response")
	}
	return json.Unmarshal(raw, out)
}

// ---------- Environment helpers ----------

func shouldSkipVerify() bool {
	v := strings.ToLower(os.Getenv("VAULT_SKIP_VERIFY"))
	return v == "1" || v == "true" || v == "yes"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
