package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Anthropic wire types ──────────────────────────────────────────────────────

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// ── Public request / response types ──────────────────────────────────────────

// QueryRequest is the body for POST /api/v1/query.
type QueryRequest struct {
	Question  string   `json:"question"`
	Files     []string `json:"files,omitempty"`
	ClusterID string   `json:"cluster_id,omitempty"`
}

// QueryResponse is returned after a successful query interpretation.
type QueryResponse struct {
	JobID      string   `json:"job_id"`
	Command    string   `json:"command"`
	Subcommand string   `json:"subcommand,omitempty"`
	Args       []string `json:"args"`
	Reasoning  string   `json:"reasoning"`
}

// ── LLM command selection ─────────────────────────────────────────────────────

const systemPrompt = `You are a command selector for the vault-audit CLI tool, which analyzes HashiCorp Vault audit logs.

Given a natural-language question, return ONLY a JSON object (no markdown, no explanation outside the JSON) describing the single best vault-audit command to run.

AVAILABLE COMMANDS
Log-analysis commands (require log files):
  system-overview        High-level overview: top operations, entities, auth methods, namespaces.
                         Args: --top N, --min-operations N
  path-hotspots          Most-accessed paths with optimization recommendations.
                         Args: --top N
  token-analysis         Token lifecycle, abuse detection, CSV export.
                         Args: --abuse-threshold N, --filter "lookup,create,renew,revoke,login", --export file.csv, --min-operations N
  kv-analysis analyze    KV secrets usage breakdown by path and entity.
                         Args: --kv-prefix "kv/", --output file.csv
  kv-analysis compare    Compare KV usage between two CSV exports (needs 2 files).
  kv-analysis summary    Summarise KV CSV export.
  entity-analysis preprocess   Extract entity-ID→name mappings from logs.
  entity-analysis creation     Which auth paths are creating entities.
  entity-analysis churn        Multi-day entity lifecycle (ephemeral detection). Needs 2+ files.
  entity-analysis gaps         Detect inactivity gaps for entities. Args: --window-seconds N
  entity-analysis timeline     Full operation timeline for one entity. Args: --entity-id <id>
  k8s-auth               Kubernetes/OpenShift auth patterns and entity churn.
  airflow-polling        Airflow secret-polling burst detection.
  client-traffic-analysis  Client traffic patterns, error rates, top clients.
                         Args: --top N, --temporal, --show-errors

Vault API commands (no log files needed, query live cluster):
  client-activity        Client activity metrics by mount. Args: --vault-addr, --start, --end (RFC3339)
  entity-list            List entities and aliases. Args: --vault-addr, --format csv|json
  kv-mounts              List KV mounts and paths. Args: --vault-addr
  auth-mounts            List authentication mounts. Args: --vault-addr

RULES
1. Choose the single most relevant command for the question.
2. If the question is about tokens/lookups → token-analysis.
3. If about secrets/KV → kv-analysis analyze.
4. If about who is accessing what overall → system-overview.
5. If about entity creation or lifecycle → entity-analysis creation or churn.
6. If about K8s service accounts → k8s-auth.
7. If about Airflow → airflow-polling.
8. Include --abuse-threshold only when the question mentions abuse, suspicious, or excessive.
9. For timeline, you MUST include --entity-id only if an ID was given; otherwise use entity-analysis creation.
10. Omit flags that weren't asked for.

RESPONSE FORMAT — return ONLY this JSON, no other text:
{
  "command": "command-name",
  "subcommand": "subcommand-or-empty-string",
  "args": ["--flag", "value"],
  "reasoning": "one sentence explaining the choice"
}`

// llmSelectCommand calls the Anthropic Messages API and returns a parsed command selection.
func llmSelectCommand(ctx context.Context, apiKey, question string) (cmd, sub string, args []string, reasoning string, err error) {
	reqBody := anthropicRequest{
		Model:     "claude-haiku-4-5-20251001",
		MaxTokens: 512,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: question},
		},
	}

	body, _ := json.Marshal(reqBody)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", "", nil, "", fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", "", nil, "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	var ar anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", "", nil, "", fmt.Errorf("decode response: %w", err)
	}
	if ar.Error != nil {
		return "", "", nil, "", fmt.Errorf("anthropic error: %s", ar.Error.Message)
	}
	if len(ar.Content) == 0 {
		return "", "", nil, "", fmt.Errorf("empty response from model")
	}

	text := strings.TrimSpace(ar.Content[0].Text)

	// Strip any accidental markdown fences.
	if strings.HasPrefix(text, "```") {
		if idx := strings.Index(text, "\n"); idx != -1 {
			text = text[idx+1:]
		}
		text = strings.TrimSuffix(strings.TrimSpace(text), "```")
	}

	var parsed struct {
		Command    string   `json:"command"`
		Subcommand string   `json:"subcommand"`
		Args       []string `json:"args"`
		Reasoning  string   `json:"reasoning"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return "", "", nil, "", fmt.Errorf("parse model JSON (%q): %w", text, err)
	}
	if parsed.Command == "" {
		return "", "", nil, "", fmt.Errorf("model returned empty command")
	}
	if parsed.Args == nil {
		parsed.Args = []string{}
	}

	return parsed.Command, parsed.Subcommand, parsed.Args, parsed.Reasoning, nil
}

// ── LLM summarization ────────────────────────────────────────────────────────

const summarizeSystemPrompt = `You are an expert HashiCorp Vault security analyst.
You will be given the output of a vault-audit CLI command and, optionally, the original question that triggered it.
Write a concise, structured summary (4-8 sentences) in plain English aimed at a platform engineer.
Focus on: what the data shows, any anomalies or risks, and one or two concrete recommendations.
Do not repeat the raw numbers verbatim — synthesise them into insights.`

// llmSummarize sends job output to the model and returns a plain-text summary.
func llmSummarize(ctx context.Context, apiKey, command, question, output string) (string, error) {
	userMsg := fmt.Sprintf("Command: %s\n", command)
	if question != "" {
		userMsg += fmt.Sprintf("Original question: %s\n", question)
	}
	userMsg += fmt.Sprintf("\nOutput:\n%s", output)

	reqBody := anthropicRequest{
		Model:     "claude-haiku-4-5-20251001",
		MaxTokens: 1024,
		System:    summarizeSystemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: userMsg}},
	}

	body, _ := json.Marshal(reqBody)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	var ar anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if ar.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", ar.Error.Message)
	}
	if len(ar.Content) == 0 {
		return "", fmt.Errorf("empty response from model")
	}
	return strings.TrimSpace(ar.Content[0].Text), nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// handleSummarizeJob summarizes a completed job's output using Claude.
// POST /api/v1/jobs/{id}/summarize  body: { "question": "optional original question" }
func (s *Server) handleSummarizeJob(w http.ResponseWriter, r *http.Request) {
	if s.anthropicKey == "" {
		writeError(w, http.StatusServiceUnavailable,
			"summarization requires ANTHROPIC_API_KEY to be set")
		return
	}

	id := chi.URLParam(r, "id")
	job, ok := s.queue.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != "done" && job.Status != "error" {
		writeError(w, http.StatusBadRequest, "job has not completed yet")
		return
	}

	var req struct {
		Question string `json:"question"`
	}
	// Ignore decode errors — question is optional.
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	output := strings.Join(job.Output, "\n")
	// Truncate very large outputs to keep token cost low.
	const maxChars = 40_000
	if len(output) > maxChars {
		output = output[:maxChars] + "\n... (output truncated)"
	}
	if output == "" {
		output = "(no output)"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	summary, err := llmSummarize(ctx, s.anthropicKey, job.Command, req.Question, output)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "summarization failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"summary": summary})
}

// handleQuery interprets a natural-language question, selects the best
// vault-audit command via the Anthropic API, submits a job, and returns
// the job ID alongside the model's reasoning.
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if s.anthropicKey == "" {
		writeError(w, http.StatusServiceUnavailable,
			"agentic queries require ANTHROPIC_API_KEY to be set")
		return
	}

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Question) == "" {
		writeError(w, http.StatusBadRequest, "question is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	cmd, sub, args, reasoning, err := llmSelectCommand(ctx, s.anthropicKey, req.Question)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query interpretation failed: "+err.Error())
		return
	}

	// Build full arg list: [subcommand] [files...] [llm-args...] [--vault-addr if cluster given]
	allArgs := []string{}
	if sub != "" {
		allArgs = append(allArgs, sub)
	}
	allArgs = append(allArgs, req.Files...)
	allArgs = append(allArgs, args...)

	// Inject cluster flags (--vault-addr, --token, --namespace) when a cluster is selected.
	if req.ClusterID != "" {
		s.clustersMu.RLock()
		cluster, ok := s.clusters[req.ClusterID]
		s.clustersMu.RUnlock()
		if ok {
			allArgs = injectClusterArgs(allArgs, cluster)
		}
	}

	job := s.queue.Submit(cmd, allArgs)

	writeJSON(w, http.StatusAccepted, QueryResponse{
		JobID:      job.ID,
		Command:    cmd,
		Subcommand: sub,
		Args:       args,
		Reasoning:  reasoning,
	})
}
