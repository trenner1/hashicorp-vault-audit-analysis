// Command testgen generates synthetic Vault audit log activity and submits a
// mix of passing, failing, and hanging jobs to the vault-audit API server.
// Used to populate the dashboard with realistic data for testing/demos.
//
// Usage:
//
//	go run ./cmd/testgen [--api http://localhost:8080] [--small N] [--large N] [--hang N]
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── ANSI colours ──────────────────────────────────────────────────────────────

const (
	colReset  = "\033[0m"
	colGreen  = "\033[32m"
	colRed    = "\033[31m"
	colYellow = "\033[33m"
	colCyan   = "\033[36m"
	colGray   = "\033[90m"
	colBold   = "\033[1m"
)

func green(s string) string  { return colGreen + s + colReset }
func red(s string) string    { return colRed + s + colReset }
func yellow(s string) string { return colYellow + s + colReset }
func cyan(s string) string   { return colCyan + s + colReset }
func bold(s string) string   { return colBold + s + colReset }

// ── Log generation ────────────────────────────────────────────────────────────

type logEntry struct {
	Time     string       `json:"time"`
	Type     string       `json:"type"`
	Auth     *authBlock   `json:"auth,omitempty"`
	Request  *reqBlock    `json:"request,omitempty"`
	Response *respBlock   `json:"response,omitempty"`
	Error    *string      `json:"error,omitempty"`
}

type authBlock struct {
	Accessor    string            `json:"accessor,omitempty"`
	ClientToken string            `json:"client_token,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	EntityID    string            `json:"entity_id,omitempty"`
	TokenType   string            `json:"token_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type reqBlock struct {
	ID            string    `json:"id,omitempty"`
	Operation     string    `json:"operation,omitempty"`
	Path          string    `json:"path,omitempty"`
	MountType     string    `json:"mount_type,omitempty"`
	MountPoint    string    `json:"mount_point,omitempty"`
	Namespace     *nsBlock  `json:"namespace,omitempty"`
	RemoteAddress string    `json:"remote_address,omitempty"`
}

type nsBlock  struct{ ID string `json:"id"` }
type respBlock struct{}

var (
	entities = []struct{ id, display, accessor, ip string }{
		{"e001-web",     "kubernetes-default-web",      "hvs.ACC001", "10.0.0.10"},
		{"e002-api",     "kubernetes-prod-api",          "hvs.ACC002", "10.0.1.20"},
		{"e003-worker",  "kubernetes-default-worker",    "hvs.ACC003", "10.0.0.30"},
		{"e004-airflow", "airflow-worker",               "hvs.ACC004", "10.2.0.40"},
		{"e005-cicd",    "approle-cicd",                 "hvs.ACC005", "10.5.0.50"},
		{"e006-trevor",  "github-trevor",                "hvs.ACC006", "192.168.1.1"},
		{"e007-batch",   "kubernetes-batch-processor",   "hvs.ACC007", "10.0.2.70"},
		{"e008-svc",     "kubernetes-infra-svcmesh",     "hvs.ACC008", "10.0.3.80"},
	}

	kvPaths = []struct{ path, mount string }{
		{"kv/data/web/config",             "kv/"},
		{"kv/data/api/database",           "kv/"},
		{"kv/data/api/redis",              "kv/"},
		{"kv/data/worker/jobs",            "kv/"},
		{"kv/data/airflow/connections/pg", "kv/"},
		{"kv/data/airflow/connections/rds","kv/"},
		{"kv/data/cicd/github-token",      "kv/"},
		{"kv/data/shared/tls-cert",        "kv/"},
	}

	operations = []string{"read", "read", "read", "list", "update", "create"}
	namespaces = []string{"root", "root", "root", "ns-platform", "ns-infra"}
)

// generateLogEntries produces n request+response pairs with varied content.
func generateLogEntries(n int, startTime time.Time) []logEntry {
	entries := make([]logEntry, 0, n*2)
	rng := rand.New(rand.NewPCG(42, 0))
	t := startTime

	for i := 0; i < n; i++ {
		t = t.Add(time.Duration(rng.Intn(5000)) * time.Millisecond)

		ent := entities[rng.Intn(len(entities))]
		op := operations[rng.Intn(len(operations))]
		ns := namespaces[rng.Intn(len(namespaces))]
		reqID := fmt.Sprintf("req-%06d", i+1)

		// Pick path based on operation style
		var path, mountType, mountPoint string
		switch rng.Intn(4) {
		case 0: // token op
			tokenOps := []string{"auth/token/lookup-self", "auth/token/renew-self", "auth/token/lookup"}
			path = tokenOps[rng.Intn(len(tokenOps))]
			mountType, mountPoint = "token", "auth/token/"
			op = []string{"lookup", "update", "lookup"}[rng.Intn(3)]
		case 1: // k8s login
			path = "auth/kubernetes/login"
			mountType, mountPoint = "kubernetes", "auth/kubernetes/"
			op = "update"
		case 2: // approle login
			path = "auth/approle/login"
			mountType, mountPoint = "approle", "auth/approle/"
			op = "update"
		default: // kv
			kv := kvPaths[rng.Intn(len(kvPaths))]
			path, mountPoint = kv.path, kv.mount
			mountType = "kv"
		}

		meta := map[string]string{}
		if strings.Contains(ent.display, "kubernetes") {
			parts := strings.SplitN(ent.display, "-", 3)
			if len(parts) == 3 {
				meta["service_account_namespace"] = parts[1]
				meta["service_account_name"] = parts[2]
			}
		} else if strings.Contains(ent.display, "airflow") {
			meta["username"] = "airflow-svc"
		} else if strings.Contains(ent.display, "github") {
			meta["username"] = ent.display[len("github-"):]
		}

		auth := &authBlock{
			Accessor:    ent.accessor,
			ClientToken: "s." + ent.id[1:4],
			DisplayName: ent.display,
			EntityID:    ent.id,
			TokenType:   "service",
			Metadata:    meta,
		}
		req := &reqBlock{
			ID:            reqID,
			Operation:     op,
			Path:          path,
			MountType:     mountType,
			MountPoint:    mountPoint,
			Namespace:     &nsBlock{ID: ns},
			RemoteAddress: ent.ip,
		}

		tStr := t.UTC().Format(time.RFC3339Nano)
		entries = append(entries, logEntry{Time: tStr, Type: "request", Auth: auth, Request: req})

		t = t.Add(time.Duration(rng.Intn(200)) * time.Millisecond)
		tStr = t.UTC().Format(time.RFC3339Nano)

		// Occasionally inject an error response (≈8% of ops)
		var errStr *string
		if rng.Intn(12) == 0 {
			s := "permission denied"
			errStr = &s
		}
		entries = append(entries, logEntry{Time: tStr, Type: "response", Auth: auth, Request: req, Response: &respBlock{}, Error: errStr})
	}

	return entries
}

func encodeNDJSON(entries []logEntry) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ── API client ────────────────────────────────────────────────────────────────

type submitReq struct {
	Command    string   `json:"command"`
	Subcommand string   `json:"subcommand,omitempty"`
	Files      []string `json:"files,omitempty"`
	Args       []string `json:"args,omitempty"`
}

type jobResp struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Error   string `json:"error"`
	Command string `json:"command"`
}

type uploadResp struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
}

func uploadLog(apiBase string, name string, data []byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return "", err
	}
	if _, err = io.Copy(fw, bytes.NewReader(data)); err != nil {
		return "", err
	}
	mw.Close()

	resp, err := http.Post(apiBase+"/api/v1/ingest/upload", mw.FormDataContentType(), &buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var ur uploadResp
	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return "", err
	}
	if ur.Path == "" {
		return "", fmt.Errorf("upload returned empty path")
	}
	return ur.Path, nil
}

func submitJob(apiBase string, req submitReq) (*jobResp, error) {
	body, _ := json.Marshal(req)
	resp, err := http.Post(apiBase+"/api/v1/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jr jobResp
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, err
	}
	return &jr, nil
}

// ── Blackhole listener (for hanging jobs) ─────────────────────────────────────

// startBlackhole starts a TCP listener that accepts connections but never
// sends or closes them, simulating a network black hole.
// Returns the listener address and a stop function.
func startBlackhole() (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, red("  could not start blackhole listener: "+err.Error()))
		return "", func() {}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Accept but never respond — connection hangs
			go func(c net.Conn) { select {} }(conn) //nolint:govet
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// ── Test scenarios ────────────────────────────────────────────────────────────

type scenario struct {
	label      string
	expectPass bool // true = should succeed, false = should fail, nil-ish = hangs
	hang       bool
	req        submitReq
}

func buildScenarios(smallPath, largePath, blackholeAddr string) []scenario {
	pass := func(label, cmd, sub string, files []string, args []string) scenario {
		return scenario{label: label, expectPass: true, req: submitReq{
			Command: cmd, Subcommand: sub, Files: files, Args: args,
		}}
	}
	fail := func(label, cmd, sub string, files []string, args []string) scenario {
		return scenario{label: label, expectPass: false, req: submitReq{
			Command: cmd, Subcommand: sub, Files: files, Args: args,
		}}
	}
	hang := func(label, cmd string, args []string) scenario {
		return scenario{label: label, hang: true, req: submitReq{
			Command: cmd, Args: args,
		}}
	}

	sf := []string{smallPath} // small file
	lf := []string{largePath} // large file

	return []scenario{
		// ── Passing jobs ───────────────────────────────────────────────────────
		pass("system-overview (small)",         "system-overview",         "",          sf, []string{"--top", "5"}),
		pass("system-overview (large)",         "system-overview",         "",          lf, []string{"--top", "20"}),
		pass("path-hotspots (small)",           "path-hotspots",           "",          sf, []string{"--top", "10"}),
		pass("path-hotspots (large)",           "path-hotspots",           "",          lf, nil),
		pass("token-analysis (small)",          "token-analysis",          "",          sf, nil),
		pass("token-analysis (large)",          "token-analysis",          "",          lf, nil),
		pass("kv-analysis analyze (small)",     "kv-analysis",             "analyze",   sf, nil),
		pass("kv-analysis analyze (large)",     "kv-analysis",             "analyze",   lf, nil),
		pass("entity-analysis preprocess",      "entity-analysis",         "preprocess",sf, nil),
		pass("entity-analysis creation",        "entity-analysis",         "creation",  sf, nil),
		pass("entity-analysis gaps",            "entity-analysis",         "gaps",      sf, nil),
		pass("k8s-auth (small)",                "k8s-auth",                "",          sf, nil),
		pass("k8s-auth (large)",                "k8s-auth",                "",          lf, nil),
		pass("airflow-polling (small)",         "airflow-polling",         "",          sf, nil),
		pass("client-traffic-analysis (small)", "client-traffic-analysis", "",          sf, nil),
		pass("client-traffic-analysis (large)", "client-traffic-analysis", "",          lf, nil),

		// ── Failing jobs ───────────────────────────────────────────────────────
		fail("system-overview — no files",       "system-overview",   "",        nil, nil),
		fail("path-hotspots — bad file path",    "path-hotspots",     "",        []string{"/does/not/exist.log"}, nil),
		fail("token-analysis — no files",        "token-analysis",    "",        nil, nil),
		fail("kv-analysis — no subcommand",      "kv-analysis",       "",        sf,  nil),
		fail("kv-analysis compare — wrong args", "kv-analysis",       "compare", nil, []string{"/only-one-arg.csv"}),
		fail("entity-analysis — no files",       "entity-analysis",   "gaps",    nil, nil),
		fail("entity-analysis — bad flag value", "entity-analysis",   "gaps",    sf,  []string{"--window-seconds", "not-a-number"}),
		fail("nonexistent command",              "does-not-exist",    "",        sf,  nil),

		// ── Hanging jobs ───────────────────────────────────────────────────────
		hang("client-activity — blackhole (hang 1)",
			"client-activity",
			[]string{"--vault-addr", "http://" + blackholeAddr, "--start", "2025-01-01T00:00:00Z", "--end", "2025-01-02T00:00:00Z"},
		),
		hang("client-activity — blackhole (hang 2)",
			"client-activity",
			[]string{"--vault-addr", "http://" + blackholeAddr, "--start", "2025-06-01T00:00:00Z", "--end", "2025-06-02T00:00:00Z"},
		),
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	apiBase  := flag.String("api",        "http://localhost:8080", "API base URL")
	smallN   := flag.Int("small-entries", 500,   "entries in the small synthetic log")
	largeN   := flag.Int("large-entries", 8000,  "entries in the large synthetic log")
	delay    := flag.Duration("delay",    200*time.Millisecond, "delay between job submissions")
	flag.Parse()

	fmt.Println()
	fmt.Println(bold("╔══════════════════════════════════════════╗"))
	fmt.Println(bold("║    vault-audit API test activity gen     ║"))
	fmt.Println(bold("╚══════════════════════════════════════════╝"))
	fmt.Printf("  API: %s\n\n", cyan(*apiBase))

	// ── Health check ─────────────────────────────────────────────────────────
	fmt.Print("  Checking API health… ")
	resp, err := http.Get(*apiBase + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Println(red("UNREACHABLE"))
		fmt.Fprintln(os.Stderr, "  Is the API server running? Start it with: docker compose up")
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Println(green("OK"))
	fmt.Println()

	// ── Generate synthetic logs ───────────────────────────────────────────────
	fmt.Printf("  Generating synthetic logs…\n")

	now := time.Now().Add(-23 * time.Hour)

	smallData, _ := encodeNDJSON(generateLogEntries(*smallN, now))
	largeData, _ := encodeNDJSON(generateLogEntries(*largeN, now))

	fmt.Printf("    %s small  (%s entries, %.1f KB)\n",
		green("✓"), cyan(fmt.Sprint(*smallN)), float64(len(smallData))/1024)
	fmt.Printf("    %s large  (%s entries, %.1f KB)\n",
		green("✓"), cyan(fmt.Sprint(*largeN)), float64(len(largeData))/1024)
	fmt.Println()

	// ── Upload logs ───────────────────────────────────────────────────────────
	fmt.Printf("  Uploading to API…\n")

	smallPath, err := uploadLog(*apiBase, "testgen-small.log", smallData)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("  upload failed: "+err.Error()))
		os.Exit(1)
	}
	fmt.Printf("    %s testgen-small.log → %s\n", green("✓"), colGray+smallPath+colReset)

	largePath, err := uploadLog(*apiBase, "testgen-large.log", largeData)
	if err != nil {
		fmt.Fprintln(os.Stderr, red("  upload failed: "+err.Error()))
		os.Exit(1)
	}
	fmt.Printf("    %s testgen-large.log → %s\n", green("✓"), colGray+largePath+colReset)
	fmt.Println()

	// ── Start blackhole listener ──────────────────────────────────────────────
	bhAddr, stopBH := startBlackhole()
	defer stopBH()
	fmt.Printf("  Blackhole listener started at %s\n\n", cyan(bhAddr))

	// ── Submit scenarios ──────────────────────────────────────────────────────
	scenarios := buildScenarios(smallPath, largePath, bhAddr)

	fmt.Printf("  Submitting %s scenarios…\n\n", bold(fmt.Sprint(len(scenarios))))

	var (
		mu       sync.Mutex
		passed   int32
		failed   int32
		hanging  int32
		errored  int32
	)

	maxLabel := 0
	for _, s := range scenarios {
		if len(s.label) > maxLabel {
			maxLabel = len(s.label)
		}
	}

	for i, s := range scenarios {
		time.Sleep(*delay)

		jr, err := submitJob(*apiBase, s.req)

		mu.Lock()
		tag := ""
		switch {
		case s.hang:
			tag = yellow("⏳ HANG ")
			atomic.AddInt32(&hanging, 1)
		case err != nil:
			tag = red("✗ ERR  ")
			atomic.AddInt32(&errored, 1)
		case s.expectPass:
			tag = green("✓ PASS ")
			atomic.AddInt32(&passed, 1)
		default:
			tag = cyan("↯ FAIL ")
			atomic.AddInt32(&failed, 1)
		}

		pad := strings.Repeat(" ", maxLabel-len(s.label)+1)
		if err != nil {
			fmt.Printf("  %2d. %s %s%s— %s\n", i+1, tag, s.label, pad, red(err.Error()))
		} else {
			fmt.Printf("  %2d. %s %s%s— job %s\n", i+1, tag, s.label, pad,
				colGray+jr.ID[:8]+"…"+colReset)
		}
		mu.Unlock()
	}

	fmt.Println()
	fmt.Println(bold("  ── Summary ─────────────────────────────────────────"))
	fmt.Printf("     %s  pass      (should succeed)\n",    green(fmt.Sprintf("%3d", passed)))
	fmt.Printf("     %s  fail      (expected errors)\n",   cyan(fmt.Sprintf("%3d", failed)))
	fmt.Printf("     %s  hanging   (TCP blackhole)\n",     yellow(fmt.Sprintf("%3d", hanging)))
	if errored > 0 {
		fmt.Printf("     %s  errored   (submission error)\n", red(fmt.Sprintf("%3d", errored)))
	}
	fmt.Printf("     %s  total\n", bold(fmt.Sprintf("%3d", int(passed+failed+hanging+errored))))
	fmt.Println()
	fmt.Printf("  Open %s to see results\n", cyan("http://localhost:3000"))
	fmt.Println()

	// Keep process alive while hang jobs are running so blackhole stays up.
	if hanging > 0 {
		fmt.Printf("  %s Blackhole keeping %d job(s) running. Press Ctrl-C to stop.\n",
			yellow("⏳"), hanging)
		select {}
	}
}
