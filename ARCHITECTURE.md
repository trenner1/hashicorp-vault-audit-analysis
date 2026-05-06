# Vault Audit Platform — Architecture Plan

> **Project**: Convert `hashicorp-vault-audit-analysis` (Rust CLI) to Go, then rearchitect
> into a containerized platform with REST API, React UI, multi-cluster support, and agentic queries.

---

## Overview

This project has two distinct phases:

| Phase | Scope | Output |
|---|---|---|
| **1 — Go Port** | Feature-complete Go port of the Rust CLI | `vault-audit` Go binary (drop-in replacement) |
| **2 — Platform** | Rearchitect into containerized API + UI | Full SaaS-style platform with Docker Compose + Helm |

---

## Phase 1: Go Port

### Goals
- Drop-in behavioral replacement for the Rust `vault-audit` binary
- All 20+ commands, same flags, same output format
- Streaming parser, parallel processing, `.gz`/`.zst` decompression
- Foundation reused directly by Phase 2 without rework

### Repository Structure

```
hashicorp-vault-audit-analysis/   ← same repo, new Go implementation
├── cmd/
│   └── vault-audit/
│       └── main.go               # cobra CLI entrypoint
├── internal/
│   ├── audit/
│   │   └── types.go              # AuditEntry, AuthInfo, RequestInfo, ResponseInfo
│   ├── commands/
│   │   ├── system_overview.go
│   │   ├── path_hotspots.go
│   │   ├── entity_analysis.go    # unified: churn, creation, preprocess, gaps, timeline
│   │   ├── token_analysis.go     # unified: operations, abuse, export
│   │   ├── kv_analysis.go        # unified: analyze, compare, summary
│   │   ├── k8s_auth.go
│   │   ├── airflow_polling.go
│   │   ├── client_activity.go
│   │   ├── client_traffic_analysis.go
│   │   ├── entity_list.go
│   │   ├── kv_mounts.go
│   │   └── auth_mounts.go
│   ├── processor/
│   │   ├── processor.go          # FileProcessor (streaming, parallel/sequential)
│   │   ├── parallel.go           # worker pool (replaces Rayon)
│   │   └── progress.go           # progress bar (progressbar/v3 or similar)
│   ├── reader/
│   │   └── reader.go             # open_file() with gz/zst auto-detection
│   ├── vault/
│   │   └── client.go             # VaultClient (LIST, GET, GET text)
│   └── utils/
│       ├── format.go             # format_number()
│       └── time.go               # parse_timestamp(), duration_human()
├── tests/
│   ├── audit_types_test.go
│   ├── processor_test.go
│   ├── reader_test.go
│   └── integration_test.go
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

### Key Rust → Go Mappings

| Rust | Go |
|---|---|
| `clap` (derive) | `github.com/spf13/cobra` |
| `serde` / `serde_json` | `encoding/json` (stdlib) |
| `rayon` (par_iter) | goroutine worker pool + `sync.WaitGroup` / `errgroup` |
| `reqwest` (async) | `net/http` (stdlib) |
| `tokio` | Not needed — Go HTTP is sync-friendly |
| `flate2` | `compress/gzip` (stdlib) |
| `zstd` | `github.com/klauspost/compress/zstd` |
| `indicatif` | `github.com/schollz/progressbar/v3` |
| `chrono` | `time` (stdlib) |
| `anyhow` / `thiserror` | `fmt.Errorf` + `errors.As` |
| `csv` | `encoding/csv` (stdlib) |
| `Arc<Mutex<T>>` | `sync.Mutex` + pointer |
| `Arc<AtomicUsize>` | `sync/atomic.Uint64` |
| `Box<dyn Read + Send>` | `io.Reader` interface |

### Parallel Processing Design (replacing Rayon)

```go
// processor/parallel.go
type WorkerPool struct {
    numWorkers int
    jobs       chan job
    wg         sync.WaitGroup
}

// For each file: launch goroutine, stream line-by-line via bufio.Scanner,
// parse JSON into AuditEntry, call user-supplied processor func.
// Results aggregated via mutex-protected accumulator.
```

The `FileProcessor.process_files_streaming()` pattern maps cleanly:
- Single file → sequential (no goroutines)
- Multiple files → one goroutine per file (up to `runtime.NumCPU()`)
- Progress: shared `atomic.Uint64` counter + mutex-protected progress bar

### Go Module

```
module github.com/trenner1/hashicorp-vault-audit-analysis

go 1.22

require (
    github.com/spf13/cobra          v1.8.x
    github.com/klauspost/compress   v1.17.x
    github.com/schollz/progressbar/v3 v3.14.x
)
```

---

## Phase 2: Containerized Platform

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                               │
│              React + TypeScript UI (Vite)                    │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP / SSE
┌───────────────────────────▼─────────────────────────────────┐
│                   Go REST API Server                         │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  Analysis  │  │  Cluster     │  │  Agentic Query       │ │
│  │  Engine    │  │  Registry    │  │  Engine (NL → cmd)   │ │
│  └─────┬──────┘  └──────┬───────┘  └──────────────────────┘ │
│        │                │                                     │
│  ┌─────▼──────┐  ┌──────▼───────┐  ┌──────────────────────┐ │
│  │  Job Queue │  │  Vault API   │  │  Log Ingestion       │ │
│  │  (in-mem   │  │  Client      │  │  (S3/GCS/Azure/      │ │
│  │  or Redis) │  │              │  │   upload)            │ │
│  └────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    PostgreSQL          Redis           Object Storage
  (config, jobs,    (job queue,     (S3/GCS/MinIO for
   results cache)    pub/sub)        uploaded logs)
```

### New Repository Structure

```
vault-audit-platform/
├── backend/
│   ├── cmd/
│   │   └── server/
│   │       └── main.go
│   ├── internal/
│   │   ├── api/
│   │   │   ├── router.go             # chi or gin router
│   │   │   ├── middleware.go         # auth, CORS, logging
│   │   │   ├── handlers/
│   │   │   │   ├── analysis.go       # POST /api/v1/analysis/run
│   │   │   │   ├── clusters.go       # CRUD /api/v1/clusters
│   │   │   │   ├── jobs.go           # GET /api/v1/jobs/{id}
│   │   │   │   ├── logs.go           # POST /api/v1/logs/upload
│   │   │   │   ├── agent.go          # POST /api/v1/agent/query
│   │   │   │   └── metrics.go        # GET /api/v1/metrics/*
│   │   │   └── sse.go                # Server-Sent Events for job progress
│   │   ├── analysis/                 # Ported from Phase 1 (reused as-is)
│   │   │   ├── engine.go             # Wraps all commands as callable functions
│   │   │   └── commands/             # All command implementations
│   │   ├── cluster/
│   │   │   ├── registry.go           # Multi-cluster config store
│   │   │   └── vault_client.go       # Per-cluster VaultClient
│   │   ├── agent/
│   │   │   ├── query_engine.go       # NL → analysis command mapper
│   │   │   ├── llm_client.go         # Claude/OpenAI API client
│   │   │   └── prompts.go            # System prompts for command mapping
│   │   ├── jobs/
│   │   │   ├── queue.go              # Job queue (in-memory or Redis)
│   │   │   ├── runner.go             # Async job execution
│   │   │   └── store.go              # Job result persistence
│   │   ├── ingestion/
│   │   │   ├── s3.go                 # AWS S3 log fetching
│   │   │   ├── gcs.go                # Google Cloud Storage
│   │   │   ├── azure.go              # Azure Blob Storage
│   │   │   └── upload.go             # Multipart upload handler
│   │   ├── storage/
│   │   │   ├── postgres.go           # PostgreSQL (cluster config, jobs, results)
│   │   │   └── migrations/           # SQL migration files
│   │   └── config/
│   │       └── config.go             # Env-based config (viper)
│   ├── go.mod
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── api/                      # Typed API client (fetch + SSE)
│   │   ├── components/
│   │   │   ├── ClusterMap/           # Visual cluster + namespace topology
│   │   │   ├── AnalysisRunner/       # Command form + streaming results
│   │   │   ├── MetricsDashboard/     # Charts, KPIs, trends
│   │   │   ├── AgentChat/            # Natural language query UI
│   │   │   └── JobProgress/          # SSE-driven progress display
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Clusters.tsx
│   │   │   ├── Analysis.tsx
│   │   │   ├── Agent.tsx
│   │   │   └── Settings.tsx
│   │   ├── store/                    # Zustand or React Query
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── Dockerfile
│
├── deployments/
│   ├── docker-compose.yml            # Local dev: API + UI + Postgres + Redis + MinIO
│   ├── docker-compose.override.yml   # Dev overrides (hot reload, debug ports)
│   └── k8s/
│       └── helm/
│           └── vault-audit-platform/
│               ├── Chart.yaml
│               ├── values.yaml
│               ├── values.prod.yaml
│               └── templates/
│                   ├── deployment-backend.yaml
│                   ├── deployment-frontend.yaml
│                   ├── service.yaml
│                   ├── ingress.yaml
│                   ├── configmap.yaml
│                   ├── secret.yaml
│                   └── pvc.yaml
│
├── scripts/
│   ├── dev.sh                        # Start local dev stack
│   └── migrate.sh                    # Run DB migrations
│
└── Makefile
```

---

## REST API Design

### Base URL: `/api/v1`

#### Cluster Registry

```
GET    /clusters                      List all registered clusters
POST   /clusters                      Register a new cluster
GET    /clusters/{id}                 Get cluster details + connection status
PUT    /clusters/{id}                 Update cluster config
DELETE /clusters/{id}                 Remove cluster
GET    /clusters/{id}/namespaces      List namespaces for a cluster
GET    /clusters/{id}/health          Check Vault connectivity
```

#### Analysis

```
POST   /analysis/run                  Submit an analysis job
  Body: { cluster_id, command, args, log_source }
  Returns: { job_id }

GET    /analysis/commands             List all available commands + their parameters
GET    /analysis/results/{job_id}     Get completed analysis results
GET    /analysis/stream/{job_id}      SSE stream: real-time progress + partial results
```

#### Log Management

```
POST   /logs/upload                   Upload a log file (multipart)
GET    /logs/sources                  List configured S3/GCS/Azure sources
POST   /logs/sources                  Add a cloud log source
GET    /logs/sources/{id}/files       List available log files in a source
```

#### Jobs

```
GET    /jobs                          List recent jobs (paginated)
GET    /jobs/{id}                     Get job status + result
DELETE /jobs/{id}                     Cancel a running job
```

#### Agentic Queries

```
POST   /agent/query                   Submit a natural language query
  Body: { question, cluster_id?, context? }
  Returns: { interpretation, command, args, job_id }

GET    /agent/history                 List past queries + their interpretations
```

#### Metrics & Dashboard

```
GET    /metrics/summary               Cross-cluster summary (entity counts, op rates)
GET    /metrics/clusters/{id}         Per-cluster metrics
GET    /metrics/clusters/{id}/namespaces/{ns}  Per-namespace metrics
GET    /metrics/trends                Time-series data for charts
```

---

## Data Model (PostgreSQL)

```sql
-- Cluster registry
CREATE TABLE clusters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    vault_addr  TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Per-cluster namespace config
CREATE TABLE cluster_namespaces (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id  UUID REFERENCES clusters(id) ON DELETE CASCADE,
    namespace   TEXT NOT NULL,
    label       TEXT,
    UNIQUE(cluster_id, namespace)
);

-- Cluster credentials (encrypted at rest)
CREATE TABLE cluster_credentials (
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE PRIMARY KEY,
    vault_token     BYTEA,          -- encrypted
    token_file_path TEXT,
    skip_tls_verify BOOLEAN DEFAULT FALSE,
    cacert          BYTEA
);

-- Log sources (S3/GCS/Azure)
CREATE TABLE log_sources (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id  UUID REFERENCES clusters(id),
    provider    TEXT NOT NULL,      -- 's3', 'gcs', 'azure'
    config      JSONB NOT NULL,     -- bucket, prefix, region, credentials ref
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis jobs
CREATE TABLE jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id  UUID REFERENCES clusters(id),
    command     TEXT NOT NULL,
    args        JSONB,
    status      TEXT DEFAULT 'pending',   -- pending, running, completed, failed
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Analysis results (chunked for large outputs)
CREATE TABLE job_results (
    job_id      UUID REFERENCES jobs(id) ON DELETE CASCADE,
    chunk_idx   INT NOT NULL,
    content     JSONB,
    PRIMARY KEY (job_id, chunk_idx)
);

-- Agent query history
CREATE TABLE agent_queries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    question        TEXT NOT NULL,
    interpretation  TEXT,
    command         TEXT,
    args            JSONB,
    job_id          UUID REFERENCES jobs(id),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Agentic Query Engine

### How It Works

```
User: "Which entities accessed kv/prod/* last week with errors?"
                    │
                    ▼
         LLM (Claude API) with system prompt:
         "You are a Vault audit analysis assistant.
          Map the user's question to one of these commands: [...]
          Return JSON: { command, args }"
                    │
                    ▼
         { command: "kv-analysis analyze",
           args: { kv_prefix: "kv/prod/", date_range: "last_7_days", ... } }
                    │
                    ▼
         Analysis Engine → Job Queue → SSE stream to UI
                    │
                    ▼
         Results + LLM-generated human-readable summary
```

### System Prompt Structure

The LLM system prompt includes:
- Full list of available commands and their parameters
- Example query → command mappings
- Instructions to extract date ranges, entity filters, cluster context
- Output schema (strict JSON)

---

## UI Pages

### Dashboard
- Total entities, operations, error rate across all clusters
- Sparkline trends (7d, 30d)
- Active job queue status
- Recent anomaly alerts

### Cluster Map
- Visual list/grid of all registered Vault clusters
- Per-cluster: namespace count, connection status (green/yellow/red), last analyzed
- Drill-down: namespace list with per-namespace metrics
- Side-by-side cluster comparison

### Analysis
- Command selector (dropdown with all 20+ commands)
- Dynamic form (parameters auto-populate from command schema)
- Cluster + log source selector
- Live streaming progress bar (SSE)
- Results panel: tables, charts, CSV export button

### Agent (Natural Language)
- Chat interface
- "Which services had the most token lookups this week?"
- Shows interpreted command before running
- Returns answer + link to full analysis results

### Settings
- Cluster registry (add/edit/remove)
- Log source configuration (S3/GCS/Azure credentials)
- API keys (for LLM provider)
- User management (optional, future)

---

## Docker Compose (Local Dev)

```yaml
services:
  backend:
    build: ./backend
    ports: ["8080:8080"]
    environment:
      - DATABASE_URL=postgres://vault:vault@postgres:5432/vault_audit
      - REDIS_URL=redis://redis:6379
      - MINIO_ENDPOINT=http://minio:9000
    depends_on: [postgres, redis, minio]

  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      - VITE_API_BASE_URL=http://localhost:8080

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: vault_audit
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: vault
    volumes: [postgres_data:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    ports: ["9000:9000", "9001:9001"]
    volumes: [minio_data:/data]

volumes:
  postgres_data:
  minio_data:
```

---

## Development Phases & Milestones

### Phase 1 — Go Port (CLI parity)
1. `internal/audit/types.go` — core data model
2. `internal/reader/` — file reader with compression
3. `internal/processor/` — streaming + parallel engine
4. `internal/vault/client.go` — Vault API client
5. `internal/utils/` — format, time helpers
6. Commands (in priority order):
   - `system-overview`
   - `entity-analysis` (all subcommands)
   - `token-analysis`
   - `kv-analysis` (all subcommands)
   - `k8s-auth`, `path-hotspots`, `airflow-polling`
   - `client-activity`, `entity-list`, `kv-mounts`, `auth-mounts`
   - `client-traffic-analysis`
   - Deprecated command shims
7. `cmd/vault-audit/main.go` — cobra CLI
8. Tests (unit + integration)

### Phase 2 — API Server
1. Add `backend/cmd/server/` entrypoint
2. Wrap analysis commands as callable engine functions
3. Add job queue + SSE streaming
4. Add cluster registry + PostgreSQL storage
5. Add log ingestion (S3/GCS/Azure/upload)
6. REST API handlers
7. Agentic query engine

### Phase 3 — Frontend
1. Vite + React + TypeScript scaffold
2. API client layer
3. Dashboard page
4. Cluster map page
5. Analysis runner page
6. Agent chat page
7. Settings page

### Phase 4 — Deployment
1. Dockerfiles (backend + frontend)
2. Docker Compose (local dev + prod)
3. Helm chart (K8s)
4. CI/CD (GitHub Actions)

---

## Technology Decisions Summary

| Concern | Choice | Rationale |
|---|---|---|
| Language | Go 1.22 | Performance, stdlib richness, single binary deployment |
| CLI framework | cobra | Industry standard, matches clap's UX |
| HTTP router | chi | Lightweight, idiomatic, stdlib-compatible |
| ORM/DB | pgx v5 + sqlc | Type-safe, no runtime reflection |
| Job queue | Redis (prod) / in-memory (dev) | Simple, reliable, supports pub/sub for SSE |
| UI framework | React 18 + TypeScript | Broad ecosystem, Vite for fast dev |
| State management | TanStack Query | Server state, cache, background refetch |
| Charts | Recharts | React-native, good for time-series |
| Topology viz | Reactflow | Cluster/namespace graph view |
| LLM provider | Claude API (Anthropic) | Best instruction-following for structured JSON output |
| Container | Docker + Compose + Helm | Standard K8s deployment path |
| DB migrations | golang-migrate | CLI + library, supports embedded migrations |
