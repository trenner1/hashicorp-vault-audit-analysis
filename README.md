# Vault Audit Analysis Tools

[![CI](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml)
[![codecov](https://codecov.io/github/trenner1/hashicorp-vault-audit-analysis/graph/badge.svg?token=QYMT1SKDQ6)](https://codecov.io/github/trenner1/hashicorp-vault-audit-analysis)

Comprehensive tools for analyzing HashiCorp Vault audit logs with both CLI and web UI interfaces.

## Features

### Dual Interface
- **CLI Tool** (`vault-audit`): Fast command-line analysis for automation and scripting
- **Web UI** (`vault-audit-server`): Interactive dashboard for visual analysis and exploration
- **Unified Architecture**: Both interfaces share the same analysis engine

### Analysis Capabilities
- **System Overview**: High-level metrics across all operations, entities, and auth methods
- **Entity Analysis**: Track entity lifecycle, creation patterns, churn, and activity gaps
- **Token Analysis**: Monitor token operations, detect abuse patterns, export detailed metrics
- **KV Secrets**: Analyze secret usage patterns, compare time periods, generate summaries
- **Authentication**: Analyze Kubernetes/OpenShift auth patterns, Airflow polling behavior
- **Path Analysis**: Identify hotspots and optimization opportunities
- **Vault API Integration**: Query live Vault clusters for entity lists, client activity, mount enumeration

### Performance
- **Parallel Processing**: Automatically uses all CPU cores for multi-file analysis
- **Streaming Parser**: Memory-efficient processing of large audit logs
- **Compressed File Support**: Direct analysis of `.gz` and `.zst` files
- **Multi-File Support**: Analyze weeks/months of logs without manual concatenation

### Web UI Features
- **Interactive Dashboard**: Real-time job execution with progress tracking
- **File Management**: Upload audit logs, browse analysis artifacts with metadata
- **Cluster Management**: Connect to live Vault clusters for API-based analysis
- **Dark Mode**: Full dark mode support with accessible contrast
- **Job History**: Track all analysis jobs with detailed output and CLI command display

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/trenner1/hashicorp-vault-audit-analysis.git
cd hashicorp-vault-audit-analysis

# Start the services
docker-compose up -d

# Access the web UI
open http://localhost:3000
```

The web UI will be available at `http://localhost:3000` with the API server at `http://localhost:8080`.

### Building from Source

#### Prerequisites
- Go 1.23 or later
- Node.js 18+ and npm (for frontend)
- Make

#### Build CLI Tool

```bash
make build
# Binary will be at ./build/vault-audit
```

#### Build API Server

```bash
make server
# Binary will be at ./server
```

#### Build Frontend

```bash
cd frontend
npm install
npm run build
# Production build will be in frontend/dist/
```

## CLI Usage

### Basic Commands

```bash
# System overview
vault-audit system-overview audit.log

# Entity analysis
vault-audit entity-analysis churn day1.log day2.log day3.log
vault-audit entity-analysis creation audit.log
vault-audit entity-analysis timeline --entity-id <UUID> audit.log

# Token analysis
vault-audit token-analysis audit.log
vault-audit token-analysis audit.log --export tokens.csv

# KV secrets analysis
vault-audit kv-analysis analyze audit.log --output kv_usage.csv
vault-audit kv-analysis compare old.csv new.csv
vault-audit kv-analysis summary usage.csv

# Path hotspots
vault-audit path-hotspots audit.log

# Authentication analysis
vault-audit k8s-auth audit.log
vault-audit airflow-polling audit.log
```

### Vault API Commands

Connect to live Vault clusters for real-time analysis:

```bash
# List all entities
vault-audit entity-list --vault-addr https://vault.example.com --vault-token hvs.xxx

# Query client activity
vault-audit client-activity --start 2025-10-01T00:00:00Z --end 2025-10-31T23:59:59Z

# Enumerate KV mounts with full tree structure
vault-audit kv-mounts --format stdout
vault-audit kv-mounts --depth 0 --format csv  # Mounts only
vault-audit kv-mounts --format json --output kv-tree.json

# Enumerate auth mounts with roles and metadata
vault-audit auth-mounts --format stdout
vault-audit auth-mounts --depth 1 --format json  # Include roles with metadata
vault-audit auth-mounts --depth 0 --format csv   # Mounts only
```

### Multi-File and Compressed File Support

```bash
# Analyze compressed files directly
vault-audit system-overview audit.log.gz

# Multiple files (automatic parallel processing)
vault-audit entity-analysis churn day1.log day2.log day3.log

# Glob patterns
vault-audit path-hotspots logs/*.log.gz

# Mix compressed and uncompressed
vault-audit token-analysis day1.log.gz day2.log day3.log.zst
```

## Web UI Usage

### Getting Started

1. **Upload Audit Logs**: Navigate to Files page and upload your audit log files
2. **Configure Clusters** (optional): Add Vault cluster connections for API-based analysis
3. **Run Analysis**: Go to Analysis page, select command and files, click Run
4. **View Results**: Monitor progress in real-time, view output, download artifacts

### Key Features

#### Dashboard
- System metrics and recent activity
- Quick access to common operations
- Job status overview

#### Analysis Page
- Select from 16+ analysis commands
- Interactive file picker with metadata preview
- Real-time progress tracking with SSE
- CLI command display for reproducibility
- Download generated artifacts

#### Files Page
- **Uploaded Files**: Manage audit log uploads
- **Analysis Artifacts**: Browse generated reports with metadata
- Timestamped outputs with command metadata
- Download and delete operations

#### Clusters Page
- Manage Vault cluster connections
- Test connectivity
- Use for API-based commands (entity-list, client-activity, kv-mounts, auth-mounts)

#### Jobs Page
- View all analysis jobs
- Real-time progress updates
- Detailed output with syntax highlighting
- Rerun previous jobs
- CLI command for manual execution

## Architecture

### CLI Tool (`vault-audit`)
- Standalone binary for command-line usage
- Fast, memory-efficient streaming parser
- Parallel processing for multi-file workloads
- Supports all analysis commands

### API Server (`vault-audit-server`)
- RESTful API wrapping CLI functionality
- Job queue with persistent storage
- Server-Sent Events (SSE) for real-time progress
- File upload and artifact management
- Cluster configuration storage

### Frontend
- React + TypeScript + Vite
- TailwindCSS for styling
- Recharts for visualizations
- Full dark mode support
- Responsive design

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Vault API Integration

### Required Permissions

Commands that interact with Vault API require specific permissions:

#### `kv-mounts` Command
```hcl
path "sys/mounts" {
  capabilities = ["read"]
}
path "+/metadata/*" {
  capabilities = ["list"]
}
path "+/*" {
  capabilities = ["list"]
}
```

#### `auth-mounts` Command
```hcl
path "sys/auth" {
  capabilities = ["read"]
}
path "auth/+/role" {
  capabilities = ["list", "read"]
}
path "auth/+/users" {
  capabilities = ["list", "read"]
}
path "auth/+/groups" {
  capabilities = ["list"]
}
```

#### `entity-list` Command
```hcl
path "identity/entity/id" {
  capabilities = ["list"]
}
path "identity/entity/id/*" {
  capabilities = ["read"]
}
path "sys/auth" {
  capabilities = ["read"]
}
```

#### `client-activity` Command
```hcl
path "sys/internal/counters/activity/export" {
  capabilities = ["read"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
path "sys/auth" {
  capabilities = ["read"]
}
```

### Environment Variables

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.your-token-here"
export VAULT_NAMESPACE="tenant1"  # Optional, for Vault Enterprise
export VAULT_SKIP_VERIFY="true"   # Optional, for dev/test only
```

### Docker Networking

When running in Docker, use `host.docker.internal` to access Vault on the host:

```bash
# In cluster configuration
Vault Address: http://host.docker.internal:8200
```

## Development

### Prerequisites
- Go 1.23+
- Node.js 18+
- Make

### Build Everything

```bash
# Build CLI and server
make build
make server

# Build frontend
cd frontend && npm install && npm run build

# Run tests
make test

# Run linters
make lint
```

### Run Locally

```bash
# Terminal 1: Start API server
./server

# Terminal 2: Start frontend dev server
cd frontend && npm run dev

# Access at http://localhost:5173
```

### Testing

```bash
# Run all tests
go test ./...

# Run with coverage
make cover

# Run specific package
go test ./internal/api -v
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture and design decisions
- [FRONTEND_SETUP.md](FRONTEND_SETUP.md) - Frontend development guide
- [examples/setup-test-auth.sh](examples/setup-test-auth.sh) - Script to populate test auth mounts

## Use Cases

### Security & Compliance
- Generate audit reports for SOC 2, ISO 27001 compliance
- Identify anomalous access patterns and potential threats
- Track access reviews and secret usage over time
- Investigate security incidents with targeted log analysis

### Platform & Infrastructure
- Optimize costs by identifying unused secrets and mounts
- Plan capacity based on usage patterns and peak times
- Inform migration and restructuring decisions
- Troubleshoot performance bottlenecks

### DevOps & Engineering
- Understand application secret dependencies
- Track secret lifecycle and identify stale credentials
- Monitor team access patterns
- Integrate into CI/CD for continuous monitoring

## Performance

- **Throughput**: ~230,000 lines/second on single files
- **Memory**: <100 MB for streaming operations
- **Parallel**: Near-linear scaling with CPU cores
- **Compressed**: Direct `.gz`/`.zst` support with no temp files

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Support

For issues or questions, please open a [GitHub issue](https://github.com/trenner1/hashicorp-vault-audit-analysis/issues).
