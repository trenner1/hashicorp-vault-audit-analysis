// Empty string = same-origin (works with Vite proxy in dev and nginx in Docker).
// Set VITE_API_URL at build time only when the API lives on a different host.
const BASE = import.meta.env.VITE_API_URL ?? ''

// Optional API key — set VITE_API_KEY at build time to enable authentication.
const API_KEY = import.meta.env.VITE_API_KEY ?? ''

function authHeaders(extra?: Record<string, string>): HeadersInit {
  return API_KEY ? { 'X-API-Key': API_KEY, ...extra } : { ...extra }
}

function jsonHeaders(): HeadersInit {
  return authHeaders({ 'Content-Type': 'application/json' })
}

export interface Job {
  id: string
  command: string
  args: string[]
  status: 'pending' | 'running' | 'done' | 'error' | 'cancelled'
  output: string[]
  exit_code: number
  created_at: string
  updated_at: string
  error: string
}

export interface Command {
  name: string
  description: string
  subcommands?: string[]
}

export interface Cluster {
  id: string
  name: string
  vault_addr: string
  namespace: string
  token_set: boolean  // true if a token is stored server-side; token itself is never returned
  created_at: string
}

export interface UploadResult {
  filename: string
  path: string
  size: number
}

export interface UploadedFile {
  filename: string
  path: string
  size: number
  created_at: string
}

export interface QueryRequest {
  question: string
  files?: string[]
  cluster_id?: string
}

export interface QueryResponse {
  job_id: string
  command: string
  subcommand?: string
  args: string[]
  reasoning: string
}

export interface SystemInfo {
  uptime_seconds: number
  anthropic_enabled: boolean
  auth_enabled: boolean
  upload_dir: string
  max_concurrent: number
  version: string
  jobs: {
    pending: number
    running: number
    done: number
    error: number
    cancelled: number
  }
}

export const api = {
  health: () =>
    fetch(`${BASE}/healthz`, { headers: authHeaders() }).then(r => r.json()),

  listCommands: () =>
    fetch(`${BASE}/api/v1/commands`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<Command[]>,

  submitJob: (command: string, subcommand: string, files: string[], args: string[], clusterId?: string) =>
    fetch(`${BASE}/api/v1/jobs`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ command, subcommand, files, args, cluster_id: clusterId || undefined }),
    }).then(r => r.json()) as Promise<Job>,

  listJobs: () =>
    fetch(`${BASE}/api/v1/jobs`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<Job[]>,

  getJob: (id: string) =>
    fetch(`${BASE}/api/v1/jobs/${id}`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<Job>,

  // EventSource doesn't support custom headers — append key as query param when set.
  streamJob: (id: string) => {
    const url = API_KEY
      ? `${BASE}/api/v1/jobs/${id}/stream?api_key=${encodeURIComponent(API_KEY)}`
      : `${BASE}/api/v1/jobs/${id}/stream`
    return new EventSource(url)
  },

  listClusters: () =>
    fetch(`${BASE}/api/v1/clusters`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<Cluster[]>,

  createCluster: (c: Omit<Cluster, 'id' | 'created_at' | 'token_set'> & { token?: string }) =>
    fetch(`${BASE}/api/v1/clusters`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify(c),
    }).then(r => r.json()) as Promise<Cluster>,

  updateCluster: (id: string, data: Omit<Cluster, 'id' | 'created_at' | 'token_set'> & { token?: string }) =>
    fetch(`${BASE}/api/v1/clusters/${id}`, {
      method: 'PATCH',
      headers: jsonHeaders(),
      body: JSON.stringify(data),
    }).then(r => r.json()) as Promise<Cluster>,

  deleteCluster: (id: string) =>
    fetch(`${BASE}/api/v1/clusters/${id}`, { method: 'DELETE', headers: authHeaders() }),

  uploadLog: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return fetch(`${BASE}/api/v1/ingest/upload`, {
      method: 'POST',
      headers: authHeaders(), // no Content-Type — browser sets multipart boundary
      body: fd,
    }).then(async r => {
      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: r.statusText }))
        throw new Error(err.error || r.statusText)
      }
      return r.json() as Promise<UploadResult>
    })
  },

  listFiles: () =>
    fetch(`${BASE}/api/v1/ingest/files`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<UploadedFile[]>,

  deleteFile: (filename: string) =>
    fetch(`${BASE}/api/v1/ingest/files/${encodeURIComponent(filename)}`, {
      method: 'DELETE',
      headers: authHeaders(),
    }).then(async r => {
      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: r.statusText }))
        throw new Error(err.error || r.statusText)
      }
      return r.json()
    }),

  cancelJob: (id: string) =>
    fetch(`${BASE}/api/v1/jobs/${id}/cancel`, { method: 'POST', headers: authHeaders() })
      .then(r => r.json()),

  rerunJob: (job: Job) =>
    fetch(`${BASE}/api/v1/jobs`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ command: job.command, args: job.args }),
    }).then(r => r.json()) as Promise<Job>,

  summarizeJob: (id: string, question?: string) =>
    fetch(`${BASE}/api/v1/jobs/${id}/summarize`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ question: question ?? '' }),
    }).then(async r => {
      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: r.statusText }))
        throw new Error(err.error || r.statusText)
      }
      return r.json() as Promise<{ summary: string }>
    }),

  systemInfo: () =>
    fetch(`${BASE}/api/v1/system`, { headers: authHeaders() })
      .then(r => r.json()) as Promise<SystemInfo>,

  deleteJob: (id: string) =>
    fetch(`${BASE}/api/v1/jobs/${id}`, { method: 'DELETE', headers: authHeaders() })
      .then(async r => {
        if (!r.ok) {
          const err = await r.json().catch(() => ({ error: r.statusText }))
          throw new Error(err.error || r.statusText)
        }
        return r.json()
      }),

  pruneJobs: (olderThanHours = 24) =>
    fetch(`${BASE}/api/v1/jobs/prune`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ older_than_hours: olderThanHours }),
    }).then(async r => {
      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: r.statusText }))
        throw new Error(err.error || r.statusText)
      }
      return r.json() as Promise<{ deleted: number; older_than_hours: number }>
    }),

  query: (req: QueryRequest) =>
    fetch(`${BASE}/api/v1/query`, {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify(req),
    }).then(async r => {
      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: r.statusText }))
        throw new Error(err.error || r.statusText)
      }
      return r.json() as Promise<QueryResponse>
    }),
}
