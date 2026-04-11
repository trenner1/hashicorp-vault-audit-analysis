import { useState, useEffect, useCallback, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { api, QueryResponse, Job } from '../api/client'
import { JobOutput } from '../components/JobOutput'

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Return just the filename portion of a path. */
function basename(p: string): string {
  return p.replace(/.*[\\/]/, '')
}

/** True if arg looks like a file path rather than a flag or subcommand. */
function isFilePath(arg: string): boolean {
  return (
    arg.startsWith('/') ||
    arg.startsWith('./') ||
    arg.startsWith('../') ||
    /\.(log|gz|zst|json|csv|txt)$/i.test(arg)
  )
}

/**
 * Render a job's args as readable chips.
 * File paths → grey chip showing just the filename (full path on hover).
 * Flags      → individual indigo-tinted chips.
 * Subcommands (no leading '--') → plain text.
 */
function ArgsDisplay({ args, compact = false }: { args: string[]; compact?: boolean }) {
  if (!args || args.length === 0) return null

  const chips: JSX.Element[] = []
  let i = 0
  
  while (i < args.length) {
    const arg = args[i]
    
    // Check if this is a flag followed by a file path
    if ((arg.startsWith('--') || arg.startsWith('-')) && i + 1 < args.length && isFilePath(args[i + 1])) {
      const flagName = arg
      const filePath = args[i + 1]
      chips.push(
        <span
          key={i}
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 ${compact ? 'text-xs' : 'text-sm'}`}
        >
          <span className="text-indigo-700 font-mono">{flagName}</span>
          <span className="text-gray-400">→</span>
          <span title={filePath} className="inline-flex items-center gap-0.5 text-gray-700 font-mono">
            <span className="text-gray-400">📄</span>
            {basename(filePath)}
          </span>
        </span>
      )
      i += 2
      continue
    }
    
    if (isFilePath(arg)) {
      chips.push(
        <span
          key={i}
          title={arg}
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded bg-gray-100 text-gray-700 font-mono border border-gray-200 ${compact ? 'text-xs' : 'text-sm'}`}
        >
          <span className="text-gray-400">📄</span>
          {basename(arg)}
        </span>
      )
    } else if (arg.startsWith('--') || arg.startsWith('-')) {
      chips.push(
        <span
          key={i}
          className={`inline-flex items-center px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-mono border border-indigo-200 ${compact ? 'text-xs' : 'text-sm'}`}
        >
          {arg}
        </span>
      )
    } else {
      // Subcommand or positional value
      chips.push(
        <span
          key={i}
          className={`inline-flex items-center px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-medium ${compact ? 'text-xs' : 'text-sm'}`}
        >
          {arg}
        </span>
      )
    }
    i++
  }

  if (compact) {
    // In the table row, only show file chips + a "+N more" if there are many
    const fileChips = args.filter(isFilePath)
    const otherCount = args.filter(a => !isFilePath(a)).length
    return (
      <div className="flex flex-wrap gap-1 mt-0.5">
        {fileChips.slice(0, 3).map((arg, i) => (
          <span
            key={i}
            title={arg}
            className="inline-flex items-center gap-0.5 px-1.5 py-0 rounded bg-gray-100 text-gray-600 font-mono text-xs border border-gray-200"
          >
            <span className="text-gray-400 text-xs">📄</span>
            {basename(arg)}
          </span>
        ))}
        {fileChips.length > 3 && (
          <span className="text-xs text-gray-400">+{fileChips.length - 3} more files</span>
        )}
        {otherCount > 0 && fileChips.length > 0 && (
          <span className="text-xs text-gray-400">{otherCount} flag{otherCount !== 1 ? 's' : ''}</span>
        )}
        {fileChips.length === 0 && chips.slice(0, 4)}
      </div>
    )
  }

  return <div className="flex flex-wrap gap-1.5 mt-1">{chips}</div>
}

/**
 * Scan job output lines for file-write messages emitted by vault-audit commands.
 * Returns deduplicated list of filenames (basenames) that were written.
 *
 * Patterns matched (case-insensitive):
 *   "Output written to: <file>"
 *   "CSV written to: <file>"
 *   "JSON written to: <file>"
 *   "Writing entity mappings to: <file>"
 *   "Writing detailed entity creation data to: <file>"
 *   "Done. Output written to: <file>"
 *   Any line ending with a known extension after ": "
 */
function detectArtifacts(output: string[]): string[] {
  const pattern = /(?:written to|writing.*to|output written to|done\.\s*output written to)\s*:\s*(\S+\.(json|csv|txt))/i
  const seen = new Set<string>()
  for (const line of output) {
    const m = line.match(pattern)
    if (m) {
      const name = basename(m[1])
      if (name) seen.add(name)
    }
  }
  return Array.from(seen)
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100]

/** Render a subset of markdown to JSX without any external dependency. */
function SimpleMarkdown({ text }: { text: string }) {
  const lines = text.split('\n')
  const elements: React.ReactNode[] = []
  let key = 0

  const renderInline = (s: string): React.ReactNode => {
    const parts = s.split(/\*\*(.*?)\*\*/g)
    if (parts.length === 1) return s
    return parts.map((p, i) => i % 2 === 1 ? <strong key={i}>{p}</strong> : p)
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    if (line.startsWith('## ')) {
      elements.push(<h2 key={key++} className="text-base font-bold text-amber-900 mt-3 mb-1">{line.slice(3)}</h2>)
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={key++} className="text-lg font-bold text-amber-900 mt-3 mb-1">{line.slice(2)}</h1>)
    } else if (/^\d+\.\s/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s/, ''))
        i++
      }
      elements.push(
        <ol key={key++} className="list-decimal list-inside space-y-1 text-sm text-amber-900 my-1">
          {items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}
        </ol>
      )
      continue
    } else if (line.startsWith('- ')) {
      const items: string[] = []
      while (i < lines.length && lines[i].startsWith('- ')) {
        items.push(lines[i].slice(2))
        i++
      }
      elements.push(
        <ul key={key++} className="list-disc list-inside space-y-1 text-sm text-amber-900 my-1">
          {items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}
        </ul>
      )
      continue
    } else if (line.trim() !== '') {
      elements.push(<p key={key++} className="text-sm text-amber-900 leading-relaxed">{renderInline(line)}</p>)
    }
    i++
  }
  return <div className="space-y-1">{elements}</div>
}

export function Jobs() {
  const params = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const queryResult = (location.state as { queryResult?: QueryResponse } | null)?.queryResult

  const [selectedJobId, setSelectedJobId] = useState<string | null>(params.id ?? null)
  const [listExpanded, setListExpanded] = useState(!params.id)
  const [summary, setSummary] = useState<string | null>(null)
  const [summaryJobId, setSummaryJobId] = useState<string | null>(null)

  // Filter + pagination state
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterCommand, setFilterCommand] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const selectJob = (id: string | null) => {
    setSelectedJobId(id)
    setListExpanded(!id)
    setSummary(null)
    setSummaryJobId(null)
    if (id) navigate(`/jobs/${id}`, { replace: true })
    else navigate('/jobs', { replace: true })
  }

  const { data: jobs = [], isLoading, refetch } = useQuery({
    queryKey: ['jobs'],
    queryFn: api.listJobs,
    refetchInterval: (query) => {
      const data = query.state.data ?? []
      return data.some((j: Job) => j.status === 'running' || j.status === 'pending') ? 3000 : false
    },
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => api.cancelJob(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jobs'] }),
  })

  const rerunMutation = useMutation({
    mutationFn: (job: Job) => api.rerunJob(job),
    onSuccess: (newJob: Job) => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      selectJob(newJob.id)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteJob(id),
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      queryClient.invalidateQueries({ queryKey: ['system'] })
      if (selectedJobId === id) selectJob(null)
    },
  })

  const summarizeMutation = useMutation({
    mutationFn: ({ id, question }: { id: string; question?: string }) =>
      api.summarizeJob(id, question),
    onSuccess: (data, vars) => {
      setSummary(data.summary)
      setSummaryJobId(vars.id)
    },
  })

  const downloadOutput = useCallback((job: Job) => {
    const text = job.output?.join('\n') ?? ''
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${job.command}-${job.id.slice(0, 8)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  // Notify on job completion
  useEffect(() => {
    if (!selectedJobId) return undefined
    const job = jobs.find((j: Job) => j.id === selectedJobId)
    if (!job) return undefined
    if (job.status !== 'done' && job.status !== 'error') return undefined
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(`Job ${job.status === 'done' ? 'completed ✓' : 'failed ✗'}`, {
        body: `${job.command} ${job.args?.join(' ') ?? ''}`.trim(),
      })
    }
    return undefined
  }, [jobs.find((j: Job) => j.id === selectedJobId)?.status, selectedJobId])

  // Request notification permission once
  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }
  }, [])

  // Auto-summarize when a query-triggered job reaches "done"
  const selectedJob = jobs.find((j: Job) => j.id === selectedJobId)
  useEffect(() => {
    if (
      queryResult &&
      selectedJobId &&
      queryResult.job_id === selectedJobId &&
      selectedJob?.status === 'done' &&
      summaryJobId !== selectedJobId &&
      !summarizeMutation.isPending &&
      !summarizeMutation.isError
    ) {
      summarizeMutation.mutate({ id: selectedJobId, question: queryResult.reasoning })
    }
  }, [selectedJob?.status, selectedJobId, queryResult, summaryJobId, summarizeMutation.isPending])

  // Reset to page 1 when filters or page size change
  useEffect(() => { setPage(1) }, [filterStatus, filterCommand, pageSize])

  // Artifact files detected from job output
  const artifacts = useMemo(
    () => (selectedJob?.status === 'done' ? detectArtifacts(selectedJob.output ?? []) : []),
    [selectedJob?.id, selectedJob?.status, selectedJob?.output?.length]
  )

  const statusColor = (status: string) => {
    switch (status) {
      case 'pending':   return 'bg-gray-100 text-gray-700'
      case 'running':   return 'bg-blue-100 text-blue-800'
      case 'done':      return 'bg-green-100 text-green-800'
      case 'error':     return 'bg-red-100 text-red-800'
      case 'cancelled': return 'bg-yellow-100 text-yellow-800'
      default:          return 'bg-gray-100 text-gray-700'
    }
  }

  // Sort newest first, then filter
  const sortedJobs = [...jobs].sort(
    (a: Job, b: Job) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )
  const filteredJobs = sortedJobs.filter((j: Job) => {
    if (filterStatus !== 'all' && j.status !== filterStatus) return false
    if (filterCommand && !j.command.toLowerCase().includes(filterCommand.toLowerCase())) return false
    return true
  })

  const totalPages = Math.max(1, Math.ceil(filteredJobs.length / pageSize))
  const clampedPage = Math.min(page, totalPages)
  const pageJobs = filteredJobs.slice((clampedPage - 1) * pageSize, clampedPage * pageSize)

  const activeCount = jobs.filter((j: Job) => j.status === 'running' || j.status === 'pending').length

  return (
    <div className="space-y-6">

      {/* ── Job detail view ── */}
      {selectedJobId && (
        <div className="space-y-4">
          <button
            onClick={() => selectJob(null)}
            className="flex items-center gap-1 text-sm text-indigo-600 hover:text-indigo-800 font-medium"
          >
            ← All jobs
          </button>

          {/* Reasoning banner */}
          {queryResult && queryResult.job_id === selectedJobId && (
            <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2 text-indigo-700 font-semibold text-sm">
                <span>✨</span><span>AI-selected command</span>
              </div>
              <p className="text-sm text-indigo-900">{queryResult.reasoning}</p>
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <span className="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded border border-indigo-200">{queryResult.command}</span>
                {queryResult.subcommand && (
                  <span className="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded border border-indigo-200">{queryResult.subcommand}</span>
                )}
                {queryResult.args.map(a => (
                  <span key={a} className="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded border border-indigo-200">{a}</span>
                ))}
              </div>
            </div>
          )}

          {/* AI Summary */}
          {summarizeMutation.isPending && summaryJobId !== selectedJobId ? (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-center gap-3">
              <svg className="animate-spin h-4 w-4 text-amber-600 shrink-0" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <span className="text-sm text-amber-700">Generating AI summary…</span>
            </div>
          ) : summarizeMutation.isError ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-red-700">Summary unavailable</p>
                <p className="text-xs text-red-500 mt-0.5">
                  {summarizeMutation.error instanceof Error
                    ? summarizeMutation.error.message
                    : 'An error occurred'}
                </p>
              </div>
              <button
                onClick={() => summarizeMutation.reset()}
                className="text-xs text-red-400 hover:text-red-600 underline ml-4 shrink-0"
              >
                dismiss
              </button>
            </div>
          ) : summary && summaryJobId === selectedJobId ? (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-amber-700 font-semibold text-sm">
                  <span>📋</span><span>AI Summary</span>
                </div>
                <button onClick={() => { setSummary(null); setSummaryJobId(null) }} className="text-amber-400 hover:text-amber-600 text-xs">
                  dismiss
                </button>
              </div>
              <SimpleMarkdown text={summary} />
            </div>
          ) : null}

          {/* Job output card */}
          <div className="bg-white rounded-lg shadow p-6 space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <h1 className="text-xl font-bold text-gray-900">
                  {selectedJob?.command ?? 'Job'}
                </h1>
                {selectedJob?.args?.length ? (
                  <ArgsDisplay args={selectedJob.args} />
                ) : null}
                <p className="text-xs font-mono text-gray-400 mt-1">{selectedJobId}</p>
              </div>

              <div className="flex items-center gap-2 flex-wrap shrink-0">
                {/* Cancel */}
                {(selectedJob?.status === 'running' || selectedJob?.status === 'pending') && (
                  <button
                    onClick={() => cancelMutation.mutate(selectedJobId)}
                    disabled={cancelMutation.isPending}
                    className="text-xs px-3 py-1 rounded border border-red-300 text-red-700 bg-red-50 hover:bg-red-100 disabled:opacity-50 transition-colors"
                  >
                    ✕ Cancel
                  </button>
                )}
                {/* Re-run */}
                {selectedJob && (selectedJob.status === 'done' || selectedJob.status === 'error' || selectedJob.status === 'cancelled') && (
                  <button
                    onClick={() => rerunMutation.mutate(selectedJob)}
                    disabled={rerunMutation.isPending}
                    className="text-xs px-3 py-1 rounded border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 transition-colors"
                  >
                    ↺ Re-run
                  </button>
                )}
                {/* Download */}
                {selectedJob?.status === 'done' && (
                  <button
                    onClick={() => downloadOutput(selectedJob)}
                    className="text-xs px-3 py-1 rounded border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 transition-colors"
                  >
                    ↓ Download
                  </button>
                )}
                {/* Summarize */}
                {selectedJob?.status === 'done' && summaryJobId !== selectedJobId && (
                  <button
                    onClick={() => summarizeMutation.mutate({ id: selectedJobId })}
                    disabled={summarizeMutation.isPending}
                    className="text-xs px-3 py-1 rounded border border-amber-300 text-amber-700 bg-amber-50 hover:bg-amber-100 disabled:opacity-50 transition-colors"
                  >
                    ✨ Summarize
                  </button>
                )}
                {/* Delete */}
                {selectedJob && (selectedJob.status === 'done' || selectedJob.status === 'error' || selectedJob.status === 'cancelled') && (
                  <button
                    onClick={() => {
                      if (window.confirm('Delete this job from history?')) {
                        deleteMutation.mutate(selectedJobId)
                      }
                    }}
                    disabled={deleteMutation.isPending}
                    className="text-xs px-3 py-1 rounded border border-red-200 text-red-600 bg-white hover:bg-red-50 disabled:opacity-50 transition-colors"
                  >
                    🗑 Delete
                  </button>
                )}
                {/* Status badge */}
                {selectedJob && (
                  <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${statusColor(selectedJob.status)}`}>
                    {selectedJob.status}
                  </span>
                )}
              </div>
            </div>

            {/* ── Artifacts ── */}
            {artifacts.length > 0 && (
              <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4 space-y-2">
                <div className="flex items-center gap-2 text-emerald-800 font-semibold text-sm">
                  <span>📎</span>
                  <span>Output files</span>
                  <span className="text-xs text-emerald-600 font-normal">— written to the uploads directory</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {artifacts.map(name => (
                    <div key={name} className="flex items-center gap-1 bg-white border border-emerald-200 rounded-lg px-3 py-2 shadow-sm">
                      <span className="text-emerald-600 text-sm font-mono font-medium">{name}</span>
                      <div className="flex gap-1 ml-2">
                        <button
                          onClick={() => navigate('/files')}
                          className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-700 hover:bg-emerald-200 transition-colors"
                          title="View in Files tab"
                        >
                          📁 Files
                        </button>
                        <button
                          onClick={() => navigate('/analysis', { state: { preloadFile: name } })}
                          className="text-xs px-2 py-0.5 rounded bg-indigo-100 text-indigo-700 hover:bg-indigo-200 transition-colors"
                          title="Use as input in a new analysis"
                        >
                          🔍 Use in Analysis
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-emerald-600">
                  These files are now available in the <button onClick={() => navigate('/files')} className="underline hover:text-emerald-800">Files tab</button> and can be used as inputs for subsequent analysis steps.
                </p>
              </div>
            )}

            <JobOutput jobId={selectedJobId} />
          </div>

          <button
            onClick={() => setListExpanded(v => !v)}
            className="text-sm text-gray-500 hover:text-gray-700 flex items-center gap-1"
          >
            {listExpanded ? '▾' : '▸'} {jobs.length} job{jobs.length !== 1 ? 's' : ''} in history
            {activeCount > 0 && (
              <span className="ml-1 px-1.5 py-0.5 text-xs bg-blue-100 text-blue-700 rounded-full">{activeCount} active</span>
            )}
          </button>
        </div>
      )}

      {/* ── Job list ── */}
      {(!selectedJobId || listExpanded) && (
        <div className="space-y-4">
          {!selectedJobId && (
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Jobs</h1>
                <p className="text-gray-600 mt-1">History of all analysis runs</p>
              </div>
              {activeCount > 0 && (
                <span className="px-3 py-1 bg-blue-100 text-blue-700 text-sm font-medium rounded-full">
                  {activeCount} active
                </span>
              )}
            </div>
          )}

          {/* Toolbar: filters + page size */}
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={() => refetch()}
              className="px-3 py-1.5 text-sm bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
            >
              Refresh
            </button>

            {/* Status filter */}
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
              className="border border-gray-300 rounded px-2 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-400"
            >
              <option value="all">All statuses</option>
              <option value="running">Running</option>
              <option value="pending">Pending</option>
              <option value="done">Done</option>
              <option value="error">Error</option>
              <option value="cancelled">Cancelled</option>
            </select>

            {/* Command filter */}
            <input
              type="text"
              placeholder="Filter by command…"
              value={filterCommand}
              onChange={e => setFilterCommand(e.target.value)}
              className="border border-gray-300 rounded px-3 py-1.5 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-400 w-48"
            />

            {filterStatus !== 'all' || filterCommand ? (
              <button
                onClick={() => { setFilterStatus('all'); setFilterCommand('') }}
                className="text-xs text-gray-500 hover:text-gray-700 underline"
              >
                Clear filters
              </button>
            ) : null}

            <span className="text-sm text-gray-400 ml-auto">
              {filteredJobs.length !== sortedJobs.length
                ? `${filteredJobs.length} of ${sortedJobs.length} jobs`
                : `${sortedJobs.length} job${sortedJobs.length !== 1 ? 's' : ''}`}
            </span>

            {/* Page size */}
            <div className="flex items-center gap-2 text-sm text-gray-600">
              <label htmlFor="page-size">Show</label>
              <select
                id="page-size"
                value={pageSize}
                onChange={e => setPageSize(Number(e.target.value))}
                className="border border-gray-300 rounded px-2 py-1 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-400"
              >
                {PAGE_SIZE_OPTIONS.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="bg-white rounded-lg shadow overflow-hidden">
            {isLoading ? (
              <div className="p-6 text-center text-gray-500">Loading…</div>
            ) : filteredJobs.length === 0 ? (
              <div className="p-6 text-center text-gray-500">
                {sortedJobs.length === 0 ? 'No jobs yet' : 'No jobs match the current filters'}
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700">ID</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700">Command</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700">Duration</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700">Created</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-700"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {pageJobs.map((job: Job) => (
                    <tr
                      key={job.id}
                      onClick={() => selectJob(job.id)}
                      className={`cursor-pointer transition-colors hover:bg-gray-50 ${job.id === selectedJobId ? 'bg-indigo-50' : ''}`}
                    >
                      <td className="px-6 py-4 text-sm font-mono text-gray-500">{job.id.slice(0, 8)}…</td>
                      <td className="px-6 py-4">
                        <p className="text-sm text-gray-900 font-medium">{job.command}</p>
                        {job.args?.length > 0 && (
                          <ArgsDisplay args={job.args} compact />
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${statusColor(job.status)}`}>
                          {job.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs font-mono text-gray-500 whitespace-nowrap">
                        {(() => {
                          const ms = new Date(job.updated_at).getTime() - new Date(job.created_at).getTime()
                          if (job.status === 'pending') return '—'
                          if (ms < 1000) return `${ms}ms`
                          if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
                          return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
                        })()}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">{new Date(job.created_at).toLocaleString()}</td>
                      <td className="px-6 py-4 text-sm text-right">
                        <div className="flex items-center justify-end gap-3">
                          <span className="text-indigo-600 font-medium">View →</span>
                          {(job.status === 'done' || job.status === 'error' || job.status === 'cancelled') && (
                            <button
                              onClick={e => {
                                e.stopPropagation()
                                deleteMutation.mutate(job.id)
                              }}
                              disabled={deleteMutation.isPending && deleteMutation.variables === job.id}
                              className="text-gray-400 hover:text-red-500 transition-colors disabled:opacity-40"
                              title="Delete job"
                            >
                              🗑
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-500">
                Showing {(clampedPage - 1) * pageSize + 1}–{Math.min(clampedPage * pageSize, filteredJobs.length)} of {filteredJobs.length}
              </p>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(1)} disabled={clampedPage === 1}
                  className="px-2 py-1 text-sm rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">«</button>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={clampedPage === 1}
                  className="px-3 py-1 text-sm rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">← Prev</button>

                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .filter(p => p === 1 || p === totalPages || Math.abs(p - clampedPage) <= 2)
                  .reduce<(number | '…')[]>((acc, p, idx, arr) => {
                    if (idx > 0 && p - (arr[idx - 1] as number) > 1) acc.push('…')
                    acc.push(p)
                    return acc
                  }, [])
                  .map((item, idx) =>
                    item === '…' ? (
                      <span key={`e${idx}`} className="px-2 py-1 text-sm text-gray-400">…</span>
                    ) : (
                      <button key={item} onClick={() => setPage(item as number)}
                        className={`px-3 py-1 text-sm rounded border transition-colors ${item === clampedPage ? 'border-indigo-500 bg-indigo-600 text-white' : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'}`}>
                        {item}
                      </button>
                    )
                  )}

                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={clampedPage === totalPages}
                  className="px-3 py-1 text-sm rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">Next →</button>
                <button onClick={() => setPage(totalPages)} disabled={clampedPage === totalPages}
                  className="px-2 py-1 text-sm rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed">»</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
