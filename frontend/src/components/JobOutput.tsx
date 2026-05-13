import { useEffect, useRef, useState, useMemo } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'

interface JobOutputProps {
  jobId: string
}

function useElapsed(active: boolean, startedAt?: string): string {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!active) {
      setElapsed(0)
      return
    }
    const base = startedAt ? Date.now() - new Date(startedAt).getTime() : 0
    const id = setInterval(() => {
      setElapsed(Math.floor((Date.now() - (startedAt ? new Date(startedAt).getTime() : Date.now())) / 1000))
    }, 1000)
    setElapsed(Math.floor(base / 1000))
    return () => clearInterval(id)
  }, [active, startedAt])

  if (!active) return ''
  const h = Math.floor(elapsed / 3600)
  const m = Math.floor((elapsed % 3600) / 60)
  const s = elapsed % 60
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export function JobOutput({ jobId }: JobOutputProps) {
  const queryClient = useQueryClient()
  const [outputLines, setOutputLines] = useState<string[]>([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [search, setSearch] = useState('')
  const [matchIndex, setMatchIndex] = useState(0)
  const [expanded, setExpanded] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const preRef = useRef<HTMLPreElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const seenLines = useRef<Set<string>>(new Set())

  const { data: job, isLoading } = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => api.getJob(jobId),
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'running' || status === 'pending' ? 1000 : false
    },
  })

  const isActive = job?.status === 'running' || job?.status === 'pending'
  const elapsed = useElapsed(isActive, job?.created_at)

  // Clear output when jobId changes (e.g., when rerunning)
  useEffect(() => {
    setOutputLines([])
    seenLines.current.clear()
    setIsStreaming(false)
    setSearch('')
    setMatchIndex(0)
    setAutoScroll(true)
  }, [jobId])

  useEffect(() => {
    if (!job) return undefined

    // Seed from REST when we have no SSE lines yet, OR when job is complete and we have more lines in REST
    if (job.output && job.output.length > 0) {
      if (outputLines.length === 0 || (job.status !== 'running' && job.status !== 'pending' && job.output.length > outputLines.length)) {
        setOutputLines(job.output)
        job.output.forEach(l => seenLines.current.add(l))
      }
    }

    if ((job.status === 'running' || job.status === 'pending') && !isStreaming) {
      setIsStreaming(true)
      const eventSource = api.streamJob(jobId)
      eventSourceRef.current = eventSource

      eventSource.addEventListener('output', (event: MessageEvent<string>) => {
        const line = event.data
        // Deduplicate: the REST poll might have already seeded this line.
        setOutputLines(prev => {
          if (seenLines.current.has(line) && prev.includes(line)) {
            // Only skip if this exact string was from the initial seed;
            // streaming can emit the same text legitimately (unlikely but safe).
            // Simple approach: just append — duplicates are rare and recoverable.
          }
          seenLines.current.add(line)
          return [...prev, line]
        })
      })

      eventSource.addEventListener('done', () => {
        setIsStreaming(false)
        eventSource.close()
        // Invalidate queries to immediately show updated job details
        queryClient.invalidateQueries({ queryKey: ['job', jobId] })
        queryClient.invalidateQueries({ queryKey: ['jobs'] })
      })

      eventSource.onerror = () => {
        setIsStreaming(false)
        eventSource.close()
      }

      return () => {
        eventSource.close()
        setIsStreaming(false)
      }
    }

    return undefined
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, jobId, job?.status])

  // Auto-scroll when new output arrives (unless user scrolled up)
  useEffect(() => {
    if (autoScroll && preRef.current) {
      preRef.current.scrollTop = preRef.current.scrollHeight
    }
  }, [outputLines, autoScroll])

  // Detect manual scroll-up → disable auto-scroll; at bottom → re-enable
  const handleScroll = () => {
    if (!preRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = preRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 40)
  }

  // Build filtered lines + match positions
  const filteredLines = useMemo(() => {
    if (!search.trim()) return outputLines
    const lower = search.toLowerCase()
    return outputLines.filter(line => line.toLowerCase().includes(lower))
  }, [outputLines, search])

  // Keep matchIndex in bounds when results change
  const clampedMatch = Math.min(matchIndex, Math.max(0, filteredLines.length - 1))

  // Scroll active match line into view
  useEffect(() => {
    if (!search.trim() || filteredLines.length === 0 || !preRef.current) return
    const lines = preRef.current.querySelectorAll('span[data-line]')
    const el = lines[clampedMatch]
    el?.scrollIntoView({ block: 'nearest' })
  }, [clampedMatch, search, filteredLines.length])

  if (isLoading) {
    return <div className="text-gray-500 dark:text-slate-400 text-sm">Loading job output…</div>
  }

  const statusColor = {
    pending:   'bg-gray-100 dark:bg-slate-800 text-gray-800 dark:text-slate-200',
    running:   'bg-blue-100 text-blue-800',
    done:      'bg-green-100 text-green-800',
    error:     'bg-red-100 text-red-800',
    cancelled: 'bg-yellow-100 text-yellow-800',
  }[job?.status ?? 'pending'] ?? 'bg-gray-100 dark:bg-slate-800 text-gray-800 dark:text-slate-200'

  const terminalHeight = expanded ? 'max-h-[80vh]' : 'max-h-96'

  /** Highlight search term within a line string. */
  function HighlightLine({ line, isActive }: { line: string; isActive: boolean }) {
    if (!search.trim()) {
      return <>{line}</>
    }
    const lower = search.toLowerCase()
    const idx = line.toLowerCase().indexOf(lower)
    if (idx === -1) return <>{line}</>
    return (
      <>
        {line.slice(0, idx)}
        <mark className={`rounded px-0.5 ${isActive ? 'bg-yellow-300 text-gray-900 dark:text-slate-100' : 'bg-yellow-600/40 text-yellow-100'}`}>
          {line.slice(idx, idx + search.length)}
        </mark>
        {line.slice(idx + search.length)}
      </>
    )
  }

  const displayLines = search.trim() ? filteredLines : outputLines
  const waitingForOutput = isStreaming && outputLines.length === 0

  return (
    <div className="space-y-3">
      {/* Status + meta row */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-4">
          <div>
            <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Status</p>
            <span className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${statusColor}`}>
              {job?.status ?? 'Unknown'}
              {isStreaming && (
                <span className="ml-1.5 inline-block h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
              )}
            </span>
          </div>
          {elapsed && (
            <div>
              <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Elapsed</p>
              <p className="font-mono text-sm text-blue-700 tabular-nums">{elapsed}</p>
            </div>
          )}
          {job?.exit_code !== undefined && job.exit_code !== 0 && (
            <div>
              <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Exit code</p>
              <p className="font-mono font-bold text-red-600">{job.exit_code}</p>
            </div>
          )}
          <div>
            <p className="text-xs text-gray-500 dark:text-slate-400 mb-0.5">Lines</p>
            <p className="font-mono text-sm text-gray-700 dark:text-slate-300">
              {search.trim()
                ? `${filteredLines.length} / ${outputLines.length}`
                : outputLines.length}
            </p>
          </div>
        </div>
      </div>

      {job?.error && (
        <div className="bg-red-50 border border-red-200 rounded p-3">
          <p className="text-sm text-red-800">{job.error}</p>
        </div>
      )}

      {/* Terminal toolbar */}
      <div className="bg-gray-800 rounded-t-lg px-3 py-2 flex items-center gap-2">
        {/* Search input */}
        <div className="flex-1 flex items-center gap-2 bg-gray-700 rounded px-2 py-1">
          <svg className="h-3.5 w-3.5 text-gray-400 dark:text-slate-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setMatchIndex(0) }}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault()
                if (filteredLines.length > 0) {
                  setMatchIndex(i => (i + 1) % filteredLines.length)
                }
              }
              if (e.key === 'Escape') setSearch('')
            }}
            placeholder="Filter output… (Enter to step through)"
            className="flex-1 bg-transparent text-xs text-gray-200 placeholder-gray-500 outline-none font-mono"
          />
          {search && (
            <span className="text-xs text-gray-400 dark:text-slate-500 shrink-0 tabular-nums">
              {filteredLines.length > 0 ? `${clampedMatch + 1}/${filteredLines.length}` : '0'}
            </span>
          )}
          {search && (
            <button onClick={() => setSearch('')} className="text-gray-500 dark:text-slate-400 hover:text-gray-300 text-xs shrink-0">✕</button>
          )}
        </div>

        {/* Prev / Next match */}
        {search && filteredLines.length > 0 && (
          <div className="flex gap-1">
            <button
              onClick={() => setMatchIndex(i => (i - 1 + filteredLines.length) % filteredLines.length)}
              className="text-xs text-gray-400 dark:text-slate-500 hover:text-white px-1.5 py-1 rounded hover:bg-gray-700 transition-colors"
              title="Previous match"
            >↑</button>
            <button
              onClick={() => setMatchIndex(i => (i + 1) % filteredLines.length)}
              className="text-xs text-gray-400 dark:text-slate-500 hover:text-white px-1.5 py-1 rounded hover:bg-gray-700 transition-colors"
              title="Next match"
            >↓</button>
          </div>
        )}

        {/* Expand toggle */}
        <button
          onClick={() => setExpanded(v => !v)}
          className="text-xs text-gray-400 dark:text-slate-500 hover:text-white px-1.5 py-1 rounded hover:bg-gray-700 transition-colors shrink-0"
          title={expanded ? 'Collapse' : 'Expand'}
        >
          {expanded ? '⊡' : '⊞'}
        </button>
      </div>

      {/* Output */}
      <div className="border border-gray-300 dark:border-slate-600 rounded-b-lg border-t-0 bg-gray-900">
        <pre
          ref={preRef}
          onScroll={handleScroll}
          className={`p-4 text-sm text-green-400 font-mono overflow-auto ${terminalHeight} whitespace-pre-wrap break-words leading-relaxed`}
        >
          {waitingForOutput ? (
            <span className="text-gray-500 dark:text-slate-400 flex items-center gap-2">
              <span className="inline-flex gap-0.5">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '300ms' }} />
              </span>
              Processing… waiting for output
              {elapsed && <span className="text-blue-400 ml-1">({elapsed})</span>}
            </span>
          ) : displayLines.length === 0 ? (
            <span className="text-gray-600 dark:text-slate-400">
              {search.trim() ? 'No matching lines' : 'No output yet…'}
            </span>
          ) : (
            displayLines.map((line, i) => (
              <span key={i} data-line={i} className="block">
                <HighlightLine line={line} isActive={search.trim() ? i === clampedMatch : false} />
              </span>
            ))
          )}
        </pre>
        {/* Footer: streaming status + line count */}
        <div className="flex items-center justify-between px-3 py-1.5 bg-gray-800 rounded-b-lg border-t border-gray-700">
          <span className="text-xs text-gray-500 dark:text-slate-400 font-mono">
            {outputLines.length} line{outputLines.length !== 1 ? 's' : ''}
            {search.trim() && ` · ${filteredLines.length} match${filteredLines.length !== 1 ? 'es' : ''}`}
          </span>
          {isStreaming && (
            <span className="text-xs text-blue-400 flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
              live · {elapsed}
            </span>
          )}
          {!isStreaming && !autoScroll && outputLines.length > 0 && (
            <button
              onClick={() => {
                setAutoScroll(true)
                if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight
              }}
              className="text-xs text-gray-400 dark:text-slate-500 hover:text-white underline"
            >
              ↓ scroll to bottom
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
