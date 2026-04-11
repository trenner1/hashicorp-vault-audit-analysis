import { useRef, useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api, UploadedFile, Job } from '../api/client'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function basename(p: string): string {
  return p.replace(/.*[\\/]/, '')
}

/**
 * Extract the 8-char hex job-ID prefix embedded in filenames produced by the
 * server's injectUniqueOutput logic.
 * Pattern: <prefix>_<YYYYMMDD>_<HHMMSS>_<jobid8>.<ext>
 */
function extractJobShortId(filename: string): string | null {
  const m = filename.match(/_([0-9a-f]{8})\.[^.]+$/i)
  return m ? m[1] : null
}

function isFilePath(arg: string): boolean {
  return (
    arg.startsWith('/') ||
    arg.startsWith('./') ||
    /\.(log|gz|zst|json|csv|txt)$/i.test(arg)
  )
}

// ── Lineage panel ─────────────────────────────────────────────────────────────

function LineagePanel({ file, job }: { file: UploadedFile; job: Job }) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)

  // Everything in args that looks like an input file, excluding the output file itself
  const inputFiles = (job.args ?? []).filter(
    a => isFilePath(a) && !a.includes(basename(file.filename))
  )

  const durationMs = new Date(job.updated_at).getTime() - new Date(job.created_at).getTime()
  const durationS  = Math.round(durationMs / 1000)
  const duration   = durationS < 60 ? `${durationS}s` : `${Math.floor(durationS / 60)}m ${durationS % 60}s`

  return (
    <div className="mt-1.5">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1.5 text-xs text-violet-600 hover:text-violet-800 font-medium"
      >
        <span className="text-violet-400">{open ? '▾' : '▸'}</span>
        <span>🔗 Lineage</span>
        <span className="text-violet-300 mx-0.5">·</span>
        <span className="font-mono">{job.id.slice(0, 8)}</span>
        <span className="text-violet-300 mx-0.5">·</span>
        <span>{new Date(job.created_at).toLocaleString()}</span>
        {inputFiles.length > 0 && (
          <>
            <span className="text-violet-300 mx-0.5">·</span>
            <span>{inputFiles.length} input{inputFiles.length !== 1 ? 's' : ''}</span>
          </>
        )}
      </button>

      {open && (
        <div className="mt-2 ml-4 p-3 bg-violet-50 border border-violet-200 rounded-lg space-y-2.5 text-xs">

          {/* Job link */}
          <div className="flex items-center gap-2">
            <span className="text-violet-500 font-semibold w-20 shrink-0">Job</span>
            <button
              onClick={() => navigate(`/jobs/${job.id}`)}
              className="font-mono text-indigo-600 hover:text-indigo-800 underline break-all"
            >
              {job.id}
            </button>
          </div>

          {/* Command */}
          <div className="flex items-center gap-2">
            <span className="text-violet-500 font-semibold w-20 shrink-0">Command</span>
            <span className="font-mono text-gray-800">
              {[job.command, ...(job.args ?? []).filter(a => !isFilePath(a) && !a.startsWith('--') && !a.startsWith('-'))].join(' ')}
            </span>
          </div>

          {/* Input files */}
          {inputFiles.length > 0 && (
            <div className="flex items-start gap-2">
              <span className="text-violet-500 font-semibold w-20 shrink-0 pt-0.5">
                Inputs ({inputFiles.length})
              </span>
              <div className="flex flex-col gap-1">
                {inputFiles.map((f, i) => (
                  <span
                    key={i}
                    title={f}
                    className="font-mono text-gray-800 bg-white border border-violet-100 rounded px-1.5 py-0.5 break-all"
                  >
                    {basename(f)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Status + duration */}
          <div className="flex items-center gap-2">
            <span className="text-violet-500 font-semibold w-20 shrink-0">Status</span>
            <span className={`px-1.5 py-0.5 rounded font-semibold ${
              job.status === 'done'  ? 'bg-green-100 text-green-700' :
              job.status === 'error' ? 'bg-red-100 text-red-700'   :
              'bg-gray-100 text-gray-600'
            }`}>
              {job.status}
            </span>
            {job.status === 'done' && (
              <span className="text-violet-400">· ran for {duration}</span>
            )}
          </div>

        </div>
      )}
    </div>
  )
}

// ── File table row ────────────────────────────────────────────────────────────

function FileRow({
  file,
  outputJob,
  onDelete,
  deleting,
}: {
  file: UploadedFile
  outputJob?: Job | null
  onDelete: (f: UploadedFile) => void
  deleting: boolean
}) {
  const navigate = useNavigate()
  const icon = file.filename.endsWith('.gz')   ? '🗜️'
             : file.filename.endsWith('.json')  ? '📄'
             : file.filename.endsWith('.csv')   ? '📊'
             : '📃'

  return (
    <tr className="hover:bg-gray-50 transition-colors align-top">
      <td className="px-6 py-4">
        <div className="flex items-start gap-3">
          <span className="text-2xl leading-none mt-0.5">{icon}</span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-gray-900 font-mono break-all">{file.filename}</p>
            {outputJob && <LineagePanel file={file} job={outputJob} />}
          </div>
        </div>
      </td>
      <td className="px-6 py-4 text-sm text-gray-600 font-mono whitespace-nowrap">
        {formatBytes(file.size)}
      </td>
      <td className="px-6 py-4 text-sm text-gray-500 whitespace-nowrap">
        {new Date(file.created_at).toLocaleString()}
      </td>
      <td className="px-6 py-4 text-right">
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={() => navigate('/analysis', { state: { preloadFile: file } })}
            className="text-xs px-3 py-1 rounded border border-indigo-300 text-indigo-700 bg-indigo-50 hover:bg-indigo-100 font-medium transition-colors whitespace-nowrap"
          >
            Use in Analysis
          </button>
          <button
            onClick={() => onDelete(file)}
            disabled={deleting}
            className="text-xs text-gray-400 hover:text-red-500 disabled:opacity-40 transition-colors"
            title="Delete file"
          >
            {deleting ? '…' : '🗑'}
          </button>
        </div>
      </td>
    </tr>
  )
}

function SectionTable({
  title,
  icon,
  headerClass,
  files,
  jobMap,
  onDelete,
  deletingFile,
  extra,
}: {
  title: string
  icon: string
  headerClass: string
  files: UploadedFile[]
  jobMap: Map<string, Job>
  onDelete: (f: UploadedFile) => void
  deletingFile: string | null
  extra?: React.ReactNode
}) {
  if (files.length === 0) return null
  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      <div className={`flex items-center justify-between px-6 py-4 border-b border-gray-100 ${headerClass}`}>
        <div className="flex items-center gap-2">
          <span>{icon}</span>
          <h2 className="text-sm font-semibold">{title}</h2>
          <span className="text-xs bg-white/60 px-2 py-0.5 rounded-full text-current opacity-70">
            {files.length} file{files.length !== 1 ? 's' : ''}
          </span>
        </div>
        {extra}
      </div>
      <table className="w-full">
        <thead className="bg-gray-50 border-b border-gray-100">
          <tr className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
            <th className="px-6 py-3">Filename</th>
            <th className="px-6 py-3">Size</th>
            <th className="px-6 py-3">Date</th>
            <th className="px-6 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {files.map(file => {
            const shortId  = extractJobShortId(file.filename)
            const outputJob = shortId ? jobMap.get(shortId) ?? null : null
            return (
              <FileRow
                key={file.filename}
                file={file}
                outputJob={outputJob}
                onDelete={f => {
                  if (window.confirm(`Delete "${f.filename}"?`)) onDelete(f)
                }}
                deleting={deletingFile === file.filename}
              />
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function Files() {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploading,       setUploading]       = useState(false)
  const [uploadProgress,  setUploadProgress]  = useState(0)
  const [uploadError,     setUploadError]     = useState<string | null>(null)
  const [uploadSuccess,   setUploadSuccess]   = useState<string | null>(null)
  const [deletingFile,    setDeletingFile]    = useState<string | null>(null)
  const [tabWarning,      setTabWarning]      = useState(false)

  useEffect(() => {
    if (!uploading) { setTabWarning(false); return }
    const h = () => setTabWarning(document.hidden)
    document.addEventListener('visibilitychange', h)
    return () => document.removeEventListener('visibilitychange', h)
  }, [uploading])

  const { data: files = [], isLoading, refetch } = useQuery<UploadedFile[]>({
    queryKey: ['files'],
    queryFn:  api.listFiles,
  })

  const { data: jobs = [] } = useQuery<Job[]>({
    queryKey: ['jobs'],
    queryFn:  api.listJobs,
    staleTime: 30_000,
  })

  // shortId (first 8 chars) → Job — used to resolve lineage for output files
  const jobsByShortId = useMemo(() => {
    const m = new Map<string, Job>()
    for (const job of jobs) m.set(job.id.slice(0, 8), job)
    return m
  }, [jobs])

  const deleteMutation = useMutation({
    mutationFn: (filename: string) => api.deleteFile(filename),
    onMutate:   (filename) => setDeletingFile(filename),
    onSettled:  () => setDeletingFile(null),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: ['files'] }),
  })

  const uploadFile = async (file: File) => {
    setUploadError(null); setUploadSuccess(null)
    setUploading(true);   setUploadProgress(0)

    const handleBeforeUnload = (e: BeforeUnloadEvent) => { e.preventDefault(); e.returnValue = '' }
    window.addEventListener('beforeunload', handleBeforeUnload)

    const doUpload = () => new Promise<{ filename: string; path: string; size: number }>((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('POST', `${import.meta.env.VITE_API_URL ?? ''}/api/v1/ingest/upload`)
      const apiKey = import.meta.env.VITE_API_KEY
      if (apiKey) xhr.setRequestHeader('X-API-Key', apiKey)
      xhr.upload.onprogress = e => { if (e.lengthComputable) setUploadProgress(Math.round(e.loaded / e.total * 100)) }
      xhr.onload  = () => xhr.status >= 200 && xhr.status < 300
        ? (() => { try { resolve(JSON.parse(xhr.responseText)) } catch { reject(new Error('Invalid server response')) } })()
        : (() => { try { reject(new Error(JSON.parse(xhr.responseText).error || xhr.statusText)) } catch { reject(new Error(xhr.statusText)) } })()
      xhr.onerror = () => reject(new Error('Network error during upload'))
      xhr.onabort = () => reject(new Error('Upload cancelled'))
      const fd = new FormData(); fd.append('file', file); xhr.send(fd)
    })

    try {
      let result: { filename: string; path: string; size: number }
      if ('locks' in navigator) {
        await navigator.locks.request('file-upload', async () => { result = await doUpload() })
      } else {
        result = await doUpload()
      }
      setUploadSuccess(`Uploaded: ${result!.filename} (${formatBytes(result!.size)})`)
      queryClient.invalidateQueries({ queryKey: ['files'] })
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      window.removeEventListener('beforeunload', handleBeforeUnload)
      setUploading(false); setUploadProgress(0)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  // Extract date from filename (e.g., "vault_audit.2025-10-08.log.gz" or "20260408172919_vault_audit.2025-10-08.log.gz")
  function extractDateFromFilename(filename: string): Date | null {
    // Try ISO date format: YYYY-MM-DD
    const isoMatch = filename.match(/(\d{4})-(\d{2})-(\d{2})/)
    if (isoMatch) {
      const [, year, month, day] = isoMatch
      return new Date(`${year}-${month}-${day}`)
    }
    
    // Try compact format: YYYYMMDD (at start of filename)
    const compactMatch = filename.match(/^(\d{8})/)
    if (compactMatch) {
      const dateStr = compactMatch[1]
      const year = dateStr.slice(0, 4)
      const month = dateStr.slice(4, 6)
      const day = dateStr.slice(6, 8)
      return new Date(`${year}-${month}-${day}`)
    }
    
    return null
  }

  // Split into log files vs analysis outputs (files whose name encodes a job ID)
  // Sort log files by date in filename (chronological order for entity churn analysis)
  const { logFiles, outputFiles } = useMemo(() => {
    const logFiles:    UploadedFile[] = []
    const outputFiles: UploadedFile[] = []
    for (const f of files) {
      const sid = extractJobShortId(f.filename)
      sid && jobsByShortId.has(sid) ? outputFiles.push(f) : logFiles.push(f)
    }
    
    // Sort log files by date in filename (oldest first)
    logFiles.sort((a, b) => {
      const dateA = extractDateFromFilename(a.filename)
      const dateB = extractDateFromFilename(b.filename)
      
      // If both have dates, sort chronologically
      if (dateA && dateB) {
        return dateA.getTime() - dateB.getTime()
      }
      
      // Files with dates come before files without dates
      if (dateA && !dateB) return -1
      if (!dateA && dateB) return 1
      
      // Fall back to alphabetical for files without dates
      return a.filename.localeCompare(b.filename)
    })
    
    return { logFiles, outputFiles }
  }, [files, jobsByShortId])

  const totalSize = files.reduce((sum, f) => sum + f.size, 0)
  const handleDelete = (f: UploadedFile) => deleteMutation.mutate(f.filename)

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Files</h1>
          <p className="text-gray-500 mt-1 text-sm">
            {files.length > 0
              ? `${files.length} file${files.length !== 1 ? 's' : ''} · ${formatBytes(totalSize)} total`
              : 'Upload log files to get started'}
          </p>
        </div>
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2"
        >
          {uploading ? (
            <>
              <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path  className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
              </svg>
              {uploadProgress > 0 ? `${uploadProgress}%` : 'Uploading…'}
            </>
          ) : <>↑ Upload File</>}
        </button>
        <input ref={fileInputRef} type="file" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) uploadFile(f) }} />
      </div>

      {/* Alerts */}
      {uploading && tabWarning && (
        <div className="bg-amber-50 border border-amber-300 rounded-lg px-4 py-3 flex items-center gap-3">
          <span className="text-amber-500 text-lg">⚠️</span>
          <p className="text-sm text-amber-800 font-medium">Upload in progress — keep this tab open ({uploadProgress}%)</p>
        </div>
      )}
      {uploadSuccess && (
        <div className="flex items-center justify-between bg-green-50 border border-green-200 rounded-lg px-4 py-3">
          <p className="text-sm text-green-700 font-medium">{uploadSuccess}</p>
          <button onClick={() => setUploadSuccess(null)} className="text-green-400 hover:text-green-600 text-xs ml-4">dismiss</button>
        </div>
      )}
      {uploadError && (
        <div className="flex items-center justify-between bg-red-50 border border-red-200 rounded-lg px-4 py-3">
          <p className="text-sm text-red-700 font-medium">Upload failed: {uploadError}</p>
          <button onClick={() => setUploadError(null)} className="text-red-400 hover:text-red-600 text-xs ml-4">dismiss</button>
        </div>
      )}

      {/* Drop zone */}
      <div
        className="border-2 border-dashed border-gray-300 rounded-xl p-8 text-center hover:border-indigo-400 hover:bg-indigo-50 transition-colors cursor-pointer"
        onClick={() => fileInputRef.current?.click()}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) uploadFile(f) }}
      >
        <div className="text-4xl mb-3">📁</div>
        <p className="text-sm font-medium text-gray-700">Drop a log file here, or click to browse</p>
        <p className="text-xs text-gray-400 mt-1">Any format accepted · no size limit</p>
        {uploading && (
          <div className="mt-4 w-full max-w-xs mx-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between text-xs text-gray-500 mb-1">
              <span>Uploading…</span><span>{uploadProgress}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-indigo-500 h-2 rounded-full transition-all duration-200" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* File lists */}
      {isLoading ? (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400 text-sm animate-pulse">Loading…</div>
      ) : files.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-10 text-center">
          <p className="text-gray-400 text-sm">No files yet. Upload a Vault audit log above to get started.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Analysis outputs — files produced by jobs, with full lineage */}
          <SectionTable
            title="Analysis Outputs"
            icon="🔗"
            headerClass="bg-violet-50 text-violet-900"
            files={outputFiles}
            jobMap={jobsByShortId}
            onDelete={handleDelete}
            deletingFile={deletingFile}
            extra={
              <p className="text-xs text-violet-500">
                Click ▸ Lineage to see source job and inputs
              </p>
            }
          />

          {/* Uploaded log files */}
          <SectionTable
            title="Uploaded Log Files"
            icon="📋"
            headerClass="text-gray-700"
            files={logFiles}
            jobMap={jobsByShortId}
            onDelete={handleDelete}
            deletingFile={deletingFile}
            extra={
              <button onClick={() => refetch()} className="text-xs text-indigo-600 hover:text-indigo-800 font-medium">
                Refresh
              </button>
            }
          />
        </div>
      )}
    </div>
  )
}
