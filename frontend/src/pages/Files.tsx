import { useRef, useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api, UploadedFile, Job, FileMetadata } from '../api/client'

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
            <span className="font-mono text-gray-800 dark:text-slate-200">
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
                    className="font-mono text-gray-800 bg-white dark:bg-slate-900 border border-violet-100 rounded px-1.5 py-0.5 break-all"
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
              'bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-400'
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

// ── Metadata panel for artifacts ──────────────────────────────────────────────

function MetadataPanel({ file }: { file: UploadedFile }) {
  const [open, setOpen] = useState(false)
  const { data: metadata, isLoading } = useQuery<FileMetadata | null>({
    queryKey: ['file-metadata', file.filename],
    queryFn: () => api.getFileMetadata(file.filename),
    enabled: open, // Only fetch when panel is opened
  })

  return (
    <div className="mt-1.5">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 hover:text-emerald-800 dark:hover:text-emerald-300 font-medium"
      >
        <span className="text-emerald-400 dark:text-emerald-500">{open ? '▾' : '▸'}</span>
        <span>📊 Metadata</span>
      </button>

      {open && (
        <div className="mt-2 ml-4 p-3 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg space-y-2.5 text-xs">
          {isLoading ? (
            <p className="text-emerald-600 dark:text-emerald-400">Loading metadata...</p>
          ) : !metadata ? (
            <p className="text-gray-500 dark:text-slate-400">No metadata available</p>
          ) : (
            <>
              {/* Command */}
              <div className="flex items-center gap-2">
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold w-24 shrink-0">Command</span>
                <span className="font-mono text-gray-800 dark:text-slate-200">
                  {metadata.command}{metadata.subcommand ? ` ${metadata.subcommand}` : ''}
                </span>
              </div>

              {/* Description */}
              <div className="flex items-start gap-2">
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold w-24 shrink-0 pt-0.5">Description</span>
                <span className="text-gray-700 dark:text-slate-300">{metadata.description}</span>
              </div>

              {/* Created */}
              <div className="flex items-center gap-2">
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold w-24 shrink-0">Created</span>
                <span className="text-gray-600 dark:text-slate-400">
                  {new Date(metadata.created_at).toLocaleString()}
                </span>
              </div>

              {/* Input files */}
              {metadata.input_files && metadata.input_files.length > 0 && (
                <div className="flex items-start gap-2">
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold w-24 shrink-0 pt-0.5">
                    Inputs ({metadata.input_files.length})
                  </span>
                  <div className="flex flex-col gap-1">
                    {metadata.input_files.map((f, i) => (
                      <span
                        key={i}
                        title={f}
                        className="font-mono text-gray-800 dark:text-slate-200 bg-white dark:bg-slate-800 border border-emerald-100 dark:border-emerald-800 rounded px-1.5 py-0.5 break-all"
                      >
                        {basename(f)}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Flags */}
              {metadata.flags && metadata.flags.length > 0 && (
                <div className="flex items-start gap-2">
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold w-24 shrink-0 pt-0.5">Flags</span>
                  <div className="flex flex-wrap gap-1">
                    {metadata.flags.map((flag, i) => (
                      <span
                        key={i}
                        className="font-mono text-xs text-emerald-700 dark:text-emerald-300 bg-emerald-100 dark:bg-emerald-900/40 px-1.5 py-0.5 rounded"
                      >
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
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
  isArtifact,
}: {
  file: UploadedFile
  outputJob?: Job | null
  onDelete: (f: UploadedFile) => void
  deleting: boolean
  isArtifact?: boolean
}) {
  const navigate = useNavigate()
  const icon = file.filename.endsWith('.gz')   ? '🗜️'
             : file.filename.endsWith('.json')  ? '📄'
             : file.filename.endsWith('.csv')   ? '📊'
             : '📃'

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors align-top">
      <td className="px-6 py-4">
        <div className="flex items-start gap-3">
          <span className="text-2xl leading-none mt-0.5">{icon}</span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-gray-900 dark:text-slate-100 font-mono break-all">{file.filename}</p>
            {isArtifact ? <MetadataPanel file={file} /> : outputJob && <LineagePanel file={file} job={outputJob} />}
          </div>
        </div>
      </td>
      <td className="px-6 py-4 text-sm text-gray-600 dark:text-slate-400 font-mono whitespace-nowrap">
        {formatBytes(file.size)}
      </td>
      <td className="px-6 py-4 text-sm text-gray-500 dark:text-slate-400 whitespace-nowrap">
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
            className="text-xs text-gray-400 dark:text-slate-500 hover:text-red-500 disabled:opacity-40 transition-colors"
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
  isArtifactSection,
}: {
  title: string
  icon: string
  headerClass: string
  files: UploadedFile[]
  jobMap: Map<string, Job>
  onDelete: (f: UploadedFile) => void
  deletingFile: string | null
  extra?: React.ReactNode
  isArtifactSection?: boolean
}) {
  if (files.length === 0) return null
  return (
    <div className="bg-white dark:bg-slate-900 rounded-lg shadow overflow-hidden">
      <div className={`flex items-center justify-between px-6 py-4 border-b border-gray-100 dark:border-slate-700 ${headerClass}`}>
        <div className="flex items-center gap-2">
          <span>{icon}</span>
          <h2 className="text-sm font-semibold">{title}</h2>
          <span className="text-xs bg-white dark:bg-slate-900/60 px-2 py-0.5 rounded-full text-current opacity-70">
            {files.length} file{files.length !== 1 ? 's' : ''}
          </span>
        </div>
        {extra}
      </div>
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-slate-800 border-b border-gray-100 dark:border-slate-700">
          <tr className="text-left text-xs font-medium text-gray-500 dark:text-slate-400 uppercase tracking-wide">
            <th className="px-6 py-3">Filename</th>
            <th className="px-6 py-3">Size</th>
            <th className="px-6 py-3">Date</th>
            <th className="px-6 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50 dark:divide-slate-800">
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
                isArtifact={isArtifactSection}
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

  // Extract date from filename - prioritize audit log date over upload timestamp
  // Examples:
  //   "vault_audit.2025-10-08.log.gz" → 2025-10-08
  //   "20260408172919_vault_audit.2025-10-08.log.gz" → 2025-10-08 (not 20260408)
  function extractDateFromFilename(filename: string): Date | null {
    // Look for ISO date format: YYYY-MM-DD (with hyphens)
    // This is typically the audit log date, not the upload timestamp
    const isoMatch = filename.match(/(\d{4})-(\d{2})-(\d{2})/)
    if (isoMatch) {
      const [, year, month, day] = isoMatch
      return new Date(`${year}-${month}-${day}`)
    }
    
    // If no ISO date, try compact format YYYYMMDD but only if it looks like a log date
    // (appears after "audit" or "vault" in the filename, not at the very start)
    const logDateMatch = filename.match(/(?:audit|vault)[._](\d{4})(\d{2})(\d{2})/)
    if (logDateMatch) {
      const [, year, month, day] = logDateMatch
      return new Date(`${year}-${month}-${day}`)
    }
    
    return null
  }

  // Split files into three categories:
  // 1. Uploaded audit logs (user uploads)
  // 2. Analysis artifacts (CSV, JSON outputs from commands)
  // 3. Metadata files (.meta.json) - hidden from display
  const { uploadedFiles, artifactFiles } = useMemo(() => {
    const uploadedFiles: UploadedFile[] = []
    const artifactFiles: UploadedFile[] = []
    
    for (const f of files) {
      // Skip .meta.json files - they're internal metadata
      if (f.filename.endsWith('.meta.json')) continue
      
      // Artifact files: CSV, JSON (non-meta), or files with timestamped pattern
      const isArtifact =
        f.filename.match(/_\d{8}_\d{6}/) ||  // Timestamped pattern: _YYYYMMDD_HHMMSS
        (f.filename.endsWith('.csv') && !f.filename.includes('vault_audit')) ||
        (f.filename.endsWith('.json') && !f.filename.includes('vault_audit'))
      
      if (isArtifact) {
        artifactFiles.push(f)
      } else {
        uploadedFiles.push(f)
      }
    }
    
    // Sort uploaded files by date in filename (oldest first)
    uploadedFiles.sort((a, b) => {
      const dateA = extractDateFromFilename(a.filename)
      const dateB = extractDateFromFilename(b.filename)
      
      if (dateA && dateB) return dateA.getTime() - dateB.getTime()
      if (dateA && !dateB) return -1
      if (!dateA && dateB) return 1
      return a.filename.localeCompare(b.filename)
    })
    
    // Sort artifacts by creation time (newest first)
    artifactFiles.sort((a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    )
    
    return { uploadedFiles, artifactFiles }
  }, [files])

  const totalSize = files.reduce((sum, f) => sum + f.size, 0)
  const handleDelete = (f: UploadedFile) => deleteMutation.mutate(f.filename)

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-slate-100">Files</h1>
          <p className="text-gray-500 dark:text-slate-400 mt-1 text-sm">
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
        className="border-2 border-dashed border-gray-300 dark:border-slate-600 rounded-xl p-8 text-center hover:border-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors cursor-pointer"
        onClick={() => fileInputRef.current?.click()}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) uploadFile(f) }}
      >
        <div className="text-4xl mb-3">📁</div>
        <p className="text-sm font-medium text-gray-700 dark:text-slate-300">Drop a log file here, or click to browse</p>
        <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">Any format accepted · no size limit</p>
        {uploading && (
          <div className="mt-4 w-full max-w-xs mx-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between text-xs text-gray-500 dark:text-slate-400 mb-1">
              <span>Uploading…</span><span>{uploadProgress}%</span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2">
              <div className="bg-indigo-500 h-2 rounded-full transition-all duration-200" style={{ width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}
      </div>

      {/* File lists */}
      {isLoading ? (
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow p-8 text-center text-gray-400 dark:text-slate-500 text-sm animate-pulse">Loading…</div>
      ) : files.length === 0 ? (
        <div className="bg-white dark:bg-slate-900 rounded-lg shadow p-10 text-center">
          <p className="text-gray-400 dark:text-slate-500 text-sm">No files yet. Upload a Vault audit log above to get started.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Uploaded audit log files */}
          <SectionTable
            title="Uploaded Files"
            icon="📋"
            headerClass="text-gray-700 dark:text-slate-300"
            files={uploadedFiles}
            jobMap={jobsByShortId}
            onDelete={handleDelete}
            deletingFile={deletingFile}
            isArtifactSection={false}
            extra={
              <button onClick={() => refetch()} className="text-xs text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300 font-medium">
                Refresh
              </button>
            }
          />

          {/* Analysis artifacts (CSV, JSON outputs) */}
          <SectionTable
            title="Analysis Artifacts"
            icon="📊"
            headerClass="bg-emerald-50 dark:bg-emerald-900/30 text-emerald-900 dark:text-emerald-200"
            files={artifactFiles}
            jobMap={jobsByShortId}
            onDelete={handleDelete}
            deletingFile={deletingFile}
            isArtifactSection={true}
            extra={
              <p className="text-xs text-emerald-600 dark:text-emerald-400">
                Click ▸ Metadata to see command details
              </p>
            }
          />
        </div>
      )}
    </div>
  )
}
