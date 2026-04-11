import { useState, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useNavigate, useLocation } from 'react-router-dom'
import { api, Command, Cluster, UploadResult, UploadedFile, FileMetadata } from '../api/client'
import { getCommandMetadata, getSubcommandMetadata } from '../data/commandMetadata'

function basename(p: string): string {
  return p.replace(/.*[\\/]/, '')
}

const COMMANDS_WITH_SUBCOMMANDS: Record<string, string[]> = {
  'kv-analysis': ['analyze', 'compare', 'summary'],
  'entity-analysis': ['churn', 'creation', 'preprocess', 'gaps', 'timeline'],
}

// ── Metadata panel for file picker ────────────────────────────────────────────

function FileMetadataPanel({ file }: { file: UploadedFile }) {
  const [open, setOpen] = useState(false)
  const { data: metadata, isLoading } = useQuery<FileMetadata | null>({
    queryKey: ['file-metadata', file.filename],
    queryFn: () => api.getFileMetadata(file.filename),
    enabled: open, // Only fetch when panel is opened
  })

  return (
    <div className="mt-1.5">
      <button
        onClick={(e) => {
          e.stopPropagation()
          setOpen(v => !v)
        }}
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
                        className="font-mono text-xs bg-emerald-100 dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-300 px-1.5 py-0.5 rounded"
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

// Commands that require Vault API connectivity rather than log files
const VAULT_API_COMMANDS = new Set([
  'client-activity',
  'entity-list',
  'kv-mounts',
  'auth-mounts',
])

export function Analysis() {
  const navigate = useNavigate()
  const location = useLocation()
  const preloadFile = (location.state as { preloadFile?: UploadedFile } | null)?.preloadFile

  const [selectedCommand, setSelectedCommand] = useState<string>('')
  const [selectedSubcommand, setSelectedSubcommand] = useState<string>('')
  const [extraFlags, setExtraFlags] = useState<string>('')
  const [uploadedFiles, setUploadedFiles] = useState<UploadResult[]>([])
  const [dragActive, setDragActive] = useState(false)
  const [uploadError, setUploadError] = useState<string>('')

  const [selectedClusterId, setSelectedClusterId] = useState<string>('')
  const [showFilePicker, setShowFilePicker] = useState(false)

  const { data: commands = [] } = useQuery<Command[]>({
    queryKey: ['commands'],
    queryFn: api.listCommands,
  })

  const { data: clusters = [] } = useQuery<Cluster[]>({
    queryKey: ['clusters'],
    queryFn: api.listClusters,
  })

  const { data: existingFiles = [] } = useQuery<UploadedFile[]>({
    queryKey: ['files'],
    queryFn: api.listFiles,
  })

  // Extract date from filename - prioritize audit log date over upload timestamp
  function extractDateFromFilename(filename: string): Date | null {
    // Look for ISO date format: YYYY-MM-DD (with hyphens)
    const isoMatch = filename.match(/(\d{4})-(\d{2})-(\d{2})/)
    if (isoMatch) {
      const [, year, month, day] = isoMatch
      return new Date(`${year}-${month}-${day}`)
    }
    
    // If no ISO date, try compact format YYYYMMDD after "audit" or "vault"
    const logDateMatch = filename.match(/(?:audit|vault)[._](\d{4})(\d{2})(\d{2})/)
    if (logDateMatch) {
      const [, year, month, day] = logDateMatch
      return new Date(`${year}-${month}-${day}`)
    }
    
    return null
  }

  // Determine which file types to show based on selected command/subcommand
  const getAcceptedFileTypes = (): string[] => {
    // kv-analysis compare needs CSV files
    if (selectedCommand === 'kv-analysis' && selectedSubcommand === 'compare') {
      return ['.csv']
    }
    // Default: audit log files
    return ['.log', '.gz', '.zst', '.json']
  }

  // Filter and sort existing files
  const sortedExistingFiles = [...existingFiles]
    .filter(f => {
      const acceptedTypes = getAcceptedFileTypes()
      return acceptedTypes.some(ext => f.filename.toLowerCase().endsWith(ext))
    })
    .sort((a, b) => {
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

  // Pre-load a file passed via navigation state from the Files page.
  useEffect(() => {
    if (preloadFile) {
      setUploadedFiles(prev => {
        if (prev.some(f => f.path === preloadFile.path)) return prev
        return [...prev, { filename: preloadFile.filename, path: preloadFile.path, size: preloadFile.size }]
      })
    }
  }, [preloadFile?.path])

  const selectedCluster = clusters.find((c: Cluster) => c.id === selectedClusterId)

  // When a Vault API command is selected and a cluster is chosen, pre-fill --vault-addr
  useEffect(() => {
    if (isVaultApiCommand && selectedCluster) {
      const flag = `--vault-addr ${selectedCluster.vault_addr}`
      if (!extraFlags.includes('--vault-addr')) {
        setExtraFlags(prev => prev ? `${prev} ${flag}` : flag)
      }
    }
  }, [selectedClusterId, selectedCommand])

  const subcommands = COMMANDS_WITH_SUBCOMMANDS[selectedCommand] ?? []
  const needsSubcommand = subcommands.length > 0
  const isVaultApiCommand = VAULT_API_COMMANDS.has(selectedCommand)

  const uploadMutation = useMutation({
    mutationFn: api.uploadLog,
    onSuccess: data => {
      setUploadedFiles(prev => [...prev, data])
      setUploadError('')
    },
    onError: err => {
      setUploadError(`Upload failed: ${err instanceof Error ? err.message : 'Unknown error'}`)
    },
  })

  const submitMutation = useMutation({
    mutationFn: ({
      command,
      subcommand,
      files,
      args,
      clusterId,
    }: {
      command: string
      subcommand: string
      files: string[]
      args: string[]
      clusterId?: string
    }) => api.submitJob(command, subcommand, files, args, clusterId),
    onSuccess: data => {
      navigate(`/jobs/${data.id}`)
    },
  })

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(e.type === 'dragenter' || e.type === 'dragover')
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    Array.from(e.dataTransfer.files).forEach(f => uploadMutation.mutate(f))
  }

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    Array.from(e.currentTarget.files ?? []).forEach(f => uploadMutation.mutate(f))
  }

  const removeUploadedFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleCommandSelect = (cmd: string) => {
    setSelectedCommand(cmd)
    setSelectedSubcommand('')
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedCommand) return
    if (needsSubcommand && !selectedSubcommand) {
      alert(`Please select a subcommand for ${selectedCommand}`)
      return
    }

    // Files: server-side paths from uploads
    const files = uploadedFiles.map(f => f.path)

    // Extra CLI flags, split on whitespace
    const args = extraFlags.trim() ? extraFlags.trim().split(/\s+/) : []

    submitMutation.mutate({ command: selectedCommand, subcommand: selectedSubcommand, files, args, clusterId: selectedClusterId || undefined })
  }

  const canSubmit =
    selectedCommand &&
    (!needsSubcommand || selectedSubcommand) &&
    (isVaultApiCommand || uploadedFiles.length > 0) &&
    !submitMutation.isPending

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-slate-100">Analysis</h1>
        <p className="text-gray-600 dark:text-slate-400 mt-2">
          {preloadFile
            ? <>Using <span className="font-mono text-gray-800 dark:text-slate-200">{preloadFile.filename}</span> · select a command and run</>
            : 'Select a command, upload log files, then run'}
        </p>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Command list */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-slate-100">Commands</h2>
          <div className="bg-white dark:bg-slate-900 rounded-lg shadow divide-y divide-gray-100">
            {(commands.length > 0 ? commands : Object.keys(COMMANDS_WITH_SUBCOMMANDS).map(k => ({ name: k, description: '' }))).map((cmd: Command) => (
              <button
                key={cmd.name}
                onClick={() => handleCommandSelect(cmd.name)}
                className={`w-full text-left px-4 py-3 transition-colors ${
                  selectedCommand === cmd.name
                    ? 'bg-indigo-600 text-white'
                    : 'hover:bg-gray-50 dark:hover:bg-slate-700/50 dark:bg-slate-800 text-gray-900 dark:text-slate-100'
                }`}
              >
                <p className="font-medium text-sm">{cmd.name}</p>
                {cmd.description && (
                  <p className={`text-xs mt-0.5 ${selectedCommand === cmd.name ? 'text-indigo-200' : 'text-gray-500 dark:text-slate-400'}`}>
                    {cmd.description}
                  </p>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Form */}
        <div className="col-span-2 space-y-6">
          {/* Command/Subcommand Info Panel */}
          {selectedCommand && (() => {
            const cmdMeta = getCommandMetadata(selectedCommand)
            const subMeta = selectedSubcommand ? getSubcommandMetadata(selectedCommand, selectedSubcommand) : null
            const displayMeta = subMeta || cmdMeta
            
            if (!displayMeta) return null
            
            return (
              <div className="bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0 mt-0.5">
                    <svg className="h-5 w-5 text-indigo-600 dark:text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold text-indigo-900 dark:text-indigo-200 mb-1">
                      {subMeta ? `${selectedCommand} ${selectedSubcommand}` : selectedCommand}
                    </h3>
                    <p className="text-sm text-indigo-800 dark:text-indigo-300 mb-3">
                      {displayMeta.description}
                    </p>
                    
                    {displayMeta.flags && displayMeta.flags.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-xs font-semibold text-indigo-900 dark:text-indigo-200 uppercase tracking-wide">Available Flags:</p>
                        <div className="space-y-1.5">
                          {displayMeta.flags.map(flag => (
                            <div key={flag.name} className="text-xs">
                              <code className="font-mono text-indigo-700 dark:text-indigo-300 font-semibold">{flag.name}</code>
                              {flag.required && <span className="ml-1 text-red-600 dark:text-red-400 font-semibold">*</span>}
                              <span className="text-indigo-600 dark:text-indigo-400 ml-2">{flag.description}</span>
                              {flag.default && (
                                <span className="text-indigo-500 dark:text-indigo-500 ml-1">(default: {flag.default})</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {displayMeta.example && (
                      <div className="mt-3 pt-3 border-t border-indigo-200 dark:border-indigo-800">
                        <p className="text-xs font-semibold text-indigo-900 dark:text-indigo-200 uppercase tracking-wide mb-1">Example:</p>
                        <code className="block text-xs font-mono bg-indigo-100 dark:bg-indigo-900/50 text-indigo-800 dark:text-indigo-200 p-2 rounded overflow-x-auto">
                          {displayMeta.example}
                        </code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })()}

          {/* Subcommand selector */}
          {needsSubcommand && (
            <div className="bg-white dark:bg-slate-900 rounded-lg shadow p-4">
              <label className="block text-sm font-medium text-gray-900 dark:text-slate-100 mb-3">
                Subcommand <span className="text-red-500">*</span>
              </label>
              <div className="flex flex-wrap gap-2">
                {subcommands.map(sub => (
                  <button
                    key={sub}
                    type="button"
                    onClick={() => setSelectedSubcommand(sub)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      selectedSubcommand === sub
                        ? 'bg-indigo-600 text-white'
                        : 'bg-gray-100 dark:bg-slate-800 text-gray-700 hover:bg-gray-200 dark:bg-slate-700'
                    }`}
                  >
                    {sub}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Upload area (not shown for Vault API commands) */}
          {!isVaultApiCommand && (
            <>
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                  dragActive
                    ? 'border-indigo-600 bg-indigo-50'
                    : 'border-gray-300 bg-white dark:bg-slate-900 hover:border-gray-400'
                }`}
              >
                <svg className="mx-auto h-10 w-10 text-gray-400 dark:text-slate-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 13h6m-3-3v6m5 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p className="text-gray-700 dark:text-slate-300 font-medium">Drop audit log files here</p>
                <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">Supports .json, .log, .gz, .zst</p>
                <label className="mt-4 inline-block cursor-pointer">
                  <span className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors text-sm font-medium">
                    Browse files
                  </span>
                  <input
                    type="file"
                    multiple
                    onChange={handleFileInputChange}
                    className="hidden"
                  />
                </label>
                {uploadMutation.isPending && (
                  <p className="text-indigo-600 text-sm mt-3">Uploading…</p>
                )}
                {uploadError && <p className="text-red-600 text-sm mt-2">{uploadError}</p>}
              </div>

              {/* Pick from already-uploaded files */}
              {existingFiles.length > 0 && (
                <div>
                  <button
                    type="button"
                    onClick={() => setShowFilePicker(v => !v)}
                    className="text-sm text-indigo-600 hover:text-indigo-800 font-medium flex items-center gap-1"
                  >
                    {showFilePicker ? '▾' : '▸'} Pick from previously uploaded files ({existingFiles.length})
                  </button>
                  {showFilePicker && (
                    <div className="mt-2 border border-gray-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-900 divide-y divide-gray-50 dark:divide-slate-800 max-h-96 overflow-y-auto shadow-sm">
                      {sortedExistingFiles.map(f => {
                        const alreadyAdded = uploadedFiles.some(u => u.path === f.path)
                        return (
                          <div key={f.filename} className="px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-slate-700/50 dark:bg-slate-800">
                            <div className="flex items-center justify-between">
                              <div className="min-w-0 flex-1">
                                <p className="text-sm font-mono text-gray-800 dark:text-slate-200 truncate">{f.filename}</p>
                                <p className="text-xs text-gray-400 dark:text-slate-500">{(f.size / 1024).toFixed(1)} KB · {new Date(f.created_at).toLocaleDateString()}</p>
                              </div>
                              <button
                                type="button"
                                onClick={() => {
                                  if (!alreadyAdded) {
                                    setUploadedFiles(prev => [...prev, { filename: f.filename, path: f.path, size: f.size }])
                                  }
                                }}
                                disabled={alreadyAdded}
                                className={`ml-4 text-xs px-3 py-1 rounded font-medium shrink-0 transition-colors ${
                                  alreadyAdded
                                    ? 'text-green-700 bg-green-50 dark:bg-green-900/30 dark:text-green-400 border border-green-200 dark:border-green-800 cursor-default'
                                    : 'text-indigo-700 bg-indigo-50 dark:bg-indigo-900/30 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/50'
                                }`}
                              >
                                {alreadyAdded ? '✓ Added' : '+ Add'}
                              </button>
                            </div>
                            <FileMetadataPanel file={f} />
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Uploaded file list */}
              {uploadedFiles.length > 0 && (
                <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                  <p className="font-semibold text-green-900 text-sm mb-2">
                    {uploadedFiles.length} file{uploadedFiles.length !== 1 ? 's' : ''} ready
                  </p>
                  <ul className="space-y-1">
                    {uploadedFiles.map((f, i) => (
                      <li key={i} className="flex items-center justify-between text-sm">
                        <span className="font-mono text-green-800 truncate">
                          {f.filename} <span className="text-green-600">({(f.size / 1024).toFixed(1)} KB)</span>
                        </span>
                        <button
                          type="button"
                          onClick={() => removeUploadedFile(i)}
                          className="ml-2 text-green-600 hover:text-red-600 transition-colors flex-shrink-0"
                          title="Remove"
                        >
                          ✕
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          {/* Vault API notice + cluster picker */}
          {isVaultApiCommand && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 space-y-3 text-sm text-amber-800">
              <p><strong>{selectedCommand}</strong> queries the Vault API directly.</p>
              {clusters.length > 0 ? (
                <div>
                  <label className="block text-xs font-medium text-amber-700 mb-1">Target cluster</label>
                  <select
                    value={selectedClusterId}
                    onChange={e => setSelectedClusterId(e.target.value)}
                    className="border border-amber-300 rounded px-2 py-1.5 text-sm bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-amber-400 w-full"
                  >
                    <option value="">— select a cluster or enter flags manually —</option>
                    {clusters.map((c: Cluster) => (
                      <option key={c.id} value={c.id}>{c.name} ({c.vault_addr})</option>
                    ))}
                  </select>
                  {selectedCluster && (
                    <p className="text-xs text-amber-600 mt-1">
                      Will add <span className="font-mono">--vault-addr {selectedCluster.vault_addr}</span> automatically.
                    </p>
                  )}
                </div>
              ) : (
                <p>No clusters registered — add one on the <strong>Clusters</strong> page or enter <span className="font-mono">--vault-addr</span> manually below.</p>
              )}
            </div>
          )}

          {/* Submit form */}
          <form onSubmit={handleSubmit} className="bg-white dark:bg-slate-900 rounded-lg shadow p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-slate-100 mb-2">
                Additional flags <span className="text-gray-400 dark:text-slate-500 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                value={extraFlags}
                onChange={e => setExtraFlags(e.target.value)}
                placeholder="--top 20 --min-operations 500"
                className="w-full px-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg font-mono text-sm bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-200 placeholder:text-gray-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-indigo-600 focus:border-transparent"
              />
            </div>

            <button
              type="submit"
              disabled={!canSubmit}
              className="w-full px-6 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {submitMutation.isPending
                ? 'Submitting…'
                : !selectedCommand
                ? 'Select a command'
                : needsSubcommand && !selectedSubcommand
                ? 'Select a subcommand'
                : !isVaultApiCommand && uploadedFiles.length === 0
                ? 'Upload at least one log file'
                : 'Run Analysis'}
            </button>

            {submitMutation.isError && (
              <div className="bg-red-50 border border-red-200 rounded p-3">
                <p className="text-sm text-red-800">
                  {submitMutation.error instanceof Error
                    ? submitMutation.error.message
                    : 'Failed to submit job'}
                </p>
              </div>
            )}
          </form>
        </div>
      </div>
    </div>
  )
}
