import { useRef, useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api, UploadedFile } from '../api/client'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export function Files() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0) // 0-100
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null)
  const [deletingFile, setDeletingFile] = useState<string | null>(null)
  const [tabWarning, setTabWarning] = useState(false)

  // Show a warning banner when the user switches away during an upload
  useEffect(() => {
    if (!uploading) { setTabWarning(false); return }
    const handleVisibility = () => setTabWarning(document.hidden)
    document.addEventListener('visibilitychange', handleVisibility)
    return () => document.removeEventListener('visibilitychange', handleVisibility)
  }, [uploading])

  const { data: files = [], isLoading, refetch } = useQuery<UploadedFile[]>({
    queryKey: ['files'],
    queryFn: api.listFiles,
  })

  const deleteMutation = useMutation({
    mutationFn: (filename: string) => api.deleteFile(filename),
    onMutate: (filename) => setDeletingFile(filename),
    onSettled: () => setDeletingFile(null),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['files'] }),
  })

  const uploadFile = async (file: File) => {
    setUploadError(null)
    setUploadSuccess(null)
    setUploading(true)
    setUploadProgress(0)

    // Warn if the user tries to close/navigate away mid-upload
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', handleBeforeUnload)

    const doUpload = () => new Promise<{ filename: string; path: string; size: number }>((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('POST', `${(import.meta.env.VITE_API_URL ?? '')}/api/v1/ingest/upload`)

      const apiKey = import.meta.env.VITE_API_KEY
      if (apiKey) xhr.setRequestHeader('X-API-Key', apiKey)

      xhr.upload.onprogress = e => {
        if (e.lengthComputable) setUploadProgress(Math.round((e.loaded / e.total) * 100))
      }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try { resolve(JSON.parse(xhr.responseText)) }
          catch { reject(new Error('Invalid server response')) }
        } else {
          try { reject(new Error(JSON.parse(xhr.responseText).error || xhr.statusText)) }
          catch { reject(new Error(xhr.statusText)) }
        }
      }
      xhr.onerror = () => reject(new Error('Network error during upload'))
      xhr.onabort = () => reject(new Error('Upload cancelled'))

      const fd = new FormData()
      fd.append('file', file)
      xhr.send(fd)
    })

    try {
      // navigator.locks keeps the tab alive (prevents browser tab-freeze) for
      // the duration of the upload, so switching away doesn't kill the transfer.
      let result: { filename: string; path: string; size: number }
      if ('locks' in navigator) {
        await navigator.locks.request('file-upload', async () => {
          result = await doUpload()
        })
      } else {
        result = await doUpload()
      }
      setUploadSuccess(`Uploaded: ${result!.filename} (${formatBytes(result!.size)})`)
      queryClient.invalidateQueries({ queryKey: ['files'] })
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      window.removeEventListener('beforeunload', handleBeforeUnload)
      setUploading(false)
      setUploadProgress(0)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) uploadFile(file)
  }

  const totalSize = files.reduce((sum, f) => sum + f.size, 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Uploaded Files</h1>
          <p className="text-gray-500 mt-1 text-sm">
            Log files available for analysis
            {files.length > 0 && ` · ${files.length} file${files.length !== 1 ? 's' : ''} · ${formatBytes(totalSize)} total`}
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
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {uploadProgress > 0 ? `${uploadProgress}%` : 'Uploading…'}
            </>
          ) : (
            <>↑ Upload File</>
          )}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleInputChange}
        />
      </div>

      {/* Tab-switch warning during upload */}
      {uploading && tabWarning && (
        <div className="bg-amber-50 border border-amber-300 rounded-lg px-4 py-3 flex items-center gap-3">
          <span className="text-amber-500 text-lg">⚠️</span>
          <p className="text-sm text-amber-800 font-medium">
            Upload in progress — keep this tab open until it completes ({uploadProgress}%)
          </p>
        </div>
      )}

      {/* Upload feedback */}
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

      {/* Drop zone hint */}
      <div
        className="border-2 border-dashed border-gray-300 rounded-xl p-8 text-center hover:border-indigo-400 hover:bg-indigo-50 transition-colors cursor-pointer"
        onClick={() => fileInputRef.current?.click()}
        onDragOver={e => e.preventDefault()}
        onDrop={e => {
          e.preventDefault()
          const file = e.dataTransfer.files?.[0]
          if (file) uploadFile(file)
        }}
      >
        <div className="text-4xl mb-3">📁</div>
        <p className="text-sm font-medium text-gray-700">Drop a log file here, or click to browse</p>
        <p className="text-xs text-gray-400 mt-1">Any format accepted · no size limit</p>
        {uploading && (
          <div className="mt-4 w-full max-w-xs mx-auto" onClick={e => e.stopPropagation()}>
            <div className="flex justify-between text-xs text-gray-500 mb-1">
              <span>Uploading…</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-indigo-500 h-2 rounded-full transition-all duration-200"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* File table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">
            {isLoading ? 'Loading…' : `${files.length} file${files.length !== 1 ? 's' : ''}`}
          </h2>
          <button
            onClick={() => refetch()}
            className="text-xs text-indigo-600 hover:text-indigo-800 font-medium"
          >
            Refresh
          </button>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-gray-400 text-sm animate-pulse">Loading files…</div>
        ) : files.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-gray-400 text-sm">No files uploaded yet.</p>
            <p className="text-gray-400 text-xs mt-1">Upload a Vault audit log above to get started.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                <th className="px-6 py-3">Filename</th>
                <th className="px-6 py-3">Size</th>
                <th className="px-6 py-3">Uploaded</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {files.map(file => (
                <tr key={file.filename} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl leading-none">
                        {file.filename.endsWith('.gz') ? '🗜️'
                          : file.filename.endsWith('.json') ? '📄'
                          : '📃'}
                      </span>
                      <div>
                        <p className="text-sm font-medium text-gray-900 font-mono">{file.filename}</p>
                        <p className="text-xs text-gray-400 font-mono truncate max-w-xs">{file.path}</p>
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
                      {/* Use in analysis */}
                      <button
                        onClick={() => navigate('/analysis', {
                          state: { preloadFile: file },
                        })}
                        className="text-xs px-3 py-1 rounded border border-indigo-300 text-indigo-700 bg-indigo-50 hover:bg-indigo-100 font-medium transition-colors whitespace-nowrap"
                      >
                        Use in Analysis
                      </button>
                      {/* Delete */}
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete "${file.filename}"?`)) {
                            deleteMutation.mutate(file.filename)
                          }
                        }}
                        disabled={deletingFile === file.filename}
                        className="text-xs text-gray-400 hover:text-red-500 disabled:opacity-40 transition-colors"
                        title="Delete file"
                      >
                        {deletingFile === file.filename ? '…' : '🗑'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
