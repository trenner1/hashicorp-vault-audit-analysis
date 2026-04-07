import { useRef, useState } from 'react'
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
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null)
  const [deletingFile, setDeletingFile] = useState<string | null>(null)

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

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setUploadError(null)
    setUploadSuccess(null)
    setUploading(true)

    try {
      const result = await api.uploadLog(file)
      setUploadSuccess(`Uploaded: ${result.filename} (${formatBytes(result.size)})`)
      queryClient.invalidateQueries({ queryKey: ['files'] })
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
      // Reset file input so the same file can be re-uploaded
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
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
              Uploading…
            </>
          ) : (
            <>↑ Upload File</>
          )}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept=".log,.json,.txt,.gz"
          onChange={handleUpload}
        />
      </div>

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
          if (!file || !fileInputRef.current) return
          const dt = new DataTransfer()
          dt.items.add(file)
          fileInputRef.current.files = dt.files
          handleUpload({ target: fileInputRef.current } as React.ChangeEvent<HTMLInputElement>)
        }}
      >
        <div className="text-4xl mb-3">📁</div>
        <p className="text-sm font-medium text-gray-700">Drop a log file here, or click to browse</p>
        <p className="text-xs text-gray-400 mt-1">Supported: .log · .json · .txt · .gz · up to 2 GB</p>
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
