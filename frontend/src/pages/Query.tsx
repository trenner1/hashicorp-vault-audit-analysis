import { useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, Cluster, UploadResult } from '../api/client'

const EXAMPLE_QUESTIONS = [
  'What are the most accessed paths in the last 24 hours?',
  'Show me an overview of all operations and auth methods',
  'Which tokens are being used most heavily?',
  'Are there any suspicious token lookups or abuse patterns?',
  'Which Kubernetes service accounts are generating the most traffic?',
  'Show me KV secret usage broken down by path',
  'Which entities were created most recently and by which auth methods?',
  'Are there any Airflow jobs polling secrets too frequently?',
]

export default function Query() {
  const navigate = useNavigate()
  const [question, setQuestion] = useState('')
  const [selectedClusterId, setSelectedClusterId] = useState<string>('')
  const [uploadedFiles, setUploadedFiles] = useState<UploadResult[]>([])
  const [uploadingCount, setUploadingCount] = useState(0)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const { data: clusters = [] } = useQuery<Cluster[]>({
    queryKey: ['clusters'],
    queryFn: api.listClusters,
  })

  const queryMutation = useMutation({
    mutationFn: () =>
      api.query({
        question,
        files: uploadedFiles.map(f => f.path),
        cluster_id: selectedClusterId || undefined,
      }),
    onSuccess: data => {
      navigate(`/jobs/${data.job_id}`, { state: { queryResult: data } })
    },
  })

  const uploadFile = useCallback(async (file: File) => {
    setUploadingCount(c => c + 1)
    try {
      const result = await api.uploadLog(file)
      setUploadedFiles(prev => [...prev, result])
    } catch (e) {
      console.error('Upload failed', e)
    } finally {
      setUploadingCount(c => c - 1)
    }
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      Array.from(e.dataTransfer.files).forEach(uploadFile)
    },
    [uploadFile]
  )

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      Array.from(e.target.files ?? []).forEach(uploadFile)
      e.target.value = ''
    },
    [uploadFile]
  )

  const removeFile = (path: string) =>
    setUploadedFiles(prev => prev.filter(f => f.path !== path))

  const canSubmit =
    question.trim().length > 0 &&
    !queryMutation.isPending &&
    uploadingCount === 0

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-slate-100">Ask a Question</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">
          Describe what you want to know in plain English. Claude will choose
          the right vault-audit command and run it automatically.
        </p>
      </div>

      {/* Question input */}
      <div className="bg-white dark:bg-slate-900 shadow rounded-lg p-6 space-y-4">
        <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">
          Your question
        </label>
        <textarea
          rows={4}
          value={question}
          onChange={e => setQuestion(e.target.value)}
          placeholder="e.g. Which paths are accessed most often, and are there any signs of token abuse?"
          className="w-full border border-gray-300 dark:border-slate-600 rounded-md px-3 py-2 text-sm bg-white dark:bg-slate-800 text-gray-900 dark:text-slate-200 placeholder:text-gray-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
        />

        {/* Example questions */}
        <div>
          <p className="text-xs font-medium text-gray-500 dark:text-slate-400 mb-2">Examples</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLE_QUESTIONS.map(q => (
              <button
                key={q}
                onClick={() => setQuestion(q)}
                className="text-xs bg-gray-100 dark:bg-slate-800 hover:bg-indigo-50 dark:hover:bg-slate-700/50 hover:text-indigo-700 dark:hover:text-indigo-400 text-gray-600 dark:text-slate-400 px-2 py-1 rounded border border-gray-200 dark:border-slate-700 hover:border-indigo-300 dark:hover:border-indigo-500 transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cluster selector */}
      {clusters.length > 0 && (
        <div className="bg-white dark:bg-slate-900 shadow rounded-lg p-6 space-y-2">
          <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">
            Target cluster{' '}
            <span className="font-normal text-gray-400 dark:text-slate-500">(optional — for live-cluster questions)</span>
          </label>
          <select
            value={selectedClusterId}
            onChange={e => setSelectedClusterId(e.target.value)}
            className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-900"
          >
            <option value="">— none (log-file analysis only) —</option>
            {clusters.map((c: Cluster) => (
              <option key={c.id} value={c.id}>{c.name} — {c.vault_addr}</option>
            ))}
          </select>
          {selectedClusterId && (
            <p className="text-xs text-indigo-600">
              The AI will prefer live-cluster commands and pass the cluster's Vault address automatically.
            </p>
          )}
        </div>
      )}

      {/* Log file upload */}
      <div className="bg-white dark:bg-slate-900 shadow rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-gray-700 dark:text-slate-300">
            Log files{' '}
            <span className="font-normal text-gray-400 dark:text-slate-500">(optional for live-cluster questions)</span>
          </label>
          {uploadedFiles.length > 0 && (
            <span className="text-xs text-gray-400 dark:text-slate-500">{uploadedFiles.length} file(s)</span>
          )}
        </div>

        {/* Drop zone */}
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
            dragOver
              ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-900/20'
              : 'border-gray-300 dark:border-slate-600 hover:border-indigo-300 hover:bg-gray-50 dark:hover:bg-indigo-900/10 dark:bg-slate-800'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept=".log,.json,.jsonl,.txt"
            className="hidden"
            onChange={handleFileChange}
          />
          {uploadingCount > 0 ? (
            <p className="text-sm text-indigo-600 animate-pulse">Uploading…</p>
          ) : (
            <>
              <svg className="mx-auto h-10 w-10 text-gray-300 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                  d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
              </svg>
              <p className="text-sm text-gray-500 dark:text-slate-400">
                Drop Vault audit log files here, or <span className="text-indigo-600 font-medium">click to browse</span>
              </p>
              <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">.log · .json · .jsonl · .txt</p>
            </>
          )}
        </div>

        {/* Uploaded file list */}
        {uploadedFiles.length > 0 && (
          <ul className="space-y-2">
            {uploadedFiles.map(f => (
              <li key={f.path} className="flex items-center justify-between bg-gray-50 dark:bg-slate-800 rounded px-3 py-2 text-sm">
                <span className="font-medium text-gray-700 dark:text-slate-300 truncate">{f.filename}</span>
                <div className="flex items-center gap-3 ml-3 shrink-0">
                  <span className="text-gray-400 dark:text-slate-500 text-xs">{(f.size / 1024).toFixed(1)} KB</span>
                  <button
                    onClick={e => { e.stopPropagation(); removeFile(f.path) }}
                    className="text-gray-400 dark:text-slate-500 hover:text-red-500 transition-colors"
                    title="Remove"
                  >
                    ✕
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Error */}
      {queryMutation.isError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
          <strong>Error: </strong>
          {queryMutation.error instanceof Error
            ? queryMutation.error.message
            : 'Query failed'}
        </div>
      )}

      {/* Submit */}
      <div className="flex justify-end">
        <button
          onClick={() => queryMutation.mutate()}
          disabled={!canSubmit}
          className="inline-flex items-center gap-2 px-6 py-2.5 bg-indigo-600 text-white text-sm font-medium rounded-lg shadow hover:bg-indigo-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {queryMutation.isPending ? (
            <>
              <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Thinking…
            </>
          ) : (
            <>
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              Run Query
            </>
          )}
        </button>
      </div>
    </div>
  )
}
