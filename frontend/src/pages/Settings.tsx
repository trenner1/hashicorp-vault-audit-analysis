import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, SystemInfo } from '../api/client'

const API_BASE = import.meta.env.VITE_API_URL || '(same origin)'
const API_KEY_SET = !!(import.meta.env.VITE_API_KEY)

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full flex-shrink-0 ${ok ? 'bg-green-500' : 'bg-red-400'}`}
    />
  )
}

function InfoRow({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-gray-100 last:border-0">
      <span className="text-sm text-gray-500 w-44 shrink-0">{label}</span>
      <span className={`text-sm text-gray-900 text-right ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export function Settings() {
  const queryClient = useQueryClient()
  const [pruneHours, setPruneHours] = useState(24)
  const [pruneResult, setPruneResult] = useState<string | null>(null)

  const { data: info, isLoading, isError, refetch } = useQuery<SystemInfo>({
    queryKey: ['system'],
    queryFn: api.systemInfo,
    refetchInterval: 15_000,
  })

  const pruneMutation = useMutation({
    mutationFn: () => api.pruneJobs(pruneHours),
    onSuccess: data => {
      setPruneResult(`Deleted ${data.deleted} job${data.deleted !== 1 ? 's' : ''} older than ${pruneHours}h`)
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      queryClient.invalidateQueries({ queryKey: ['system'] })
    },
    onError: err => {
      setPruneResult(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`)
    },
  })

  const totalJobs = info
    ? Object.values(info.jobs).reduce((a, b) => a + b, 0)
    : 0

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500 mt-1 text-sm">System status, configuration, and maintenance</p>
      </div>

      {/* ── Server Status ─────────────────────────────────────── */}
      <section className="bg-white rounded-lg shadow divide-y divide-gray-100">
        <div className="px-6 py-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Server Status</h2>
          <button
            onClick={() => refetch()}
            className="text-xs text-indigo-600 hover:text-indigo-800 font-medium"
          >
            Refresh
          </button>
        </div>

        <div className="px-6 py-4">
          {isLoading && (
            <p className="text-sm text-gray-400 animate-pulse">Loading system info…</p>
          )}
          {isError && (
            <p className="text-sm text-red-600">Could not reach server — is the API running?</p>
          )}
          {info && (
            <div className="space-y-0">
              <InfoRow
                label="Server"
                value={
                  <span className="flex items-center gap-2 justify-end">
                    <StatusDot ok={true} />
                    Online
                  </span>
                }
              />
              <InfoRow label="Version" value={info.version} mono />
              <InfoRow label="Uptime" value={formatUptime(info.uptime_seconds)} mono />
              <InfoRow label="API base URL" value={API_BASE} mono />
              <InfoRow
                label="API authentication"
                value={
                  <span className="flex items-center gap-2 justify-end">
                    <StatusDot ok={info.auth_enabled} />
                    {info.auth_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                }
              />
              <InfoRow
                label="Frontend API key"
                value={
                  <span className="flex items-center gap-2 justify-end">
                    <StatusDot ok={API_KEY_SET} />
                    {API_KEY_SET ? 'Set (VITE_API_KEY)' : 'Not set'}
                  </span>
                }
              />
              <InfoRow
                label="AI query (Anthropic)"
                value={
                  <span className="flex items-center gap-2 justify-end">
                    <StatusDot ok={info.anthropic_enabled} />
                    {info.anthropic_enabled ? 'Enabled' : 'Disabled — set ANTHROPIC_API_KEY'}
                  </span>
                }
              />
              <InfoRow label="Upload directory" value={info.upload_dir} mono />
              <InfoRow
                label="Max concurrent jobs"
                value={info.max_concurrent === 0 ? 'Unlimited' : String(info.max_concurrent)}
                mono
              />
            </div>
          )}
        </div>
      </section>

      {/* ── Job Statistics ────────────────────────────────────── */}
      {info && (
        <section className="bg-white rounded-lg shadow divide-y divide-gray-100">
          <div className="px-6 py-4">
            <h2 className="text-base font-semibold text-gray-900">Job Statistics</h2>
          </div>
          <div className="px-6 py-4">
            <div className="grid grid-cols-5 gap-3">
              {(
                [
                  { key: 'running', label: 'Running', color: 'text-blue-600 bg-blue-50' },
                  { key: 'pending', label: 'Pending', color: 'text-yellow-700 bg-yellow-50' },
                  { key: 'done', label: 'Done', color: 'text-green-700 bg-green-50' },
                  { key: 'error', label: 'Error', color: 'text-red-700 bg-red-50' },
                  { key: 'cancelled', label: 'Cancelled', color: 'text-gray-600 bg-gray-100' },
                ] as const
              ).map(({ key, label, color }) => (
                <div key={key} className={`rounded-lg p-3 text-center ${color}`}>
                  <p className="text-2xl font-bold">{info.jobs[key] ?? 0}</p>
                  <p className="text-xs font-medium mt-0.5">{label}</p>
                </div>
              ))}
            </div>
            <p className="text-xs text-gray-400 mt-3 text-right">{totalJobs} total jobs in memory</p>
          </div>
        </section>
      )}

      {/* ── Job Retention ─────────────────────────────────────── */}
      <section className="bg-white rounded-lg shadow divide-y divide-gray-100">
        <div className="px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Job Retention</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Remove completed, errored, and cancelled jobs to free up memory and disk space.
            Running and pending jobs are never deleted.
          </p>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div className="flex items-center gap-4">
            <label className="text-sm font-medium text-gray-700 shrink-0">
              Delete jobs older than
            </label>
            <select
              value={pruneHours}
              onChange={e => setPruneHours(Number(e.target.value))}
              className="border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white"
            >
              <option value={1}>1 hour</option>
              <option value={6}>6 hours</option>
              <option value={12}>12 hours</option>
              <option value={24}>24 hours (default)</option>
              <option value={48}>2 days</option>
              <option value={168}>7 days</option>
              <option value={720}>30 days</option>
            </select>
            <button
              onClick={() => {
                setPruneResult(null)
                pruneMutation.mutate()
              }}
              disabled={pruneMutation.isPending}
              className="px-4 py-1.5 bg-red-600 text-white text-sm font-medium rounded-md hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {pruneMutation.isPending ? 'Pruning…' : 'Prune Now'}
            </button>
          </div>

          {pruneResult && (
            <p className={`text-sm font-medium ${pruneResult.startsWith('Error') ? 'text-red-600' : 'text-green-700'}`}>
              {pruneResult}
            </p>
          )}
        </div>
      </section>

      {/* ── Environment Variables Reference ───────────────────── */}
      <section className="bg-white rounded-lg shadow divide-y divide-gray-100">
        <div className="px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Environment Variables</h2>
          <p className="text-sm text-gray-500 mt-0.5">Server-side variables (set in docker-compose.yml or shell)</p>
        </div>
        <div className="px-6 py-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs font-medium text-gray-400 uppercase tracking-wide">
                <th className="pb-2 pr-4">Variable</th>
                <th className="pb-2 pr-4">Default</th>
                <th className="pb-2">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {[
                { name: 'PORT', def: '8080', desc: 'HTTP listen port' },
                { name: 'VAULT_AUDIT_BINARY', def: './vault-audit', desc: 'Path to vault-audit binary' },
                { name: 'UPLOAD_DIR', def: './uploads', desc: 'Uploaded log file storage' },
                { name: 'DATA_DIR', def: './data', desc: 'Persistent job storage directory' },
                { name: 'MAX_CONCURRENT_JOBS', def: '5', desc: 'Max simultaneous running jobs (0 = unlimited)' },
                { name: 'API_KEY', def: '(none)', desc: 'Require X-API-Key / Bearer auth on all endpoints' },
                { name: 'ANTHROPIC_API_KEY', def: '(none)', desc: 'Enables AI query and summarization features' },
                { name: 'APP_VERSION', def: 'dev', desc: 'Version string shown in this panel' },
              ].map(row => (
                <tr key={row.name}>
                  <td className="py-2 pr-4 font-mono text-indigo-700 whitespace-nowrap">{row.name}</td>
                  <td className="py-2 pr-4 font-mono text-gray-500 whitespace-nowrap">{row.def}</td>
                  <td className="py-2 text-gray-600">{row.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-6 py-4 bg-gray-50 rounded-b-lg">
          <p className="text-xs font-medium text-gray-500 mb-1">Frontend (Vite build-time)</p>
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {[
                { name: 'VITE_API_URL', def: '(same origin)', desc: 'Override API base URL for remote backends' },
                { name: 'VITE_API_KEY', def: '(none)', desc: 'API key sent as X-API-Key header from browser' },
              ].map(row => (
                <tr key={row.name}>
                  <td className="py-2 pr-4 font-mono text-indigo-700 whitespace-nowrap">{row.name}</td>
                  <td className="py-2 pr-4 font-mono text-gray-500 whitespace-nowrap">{row.def}</td>
                  <td className="py-2 text-gray-600">{row.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
