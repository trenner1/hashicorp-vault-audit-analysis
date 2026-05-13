import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { api, Job } from '../api/client'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (h > 0) return `${h}h ${m}m`
  return `${Math.floor(seconds / 60)}m`
}

// ── Colour palette ────────────────────────────────────────────────
const STATUS_COLORS: Record<string, string> = {
  done: '#22c55e',
  running: '#6366f1',
  pending: '#94a3b8',
  error: '#ef4444',
}

const COMMAND_COLORS = [
  '#6366f1', '#8b5cf6', '#ec4899', '#f59e0b',
  '#10b981', '#3b82f6', '#f97316', '#14b8a6',
]

// ── Data helpers ──────────────────────────────────────────────────

/** Bucket jobs into hourly slots for the last 24 h. */
function buildTimeline(jobs: Job[]) {
  const now = Date.now()
  const slots: Record<string, { hour: string; done: number; error: number; running: number }> = {}

  for (let i = 23; i >= 0; i--) {
    const d = new Date(now - i * 3_600_000)
    const key = `${d.getHours().toString().padStart(2, '0')}:00`
    slots[key] = { hour: key, done: 0, error: 0, running: 0 }
  }

  jobs.forEach(job => {
    const d = new Date(job.created_at)
    if (now - d.getTime() > 24 * 3_600_000) return
    const key = `${d.getHours().toString().padStart(2, '0')}:00`
    if (!slots[key]) return
    const status = job.status === 'pending' ? 'running' : job.status
    if (status === 'done' || status === 'error' || status === 'running') {
      slots[key][status]++
    }
  })

  return Object.values(slots)
}

/** Count jobs by command, return top 8. */
function buildCommandBreakdown(jobs: Job[]) {
  const counts: Record<string, number> = {}
  jobs.forEach(j => { counts[j.command] = (counts[j.command] ?? 0) + 1 })
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([command, count]) => ({ command: command.replace(/-/g, '\u2011'), count }))
}

/** Count jobs by status for pie chart. */
function buildStatusBreakdown(jobs: Job[]) {
  const counts: Record<string, number> = { done: 0, error: 0, running: 0, pending: 0 }
  jobs.forEach(j => { counts[j.status] = (counts[j.status] ?? 0) + 1 })
  return Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))
}

// ── Stat card ─────────────────────────────────────────────────────
function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string
  value: string | number
  sub?: string
  accent?: string
}) {
  return (
    <div className={`bg-white dark:bg-slate-900 rounded-xl shadow-sm border-l-4 p-5 ${accent ?? 'border-indigo-500'}`}>
      <p className="text-xs font-semibold text-gray-500 dark:text-slate-400 uppercase tracking-wide">{label}</p>
      <p className="text-3xl font-bold text-gray-900 dark:text-slate-100 mt-1">{value}</p>
      {sub && <p className="text-xs text-gray-400 dark:text-slate-500 mt-1">{sub}</p>}
    </div>
  )
}

// ── Custom tooltip ────────────────────────────────────────────────
function ChartTooltip({ active, payload, label }: {
  active?: boolean
  payload?: Array<{ name: string; value: number; color: string }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg shadow-lg p-3 text-sm">
      {label && <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">{label}</p>}
      {payload.map(p => (
        <p key={p.name} style={{ color: p.color }}>
          {p.name}: <span className="font-bold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────
export function Dashboard() {
  const navigate = useNavigate()
  const [isDark, setIsDark] = useState(false)
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const [commandFilter, setCommandFilter] = useState<string | null>(null)

  useEffect(() => {
    // Check if dark mode is active
    const checkDarkMode = () => {
      setIsDark(document.documentElement.classList.contains('dark'))
    }
    checkDarkMode()
    
    // Watch for dark mode changes
    const observer = new MutationObserver(checkDarkMode)
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    
    return () => observer.disconnect()
  }, [])

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    staleTime: Infinity,
  })

  const { data: sysInfo } = useQuery({
    queryKey: ['system'],
    queryFn: api.systemInfo,
    refetchInterval: 30_000,
  })

  const { data: jobs = [], isLoading } = useQuery<Job[]>({
    queryKey: ['jobs'],
    queryFn: api.listJobs,
    // Poll every 3 s when jobs are active, stop when everything is terminal.
    refetchInterval: (query) => {
      const data = query.state.data ?? []
      return data.some((j: Job) => j.status === 'running' || j.status === 'pending') ? 3000 : false
    },
  })

  const { data: clusters = [] } = useQuery({
    queryKey: ['clusters'],
    queryFn: api.listClusters,
  })

  // Derived stats
  const total = jobs.length
  const running = jobs.filter(j => j.status === 'running' || j.status === 'pending').length
  const done = jobs.filter(j => j.status === 'done').length
  const errors = jobs.filter(j => j.status === 'error').length
  const successRate = total > 0 ? Math.round((done / (done + errors || 1)) * 100) : 0

  const timeline = buildTimeline(jobs)
  const commandData = buildCommandBreakdown(jobs)
  const statusData = buildStatusBreakdown(jobs)
  
  // Filter jobs based on selected status and command
  let filteredJobs = jobs
  if (statusFilter) {
    filteredJobs = filteredJobs.filter((j) =>
      statusFilter === 'running'
        ? j.status === 'running' || j.status === 'pending'
        : j.status === statusFilter
    )
  }
  if (commandFilter) {
    filteredJobs = filteredJobs.filter(j => j.command === commandFilter)
  }
  
  const recentJobs = [...filteredJobs]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 8)

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-slate-100">Dashboard</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-0.5">Vault Audit Analysis Platform</p>
        </div>
        <div className="flex items-center gap-4">
          {sysInfo && (
            <span className="text-xs text-gray-400 dark:text-slate-500 font-mono">
              v{sysInfo.version} · up {formatUptime(sysInfo.uptime_seconds)}
            </span>
          )}
          <div className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-full ${health ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className={`text-sm font-medium ${health ? 'text-green-700' : 'text-red-700'}`}>
              {health ? 'API healthy' : 'API unreachable'}
            </span>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Jobs" value={total} sub="all time" accent="border-indigo-500" />
        <StatCard label="Running" value={running} sub="active now" accent="border-blue-500" />
        <StatCard
          label="Success Rate"
          value={total === 0 ? '—' : `${successRate}%`}
          sub={`${done} done · ${errors} errors`}
          accent={successRate >= 90 ? 'border-green-500' : successRate >= 70 ? 'border-amber-500' : 'border-red-500'}
        />
        <StatCard
          label="Clusters"
          value={clusters.length}
          sub="registered"
          accent="border-purple-500"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-6">
        {/* Activity timeline — takes 2/3 */}
        <div className="col-span-2 bg-white dark:bg-slate-900 rounded-xl shadow-sm p-5">
          <h2 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-4">Job Activity — Last 24 Hours</h2>
          {isLoading ? (
            <div className="h-48 flex items-center justify-center text-gray-400 dark:text-slate-500 text-sm">Loading…</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradDone" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradError" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#334155' : '#f1f5f9'} />
                <XAxis
                  dataKey="hour"
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  tickLine={false}
                  axisLine={false}
                  interval={3}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: '#94a3b8' }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip content={<ChartTooltip />} />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 12, paddingTop: 8 }}
                />
                <Area
                  type="monotone"
                  dataKey="done"
                  name="Done"
                  stroke="#22c55e"
                  fill="url(#gradDone)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="error"
                  name="Error"
                  stroke="#ef4444"
                  fill="url(#gradError)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="running"
                  name="Running"
                  stroke="#6366f1"
                  fill="none"
                  strokeWidth={2}
                  strokeDasharray="4 2"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Status distribution — 1/3 */}
        <div className="bg-white dark:bg-slate-900 rounded-xl shadow-sm p-5">
          <h2 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-4">Status Distribution</h2>
          {statusData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-gray-400 dark:text-slate-500 text-sm">No jobs yet</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={statusData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                    onClick={(data: any) => {
                      if (!data || !data.name) return
                      const newFilter = statusFilter === data.name ? null : data.name
                      setStatusFilter(newFilter)
                      setCommandFilter(null) // Clear command filter when status is selected
                    }}
                    style={{ cursor: 'pointer' }}
                  >
                    {statusData.map((entry, i) => (
                      <Cell
                        key={i}
                        fill={STATUS_COLORS[entry.name] ?? '#94a3b8'}
                        opacity={statusFilter === null || statusFilter === entry.name ? 1 : 0.3}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1 mt-2">
                {statusData.map(d => (
                  <div
                    key={d.name}
                    className="flex items-center justify-between text-xs cursor-pointer hover:bg-gray-50 dark:hover:bg-slate-800 px-2 py-1 rounded transition-colors"
                    onClick={() => {
                      const newFilter = statusFilter === d.name ? null : d.name
                      setStatusFilter(newFilter)
                      setCommandFilter(null)
                    }}
                  >
                    <div className="flex items-center gap-1.5">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{
                          background: STATUS_COLORS[d.name] ?? '#94a3b8',
                          opacity: statusFilter === null || statusFilter === d.name ? 1 : 0.3
                        }}
                      />
                      <span
                        className="capitalize text-gray-600 dark:text-slate-400"
                        style={{ opacity: statusFilter === null || statusFilter === d.name ? 1 : 0.5 }}
                      >
                        {d.name}
                      </span>
                    </div>
                    <span
                      className="font-semibold text-gray-800 dark:text-slate-200"
                      style={{ opacity: statusFilter === null || statusFilter === d.name ? 1 : 0.5 }}
                    >
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Command breakdown */}
      {commandData.length > 0 && (
        <div className="bg-white dark:bg-slate-900 rounded-xl shadow-sm p-5">
          <h2 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-4">Jobs by Command</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={commandData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#334155' : '#f1f5f9'} vertical={false} />
              <XAxis
                dataKey="command"
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fontSize: 11, fill: '#94a3b8' }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<ChartTooltip />} />
              <Bar
                dataKey="count"
                name="Jobs"
                radius={[4, 4, 0, 0]}
                onClick={(data: any) => {
                  if (!data || !data.command) return
                  const cmd = data.command.replace(/\u2011/g, '-') // Convert back from non-breaking hyphen
                  const newFilter = commandFilter === cmd ? null : cmd
                  setCommandFilter(newFilter)
                  setStatusFilter(null) // Clear status filter when command is selected
                }}
                style={{ cursor: 'pointer' }}
              >
                {commandData.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={COMMAND_COLORS[i % COMMAND_COLORS.length]}
                    opacity={commandFilter === null || commandFilter === entry.command.replace(/\u2011/g, '-') ? 1 : 0.3}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent jobs */}
      <div className="bg-white dark:bg-slate-900 rounded-xl shadow-sm">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-gray-700 dark:text-slate-300">Recent Jobs</h2>
            {(statusFilter || commandFilter) && (
              <div className="flex items-center gap-2">
                {statusFilter && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300">
                    Status: {statusFilter}
                    <button
                      onClick={() => setStatusFilter(null)}
                      className="hover:text-indigo-900 dark:hover:text-indigo-100"
                    >
                      ×
                    </button>
                  </span>
                )}
                {commandFilter && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300">
                    Command: {commandFilter}
                    <button
                      onClick={() => setCommandFilter(null)}
                      className="hover:text-indigo-900 dark:hover:text-indigo-100"
                    >
                      ×
                    </button>
                  </span>
                )}
              </div>
            )}
          </div>
          <button
            onClick={() => navigate('/jobs')}
            className="text-xs text-indigo-600 hover:text-indigo-700 font-medium"
          >
            View all →
          </button>
        </div>
        {isLoading ? (
          <div className="p-6 text-center text-gray-400 dark:text-slate-500 text-sm">Loading…</div>
        ) : recentJobs.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-400 dark:text-slate-500 text-sm">No jobs yet.</p>
            <button
              onClick={() => navigate('/analysis')}
              className="mt-3 px-4 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors font-medium"
            >
              Run your first analysis
            </button>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs font-medium text-gray-400 dark:text-slate-500 uppercase tracking-wide">
                <th className="px-5 py-3">Command</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Started</th>
                <th className="px-5 py-3">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50 dark:divide-slate-800">
              {recentJobs.map(job => {
                const start = new Date(job.created_at).getTime()
                const end = new Date(job.updated_at).getTime()
                const durMs = end - start
                const dur =
                  durMs < 1000
                    ? `${durMs}ms`
                    : durMs < 60_000
                    ? `${(durMs / 1000).toFixed(1)}s`
                    : `${Math.floor(durMs / 60_000)}m ${Math.round((durMs % 60_000) / 1000)}s`

                return (
                  <tr
                    key={job.id}
                    onClick={() => navigate(`/jobs/${job.id}`)}
                    className="hover:bg-gray-50 dark:hover:bg-slate-700/50 dark:bg-slate-800 cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-3 text-sm font-medium text-gray-900 dark:text-slate-100">{job.command}</td>
                    <td className="px-5 py-3">
                      <span
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
                        style={{
                          background: `${STATUS_COLORS[job.status] ?? '#94a3b8'}1a`,
                          color: STATUS_COLORS[job.status] ?? '#64748b',
                        }}
                      >
                        {job.status === 'running' && (
                          <span className="h-1.5 w-1.5 rounded-full bg-indigo-500 animate-pulse" />
                        )}
                        {job.status}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-sm text-gray-500 dark:text-slate-400">
                      {new Date(job.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-5 py-3 text-sm font-mono text-gray-500 dark:text-slate-400">{dur}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* CTA */}
      <div className="flex gap-3">
        <button
          onClick={() => navigate('/analysis')}
          className="px-5 py-2.5 bg-indigo-600 text-white rounded-lg text-sm font-semibold hover:bg-indigo-700 transition-colors"
        >
          Run Analysis
        </button>
        <button
          onClick={() => navigate('/clusters')}
          className="px-5 py-2.5 bg-white dark:bg-slate-900 text-gray-700 dark:text-slate-200 border border-gray-300 dark:border-slate-700 rounded-lg text-sm font-semibold hover:bg-gray-50 dark:hover:bg-slate-800 transition-colors"
        >
          Manage Clusters
        </button>
      </div>
    </div>
  )
}
