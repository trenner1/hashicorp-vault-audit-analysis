import { ReactNode, useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '🏠' },
  { path: '/query', label: 'Ask a Question', icon: '✨' },
  { path: '/analysis', label: 'Analysis', icon: '🔍' },
  { path: '/files', label: 'Files', icon: '📁' },
  { path: '/clusters', label: 'Clusters', icon: '🌐' },
  { path: '/jobs', label: 'Jobs', icon: '📋' },
  { path: '/settings', label: 'Settings', icon: '⚙️' },
]

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem('theme')
    return saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)
  })

  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  }, [isDark])

  const { data: sysInfo } = useQuery({
    queryKey: ['system'],
    queryFn: api.systemInfo,
    // Poll every 5 s so the active-jobs counter stays current.
    // When there are running jobs the badge should update without a page refresh.
    refetchInterval: 5_000,
    staleTime: 0,
  })

  return (
    <div className="flex h-screen bg-white dark:bg-slate-900">
      <nav className="w-64 bg-gray-900 dark:bg-slate-950 text-white flex flex-col border-r border-gray-700 dark:border-slate-800">
        <div className="p-6 border-b border-gray-700 dark:border-slate-800">
          <h1 className="text-xl font-bold text-indigo-400 dark:text-indigo-300">Vault Audit</h1>
          <p className="text-xs text-gray-400 dark:text-slate-400 mt-1">Analysis Platform</p>
        </div>

        <ul className="flex-1 py-4">
          {navItems.map(item => {
            const isActive =
              item.path === '/'
                ? location.pathname === '/'
                : location.pathname.startsWith(item.path)
            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={`px-4 py-3 flex items-center gap-3 hover:bg-gray-800 dark:hover:bg-slate-800 transition-colors ${
                    isActive
                      ? 'bg-indigo-600 dark:bg-indigo-700 text-white border-l-4 border-indigo-400 dark:border-indigo-300'
                      : 'text-gray-300 dark:text-slate-300'
                  }`}
                >
                  <span className="text-xl">{item.icon}</span>
                  <span className="text-sm font-medium">{item.label}</span>
                </Link>
              </li>
            )
          })}
        </ul>

        <div className="px-4 py-4 border-t border-gray-700 dark:border-slate-800 space-y-2">
          <button
            onClick={() => setIsDark(!isDark)}
            className="w-full px-3 py-2 text-sm bg-gray-800 dark:bg-slate-800 hover:bg-gray-700 dark:hover:bg-slate-700 rounded transition-colors flex items-center justify-center gap-2"
          >
            <span>{isDark ? '☀️' : '🌙'}</span>
            <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
          </button>
          <div className="text-xs text-gray-500 dark:text-slate-500 space-y-0.5">
            <p>v{sysInfo?.version ?? '—'}</p>
            {sysInfo && (
              <p className="text-gray-600 dark:text-slate-600">
                {sysInfo.jobs.running > 0
                  ? `${sysInfo.jobs.running} job${sysInfo.jobs.running !== 1 ? 's' : ''} running`
                  : 'No active jobs'}
              </p>
            )}
          </div>
        </div>
      </nav>

      <main className="flex-1 overflow-auto bg-gray-50 dark:bg-slate-800">
        <div className="p-8">{children}</div>
      </main>
    </div>
  )
}
