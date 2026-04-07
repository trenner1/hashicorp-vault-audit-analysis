import { ReactNode } from 'react'
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

  const { data: sysInfo } = useQuery({
    queryKey: ['system'],
    queryFn: api.systemInfo,
    staleTime: 60_000,
  })

  return (
    <div className="flex h-screen bg-white">
      <nav className="w-64 bg-gray-900 text-white flex flex-col border-r border-gray-700">
        <div className="p-6 border-b border-gray-700">
          <h1 className="text-xl font-bold text-indigo-400">Vault Audit</h1>
          <p className="text-xs text-gray-400 mt-1">Analysis Platform</p>
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
                  className={`px-4 py-3 flex items-center gap-3 hover:bg-gray-800 transition-colors ${
                    isActive
                      ? 'bg-indigo-600 text-white border-l-4 border-indigo-400'
                      : 'text-gray-300'
                  }`}
                >
                  <span className="text-xl">{item.icon}</span>
                  <span className="text-sm font-medium">{item.label}</span>
                </Link>
              </li>
            )
          })}
        </ul>

        <div className="px-4 py-4 border-t border-gray-700 text-xs text-gray-500 space-y-0.5">
          <p>v{sysInfo?.version ?? '—'}</p>
          {sysInfo && (
            <p className="text-gray-600">
              {sysInfo.jobs.running > 0
                ? `${sysInfo.jobs.running} job${sysInfo.jobs.running !== 1 ? 's' : ''} running`
                : 'No active jobs'}
            </p>
          )}
        </div>
      </nav>

      <main className="flex-1 overflow-auto bg-gray-50">
        <div className="p-8">{children}</div>
      </main>
    </div>
  )
}
