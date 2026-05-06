import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Analysis } from './pages/Analysis'
import { Jobs } from './pages/Jobs'
import { Clusters } from './pages/Clusters'
import { Settings } from './pages/Settings'
import { Files } from './pages/Files'
import Query from './pages/Query'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/query" element={<Query />} />
        <Route path="/analysis" element={<Analysis />} />
        <Route path="/files" element={<Files />} />
        <Route path="/jobs" element={<Jobs />} />
        <Route path="/jobs/:id" element={<Jobs />} />
        <Route path="/clusters" element={<Clusters />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<div className="text-gray-600 dark:text-slate-400">Page not found</div>} />
      </Routes>
    </Layout>
  )
}
