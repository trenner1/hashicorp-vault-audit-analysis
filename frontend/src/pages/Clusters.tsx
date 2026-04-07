import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, Cluster } from '../api/client'

type ClusterFormData = {
  name: string
  vault_addr: string
  namespace: string
  token: string
}

const EMPTY_FORM: ClusterFormData = { name: '', vault_addr: '', namespace: '', token: '' }

function ClusterForm({
  initial,
  onSubmit,
  onCancel,
  submitLabel,
  isPending,
  error,
}: {
  initial: ClusterFormData
  onSubmit: (data: ClusterFormData) => void
  onCancel: () => void
  submitLabel: string
  isPending: boolean
  error?: string | null
}) {
  const [data, setData] = useState<ClusterFormData>(initial)
  const set = (k: keyof ClusterFormData) =>
    (e: React.ChangeEvent<HTMLInputElement>) => setData(d => ({ ...d, [k]: e.target.value }))

  return (
    <form
      onSubmit={e => { e.preventDefault(); onSubmit(data) }}
      className="space-y-4"
    >
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">
            Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={data.name}
            onChange={set('name')}
            placeholder="Production"
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Namespace</label>
          <input
            type="text"
            value={data.namespace}
            onChange={set('namespace')}
            placeholder="admin"
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Vault Address <span className="text-red-500">*</span>
        </label>
        <input
          type="text"
          value={data.vault_addr}
          onChange={set('vault_addr')}
          placeholder="https://vault.example.com:8200"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          required
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">
          Vault Token <span className="text-gray-400 font-normal">(optional — stored server-side, never echoed)</span>
        </label>
        <input
          type="password"
          value={data.token}
          onChange={set('token')}
          placeholder="hvs.••••••••"
          autoComplete="off"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />
        <p className="text-xs text-gray-400 mt-1">
          Leave blank when editing to keep the existing token. The token is passed as <code className="bg-gray-100 px-1 rounded">--token</code> to API commands.
        </p>
      </div>

      {error && (
        <p className="text-sm text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={isPending}
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
        >
          {isPending ? 'Saving…' : submitLabel}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-white text-gray-700 text-sm font-medium rounded-lg border border-gray-300 hover:bg-gray-50 transition-colors"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

export function Clusters() {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)

  const { data: clusters = [], isLoading } = useQuery({
    queryKey: ['clusters'],
    queryFn: api.listClusters,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['clusters'] })

  const createMutation = useMutation({
    mutationFn: (d: ClusterFormData) => api.createCluster(d),
    onSuccess: () => { invalidate(); setShowCreate(false) },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: ClusterFormData }) =>
      api.updateCluster(id, data),
    onSuccess: () => { invalidate(); setEditingId(null) },
  })

  const deleteMutation = useMutation({
    mutationFn: api.deleteCluster,
    onSuccess: invalidate,
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Clusters</h1>
          <p className="text-gray-500 mt-1 text-sm">Vault cluster connections for API-based commands</p>
        </div>
        {!showCreate && (
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 bg-indigo-600 text-white text-sm font-semibold rounded-lg hover:bg-indigo-700 transition-colors"
          >
            + Add Cluster
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-base font-semibold text-gray-900 mb-4">New Cluster</h2>
          <ClusterForm
            initial={EMPTY_FORM}
            onSubmit={data => createMutation.mutate(data)}
            onCancel={() => setShowCreate(false)}
            submitLabel="Create Cluster"
            isPending={createMutation.isPending}
            error={createMutation.isError
              ? (createMutation.error instanceof Error ? createMutation.error.message : 'Failed to create')
              : null}
          />
        </div>
      )}

      {/* Cluster list */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-400 text-sm">Loading…</div>
        ) : clusters.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-gray-400 text-sm">No clusters configured yet.</p>
            <p className="text-gray-400 text-xs mt-1">
              Add a cluster to enable API-based commands like client-activity and entity-list.
            </p>
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-100">
              <tr className="text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                <th className="px-6 py-3">Name</th>
                <th className="px-6 py-3">Vault Address</th>
                <th className="px-6 py-3">Namespace</th>
                <th className="px-6 py-3">Token</th>
                <th className="px-6 py-3">Added</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {[...(clusters as Cluster[])].sort(
                (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
              ).map(cluster => (
                <>
                  <tr key={cluster.id} className={`hover:bg-gray-50 transition-colors ${editingId === cluster.id ? 'bg-indigo-50' : ''}`}>
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{cluster.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 font-mono">{cluster.vault_addr}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">{cluster.namespace || '—'}</td>
                    <td className="px-6 py-4">
                      {cluster.token_set ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-700 bg-green-50 border border-green-200 rounded-full px-2 py-0.5">
                          <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                          set
                        </span>
                      ) : (
                        <span className="text-xs text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      {new Date(cluster.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-3">
                        <button
                          onClick={() => setEditingId(editingId === cluster.id ? null : cluster.id)}
                          className="text-xs text-indigo-600 hover:text-indigo-800 font-medium"
                        >
                          {editingId === cluster.id ? 'Cancel edit' : 'Edit'}
                        </button>
                        <button
                          onClick={() => {
                            if (window.confirm(`Delete cluster "${cluster.name}"?`)) {
                              deleteMutation.mutate(cluster.id)
                            }
                          }}
                          disabled={deleteMutation.isPending && deleteMutation.variables === cluster.id}
                          className="text-xs text-red-500 hover:text-red-700 font-medium disabled:opacity-40"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  {editingId === cluster.id && (
                    <tr key={`${cluster.id}-edit`}>
                      <td colSpan={5} className="px-6 py-4 bg-indigo-50 border-b border-indigo-100">
                        <ClusterForm
                          initial={{
                            name: cluster.name,
                            vault_addr: cluster.vault_addr,
                            namespace: cluster.namespace,
                            token: '', // intentionally blank — leave existing token unless user types a new one
                          }}
                          onSubmit={data => updateMutation.mutate({ id: cluster.id, data })}
                          onCancel={() => setEditingId(null)}
                          submitLabel="Save Changes"
                          isPending={updateMutation.isPending}
                          error={updateMutation.isError
                            ? (updateMutation.error instanceof Error ? updateMutation.error.message : 'Failed to update')
                            : null}
                        />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
