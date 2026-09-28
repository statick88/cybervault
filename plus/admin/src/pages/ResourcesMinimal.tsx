import React from "react"
import { Plus, Search, Server, ChevronLeft, ChevronRight } from "lucide-react"
import { resourcesApi, type Resource } from "../services/api"

const TYPES = ["web", "ssh", "rdp", "vpn", "database", "kubernetes", "microservice", "firewall", "backup", "other"]

export function ResourcesMinimal() {
  const [resources, setResources] = React.useState<Resource[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [typeFilter, setTypeFilter] = React.useState("")

  const limit = 10

  React.useEffect(() => { fetchResources() }, [page, typeFilter, search])

  async function fetchResources() {
    setLoading(true)
    try {
      const res = await resourcesApi.list({
        limit,
        offset: (page - 1) * limit,
        ...(search && { name: search }),
        ...(typeFilter && { type: typeFilter }),
      })
      setResources(res.resources)
      setTotal(res.total)
    } catch (error) { console.error("Failed to fetch resources:", error) }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Resources</h1></div>
        <button className="btn-primary"><Plus className="w-4 h-4 mr-2" />Add Resource</button>
      </div>
      <div className="card">
        <div className="card-body">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" />
              <input type="search" placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" />
            </div>
            <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="input sm:w-40"><option value="">All Types</option>{TYPES.map((t) => (<option key={t} value={t}>{t}</option>))}</select>
          </div>
        </div>
        <div className="card">
          <div className="table-container">
            <table className="w-full">
              <thead className="table-header"><tr><th className="px-6 py-3">Name</th><th className="px-6 py-3">Type</th><th className="px-6 py-3">Endpoint</th></tr></thead>
              <tbody className="divide-y divide-surface-100">
                {loading ? (
                  <tr><td colSpan={3} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading resources...</div></td></tr>
                ) : resources.length === 0 ? (
                  <tr><td colSpan={3} className="px-6 py-12 text-center text-surface-500"><div className="flex flex-col items-center gap-2"><Server className="w-8 h-8 text-surface-300" /><p>No resources found</p></div></td></tr>
                ) : resources.map((resource) => (
                  <tr key={resource.id} className="table-row">
                    <td className="px-6 py-4"><div className="font-medium text-surface-900">{resource.name}</div></td>
                    <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-surface-100 text-surface-700">{resource.type}</span></td>
                    <td className="px-6 py-4"><code className="text-sm text-surface-600 font-mono">{resource.endpoint}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} resources</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
