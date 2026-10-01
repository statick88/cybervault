import React from "react"
import { Search, ChevronLeft, ChevronRight } from "lucide-react"
import type { Challenge } from "../services/api"

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: "bg-amber-100 text-amber-800",
    completed: "bg-green-100 text-green-800",
    failed: "bg-red-100 text-red-800",
    expired: "bg-gray-100 text-gray-800"
  }
  return <span className={`px-2 py-1 text-xs rounded-full ${styles[status] || "bg-gray-100 text-gray-800"}`}>{status}</span>
}

export function Challenges() {
  const [challenges, setChallenges] = React.useState<Challenge[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [statusFilter, setStatusFilter] = React.useState("")
  const [limit] = React.useState(10)

  React.useEffect(() => { fetchChallenges() }, [page, search, statusFilter])

  async function fetchChallenges() {
    setLoading(true)
    try {
      const res = await fetch(`/api/v1/challenges?limit=${limit}&offset=${(page - 1) * 10}&search=${search}&status=${statusFilter}`)
      const data = await res.json()
      setChallenges(data.challenges)
      setTotal(data.total)
    } catch (error) { console.error("Failed to fetch challenges:", error) }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Challenges</h1><p className="text-surface-500 mt-1">Monitor and manage authentication challenges</p></div>
      </div>

      <div className="card"><div className="card-body">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" /><input type="search" placeholder="Search challenges..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" /></div>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="input sm:w-40"><option value="">All Statuses</option><option value="pending">Pending</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="expired">Expired</option></select>
        </div></div>

      <div className="card">
        <div className="table-container"><table className="w-full">
          <thead className="table-header"><tr><th className="px-6 py-3">ID</th><th className="px-6 py-3">User</th><th className="px-6 py-3">Resource</th><th className="px-6 py-3">Operation</th><th className="px-6 py-3">Status</th><th className="px-6 py-3">Risk Score</th><th className="px-6 py-3">Created</th><th className="px-6 py-3">Expires</th><th className="px-6 py-3 text-right">Actions</th></tr></thead>
          <tbody className="divide-y divide-surface-100">
            {loading ? (
              <tr><td colSpan={9} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading challenges...</div></td></tr>
            ) : challenges.map((challenge) => (
              <tr key={challenge.id} className="table-row">
                <td className="px-6 py-4"><code className="text-sm text-surface-600 font-mono">{challenge.id.slice(0, 8)}...</code></td>
                <td className="px-6 py-4"><span className="text-surface-600">{challenge.user?.email ?? challenge.userId}</span></td>
                <td className="px-6 py-4"><span className="text-surface-600">{challenge.resourceId}</span></td>
                <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-primary-100 text-primary-700">{challenge.operation}</span></td>
                <td className="px-6 py-4"><StatusBadge status={challenge.status} /></td>
                <td className="px-6 py-4"><span className="text-sm text-surface-600">{challenge.riskScore}%</span></td>
                <td className="px-6 py-4"><span className="text-sm text-surface-600">{new Date(challenge.createdAt).toLocaleString()}</span></td>
                <td className="px-6 py-4"><span className="text-sm text-surface-600">{new Date(challenge.expiresAt).toLocaleString()}</span></td>
                <td className="px-6 py-4 text-right"><button className="p-2 rounded-lg text-surface-500 hover:bg-surface-100 hover:text-surface-700 transition-colors" aria-label="View details"><svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542 7-4.477 0-8.268-2.943-9.542 7z" /></svg></button></td>
              </tr>
            ))}
          </tbody></table></div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} challenges</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
