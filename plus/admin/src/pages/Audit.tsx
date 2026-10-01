import React from "react"
import { Search, ChevronLeft, ChevronRight, FileText, Download } from "lucide-react"
import type { AuditEntry } from "../services/api"

function DecisionBadge({ decision }: { decision: string }) {
  const styles: Record<string, string> = {
    allow: "bg-green-100 text-green-800",
    deny: "bg-red-100 text-red-800",
    challenge: "bg-amber-100 text-amber-800",
    revoke: "bg-red-100 text-red-800"
  }
  return <span className={`px-2 py-1 text-xs rounded-full ${styles[decision] || "bg-gray-100 text-gray-800"}`}>{decision}</span>
}

export function Audit() {
  const [events, setEvents] = React.useState<AuditEntry[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [eventFilter, setEventFilter] = React.useState("")
  const [decisionFilter, setDecisionFilter] = React.useState("")
  const [limit] = React.useState(10)

  React.useEffect(() => { fetchEvents() }, [page, search, eventFilter, decisionFilter])

  async function fetchEvents() {
    setLoading(true)
    try {
      const res = await fetch(`/api/v1/audit?limit=${limit}&offset=${(page - 1) * 10}&search=${search}&event=${eventFilter}&decision=${decisionFilter}`)
      const data = await res.json()
      setEvents(data.events)
      setTotal(data.total)
    } catch (error) { console.error("Failed to fetch audit events:", error) }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Audit Log</h1><p className="text-surface-500 mt-1">Monitor and review security events</p></div>
        <div className="flex gap-2"><button className="btn-secondary"><Download className="w-4 h-4 mr-2" />Export CSV</button></div>
      </div>

      <div className="card"><div className="card-body">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" /><input type="search" placeholder="Search events..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" /></div>
          <select value={eventFilter} onChange={(e) => setEventFilter(e.target.value)} className="input sm:w-40"><option value="">All Events</option><option value="capability_requested">Capability Requested</option><option value="capability_granted">Capability Granted</option><option value="capability_denied">Capability Denied</option><option value="capability_revoked">Capability Revoked</option><option value="challenge_created">Challenge Created</option><option value="challenge_completed">Challenge Completed</option><option value="challenge_failed">Challenge Failed</option><option value="challenge_expired">Challenge Expired</option><option value="entitlement_created">Entitlement Created</option><option value="entitlement_updated">Entitlement Updated</option><option value="entitlement_deleted">Entitlement Deleted</option></select>
          <select value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)} className="input sm:w-40"><option value="">All Decisions</option><option value="allow">Allow</option><option value="deny">Deny</option><option value="challenge">Challenge</option><option value="revoke">Revoke</option></select>
        </div></div>

      <div className="card">
        <div className="table-container"><table className="w-full">
          <thead className="table-header"><tr><th className="px-6 py-3">Timestamp</th><th className="px-6 py-3">Event</th><th className="px-6 py-3">User</th><th className="px-6 py-3">Resource</th><th className="px-6 py-3">Operation</th><th className="px-6 py-3">Decision</th><th className="px-6 py-3">Risk Score</th><th className="px-6 py-3">Context</th></tr></thead>
          <tbody className="divide-y divide-surface-100">
            {loading ? <tr><td colSpan={8} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading events...</div></td></tr> : events.length === 0 ? <tr><td colSpan={8} className="px-6 py-12 text-center text-surface-500"><div className="empty-state"><FileText className="empty-state-icon w-12 h-12" /><h3 className="empty-state-title">No audit events found</h3><p className="empty-state-description">No events match the current filters.</p></div></td></tr> : (
              events.map((event) => (
                <tr key={event.id} className="table-row">
                  <td className="px-6 py-4"><span className="text-sm text-surface-600 font-mono">{new Date(event.timestamp).toLocaleString()}</span></td>
                  <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">{event.event}</span></td>
                  <td className="px-6 py-4"><span className="text-sm text-surface-600">{event.userId}</span></td>
                  <td className="px-6 py-4"><span className="text-sm text-surface-600">{event.resourceId}</span></td>
                  <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-primary-100 text-primary-700">{event.operation}</span></td>
                  <td className="px-6 py-4"><DecisionBadge decision={event.decision} /></td>
                  <td className="px-6 py-4"><span className="text-sm text-surface-600">{event.riskScore}%</span></td>
                  <td className="px-6 py-4"><span className="text-sm text-surface-500 max-w-xs truncate block">{JSON.stringify(event.context)}</span></td>
                </tr>
              ))
            )}
          </tbody></table></div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} events</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
