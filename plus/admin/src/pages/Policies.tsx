import React from "react"
import { Plus, Edit, Trash2, ShieldAlert, X, ChevronLeft, ChevronRight } from "lucide-react"
import type { Policy } from "../services/api"

export function Policies() {
  const [policies, setPolicies] = React.useState<Policy[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [showModal, setShowModal] = React.useState(false)
  const [editingPolicy, setEditingPolicy] = React.useState<Policy | null>(null)
  const [formData, setFormData] = React.useState<Policy>({
    id: "", name: "", description: "", riskThreshold: 50,
    challengeTtlMinutes: 10, pinTtlMinutes: 5, maxAttempts: 3,
    newCountryRisk: 20, unknownCountryRisk: 30, newIpRisk: 15,
    newDeviceRisk: 25, outsideBusinessHoursRisk: 15,
    workDays: "1,2,3,4,5", workHoursStart: "09:00", workHoursEnd: "18:00",
    forcedStepUpOps: ["ADMIN", "BACKUP", "RESTORE", "ROTATE_SECRET", "EDIT_SECRET", "DELETE_SECRET"],
    alwaysDeniedOps: ["EXPORT_SECRET"]
  })

  const limit = 10

  React.useEffect(() => { fetchPolicies() }, [page, search])

  async function fetchPolicies() {
    setLoading(true)
    try {
      const res = await fetch(`/api/v1/policies?limit=${limit}&offset=${(page - 1) * 10}&search=${search}`)
      const data = await res.json()
      setPolicies(data.policies)
      setTotal(data.total)
    } catch (error) { console.error("Failed to fetch policies:", error) }
    finally { setLoading(false) }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      if (editingPolicy) {
        await fetch(`/api/v1/policies/${editingPolicy.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(formData) })
      } else {
        await fetch("/api/v1/policies", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(formData) })
      }
      setShowModal(false)
    } catch (error) { console.error("Failed to save policy:", error) }
  }

  async function handleDelete(id: string) {
    if (!confirm("Are you sure you want to delete this policy?")) return
    try { await fetch(`/api/v1/policies/${id}`, { method: "DELETE" }) } catch (error) { console.error("Failed to delete policy:", error) }
  }

  function openCreateModal() {
    setEditingPolicy(null)
    setFormData({ id: "", name: "", description: "", riskThreshold: 50, challengeTtlMinutes: 10, pinTtlMinutes: 5, maxAttempts: 3, newCountryRisk: 20, unknownCountryRisk: 30, newIpRisk: 15, newDeviceRisk: 25, outsideBusinessHoursRisk: 15, workDays: "1,2,3,4,5", workHoursStart: "09:00", workHoursEnd: "18:00", forcedStepUpOps: ["ADMIN", "BACKUP", "RESTORE", "ROTATE_SECRET", "EDIT_SECRET", "DELETE_SECRET"], alwaysDeniedOps: ["EXPORT_SECRET"] })
    setShowModal(true)
  }

  function openEditModal(policy: Policy) {
    setEditingPolicy(policy)
    setFormData({ ...policy, forcedStepUpOps: policy.forcedStepUpOps || [], alwaysDeniedOps: policy.alwaysDeniedOps || [] })
    setShowModal(true)
  }

  function closeModal() { setShowModal(false); setEditingPolicy(null) }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Policies</h1><p className="text-surface-500 mt-1">Configure risk thresholds, challenge TTLs, and operation policies</p></div>
        <button onClick={openCreateModal} className="btn-primary"><Plus className="w-4 h-4 mr-2" />Add Policy</button>
      </div>

      <div className="card"><div className="card-body">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1"><ShieldAlert className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" /><input type="search" placeholder="Search policies..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" /></div>
        </div></div>

      <div className="card">
        <div className="table-container"><table className="w-full">
          <thead className="table-header"><tr><th className="px-6 py-3">Name</th><th className="px-6 py-3">Risk Threshold</th><th className="px-6 py-3">Challenge TTL</th><th className="px-6 py-3">Max Attempts</th><th className="px-6 py-3 hidden lg:table-cell">Forced Step-Up Ops</th><th className="px-6 py-3 text-right">Actions</th></tr></thead>
          <tbody className="divide-y divide-surface-100">
            {loading ? (
              <tr><td colSpan={6} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading policies...</div></td></tr>
            ) : policies.map((policy) => (
              <tr key={policy.id} className="table-row">
                <td className="px-6 py-4"><div className="font-medium text-surface-900">{policy.name}</div></td>
                <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-primary-100 text-primary-700">{policy.riskThreshold}%</span></td>
                <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">{policy.challengeTtlMinutes} min</span></td>
                <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-amber-100 text-amber-800">{policy.maxAttempts}</span></td>
                <td className="px-6 py-4 hidden lg:table-cell"><span className="text-sm text-surface-600 truncate max-w-xs">{policy.forcedStepUpOps.join(", ")}</span></td>
                <td className="px-6 py-4 text-right"><div className="flex items-center justify-end gap-2"><button onClick={() => openEditModal(policy)} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100 hover:text-surface-700 transition-colors" aria-label="Edit policy"><Edit className="w-5 h-5" /></button><button onClick={() => handleDelete(policy.id)} className="p-2 rounded-lg text-surface-500 hover:bg-red-50 hover:text-red-600 transition-colors" aria-label="Delete policy"><Trash2 className="w-5 h-5" /></button></div></td>
              </tr>
            ))}
          </tbody></table></div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} policies</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-surface-900">{editingPolicy ? "Edit Policy" : "Add Policy"}</h2>
              <button onClick={closeModal} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100" aria-label="Close modal"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="card-body space-y-4 overflow-y-auto">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="sm:col-span-2"><label className="label">Name *</label><input type="text" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="input" placeholder="e.g., Default risk policy" required /></div>
                <div className="sm:col-span-2"><label className="label">Description</label><textarea value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} className="input min-h-[80px] resize-y" placeholder="Optional description..." /></div>
                <div><label className="label">Risk Threshold</label><input type="number" value={formData.riskThreshold} onChange={(e) => setFormData({ ...formData, riskThreshold: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">Challenge TTL (min)</label><input type="number" value={formData.challengeTtlMinutes} onChange={(e) => setFormData({ ...formData, challengeTtlMinutes: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">PIN TTL (min)</label><input type="number" value={formData.pinTtlMinutes} onChange={(e) => setFormData({ ...formData, pinTtlMinutes: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">Max Attempts</label><input type="number" value={formData.maxAttempts} onChange={(e) => setFormData({ ...formData, maxAttempts: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">New Country Risk</label><input type="number" value={formData.newCountryRisk} onChange={(e) => setFormData({ ...formData, newCountryRisk: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">Unknown Country Risk</label><input type="number" value={formData.unknownCountryRisk} onChange={(e) => setFormData({ ...formData, unknownCountryRisk: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">New IP Risk</label><input type="number" value={formData.newIpRisk} onChange={(e) => setFormData({ ...formData, newIpRisk: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">New Device Risk</label><input type="number" value={formData.newDeviceRisk} onChange={(e) => setFormData({ ...formData, newDeviceRisk: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">Outside Business Hours Risk</label><input type="number" value={formData.outsideBusinessHoursRisk} onChange={(e) => setFormData({ ...formData, outsideBusinessHoursRisk: Number(e.target.value) })} className="input" /></div>
                <div><label className="label">Work Days</label><input type="text" value={formData.workDays} onChange={(e) => setFormData({ ...formData, workDays: e.target.value })} className="input" placeholder="1,2,3,4,5" /></div>
                <div><label className="label">Work Hours Start</label><input type="time" value={formData.workHoursStart} onChange={(e) => setFormData({ ...formData, workHoursStart: e.target.value })} className="input" /></div>
                <div><label className="label">Work Hours End</label><input type="time" value={formData.workHoursEnd} onChange={(e) => setFormData({ ...formData, workHoursEnd: e.target.value })} className="input" /></div>
                <div className="sm:col-span-2"><label className="label">Forced Step-Up Ops (comma-separated)</label><input type="text" value={formData.forcedStepUpOps.join(", ")} onChange={(e) => setFormData({ ...formData, forcedStepUpOps: e.target.value.split(",").map((op) => op.trim()).filter(Boolean) })} className="input" placeholder="ADMIN, BACKUP, RESTORE" /></div>
                <div className="sm:col-span-2"><label className="label">Always Denied Ops (comma-separated)</label><input type="text" value={formData.alwaysDeniedOps.join(", ")} onChange={(e) => setFormData({ ...formData, alwaysDeniedOps: e.target.value.split(",").map((op) => op.trim()).filter(Boolean) })} className="input" placeholder="EXPORT_SECRET" /></div>
              </div>
              <div className="card-footer flex justify-end gap-3">
                <button type="button" onClick={closeModal} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">{editingPolicy ? "Save Changes" : "Create Policy"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
