import React from "react"
import { X } from "lucide-react"
import { resourcesApi, usersApi, entitlementsApi, type Resource, type User, type Entitlement } from "../services/api"

/** Shape of the entitlement edit form; `pestilloState` is constrained by the API type. */
type EntitlementForm = {
  userId: string
  resourceId: string
  pestilloState: Entitlement["pestilloState"]
  allowedOperations: string[]
  validFrom: string
  validUntil: string
}

export function Matrix() {
  const [resources, setResources] = React.useState<Resource[]>([])
  const [users, setUsers] = React.useState<User[]>([])
  const [entitlements, setEntitlements] = React.useState<Entitlement[]>([])
  const [loading, setLoading] = React.useState(true)
  const [showModal, setShowModal] = React.useState(false)
  const [editingEntitlement, setEditingEntitlement] = React.useState<Entitlement | null>(null)
  const [formData, setFormData] = React.useState<EntitlementForm>({
    userId: "", resourceId: "", pestilloState: "closed", allowedOperations: [], validFrom: "", validUntil: ""
  })

  React.useEffect(() => { fetchData() }, [])

  async function fetchData() {
    setLoading(true)
    try {
      const [resourcesRes, usersRes, entitlementsRes] = await Promise.all([
        resourcesApi.list({ limit: 100 }),
        usersApi.list({ limit: 100 }),
        entitlementsApi.list({ limit: 100 })
      ])
      setResources(resourcesRes.resources)
      setUsers(usersRes.users)
      setEntitlements(entitlementsRes.entitlements)
    } catch (error) { console.error("Failed to fetch matrix data:", error) }
    finally { setLoading(false) }
  }

  const pestilloStates = ["closed", "enabled", "step_up", "temporary"]
  const operations = ["AUTOFILL", "VIEW", "TOTP", "CONNECT", "READ", "ADMIN", "BACKUP", "RESTORE", "ROTATE_SECRET", "EDIT_SECRET", "DELETE_SECRET", "EXPORT_SECRET"]

  const getEntitlement = (userId: string, resourceId: string) =>
    entitlements.find(e => e.userId === userId && e.resourceId === resourceId)

  const handleCellClick = (user: User, resource: Resource) => {
    const entitlement = getEntitlement(user.id, resource.id)
    setEditingEntitlement(entitlement ?? null)
    setFormData({
      userId: user.id,
      resourceId: resource.id,
      pestilloState: entitlement?.pestilloState ?? "closed",
      allowedOperations: entitlement?.allowedOperations ?? [],
      validFrom: entitlement?.validFrom ?? "",
      validUntil: entitlement?.validUntil ?? "",
    })
    setShowModal(true)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editingEntitlement?.id) {
        await fetch(`/api/v1/entitlements/${editingEntitlement.id}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(formData) })
      } else {
        await fetch("/api/v1/entitlements", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(formData) })
      }
      setShowModal(false)
      // Refresh data
      await fetchData()
    } catch (error) { console.error("Failed to save entitlement:", error) }
  }

  function closeModal() { setShowModal(false); setEditingEntitlement(null) }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Entitlement Matrix</h1><p className="text-surface-500 mt-1">Manage user-resource entitlements and pestillo states</p></div>
      </div>

      <div className="card">
        <div className="card-body">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="table-header">
                <tr>
                  <th className="px-6 py-3 sticky left-0 bg-surface-50">User / Resource</th>
                  {resources.map((resource) => (
                    <th key={resource.id} className="px-4 py-3 text-center min-w-[120px] max-w-[200px] overflow-hidden text-ellipsis whitespace-nowrap bg-surface-50 border-r border-surface-200">
                      <div className="font-medium text-surface-900">{resource.name}</div>
                      <div className="text-xs text-surface-500 truncate">{resource.type}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-100">
                {loading ? (
                  <tr><td colSpan={resources.length + 1} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading matrix...</div></td></tr>
                ) : users.map((user) => (
                  <tr key={user.id} className="table-row">
                    <td className="px-4 py-3 sticky left-0 bg-white">
                      <div className="font-medium text-surface-900">{user.name}</div>
                      <div className="text-sm text-surface-500">{user.email}</div>
                    </td>
                    {resources.map((resource) => {
                      const entitlement = entitlements.find(e => e.userId === user.id && e.resourceId === resource.id)
                      const state = entitlement?.pestilloState || "closed"
                      const stateColors: Record<string, string> = {
                        closed: "bg-red-100 text-red-800",
                        enabled: "bg-green-100 text-green-800",
                        step_up: "bg-amber-100 text-amber-800",
                        temporary: "bg-blue-100 text-blue-800"
                      }
                      return (
                        <td key={resource.id} className="px-4 py-3 text-center">
                          <button
                            onClick={() => handleCellClick(user, resource)}
                            className={`w-full px-3 py-2 rounded-lg text-sm font-medium transition-colors ${stateColors[state] || "bg-red-100 text-red-800"} hover:opacity-80`}
                          >
                            {state}
                          </button>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-surface-900">{editingEntitlement ? "Edit Entitlement" : "Add Entitlement"}</h2>
              <button onClick={closeModal} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100" aria-label="Close modal"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="card-body space-y-4">
              <div>
                <label className="label">User</label>
                <select value={formData.userId} onChange={(e) => setFormData({ ...formData, userId: e.target.value })} className="input" required>
                  <option value="" disabled>Select a user</option>
                  {users.map((u) => (<option key={u.id} value={u.id}>{u.name} ({u.email})</option>))}
                </select>
              </div>
              <div>
                <label className="label">Resource</label>
                <select value={formData.resourceId} onChange={(e) => setFormData({ ...formData, resourceId: e.target.value })} className="input" required>
                  <option value="" disabled>Select a resource</option>
                  {resources.map((r) => (<option key={r.id} value={r.id}>{r.name}</option>))}
                </select>
              </div>
              <div>
                <label className="label">Pestillo State</label>
                <select value={formData.pestilloState} onChange={(e) => setFormData({ ...formData, pestilloState: e.target.value as Entitlement["pestilloState"] })} className="input">
                  {pestilloStates.map((s) => (<option key={s} value={s}>{s}</option>))}
                </select>
              </div>
              <div>
                <label className="label">Allowed Operations</label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {operations.map((op) => (
                    <label key={op} className="flex items-center gap-2 text-sm text-surface-700">
                      <input
                        type="checkbox"
                        checked={formData.allowedOperations.includes(op)}
                        onChange={(e) => setFormData({
                          ...formData,
                          allowedOperations: e.target.checked
                            ? [...formData.allowedOperations, op]
                            : formData.allowedOperations.filter((o) => o !== op),
                        })}
                      />
                      {op}
                    </label>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div><label className="label">Valid From</label><input type="date" value={formData.validFrom} onChange={(e) => setFormData({ ...formData, validFrom: e.target.value })} className="input" /></div>
                <div><label className="label">Valid Until</label><input type="date" value={formData.validUntil} onChange={(e) => setFormData({ ...formData, validUntil: e.target.value })} className="input" /></div>
              </div>
              <div className="card-footer flex justify-end gap-3">
                <button type="button" onClick={closeModal} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">{editingEntitlement ? "Save Changes" : "Create Entitlement"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
