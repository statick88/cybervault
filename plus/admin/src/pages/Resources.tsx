import React from "react"
import { Plus, Search, Server, Trash2, Eye, X, ChevronLeft, ChevronRight } from "lucide-react"
import { resourcesApi, type Resource, type ResourceCreateInput } from "../services/api"

function ResourceRow({ resource, onEdit, onDelete }: {
  resource: Resource
  onEdit: (resource: Resource) => void
  onDelete: (id: string) => void
}) {
  return (
    <tr key={resource.id} className="table-row">
      <td className="px-6 py-4"><div className="font-medium text-surface-900">{resource.name}</div></td>
      <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-surface-100 text-surface-700">{resource.type}</span></td>
      <td className="px-6 py-4"><code className="text-sm text-surface-600 font-mono">{resource.endpoint}</code></td>
      <td className="px-6 py-4 hidden md:table-cell"><span className="px-2 py-1 text-xs rounded-full bg-surface-100 text-surface-700">{resource.environment}</span></td>
      <td className="px-6 py-4 hidden lg:table-cell"><span className={"criticality-badge px-2 py-1 text-xs rounded-full " + (resource.criticality === "low" ? "criticality-low" : resource.criticality === "medium" ? "criticality-medium" : resource.criticality === "high" ? "criticality-high" : "criticality-critical")}>{resource.criticality}</span></td>
      <td className="px-6 py-4 hidden lg:table-cell"><span className="text-sm text-surface-600">{resource.ownerTeam || "\u2014"}</span></td>
      <td className="px-6 py-4 text-right"><div className="flex items-center justify-end gap-2"><button onClick={() => onEdit(resource)} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100 hover:text-surface-700 transition-colors" aria-label="Edit resource"><Eye className="w-5 h-5" /></button><button onClick={() => onDelete(resource.id)} className="p-2 rounded-lg text-surface-500 hover:bg-red-50 hover:text-red-600 transition-colors" aria-label="Delete resource"><Trash2 className="w-5 h-5" /></button></div></td>
    </tr>
  )
}

export function Resources() {
  const [resources, setResources] = React.useState<Resource[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [typeFilter, setTypeFilter] = React.useState("")
  const [envFilter, setEnvFilter] = React.useState("")
  const [criticalityFilter, setCriticalityFilter] = React.useState("")
  const [showModal, setShowModal] = React.useState(false)
  const [editingResource, setEditingResource] = React.useState<Resource | null>(null)
  const [formData, setFormData] = React.useState<ResourceCreateInput>({
    id: "", name: "", type: "web", endpoint: "",
    environment: "production", criticality: "medium",
    description: "", tags: [], ownerTeam: "",
  })

  const limit = 10

  React.useEffect(() => { fetchResources() }, [page])

  async function fetchResources() {
    setLoading(true)
    try {
      const res = await resourcesApi.list({ limit, offset: (page - 1) * limit })
      setResources(res.resources)
      setTotal(res.total)
    } catch (error) { console.error("Failed to fetch resources:", error) }
    finally { setLoading(false) }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      if (editingResource) { await resourcesApi.update(editingResource.id, formData) }
      else { await resourcesApi.create(formData) }
      setShowModal(false)
      setEditingResource(null)
      fetchResources()
    } catch (error) { console.error("Failed to save resource:", error) }
  }

  async function handleDelete(id: string) {
    if (!confirm("Are you sure you want to delete this resource?")) return
    try { await resourcesApi.delete(id); fetchResources() }
    catch (error) { console.error("Failed to delete resource:", error) }
  }

  function openCreateModal() {
    setEditingResource(null)
    setFormData({ id: "", name: "", type: "web", endpoint: "", environment: "production", criticality: "medium", description: "", tags: [], ownerTeam: "" })
    setShowModal(true)
  }

  function openEditModal(resource: Resource) {
    setEditingResource(resource)
    setFormData({ id: resource.id, name: resource.name, type: resource.type, endpoint: resource.endpoint, environment: resource.environment, criticality: resource.criticality, description: resource.description || "", tags: resource.tags, ownerTeam: resource.ownerTeam || "" })
    setShowModal(true)
  }

  function closeModal() { setShowModal(false); setEditingResource(null) }

  const types = ["web", "ssh", "rdp", "vpn", "database", "kubernetes", "microservice", "firewall", "backup", "other"]
  const environments = ["production", "staging", "development", "testing", "dr"]
  const criticalities = ["low", "medium", "high", "critical"]

  const resourceRows = React.useMemo(() => resources.map((resource) => (
    <ResourceRow key={resource.id} resource={resource} onEdit={openEditModal} onDelete={handleDelete} />
  )), [resources, openEditModal, handleDelete])

  let content
  if (loading) {
    content = <tr><td colSpan={7} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading resources...</div></td></tr>
  } else if (resources.length === 0) {
    content = <tr><td colSpan={7} className="px-6 py-12 text-center text-surface-500"><div className="empty-state"><Server className="empty-state-icon w-12 h-12" /><h3 className="empty-state-title">No resources found</h3><p className="empty-state-description">Get started by adding your first resource.</p><button onClick={openCreateModal} className="btn-primary mt-4"><Plus className="w-4 h-4 mr-2" />Add Resource</button></div></td></tr>
  } else {
    content = resourceRows
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Resources</h1><p className="text-surface-500 mt-1">Manage infrastructure resources</p></div>
        <button onClick={openCreateModal} className="btn-primary"><Plus className="w-4 h-4 mr-2" />Add Resource</button>
      </div>

      <div className="card"><div className="card-body">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" /><input type="search" placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" /></div>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="input sm:w-40"><option value="">All Types</option>{types.map((t) => (<option key={t} value={t}>{t}</option>))}</select>
          <select value={envFilter} onChange={(e) => setEnvFilter(e.target.value)} className="input sm:w-40"><option value="">All Environments</option>{environments.map((e) => (<option key={e} value={e}>{e}</option>))}</select>
          <select value={criticalityFilter} onChange={(e) => setCriticalityFilter(e.target.value)} className="input sm:w-40"><option value="">All Criticalities</option>{criticalities.map((c) => (<option key={c} value={c}>{c}</option>))}</select>
        </div></div>
      </div>

      <div className="card">
        <div className="table-container"><table className="w-full">
          <thead className="table-header"><tr><th className="px-6 py-3">Name</th><th className="px-6 py-3">Type</th><th className="px-6 py-3">Endpoint</th><th className="px-6 py-3 hidden md:table-cell">Environment</th><th className="px-6 py-3 hidden lg:table-cell">Criticality</th><th className="px-6 py-3 hidden lg:table-cell">Owner Team</th><th className="px-6 py-3 text-right">Actions</th></tr></thead>
          <tbody className="divide-y divide-surface-100">
            {content}
            </tbody>
          </table></div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} resources</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-surface-900">{editingResource ? "Edit Resource" : "Add Resource"}</h2>
              <button onClick={closeModal} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100" aria-label="Close modal"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="card-body space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div><label className="label">Name *</label><input type="text" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="input" placeholder="e.g., Production Database" required /></div>
                <div><label className="label">Type *</label><select value={formData.type} onChange={(e) => setFormData({ ...formData, type: e.target.value })} className="input" required>{types.map((t) => (<option key={t} value={t}>{t}</option>))}</select></div>
                <div className="sm:col-span-2"><label className="label">Endpoint *</label><input type="text" value={formData.endpoint} onChange={(e) => setFormData({ ...formData, endpoint: e.target.value })} className="input" placeholder="e.g., db01.internal:5432 or https://api.example.com" required /></div>
                <div><label className="label">Environment *</label><select value={formData.environment} onChange={(e) => setFormData({ ...formData, environment: e.target.value })} className="input" required>{environments.map((e) => (<option key={e} value={e}>{e}</option>))}</select></div>
                <div><label className="label">Criticality *</label><select value={formData.criticality} onChange={(e) => setFormData({ ...formData, criticality: e.target.value })} className="input" required>{criticalities.map((c) => (<option key={c} value={c}>{c}</option>))}</select></div>
                <div className="sm:col-span-2"><label className="label">Owner Team</label><input type="text" value={formData.ownerTeam} onChange={(e) => setFormData({ ...formData, ownerTeam: e.target.value })} className="input" placeholder="e.g., Platform Team" /></div>
                <div className="sm:col-span-2"><label className="label">Tags (comma-separated)</label><input type="text" value={formData.tags?.join(", ") ?? ""} onChange={(e) => setFormData({ ...formData, tags: e.target.value.split(",").map(t => t.trim()).filter(Boolean) })} className="input" placeholder="postgres, production, critical" /></div>
                <div className="sm:col-span-2"><label className="label">Description</label><textarea value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} className="input min-h-[80px] resize-y" placeholder="Optional description..." /></div>
              </div>
              <div className="card-footer flex justify-end gap-3">
                <button type="button" onClick={closeModal} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">{editingResource ? "Save Changes" : "Create Resource"}</button>
              </div>
            </form>
          </div>
        </div>
        )}
      </div>
  )
}
