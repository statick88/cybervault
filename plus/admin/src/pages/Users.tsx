import React from "react"
import { Plus, Search, Edit, Trash2, Users as UsersIcon, X, ChevronLeft, ChevronRight } from "lucide-react"
import { usersApi, type User } from "../services/api"

function UserRow({ user, onEdit, onDelete }: {
  user: User
  onEdit: (user: User) => void
  onDelete: (id: string) => void
}) {
  return (
    <tr key={user.id} className="table-row">
      <td className="px-6 py-4"><div className="font-medium text-surface-900">{user.name}</div></td>
      <td className="px-6 py-4"><span className="text-surface-600">{user.email}</span></td>
      <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-primary-100 text-primary-700">{user.role}</span></td>
      <td className="px-6 py-4"><span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-800">{user.active ? "Active" : "Inactive"}</span></td>
      <td className="px-6 py-4 hidden lg:table-cell"><span className="text-sm text-surface-600">{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : "Never"}</span></td>
      <td className="px-6 py-4 text-right"><div className="flex items-center justify-end gap-2"><button onClick={() => onEdit(user)} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100 hover:text-surface-700 transition-colors" aria-label="Edit user"><Edit className="w-5 h-5" /></button><button onClick={() => onDelete(user.id)} className="p-2 rounded-lg text-surface-500 hover:bg-red-50 hover:text-red-600 transition-colors" aria-label="Delete user"><Trash2 className="w-5 h-5" /></button></div></td>
    </tr>
  )
}

export function Users() {
  const [users, setUsers] = React.useState<User[]>([])
  const [loading, setLoading] = React.useState(true)
  const [total, setTotal] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [search, setSearch] = React.useState("")
  const [roleFilter, setRoleFilter] = React.useState("")
  const [statusFilter, setStatusFilter] = React.useState("")
  const [showModal, setShowModal] = React.useState(false)
  const [editingUser, setEditingUser] = React.useState<User | null>(null)
  const [formData, setFormData] = React.useState({
    id: "", email: "", name: "", role: "operator", status: "active"
  })

  const limit = 10

  React.useEffect(() => { fetchUsers() }, [page])

  async function fetchUsers() {
    setLoading(true)
    try {
      const res = await usersApi.list({ limit, offset: (page - 1) * limit })
      setUsers(res.users)
      setTotal(res.total)
    } catch (error) { console.error("Failed to fetch users:", error) }
    finally { setLoading(false) }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      if (editingUser) { await usersApi.update(editingUser.id, formData) }
      else { await usersApi.create(formData) }
      setShowModal(false)
      setEditingUser(null)
      fetchUsers()
    } catch (error) { console.error("Failed to save user:", error) }
  }

  async function handleDelete(id: string) {
    if (!confirm("Are you sure you want to delete this user?")) return
    try { await usersApi.delete(id); fetchUsers() }
    catch (error) { console.error("Failed to delete user:", error) }
  }

  function openCreateModal() {
    setEditingUser(null)
    setFormData({ id: "", email: "", name: "", role: "operator", status: "active" })
    setShowModal(true)
  }

  function openEditModal(user: User) {
    setEditingUser(user)
    setFormData({ id: user.id, email: user.email, name: user.name, role: user.role, status: user.active ? "active" : "inactive" })
    setShowModal(true)
  }

  function closeModal() { setShowModal(false); setEditingUser(null) }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Users</h1><p className="text-surface-500 mt-1">Manage user accounts and permissions</p></div>
        <button onClick={openCreateModal} className="btn-primary"><Plus className="w-4 h-4 mr-2" />Add User</button>
      </div>

      <div className="card"><div className="card-body">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" /><input type="search" placeholder="Search users..." value={search} onChange={(e) => setSearch(e.target.value)} className="input pl-10" /></div>
          <select value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)} className="input sm:w-40"><option value="">All Roles</option><option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option><option value="auditor">Auditor</option></select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="input sm:w-40"><option value="">All Statuses</option><option value="active">Active</option><option value="inactive">Inactive</option><option value="suspended">Suspended</option></select>
        </div></div>

      <div className="card">
        <div className="table-container"><table className="w-full">
          <thead className="table-header"><tr><th className="px-6 py-3">Name</th><th className="px-6 py-3">Email</th><th className="px-6 py-3">Role</th><th className="px-6 py-3">Status</th><th className="px-6 py-3 hidden lg:table-cell">Last Login</th><th className="px-6 py-3 text-right">Actions</th></tr></thead>
          <tbody className="divide-y divide-surface-100">
            {loading ? (
              <tr><td colSpan={6} className="px-6 py-12 text-center text-surface-500"><div className="flex items-center justify-center gap-2"><svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>Loading users...</div></td></tr>
            ) : users.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-12 text-center text-surface-500"><div className="empty-state"><UsersIcon className="empty-state-icon w-12 h-12" /><h3 className="empty-state-title">No users found</h3><p className="empty-state-description">Get started by adding your first user.</p><button onClick={openCreateModal} className="btn-primary mt-4"><Plus className="w-4 h-4 mr-2" />Add User</button></div></td></tr>
            ) : (
              users.map((user) => (
                <UserRow key={user.id} user={user} onEdit={openEditModal} onDelete={handleDelete} />
              ))
            )}
          </tbody></table></div>
          {total > limit && (
            <div className="card-footer flex items-center justify-between">
              <p className="text-sm text-surface-500">Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} users</p>
              <div className="pagination"><button onClick={() => setPage(page - 1)} disabled={page === 1} className="pagination-btn" aria-label="Previous page"><ChevronLeft className="w-4 h-4" /></button><span className="px-3 text-sm text-surface-600">Page {page} of {Math.ceil(total / limit)}</span><button onClick={() => setPage(page + 1)} disabled={page === Math.ceil(total / limit)} className="pagination-btn" aria-label="Next page"><ChevronRight className="w-4 h-4" /></button></div>
            </div>
          )}
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="card-header flex items-center justify-between">
              <h2 className="text-lg font-semibold text-surface-900">{editingUser ? "Edit User" : "Add User"}</h2>
              <button onClick={closeModal} className="p-2 rounded-lg text-surface-500 hover:bg-surface-100" aria-label="Close modal"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="card-body space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div><label className="label">Email *</label><input type="email" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} className="input" placeholder="e.g., jane.smith@company.com" required /></div>
                <div><label className="label">Name *</label><input type="text" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} className="input" placeholder="e.g., Jane Smith" required /></div>
                <div><label className="label">Role *</label><select value={formData.role} onChange={(e) => setFormData({ ...formData, role: e.target.value })} className="input"><option value="admin">Admin</option><option value="operator">Operator</option><option value="viewer">Viewer</option><option value="auditor">Auditor</option></select></div>
                <div><label className="label">Status *</label><select value={formData.status} onChange={(e) => setFormData({ ...formData, status: e.target.value })} className="input"><option value="active">Active</option><option value="inactive">Inactive</option><option value="suspended">Suspended</option></select></div>
              </div>
              <div className="card-footer flex justify-end gap-3">
                <button type="button" onClick={closeModal} className="btn-secondary">Cancel</button>
                <button type="submit" className="btn-primary">{editingUser ? "Save Changes" : "Create User"}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
