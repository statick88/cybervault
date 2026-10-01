import { useState } from "react";
import { Outlet, NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Server,
  Users,
  Grid,
  Shield,
  AlertTriangle,
  FileText,
  Settings,
  Menu,
  X,
  ChevronDown,
  User,
  LogOut,
  Bell,
  Search,
} from "lucide-react";
import { clsx } from "clsx";

const navigation = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Resources", href: "/resources", icon: Server },
  { name: "Users", href: "/users", icon: Users },
  { name: "Matrix", href: "/matrix", icon: Grid },
  { name: "Policies", href: "/policies", icon: Shield },
  { name: "Challenges", href: "/challenges", icon: AlertTriangle },
  { name: "Audit", href: "/audit", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const location = useLocation();

  return (
    <div className="min-h-screen bg-surface-50 flex">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          "fixed lg:static inset-y-0 left-0 z-50 w-64 bg-white border-r border-surface-200 transform transition-transform duration-200 ease-in-out lg:translate-x-0",
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        )}
        aria-label="Sidebar navigation"
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-between h-16 px-4 border-b border-surface-200">
            <NavLink to="/" className="flex items-center gap-2 text-xl font-bold text-primary-600">
              <svg className="w-8 h-8 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span className="hidden sm:inline">CyberVault Plus</span>
            </NavLink>
            <button
              className="lg:hidden p-2 rounded-lg text-surface-500 hover:bg-surface-100"
              onClick={() => setSidebarOpen(false)}
              aria-label="Close sidebar"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Main navigation">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href || (item.href !== "/" && location.pathname.startsWith(item.href));
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={({ isActive }) =>
                    clsx(
                      "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors",
                      isActive
                        ? "bg-primary-50 text-primary-700"
                        : "text-surface-600 hover:bg-surface-100 hover:text-surface-900"
                    )
                  }
                  aria-current={isActive ? "page" : undefined}
                >
                  <Icon className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
                  {item.name}
                </NavLink>
              );
            })}
          </nav>

          {/* User section */}
          <div className="p-4 border-t border-surface-200">
            <div className="relative">
              <button
                className="flex items-center gap-3 w-full px-3 py-2 rounded-lg hover:bg-surface-100 transition-colors"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                aria-expanded={userMenuOpen}
                aria-haspopup="true"
              >
                <div className="w-9 h-9 rounded-full bg-primary-100 flex items-center justify-center">
                  <User className="w-5 h-5 text-primary-600" />
                </div>
                <div className="flex-1 min-w-0 text-left">
                  <p className="text-sm font-medium text-surface-900 truncate">Admin User</p>
                  <p className="text-xs text-surface-500 truncate">admin@cybervault.example</p>
                </div>
                <ChevronDown className="w-4 h-4 text-surface-400" />
              </button>

              {userMenuOpen && (
                <div className="absolute bottom-full left-0 right-0 mb-2 bg-white rounded-lg border border-surface-200 shadow-lg py-1 z-50 animate-fade-in">
                  <div className="px-3 py-2 border-b border-surface-200">
                    <p className="text-xs font-medium text-surface-500 uppercase tracking-wider">Account</p>
                  </div>
                  <button className="w-full px-4 py-2 text-left text-sm text-surface-700 hover:bg-surface-50 flex items-center gap-2">
                    <User className="w-4 h-4" />
                    Profile
                  </button>
                  <button className="w-full px-4 py-2 text-left text-sm text-surface-700 hover:bg-surface-50 flex items-center gap-2">
                    <Settings className="w-4 h-4" />
                    Settings
                  </button>
                  <div className="border-t border-surface-200 my-1" />
                  <button className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2">
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 lg:ml-64 min-h-screen">
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-white border-b border-surface-200">
          <div className="flex items-center justify-between h-16 px-4 sm:px-6">
            <div className="flex items-center gap-4">
              <button
                className="lg:hidden p-2 rounded-lg text-surface-500 hover:bg-surface-100"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open sidebar"
              >
                <Menu className="w-6 h-6" />
              </button>
              <div className="hidden sm:block">
                <h1 className="text-lg font-semibold text-surface-900">CyberVault Plus Admin</h1>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* Search */}
              <div className="hidden md:block relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" />
                <input
                  type="search"
                  placeholder="Search resources, users, policies..."
                  className="pl-10 pr-4 py-2 w-64 bg-surface-100 border-none rounded-lg text-sm text-surface-900 placeholder-surface-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:bg-white"
                  aria-label="Search"
                />
              </div>

              {/* Notifications */}
              <button className="relative p-2 rounded-lg text-surface-500 hover:bg-surface-100 transition-colors" aria-label="Notifications">
                <Bell className="w-5 h-5" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
              </button>

              {/* User avatar - mobile */}
              <div className="md:hidden">
                <button className="p-2 rounded-lg text-surface-500 hover:bg-surface-100" aria-label="User menu">
                  <User className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="p-4 sm:p-6 lg:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}