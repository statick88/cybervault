import React from "react"
import { Shield, Database, Mail, Bell, Save, Lock, Cpu } from "lucide-react"
import { clsx } from "clsx"

export function Settings() {
  const [activeTab, setActiveTab] = React.useState("general")
  const [settings, setSettings] = React.useState({
    general: { siteName: "CyberVault Plus", timezone: "UTC", language: "en" },
    security: { sessionTimeout: 30, mfaRequired: true, passwordMinLength: 12, maxFailedAttempts: 5, lockoutDuration: 30 },
    database: { host: "localhost", port: 5432, name: "cybervault", ssl: true, poolSize: 10 },
    email: { host: "smtp.example.com", port: 587, username: "", password: "", fromAddress: "noreply@cybervault.example", tls: true },
    notifications: { emailAlerts: true, slackWebhook: "", criticalOnly: false },
    advanced: { debugMode: false, logLevel: "info", corsOrigins: "https://cybervault.example.com", rateLimitEnabled: true, rateLimitMax: 100, rateLimitWindowMs: 900000 }
  })

  const tabs = [
    { id: "general", label: "General", icon: Shield },
    { id: "security", label: "Security", icon: Lock },
    { id: "database", label: "Database", icon: Database },
    { id: "email", label: "Email", icon: Mail },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "advanced", label: "Advanced", icon: Cpu }
  ]

  const handleSave = async (section: string) => {
    try {
      await fetch(`/api/v1/settings/${section}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings[section as keyof typeof settings]) })
      alert(`${section} settings saved successfully`)
    } catch (error) { console.error(`Failed to save ${section} settings:`, error) }
  }

  function renderGeneral() {
    return (
      <div className="space-y-4">
        <div><label className="label">Site Name</label><input type="text" value={settings.general.siteName} onChange={(e) => setSettings(p => ({ ...p, general: { ...p.general, siteName: e.target.value } }))} className="input" /></div>
        <div><label className="label">Timezone</label><select value={settings.general.timezone} onChange={(e) => setSettings(p => ({ ...p, general: { ...p.general, timezone: e.target.value } }))} className="input"><option value="UTC">UTC</option><option value="America/New_York">America/New_York</option><option value="Europe/London">Europe/London</option><option value="Asia/Tokyo">Asia/Tokyo</option></select></div>
        <div><label className="label">Language</label><select value={settings.general.language} onChange={(e) => setSettings(p => ({ ...p, general: { ...p.general, language: e.target.value } }))} className="input"><option value="en">English</option><option value="es">Spanish</option><option value="fr">French</option><option value="de">German</option></select></div>
      </div>
    )
  }

  function renderSecurity() {
    return (
      <div className="space-y-4">
        <div><label className="label">Session Timeout (minutes)</label><input value={settings.security.sessionTimeout} onChange={(e) => setSettings(p => ({ ...p, security: { ...p.security, sessionTimeout: parseInt(e.target.value) || 30 } }))} className="input" type="number" min="5" max="480" /></div>
        <div className="flex items-center gap-3"><input type="checkbox" id="mfaRequired" checked={settings.security.mfaRequired} onChange={(e) => setSettings(p => ({ ...p, security: { ...p.security, mfaRequired: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="mfaRequired" className="text-sm text-surface-700">Require MFA for all users</label></div>
        <div><label className="label">Minimum Password Length</label><input value={settings.security.passwordMinLength} onChange={(e) => setSettings(p => ({ ...p, security: { ...p.security, passwordMinLength: parseInt(e.target.value) || 12 } }))} className="input" type="number" min="8" max="64" /></div>
        <div><label className="label">Max Failed Attempts</label><input value={settings.security.maxFailedAttempts} onChange={(e) => setSettings(p => ({ ...p, security: { ...p.security, maxFailedAttempts: parseInt(e.target.value) || 5 } }))} className="input" type="number" min="1" max="20" /></div>
        <div><label className="label">Lockout Duration (minutes)</label><input value={settings.security.lockoutDuration} onChange={(e) => setSettings(p => ({ ...p, security: { ...p.security, lockoutDuration: parseInt(e.target.value) || 30 } }))} className="input" type="number" min="5" max="1440" /></div>
      </div>
    )
  }

  function renderDatabase() {
    return (
      <div className="space-y-4">
        <div><label className="label">Host</label><input type="text" value={settings.database.host} onChange={(e) => setSettings(p => ({ ...p, database: { ...p.database, host: e.target.value } }))} className="input" /></div>
        <div><label className="label">Port</label><input value={settings.database.port} onChange={(e) => setSettings(p => ({ ...p, database: { ...p.database, port: parseInt(e.target.value) || 5432 } }))} className="input" type="number" /></div>
        <div><label className="label">Database Name</label><input type="text" value={settings.database.name} onChange={(e) => setSettings(p => ({ ...p, database: { ...p.database, name: e.target.value } }))} className="input" /></div>
        <div className="flex items-center gap-3"><input type="checkbox" id="ssl" checked={settings.database.ssl} onChange={(e) => setSettings(p => ({ ...p, database: { ...p.database, ssl: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="ssl" className="text-sm text-surface-700">Enable SSL</label></div>
        <div><label className="label">Connection Pool Size</label><input value={settings.database.poolSize} onChange={(e) => setSettings(p => ({ ...p, database: { ...p.database, poolSize: parseInt(e.target.value) || 10 } }))} className="input" type="number" min="1" max="100" /></div>
      </div>
    )
  }

  function renderEmail() {
    return (
      <div className="space-y-4">
        <div><label className="label">SMTP Host</label><input type="text" value={settings.email.host} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, host: e.target.value } }))} className="input" /></div>
        <div><label className="label">SMTP Port</label><input value={settings.email.port} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, port: parseInt(e.target.value) || 587 } }))} className="input" type="number" /></div>
        <div><label className="label">Username</label><input type="text" value={settings.email.username} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, username: e.target.value } }))} className="input" /></div>
        <div><label className="label">Password</label><input type="password" value={settings.email.password} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, password: e.target.value } }))} className="input" /></div>
        <div><label className="label">From Address</label><input type="email" value={settings.email.fromAddress} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, fromAddress: e.target.value } }))} className="input" /></div>
        <div className="flex items-center gap-3"><input type="checkbox" id="tls" checked={settings.email.tls} onChange={(e) => setSettings(p => ({ ...p, email: { ...p.email, tls: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="tls" className="text-sm text-surface-700">Enable TLS</label></div>
      </div>
    )
  }

  function renderNotifications() {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3"><input type="checkbox" id="emailAlerts" checked={settings.notifications.emailAlerts} onChange={(e) => setSettings(p => ({ ...p, notifications: { ...p.notifications, emailAlerts: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="emailAlerts" className="text-sm text-surface-700">Enable email alerts for critical events</label></div>
        <div><label className="label">Slack Webhook URL</label><input type="url" value={settings.notifications.slackWebhook} onChange={(e) => setSettings(p => ({ ...p, notifications: { ...p.notifications, slackWebhook: e.target.value } }))} className="input" placeholder="https://hooks.slack.com/services/..." /></div>
        <div className="flex items-center gap-3"><input type="checkbox" id="criticalOnly" checked={settings.notifications.criticalOnly} onChange={(e) => setSettings(p => ({ ...p, notifications: { ...p.notifications, criticalOnly: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="criticalOnly" className="text-sm text-surface-700">Only send alerts for critical severity events</label></div>
      </div>
    )
  }

  function renderAdvanced() {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3"><input type="checkbox" id="debugMode" checked={settings.advanced.debugMode} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, debugMode: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="debugMode" className="text-sm text-surface-700">Enable debug mode (verbose logging)</label></div>
        <div><label className="label">Log Level</label><select value={settings.advanced.logLevel} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, logLevel: e.target.value } }))} className="input"><option value="debug">Debug</option><option value="info">Info</option><option value="warn">Warning</option><option value="error">Error</option></select></div>
        <div><label className="label">CORS Origins (comma-separated)</label><input type="text" value={settings.advanced.corsOrigins} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, corsOrigins: e.target.value } }))} className="input" placeholder="https://app.example.com, https://admin.example.com" /></div>
        <div className="flex items-center gap-3"><input type="checkbox" id="rateLimitEnabled" checked={settings.advanced.rateLimitEnabled} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, rateLimitEnabled: e.target.checked } }))} className="rounded border-surface-300 text-primary-600 focus:ring-primary-500" /><label htmlFor="rateLimitEnabled" className="text-sm text-surface-700">Enable rate limiting</label></div>
        <div><label className="label">Rate Limit Max Requests</label><input value={settings.advanced.rateLimitMax} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, rateLimitMax: parseInt(e.target.value) || 100 } }))} className="input" type="number" min="1" max="10000" /></div>
        <div><label className="label">Rate Limit Window (ms)</label><input value={settings.advanced.rateLimitWindowMs} onChange={(e) => setSettings(p => ({ ...p, advanced: { ...p.advanced, rateLimitWindowMs: parseInt(e.target.value) || 900000 } }))} className="input" type="number" min="60000" max="3600000" /></div>
      </div>
    )
  }

  function renderTabContent(tabId: string) {
    switch (tabId) {
      case "general": return renderGeneral()
      case "security": return renderSecurity()
      case "database": return renderDatabase()
      case "email": return renderEmail()
      case "notifications": return renderNotifications()
      case "advanced": return renderAdvanced()
      default: return <div className="text-center py-12 text-surface-500">Select a tab to view settings</div>
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div><h1 className="text-2xl font-bold text-surface-900">Settings</h1><p className="text-surface-500 mt-1">Configure CyberVault Plus system settings</p></div>
        <button onClick={() => handleSave(activeTab)} className="btn-primary"><Save className="w-4 h-4 mr-2" />Save Changes</button>
      </div>

      <div className="card">
        <div className="border-b border-surface-200">
          <nav className="flex overflow-x-auto" aria-label="Settings tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  "px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap",
                  activeTab === tab.id
                    ? "border-primary-600 text-primary-600"
                    : "border-transparent text-surface-500 hover:text-surface-700 hover:border-surface-300"
                )}
              >
                <tab.icon className="w-4 h-4 mr-2" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="card-body p-6">
          {renderTabContent(activeTab)}
        </div>
      </div>
    </div>
  )
}