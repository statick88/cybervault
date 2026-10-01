import React from "react";
import {
  Users,
  Server,
  Shield,
  AlertTriangle,
  Grid,
  Activity,
  ArrowUpRight,
  ArrowDownRight,
} from "lucide-react";
import { clsx } from "clsx";
import { resourcesApi, usersApi, entitlementsApi, challengesApi, healthApi } from "../services/api";

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: "up" | "down";
  icon: React.ReactNode;
  color: string;
}

function StatCard({ title, value, change, changeType, icon, color }: StatCardProps) {
  return (
    <div className="card">
      <div className="card-body">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-surface-500">{title}</p>
            <p className="text-2xl font-bold text-surface-900 mt-1">{value}</p>
            {change && (
              <p className={clsx("text-sm mt-1 flex items-center gap-1", changeType === "up" ? "text-green-600" : "text-red-600")}>
                {changeType === "up" ? <ArrowUpRight className="w-4 h-4" /> : <ArrowDownRight className="w-4 h-4" />}
                <span>{change}</span>
                <span className="text-surface-500">vs last period</span>
              </p>
            )}
          </div>
          <div className={clsx("p-3 rounded-xl", color)}>
            {icon}
          </div>
        </div>
      </div>
    </div>
  );
}

export function Dashboard() {
  const [stats, setStats] = React.useState({
    totalResources: 0,
    totalUsers: 0,
    activeEntitlements: 0,
    pendingChallenges: 0,
    systemHealth: "healthy" as "healthy" | "unhealthy",
  });
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchStats() {
      try {
        const [resourcesRes, usersRes, entitlementsRes, challengesRes, healthRes] = await Promise.all([
          resourcesApi.list({ limit: 1 }),
          usersApi.list({ limit: 1, active: true }),
          entitlementsApi.list({ activeOnly: true, limit: 1 }),
          challengesApi.list({ status: "pending", limit: 1 }),
          healthApi.health(),
        ]);

        setStats({
          totalResources: resourcesRes.total,
          totalUsers: usersRes.total,
          activeEntitlements: entitlementsRes.total,
          pendingChallenges: challengesRes.total,
          systemHealth: healthRes.status,
        });
      } catch (error) {
        console.error("Failed to fetch dashboard stats:", error);
      } finally {
        setLoading(false);
      }
    }

    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  const statsCards = [
    {
      title: "Total Resources",
      value: stats.totalResources,
      change: "+12%",
      changeType: "up" as const,
      icon: <Server className="w-6 h-6" />,
      color: "bg-blue-100 text-blue-600",
    },
    {
      title: "Active Users",
      value: stats.totalUsers,
      change: "+5%",
      changeType: "up" as const,
      icon: <Users className="w-6 h-6" />,
      color: "bg-green-100 text-green-600",
    },
    {
      title: "Active Entitlements",
      value: stats.activeEntitlements,
      change: "+8%",
      changeType: "up" as const,
      icon: <Shield className="w-6 h-6" />,
      color: "bg-purple-100 text-purple-600",
    },
    {
      title: "Pending Challenges",
      value: stats.pendingChallenges,
      change: "-3%",
      changeType: "down" as const,
      icon: <AlertTriangle className="w-6 h-6" />,
      color: "bg-amber-100 text-amber-600",
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-surface-900">Dashboard</h1>
          <p className="text-surface-500 mt-1">Overview of your CyberVault Plus environment</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={clsx(
            "px-3 py-1 rounded-full text-xs font-medium",
            stats.systemHealth === "healthy" ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
          )}>
            <span className={clsx("inline-block w-2 h-2 rounded-full mr-1.5", stats.systemHealth === "healthy" ? "bg-green-500" : "bg-red-500")} />
            System {stats.systemHealth}
          </span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {loading ? (
          <div className="col-span-full flex items-center justify-center gap-2 py-12 text-surface-500">
            <svg className="animate-spin h-6 w-6 text-primary-600" viewBox="0 0 24 24" aria-hidden="true"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>
            Loading dashboard...
          </div>
        ) : statsCards.map((stat) => (
          <StatCard key={stat.title} {...stat} />
        ))}
      </div>

      {/* Activity & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-surface-900">Recent Activity</h2>
          </div>
          <div className="card-body">
            <div className="space-y-4">
              <ActivityItem
                icon={<Activity className="w-5 h-5 text-blue-500" />}
                title="New resource created"
                description="db-prod-001 (PostgreSQL) added by admin@company.com"
                time="2 min ago"
              />
              <ActivityItem
                icon={<Shield className="w-5 h-5 text-green-500" />}
                title="Entitlement updated"
                description="john.doe@company.com granted AUTOFILL on db-prod-001"
                time="15 min ago"
              />
              <ActivityItem
                icon={<AlertTriangle className="w-5 h-5 text-amber-500" />}
                title="Challenge triggered"
                description="Step-up required for jane.smith@company.com on vpn-corp-001"
                time="1 hour ago"
              />
              <ActivityItem
                icon={<Users className="w-5 h-5 text-purple-500" />}
                title="New user added"
                description="mike.wilson@company.com added as operator"
                time="3 hours ago"
              />
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="card">
          <div className="card-header">
            <h2 className="text-lg font-semibold text-surface-900">Quick Actions</h2>
          </div>
          <div className="card-body">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <QuickAction
                icon={<Server className="w-5 h-5" />}
                title="Add Resource"
                description="Register a new infrastructure resource"
                href="/resources"
              />
              <QuickAction
                icon={<Users className="w-5 h-5" />}
                title="Invite User"
                description="Add a new team member"
                href="/users"
              />
              <QuickAction
                icon={<Grid className="w-5 h-5" />}
                title="Configure Matrix"
                description="Set up user-resource entitlements"
                href="/matrix"
              />
              <QuickAction
                icon={<Shield className="w-5 h-5" />}
                title="Update Policies"
                description="Adjust risk thresholds and TTLs"
                href="/policies"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityItem({ icon, title, description, time }: { icon: React.ReactNode; title: string; description: string; time: string }) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-surface-100 flex items-center justify-center">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-surface-900">{title}</p>
        <p className="text-sm text-surface-500 truncate">{description}</p>
        <p className="text-xs text-surface-400 mt-1">{time}</p>
      </div>
    </div>
  );
}

function QuickAction({ icon, title, description, href }: { icon: React.ReactNode; title: string; description: string; href: string }) {
  return (
    <a href={href} className="card p-4 hover:shadow-md transition-shadow">
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-primary-100 flex items-center justify-center text-primary-600">
          {icon}
        </div>
        <div>
          <h3 className="font-medium text-surface-900">{title}</h3>
          <p className="text-sm text-surface-500 mt-1">{description}</p>
        </div>
      </div>
    </a>
  );
}