/**
 * Plus Admin API Client
 * Type-safe API client for Plus Admin UI
 */

const API_BASE = process.env.REACT_APP_PLUS_API_URL || "http://localhost:3001";

interface RequestOptions extends RequestInit {
  params?: Record<string, string | number | boolean>;
}

function toQueryString(params: Record<string, string | number | boolean>): string {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  return searchParams.toString();
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { params, ...fetchOptions } = options;
  const queryString = params ? toQueryString(params) : "";
  const url = `${API_BASE}${endpoint}${queryString ? `?${queryString}` : ""}`;

  const response = await fetch(url, {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      ...fetchOptions.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// Types
export interface Resource {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  environment: string;
  criticality: string;
  description?: string;
  tags: string[];
  ownerTeam?: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ResourceCreateInput {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  environment: string;
  criticality: string;
  description?: string;
  tags?: string[];
  ownerTeam?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  habitualCountries: string[];
  timezone: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface UserCreateInput {
  email: string;
  name: string;
  role: string;
  habitualCountries?: string[];
  timezone?: string;
}

export interface Entitlement {
  id: string;
  userId: string;
  resourceId: string;
  pestilloState: "closed" | "enabled" | "step_up" | "temporary";
  allowedOperations: string[];
  validFrom?: string;
  validUntil?: string;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  resource?: Resource;
  user?: User;
}

export interface EntitlementUpdateInput {
  pestilloState?: "closed" | "enabled" | "step_up" | "temporary";
  allowedOperations?: string[];
  validFrom?: string;
  validUntil?: string;
}

export interface Challenge {
  id: string;
  userId: string;
  resourceId: string;
  operation: string;
  secretRef: string;
  deviceId?: string;
  type: string;
  status: string;
  emailSentAt?: number;
  accessedAt?: number;
  completedAt?: number;
  expiresAt: number;
  attempts: number;
  maxAttempts: number;
  riskScore?: number;
  riskReasons?: string[];
  createdAt: number;
  updatedAt: number;
  resource?: Resource;
  user?: User;
}

export interface AuditEntry {
  id: string;
  event: string;
  userId: string;
  resourceId?: string;
  operation?: string;
  decision: string;
  riskScore?: number;
  riskReasons?: string[];
  context?: Record<string, unknown>;
  timestamp: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface RiskEvaluation {
  totalScore: number;
  factors: Array<{
    name: string;
    score: number;
    weight: number;
    reason: string;
  }>;
  decision: "allow" | "challenge" | "deny";
  timestamp: number;
}

// Resources API
export const resourcesApi = {
  list: (params?: { name?: string; type?: string; environment?: string; criticality?: string; tags?: string; active?: boolean; limit?: number; offset?: number }) =>
    request<{ resources: Resource[]; total: number }>("/api/v1/resources", { params }),

  get: (id: string) => request<Resource>(`/api/v1/resources/${id}`),

  create: (data: ResourceCreateInput) => request<Resource>("/api/v1/resources", { method: "POST", body: JSON.stringify(data) }),

  update: (id: string, data: Partial<ResourceCreateInput>) => request<Resource>(`/api/v1/resources/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  delete: (id: string) => request<void>(`/api/v1/resources/${id}`, { method: "DELETE" }),
};

// Users API
export const usersApi = {
  list: (params?: { name?: string; email?: string; role?: string; active?: boolean; habitualCountry?: string; limit?: number; offset?: number }) =>
    request<{ users: User[]; total: number }>("/api/v1/users", { params }),

  get: (id: string) => request<User>(`/api/v1/users/${id}`),

  create: (data: UserCreateInput) => request<User>("/api/v1/users", { method: "POST", body: JSON.stringify(data) }),

  update: (id: string, data: Partial<UserCreateInput>) => request<User>(`/api/v1/users/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  delete: (id: string) => request<void>(`/api/v1/users/${id}`, { method: "DELETE" }),
};

// Entitlements API
export const entitlementsApi = {
  list: (params?: { userId?: string; resourceId?: string; pestilloState?: string; activeOnly?: boolean; limit?: number; offset?: number }) =>
    request<{ entitlements: Entitlement[]; total: number }>("/api/v1/entitlements", { params }),

  get: (id: string) => request<Entitlement>(`/api/v1/entitlements/${id}`),

  getByUserAndResource: (userId: string, resourceId: string) => request<Entitlement | null>(`/api/v1/entitlements/user/${userId}/resource/${resourceId}`),

  create: (data: { userId: string; resourceId: string; pestilloState: string; allowedOperations: string[]; validFrom?: string; validUntil?: string; createdBy: string }) =>
    request<Entitlement>("/api/v1/entitlements", { method: "POST", body: JSON.stringify(data) }),

  update: (id: string, data: EntitlementUpdateInput) => request<Entitlement>(`/api/v1/entitlements/${id}`, { method: "PATCH", body: JSON.stringify(data) }),

  delete: (id: string) => request<void>(`/api/v1/entitlements/${id}`, { method: "DELETE" }),

  getMatrix: (params?: { userId?: string; resourceId?: string }) => request<Entitlement[]>("/api/v1/entitlements/matrix", { params }),
};

// Challenges API
export const challengesApi = {
  list: (params?: { userId?: string; status?: string; limit?: number; offset?: number }) =>
    request<{ challenges: any[]; total: number }>("/api/v1/challenges", { params }),

  get: (id: string) => request<any>(`/api/v1/challenges/${id}`),

  getPendingByUser: (userId: string) => request<any[]>(`/api/v1/challenges/user/${userId}/pending`),
};

// Audit API
export const auditApi = {
  list: (params?: { event?: string; userId?: string; resourceId?: string; decision?: string; from?: string; to?: string; limit?: number; offset?: number }) =>
    request<{ entries: any[]; total: number }>("/api/v1/audit", { params }),
};

// Capabilities API
export const capabilitiesApi = {
  request: (data: {
    userId: string;
    resourceId: string;
    operation: string;
    secretRef: string;
    deviceId?: string;
    assurance: 1 | 2 | 3;
    ttlSeconds?: number;
    context?: Record<string, unknown>;
  }) => request<any>("/api/v1/capabilities/request", { method: "POST", body: JSON.stringify(data) }),
};

// Public Key API
export const cryptoApi = {
  getPublicKey: () => request<{ publicKey: string; algorithm: string }>("/api/v1/crypto/public-key"),
};

// Health API
export const healthApi = {
  health: () => request<any>("/health"),
  ready: () => request<any>("/ready"),
};

// Policies API (for risk thresholds, TTLs, etc.)
// NOTE: the server does not expose GET /api/v1/policies yet; this interface is
// the shape the admin UI reads and writes (see pages/Policies.tsx formData).
export interface Policy {
  id: string;
  name: string;
  description: string;
  riskThreshold: number;
  challengeTtlMinutes: number;
  pinTtlMinutes: number;
  maxAttempts: number;
  newCountryRisk: number;
  unknownCountryRisk: number;
  newIpRisk: number;
  newDeviceRisk: number;
  outsideBusinessHoursRisk: number;
  workDays: string;
  workHoursStart: string;
  workHoursEnd: string;
  forcedStepUpOps: string[];
  alwaysDeniedOps: string[];
}

export const policiesApi = {
  getRiskPolicy: () => request<any>("/api/v1/policies/risk"),
  updateRiskPolicy: (data: any) => request<any>("/api/v1/policies/risk", { method: "PATCH", body: JSON.stringify(data) }),

  getChallengePolicy: () => request<any>("/api/v1/policies/challenge"),
  updateChallengePolicy: (data: any) => request<any>("/api/v1/policies/challenge", { method: "PATCH", body: JSON.stringify(data) }),

  getOperationPolicy: () => request<any>("/api/v1/policies/operations"),
  updateOperationPolicy: (data: any) => request<any>("/api/v1/policies/operations", { method: "PATCH", body: JSON.stringify(data) }),
};