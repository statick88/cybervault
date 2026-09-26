/**
 * Operations Registry — Supported Operations for CyberVault Plus
 *
 * Central definition of all operations that can be authorized via capabilities.
 * Each operation has metadata for UI, risk assessment, and policy enforcement.
 */

export type CapabilityOperation =
  | "AUTOFILL"
  | "VIEW"
  | "TOTP"
  | "CONNECT"
  | "READ"
  | "ADMIN"
  | "BACKUP"
  | "RESTORE"
  | "ROTATE_SECRET"
  | "EDIT_SECRET"
  | "DELETE_SECRET"
  | "EXPORT_SECRET";

export interface OperationMetadata {
  operation: CapabilityOperation;
  displayName: string;
  description: string;
  category: "credential" | "connection" | "administrative" | "backup" | "secret";
  defaultRiskLevel: "low" | "medium" | "high" | "critical";
  requiresStepUpByDefault: boolean;
  // For audit/logging
  auditCategory: string;
}

/** Registry of all supported operations with metadata */
export const OPERATIONS_REGISTRY: Record<CapabilityOperation, OperationMetadata> = {
  AUTOFILL: {
    operation: "AUTOFILL",
    displayName: "Auto-fill Credentials",
    description: "Automatically fill username/password in web forms",
    category: "credential",
    defaultRiskLevel: "medium",
    requiresStepUpByDefault: false,
    auditCategory: "credential_access",
  },
  VIEW: {
    operation: "VIEW",
    displayName: "View Credential",
    description: "View credential details (username, password, metadata) in UI",
    category: "credential",
    defaultRiskLevel: "low",
    requiresStepUpByDefault: false,
    auditCategory: "credential_access",
  },
  TOTP: {
    operation: "TOTP",
    displayName: "Generate TOTP Code",
    description: "Generate time-based one-time password for 2FA",
    category: "credential",
    defaultRiskLevel: "low",
    requiresStepUpByDefault: false,
    auditCategory: "credential_access",
  },
  CONNECT: {
    operation: "CONNECT",
    displayName: "Initiate Connection",
    description: "Establish SSH, RDP, VPN, or database connection using credential",
    category: "connection",
    defaultRiskLevel: "medium",
    requiresStepUpByDefault: false,
    auditCategory: "connection",
  },
  READ: {
    operation: "READ",
    displayName: "Read Resource Data",
    description: "Read data from resource (database query, API GET, file read)",
    category: "connection",
    defaultRiskLevel: "low",
    requiresStepUpByDefault: false,
    auditCategory: "data_access",
  },
  ADMIN: {
    operation: "ADMIN",
    displayName: "Administrative Action",
    description: "Perform administrative operations (user mgmt, config changes, deployments)",
    category: "administrative",
    defaultRiskLevel: "critical",
    requiresStepUpByDefault: true,
    auditCategory: "admin_action",
  },
  BACKUP: {
    operation: "BACKUP",
    displayName: "Trigger Backup",
    description: "Initiate backup of resource (database dump, config backup, snapshot)",
    category: "backup",
    defaultRiskLevel: "high",
    requiresStepUpByDefault: true,
    auditCategory: "backup",
  },
  RESTORE: {
    operation: "RESTORE",
    displayName: "Restore from Backup",
    description: "Restore resource from backup (database restore, config restore)",
    category: "backup",
    defaultRiskLevel: "critical",
    requiresStepUpByDefault: true,
    auditCategory: "backup",
  },
  ROTATE_SECRET: {
    operation: "ROTATE_SECRET",
    displayName: "Rotate Secret",
    description: "Rotate credential/secret (password change, key rotation, cert renewal)",
    category: "secret",
    defaultRiskLevel: "high",
    requiresStepUpByDefault: true,
    auditCategory: "secret_management",
  },
  EDIT_SECRET: {
    operation: "EDIT_SECRET",
    displayName: "Edit Secret",
    description: "Modify secret value or metadata",
    category: "secret",
    defaultRiskLevel: "high",
    requiresStepUpByDefault: true,
    auditCategory: "secret_management",
  },
  DELETE_SECRET: {
    operation: "DELETE_SECRET",
    displayName: "Delete Secret",
    description: "Permanently delete a secret/credential",
    category: "secret",
    defaultRiskLevel: "critical",
    requiresStepUpByDefault: true,
    auditCategory: "secret_management",
  },
  EXPORT_SECRET: {
    operation: "EXPORT_SECRET",
    displayName: "Export Secret",
    description: "Export secret in portable format (may be denied by policy)",
    category: "secret",
    defaultRiskLevel: "critical",
    requiresStepUpByDefault: true,
    auditCategory: "secret_management",
  },
} as const;

/** All operation codes as array */
export const ALL_OPERATIONS: CapabilityOperation[] = Object.keys(OPERATIONS_REGISTRY) as CapabilityOperation[];

/** Operations grouped by category */
export const OPERATIONS_BY_CATEGORY: Record<string, CapabilityOperation[]> = {
  credential: ["AUTOFILL", "VIEW", "TOTP"],
  connection: ["CONNECT", "READ"],
  administrative: ["ADMIN"],
  backup: ["BACKUP", "RESTORE"],
  secret: ["ROTATE_SECRET", "EDIT_SECRET", "DELETE_SECRET", "EXPORT_SECRET"],
};

/** Operations that require step-up by default (per security invariants) */
export const DEFAULT_STEP_UP_OPERATIONS: CapabilityOperation[] = [
  "ADMIN",
  "BACKUP",
  "RESTORE",
  "ROTATE_SECRET",
  "EDIT_SECRET",
  "DELETE_SECRET",
  "EXPORT_SECRET",
];

/** Operations that are always denied by default (configurable via policy) */
export const DEFAULT_DENIED_OPERATIONS: CapabilityOperation[] = [];

/**
 * Get metadata for an operation
 */
export function getOperationMetadata(operation: CapabilityOperation): OperationMetadata {
  return OPERATIONS_REGISTRY[operation];
}

/**
 * Get default risk level for an operation
 */
export function getDefaultRiskLevel(operation: CapabilityOperation): OperationMetadata["defaultRiskLevel"] {
  return OPERATIONS_REGISTRY[operation].defaultRiskLevel;
}

/**
 * Check if operation requires step-up by default
 */
export function requiresStepUpByDefault(operation: CapabilityOperation): boolean {
  return OPERATIONS_REGISTRY[operation].requiresStepUpByDefault;
}

/**
 * Get all operations in a category
 */
export function getOperationsByCategory(category: string): CapabilityOperation[] {
  return OPERATIONS_BY_CATEGORY[category] || [];
}

/**
 * Validate operation code
 */
export function isValidOperation(operation: string): operation is CapabilityOperation {
  return operation in OPERATIONS_REGISTRY;
}

/**
 * Get audit category for operation
 */
export function getAuditCategory(operation: CapabilityOperation): string {
  return OPERATIONS_REGISTRY[operation].auditCategory;
}