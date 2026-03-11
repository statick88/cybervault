// Domain Layer - Main Entry Point
// Exporta todos los contratos de dominio

// Entidades
export { Vault } from "./entities/vault";
export type { VaultProps } from "./entities/vault";
export { Vulnerability } from "./entities/vulnerability";
export type {
  VulnerabilityProps,
  SeverityLevel,
  VulnerabilityStatus,
} from "./entities/vulnerability";

// Value Objects
export { VaultId, VulnerabilityId, CryptoHash } from "./value-objects/ids";

// Repositorios
export type {
  IVaultRepository,
  IVulnerabilityRepository,
} from "./repositories";

// Servicios
export type {
  ICryptoService,
  IIPFSService,
  IAuditService,
  SecurityReport,
  SecurityConfigCheck,
} from "./services";
