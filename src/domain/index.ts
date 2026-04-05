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
export { Credential } from "./entities/credential";
export type { CredentialProps } from "./entities/credential";

// Value Objects
export {
  VaultId,
  VulnerabilityId,
  CredentialId,
  CryptoHash,
} from "./value-objects/ids";

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
