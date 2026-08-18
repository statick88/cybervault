export { ChromeStorageVaultRepository } from "./ChromeStorageVaultRepository";
export { InMemoryVulnerabilityRepository } from "./InMemoryVulnerabilityRepository";
export { PostgresVaultRepository } from "./PostgresVaultRepository";
export { PostgresCredentialRepository } from "./PostgresCredentialRepository";

// Tipos de repositorios para facilitar la inyección de dependencias
export type {
  IVaultRepository,
  ICredentialRepository,
  IVulnerabilityRepository,
} from "../../domain/repositories";
