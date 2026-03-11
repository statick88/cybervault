// Domain Repository Interfaces
// Patrón de repositorio para acceso a datos

import { Vault } from './entities/vault';
import { Vulnerability } from './entities/vulnerability';
import { VaultId, VulnerabilityId } from './value-objects/ids';

/**
 * Repositorio para Vaults (bóvedas de claves)
 */
export interface IVaultRepository {
  /**
   * Guarda una bóveda en el almacenamiento
   */
  save(vault: Vault): Promise<Vault>;

  /**
   * Obtiene una bóveda por su ID
   */
  findById(id: VaultId): Promise<Vault | null>;

  /**
   * Elimina una bóveda
   */
  delete(id: VaultId): Promise<boolean>;

  /**
   * Listar todas las bóvedas
   */
  list(): Promise<Vault[]>;
}

/**
 * Repositorio para Vulnerabilidades
 */
export interface IVulnerabilityRepository {
  /**
   * Guarda una vulnerabilidad
   */
  save(vulnerability: Vulnerability): Promise<Vulnerability>;

  /**
   * Obtiene una vulnerabilidad por su ID
   */
  findById(id: VulnerabilityId): Promise<Vulnerability | null>;

  /**
   * Busca vulnerabilidades por criterios
   */
  search(criteria: {
    severity?: string;
    status?: string;
    dateFrom?: Date;
    dateTo?: Date;
  }): Promise<Vulnerability[]>;

  /**
   * Elimina una vulnerabilidad
   */
  delete(id: VulnerabilityId): Promise<boolean>;
}
