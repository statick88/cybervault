import { IVaultRepository } from "../../domain/repositories";
import { Vault } from "../../domain/entities/vault";

/**
 * Use Case: Crear una nueva bóveda
 *
 * Responsabilidad: Orquestar la creación de una bóveda vacía con metadata inicial
 * Dependencias: Repositorio de bóvedas, servicio de criptografía (para futuro uso)
 */
export class CreateVaultUseCase {
  constructor(private vaultRepository: IVaultRepository) {}

  async execute(data: {
    name: string;
    description?: string;
    encryptionKeyId: string;
  }): Promise<Vault> {
    const vault = Vault.create({
      name: data.name,
      description: data.description,
      encryptedData: "", // placeholder - frontend encripta y guarda después
      encryptionKeyId: data.encryptionKeyId,
    });
    return await this.vaultRepository.save(vault);
  }
}
