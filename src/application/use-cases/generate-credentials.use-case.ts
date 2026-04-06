import { CredentialsGenerator } from "../../domain/services/autocompletado/credentials-generator";
import { GeneratedCredentials } from "../../domain/services/autocompletado/credentials-generator";

/**
 * Use Case: Generar credenciales seguras con sal y pimienta
 *
 * Responsabilidad: Generar credenciales aleatorias de alta entropía para un dominio
 * Dependencias: Servicio de generación de credenciales (dominio)
 */
export class GenerateCredentialsUseCase {
  constructor(private credentialsGenerator: CredentialsGenerator) {}

  async execute(domain: string): Promise<GeneratedCredentials> {
    return await this.credentialsGenerator.generateCredentials(domain);
  }
}
