import { CredentialsGenerator } from "../../domain/services/autocompletado/credentials-generator";
import {
  EmailWithSalt,
  PasswordWithPepper,
  OriginalCredentials,
} from "../../domain/services/autocompletado/credentials-types";

/**
 * Use Case: Extraer credenciales originales de credenciales almacenadas
 *
 * Responsabilidad: Quitar sal y pimienta para recuperar credenciales originales
 * Dependencias: Servicio de generación de credenciales (dominio)
 *
 * NOTA: Recibe tipos fuertes para seguridad en tiempo de compilación
 */
export class ExtractCredentialsUseCase {
  constructor(private credentialsGenerator: CredentialsGenerator) {}

  async execute(
    storedEmail: EmailWithSalt,
    storedPassword: PasswordWithPepper,
  ): Promise<OriginalCredentials> {
    return await this.credentialsGenerator.extractOriginalCredentialsStrong(
      storedEmail,
      storedPassword,
    );
  }
}
