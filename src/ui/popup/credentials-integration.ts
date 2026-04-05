/**
 * Integración del módulo de credenciales con sal y pimienta
 * Proporciona funciones para generar, extraer y validar credenciales con protección criptográfica
 */

import {
  CredentialsGenerator,
  CredentialsValidator,
  EntropyValidator,
  CredentialsTypeFactory,
  GeneratedCredentials,
  GeneratedCredentialsStrong,
  OriginalCredentials,
} from "../../domain/services/autocompletado";
import { CryptoService } from "../../infrastructure/crypto/crypto-service";

// Instancia única del generador de credenciales
let generatorInstance: CredentialsGenerator | null = null;

/**
 * Obtiene o crea la instancia del generador de credenciales
 */
function getGenerator(): CredentialsGenerator {
  if (!generatorInstance) {
    generatorInstance = new CredentialsGenerator();
  }
  return generatorInstance;
}

/**
 * Genera credenciales con sal y pimienta para un dominio específico
 * @param domain Dominio del sitio web (ej: "example.com")
 * @returns Objeto con credenciales generadas
 */
export async function generateSecureCredentials(
  domain: string
): Promise<GeneratedCredentials> {
  try {
    const generator = getGenerator();
    const result = await generator.generateCredentials(domain);
    return result;
  } catch (error) {
    console.error("Error generando credenciales seguras:", error);
    throw error;
  }
}

/**
 * Genera credenciales fuertes con sal y pimienta para un dominio específico
 * @param domain Dominio validado del sitio web
 * @returns Objeto con credenciales fuertes generadas
 */
export async function generateStrongCredentials(
  domain: string
): Promise<GeneratedCredentialsStrong> {
  try {
    const generator = getGenerator();
    // Primero validamos el dominio
    if (!CredentialsValidator.isValidDomain(domain)) {
      throw new Error(`Dominio inválido: ${domain}`);
    }
    // Creamos un tipo fuerte para el dominio
    const validDomain = CredentialsTypeFactory.createValidDomain(domain);
    // Generamos credenciales fuertes
    const result = await generator.generateCredentialsStrong(validDomain);
    return result;
  } catch (error) {
    console.error("Error generando credenciales fuertes:", error);
    throw error;
  }
}

/**
 * Extrae la credencial original desde credenciales almacenadas fuertes
 * @param storedCredentials Credenciales almacenadas (con sal y pimienta)
 * @returns Credenciales originales
 */
export async function extractOriginalCredentials(
  storedCredentials: GeneratedCredentialsStrong
): Promise<OriginalCredentials> {
  try {
    const generator = getGenerator();
    const original = await generator.extractOriginalCredentialsStrong(
      storedCredentials.email,
      storedCredentials.password
    );
    return original;
  } catch (error) {
    console.error("Error extrayendo credenciales originales:", error);
    throw error;
  }
}

/**
 * Valida el formato de un dominio
 * @param domain Dominio a validar
 * @returns true si el formato es válido
 */
export function validateDomainFormat(domain: string): boolean {
  return CredentialsValidator.isValidDomain(domain);
}

/**
 * Valida la entropía de una contraseña
 * @param password Contraseña a validar
 * @returns Información de entropía
 */
export function validatePasswordEntropy(
  password: string
): {
  isValid: boolean;
  entropy: number;
  strength: "weak" | "medium" | "strong" | "very-strong";
  feedback: string[];
} {
  const result = EntropyValidator.validatePasswordEntropy(password);
  
  // Determinar fortaleza basada en entropía
  let strength: "weak" | "medium" | "strong" | "very-strong";
  if (result.entropy < 28) strength = "weak";
  else if (result.entropy < 36) strength = "medium";
  else if (result.entropy < 60) strength = "strong";
  else strength = "very-strong";
  
  return {
    isValid: result.isValid,
    entropy: result.entropy,
    strength,
    feedback: result.details,
  };
}

/**
 * Genera una contraseña simple (sin sal/pimienta) para compatibilidad
 * @param length Longitud de la contraseña
 * @param options Opciones de caracteres
 * @returns Contraseña generada
 */
export function generateSimplePassword(
  length: number = 16,
  options: {
    uppercase?: boolean;
    lowercase?: boolean;
    numbers?: boolean;
    symbols?: boolean;
  } = {}
): string {
  const {
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
  } = options;

  let chars = "";
  if (uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lowercase) chars += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!chars) {
    throw new Error("Se debe seleccionar al menos un tipo de carácter");
  }

  let password = "";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }

  return password;
}
