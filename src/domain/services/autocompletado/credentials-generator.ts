/**
 * Generador de Credenciales con Sal y Pimienta
 * Implementa el concepto de "salting" y "peppering" para mayor seguridad en credenciales almacenadas
 */

import { CryptoService } from "../../../infrastructure/crypto/crypto-service";
import {
  InvalidEmailFormatError,
  InvalidPasswordFormatError,
  SaltExtractionError,
  PepperExtractionError,
  InvalidDomainError,
} from "./credentials-errors";
import { CredentialsValidator } from "./credentials-validator";

import {
  EmailWithSalt,
  PasswordWithPepper,
  OriginalCredentials,
  CredentialsTypeFactory,
  GeneratedCredentialsStrong,
  ValidDomain,
  CredentialsTypeUtils,
} from "./credentials-types";
import { EntropyValidator, RandomnessAnalyzer } from "./entropy-validator";

export interface GeneratedCredentials {
  email: string;
  password: string;
  originalEmail: string;
  originalPassword: string;
  salt: string;
  pepper: string;
}

export interface StoredCredentials {
  email: string;
  password: string;
  domain: string;
}

export class CredentialsGenerator {
  /**
   * Constructor del generador de credenciales
   * @param _cryptoService Servicio de criptografía inyectado (no se usa actualmente)
   */
  constructor(_cryptoService?: CryptoService) {
    // No se utiliza, se inyecta solo por compatibilidad
  }

  /**
   * Genera credenciales seguras con sal y pimienta
   * @param domain Dominio del sitio web
   * @returns Credenciales generadas con sal y pimienta
   * @throws InvalidDomainError si el dominio es inválido
   */
  async generateCredentials(domain: string): Promise<GeneratedCredentials> {
    // Validar dominio
    if (!CredentialsValidator.isValidDomain(domain)) {
      throw new InvalidDomainError(domain);
    }

    // Generar sal aleatoria (32 caracteres hexadecimales = 128 bits)
    const salt = await this.generateRandomString(32);

    // Validar entropía de la sal
    EntropyValidator.validateSaltEntropy(salt);

    // Generar pimienta aleatoria (32 caracteres hexadecimales = 128 bits)
    const pepper = await this.generateRandomString(32);

    // Validar entropía de la pimienta
    EntropyValidator.validatePepperEntropy(pepper);

    // Generar email base (usuario aleatorio - 16 caracteres)
    const userBase = await this.generateRandomString(16);

    // Generar password base (32 caracteres aleatorios con entropía)
    const passwordBase = await this.generateComplexPassword(32);

    // Validar entropía del password base
    const passwordEntropyValidation =
      EntropyValidator.validatePasswordEntropy(passwordBase);
    if (!passwordEntropyValidation.isValid) {
      console.warn(
        `Password base con baja entropía: ${passwordEntropyValidation.details.join(", ")}`,
      );
    }

    // Crear email con sal: usuario+salt@domain.extension
    const emailWithSalt = `${userBase}+${salt}@${domain}`;

    // Crear password con pimienta: password+pepper
    const passwordWithPepper = `${passwordBase}+${pepper}`;

    // Email y password originales (sin sal ni pimienta)
    const originalEmail = `${userBase}@${domain}`;
    const originalPassword = passwordBase;

    return {
      email: emailWithSalt,
      password: passwordWithPepper,
      originalEmail,
      originalPassword,
      salt,
      pepper,
    };
  }

  /**
   * Genera credenciales seguras con tipos fuertes
   * @param domain Dominio del sitio web (ValidDomain)
   * @returns Credenciales generadas con tipos fuertes
   * @throws InvalidDomainError si el dominio es inválido
   */
  async generateCredentialsStrong(
    domain: ValidDomain,
  ): Promise<GeneratedCredentialsStrong> {
    // Generar credenciales normales
    const credentials = await this.generateCredentials(domain);

    // Convertir a tipos fuertes
    return {
      email: CredentialsTypeFactory.createEmailWithSalt(credentials.email),
      password: CredentialsTypeFactory.createPasswordWithPepper(
        credentials.password,
      ),
      originalEmail: CredentialsTypeFactory.createEmailOriginal(
        credentials.originalEmail,
      ),
      originalPassword: CredentialsTypeFactory.createPasswordOriginal(
        credentials.originalPassword,
      ),
      salt: CredentialsTypeFactory.createSalt(credentials.salt),
      pepper: CredentialsTypeFactory.createPepper(credentials.pepper),
    };
  }

  /**
   * Extrae las credenciales originales con tipos fuertes
   * @param storedEmail Email almacenado (con sal)
   * @param storedPassword Password almacenado (con pimienta)
   * @returns Credenciales originales con tipos fuertes
   * @throws InvalidEmailFormatError si el email no tiene formato válido
   * @throws InvalidPasswordFormatError si el password no tiene formato válido
   */
  async extractOriginalCredentialsStrong(
    storedEmail: EmailWithSalt,
    storedPassword: PasswordWithPepper,
  ): Promise<OriginalCredentials> {
    // Extraer usando utilidades de tipos
    const originalEmail = CredentialsTypeUtils.toOriginalEmail(storedEmail);
    const originalPassword =
      CredentialsTypeUtils.toOriginalPassword(storedPassword);

    return {
      email: originalEmail,
      password: originalPassword,
    };
  }

  /**
   * Extrae las credenciales originales de las almacenadas
   * @param storedEmail Email almacenado (con sal)
   * @param storedPassword Password almacenado (con pimienta)
   * @returns Credenciales originales sin sal ni pimienta
   * @throws InvalidEmailFormatError si el email no tiene formato válido
   * @throws InvalidPasswordFormatError si el password no tiene formato válido
   */
  async extractOriginalCredentials(
    storedEmail: string,
    storedPassword: string,
  ): Promise<{ email: string; password: string }> {
    // Validar que los inputs no estén vacíos
    if (!storedEmail || storedEmail.trim() === "") {
      throw new InvalidEmailFormatError(storedEmail, "Email vacío");
    }

    if (!storedPassword || storedPassword.trim() === "") {
      throw new InvalidPasswordFormatError(storedPassword, "Password vacío");
    }

    // Extraer email original (quitar +salt)
    const emailMatch = storedEmail.match(/^([^+]+)\+[^@]+@(.+)$/);
    if (!emailMatch) {
      throw new InvalidEmailFormatError(
        storedEmail,
        "Formato esperado: usuario+salt@dominio.extension",
      );
    }

    const originalEmail = `${emailMatch[1]}@${emailMatch[2]}`;

    // Extraer password original (quitar +pepper)
    const passwordMatch = storedPassword.match(/^([^+]+)\+[^+]+$/);
    if (!passwordMatch) {
      throw new InvalidPasswordFormatError(
        storedPassword,
        "Formato esperado: password+pepper",
      );
    }

    const originalPassword = passwordMatch[1];

    return {
      email: originalEmail,
      password: originalPassword,
    };
  }

  /**
   * Genera una cadena aleatoria segura
   * @param length Longitud de la cadena
   * @returns Cadena aleatoria en formato hexadecimal
   */
  private async generateRandomString(length: number): Promise<string> {
    const array = new Uint8Array(length / 2);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      "",
    );
  }

  /**
   * Genera un password complejo con entropía alta
   * @param length Longitud del password
   * @returns Password complejo con mayúsculas, minúsculas, números y símbolos
   */
  private async generateComplexPassword(length: number): Promise<string> {
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    const allChars = uppercase + lowercase + numbers + symbols;

    // Generar array de bytes aleatorios
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);

    // Construir password asegurando al menos un carácter de cada tipo
    let password = "";

    // Asegurar al menos un carácter de cada tipo
    password += uppercase[array[0] % uppercase.length];
    password += lowercase[array[1] % lowercase.length];
    password += numbers[array[2] % numbers.length];
    password += symbols[array[3] % symbols.length];

    // Completar con caracteres aleatorios
    for (let i = 4; i < length; i++) {
      password += allChars[array[i] % allChars.length];
    }

    // Mezclar el password para evitar patrones predecibles
    return this.shuffleString(password, array);
  }

  /**
   * Mezcla una cadena aleatoriamente usando el algoritmo Fisher-Yates
   * @param str String a mezclar
   * @param randomArray Array de números aleatorios para la mezcla
   * @returns String mezclado
   */
  private shuffleString(str: string, randomArray: Uint8Array): string {
    const arr = str.split("");
    let currentIndex = arr.length;
    let randomIndex: number;

    // Fisher-Yates shuffle
    while (currentIndex !== 0) {
      randomIndex = randomArray[currentIndex - 1] % currentIndex;
      currentIndex--;

      [arr[currentIndex], arr[randomIndex]] = [
        arr[randomIndex],
        arr[currentIndex],
      ];
    }

    return arr.join("");
  }

  /**
   * Valida si un email sigue el formato de sal
   * @param email Email a validar
   * @returns true si sigue el formato, false en caso contrario
   */
  isValidEmailWithSalt(email: string): boolean {
    return CredentialsValidator.isValidEmailWithSalt(email);
  }

  /**
   * Valida si un password sigue el formato de pimienta
   * @param password Password a validar
   * @returns true si sigue el formato, false en caso contrario
   */
  isValidPasswordWithPepper(password: string): boolean {
    return CredentialsValidator.isValidPasswordWithPepper(password);
  }

  /**
   * Extrae la sal de un email
   * @param email Email con sal
   * @returns La sal extraída
   * @throws SaltExtractionError si no se puede extraer la sal
   */
  extractSalt(email: string): string {
    try {
      return CredentialsValidator.extractSalt(email);
    } catch (error) {
      if (error instanceof InvalidEmailFormatError) {
        throw new SaltExtractionError(error.email, error.message);
      }
      throw error;
    }
  }

  /**
   * Extrae la pimienta de un password
   * @param password Password con pimienta
   * @returns La pimienta extraída
   * @throws PepperExtractionError si no se puede extraer la pimienta
   */
  extractPepper(password: string): string {
    try {
      return CredentialsValidator.extractPepper(password);
    } catch (error) {
      if (error instanceof InvalidPasswordFormatError) {
        throw new PepperExtractionError(error.password, error.message);
      }
      throw error;
    }
  }

  /**
   * Analiza la calidad de las credenciales generadas
   * @param credentials Credenciales a analizar
   * @returns Análisis de calidad de aleatoriedad
   */
  analyzeCredentialsQuality(credentials: GeneratedCredentials): {
    isValid: boolean;
    entropyAnalysis: {
      salt: number;
      pepper: number;
      passwordBase: number;
    };
    randomnessAnalysis: {
      salt: ReturnType<typeof RandomnessAnalyzer.analyzeHexString>;
      pepper: ReturnType<typeof RandomnessAnalyzer.analyzeHexString>;
    };
    warnings: string[];
  } {
    const warnings: string[] = [];

    // Analizar sal
    const saltAnalysis = RandomnessAnalyzer.analyzeHexString(credentials.salt);
    if (!saltAnalysis.isValid) {
      warnings.push(`Sal con problemas: ${saltAnalysis.issues.join(", ")}`);
    }

    // Analizar pimienta
    const pepperAnalysis = RandomnessAnalyzer.analyzeHexString(
      credentials.pepper,
    );
    if (!pepperAnalysis.isValid) {
      warnings.push(
        `Pimienta con problemas: ${pepperAnalysis.issues.join(", ")}`,
      );
    }

    // Calcular entropía del password base
    const passwordEntropy = EntropyValidator.estimatePasswordEntropy(
      credentials.originalPassword,
    );
    if (passwordEntropy < EntropyValidator.MIN_PASSWORD_ENTROPY) {
      warnings.push(
        `Password base con baja entropía: ${passwordEntropy.toFixed(1)} bits`,
      );
    }

    return {
      isValid: warnings.length === 0,
      entropyAnalysis: {
        salt: saltAnalysis.entropy,
        pepper: pepperAnalysis.entropy,
        passwordBase: passwordEntropy,
      },
      randomnessAnalysis: {
        salt: saltAnalysis,
        pepper: pepperAnalysis,
      },
      warnings,
    };
  }
}
