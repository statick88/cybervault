/**
 * Validador de Credenciales con Regex Mejoradas
 * Proporciona patrones de validación mejorados para emails y passwords
 */

import {
  InvalidEmailFormatError,
  InvalidPasswordFormatError,
} from "./credentials-errors";
/**
 * Patrones de validación mejorados
 */
export class CredentialsPatterns {
  // Email base (sin sal): usuario@dominio.extension
  // Formato: alfanuméricos + algunos caracteres especiales permitidos en email
  static readonly EMAIL_BASE =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  // Email con sal: usuario+salt@dominio.extension
  // Salt: 32 caracteres hexadecimales (128 bits de entropía)
  static readonly EMAIL_WITH_SALT =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+\+[a-fA-F0-9]{32}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  // Password base (sin pimienta): 32+ caracteres
  // Permite: alfanuméricos, caracteres especiales comunes
  static readonly PASSWORD_BASE =
    /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{32,}$/;

  // Password con pimienta: password+pepper
  // Pepper: 32 caracteres hexadecimales (128 bits de entropía)
  static readonly PASSWORD_WITH_PEPPER =
    /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{32,}\+[a-fA-F0-9]{32}$/;

  // Dominio válido
  static readonly DOMAIN =
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  // Extractor de sal (captura grupo 1)
  static readonly EXTRACT_SALT = /^[^+]+\+([^@]+)@/;

  // Extractor de pimienta (captura grupo 1)
  static readonly EXTRACT_PEPPER = /^[^+]+\+([^+]+)$/;
}

/**
 * Validador de credenciales con patrones mejorados
 */
export class CredentialsValidator {
  /**
   * Valida si un email tiene formato válido
   * @param email Email a validar
   * @returns true si el formato es válido
   */
  static isValidEmail(email: string): boolean {
    if (!email || typeof email !== "string") return false;
    return CredentialsPatterns.EMAIL_BASE.test(email);
  }

  /**
   * Valida si un email con sal tiene formato válido
   * @param email Email con sal a validar
   * @returns true si el formato es válido
   */
  static isValidEmailWithSalt(email: string): boolean {
    if (!email || typeof email !== "string") return false;
    return CredentialsPatterns.EMAIL_WITH_SALT.test(email);
  }

  /**
   * Valida si un password tiene formato válido
   * @param password Password a validar
   * @returns true si el formato es válido
   */
  static isValidPassword(password: string): boolean {
    if (!password || typeof password !== "string") return false;
    return CredentialsPatterns.PASSWORD_BASE.test(password);
  }

  /**
   * Valida si un password con pimienta tiene formato válido
   * @param password Password con pimienta a validar
   * @returns true si el formato es válido
   */
  static isValidPasswordWithPepper(password: string): boolean {
    if (!password || typeof password !== "string") return false;
    return CredentialsPatterns.PASSWORD_WITH_PEPPER.test(password);
  }

  /**
   * Valida si un dominio es válido
   * @param domain Dominio a validar
   * @returns true si el dominio es válido
   */
  static isValidDomain(domain: string): boolean {
    if (!domain || typeof domain !== "string") return false;
    return CredentialsPatterns.DOMAIN.test(domain);
  }

  /**
   * Extrae la sal de un email con sal
   * @param email Email con sal
   * @returns La sal extraída
   * @throws InvalidEmailFormatError si el email es inválido
   */
  static extractSalt(email: string): string {
    if (!email || email.trim() === "") {
      throw new InvalidEmailFormatError(email, "Email vacío");
    }

    const match = email.match(CredentialsPatterns.EXTRACT_SALT);
    if (!match) {
      throw new InvalidEmailFormatError(
        email,
        "Formato esperado: usuario+salt@dominio.extension",
      );
    }

    return match[1];
  }

  /**
   * Extrae la pimienta de un password con pimienta
   * @param password Password con pimienta
   * @returns La pimienta extraída
   * @throws InvalidPasswordFormatError si el password es inválido
   */
  static extractPepper(password: string): string {
    if (!password || password.trim() === "") {
      throw new InvalidPasswordFormatError(password, "Password vacío");
    }

    const match = password.match(CredentialsPatterns.EXTRACT_PEPPER);
    if (!match) {
      throw new InvalidPasswordFormatError(
        password,
        "Formato esperado: password+pepper",
      );
    }

    return match[1];
  }

  /**
   * Valida y extrae componentes de email con sal
   * @param email Email con sal
   * @returns Objeto con usuario, sal y dominio
   * @throws InvalidEmailFormatError si el email es inválido
   */
  static parseEmailWithSalt(email: string): {
    user: string;
    salt: string;
    domain: string;
    fullEmail: string;
  } {
    if (!email || email.trim() === "") {
      throw new InvalidEmailFormatError(email, "Email vacío");
    }

    const match = email.match(/^([^+]+)\+([^@]+)@(.+)$/);
    if (!match) {
      throw new InvalidEmailFormatError(
        email,
        "Formato esperado: usuario+salt@dominio.extension",
      );
    }

    const [, user, salt, domain] = match;

    // Validar longitud de sal (32 caracteres hexadecimales)
    if (salt.length !== 32 || !/^[a-fA-F0-9]{32}$/.test(salt)) {
      throw new InvalidEmailFormatError(
        email,
        `Sal inválida: debe ser 32 caracteres hexadecimales (encontrados: ${salt.length})`,
      );
    }

    // Validar dominio
    if (!this.isValidDomain(domain)) {
      throw new InvalidEmailFormatError(email, `Dominio inválido: ${domain}`);
    }

    return {
      user,
      salt,
      domain,
      fullEmail: email,
    };
  }

  /**
   * Valida y extrae componentes de password con pimienta
   * @param password Password con pimienta
   * @returns Objeto con password base y pimienta
   * @throws InvalidPasswordFormatError si el password es inválido
   */
  static parsePasswordWithPepper(password: string): {
    passwordBase: string;
    pepper: string;
    fullPassword: string;
  } {
    if (!password || password.trim() === "") {
      throw new InvalidPasswordFormatError(password, "Password vacío");
    }

    const match = password.match(/^([^+]+)\+([^+]+)$/);
    if (!match) {
      throw new InvalidPasswordFormatError(
        password,
        "Formato esperado: password+pepper",
      );
    }

    const [, passwordBase, pepper] = match;

    // Validar longitud de password base (mínimo 32 caracteres)
    if (passwordBase.length < 32) {
      throw new InvalidPasswordFormatError(
        password,
        `Password base demasiado corto: mínimo 32 caracteres (encontrados: ${passwordBase.length})`,
      );
    }

    // Validar longitud de pimienta (32 caracteres hexadecimales)
    if (pepper.length !== 32 || !/^[a-fA-F0-9]{32}$/.test(pepper)) {
      throw new InvalidPasswordFormatError(
        password,
        `Pimienta inválida: debe ser 32 caracteres hexadecimales (encontrados: ${pepper.length})`,
      );
    }

    return {
      passwordBase,
      pepper,
      fullPassword: password,
    };
  }

  /**
   * Valida la calidad de un email base
   * @param email Email base (sin sal)
   * @returns Objeto con validación y detalles
   */
  static validateEmailBase(email: string): {
    isValid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!email) {
      errors.push("Email vacío");
      return { isValid: false, errors, warnings };
    }

    // Validar formato básico
    if (!CredentialsPatterns.EMAIL_BASE.test(email)) {
      errors.push("Formato de email inválido");
    }

    // Validar longitud
    if (email.length < 6) {
      errors.push("Email demasiado corto (mínimo 6 caracteres)");
    } else if (email.length > 254) {
      errors.push("Email demasiado largo (máximo 254 caracteres)");
    }

    // Validar caracteres especiales repetidos
    if (email.includes("..")) {
      warnings.push("Email contiene puntos consecutivos");
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Valida la calidad de un password base
   * @param password Password base (sin pimienta)
   * @returns Objeto con validación y detalles
   */
  static validatePasswordBase(password: string): {
    isValid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!password) {
      errors.push("Password vacío");
      return { isValid: false, errors, warnings };
    }

    // Validar longitud
    if (password.length < 32) {
      errors.push(
        `Password demasiado corto: ${password.length} caracteres (mínimo 32)`,
      );
    }

    // Validar complejidad
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(
      password,
    );

    if (!hasUpperCase) warnings.push("Password sin mayúsculas");
    if (!hasLowerCase) warnings.push("Password sin minúsculas");
    if (!hasNumbers) warnings.push("Password sin números");
    if (!hasSpecialChars) warnings.push("Password sin caracteres especiales");

    // Calcular entropía aproximada
    const charsetSize =
      (hasUpperCase ? 26 : 0) +
      (hasLowerCase ? 26 : 0) +
      (hasNumbers ? 10 : 0) +
      (hasSpecialChars ? 32 : 0);

    const entropy = password.length * Math.log2(charsetSize || 1);

    if (entropy < 128) {
      warnings.push(
        `Entropía baja: ${entropy.toFixed(1)} bits (recomendado: ≥128 bits)`,
      );
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }
}
