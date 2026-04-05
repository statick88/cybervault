/**
 * Errores personalizados para el módulo de credenciales
 * Proporciona errores específicos con información detallada
 */

/**
 * Error base para operaciones de credenciales
 */
export class CredentialsError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'CredentialsError';
  }
}

/**
 * Error cuando el formato de email es inválido
 */
export class InvalidEmailFormatError extends CredentialsError {
  constructor(public readonly email: string, details?: string) {
    const message = details 
      ? `Formato de email inválido: ${email}. ${details}`
      : `Formato de email inválido: ${email}`;
    super(message, 'INVALID_EMAIL_FORMAT');
    this.name = 'InvalidEmailFormatError';
  }
}

/**
 * Error cuando el formato de password es inválido
 */
export class InvalidPasswordFormatError extends CredentialsError {
  constructor(public readonly password: string, details?: string) {
    const message = details 
      ? `Formato de password inválido: ${password}. ${details}`
      : `Formato de password inválido: ${password}`;
    super(message, 'INVALID_PASSWORD_FORMAT');
    this.name = 'InvalidPasswordFormatError';
  }
}

/**
 * Error cuando la extracción de sal falla
 */
export class SaltExtractionError extends CredentialsError {
  constructor(public readonly email: string, details?: string) {
    const message = details 
      ? `No se pudo extraer la sal del email: ${email}. ${details}`
      : `No se pudo extraer la sal del email: ${email}`;
    super(message, 'SALT_EXTRACTION_FAILED');
    this.name = 'SaltExtractionError';
  }
}

/**
 * Error cuando la extracción de pimienta falla
 */
export class PepperExtractionError extends CredentialsError {
  constructor(public readonly password: string, details?: string) {
    const message = details 
      ? `No se pudo extraer la pimienta del password: ${password}. ${details}`
      : `No se pudo extraer la pimienta del password: ${password}`;
    super(message, 'PEPPER_EXTRACTION_FAILED');
    this.name = 'PepperExtractionError';
  }
}

/**
 * Error cuando la validación de entropía falla
 */
export class EntropyValidationError extends CredentialsError {
  constructor(public readonly data: string, public readonly requiredEntropy: number) {
    super(
      `Entropía insuficiente. Requerida: ${requiredEntropy} bits, obtenida: menos`,
      'ENTROPY_VALIDATION_FAILED'
    );
    this.name = 'EntropyValidationError';
  }
}

/**
 * Error cuando el dominio es inválido
 */
export class InvalidDomainError extends CredentialsError {
  constructor(public readonly domain: string) {
    super(`Dominio inválido: ${domain}`, 'INVALID_DOMAIN');
    this.name = 'InvalidDomainError';
  }
}

/**
 * Error cuando la longitud es inválida
 */
export class InvalidLengthError extends CredentialsError {
  constructor(
    public readonly value: string,
    public readonly minLength: number,
    public readonly maxLength: number
  ) {
    super(
      `Longitud inválida. Mínimo: ${minLength}, Máximo: ${maxLength}, Actual: ${value.length}`,
      'INVALID_LENGTH'
    );
    this.name = 'InvalidLengthError';
  }
}

/**
 * Utilidades para manejo de errores
 */
export class CredentialsErrorUtils {
  /**
   * Verifica si un error es del módulo de credenciales
   */
  static isCredentialsError(error: unknown): error is CredentialsError {
    return error instanceof CredentialsError;
  }

  /**
   * Verifica si un error es de formato de email
   */
  static isInvalidEmailFormat(error: unknown): error is InvalidEmailFormatError {
    return error instanceof InvalidEmailFormatError;
  }

  /**
   * Verifica si un error es de formato de password
   */
  static isInvalidPasswordFormat(error: unknown): error is InvalidPasswordFormatError {
    return error instanceof InvalidPasswordFormatError;
  }

  /**
   * Obtiene el código de error de un error de credenciales
   */
  static getErrorCode(error: unknown): string | null {
    if (this.isCredentialsError(error)) {
      return error.code;
    }
    return null;
  }
}