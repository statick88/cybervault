/**
 * ValidationService - Servicio de validación y sanitización
 * Proporciona funciones reutilizables para validar y sanitizar datos de credenciales
 *
 * SECURITY: Zero Trust Architecture
 * - Never trust input: all data validated before use
 * - Defense in depth: multiple validation layers
 */

// ============================================================================
// Types
// ============================================================================

/**
 * Datos de credenciales para sanitización
 */
export interface CredentialData {
  title?: string;
  username?: string;
  url?: string;
  notes?: string;
  tags?: string[];
}

/**
 * Resultado de validación de fortaleza de contraseña
 */
export interface PasswordStrengthResult {
  isValid: boolean;
  score: number;
  feedback: string[];
}

/**
 * Datos sanitizados de credenciales
 */
export interface SanitizedCredentialData {
  title?: string;
  username?: string;
  url?: string;
  notes?: string;
  tags?: string[];
}

// ============================================================================
// Service Class
// ============================================================================

/**
 * ValidationService - Servicio de validación y sanitización
 * Proporciona métodos reutilizables para validar y sanitizar datos de credenciales
 *
 * SECURITY: Zero Trust Architecture
 * - Never trust input: all data validated before use
 * - Defense in depth: multiple validation layers
 */
export class ValidationService {
  // Constants
  private readonly MAX_TITLE_LENGTH = 100;
  private readonly MAX_USERNAME_LENGTH = 254;
  private readonly MAX_URL_LENGTH = 2048;
  private readonly MAX_NOTES_LENGTH = 10000;
  private readonly MAX_TAGS = 20;
  private readonly MAX_TAG_LENGTH = 30;

  /**
   * Sanitize and validate string input
   * SECURITY: Zero Trust - never trust user input
   */
  sanitizeString(input: string, maxLength: number): string {
    if (typeof input !== "string") return "";
    return input.trim().slice(0, maxLength);
  }

  /**
   * Validate URL format
   * SECURITY: Prevent SSRF and malicious URLs
   */
  isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return ["http:", "https:"].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  /**
   * Validate email format
   */
  isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate and clean tags array
   */
  validateTags(tags: string[]): string[] {
    return tags
      .slice(0, this.MAX_TAGS)
      .map((t) => this.sanitizeString(t, this.MAX_TAG_LENGTH))
      .filter((t) => t.length > 0);
  }

  /**
   * Validate password strength
   */
  validatePasswordStrength(password: string): PasswordStrengthResult {
    const entropy = this.estimatePasswordEntropy(password);
    const score = Math.min(100, Math.round((entropy / 128) * 100));

    const feedback: string[] = [];
    let isValid = true;

    if (password.length < 8) {
      feedback.push("Contraseña muy corta (mínimo 8 caracteres)");
      isValid = false;
    } else if (password.length < 12) {
      feedback.push("Considera usar una contraseña más larga (12+ caracteres)");
    }

    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[^a-zA-Z0-9]/.test(password);

    const varietyCount = [
      hasUppercase,
      hasLowercase,
      hasNumbers,
      hasSymbols,
    ].filter(Boolean).length;

    if (varietyCount < 2) {
      feedback.push(
        "Usa más tipos de caracteres (mayúsculas, minúsculas, números, símbolos)",
      );
    }

    if (entropy < 28) {
      feedback.push("Entropía muy baja - contraseña predecible");
      isValid = false;
    } else if (entropy < 36) {
      feedback.push("Entropía baja - consider usar generador");
      isValid = false;
    } else if (entropy < 60) {
      feedback.push("Entropía media - podría ser más segura");
    }

    if (/^(.)\1+$/.test(password)) {
      feedback.push("Contraseña con caracteres repetitivos");
      isValid = false;
    }

    const sequences = ["123", "abc", "qwerty", "password", "admin"];
    const lowerPassword = password.toLowerCase();
    if (sequences.some((seq) => lowerPassword.includes(seq))) {
      feedback.push("Contraseña contiene secuencias comunes");
      isValid = false;
    }

    if (/^[a-z]{2,}[0-9]{2,}$/.test(password) || /^[0-9]{4,}$/.test(password)) {
      feedback.push("Contraseña parece info personal (nombre+fecha)");
      isValid = false;
    }

    if (feedback.length === 0) {
      if (score >= 80) {
        feedback.push("Contraseña muy fuerte");
      } else if (score >= 60) {
        feedback.push("Contraseña aceptable");
      } else {
        feedback.push("Contraseña débil");
      }
    }

    return { isValid, score, feedback };
  }

  /**
   * Check if password is strong enough (score >= 60)
   */
  isStrongPassword(password: string): boolean {
    const result = this.validatePasswordStrength(password);
    return result.score >= 60;
  }

  /**
   * Comprehensive sanitization of credential data
   */
  sanitizeCredentialData(data: CredentialData): SanitizedCredentialData {
    const sanitized: SanitizedCredentialData = {};

    if (data.title !== undefined) {
      sanitized.title = this.sanitizeString(data.title, this.MAX_TITLE_LENGTH);
    }

    if (data.username !== undefined) {
      sanitized.username = this.sanitizeString(
        data.username,
        this.MAX_USERNAME_LENGTH,
      );
    }

    if (data.url !== undefined) {
      const urlSanitized = this.sanitizeString(data.url, this.MAX_URL_LENGTH);
      sanitized.url = urlSanitized ? urlSanitized : undefined;
    }

    if (data.notes !== undefined) {
      sanitized.notes = this.sanitizeString(data.notes, this.MAX_NOTES_LENGTH);
    }

    if (data.tags !== undefined) {
      sanitized.tags = this.validateTags(data.tags);
    }

    return sanitized;
  }

  /**
   * Estimate password entropy
   */
  private estimatePasswordEntropy(password: string): number {
    if (!password) return 0;

    let charsetSize = 0;

    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

    if (charsetSize === 0) charsetSize = 1;

    return password.length * Math.log2(charsetSize);
  }
}
