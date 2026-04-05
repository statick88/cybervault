/**
 * Validador de Entropía Criptográfica
 * Verifica la calidad de la aleatoriedad en generación de credenciales
 */

import { EntropyValidationError } from './credentials-errors';

/**
 * Calculadora de entropía para diferentes tipos de datos
 */
export class EntropyCalculator {
  /**
   * Calcula la entropía de una cadena de texto
   * @param data Cadena de texto
   * @returns Entropía en bits
   */
  static calculateStringEntropy(data: string): number {
    if (!data || data.length === 0) return 0;

    // Contar frecuencia de cada carácter
    const charCount = new Map<string, number>();
    for (const char of data) {
      charCount.set(char, (charCount.get(char) || 0) + 1);
    }

    // Calcular entropía usando fórmula de Shannon
    let entropy = 0;
    const totalChars = data.length;

    for (const count of charCount.values()) {
      const probability = count / totalChars;
      entropy -= probability * Math.log2(probability);
    }

    // Multiplicar por el tamaño del alfabeto
    const alphabetSize = charCount.size;
    return entropy * alphabetSize;
  }

  /**
   * Calcula la entropía de bytes aleatorios
   * @param bytes Array de bytes
   * @returns Entropía en bits
   */
  static calculateBytesEntropy(bytes: Uint8Array): number {
    if (!bytes || bytes.length === 0) return 0;

    // Cada byte puede tener 256 valores posibles
    // Entropía máxima por byte = 8 bits
    return bytes.length * 8;
  }

  /**
   * Calcula la entropía de un string hexadecimal
   * @param hexString String hexadecimal
   * @returns Entropía en bits
   */
  static calculateHexEntropy(hexString: string): number {
    if (!hexString) return 0;

    // Cada carácter hexadecimal tiene 16 posibilidades
    // Entropía por carácter = log2(16) = 4 bits
    const cleanHex = hexString.replace(/[^a-fA-F0-9]/g, '');
    return cleanHex.length * 4;
  }
}

/**
 * Validador de aleatoriedad
 */
export class RandomnessValidator {
  /**
   * Verifica si los bytes tienen distribución uniforme
   * @param bytes Array de bytes
   * @returns Verdadero si la distribución es uniforme
   */
  static isUniformDistribution(bytes: Uint8Array): boolean {
    if (!bytes || bytes.length === 0) return false;

    // Contar frecuencia de cada valor de byte (0-255)
    const frequency = new Array(256).fill(0);
    for (const byte of bytes) {
      frequency[byte]++;
    }

    // Calcular desviación estándar de las frecuencias
    const mean = bytes.length / 256;
    let sumSquaredDiff = 0;

    for (const count of frequency) {
      sumSquaredDiff += Math.pow(count - mean, 2);
    }

    const variance = sumSquaredDiff / 256;
    const stdDev = Math.sqrt(variance);

    // Consideramos uniforme si la desviación estándar es menor al 20% de la media
    const threshold = mean * 0.2;
    return stdDev <= threshold;
  }

  /**
   * Verifica patrones repetitivos en los datos
   * @param data Datos a analizar
   * @returns Verdadero si no hay patrones repetitivos significativos
   */
  static hasNoRepetitivePatterns(data: string | Uint8Array): boolean {
    if (!data || data.length < 4) return true;

    const array = typeof data === 'string' 
      ? new TextEncoder().encode(data) 
      : data;

    // Buscar patrones repetitivos de longitud 2, 3 y 4
    for (let patternLength = 2; patternLength <= 4; patternLength++) {
      const patterns = new Map<string, number>();

      for (let i = 0; i <= array.length - patternLength; i++) {
        const pattern = array.slice(i, i + patternLength).join(',');
        patterns.set(pattern, (patterns.get(pattern) || 0) + 1);
      }

      // Verificar si algún patrón se repite demasiado
      const maxRepetitions = Math.floor(array.length / (patternLength * 2));
      for (const count of patterns.values()) {
        if (count > maxRepetitions) {
          return false;
        }
      }
    }

    return true;
  }
}

/**
 * Clase principal de validación de entropía
 */
export class EntropyValidator {
  /**
   * Entropía mínima requerida para sal y pimienta (bits)
   */
  static readonly MIN_ENTROPY = 128;

  /**
   * Entropía mínima requerida para password base (bits)
   */
  static readonly MIN_PASSWORD_ENTROPY = 128;

  /**
   * Verifica si la entropía de una sal cumple con el mínimo
   * @param salt Sal a verificar
   * @throws EntropyValidationError si la entropía es insuficiente
   */
  static validateSaltEntropy(salt: string): void {
    if (!salt || salt.length !== 32) {
      throw new EntropyValidationError(salt, this.MIN_ENTROPY);
    }

    const entropy = EntropyCalculator.calculateHexEntropy(salt);
    if (entropy < this.MIN_ENTROPY) {
      throw new EntropyValidationError(salt, this.MIN_ENTROPY);
    }
  }

  /**
   * Verifica si la entropía de una pimienta cumple con el mínimo
   * @param pepper Pimienta a verificar
   * @throws EntropyValidationError si la entropía es insuficiente
   */
  static validatePepperEntropy(pepper: string): void {
    if (!pepper || pepper.length !== 32) {
      throw new EntropyValidationError(pepper, this.MIN_ENTROPY);
    }

    const entropy = EntropyCalculator.calculateHexEntropy(pepper);
    if (entropy < this.MIN_ENTROPY) {
      throw new EntropyValidationError(pepper, this.MIN_ENTROPY);
    }
  }

  /**
   * Verifica la calidad de un password base
   * @param password Password a verificar
   * @returns Objeto con validación y detalles
   */
  static validatePasswordEntropy(password: string): {
    isValid: boolean;
    entropy: number;
    details: string[];
  } {
    const details: string[] = [];

    if (!password) {
      return { isValid: false, entropy: 0, details: ['Password vacío'] };
    }

    const entropy = EntropyCalculator.calculateStringEntropy(password);

    if (entropy < this.MIN_PASSWORD_ENTROPY) {
      details.push(`Entropía insuficiente: ${entropy.toFixed(1)} bits (mínimo: ${this.MIN_PASSWORD_ENTROPY})`);
    }

    // Verificar distribución uniforme
    const bytes = new TextEncoder().encode(password);
    if (!RandomnessValidator.isUniformDistribution(bytes)) {
      details.push('Distribución no uniforme detectada');
    }

    // Verificar patrones repetitivos
    if (!RandomnessValidator.hasNoRepetitivePatterns(bytes)) {
      details.push('Patrones repetitivos detectados');
    }

    return {
      isValid: entropy >= this.MIN_PASSWORD_ENTROPY,
      entropy,
      details
    };
  }

  /**
   * Verifica la calidad de un array de bytes aleatorios
   * @param bytes Array de bytes
   * @returns Objeto con validación y detalles
   */
  static validateBytesEntropy(bytes: Uint8Array): {
    isValid: boolean;
    entropy: number;
    details: string[];
  } {
    const details: string[] = [];

    if (!bytes || bytes.length === 0) {
      return { isValid: false, entropy: 0, details: ['Bytes vacíos'] };
    }

    const entropy = EntropyCalculator.calculateBytesEntropy(bytes);

    // Calcular entropía esperada (máxima) vs real
    const expectedEntropy = bytes.length * 8;

    if (entropy < expectedEntropy * 0.9) {
      details.push(`Entropía baja: ${entropy.toFixed(1)} bits (esperado: ${expectedEntropy})`);
    }

    // Verificar distribución uniforme
    if (!RandomnessValidator.isUniformDistribution(bytes)) {
      details.push('Distribución no uniforme detectada');
    }

    return {
      isValid: entropy >= expectedEntropy * 0.9,
      entropy,
      details
    };
  }

  /**
   * Calcula la entropía aproximada de un password basado en su complejidad
   * @param password Password a analizar
   * @returns Entropía aproximada en bits
   */
  static estimatePasswordEntropy(password: string): number {
    if (!password) return 0;

    let charsetSize = 0;

    // Mayúsculas (26)
    if (/[A-Z]/.test(password)) charsetSize += 26;
    
    // Minúsculas (26)
    if (/[a-z]/.test(password)) charsetSize += 26;
    
    // Números (10)
    if (/[0-9]/.test(password)) charsetSize += 10;
    
    // Símbolos (32 caracteres comunes)
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

    // Entropía = longitud * log2(tamaño del alfabeto)
    return password.length * Math.log2(charsetSize);
  }
}

/**
 * Clase para análisis de calidad de aleatoriedad
 */
export class RandomnessAnalyzer {
  /**
   * Analiza la aleatoriedad de un string hexadecimal
   * @param hexString String hexadecimal
   * @returns Análisis detallado
   */
  static analyzeHexString(hexString: string): {
    isValid: boolean;
    entropy: number;
    uniformDistribution: boolean;
    noPatterns: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    const cleanHex = hexString.replace(/[^a-fA-F0-9]/g, '');

    // Calcular entropía
    const entropy = EntropyCalculator.calculateHexEntropy(cleanHex);

    // Verificar distribución uniforme
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
    }
    const uniformDistribution = RandomnessValidator.isUniformDistribution(bytes);

    // Verificar patrones
    const noPatterns = RandomnessValidator.hasNoRepetitivePatterns(bytes);

    // Generar reporte de problemas
    if (entropy < 128) issues.push('Entropía baja');
    if (!uniformDistribution) issues.push('Distribución no uniforme');
    if (!noPatterns) issues.push('Patrones repetitivos detectados');

    return {
      isValid: entropy >= 128 && uniformDistribution && noPatterns,
      entropy,
      uniformDistribution,
      noPatterns,
      issues
    };
  }
}