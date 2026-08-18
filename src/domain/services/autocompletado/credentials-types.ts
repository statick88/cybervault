/**
 * Tipos de Seguridad para Credenciales
 * Definición de tipos TypeScript fuertes para prevención de errores en tiempo de compilación
 */

/**
 * Tipo de marca para Email con Sal
 * Previene mezcla de email regular con email con sal
 */
export type EmailWithSalt = string & { readonly __brand: 'EmailWithSalt' };

/**
 * Tipo de marca para Email original (sin sal)
 */
export type EmailOriginal = string & { readonly __brand: 'EmailOriginal' };

/**
 * Tipo de marca para Password con Pimienta
 * Previene mezcla de password regular con password con pimienta
 */
export type PasswordWithPepper = string & { readonly __brand: 'PasswordWithPepper' };

/**
 * Tipo de marca para Password original (sin pimienta)
 */
export type PasswordOriginal = string & { readonly __brand: 'PasswordOriginal' };

/**
 * Tipo de marca para Sal criptográfica
 */
export type Salt = string & { readonly __brand: 'Salt' };

/**
 * Tipo de marca para Pimienta criptográfica
 */
export type Pepper = string & { readonly __brand: 'Pepper' };

/**
 * Tipo de marca para Dominio válido
 */
export type ValidDomain = string & { readonly __brand: 'ValidDomain' };

/**
 * Interfaz de Credenciales Generadas con tipos fuertes
 */
export interface GeneratedCredentialsStrong {
  email: EmailWithSalt;
  password: PasswordWithPepper;
  originalEmail: EmailOriginal;
  originalPassword: PasswordOriginal;
  salt: Salt;
  pepper: Pepper;
}

/**
 * Interfaz de Credenciales Almacenadas con tipos fuertes
 */
export interface StoredCredentialsStrong {
  email: EmailWithSalt;
  password: PasswordWithPepper;
  domain: ValidDomain;
}

/**
 * Interfaz de Credenciales Originales (sin sal ni pimienta)
 */
export interface OriginalCredentials {
  email: EmailOriginal;
  password: PasswordOriginal;
}

/**
 * Factorías de tipos para crear valores seguros
 */
export class CredentialsTypeFactory {
  /**
   * Crea un EmailWithSalt a partir de un string
   * @param email String que representa un email con sal
   * @returns EmailWithSalt
   * @throws Error si el formato no es válido
   */
  static createEmailWithSalt(email: string): EmailWithSalt {
    if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+\+[a-fA-F0-9]{32}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(email)) {
      throw new Error(`EmailWithSalt inválido: ${email}`);
    }
    return email as EmailWithSalt;
  }

  /**
   * Crea un EmailOriginal a partir de un string
   * @param email String que representa un email original
   * @returns EmailOriginal
   * @throws Error si contiene sal
   */
  static createEmailOriginal(email: string): EmailOriginal {
    if (email.includes('+')) {
      throw new Error(`EmailOriginal no debe contener sal: ${email}`);
    }
    return email as EmailOriginal;
  }

  /**
   * Crea un PasswordWithPepper a partir de un string
   * @param password String que representa un password con pimienta
   * @returns PasswordWithPepper
   * @throws Error si el formato no es válido
   */
  static createPasswordWithPepper(password: string): PasswordWithPepper {
    if (!/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{32,}\+[a-fA-F0-9]{32}$/.test(password)) {
      throw new Error(`PasswordWithPepper inválido: ${password}`);
    }
    return password as PasswordWithPepper;
  }

  /**
   * Crea un PasswordOriginal a partir de un string
   * @param password String que representa un password original
   * @returns PasswordOriginal
   * @throws Error si contiene pimienta
   */
  static createPasswordOriginal(password: string): PasswordOriginal {
    if (/\+[a-fA-F0-9]{32}$/.test(password)) {
      throw new Error(`PasswordOriginal no debe contener pimienta: ${password}`);
    }
    return password as PasswordOriginal;
  }

  /**
   * Crea una Sal a partir de un string
   * @param salt String que representa una sal (32 caracteres hexadecimales)
   * @returns Salt
   * @throws Error si no tiene el formato correcto
   */
  static createSalt(salt: string): Salt {
    if (!/^[a-fA-F0-9]{32}$/.test(salt)) {
      throw new Error(`Sal inválida: debe ser 32 caracteres hexadecimales`);
    }
    return salt as Salt;
  }

  /**
   * Crea una Pimienta a partir de un string
   * @param pepper String que representa una pimienta (32 caracteres hexadecimales)
   * @returns Pepper
   * @throws Error si no tiene el formato correcto
   */
  static createPepper(pepper: string): Pepper {
    if (!/^[a-fA-F0-9]{32}$/.test(pepper)) {
      throw new Error(`Pimienta inválida: debe ser 32 caracteres hexadecimales`);
    }
    return pepper as Pepper;
  }

  /**
   * Crea un Dominio válido a partir de un string
   * @param domain String que representa un dominio
   * @returns ValidDomain
   * @throws Error si el dominio no es válido
   */
  static createValidDomain(domain: string): ValidDomain {
    if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(domain)) {
      throw new Error(`Dominio inválido: ${domain}`);
    }
    return domain as ValidDomain;
  }
}

/**
 * Utilidades para conversión de tipos
 */
export class CredentialsTypeUtils {
  /**
   * Convierte EmailWithSalt a EmailOriginal
   * @param emailWithSalt Email con sal
   * @returns Email original
   */
  static toOriginalEmail(emailWithSalt: EmailWithSalt): EmailOriginal {
    const match = emailWithSalt.match(/^(.+)\+[a-fA-F0-9]{32}@(.+)$/);
    if (!match) {
      throw new Error('Formato de EmailWithSalt inválido');
    }
    return CredentialsTypeFactory.createEmailOriginal(`${match[1]}@${match[2]}`);
  }

  /**
   * Convierte PasswordWithPepper a PasswordOriginal
   * @param passwordWithPepper Password con pimienta
   * @returns Password original
   */
  static toOriginalPassword(passwordWithPepper: PasswordWithPepper): PasswordOriginal {
    const match = passwordWithPepper.match(/^(.+)\+[a-fA-F0-9]{32}$/);
    if (!match) {
      throw new Error('Formato de PasswordWithPepper inválido');
    }
    return CredentialsTypeFactory.createPasswordOriginal(match[1]);
  }

  /**
   * Extrae la sal de un EmailWithSalt
   * @param emailWithSalt Email con sal
   * @returns Sal
   */
  static extractSalt(emailWithSalt: EmailWithSalt): Salt {
    const match = emailWithSalt.match(/^[^+]+\+([a-fA-F0-9]{32})@/);
    if (!match) {
      throw new Error('No se pudo extraer la sal');
    }
    return CredentialsTypeFactory.createSalt(match[1]);
  }

  /**
   * Extrae la pimienta de un PasswordWithPepper
   * @param passwordWithPepper Password con pimienta
   * @returns Pimienta
   */
  static extractPepper(passwordWithPepper: PasswordWithPepper): Pepper {
    const match = passwordWithPepper.match(/^[^+]+\+([a-fA-F0-9]{32})$/);
    if (!match) {
      throw new Error('No se pudo extraer la pimienta');
    }
    return CredentialsTypeFactory.createPepper(match[1]);
  }
}