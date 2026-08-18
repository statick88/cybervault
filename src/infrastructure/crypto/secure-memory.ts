/**
 * Secure Memory Utilities
 * Proporciona funciones para manejo seguro de buffers sensibles en memoria
 */

/**
 * Sobrescribe un ArrayBuffer con ceros (zero-fill) para limpiar memoria sensible
 * @param buffer Buffer a sobrescribir
 */
export function secureZero(buffer: ArrayBuffer | Uint8Array): void {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  view.fill(0);
}

/**
 * Clase wrapper para buffers sensibles con limpieza automática
 */
export class SecureBuffer {
  private buffer: Uint8Array;
  private isFreed: boolean = false;

  constructor(length: number) {
    this.buffer = new Uint8Array(length);
  }

  /**
   * Obtiene el buffer como Uint8Array (solo lectura)
   */
  get view(): Uint8Array {
    if (this.isFreed) {
      throw new Error('Buffer ya fue liberado');
    }
    return this.buffer;
  }

  /**
   * Copia datos al buffer de forma segura
   */
  copyFrom(data: Uint8Array | ArrayBuffer): void {
    if (this.isFreed) {
      throw new Error('Buffer ya fue liberado');
    }
    const source = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (source.length > this.buffer.length) {
      throw new Error('Datos exceden capacidad del buffer');
    }
    this.buffer.set(source);
  }

  /**
   * Copia datos desde el buffer
   */
  copyTo(destination: Uint8Array): void {
    if (this.isFreed) {
      throw new Error('Buffer ya fue liberado');
    }
    destination.set(this.buffer.subarray(0, destination.length));
  }

  /**
   * Libera el buffer de forma segura sobrescribiendo con ceros
   */
  free(): void {
    if (!this.isFreed) {
      secureZero(this.buffer);
      this.isFreed = true;
    }
  }

  /**
   * Obtiene la longitud del buffer
   */
  get length(): number {
    return this.buffer.length;
  }

  /**
   * Verifica si el buffer fue liberado
   */
  get freed(): boolean {
    return this.isFreed;
  }
}

/**
 * Computes a SHA-512 digest of arbitrary data.
 *
 * ⚠️ WARNING: This is NOT a password hashing function. It is a plain,
 * unsalted, fast digest — do NOT use it to hash passwords or other
 * low-entropy secrets. Use a proper KDF (e.g. PBKDF2 with a per-user
 * salt) for password storage; see `hashPassword` in
 * src/infrastructure/api/auth.ts.
 *
 * @param data Data to digest
 * @returns Promise with SHA-512 digest as Uint8Array
 */
export async function hashData(data: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);
    return new Uint8Array(hashBuffer);
  } finally {
    // Limpieza segura del buffer temporal
    secureZero(dataBuffer);
  }
}

/**
 * Genera salt aleatorio seguro
 * @param length Longitud del salt en bytes
 * @returns Salt como Uint8Array
 */
export function generateSecureSalt(length: number = 16): Uint8Array {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Asigna un SecureBuffer específicamente para operaciones de channel binding
 * Pre-allocates buffer with the exact size needed for HMAC-SHA256 operations
 * 
 * @param size Tamaño del buffer en bytes (default: 64 bytes para HMAC-SHA256 key + nonce)
 * @returns SecureBuffer instance ready for binding operations
 */
export function allocateForBinding(size: number = 64): SecureBuffer {
  return new SecureBuffer(size);
}
