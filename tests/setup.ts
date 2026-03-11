/**
 * Configuración global para pruebas
 */

// Polifill para crypto.randomUUID si no está disponible
if (typeof crypto === 'undefined') {
  // @ts-ignore
  global.crypto = require('crypto').webcrypto;
}

// Configurar timeout para pruebas criptográficas
jest.setTimeout(30000);
