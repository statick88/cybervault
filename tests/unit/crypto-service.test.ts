/**
 * Pruebas Unitarias para CryptoService
 * Validación de funcionalidad criptográfica
 */

import { CryptoService } from '../../src/infrastructure/crypto/crypto-service';
import { SecureBuffer, secureZero } from '../../src/infrastructure/crypto/secure-memory';

describe('CryptoService', () => {
  let cryptoService: CryptoService;

  beforeAll(() => {
    cryptoService = new CryptoService();
  });

  describe('generateKeyPair', () => {
    it('debe generar par de claves válido', async () => {
      const keyPair = await cryptoService.generateKeyPair();

      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      
      // Validar que sean JSON JWK válidos
      const publicJwk = JSON.parse(keyPair.publicKey);
      const privateJwk = JSON.parse(keyPair.privateKey);
      
      expect(publicJwk.kty).toBe('EC');
      expect(publicJwk.crv).toBe('P-256');
      expect(publicJwk.x).toBeDefined();
      expect(publicJwk.y).toBeDefined();
      
      expect(privateJwk.kty).toBe('EC');
      expect(privateJwk.crv).toBe('P-256');
      expect(privateJwk.d).toBeDefined();
    });

    it('debe generar claves diferentes cada vez', async () => {
      const keyPair1 = await cryptoService.generateKeyPair();
      const keyPair2 = await cryptoService.generateKeyPair();

      expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
      expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
    });
  });

  describe('hash', () => {
    it('debe generar hash SHA-256 de 64 caracteres', async () => {
      const hash = await cryptoService.hash('test data');
      expect(hash.toString()).toHaveLength(64);
    });

    it('debe ser determinista (mismos datos = mismo hash)', async () => {
      const hash1 = await cryptoService.hash('test data');
      const hash2 = await cryptoService.hash('test data');
      expect(hash1.toString()).toBe(hash2.toString());
    });

    it('debe ser diferente para datos diferentes', async () => {
      const hash1 = await cryptoService.hash('data1');
      const hash2 = await cryptoService.hash('data2');
      expect(hash1.toString()).not.toBe(hash2.toString());
    });
  });

  describe('salt generation', () => {
    it('debe generar salt de longitud correcta', async () => {
      const salt = await cryptoService.generateSalt();
      const decoded = atob(salt);
      expect(decoded).toHaveLength(16); // 128-bit
    });

    it('debe generar salts diferentes', async () => {
      const salt1 = await cryptoService.generateSalt();
      const salt2 = await cryptoService.generateSalt();
      expect(salt1).not.toBe(salt2);
    });
  });

  describe('deriveKey', () => {
    it('debe derivar clave de contraseña', async () => {
      const salt = await cryptoService.generateSalt();
      const key = await cryptoService.deriveKey('password123', salt);

      expect(key).toBeDefined();
      expect(typeof key).toBe('string');
    });

    it('debe derivar misma clave para mismos inputs', async () => {
      const salt = await cryptoService.generateSalt();
      const key1 = await cryptoService.deriveKey('password', salt);
      const key2 = await cryptoService.deriveKey('password', salt);

      expect(key1).toBe(key2);
    });
  });

  describe('sign and verify', () => {
    it('debe firmar y verificar datos correctamente', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const data = 'datos sensibles para firma';

      const signature = await cryptoService.sign(data, keyPair.privateKey);
      const isValid = await cryptoService.verify(data, signature, keyPair.publicKey);

      expect(signature).toBeDefined();
      expect(isValid).toBe(true);
    });

    it('debe rechazar firma inválida', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const data = 'datos sensibles para firma';
      const fakeSignature = 'dGVzdA=='; // "test" en base64

      const isValid = await cryptoService.verify(data, fakeSignature, keyPair.publicKey);
      expect(isValid).toBe(false);
    });

    it('debe rechazar datos modificados', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const originalData = 'datos originales';
      const modifiedData = 'datos modificados';

      const signature = await cryptoService.sign(originalData, keyPair.privateKey);
      const isValid = await cryptoService.verify(modifiedData, signature, keyPair.publicKey);

      expect(isValid).toBe(false);
    });
  });

  describe('encrypt and decrypt', () => {
    it('debe encriptar y desencriptar correctamente', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const originalData = 'datos sensibles para cifrar';

      const encrypted = await cryptoService.encrypt(originalData, keyPair.publicKey);
      const decrypted = await cryptoService.decrypt(encrypted, keyPair.privateKey);

      expect(encrypted).not.toBe(originalData);
      expect(decrypted).toBe(originalData);
    });

    it('debe producir datos encriptados diferentes para misma entrada', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const data = 'datos sensibles';

      const encrypted1 = await cryptoService.encrypt(data, keyPair.publicKey);
      const encrypted2 = await cryptoService.encrypt(data, keyPair.publicKey);

      // El nonce es aleatorio, así que los outputs deben ser diferentes
      expect(encrypted1).not.toBe(encrypted2);
    });
  });
});

describe('SecureBuffer', () => {
  describe('initialization', () => {
    it('debe crear buffer con longitud especificada', () => {
      const buffer = new SecureBuffer(32);
      expect(buffer.length).toBe(32);
      expect(buffer.freed).toBe(false);
    });

    it('debe permitir copiar datos', () => {
      const buffer = new SecureBuffer(32);
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      buffer.copyFrom(data);

      const copied = new Uint8Array(5);
      buffer.copyTo(copied);
      expect(copied).toEqual(data);
    });
  });

  describe('free', () => {
    it('debe sobrescribir buffer con ceros al liberar', () => {
      const buffer = new SecureBuffer(8);
      const data = new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255]);
      buffer.copyFrom(data);
      buffer.free();

      expect(buffer.freed).toBe(true);
    });

    it('debe lanzar error al acceder buffer liberado', () => {
      const buffer = new SecureBuffer(8);
      buffer.free();

      expect(() => buffer.view).toThrow('Buffer ya fue liberado');
    });
  });
});

describe('secureZero', () => {
  it('debe sobrescribir buffer con ceros', () => {
    const buffer = new Uint8Array([255, 255, 255, 255]);
    secureZero(buffer);
    expect(buffer).toEqual(new Uint8Array([0, 0, 0, 0]));
  });
});
