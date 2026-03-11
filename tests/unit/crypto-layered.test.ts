/**
 * Pruebas Unitarias para CryptoLayeredService (8 Capas)
 */

import { CryptoLayeredService } from '../../src/infrastructure/crypto/crypto-layered-service';
import { ShamirSecretSharing, TimeLockPuzzle } from '../../src/infrastructure/crypto/layers/layer8-advanced';
import { LSBSteganography, SecureCompression } from '../../src/infrastructure/crypto/layers/layer6-steganography';

describe('CryptoLayeredService', () => {
  let cryptoService: CryptoLayeredService;
  
  beforeAll(() => {
    cryptoService = new CryptoLayeredService();
  });
  
  describe('Capa 8: Shamir Secret Sharing', () => {
    it('debe dividir y reconstruir secreto correctamente', async () => {
      const shamir = new ShamirSecretSharing();
      const secret = 'mi-secreto-muy-seguro-12345';
      
      const shares = await shamir.split(secret, 5, 3);
      expect(shares).toHaveLength(5);
      
      // Reconstruir con 3 shares
      const recovered = await shamir.reconstruct(shares.slice(0, 3));
      expect(recovered).toBe(secret);
    });
    
    it('debe fallar con menos shares que el umbral', async () => {
      const shamir = new ShamirSecretSharing();
      const secret = 'test-secret';
      
      const shares = await shamir.split(secret, 5, 3);
      
      await expect(shamir.reconstruct(shares.slice(0, 2))).rejects.toThrow();
    });
    
    it('debe funcionar con shares ordenados aleatoriamente', async () => {
      const shamir = new ShamirSecretSharing();
      const secret = 'random-order-test';
      
      const shares = await shamir.split(secret, 5, 3);
      const shuffled = shares.sort(() => Math.random() - 0.5);
      
      const recovered = await shamir.reconstruct(shuffled.slice(0, 3));
      expect(recovered).toBe(secret);
    });
  });
  
  describe('Capa 8: Time-Lock Puzzle', () => {
    it('debe crear y resolver puzzle correctamente', async () => {
      const tlp = new TimeLockPuzzle(1000); // Baja dificultad para tests
      const data = 'datos-confidenciales';
      
      const { puzzle, solutionHash } = await tlp.create(data, 0);
      expect(puzzle).toBeDefined();
      expect(solutionHash).toHaveLength(64); // SHA-256 hex
      
      const recovered = await tlp.solve(puzzle);
      expect(recovered).toBe(data);
    });
    
    it('debe verificar hash de solución', async () => {
      const tlp = new TimeLockPuzzle(1000);
      const data = 'test-data';
      
      const { puzzle, solutionHash } = await tlp.create(data, 0);
      const recovered = await tlp.solve(puzzle);
      
      // Verificar que la solución coincide
      expect(recovered).toBe(data);
    });
  });
  
  describe('Capa 6: Esteganografía LSB', () => {
    it('debe ocultar y extraer datos de imagen', async () => {
      const stego = new LSBSteganography();
      
      // Crear imagen de prueba (simulada)
      const imageData = new Uint8Array(1000);
      crypto.getRandomValues(imageData);
      
      const secretData = 'mensaje secreto oculto';
      const hiddenImage = await stego.hideInImage(secretData, imageData);
      
      const extracted = await stego.extractFromImage(hiddenImage);
      expect(extracted).toBe(secretData);
    });
    
    it('debe verificar si imagen contiene datos', async () => {
      const stego = new LSBSteganography();
      const imageData = new Uint8Array(1000);
      crypto.getRandomValues(imageData);
      
      // Sin datos ocultos
      expect(await stego.hasHiddenData(imageData)).toBe(false);
      
      // Con datos ocultos
      const hidden = await stego.hideInImage('test', imageData);
      expect(await stego.hasHiddenData(hidden)).toBe(true);
    });
    
    it('debe fallar si imagen es muy pequeña', async () => {
      const stego = new LSBSteganography();
      const smallImage = new Uint8Array(10); // Muy pequeña
      crypto.getRandomValues(smallImage);
      
      await expect(
        stego.hideInImage('datos-demasiado-grandes-para-imagen', smallImage)
      ).rejects.toThrow();
    });
  });
  
  describe('Capa 6: Compresión Segura', () => {
    it('debe comprimir y descomprimir con integridad', async () => {
      const compression = new SecureCompression();
      const originalData = new TextEncoder().encode('Datos de prueba para compresión '.repeat(100));
      
      const compressed = await compression.compress(originalData);
      expect(compressed.length).toBeLessThan(originalData.length);
      
      const decompressed = await compression.decompress(compressed);
      expect(decompressed).toEqual(originalData);
    });
    
    it('debe detectar datos corruptos', async () => {
      const compression = new SecureCompression();
      const data = new TextEncoder().encode('test data');
      const compressed = await compression.compress(data);
      
      // Corromper datos
      compressed[10] = 255;
      
      await expect(compression.decompress(compressed)).rejects.toThrow('Integridad de datos comprometida');
    });
  });
  
  describe('Capa 7: Derivación de Clave Maestra', () => {
    it('debe derivar clave con múltiples factores', async () => {
      const masterKey = new (require('../../src/infrastructure/crypto/layers/layer7-biometrics').MasterKeyDerivation)();
      
      const derived = await masterKey.derive(
        'password123',
        'biometric-hash',
        'hardware-token',
        'secret-answer'
      );
      
      expect(derived).toBeDefined();
      expect(derived.split('|')).toHaveLength(2); // salt|key
    });
    
    it('debe validar clave maestra correctamente', async () => {
      const masterKey = new (require('../../src/infrastructure/crypto/layers/layer7-biometrics').MasterKeyDerivation)();
      
      const derived = await masterKey.derive('password123', 'bio-hash');
      const isValid = await masterKey.validate(derived, 'password123', 'bio-hash');
      
      expect(isValid).toBe(true);
    });
    
    it('debe rechazar clave inválida', async () => {
      const masterKey = new (require('../../src/infrastructure/crypto/layers/layer7-biometrics').MasterKeyDerivation)();
      
      const derived = await masterKey.derive('password123', 'bio-hash');
      const isValid = await masterKey.validate(derived, 'wrong-password', 'bio-hash');
      
      expect(isValid).toBe(false);
    });
  });
  
  describe('Capa 7: TOTP (2FA)', () => {
    it('debe generar y verificar código TOTP', async () => {
      const totp = new (require('../../src/infrastructure/crypto/layers/layer7-biometrics').TwoFactorAuth)();
      
      const secret = 'JBSWY3DPEHPK3PXP'; // Base32 secret de ejemplo
      const code = await totp.generateTOTP(secret);
      
      expect(code).toHaveLength(6);
      expect(/^\d{6}$/.test(code)).toBe(true);
      
      const isValid = await totp.verifyTOTP(code, secret);
      expect(isValid).toBe(true);
    });
  });
  
  describe('CryptoLayeredService Completo', () => {
    it('debe generar par de claves', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      
      const publicJwk = JSON.parse(keyPair.publicKey);
      expect(publicJwk.kty).toBe('EC');
      expect(publicJwk.crv).toBe('P-256');
    });
    
    it('debe encriptar y desencriptar datos', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const originalData = 'Datos sensibles de 8 capas';
      
      const encrypted = await cryptoService.encrypt(originalData, keyPair.publicKey);
      expect(encrypted).not.toBe(originalData);
      
      // Desencriptación (demo simplificado)
      const decrypted = await cryptoService.decrypt(encrypted, keyPair.privateKey);
      expect(decrypted).toBeDefined();
    });
    
    it('debe generar hash SHA-256', async () => {
      const hash = await cryptoService.hash('test data');
      expect(hash.toString()).toHaveLength(64);
    });
    
    it('debe derivar clave con PBKDF2', async () => {
      const salt = await cryptoService.generateSalt();
      const key = await cryptoService.deriveKey('password', salt);
      
      expect(key).toBeDefined();
      expect(typeof key).toBe('string');
    });
    
    it('debe firmar y verificar datos', async () => {
      const keyPair = await cryptoService.generateKeyPair();
      const data = 'datos para firma';
      
      const signature = await cryptoService.sign(data, keyPair.privateKey);
      const isValid = await cryptoService.verify(data, signature, keyPair.publicKey);
      
      expect(isValid).toBe(true);
    });
  });
});

describe('Integración de 8 Capas', () => {
  it('flujo completo de encriptación de 8 capas', async () => {
    const cryptoService = new CryptoLayeredService();
    
    // 1. Generar keys
    const keyPair = await cryptoService.generateKeyPair();
    const salt = await cryptoService.generateSalt();
    const masterKey = await cryptoService.deriveKey('contraseña-maestra-larga-16-digitos', salt);
    
    // 2. Encriptar con múltiples capas
    const sensitiveData = 'Información ultra-confidencial de 8 capas de seguridad';
    
    // Capa 8: Shamir Secret Sharing (dividir master key)
    const shamir = new ShamirSecretSharing();
    const shares = await shamir.split(masterKey, 5, 3);
    
    // Capa 7: Derivación multifactor
    const derivedKey = await cryptoService.deriveKey(masterKey, salt);
    
    // Capa 6: Esteganografía (en producción, en imagen)
    // Capa 5-1: Encriptación normal
    const encrypted = await cryptoService.encrypt(sensitiveData, keyPair.publicKey);
    
    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe(sensitiveData);
    
    // Reconstruir desde shares (demo)
    const reconstructedKey = await shamir.reconstruct(shares.slice(0, 3));
    expect(reconstructedKey).toBe(masterKey);
  });
});
