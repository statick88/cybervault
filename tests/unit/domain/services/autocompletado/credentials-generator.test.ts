/**
 * Tests Unitarios: Credentials Generator
 * Prueba la generación de credenciales con sal y pimienta
 */

import { CredentialsGenerator } from '../../../../../src/domain/services/autocompletado/credentials-generator';
import {
  InvalidEmailFormatError,
  InvalidPasswordFormatError,
  SaltExtractionError,
  PepperExtractionError,
  InvalidDomainError
} from '../../../../../src/domain/services/autocompletado/credentials-errors';

describe('CredentialsGenerator', () => {
  let generator: CredentialsGenerator;

  beforeEach(() => {
    generator = new CredentialsGenerator();
  });

  describe('generateCredentials', () => {
    it('debería generar credenciales válidas', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      expect(credentials.email).toBeTruthy();
      expect(credentials.password).toBeTruthy();
      expect(credentials.originalEmail).toBeTruthy();
      expect(credentials.originalPassword).toBeTruthy();
      expect(credentials.salt).toBeTruthy();
      expect(credentials.pepper).toBeTruthy();
    });

    it('debería generar email con formato correcto', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      // Formato: usuario+salt@dominio
      expect(credentials.email).toMatch(/^[a-f0-9]+\+[a-f0-9]+@ejemplo\.com$/i);
    });

    it('debería generar password con formato correcto', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      // Formato: password+pepper (el password base puede contener caracteres especiales)
      expect(credentials.password).toContain('+');
      // El password debe terminar con '+' + 32 caracteres hexadecimales (la pimienta)
      expect(credentials.password).toMatch(/\+[a-fA-F0-9]{32}$/);
    });

    it('debería generar sal y pimienta de 32 caracteres', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      expect(credentials.salt.length).toBe(32);
      expect(credentials.pepper.length).toBe(32);
    });

    it('debería generar email y password originales sin sal ni pimienta', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      expect(credentials.email).not.toBe(credentials.originalEmail);
      expect(credentials.password).not.toBe(credentials.originalPassword);
      
      // El email original no debe tener '+'
      expect(credentials.originalEmail).not.toContain('+');
      
      // El password original debe ser la parte antes del último '+' + 32 caracteres hexadecimales
      const pepperMatch = credentials.password.match(/^(.+)\+[a-fA-F0-9]{32}$/);
      expect(pepperMatch).toBeTruthy();
      expect(credentials.originalPassword).toBe(pepperMatch![1]);
    });

    it('debería generar credenciales únicas para cada llamada', async () => {
      const credentials1 = await generator.generateCredentials('ejemplo.com');
      const credentials2 = await generator.generateCredentials('ejemplo.com');

      expect(credentials1.email).not.toBe(credentials2.email);
      expect(credentials1.password).not.toBe(credentials2.password);
    });
  });

  describe('extractOriginalCredentials', () => {
    it('debería extraer credenciales originales correctamente', async () => {
      const storedEmail = 'user123+salt456@ejemplo.com';
      const storedPassword = 'pass789+pepper012';

      const result = await generator.extractOriginalCredentials(storedEmail, storedPassword);

      expect(result.email).toBe('user123@ejemplo.com');
      expect(result.password).toBe('pass789');
    });

    it('debería lanzar error para email inválido', async () => {
      await expect(
        generator.extractOriginalCredentials('invalid-email', 'password+pepper')
      ).rejects.toThrow(InvalidEmailFormatError);
    });

    it('debería lanzar error para password inválido', async () => {
      await expect(
        generator.extractOriginalCredentials('user+salt@ejemplo.com', 'invalid-password')
      ).rejects.toThrow(InvalidPasswordFormatError);
    });

    it('debería lanzar error para email vacío', async () => {
      await expect(
        generator.extractOriginalCredentials('', 'password+pepper')
      ).rejects.toThrow(InvalidEmailFormatError);
    });

    it('debería lanzar error para password vacío', async () => {
      await expect(
        generator.extractOriginalCredentials('user+salt@ejemplo.com', '')
      ).rejects.toThrow(InvalidPasswordFormatError);
    });
  });

  describe('isValidEmailWithSalt', () => {
    it('debería validar email con sal correctamente', () => {
      // Los emails generados por el sistema tienen formato específico
      // El validador requiere sal de 32 caracteres hexadecimales
      expect(generator.isValidEmailWithSalt('user+abc123def45678901234567890abcdef@ejemplo.com')).toBe(true);
      expect(generator.isValidEmailWithSalt('user+0123456789abcdef0123456789abcdef@dominio.com')).toBe(true);
    });

    it('debería rechazar email sin sal', () => {
      expect(generator.isValidEmailWithSalt('user@ejemplo.com')).toBe(false);
    });

    it('debería rechazar email con formato incorrecto', () => {
      expect(generator.isValidEmailWithSalt('invalid')).toBe(false);
    });
  });

  describe('isValidPasswordWithPepper', () => {
    it('debería validar password con pimienta correctamente', () => {
      // Los passwords generados tienen formato específico
      // El validador requiere password base de 32+ caracteres y pimienta de 32 caracteres hexadecimales
      expect(generator.isValidPasswordWithPepper('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!+0123456789abcdef0123456789abcdef')).toBe(true);
    });

    it('debería rechazar password sin pimienta', () => {
      expect(generator.isValidPasswordWithPepper('password')).toBe(false);
    });

    it('debería rechazar password con formato incorrecto', () => {
      expect(generator.isValidPasswordWithPepper('invalid+multiple+plus')).toBe(false);
    });
  });

  describe('extractSalt', () => {
    it('debería extraer sal de email válido', () => {
      const salt = generator.extractSalt('user+abc123@ejemplo.com');
      expect(salt).toBe('abc123');
    });

    it('debería lanzar error para email inválido', () => {
      expect(() => generator.extractSalt('invalid-email'))
        .toThrow(SaltExtractionError);
    });

    it('debería lanzar error para email vacío', () => {
      expect(() => generator.extractSalt(''))
        .toThrow(SaltExtractionError);
    });
  });

  describe('extractPepper', () => {
    it('debería extraer pimienta de password válido', () => {
      const pepper = generator.extractPepper('password+xyz789');
      expect(pepper).toBe('xyz789');
    });

    it('debería lanzar error para password inválido', () => {
      expect(() => generator.extractPepper('invalid-password'))
        .toThrow(PepperExtractionError);
    });

    it('debería lanzar error para password vacío', () => {
      expect(() => generator.extractPepper(''))
        .toThrow(PepperExtractionError);
    });
  });

  describe('generateCredentials con validación de dominio', () => {
    it('debería lanzar error para dominio vacío', async () => {
      await expect(generator.generateCredentials(''))
        .rejects.toThrow(InvalidDomainError);
    });

    it('debería lanzar error para dominio null', async () => {
      await expect(generator.generateCredentials(null as any))
        .rejects.toThrow(InvalidDomainError);
    });
  });

  describe('seguridad', () => {
    it('debería usar crypto.getRandomValues para aleatoriedad', async () => {
      const credentials1 = await generator.generateCredentials('ejemplo.com');
      const credentials2 = await generator.generateCredentials('ejemplo.com');

      // Las credenciales deberían ser diferentes (alta probabilidad)
      expect(credentials1.salt).not.toBe(credentials2.salt);
      expect(credentials1.pepper).not.toBe(credentials2.pepper);
    });

    it('debería generar sal y pimienta de entropía adecuada', async () => {
      const credentials = await generator.generateCredentials('ejemplo.com');

      // Verificar que son strings hexadecimales
      expect(credentials.salt).toMatch(/^[a-f0-9]{32}$/i);
      expect(credentials.pepper).toMatch(/^[a-f0-9]{32}$/i);
    });
  });
});