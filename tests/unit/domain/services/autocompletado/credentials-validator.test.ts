/**
 * Tests Unitarios: Credentials Validator
 * Prueba el validador de credenciales con regex mejoradas
 */

import { CredentialsValidator, CredentialsPatterns } from '../../../../../src/domain/services/autocompletado/credentials-validator';
import { InvalidEmailFormatError, InvalidPasswordFormatError } from '../../../../../src/domain/services/autocompletado/credentials-errors';

describe('CredentialsValidator', () => {
  describe('CredentialsPatterns', () => {
    it('debería tener patrones definidos', () => {
      expect(CredentialsPatterns.EMAIL_BASE).toBeDefined();
      expect(CredentialsPatterns.EMAIL_WITH_SALT).toBeDefined();
      expect(CredentialsPatterns.PASSWORD_BASE).toBeDefined();
      expect(CredentialsPatterns.PASSWORD_WITH_PEPPER).toBeDefined();
      expect(CredentialsPatterns.DOMAIN).toBeDefined();
    });
  });

  describe('isValidEmail', () => {
    it('debería validar emails válidos', () => {
      expect(CredentialsValidator.isValidEmail('user@example.com')).toBe(true);
      expect(CredentialsValidator.isValidEmail('user.name@example.com')).toBe(true);
      expect(CredentialsValidator.isValidEmail('user+tag@example.com')).toBe(true);
    });

    it('debería rechazar emails inválidos', () => {
      expect(CredentialsValidator.isValidEmail('')).toBe(false);
      expect(CredentialsValidator.isValidEmail('invalid')).toBe(false);
      expect(CredentialsValidator.isValidEmail('@example.com')).toBe(false);
      expect(CredentialsValidator.isValidEmail('user@')).toBe(false);
    });
  });

  describe('isValidEmailWithSalt', () => {
    it('debería validar emails con sal válidos', () => {
      expect(CredentialsValidator.isValidEmailWithSalt('user+abc123def45678901234567890abcdef@example.com')).toBe(true);
      expect(CredentialsValidator.isValidEmailWithSalt('username+0123456789abcdef0123456789abcdef@domain.com')).toBe(true);
    });

    it('debería rechazar emails con sal inválidos', () => {
      expect(CredentialsValidator.isValidEmailWithSalt('user@example.com')).toBe(false);
      expect(CredentialsValidator.isValidEmailWithSalt('user+short@domain.com')).toBe(false);
      expect(CredentialsValidator.isValidEmailWithSalt('user+invalidhex@domain.com')).toBe(false);
    });
  });

  describe('isValidPassword', () => {
    it('debería validar passwords válidos', () => {
      expect(CredentialsValidator.isValidPassword('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!')).toBe(true);
    });

    it('debería rechazar passwords inválidos', () => {
      expect(CredentialsValidator.isValidPassword('')).toBe(false);
      expect(CredentialsValidator.isValidPassword('short')).toBe(false);
    });
  });

  describe('isValidPasswordWithPepper', () => {
    it('debería validar passwords con pimienta válidos', () => {
      expect(CredentialsValidator.isValidPasswordWithPepper('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!+0123456789abcdef0123456789abcdef')).toBe(true);
    });

    it('debería rechazar passwords con pimienta inválidos', () => {
      expect(CredentialsValidator.isValidPasswordWithPepper('password+short')).toBe(false);
      expect(CredentialsValidator.isValidPasswordWithPepper('password+invalidhex')).toBe(false);
    });
  });

  describe('isValidDomain', () => {
    it('debería validar dominios válidos', () => {
      expect(CredentialsValidator.isValidDomain('example.com')).toBe(true);
      expect(CredentialsValidator.isValidDomain('sub.domain.example.com')).toBe(true);
    });

    it('debería rechazar dominios inválidos', () => {
      expect(CredentialsValidator.isValidDomain('')).toBe(false);
      expect(CredentialsValidator.isValidDomain('.com')).toBe(false);
      expect(CredentialsValidator.isValidDomain('example.')).toBe(false);
    });
  });

  describe('extractSalt', () => {
    it('debería extraer sal de email válido', () => {
      const salt = CredentialsValidator.extractSalt('user+abc123def45678901234567890abcdef@example.com');
      expect(salt).toBe('abc123def45678901234567890abcdef');
    });

    it('debería lanzar error para email inválido', () => {
      expect(() => CredentialsValidator.extractSalt('invalid-email'))
        .toThrow(InvalidEmailFormatError);
    });
  });

  describe('extractPepper', () => {
    it('debería extraer pimienta de password válido', () => {
      const pepper = CredentialsValidator.extractPepper('password+0123456789abcdef0123456789abcdef');
      expect(pepper).toBe('0123456789abcdef0123456789abcdef');
    });

    it('debería lanzar error para password inválido', () => {
      expect(() => CredentialsValidator.extractPepper('invalid-password'))
        .toThrow(InvalidPasswordFormatError);
    });
  });

  describe('parseEmailWithSalt', () => {
    it('debería parsear email con sal correctamente', () => {
      const parsed = CredentialsValidator.parseEmailWithSalt('user+abc123def45678901234567890abcdef@example.com');
      
      expect(parsed.user).toBe('user');
      expect(parsed.salt).toBe('abc123def45678901234567890abcdef');
      expect(parsed.domain).toBe('example.com');
      expect(parsed.fullEmail).toBe('user+abc123def45678901234567890abcdef@example.com');
    });

    it('debería lanzar error para sal con longitud incorrecta', () => {
      expect(() => CredentialsValidator.parseEmailWithSalt('user+short@example.com'))
        .toThrow(InvalidEmailFormatError);
    });
  });

  describe('parsePasswordWithPepper', () => {
    it('debería parsear password con pimienta correctamente', () => {
      const parsed = CredentialsValidator.parsePasswordWithPepper(
        'Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!+0123456789abcdef0123456789abcdef'
      );
      
      expect(parsed.passwordBase).toBe('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!');
      expect(parsed.pepper).toBe('0123456789abcdef0123456789abcdef');
    });

    it('debería lanzar error para password base demasiado corto', () => {
      expect(() => CredentialsValidator.parsePasswordWithPepper('short+0123456789abcdef0123456789abcdef'))
        .toThrow(InvalidPasswordFormatError);
    });
  });

  describe('validateEmailBase', () => {
    it('debería retornar válido para email correcto', () => {
      const result = CredentialsValidator.validateEmailBase('user@example.com');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('debería detectar errores en email', () => {
      const result = CredentialsValidator.validateEmailBase('');
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('validatePasswordBase', () => {
    it('debería retornar válido para password complejo', () => {
      const result = CredentialsValidator.validatePasswordBase('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('debería detectar advertencias para password simple', () => {
      const result = CredentialsValidator.validatePasswordBase('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });
});