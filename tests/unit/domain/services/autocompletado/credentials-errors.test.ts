/**
 * Tests Unitarios: Errores de Credenciales
 * Prueba las clases de error personalizadas
 */

import {
  CredentialsError,
  InvalidEmailFormatError,
  InvalidPasswordFormatError,
  SaltExtractionError,
  PepperExtractionError,
  InvalidDomainError,
  InvalidLengthError,
  CredentialsErrorUtils
} from '../../../../../src/domain/services/autocompletado/credentials-errors';

describe('CredentialsErrors', () => {
  describe('CredentialsError', () => {
    it('debería crear un error con código', () => {
      const error = new CredentialsError('Mensaje de prueba', 'TEST_CODE');
      
      expect(error.message).toBe('Mensaje de prueba');
      expect(error.code).toBe('TEST_CODE');
      expect(error.name).toBe('CredentialsError');
    });
  });

  describe('InvalidEmailFormatError', () => {
    it('debería crear error con email', () => {
      const email = 'invalid-email';
      const error = new InvalidEmailFormatError(email);
      
      expect(error.email).toBe(email);
      expect(error.code).toBe('INVALID_EMAIL_FORMAT');
      expect(error.message).toContain(email);
    });

    it('debería incluir detalles adicionales', () => {
      const error = new InvalidEmailFormatError('test@example.com', 'Detalles adicionales');
      expect(error.message).toContain('Detalles adicionales');
    });
  });

  describe('InvalidPasswordFormatError', () => {
    it('debería crear error con password', () => {
      const password = 'invalid-password';
      const error = new InvalidPasswordFormatError(password);
      
      expect(error.password).toBe(password);
      expect(error.code).toBe('INVALID_PASSWORD_FORMAT');
      expect(error.message).toContain(password);
    });
  });

  describe('SaltExtractionError', () => {
    it('debería crear error con email', () => {
      const email = 'user@example.com';
      const error = new SaltExtractionError(email);
      
      expect(error.email).toBe(email);
      expect(error.code).toBe('SALT_EXTRACTION_FAILED');
      expect(error.message).toContain(email);
    });
  });

  describe('PepperExtractionError', () => {
    it('debería crear error con password', () => {
      const password = 'password123';
      const error = new PepperExtractionError(password);
      
      expect(error.password).toBe(password);
      expect(error.code).toBe('PEPPER_EXTRACTION_FAILED');
      expect(error.message).toContain(password);
    });
  });

  describe('InvalidDomainError', () => {
    it('debería crear error con dominio', () => {
      const domain = 'invalid-domain';
      const error = new InvalidDomainError(domain);
      
      expect(error.domain).toBe(domain);
      expect(error.code).toBe('INVALID_DOMAIN');
      expect(error.message).toContain(domain);
    });
  });

  describe('InvalidLengthError', () => {
    it('debería crear error con longitudes', () => {
      const value = 'abc';
      const error = new InvalidLengthError(value, 5, 10);
      
      expect(error.value).toBe(value);
      expect(error.minLength).toBe(5);
      expect(error.maxLength).toBe(10);
      expect(error.code).toBe('INVALID_LENGTH');
      expect(error.message).toContain('3');
      expect(error.message).toContain('5');
      expect(error.message).toContain('10');
    });
  });

  describe('CredentialsErrorUtils', () => {
    describe('isCredentialsError', () => {
      it('debería retornar true para errores de credenciales', () => {
        const error = new InvalidEmailFormatError('test@example.com');
        expect(CredentialsErrorUtils.isCredentialsError(error)).toBe(true);
      });

      it('debería retornar false para errores genéricos', () => {
        const error = new Error('Error genérico');
        expect(CredentialsErrorUtils.isCredentialsError(error)).toBe(false);
      });

      it('debería retornar false para null/undefined', () => {
        expect(CredentialsErrorUtils.isCredentialsError(null)).toBe(false);
        expect(CredentialsErrorUtils.isCredentialsError(undefined)).toBe(false);
      });
    });

    describe('isInvalidEmailFormat', () => {
      it('debería detectar errores de formato de email', () => {
        const error = new InvalidEmailFormatError('test@example.com');
        expect(CredentialsErrorUtils.isInvalidEmailFormat(error)).toBe(true);
      });

      it('debería retornar false para otros errores', () => {
        const error = new InvalidPasswordFormatError('password');
        expect(CredentialsErrorUtils.isInvalidEmailFormat(error)).toBe(false);
      });
    });

    describe('isInvalidPasswordFormat', () => {
      it('debería detectar errores de formato de password', () => {
        const error = new InvalidPasswordFormatError('password');
        expect(CredentialsErrorUtils.isInvalidPasswordFormat(error)).toBe(true);
      });

      it('debería retornar false para otros errores', () => {
        const error = new InvalidEmailFormatError('test@example.com');
        expect(CredentialsErrorUtils.isInvalidPasswordFormat(error)).toBe(false);
      });
    });

    describe('getErrorCode', () => {
      it('debería retornar el código de error', () => {
        const error = new InvalidEmailFormatError('test@example.com');
        expect(CredentialsErrorUtils.getErrorCode(error)).toBe('INVALID_EMAIL_FORMAT');
      });

      it('debería retornar null para errores no de credenciales', () => {
        const error = new Error('Error genérico');
        expect(CredentialsErrorUtils.getErrorCode(error)).toBeNull();
      });
    });
  });
});