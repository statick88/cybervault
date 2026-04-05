/**
 * Tests Unitarios: Tipos de Seguridad
 * Prueba la definición y uso de tipos TypeScript fuertes
 */

import {
  CredentialsTypeFactory,
  CredentialsTypeUtils,
  EmailWithSalt,
  PasswordWithPepper,
  Salt,
  Pepper
} from '../../../../../src/domain/services/autocompletado/credentials-types';

describe('CredentialsTypes', () => {
  describe('CredentialsTypeFactory', () => {
    describe('createEmailWithSalt', () => {
      it('debería crear EmailWithSalt válido', () => {
        const email = 'user+abc123def45678901234567890abcdef@example.com';
        const result = CredentialsTypeFactory.createEmailWithSalt(email);
        expect(result).toBe(email);
      });

      it('debería lanzar error para email inválido', () => {
        expect(() => CredentialsTypeFactory.createEmailWithSalt('invalid-email'))
          .toThrow('EmailWithSalt inválido');
      });

      it('debería lanzar error para email sin sal', () => {
        expect(() => CredentialsTypeFactory.createEmailWithSalt('user@example.com'))
          .toThrow('EmailWithSalt inválido');
      });

      it('debería lanzar error para sal con longitud incorrecta', () => {
        expect(() => CredentialsTypeFactory.createEmailWithSalt('user+short@example.com'))
          .toThrow('EmailWithSalt inválido');
      });
    });

    describe('createEmailOriginal', () => {
      it('debería crear EmailOriginal válido', () => {
        const email = 'user@example.com';
        const result = CredentialsTypeFactory.createEmailOriginal(email);
        expect(result).toBe(email);
      });

      it('debería lanzar error si el email contiene sal', () => {
        expect(() => CredentialsTypeFactory.createEmailOriginal('user+salt@example.com'))
          .toThrow('EmailOriginal no debe contener sal');
      });
    });

    describe('createPasswordWithPepper', () => {
      it('debería crear PasswordWithPepper válido', () => {
        const password = 'Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!+0123456789abcdef0123456789abcdef';
        const result = CredentialsTypeFactory.createPasswordWithPepper(password);
        expect(result).toBe(password);
      });

      it('debería lanzar error para password inválido', () => {
        expect(() => CredentialsTypeFactory.createPasswordWithPepper('invalid'))
          .toThrow('PasswordWithPepper inválido');
      });

      it('debería lanzar error para password con pimienta corta', () => {
        expect(() => CredentialsTypeFactory.createPasswordWithPepper('password+short'))
          .toThrow('PasswordWithPepper inválido');
      });
    });

    describe('createPasswordOriginal', () => {
      it('debería crear PasswordOriginal válido', () => {
        const password = 'Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!';
        const result = CredentialsTypeFactory.createPasswordOriginal(password);
        expect(result).toBe(password);
      });

      it('debería lanzar error si el password contiene pimienta', () => {
        expect(() => CredentialsTypeFactory.createPasswordOriginal('password+0123456789abcdef0123456789abcdef'))
          .toThrow('PasswordOriginal no debe contener pimienta');
      });
    });

    describe('createSalt', () => {
      it('debería crear Salt válido', () => {
        const salt = '0123456789abcdef0123456789abcdef';
        const result = CredentialsTypeFactory.createSalt(salt);
        expect(result).toBe(salt);
      });

      it('debería lanzar error para sal con longitud incorrecta', () => {
        expect(() => CredentialsTypeFactory.createSalt('short'))
          .toThrow('Sal inválida');
      });

      it('debería lanzar error para sal con caracteres no hexadecimales', () => {
        expect(() => CredentialsTypeFactory.createSalt('0123456789abcdef0123456789xyz'))
          .toThrow('Sal inválida');
      });
    });

    describe('createPepper', () => {
      it('debería crear Pepper válido', () => {
        const pepper = 'fedcba9876543210fedcba9876543210';
        const result = CredentialsTypeFactory.createPepper(pepper);
        expect(result).toBe(pepper);
      });

      it('debería lanzar error para pimienta con longitud incorrecta', () => {
        expect(() => CredentialsTypeFactory.createPepper('short'))
          .toThrow('Pimienta inválida');
      });
    });

    describe('createValidDomain', () => {
      it('debería crear ValidDomain válido', () => {
        const domain = 'example.com';
        const result = CredentialsTypeFactory.createValidDomain(domain);
        expect(result).toBe(domain);
      });

      it('debería lanzar error para dominio inválido', () => {
        expect(() => CredentialsTypeFactory.createValidDomain(''))
          .toThrow('Dominio inválido');
      });
    });
  });

  describe('CredentialsTypeUtils', () => {
    describe('toOriginalEmail', () => {
      it('debería convertir EmailWithSalt a EmailOriginal', () => {
        const emailWithSalt = 'user+abc123def45678901234567890abcdef@example.com' as EmailWithSalt;
        const result = CredentialsTypeUtils.toOriginalEmail(emailWithSalt);
        expect(result).toBe('user@example.com');
      });

      it('debería lanzar error para formato inválido', () => {
        const invalidEmail = 'invalid@example.com' as EmailWithSalt;
        expect(() => CredentialsTypeUtils.toOriginalEmail(invalidEmail))
          .toThrow('Formato de EmailWithSalt inválido');
      });
    });

    describe('toOriginalPassword', () => {
      it('debería convertir PasswordWithPepper a PasswordOriginal', () => {
        const passwordWithPepper = 'Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!+0123456789abcdef0123456789abcdef' as PasswordWithPepper;
        const result = CredentialsTypeUtils.toOriginalPassword(passwordWithPepper);
        expect(result).toBe('Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8!');
      });
    });

    describe('extractSalt', () => {
      it('debería extraer sal de EmailWithSalt', () => {
        const emailWithSalt = 'user+abc123def45678901234567890abcdef@example.com' as EmailWithSalt;
        const result = CredentialsTypeUtils.extractSalt(emailWithSalt);
        expect(result).toBe('abc123def45678901234567890abcdef');
      });
    });

    describe('extractPepper', () => {
      it('debería extraer pimienta de PasswordWithPepper', () => {
        const passwordWithPepper = 'password+0123456789abcdef0123456789abcdef' as PasswordWithPepper;
        const result = CredentialsTypeUtils.extractPepper(passwordWithPepper);
        expect(result).toBe('0123456789abcdef0123456789abcdef');
      });
    });
  });
});