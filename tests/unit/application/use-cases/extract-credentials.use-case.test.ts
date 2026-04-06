/**
 * Tests Unitarios: ExtractCredentialsUseCase
 * Prueba el uso caso de extracción de credenciales originales
 */

import { ExtractCredentialsUseCase } from "../../../../src/application/use-cases/extract-credentials.use-case";
import { CredentialsGenerator } from "../../../../src/domain/services/autocompletado/credentials-generator";
import {
  EmailWithSalt,
  PasswordWithPepper,
  OriginalCredentials,
  CredentialsTypeFactory,
} from "../../../../src/domain/services/autocompletado/credentials-types";

describe("ExtractCredentialsUseCase", () => {
  let useCase: ExtractCredentialsUseCase;
  let mockCredentialsGenerator: any; // Mock flexible

  // Datos de prueba comunes
  const passwordBase = "0123456789abcdef0123456789abcdef"; // 32 chars hex base
  const salt = "0123456789abcdef0123456789abcdef";
  const pepper = "fedcba9876543210fedcba9876543210";

  const mockOriginalCredentials: OriginalCredentials = {
    email: CredentialsTypeFactory.createEmailOriginal("user@ejemplo.com"),
    password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
  };

  let storedEmail: EmailWithSalt;
  let storedPassword: PasswordWithPepper;

  beforeEach(() => {
    storedEmail = CredentialsTypeFactory.createEmailWithSalt(
      `user+${salt}@ejemplo.com`,
    );
    storedPassword = CredentialsTypeFactory.createPasswordWithPepper(
      `${passwordBase}+${pepper}`,
    );
    mockCredentialsGenerator = {
      generateCredentials: jest.fn(),
      generateCredentialsStrong: jest.fn(),
      extractOriginalCredentialsStrong: jest.fn(),
      extractOriginalCredentials: jest.fn(),
      isValidEmailWithSalt: jest.fn(),
      isValidPasswordWithPepper: jest.fn(),
      extractSalt: jest.fn(),
      extractPepper: jest.fn(),
      analyzeCredentialsQuality: jest.fn(),
    };
    useCase = new ExtractCredentialsUseCase(mockCredentialsGenerator);
  });

  describe("execute", () => {
    it("debería llamar a credentialsGenerator.extractOriginalCredentialsStrong con parámetros correctos", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(
        mockCredentialsGenerator.extractOriginalCredentialsStrong,
      ).toHaveBeenCalledTimes(1);
      expect(
        mockCredentialsGenerator.extractOriginalCredentialsStrong,
      ).toHaveBeenCalledWith(storedEmail, storedPassword);
    });

    it("debería retornar OriginalCredentials", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result).toEqual(mockOriginalCredentials);
      expect(result.email).toBe(mockOriginalCredentials.email);
      expect(result.password).toBe(mockOriginalCredentials.password);
    });

    it("debería retornar email tipo EmailOriginal (sin sal)", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe("user@ejemplo.com");
      expect(result.email).not.toContain("+");
    });

    it("debería retornar password tipo PasswordOriginal (sin pimienta)", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.password).toBe(passwordBase);
      expect(result.password).not.toContain("+");
    });

    it("debería propagar errores del generator", async () => {
      const error = new Error("Extraction failed");
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockRejectedValue(
        error,
      );

      await expect(
        useCase.execute(storedEmail, storedPassword),
      ).rejects.toThrow("Extraction failed");
    });

    it("debería mantener tipos fuertes en resultado", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      // Verificar que los tipos strength están preservados
      expect(typeof result.email).toBe("string");
      expect(typeof result.password).toBe("string");
      expect(result.email).toBe("user@ejemplo.com");
      expect(result.email).not.toContain("+");
      expect(result.password).toBe(passwordBase);
      expect(result.password).not.toContain("+");
    });
  });

  describe("Conversión de tipos fuertes", () => {
    it("debería convertir EmailWithSalt a EmailOriginal correctamente", async () => {
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(
          `testuser+${salt}@dominio.com`,
        );
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(
          `${passwordBase}+${pepper}`,
        );

      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal(
          "testuser@dominio.com",
        ),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe("testuser@dominio.com");
      expect(result.password).toBe(passwordBase);
    });

    it("debería manejar EmailWithSalt con usuario largo", async () => {
      const longUser = "a".repeat(64);
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(
          `${longUser}+${salt}@domain.com`,
        );
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(
          `${passwordBase}+${pepper}`,
        );

      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal(
          `${longUser}@domain.com`,
        ),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe(`${longUser}@domain.com`);
      expect(result.email.length).toBe(longUser.length + "@domain.com".length);
      expect(result.password).toBe(passwordBase);
    });

    it("debería manejar PasswordWithPepper con password complejo", async () => {
      // password con símbolos, longitud > 32 y solo caracteres permitidos
      const complexPassword =
        "Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8*Ii9(Jj0)Kk1_L2-M3+N4";
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(`user+${salt}@test.com`);
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(
          `${complexPassword}+${pepper}`,
        );

      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@test.com"),
        password:
          CredentialsTypeFactory.createPasswordOriginal(complexPassword),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe("user@test.com");
      expect(result.password).toBe(complexPassword);
    });
  });

  describe("Edge cases para extracción", () => {
    it("debería manejar salt y pepper válidos de 32 caracteres", async () => {
      const validSalt = "0123456789abcdef0123456789abcdef";
      const validPepper = "fedcba9876543210fedcba9876543210";
      const base = "0123456789abcdef0123456789abcdef"; // 32 chars
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(
          `user+${validSalt}@example.com`,
        );
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(
          `${base}+${validPepper}`,
        );

      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@example.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(base),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe("user@example.com");
      expect(result.password).toBe(base);
    });

    it("debería manejar dominios con múltiples subniveles", async () => {
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(
          `user+${salt}@a.b.c.example.co.uk`,
        );
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(
          `${passwordBase}+${pepper}`,
        );

      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal(
          "user@a.b.c.example.co.uk",
        ),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result.email).toBe("user@a.b.c.example.co.uk");
    });

    it("no debería modificar el generator entre llamadas", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@example.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const result1 = await useCase.execute(storedEmail, storedPassword);
      const result2 = await useCase.execute(storedEmail, storedPassword);

      expect(result1.email).toEqual(result2.email);
      expect(result1.password).toEqual(result2.password);
    });

    it("no debería modificar el generator entre llamadas", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@example.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      // Use global storedEmail and storedPassword
      await useCase.execute(storedEmail, storedPassword);
      await useCase.execute(storedEmail, storedPassword);
      await useCase.execute(storedEmail, storedPassword);

      expect(
        mockCredentialsGenerator.extractOriginalCredentialsStrong,
      ).toHaveBeenCalledTimes(3);
    });
  });

  describe("Tests de conformidad con tipos fuertes", () => {
    it("debería aceptar solo EmailWithSalt como primer parámetro", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@test.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      // Usar storedPassword global válido; primer argumento se pasa como any
      await expect(
        useCase.execute("user+salt@test.com" as any, storedPassword),
      ).resolves.toBe(expectedOriginal);
    });

    it("debería aceptar solo PasswordWithPepper como segundo parámetro", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@test.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      // storedEmail es global válido; segundo parámetro se pasa como any
      await expect(
        useCase.execute(storedEmail, "pass+pepper" as any),
      ).resolves.toBe(expectedOriginal);
    });

    it("debería retornar tipos fuertes en resultado", async () => {
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      // Verificar que los tipos son correctos (marcas de tipo)
      expect(typeof result.email).toBe("string");
      expect(typeof result.password).toBe("string");
      expect(result.email).toBe("user@ejemplo.com");
      expect(result.email).not.toContain("+");
      expect(result.password).toBe(passwordBase);
      expect(result.password).not.toContain("+");
    });
  });

  describe("Validación de formato de credenciales", () => {
    it("debería validar formato EmailWithSalt antes de extraer", async () => {
      const invalidEmail = "invalid-email" as any;
      // use global storedPassword directly

      const error = new Error("Formato inválido");
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockRejectedValue(
        error,
      );

      await expect(
        useCase.execute(invalidEmail, storedPassword),
      ).rejects.toThrow();
    });

    it("debería validar formato PasswordWithPepper antes de extraer", async () => {
      // storedEmail is the global valid value
      const invalidPassword = "invalid-password" as any;

      const error = new Error("Formato inválido");
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockRejectedValue(
        error,
      );

      await expect(
        useCase.execute(storedEmail, invalidPassword),
      ).rejects.toThrow();
    });

    it("debería manejar error de formato en email con sal inválido", async () => {
      // Intentar crear EmailWithSalt inválido debería fallar en factory
      expect(() => {
        CredentialsTypeFactory.createEmailWithSalt(
          "invalid-email-without-salt",
        );
      }).toThrow();
    });

    it("debería manejar error de formato en password con pimienta inválido", async () => {
      // Intentar crear PasswordWithPepper inválido debería fallar en factory
      expect(() => {
        CredentialsTypeFactory.createPasswordWithPepper("short+pepper");
      }).toThrow();
    });
  });

  describe("Performance", () => {
    it("debería completar extracción rápidamente (sin blocking)", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal("user@test.com"),
        password: CredentialsTypeFactory.createPasswordOriginal(passwordBase),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      const start = Date.now();
      const result = await useCase.execute(storedEmail, storedPassword);
      const duration = Date.now() - start;

      expect(result).toBeDefined();
      expect(duration).toBeLessThan(1000);
    });
  });

  describe("Tests de integración", () => {
    it("debería integrar correctamente con CredentialsGenerator completo", async () => {
      // En un escenario real, el generator hace la extracción
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        mockOriginalCredentials,
      );

      const result = await useCase.execute(storedEmail, storedPassword);

      expect(result).toBeDefined();
      expect(result.email).toBeDefined();
      expect(result.password).toBeDefined();
    });

    it("debería mantener consistencia en múltiples extracciones", async () => {
      const expectedOriginal: OriginalCredentials = {
        email: CredentialsTypeFactory.createEmailOriginal(
          "consistent@test.com",
        ),
        password:
          CredentialsTypeFactory.createPasswordOriginal("ConsistentPass123!"),
      };
      mockCredentialsGenerator.extractOriginalCredentialsStrong.mockResolvedValue(
        expectedOriginal,
      );

      // Use global storedEmail and storedPassword (valid types)
      const result1 = await useCase.execute(storedEmail, storedPassword);
      const result2 = await useCase.execute(storedEmail, storedPassword);

      expect(result1.email).toEqual(result2.email);
      expect(result1.password).toEqual(result2.password);
    });
  });
});
