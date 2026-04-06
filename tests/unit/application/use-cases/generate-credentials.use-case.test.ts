/**
 * Tests Unitarios: GenerateCredentialsUseCase
 * Prueba el uso caso de generación de credenciales
 */

import { GenerateCredentialsUseCase } from "../../../../src/application/use-cases/generate-credentials.use-case";
import {
  CredentialsGenerator,
  GeneratedCredentials,
} from "../../../../src/domain/services/autocompletado/credentials-generator";
import { InvalidDomainError } from "../../../../src/domain/services/autocompletado/credentials-errors";

describe("GenerateCredentialsUseCase", () => {
  let useCase: GenerateCredentialsUseCase;
  let mockCredentialsGenerator: any; // Usamos any para mock simpler

  // Mock de credenciales generadas para reusar
  const mockGeneratedCredentials: GeneratedCredentials = {
    email: "0123456789abcdef+0123456789abcdef0123456789abcdef@ejemplo.com",
    password:
      "0123456789abcdef0123456789abcdef+0123456789abcdef0123456789abcdef",
    originalEmail: "0123456789abcdef@ejemplo.com",
    originalPassword: "0123456789abcdef0123456789abcdef",
    salt: "0123456789abcdef0123456789abcdef",
    pepper: "0123456789abcdef0123456789abcdef",
  };

  beforeEach(() => {
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
    useCase = new GenerateCredentialsUseCase(mockCredentialsGenerator);
  });

  describe("execute", () => {
    it("debería llamar a credentialsGenerator.generateCredentials con dominio", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      const result = await useCase.execute("ejemplo.com");

      expect(
        mockCredentialsGenerator.generateCredentials,
      ).toHaveBeenCalledTimes(1);
      expect(mockCredentialsGenerator.generateCredentials).toHaveBeenCalledWith(
        "ejemplo.com",
      );
    });

    it("debería retornar GeneratedCredentials", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      const result = await useCase.execute("ejemplo.com");

      expect(result).toEqual(mockGeneratedCredentials);
      expect(result.email).toBe(mockGeneratedCredentials.email);
      expect(result.password).toBe(mockGeneratedCredentials.password);
      expect(result.originalEmail).toBe(mockGeneratedCredentials.originalEmail);
      expect(result.originalPassword).toBe(
        mockGeneratedCredentials.originalPassword,
      );
      expect(result.salt).toBe(mockGeneratedCredentials.salt);
      expect(result.pepper).toBe(mockGeneratedCredentials.pepper);
    });

    it("debería retornar email con formato correcto", async () => {
      const emailForDomain =
        "0123456789abcdef+0123456789abcdef0123456789abcdef@dominio.com";
      const credentials: GeneratedCredentials = {
        ...mockGeneratedCredentials,
        email: emailForDomain,
        originalEmail: "0123456789abcdef@dominio.com",
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("dominio.com");

      expect(result.email).toMatch(/^[a-f0-9]+\+[a-f0-9]{32}@dominio\.com$/i);
    });

    it("debería retornar password con formato correcto", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      const result = await useCase.execute("dominio.com");

      expect(result.password).toMatch(
        /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{32,}\+[a-fA-F0-9]{32}$/,
      );
    });

    it("debería retornar salt y pepper de 32 caracteres hexadecimales", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      const result = await useCase.execute("test.com");

      expect(result.salt.length).toBe(32);
      expect(result.pepper.length).toBe(32);
      expect(result.salt).toMatch(/^[a-fA-F0-9]{32}$/);
      expect(result.pepper).toMatch(/^[a-fA-F0-9]{32}$/);
    });

    it("debería propagar InvalidDomainError cuando el dominio es inválido", async () => {
      mockCredentialsGenerator.generateCredentials.mockRejectedValue(
        new InvalidDomainError("test"),
      );

      await expect(useCase.execute("test")).rejects.toThrow(InvalidDomainError);
    });

    it("debería propagar cualquier error del generator", async () => {
      const error = new Error("Generator failure");
      mockCredentialsGenerator.generateCredentials.mockRejectedValue(error);

      await expect(useCase.execute("ejemplo.com")).rejects.toThrow(
        "Generator failure",
      );
    });

    it("debería manejar diferentes dominios", async () => {
      const mockForDomain1 = {
        ...mockGeneratedCredentials,
        email: "user+salt@domain1.com",
      };
      const mockForDomain2 = {
        ...mockGeneratedCredentials,
        email: "user+salt@domain2.com",
      };

      mockCredentialsGenerator.generateCredentials
        .mockResolvedValueOnce(mockForDomain1)
        .mockResolvedValueOnce(mockForDomain2);

      const result1 = await useCase.execute("domain1.com");
      const result2 = await useCase.execute("domain2.com");

      expect(result1.email).toContain("@domain1.com");
      expect(result2.email).toContain("@domain2.com");
    });
  });

  describe("Validaciones", () => {
    it("debería validar que originalEmail no contiene sal", async () => {
      const credentials = {
        email: "user+salt1234567890123456789012345678@ejemplo.com",
        password: "pass+pepper",
        originalEmail: "user@ejemplo.com",
        originalPassword: "pass",
        salt: "salt1234567890123456789012345678",
        pepper: "pepper1234567890123456789012345678",
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("ejemplo.com");

      expect(result.originalEmail).not.toContain("+");
      expect(result.originalEmail).toBe("user@ejemplo.com");
    });

    it("debería validar que originalPassword no contiene pimienta", async () => {
      const credentials = {
        email: "user+salt@ejemplo.com",
        password: "ComplexPass+pepper1234567890123456789012345678",
        originalEmail: "user@ejemplo.com",
        originalPassword: "ComplexPass",
        salt: "salt1234567890123456789012345678",
        pepper: "pepper1234567890123456789012345678",
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("ejemplo.com");

      expect(result.originalPassword).not.toContain("+");
      expect(result.originalPassword).toBe("ComplexPass");
    });
  });

  describe("Configuración de entropía", () => {
    it("debería retornar credenciales con alta entropía", async () => {
      const highEntropyPasswordBase = "A".repeat(128);
      const salt = "0123456789abcdef0123456789abcdef";
      const pepper = "fedcba9876543210fedcba9876543210";
      const credentials: GeneratedCredentials = {
        email: `0123456789abcdef+${salt}@ejemplo.com`,
        password: `${highEntropyPasswordBase}+${pepper}`,
        originalEmail: "0123456789abcdef@ejemplo.com",
        originalPassword: highEntropyPasswordBase,
        salt,
        pepper,
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("ejemplo.com");

      // Verificar que la sal y pimienta tienen 128 bits de entropía (32 hex chars)
      expect(result.salt).toHaveLength(32);
      expect(result.pepper).toHaveLength(32);
    });
  });

  describe("Tests de factory methods de CredentialsGenerator", () => {
    it("debería usar generateCredentials del generator", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      await useCase.execute("test.com");

      expect(mockCredentialsGenerator.generateCredentials).toHaveBeenCalledWith(
        "test.com",
      );
    });

    it("no debería llamar a generateCredentialsStrong en execute", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      await useCase.execute("test.com");

      expect(
        mockCredentialsGenerator.generateCredentialsStrong,
      ).not.toHaveBeenCalled();
    });

    it("no debería llamar a extractOriginalCredentialsStrong en execute", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      await useCase.execute("test.com");

      expect(
        mockCredentialsGenerator.extractOriginalCredentialsStrong,
      ).not.toHaveBeenCalled();
    });
  });

  describe("Edge cases", () => {
    it("debería manejar dominio con subdominios", async () => {
      const credentials = {
        email: "user+salt@sub.domain.example.com",
        password: "pass+pepper",
        originalEmail: "user@sub.domain.example.com",
        originalPassword: "pass",
        salt: "salt1234567890123456789012345678",
        pepper: "pepper1234567890123456789012345678",
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("sub.domain.example.com");

      expect(result.originalEmail).toBe("user@sub.domain.example.com");
    });

    it("debería manejar dominio con puerto? (depende de validación)", async () => {
      // Dependiendo de la validación, esto podría fallar
      const error = new InvalidDomainError("localhost:3000");
      mockCredentialsGenerator.generateCredentials.mockRejectedValue(error);

      await expect(useCase.execute("localhost:3000")).rejects.toThrow(
        InvalidDomainError,
      );
    });

    it("debería manejar credenciales con caracteres especiales en password", async () => {
      const specialCharsPassword =
        "P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?~`+pepper1234567890123456789012345678";
      const credentials = {
        email: "user+salt@test.com",
        password: specialCharsPassword,
        originalEmail: "user@test.com",
        originalPassword: "P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?~`",
        salt: "salt1234567890123456789012345678",
        pepper: "pepper1234567890123456789012345678",
      };
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        credentials,
      );

      const result = await useCase.execute("test.com");

      expect(result.originalPassword).toBe(
        "P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?~`",
      );
    });
  });

  describe("Tests de conformidad con interfaces", () => {
    it("debería cumplir con interfaz GeneratedCredentials", async () => {
      mockCredentialsGenerator.generateCredentials.mockResolvedValue(
        mockGeneratedCredentials,
      );

      const result = await useCase.execute("ejemplo.com");

      // Verificar que tiene todas las propiedades requeridas
      expect(result).toHaveProperty("email");
      expect(result).toHaveProperty("password");
      expect(result).toHaveProperty("originalEmail");
      expect(result).toHaveProperty("originalPassword");
      expect(result).toHaveProperty("salt");
      expect(result).toHaveProperty("pepper");

      // Verificar tipos
      expect(typeof result.email).toBe("string");
      expect(typeof result.password).toBe("string");
      expect(typeof result.originalEmail).toBe("string");
      expect(typeof result.originalPassword).toBe("string");
      expect(typeof result.salt).toBe("string");
      expect(typeof result.pepper).toBe("string");
    });
  });
});
