/**
 * Tests Unitarios: CreateVaultUseCase
 * Prueba el uso caso de creación de una nueva bóveda
 */

import { CreateVaultUseCase } from "../../../../src/application/use-cases/create-vault.use-case";
import { IVaultRepository } from "../../../../src/domain/repositories";
import { Vault } from "../../../../src/domain/entities/vault";
import { VaultId } from "../../../../src/domain/value-objects/ids";

describe("CreateVaultUseCase", () => {
  let useCase: CreateVaultUseCase;
  let mockVaultRepository: jest.Mocked<IVaultRepository>;
  let testVault: Vault;

  beforeEach(() => {
    mockVaultRepository = {
      save: jest.fn().mockImplementation((vault) => Promise.resolve(vault)),
      findById: jest.fn(),
      delete: jest.fn(),
      list: jest.fn(),
    };
    useCase = new CreateVaultUseCase(mockVaultRepository);

    testVault = Vault.create({
      name: "Test Vault",
      description: "Test Description",
      encryptedData: "",
      encryptionKeyId: "test-key-id",
    });
  });

  describe("execute", () => {
    it("debería llamar a repository.save con vault creado", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      const result = await useCase.execute({
        name: "Test Vault",
        encryptionKeyId: "test-key-id",
      });

      expect(mockVaultRepository.save).toHaveBeenCalledTimes(1);
      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault).toBeInstanceOf(Vault);
      expect(savedVault.name).toBe("Test Vault");
      expect(savedVault.encryptionKeyId).toBe("test-key-id");
    });

    it("debería pasar datos correctos al crear vault", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "My Vault",
        description: "My Description",
        encryptionKeyId: "my-key-id",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.name).toBe("My Vault");
      expect(savedVault.description).toBe("My Description");
      expect(savedVault.encryptionKeyId).toBe("my-key-id");
      expect(savedVault.encryptedData).toBe(""); // Placeholder vacío
    });

    it("debería retornar vault guardado", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      const result = await useCase.execute({
        name: "Test Vault",
        encryptionKeyId: "test-key-id",
      });

      expect(result).toEqual(testVault);
    });

    it("debería generar ID único para cada vault", async () => {
      const savedVault1 = await useCase.execute({
        name: "Vault 1",
        encryptionKeyId: "key-1",
      });
      const savedVault2 = await useCase.execute({
        name: "Vault 2",
        encryptionKeyId: "key-2",
      });

      expect(savedVault1.id.equals(savedVault2.id)).toBe(false);
    });

    it("debería establecer createdAt y updatedAt", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "Test Vault",
        encryptionKeyId: "test-key-id",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.createdAt).toBeInstanceOf(Date);
      expect(savedVault.updatedAt).toBeInstanceOf(Date);
      expect(savedVault.createdAt.getTime()).toBe(
        savedVault.updatedAt.getTime(),
      );
    });

    it("debería manejar description opcional", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "No Description Vault",
        encryptionKeyId: "key-id",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.description).toBeUndefined();
    });

    it("debería propagar errores del repository", async () => {
      const error = new Error("Repository error");
      mockVaultRepository.save.mockRejectedValue(error);

      await expect(
        useCase.execute({
          name: "Test Vault",
          encryptionKeyId: "test-key-id",
        }),
      ).rejects.toThrow("Repository error");
    });

    it("debería crear vault con parámetros mínimos", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "Minimal Vault",
        encryptionKeyId: "min-key",
      });

      expect(mockVaultRepository.save).toHaveBeenCalledTimes(1);
      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.name).toBe("Minimal Vault");
      expect(savedVault.encryptionKeyId).toBe("min-key");
      expect(savedVault.description).toBeUndefined();
    });
  });

  describe("Validaciones de business logic", () => {
    it("debería crear vaults con nombres especiales", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "Vault con acentos y ñ",
        encryptionKeyId: "key-especial",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.name).toBe("Vault con acentos y ñ");
    });

    it("debería crear vault con encryptionKeyId complejo", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "Complex Key Vault",
        encryptionKeyId: "key-123-abc-xyz-789",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.encryptionKeyId).toBe("key-123-abc-xyz-789");
    });

    it("debería permitir nombre vault vacío?", async () => {
      // NOTA: Esto depende de las reglas de negocio
      // Si se debe validar nombre vacío, agregar validación en el use case
      mockVaultRepository.save.mockResolvedValue(testVault);

      // Este test pasará si no hay validación
      await useCase.execute({
        name: "",
        encryptionKeyId: "key-id",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(savedVault.name).toBe("");
    });
  });

  describe("Tests de integración con entidades", () => {
    it("debería crear vault con Vault.create factory method", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "Factory Test",
        encryptionKeyId: "factory-key",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      expect(Vault).toBeDefined();
      expect(savedVault).toBeInstanceOf(Vault);
    });

    it("debería mantener immutabilidad del vault original", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      const inputData = {
        name: "Immutability Test",
        encryptionKeyId: "immutable-key",
      };
      const result = await useCase.execute(inputData);

      expect(inputData.name).toBe("Immutability Test");
      expect(result).not.toBe(inputData);
    });

    it("debería convertir vault a plainObject correctamente", async () => {
      mockVaultRepository.save.mockResolvedValue(testVault);

      await useCase.execute({
        name: "PlainObject Test",
        encryptionKeyId: "plain-key",
      });

      const savedVault = mockVaultRepository.save.mock.calls[0][0];
      const plain = savedVault.toPlainObject();

      expect(plain).toHaveProperty("id");
      expect(plain).toHaveProperty("name");
      expect(plain).toHaveProperty("encryptedData");
      expect(plain).toHaveProperty("encryptionKeyId");
      expect(plain).toHaveProperty("createdAt");
      expect(plain).toHaveProperty("updatedAt");
      expect(typeof plain.id).toBe("string");
      expect(typeof plain.createdAt).toBe("string");
      expect(typeof plain.updatedAt).toBe("string");
    });
  });
});
