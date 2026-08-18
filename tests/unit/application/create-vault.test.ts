import { CreateVaultUseCase } from "../../../src/application/use-cases/create-vault.use-case";
import type { IVaultRepository } from "../../../src/domain/repositories";
import { Vault } from "../../../src/domain/entities/vault";

describe("CreateVaultUseCase", () => {
  const mockRepository: IVaultRepository = {
    save: jest.fn(),
    findById: jest.fn(),
    list: jest.fn(),
    listByOwnerId: jest.fn(),
    findByVaultIdAndOwnerId: jest.fn(),
    delete: jest.fn(),
  };

  const useCase = new CreateVaultUseCase(mockRepository);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("calls repository.save with a Vault instance", async () => {
    const saved = Vault.create({
      name: "Test",
      encryptedData: "",
      encryptionKeyId: "k1",
    });
    (mockRepository.save as jest.Mock).mockResolvedValue(saved);

    const result = await useCase.execute({
      name: "Test",
      encryptionKeyId: "k1",
    });

    expect(mockRepository.save).toHaveBeenCalledTimes(1);
    const arg = (mockRepository.save as jest.Mock).mock.calls[0][0];
    expect(arg).toBeInstanceOf(Vault);
    expect(result).toBe(saved);
  });

  it("passes name, description, ownerId to Vault.create", async () => {
    (mockRepository.save as jest.Mock).mockImplementation((v) =>
      Promise.resolve(v),
    );

    await useCase.execute({
      name: "Production",
      description: "Prod vault",
      encryptionKeyId: "key-prod",
      ownerId: "user-42",
    });

    const vault: Vault = (mockRepository.save as jest.Mock).mock.calls[0][0];
    expect(vault.name).toBe("Production");
    expect(vault.description).toBe("Prod vault");
    expect(vault.ownerId).toBe("user-42");
  });

  it("sets encryptedData to empty string (placeholder)", async () => {
    (mockRepository.save as jest.Mock).mockImplementation((v) =>
      Promise.resolve(v),
    );

    await useCase.execute({
      name: "Empty",
      encryptionKeyId: "k",
    });

    const vault: Vault = (mockRepository.save as jest.Mock).mock.calls[0][0];
    expect(vault.encryptedData).toBe("");
  });

  it("propagates repository errors", async () => {
    (mockRepository.save as jest.Mock).mockRejectedValue(
      new Error("DB connection failed"),
    );

    await expect(
      useCase.execute({ name: "Fail", encryptionKeyId: "k" }),
    ).rejects.toThrow("DB connection failed");
  });

  it("returns a Vault with a generated id", async () => {
    (mockRepository.save as jest.Mock).mockImplementation((v) =>
      Promise.resolve(v),
    );

    const result = await useCase.execute({
      name: "WithId",
      encryptionKeyId: "k",
    });

    expect(result.id).toBeDefined();
    expect(result.id.toString()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });
});
