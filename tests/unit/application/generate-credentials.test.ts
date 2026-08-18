import { GenerateCredentialsUseCase } from "../../../src/application/use-cases/generate-credentials.use-case";
import type { CredentialsGenerator } from "../../../src/domain/services/autocompletado/credentials-generator";
import type { GeneratedCredentials } from "../../../src/domain/services/autocompletado/credentials-generator";

describe("GenerateCredentialsUseCase", () => {
  const mockGenerator: jest.Mocked<CredentialsGenerator> = {
    generateCredentials: jest.fn(),
    extractOriginalCredentialsStrong: jest.fn(),
    extractSalt: jest.fn(),
    extractPepper: jest.fn(),
    generateRandomString: jest.fn(),
    generateComplexPassword: jest.fn(),
    analyzeCredentialQuality: jest.fn(),
  } as unknown as jest.Mocked<CredentialsGenerator>;

  const useCase = new GenerateCredentialsUseCase(mockGenerator);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("delegates to credentialsGenerator.generateCredentials", async () => {
    const expected: GeneratedCredentials = {
      email: "user+salt@domain.com",
      password: "pass+pepper",
      originalEmail: "user@domain.com",
      originalPassword: "pass",
      salt: "aaa",
      pepper: "bbb",
    };
    mockGenerator.generateCredentials.mockResolvedValue(expected);

    const result = await useCase.execute("domain.com");

    expect(mockGenerator.generateCredentials).toHaveBeenCalledWith("domain.com");
    expect(result).toBe(expected);
  });

  it("propagates errors from the generator", async () => {
    mockGenerator.generateCredentials.mockRejectedValue(
      new Error("Invalid domain"),
    );

    await expect(useCase.execute("bad..domain")).rejects.toThrow(
      "Invalid domain",
    );
  });

  it("returns the exact object from the generator", async () => {
    const creds: GeneratedCredentials = {
      email: "e",
      password: "p",
      originalEmail: "oe",
      originalPassword: "op",
      salt: "s",
      pepper: "pe",
    };
    mockGenerator.generateCredentials.mockResolvedValue(creds);

    const result = await useCase.execute("example.com");
    expect(result).toEqual(creds);
  });
});
