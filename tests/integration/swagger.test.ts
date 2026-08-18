import request from "supertest";

jest.mock("../../src/domain/value-objects/ids", () => {
  const crypto = require("crypto");

  class MockVaultId {
    private readonly value: string;
    private constructor(value: string) { this.value = value; }
    toString() { return this.value; }
    equals(other: MockVaultId) { return this.value === other.value; }
    static generate() { return new MockVaultId(crypto.randomUUID()); }
    static fromString(value: string) { return new MockVaultId(value); }
  }

  class MockCredentialId {
    private readonly value: string;
    private constructor(value: string) { this.value = value; }
    toString() { return this.value; }
    static generate() { return new MockCredentialId(crypto.randomUUID()); }
    static fromString(value: string) { return new MockCredentialId(value); }
  }

  class MockVulnerabilityId {
    private readonly value: string;
    private constructor(value: string) { this.value = value; }
    toString() { return this.value; }
    static generate() { return new MockVulnerabilityId(crypto.randomUUID()); }
    static fromString(value: string) { return new MockVulnerabilityId(value); }
  }

  class MockCryptoHash {
    private readonly value: string;
    private constructor(value: string) { this.value = value; }
    toString() { return this.value; }
    static fromString(value: string) { return new MockCryptoHash(value); }
  }

  return {
    VaultId: MockVaultId,
    CredentialId: MockCredentialId,
    VulnerabilityId: MockVulnerabilityId,
    CryptoHash: MockCryptoHash,
  };
});

import { ApiServer, _clearRateLimitForTests } from "../../src/infrastructure/api/server";
import type { IVaultRepository, ICredentialRepository } from "../../src/domain/repositories";
import type { VaultId } from "../../src/domain/value-objects/ids";

class MockVaultRepository implements IVaultRepository {
  async save(vault: any) { return vault; }
  async findById(): Promise<any> { return null; }
  async findByVaultIdAndOwnerId(): Promise<any> { return null; }
  async delete() { return true; }
  async list() { return []; }
  async listByOwnerId() { return []; }
}

class MockCredentialRepository implements ICredentialRepository {
  async save(cred: any) { return cred; }
  async findById() { return null; }
  async findByVaultId() { return []; }
  async delete() { return true; }
  async list() { return []; }
}

function createMockCredentialsGenerator() {
  return {
    generateCredentials: jest.fn(),
    analyzeCredentialsQuality: jest.fn().mockReturnValue({
      isValid: true,
      entropyAnalysis: {},
      warnings: [],
    }),
    isValidEmailWithSalt: jest.fn().mockReturnValue(true),
    isValidPasswordWithPepper: jest.fn().mockReturnValue(true),
  } as any;
}

let server: any;

beforeEach(async () => {
  _clearRateLimitForTests();
  const app = new ApiServer(
    new MockVaultRepository(),
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    createMockCredentialsGenerator(),
    new MockCredentialRepository(),
  );
  server = await app.start(0);
});

afterEach((done) => {
  if (server) server.close(done);
  else done();
});

describe("Swagger UI", () => {
  it("GET /api/docs returns HTML", async () => {
    const res = await request(server).get("/api/docs");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    expect(res.text).toContain("swagger-ui");
    expect(res.text).toContain("CyberVault API Docs");
  });

  it("GET /api/docs/openapi.json returns valid JSON", async () => {
    const res = await request(server).get("/api/docs/openapi.json");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);

    const spec = res.body;
    expect(spec).toHaveProperty("openapi");
    expect(spec.openapi).toBe("3.0.3");
    expect(spec).toHaveProperty("info");
    expect(spec.info.title).toBe("CyberVault API");
    expect(spec.info.version).toBe("1.0.0");
  });

  it("OpenAPI spec contains all expected paths", async () => {
    const res = await request(server).get("/api/docs/openapi.json");
    const spec = res.body;

    const expectedPaths = [
      "/health",
      "/ready",
      "/metrics",
      "/api",
      "/api/v1/auth/register",
      "/api/v1/auth/login",
      "/api/v1/auth/verify",
      "/api/v1/vaults",
      "/api/v1/vaults/{vaultId}",
      "/api/v1/credentials",
      "/api/v1/credentials/generate",
      "/api/v1/credentials/extract",
      "/api/v1/credentials/validate",
    ];

    for (const path of expectedPaths) {
      expect(spec.paths).toHaveProperty(path);
    }
  });

  it("OpenAPI spec has security scheme defined", async () => {
    const res = await request(server).get("/api/docs/openapi.json");
    const spec = res.body;

    expect(spec.components).toHaveProperty("securitySchemes");
    expect(spec.components.securitySchemes).toHaveProperty("bearerAuth");
    expect(spec.components.securitySchemes.bearerAuth.type).toBe("http");
    expect(spec.components.securitySchemes.bearerAuth.scheme).toBe("bearer");
  });

  it("OpenAPI spec has data schemas defined", async () => {
    const res = await request(server).get("/api/docs/openapi.json");
    const spec = res.body;

    const expectedSchemas = [
      "ErrorResponse",
      "HealthResponse",
      "ReadyResponse",
      "Vault",
      "VaultListResponse",
      "CreateVaultRequest",
      "RegisterRequest",
      "LoginRequest",
      "GeneratedCredentialsResponse",
      "ExtractCredentialsRequest",
    ];

    for (const schema of expectedSchemas) {
      expect(spec.components.schemas).toHaveProperty(schema);
    }
  });
});
