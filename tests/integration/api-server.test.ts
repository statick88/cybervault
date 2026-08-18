import request from "supertest";

// Mock the branded ID module — VaultIdBrand is a `declare const` that only
// exists at compile-time; ts-jest doesn't strip it, so we replace the module
// with a runtime-safe version before importing anything that touches it.
jest.mock("../../src/domain/value-objects/ids", () => {
  const crypto = require("crypto");

  class MockVaultId {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    equals(other: MockVaultId) { return this.value === other.value; }
    static generate() {
      return new MockVaultId(crypto.randomUUID());
    }
    static fromString(value: string) {
      return new MockVaultId(value);
    }
  }

  class MockCredentialId {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    static generate() {
      return new MockCredentialId(crypto.randomUUID());
    }
    static fromString(value: string) {
      return new MockCredentialId(value);
    }
  }

  class MockVulnerabilityId {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    static generate() {
      return new MockVulnerabilityId(crypto.randomUUID());
    }
    static fromString(value: string) {
      return new MockVulnerabilityId(value);
    }
  }

  class MockCryptoHash {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    static fromString(value: string) {
      return new MockCryptoHash(value);
    }
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

// --- In-memory mock repositories ---

class MockVaultRepository implements IVaultRepository {
  private vaults = new Map<string, any>();

  async save(vault: any): Promise<any> {
    this.vaults.set(vault.id.toString(), vault);
    return vault;
  }

  async findById(id: VaultId): Promise<any | null> {
    return this.vaults.get(id.toString()) ?? null;
  }

  async findByVaultIdAndOwnerId(vaultId: string, ownerId: string): Promise<any | null> {
    const vault = this.vaults.get(vaultId) ?? null;
    if (!vault) return null;
    return vault.ownerId === ownerId ? vault : null;
  }

  async delete(id: VaultId): Promise<boolean> {
    return this.vaults.delete(id.toString());
  }

  async list(): Promise<any[]> {
    return Array.from(this.vaults.values());
  }

  async listByOwnerId(ownerId: string): Promise<any[]> {
    return Array.from(this.vaults.values()).filter(
      (v) => v.ownerId === ownerId,
    );
  }
}

class MockCredentialRepository implements ICredentialRepository {
  async save(cred: any): Promise<any> { return cred; }
  async findById(): Promise<any> { return null; }
  async findByVaultId(): Promise<any[]> { return []; }
  async delete(): Promise<boolean> { return true; }
  async list(): Promise<any[]> { return []; }
}

const noopCrypto = {} as any;

function createMockCredentialsGenerator() {
  return {
    generateCredentials: jest.fn().mockResolvedValue({
      email: "test-abc123@example.com",
      password: "SecureP@ssw0rd!",
      originalEmail: "user@domain.com",
      originalPassword: "MySecret123",
      salt: "a".repeat(32),
      pepper: "b".repeat(32),
    }),
    analyzeCredentialsQuality: jest.fn().mockReturnValue({
      isValid: true,
      entropyAnalysis: { salt: 128, pepper: 128, passwordBase: 60 },
      randomnessAnalysis: {
        salt: { isValid: true, issues: [] as string[] },
        pepper: { isValid: true, issues: [] as string[] },
      },
      warnings: [],
    }),
    isValidEmailWithSalt: jest.fn().mockReturnValue(true),
    isValidPasswordWithPepper: jest.fn().mockReturnValue(true),
  } as any;
}

let vaultRepo: MockVaultRepository;
let server: any;
let authToken: string;

/**
 * Registers a user and returns a Bearer token for protected endpoints.
 * The register/login routes are public; everything else requires auth
 * (JWT_SECRET is always set in tests via tests/jest.setup.js).
 */
async function getAuthToken(): Promise<string> {
  const email = `auth-${Date.now()}@test.com`;
  const password = "strongpass123";

  await request(server)
    .post("/api/v1/auth/register")
    .send({ email, password });

  const loginRes = await request(server)
    .post("/api/v1/auth/login")
    .send({ email, password });

  expect(loginRes.status).toBe(200);
  return loginRes.body.token as string;
}

beforeEach(async () => {
  _clearRateLimitForTests();
  vaultRepo = new MockVaultRepository();

  const app = new ApiServer(
    vaultRepo,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    createMockCredentialsGenerator(),
    new MockCredentialRepository(),
  );

  server = await app.start(0);
  authToken = await getAuthToken();
});

afterEach((done) => {
  if (server) {
    server.close(done);
  } else {
    done();
  }
});

// --- Auth: register ---

describe("POST /api/v1/auth/register", () => {
  it("registers a new user successfully", async () => {
    const res = await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "register-ok@test.com", password: "strongpass123" });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("userId");
    expect(res.body.email).toBe("register-ok@test.com");
    expect(res.body.message).toMatch(/User registered successfully/);
  });

  it("rejects duplicate email (returns 200 to prevent enumeration)", async () => {
    await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "dup@test.com", password: "strongpass123" });

    const res = await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "dup@test.com", password: "strongpass456" });

    // Returns 200 (not 409) to prevent user enumeration
    expect(res.status).toBe(200);
  });

  it("rejects missing fields", async () => {
    const res = await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "only@test.com" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Email and password required");
  });

  it("rejects short password", async () => {
    const res = await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "short@test.com", password: "abc" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/at least 8 characters/);
  });

  it("rejects invalid email format", async () => {
    const res = await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "not-an-email", password: "strongpass123" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Invalid email format");
  });
});

// --- Auth: login ---

describe("POST /api/v1/auth/login", () => {
  beforeEach(async () => {
    await request(server)
      .post("/api/v1/auth/register")
      .send({ email: "login@test.com", password: "correctpass1" });
  });

  it("logs in with valid credentials", async () => {
    const res = await request(server)
      .post("/api/v1/auth/login")
      .send({ email: "login@test.com", password: "correctpass1" });

    expect(res.status).toBe(200);
    expect(res.body.email).toBe("login@test.com");
    expect(res.body.message).toMatch(/Login successful/);
  });

  it("rejects wrong password", async () => {
    const res = await request(server)
      .post("/api/v1/auth/login")
      .send({ email: "login@test.com", password: "wrongpass999" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  it("rejects non-existent user", async () => {
    const res = await request(server)
      .post("/api/v1/auth/login")
      .send({ email: "nouser@test.com", password: "whatever123" });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe("Invalid email or password");
  });

  it("rejects missing fields", async () => {
    const res = await request(server)
      .post("/api/v1/auth/login")
      .send({ email: "login@test.com" });

    expect(res.status).toBe(400);
  });
});

// --- Vault CRUD ---

describe("Vault CRUD", () => {
  const VAULT_PAYLOAD = {
    name: "Test Vault",
    description: "A test vault",
    encryptionKeyId: "key-001",
  };

  it("creates a vault", async () => {
    const res = await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${authToken}`)
      .send(VAULT_PAYLOAD);

    expect(res.status).toBe(201);
    expect(res.body.name).toBe("Test Vault");
    expect(res.body).toHaveProperty("id");
    expect(res.body.encryptionKeyId).toBe("key-001");
  });

  it("lists vaults", async () => {
    await request(server).post("/api/v1/vaults").set("Authorization", `Bearer ${authToken}`).send(VAULT_PAYLOAD);
    await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ ...VAULT_PAYLOAD, name: "Vault 2" });

    const res = await request(server).get("/api/v1/vaults").set("Authorization", `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.vaults).toHaveLength(2);
    expect(res.body.total).toBe(2);
  });

  it("gets a vault by id", async () => {
    const createRes = await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${authToken}`)
      .send(VAULT_PAYLOAD);
    const vaultId = createRes.body.id;

    const res = await request(server).get(`/api/v1/vaults/${vaultId}`).set("Authorization", `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.id).toBe(vaultId);
    expect(res.body.name).toBe("Test Vault");
  });

  it("returns 404 for non-existent vault", async () => {
    const res = await request(server).get("/api/v1/vaults/nonexistent-id").set("Authorization", `Bearer ${authToken}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Vault not found");
  });

  it("deletes a vault", async () => {
    const createRes = await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${authToken}`)
      .send(VAULT_PAYLOAD);
    const vaultId = createRes.body.id;

    const res = await request(server).delete(`/api/v1/vaults/${vaultId}`).set("Authorization", `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("deleted");

    const getRes = await request(server).get(`/api/v1/vaults/${vaultId}`).set("Authorization", `Bearer ${authToken}`);
    expect(getRes.status).toBe(404);
  });

  it("returns 404 when deleting non-existent vault", async () => {
    const res = await request(server).delete("/api/v1/vaults/no-such-id").set("Authorization", `Bearer ${authToken}`);

    expect(res.status).toBe(404);
  });

  it("rejects vault creation without required fields", async () => {
    const res = await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ name: "Incomplete" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/encryptionKeyId/);
  });
});

// --- Credentials generate ---

describe("POST /api/v1/credentials/generate", () => {
  it("generates credentials for a valid domain", async () => {
    const res = await request(server)
      .post("/api/v1/credentials/generate")
      .set("Authorization", `Bearer ${authToken}`)
      .send({ domain: "example.com" });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("email");
    expect(res.body).toHaveProperty("password");
    expect(res.body.domain).toBe("example.com");
    expect(res.body).toHaveProperty("quality");
    expect(res.body.quality.isValid).toBe(true);
  });

  it("rejects missing domain", async () => {
    const res = await request(server)
      .post("/api/v1/credentials/generate")
      .set("Authorization", `Bearer ${authToken}`)
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Domain is required");
  });
});

// --- Health and misc ---

describe("Health and misc endpoints", () => {
  it("GET /health returns 200", async () => {
    const res = await request(server).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("healthy");
  });

  it("GET /ready returns 200", async () => {
    const res = await request(server).get("/ready");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ready");
  });

  it("GET /api returns API info", async () => {
    const res = await request(server).get("/api");
    expect(res.status).toBe(200);
    expect(res.body.name).toBe("CyberVault API");
    expect(res.body).toHaveProperty("endpoints");
  });

  it("returns 404 for unknown routes", async () => {
    const res = await request(server).get("/api/v1/nonexistent");
    expect(res.status).toBe(404);
  });
});
