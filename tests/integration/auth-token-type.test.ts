/**
 * H1 — a 7-day refresh token must not authenticate as an access token.
 *
 * THE DEFECT
 * ----------
 * `authenticate` (the single gate in front of every authenticated Core route)
 * called `verifyToken` and attached `decoded.userId` without ever looking at
 * `decoded.type`. `verifyToken` returned `type: decoded.type` but nothing
 * compared it — the evidence the finding cites:
 *
 *     grep -E "type ===|type !==" src/infrastructure/api/auth.ts   →  no matches
 *
 * so a refresh token (7-day `exp`) was accepted by `/api/v1/vaults`,
 * `/api/v1/auth/verify`, `/api/v1/credentials`, … exactly like an access
 * token (15-minute `exp`). The refresh flow itself already checked
 * `decoded.type !== "refresh"` — only the access side was missing.
 *
 * WHAT IS PINNED HERE
 * 1. The refresh token is refused on a protected route (GET and POST).
 * 2. The access token still works — the fix rejects MORE, never less.
 * 3. `/api/v1/auth/refresh` still accepts the refresh token, and still
 *    refuses an access token: the exchange flow is unbroken.
 * 4. `authenticate` itself refuses a refresh token before `next()` runs.
 */

import request from "supertest";

// Mock the branded ID module — same block as tests/integration/api-server.test.ts
// (VaultIdBrand is `declare const` and only exists at compile time).
jest.mock("../../src/domain/value-objects/ids", () => {
  const crypto = require("crypto");

  class MockVaultId {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    equals(other: MockVaultId) { return this.value === other.value; }
    static generate() { return new MockVaultId(crypto.randomUUID()); }
    static fromString(value: string) { return new MockVaultId(value); }
  }

  class MockCredentialId {
    private readonly value: string;
    private constructor(value: string) {
      this.value = value;
    }
    toString() { return this.value; }
    static generate() { return new MockCredentialId(crypto.randomUUID()); }
    static fromString(value: string) { return new MockCredentialId(value); }
  }

  return { VaultId: MockVaultId, CredentialId: MockCredentialId };
});

import { ApiServer, _clearRateLimitForTests } from "../../src/infrastructure/api/server";
import {
  authenticate,
  generateToken,
  generateRefreshToken,
  verifyToken,
  type AuthenticatedRequest,
} from "../../src/infrastructure/api/auth";
import type { IVaultRepository, ICredentialRepository } from "../../src/domain/repositories";
import type { ServerResponse } from "http";

const SECRET = "h1-test-secret-that-is-at-least-32-chars";

class MockVaultRepository implements IVaultRepository {
  private vaults = new Map<string, any>();
  async save(vault: any): Promise<any> {
    this.vaults.set(vault.id.toString(), vault);
    return vault;
  }
  async findById(id: any): Promise<any | null> { return this.vaults.get(id.toString()) ?? null; }
  async findByVaultIdAndOwnerId(vaultId: string, ownerId: string): Promise<any | null> {
    const vault = this.vaults.get(vaultId) ?? null;
    return vault && vault.ownerId === ownerId ? vault : null;
  }
  async delete(id: any): Promise<boolean> { return this.vaults.delete(id.toString()); }
  async list(): Promise<any[]> { return Array.from(this.vaults.values()); }
  async listByOwnerId(ownerId: string): Promise<any[]> {
    return Array.from(this.vaults.values()).filter((v) => v.ownerId === ownerId);
  }
  async updateMetadata(): Promise<void> { /* not under test */ }
}

class MockCredentialRepository implements ICredentialRepository {
  async save(cred: any): Promise<any> { return cred; }
  async findById(): Promise<any> { return null; }
  async findByVaultId(): Promise<any[]> { return []; }
  async findBySecretRef(): Promise<any> { return null; }
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
      randomnessAnalysis: { isValid: true, issues: [] as string[], pepper: 64 },
      warnings: [],
    }),
    isValidEmailWithSalt: jest.fn().mockReturnValue(true),
    isValidPasswordWithPepper: jest.fn().mockReturnValue(true),
  } as any;
}

async function startHarness(): Promise<any> {
  const app = new ApiServer(
    new MockVaultRepository(),
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    createMockCredentialsGenerator(),
    new MockCredentialRepository(),
  );
  return app.start(0);
}

function closeHarness(server: any): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

describe("H1: a refresh token is not an access token", () => {
  let server: any;
  let accessToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    _clearRateLimitForTests();
    server = await startHarness();

    const email = `h1-${Date.now()}@test.com`;
    await request(server).post("/api/v1/auth/register").send({ email, password: "strongpass123" });
    const login = await request(server)
      .post("/api/v1/auth/login")
      .send({ email, password: "strongpass123" });
    expect(login.status).toBe(200);
    accessToken = login.body.token;
    refreshToken = login.body.refreshToken;
  });

  afterAll(async () => {
    if (server) await closeHarness(server);
  });

  it("hands out two tokens of different types and expiries", () => {
    const access = verifyToken(accessToken, process.env.JWT_SECRET as string);
    const refresh = verifyToken(refreshToken, process.env.JWT_SECRET as string);

    expect(access?.type).toBe("access");
    expect(refresh?.type).toBe("refresh");
    expect(refresh?.userId).toBe(access?.userId);
  });

  it("refuses a refresh token on a protected GET route", async () => {
    const res = await request(server)
      .get("/api/v1/vaults")
      .set("Authorization", `Bearer ${refreshToken}`);

    expect(res.status).toBe(401);
  });

  it("refuses a refresh token on a protected POST route", async () => {
    const res = await request(server)
      .post("/api/v1/vaults")
      .set("Authorization", `Bearer ${refreshToken}`)
      .send({ name: "Nope", encryptionKeyId: "k" });

    expect(res.status).toBe(401);
  });

  it("refuses a refresh token on the token-verification route", async () => {
    const res = await request(server)
      .get("/api/v1/auth/verify")
      .set("Authorization", `Bearer ${refreshToken}`);

    expect(res.status).toBe(401);
    expect(res.body.valid).toBeUndefined();
  });

  it("still accepts the access token on the same routes", async () => {
    const list = await request(server)
      .get("/api/v1/vaults")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(list.status).toBe(200);

    const verify = await request(server)
      .get("/api/v1/auth/verify")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(verify.status).toBe(200);
    expect(verify.body.valid).toBe(true);
  });

  it("still exchanges the refresh token at the refresh endpoint", async () => {
    const res = await request(server)
      .post("/api/v1/auth/refresh")
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(verifyToken(res.body.token, process.env.JWT_SECRET as string)?.type).toBe("access");
    expect(verifyToken(res.body.refreshToken, process.env.JWT_SECRET as string)?.type).toBe(
      "refresh",
    );
  });

  it("still refuses an access token at the refresh endpoint", async () => {
    const res = await request(server)
      .post("/api/v1/auth/refresh")
      .send({ refreshToken: accessToken });

    expect(res.status).toBe(401);
  });

  it("authenticate() itself refuses a refresh token before calling next()", () => {
    process.env.JWT_SECRET = SECRET;
    try {
      const req = {
        headers: { authorization: `Bearer ${generateRefreshToken("user-1", SECRET)}` },
      } as unknown as AuthenticatedRequest;

      const writeHead = jest.fn();
      const end = jest.fn();
      const res = { writeHead, end } as unknown as ServerResponse;
      const next = jest.fn();

      authenticate(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(req.userId).toBeUndefined();
      expect(writeHead).toHaveBeenCalledWith(401, expect.anything());
    } finally {
      process.env.JWT_SECRET = "test-only-secret-change-me-32chars";
    }
  });

  it("authenticate() calls next() for an access token", () => {
    process.env.JWT_SECRET = SECRET;
    try {
      const req = {
        headers: { authorization: `Bearer ${generateToken("user-1", SECRET)}` },
      } as unknown as AuthenticatedRequest;

      const writeHead = jest.fn();
      const res = { writeHead, end: jest.fn() } as unknown as ServerResponse;
      const next = jest.fn();

      authenticate(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      expect(req.userId).toBe("user-1");
      expect(writeHead).not.toHaveBeenCalled();
    } finally {
      process.env.JWT_SECRET = "test-only-secret-change-me-32chars";
    }
  });
});
