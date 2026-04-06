/**
 * Tests unitarios para ApiServer
 * Enfoque: pruebas de integración ligeras con mocks de servicios pesados
 * Se usa fetch (Node 18+) en lugar de supertest para evitar dependencias ESM.
 */

// Mock de CryptoService (evita ESM de @noble/hashes)
jest.mock("@/infrastructure/crypto/crypto-service", () => ({
  CryptoService: class {
    // métodos no utilizados en los handlers
  },
}));

// Mock de CredentialsGenerator
jest.mock("@/domain/services/autocompletado/credentials-generator", () => {
  return {
    CredentialsGenerator: class {
      constructor(_cryptoService: any) {}

      async generateCredentials(domain: string) {
        return {
          email: `user+salt123@${domain}`,
          password: `pass+pepper456`,
          originalEmail: `user@${domain}`,
          originalPassword: "pass123",
          salt: "salt123",
          pepper: "pepper456",
        };
      }

      async extractOriginalCredentialsStrong(
        storedEmail: any,
        storedPassword: any,
      ) {
        const email = storedEmail.toString();
        const pass = storedPassword.toString();
        const emailMatch = email.match(/^([^+]+)\+[^@]+@(.+)$/);
        const passMatch = pass.match(/^([^+]+)\+[^+]+$/);
        if (!emailMatch || !passMatch) {
          throw new Error("Invalid format");
        }
        return {
          email: `${emailMatch[1]}@${emailMatch[2]}`,
          password: passMatch[1],
        };
      }

      analyzeCredentialsQuality(_credentials: any) {
        return {
          isValid: true,
          entropyAnalysis: { salt: 128, pepper: 128, passwordBase: 60 },
          randomnessAnalysis: { salt: {}, pepper: {} },
          warnings: [],
        };
      }

      isValidEmailWithSalt(email: string) {
        return /^[^+]+\+[^@]+@[^@]+$/.test(email);
      }

      isValidPasswordWithPepper(password: string) {
        return /^[^+]+\+[^+]+$/.test(password);
      }
    },
  };
});

import { ApiServer } from "@/infrastructure/api/server";
import { _clearRateLimitForTests } from "@/infrastructure/api/server";
import { InMemoryVaultRepository } from "../infrastructure/repositories/in-memory-vault-repository";
import { EncryptionService } from "@/infrastructure/crypto/EncryptionService";
import { HashingService } from "@/infrastructure/crypto/HashingService";
import { SignatureService } from "@/infrastructure/crypto/signature-service";
import { KeyManagementService } from "@/infrastructure/crypto/KeyManagementService";
import { CredentialsGenerator } from "@/domain/services/autocompletado/credentials-generator";
import jwt from "jsonwebtoken";
import { Server } from "http";

let server: Server;
let apiServer: ApiServer;
let vaultRepo: InMemoryVaultRepository;
let port: number;

/**
 * Genera un token JWT válido para pruebas
 */
function generateTestToken(userId: string = "test-user"): string {
  return jwt.sign({ sub: userId }, "test-secret");
}

async function fetchJSON(
  input: RequestInfo,
  init?: RequestInit,
): Promise<{ status: number; body: any }> {
  const res = await fetch(input, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

describe("ApiServer", () => {
  beforeAll(async () => {
    vaultRepo = new InMemoryVaultRepository();

    // Mocks de servicios de criptografía
    const mockEncryption = { encrypt: jest.fn(), decrypt: jest.fn() };
    const mockHashing = { hash: jest.fn() };
    const mockSignature = { sign: jest.fn(), verify: jest.fn() };
    const mockKeyMgmt = { generateKeyPair: jest.fn() };

    const generator = new CredentialsGenerator();

    server = await startServer(
      0,
      vaultRepo,
      mockEncryption as any,
      mockHashing as any,
      mockSignature as any,
      mockKeyMgmt as any,
      generator,
    );
    port = (server.address() as any).port;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  beforeEach(() => {
    vaultRepo.clear();
    _clearRateLimitForTests();
  });

  describe("Health Checks", () => {
    test("GET /health devuelve 200 con status healthy", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/health`,
      );
      expect(status).toBe(200);
      expect(body).toHaveProperty("status", "healthy");
      expect(body).toHaveProperty("service", "cyber-vault-api");
      expect(body).toHaveProperty("timestamp");
    });

    test("GET /ready devuelve 200 con status ready", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/ready`,
      );
      expect(status).toBe(200);
      expect(body).toHaveProperty("status", "ready");
      expect(body).toHaveProperty("timestamp");
    });
  });

  describe("Autenticación JWT", () => {
    const vaultPayload = {
      name: "Test Vault",
      encryptionKeyId: "key-123",
    };

    test("POST /api/v1/vaults sin Authorization header retorna 401", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        { method: "POST", body: JSON.stringify(vaultPayload) },
      );
      expect(status).toBe(401);
      expect(body).toHaveProperty("error", "No token provided");
    });

    test("POST /api/v1/vaults con token inválido retorna 401", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: "Bearer invalid-token" },
          body: JSON.stringify(vaultPayload),
        },
      );
      expect(status).toBe(401);
      expect(body).toHaveProperty("error", "Invalid token");
    });

    test("POST /api/v1/vaults con token válido retorna 201", async () => {
      const token = generateTestToken();
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: JSON.stringify(vaultPayload),
        },
      );
      expect(status).toBe(201);
      expect(body).toHaveProperty("id");
      expect(body).toHaveProperty("name", vaultPayload.name);
      expect(body).toHaveProperty(
        "encryptionKeyId",
        vaultPayload.encryptionKeyId,
      );
    });
  });

  describe("Rate Limiting", () => {
    const validToken = generateTestToken();
    const vaultPayload = {
      name: "RateLimitTest",
      encryptionKeyId: "key-ratelimit",
    };

    test("permite 100 requests exitosos", async () => {
      for (let i = 0; i < 100; i++) {
        const { status } = await fetchJSON(
          `http://localhost:${port}/api/v1/vaults`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${validToken}` },
            body: JSON.stringify(vaultPayload),
          },
        );
        expect(status).toBe(201);
      }
    });

    test("deniega el request 101 con 429", async () => {
      for (let i = 0; i < 100; i++) {
        await fetchJSON(`http://localhost:${port}/api/v1/vaults`, {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(vaultPayload),
        });
      }

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(vaultPayload),
        },
      );
      expect(status).toBe(429);
      expect(body).toHaveProperty("error", "Rate limit exceeded");
    });
  });

  describe("Endpoint POST /api/v1/vaults", () => {
    const validToken = generateTestToken();

    test("crea vault con datos válidos", async () => {
      const payload = {
        name: "My Vault",
        description: "Description test",
        encryptionKeyId: "key-456",
      };

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(201);
      expect(body).toHaveProperty("id");
      expect(body.name).toBe(payload.name);
      expect(body.description).toBe(payload.description);
      expect(body.encryptionKeyId).toBe(payload.encryptionKeyId);
      expect(body).toHaveProperty("createdAt");
      expect(body).toHaveProperty("updatedAt");
    });

    test("falla si falta name", async () => {
      const payload = { encryptionKeyId: "key-456" };

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(400);
      expect(body.error).toContain("Name and encryptionKeyId are required");
    });

    test("falla si falta encryptionKeyId", async () => {
      const payload = { name: "My Vault" };

      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(400);
    });

    test("permite múltiples vaults con el mismo nombre", async () => {
      const payload = {
        name: "Duplicate Name",
        encryptionKeyId: "key-1",
      };

      await fetchJSON(`http://localhost:${port}/api/v1/vaults`, {
        method: "POST",
        headers: { Authorization: `Bearer ${validToken}` },
        body: JSON.stringify(payload),
      });

      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(201);
    });
  });

  describe("Endpoint POST /api/v1/credentials/generate", () => {
    const validToken = generateTestToken();

    test("genera credenciales para dominio válido", async () => {
      const payload = { domain: "example.com" };

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/generate`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(201);
      expect(body).toHaveProperty("email");
      expect(body).toHaveProperty("password");
      expect(body).toHaveProperty("originalEmail");
      expect(body).toHaveProperty("originalPassword");
      expect(body).toHaveProperty("domain", "example.com");
      expect(body).toHaveProperty("quality");
      expect(body.quality).toHaveProperty("isValid");
      expect(body.quality).toHaveProperty("entropy");
      expect(body.quality).toHaveProperty("warnings");
      expect(body).toHaveProperty("timestamp");
    });

    test("rechaza dominio inválido", async () => {
      const payload = { domain: "dominio inválido" };

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/generate`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(400);
      expect(body.error).toContain("Invalid domain");
    });

    test("rechaza si falta domain", async () => {
      const payload = {};

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/generate`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify(payload),
        },
      );
      expect(status).toBe(400);
      expect(body.error).toBe("Domain is required");
    });
  });

  describe("Endpoint POST /api/v1/credentials/extract", () => {
    const validToken = generateTestToken();

    test("extrae credenciales originales desde stored format", async () => {
      const storedEmail = "user+abcd1234@example.com";
      const storedPassword = "pass+efgh5678";

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/extract`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({
            email: storedEmail,
            password: storedPassword,
          }),
        },
      );
      expect(status).toBe(200);
      expect(body).toHaveProperty("email", "user@example.com");
      expect(body).toHaveProperty("password", "pass");
      expect(body).toHaveProperty("timestamp");
    });

    test("falla si email o password faltantes", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/extract`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({ email: "user+salt@example.com" }),
        },
      );
      expect(status).toBe(400);
      expect(body.error).toBe("Email and password are required");
    });

    test("falla con email en formato incorrecto", async () => {
      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/extract`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({
            email: "invalid-email",
            password: "pass+pepper",
          }),
        },
      );
      expect(status).toBe(400);
    });

    test("falla con password en formato incorrecto", async () => {
      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/extract`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({
            email: "user+salt@example.com",
            password: "invalidpass",
          }),
        },
      );
      expect(status).toBe(400);
    });
  });

  describe("Endpoint GET /api/v1/credentials/validate (Público)", () => {
    test("valida email y password simultáneamente", async () => {
      const email = "user+1234@example.com";
      const password = "pass+5678";

      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/validate?email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`,
      );
      expect(status).toBe(200);
      expect(body.email).toHaveProperty("isValid", true);
      expect(body.email).toHaveProperty("hasSalt", true);
      expect(body.password).toHaveProperty("isValid", true);
      expect(body.password).toHaveProperty("hasPepper", true);
    });

    test("valida solo email", async () => {
      const email = "user+1234@example.com";
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/validate?email=${encodeURIComponent(email)}`,
      );
      expect(status).toBe(200);
      expect(body.email).toHaveProperty("isValid", true);
      expect(body.password).toBeUndefined();
    });

    test("valida solo password", async () => {
      const password = "pass+5678";
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/validate?password=${encodeURIComponent(password)}`,
      );
      expect(status).toBe(200);
      expect(body.password).toHaveProperty("isValid", true);
      expect(body.email).toBeUndefined();
    });

    test("retorna 400 si no se proporcionan parámetros", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/validate`,
      );
      expect(status).toBe(400);
      expect(body.error).toBe("Email or password parameter required");
    });

    test("rechaza email sin formato de sal", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/credentials/validate?email=userexample.com`,
      );
      expect(status).toBe(200);
      expect(body.email.isValid).toBe(false);
    });
  });

  describe("Métodos no permitidos", () => {
    const validToken = generateTestToken();

    test("POST /health retorna 405", async () => {
      const { status } = await fetchJSON(`http://localhost:${port}/health`, {
        method: "POST",
        headers: { Authorization: `Bearer ${validToken}` },
        body: JSON.stringify({}),
      });
      expect(status).toBe(405);
    });

    test("GET /api/v1/vaults retorna 405", async () => {
      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "GET",
          headers: { Authorization: `Bearer ${validToken}` },
        },
      );
      expect(status).toBe(405);
    });
  });

  describe("Endpoints no existentes", () => {
    const validToken = generateTestToken();

    test("ruta desconocida retorna 404", async () => {
      const { status, body } = await fetchJSON(
        `http://localhost:${port}/api/v1/unknown`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({}),
        },
      );
      expect(status).toBe(404);
      expect(body).toHaveProperty("error", "Not found");
    });
  });

  describe("Manejo de errores", () => {
    let validToken: string;

    beforeEach(() => {
      validToken = generateTestToken();
    });

    test("POST /api/v1/vaults cuando repositorio falla retorna 400", async () => {
      const spy = jest
        .spyOn(vaultRepo, "save")
        .mockRejectedValue(new Error("Database failure"));

      const { status } = await fetchJSON(
        `http://localhost:${port}/api/v1/vaults`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${validToken}` },
          body: JSON.stringify({
            name: "FailVault",
            encryptionKeyId: "key-err",
          }),
        },
      );
      expect(status).toBe(400);

      spy.mockRestore();
    });

    test("protected endpoint retorna 500 cuando JWT_SECRET no está configurado", async () => {
      const originalSecret = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;
      jest.resetModules();

      try {
        const { ApiServer: ApiServerNoSecret } =
          await import("@/infrastructure/api/server");
        const { EncryptionService } =
          await import("@/infrastructure/crypto/EncryptionService");
        const { HashingService } =
          await import("@/infrastructure/crypto/HashingService");
        const { SignatureService } =
          await import("@/infrastructure/crypto/signature-service");
        const { KeyManagementService } =
          await import("@/infrastructure/crypto/KeyManagementService");
        const { CredentialsGenerator } =
          await import("@/domain/services/autocompletado/credentials-generator");

        const repo = new InMemoryVaultRepository();
        const encryptionService = new EncryptionService();
        const hashingService = new HashingService();
        const signatureService = new SignatureService();
        const keyManagementService = new KeyManagementService();
        const generator = new CredentialsGenerator();
        const apiServer2 = new ApiServerNoSecret(
          repo,
          encryptionService,
          hashingService,
          signatureService,
          keyManagementService,
          generator,
        );
        const server2 = await apiServer2.start(0);
        const port2 = (server2.address() as any).port;

        try {
          const { status, body } = await fetchJSON(
            `http://localhost:${port2}/api/v1/vaults`,
            {
              method: "GET",
              headers: { Authorization: `Bearer ${generateTestToken()}` },
            },
          );
          expect(status).toBe(500);
          expect(body).toHaveProperty("error", "JWT_SECRET not configured");
        } finally {
          await server2.close();
        }
      } finally {
        if (originalSecret) process.env.JWT_SECRET = originalSecret;
        jest.resetModules();
      }
    });
  });
});
