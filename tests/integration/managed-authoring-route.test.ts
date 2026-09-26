/**
 * O5.9 — Managed authoring over HTTP (`POST /api/v1/vaults/{id}/managed-credentials`).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `ManagedAuthoringUseCase` (O5.8) was fully implemented and tested but nothing
 * in the running server called it — dead code in production. This suite drives
 * it through the real HTTP gateway, the same way `api-server.test.ts` builds
 * the server, and pins the two properties that only show up end to end:
 *
 * 1. THE OPAQUE DOMAIN INDEX. `src/domain/services/autofill/domain-index.ts`
 *    exists so the backend never learns which origins a user has credentials
 *    for — that list is a map of their infrastructure. The use case returns
 *    `record.origin` for ExactMatch binding, so the ROUTE is the place where
 *    the origin could leak into the database. Every assertion about "no
 *    origin" here reads the PERSISTED ROW from the credential repository (and
 *    the wrapped-share store), never just the HTTP response.
 *
 * 2. ONE RELEASE SHARE STORE. The share written by the authoring route must be
 *    readable by the ALREADY-MOUNTED `/managed-release` route for the same
 *    `secretRef`; both are wired to the same `InMemoryReleaseShareStore`
 *    instance and the same `RELEASE_SHARE_KEK_SECRET`. The final test then
 *    completes the whole path over HTTP only: author → release → decrypt on
 *    the "client" side with VEK + released share.
 *
 * The VEK never comes from Core: the server has no VEK of its own, so the
 * caller supplies the session VEK in the body and a missing one fails closed
 * with the use case's `VEK_MISSING` (never a generated or derived key).
 */

import request from "supertest";

// Mock the branded ID module — VaultIdBrand is a `declare const` that only
// exists at compile-time; ts-jest doesn't strip it, so we replace the module
// with a runtime-safe version before importing anything that touches it.
// Same block as tests/integration/api-server.test.ts.
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

  return { VaultId: MockVaultId, CredentialId: MockCredentialId };
});

import { ApiServer, _clearRateLimitForTests } from "../../src/infrastructure/api/server";
import type { IVaultRepository, ICredentialRepository } from "../../src/domain/repositories";
import type { VaultId } from "../../src/domain/value-objects/ids";
import { deriveManagedEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import {
  generateEd25519KeyPair,
  createCapabilityPayload,
  signCapability,
} from "../../src/infrastructure/crypto/ed25519-capability";
import type { Ed25519KeyPair } from "../../src/infrastructure/crypto/ed25519-capability";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const USERNAME = "alice@example.com";
const PASSWORD = "correct-horse-battery-staple-9!";
const TOTP_SEED = "JBSWY3DPEHPK3PXP";
/** Raw user input; the canonical form returned to the client is `https://github.com:443`. */
const ORIGIN_INPUT = "https://github.com";
const ORIGIN_CANONICAL = "https://github.com:443";
const TITLE = "GitHub (corp)";

const VEK_B64 = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));
const RELEASE_SHARE_KEK_SECRET_B64 = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));

const keyPair: Ed25519KeyPair = generateEd25519KeyPair();

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Client-side AES-GCM open — the exact `salt(32) | iv(12) | ciphertext+tag`
 * layout implemented by `src/ui/content-scripts/managed-decrypt.ts`.
 */
async function decryptAESGCM(
  ciphertextBase64: string,
  keyBase64: string,
): Promise<string | null> {
  try {
    const combined = base64ToBinary(ciphertextBase64);
    const saltLength = 32;
    const ivLength = 12;
    const iv = combined.slice(saltLength, saltLength + ivLength);
    const ciphertextWithTag = combined.slice(saltLength + ivLength);
    const key = base64ToBinary(keyBase64);
    const cryptoKey = await crypto.subtle.importKey("raw", toArrayBuffer(key), "AES-GCM", false, [
      "decrypt",
    ]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
      cryptoKey,
      toArrayBuffer(ciphertextWithTag),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Mock repositories — the credential repo keeps every row it is handed so the  */
/* tests can assert against what was ACTUALLY persisted, not against a response */
/* -------------------------------------------------------------------------- */

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
    return Array.from(this.vaults.values()).filter((v) => v.ownerId === ownerId);
  }

  async updateMetadata(vaultId: string, metadata: Record<string, unknown>): Promise<void> {
    const vault = this.vaults.get(vaultId);
    if (vault) {
      vault.metadata = { ...vault.metadata, ...metadata };
    }
  }
}

class MockCredentialRepository implements ICredentialRepository {
  private rows = new Map<string, any>();

  async save(credential: any): Promise<any> {
    this.rows.set(credential.id.toString(), credential);
    return credential;
  }

  async findById(id: any): Promise<any | null> {
    return this.rows.get(id.toString()) ?? null;
  }

  async findByVaultId(vaultId: any): Promise<any[]> {
    return Array.from(this.rows.values()).filter(
      (c) => c.vaultId.toString() === vaultId.toString(),
    );
  }

  async findBySecretRef(secretRef: string): Promise<any | null> {
    return (
      Array.from(this.rows.values()).find((c) => c.releaseShareRef === secretRef) ?? null
    );
  }

  async delete(id: any): Promise<boolean> {
    return this.rows.delete(id.toString());
  }

  async list(): Promise<any[]> {
    return Array.from(this.rows.values());
  }

  /** What is actually stored — the assertion target for the origin invariant. */
  persistedRows(): any[] {
    return Array.from(this.rows.values());
  }
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
      randomnessAnalysis: { salt: { isValid: true, issues: [] as string[] }, pepper: { isValid: true, issues: [] as string[] }, passwordBase: { isValid: true, issues: [] as string[] } },
      warnings: [],
    }),
    isValidEmailWithSalt: jest.fn().mockReturnValue(true),
    isValidPasswordWithPepper: jest.fn().mockReturnValue(true),
  } as any;
}

/* -------------------------------------------------------------------------- */
/* Harness                                                                     */
/* -------------------------------------------------------------------------- */

interface Harness {
  app: any;
  server: any;
  credentialRepo: MockCredentialRepository;
}

/**
 * Builds the server exactly like tests/integration/api-server.test.ts does.
 * The Release Share KEK secret is read from the environment in the ApiServer
 * constructor, so it must be set (or deleted) BEFORE this call.
 */
async function startHarness(): Promise<Harness> {
  const vaultRepo = new MockVaultRepository();
  const credentialRepo = new MockCredentialRepository();
  const app = new ApiServer(
    vaultRepo,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    createMockCredentialsGenerator(),
    credentialRepo,
  );
  const server = await app.start(0);
  return { app, server, credentialRepo };
}

function closeHarness(harness: Harness): Promise<void> {
  return new Promise((resolve) => harness.server.close(() => resolve()));
}

/** Registers a user and returns a Bearer token (same helper shape as api-server.test.ts). */
async function getAuthToken(server: any): Promise<string> {
  const email = `auth-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
  const password = "strongpass123";

  await request(server).post("/api/v1/auth/register").send({ email, password });

  const loginRes = await request(server).post("/api/v1/auth/login").send({ email, password });
  expect(loginRes.status).toBe(200);
  return loginRes.body.token as string;
}

async function createVault(server: any, authToken: string): Promise<string> {
  const res = await request(server)
    .post("/api/v1/vaults")
    .set("Authorization", `Bearer ${authToken}`)
    .send({ name: "Managed Vault", description: "O5.9", encryptionKeyId: "key-001" });
  expect(res.status).toBe(201);
  return res.body.id as string;
}

function authorBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    origin: ORIGIN_INPUT,
    username: USERNAME,
    password: PASSWORD,
    title: TITLE,
    totpSeedBase32: TOTP_SEED,
    secretRef: crypto.randomUUID(),
    vek: VEK_B64,
    ...overrides,
  };
}

let harness: Harness;
let server: any;
let authToken: string;
let vaultId: string;

beforeEach(async () => {
  _clearRateLimitForTests();
  process.env.RELEASE_SHARE_KEK_SECRET = RELEASE_SHARE_KEK_SECRET_B64;
  harness = await startHarness();
  server = harness.server;
  authToken = await getAuthToken(server);
  vaultId = await createVault(server, authToken);
});

afterEach(async () => {
  if (harness) await closeHarness(harness);
  process.env.RELEASE_SHARE_KEK_SECRET = RELEASE_SHARE_KEK_SECRET_B64;
});

function post(body: Record<string, unknown>, target: Harness = harness, token = authToken, id = vaultId) {
  return request(target.server)
    .post(`/api/v1/vaults/${id}/managed-credentials`)
    .set("Authorization", `Bearer ${token}`)
    .send(body);
}

/** Authorize + release through the ALREADY-MOUNTED release route. */
async function releaseViaHttp(
  secretRef: string,
  target: Harness = harness,
  token = authToken,
  id = vaultId,
) {
  const payload = createCapabilityPayload({
    userId: "user-1",
    resourceId: secretRef,
    operation: "AUTOFILL",
    secretRef,
    deviceId: "device-1",
    assurance: 2,
  });
  const capabilityToken = await signCapability(payload, keyPair.privateKey);
  return request(target.server)
    .post(`/api/v1/vaults/${id}/managed-release`)
    .set("Authorization", `Bearer ${token}`)
    .send({ capabilityToken, plusPublicKey: keyPair.publicKeyBase64 });
}

/* -------------------------------------------------------------------------- */

describe("POST /api/v1/vaults/{vaultId}/managed-credentials (O5.9)", () => {
  it("authors a managed credential and returns the canonical origin for ExactMatch binding", async () => {
    const res = await post(authorBody());

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.record.mode).toBe("managed");
    expect(res.body.record.origin).toBe(ORIGIN_CANONICAL);
    expect(res.body.credentialId).toBe(res.body.record.id);
    expect(res.body.record.releaseShareRef).toEqual(expect.any(String));
    expect(res.body.lookupToken).toMatch(/^[0-9a-f]{64}$/);
    expect(res.body.index.byToken[res.body.lookupToken]).toContain(res.body.record.id);

    // The response carries ciphertext and opaque material only — no plaintext
    // credential and never the Release Share.
    const responseText = JSON.stringify(res.body);
    expect(responseText).not.toContain(PASSWORD);
    expect(responseText).not.toContain(USERNAME);
    expect(responseText).not.toContain(TOTP_SEED);
    expect(JSON.parse(responseText)).not.toHaveProperty("releaseShare");
  });

  it("persists no origin/url and no plaintext username, password or TOTP seed in the credential row", async () => {
    const res = await post(authorBody());
    expect(res.status).toBe(201);

    // Assert against the PERSISTED ROW, not the response.
    const rows = harness.credentialRepo.persistedRows();
    expect(rows).toHaveLength(1);
    const row = rows[0];
    const persisted = JSON.stringify(row.toPlainObject());

    expect(row.url).toBeUndefined();
    expect(persisted).not.toContain(ORIGIN_CANONICAL);
    expect(persisted).not.toContain(ORIGIN_INPUT);
    expect(persisted).not.toContain("github.com");
    expect(persisted).not.toContain(USERNAME);
    expect(persisted).not.toContain("alice");
    expect(persisted).not.toContain(PASSWORD);
    expect(persisted).not.toContain(TOTP_SEED);
    expect(persisted).not.toContain(binaryToBase64(base64ToBinary(VEK_B64).slice(0, 8)));

    // Username is the redacted hint; the secret lives only in ciphertext.
    expect(row.username).not.toBe(USERNAME);
    expect(row.username).toContain("*");
    expect(row.encryptedPassword).not.toContain(PASSWORD);
    expect(row.encryptedPassword).not.toContain(USERNAME);
    expect(row.mode).toBe("managed");
    expect(row.releaseShareRef).toBe(res.body.record.releaseShareRef);

    // The response is the ONLY place the origin appears: neither the wrapped
    // Release Share store nor the opaque index may carry it.
    const storeText = JSON.stringify((harness.app as any).releaseShareStore.snapshot());
    expect(storeText).not.toContain("github.com");
    expect(JSON.stringify(res.body.index)).not.toContain("github.com");
    expect(res.body.record.origin).toBe(ORIGIN_CANONICAL);
  });

  it("rejects a non-absolute origin with the rejection code the use case uses", async () => {
    const bare = await post(authorBody({ origin: "github.com" }));
    expect(bare.status).toBe(403);
    expect(bare.body.reason).toBe("ORIGIN_NOT_ABSOLUTE");
    expect(bare.body.error).toContain("absolute");

    const schemeless = await post(authorBody({ origin: "https//github.com" }));
    expect(schemeless.status).toBe(403);
    expect(schemeless.body.reason).toBe("ORIGIN_NOT_ABSOLUTE");

    const empty = await post(authorBody({ origin: "   " }));
    expect(empty.status).toBe(403);
    expect(empty.body.reason).toBe("ORIGIN_MISSING");

    expect(harness.credentialRepo.persistedRows()).toHaveLength(0);
    expect((harness.app as any).releaseShareStore.snapshot()).toHaveLength(0);
  });

  it("rejects a non-http(s) scheme with the rejection code the use case uses", async () => {
    const ftp = await post(authorBody({ origin: "ftp://example.com" }));
    expect(ftp.status).toBe(403);
    expect(ftp.body.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

    const js = await post(authorBody({ origin: "javascript://alert(1)" }));
    expect(js.status).toBe(403);
    expect(js.body.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

    const file = await post(authorBody({ origin: "file:///etc/passwd" }));
    expect(file.status).toBe(403);
    expect(file.body.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

    expect(harness.credentialRepo.persistedRows()).toHaveLength(0);
    expect((harness.app as any).releaseShareStore.snapshot()).toHaveLength(0);
  });

  it("refuses fail-closed when RELEASE_SHARE_KEK_SECRET is unset, naming the real blocker", async () => {
    delete process.env.RELEASE_SHARE_KEK_SECRET;
    const unconfigured = await startHarness();
    try {
      const token = await getAuthToken(unconfigured.server);
      const vault = await createVault(unconfigured.server, token);

      const res = await post(authorBody(), unconfigured, token, vault);

      expect(res.status).toBe(403);
      expect(res.body.reason).toBe("RELEASE_SHARE_KEK_INVALID");
      expect(res.body.error).toContain("RELEASE_SHARE_KEK_SECRET");
      // Fail CLOSED, not open: nothing was written anywhere.
      expect(unconfigured.credentialRepo.persistedRows()).toHaveLength(0);
      expect((unconfigured.app as any).releaseShareStore.snapshot()).toHaveLength(0);
    } finally {
      await closeHarness(unconfigured);
      process.env.RELEASE_SHARE_KEK_SECRET = RELEASE_SHARE_KEK_SECRET_B64;
    }
  });

  it("refuses a request without a VEK instead of generating or deriving one", async () => {
    const withoutVek = await post(authorBody({ vek: undefined }));
    expect(withoutVek.status).toBe(403);
    expect(withoutVek.body.reason).toBe("VEK_MISSING");

    const emptyVek = await post(authorBody({ vek: "" }));
    expect(emptyVek.status).toBe(403);
    expect(emptyVek.body.reason).toBe("VEK_MISSING");

    // A credential authored without the caller's VEK would be one the client
    // can never open (defect D1 in a new costume) — nothing may be persisted.
    expect(harness.credentialRepo.persistedRows()).toHaveLength(0);
    expect((harness.app as any).releaseShareStore.snapshot()).toHaveLength(0);
  });

  it("makes the saved share resolvable by the already-mounted release route for the same secretRef", async () => {
    const secretRef = crypto.randomUUID();
    const authored = await post(authorBody({ secretRef }));
    expect(authored.status).toBe(201);

    // Same ApiServer => same InMemoryReleaseShareStore instance and same KEK
    // secret; the release route must find both the row and the wrapped share.
    const release = await releaseViaHttp(secretRef);

    expect(release.status).toBe(200);
    expect(release.body.success).toBe(true);
    expect(release.body.releaseShare).toBeDefined();
    expect(release.body.releaseShare).not.toBe(secretRef);
    expect(release.body.credentialId).toBe(authored.body.credentialId);
  });

  it("round trips authoring → release → client decrypt over HTTP only", async () => {
    const secretRef = crypto.randomUUID();
    const authored = await post(authorBody({ secretRef }));
    expect(authored.status).toBe(201);

    const release = await releaseViaHttp(secretRef);
    expect(release.status).toBe(200);
    expect(release.body.success).toBe(true);

    // Client side: VEK + released share -> EntryKey -> original credentials.
    const releaseShare = base64ToBinary(release.body.releaseShare);
    expect(releaseShare.byteLength).toBe(32);

    const derived = await deriveManagedEntryKey(
      base64ToBinary(VEK_B64),
      releaseShare,
      base64ToBinary(authored.body.record.salt),
      authored.body.credentialId,
      authored.body.record.version,
    );

    const plaintext = await decryptAESGCM(
      authored.body.record.encryptedSecret,
      derived.keyBase64,
    );
    expect(plaintext).not.toBeNull();

    const envelope = JSON.parse(plaintext as string) as { u: string; p: string };
    expect(envelope.u).toBe(USERNAME);
    expect(envelope.p).toBe(PASSWORD);

    // Same key opens the TOTP envelope too.
    const totpPlaintext = await decryptAESGCM(
      authored.body.record.encryptedTotpSecret,
      derived.keyBase64,
    );
    expect(totpPlaintext).not.toBeNull();
  });

  it("requires authentication", async () => {
    const res = await request(server)
      .post(`/api/v1/vaults/${vaultId}/managed-credentials`)
      .send(authorBody());

    expect(res.status).toBe(401);
    expect(harness.credentialRepo.persistedRows()).toHaveLength(0);
  });
});
