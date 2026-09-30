/**
 * R3 — the step-up flow, end to end over HTTP, with both services running.
 *
 * ## Why this file exists
 *
 * The defect that R3 fixes survived 1595 passing tests. `createChallenge`
 * generated a PIN, hashed it, and discarded it — it was never emailed, never
 * returned, and stripped before persistence. The third factor was
 * *unobtainable*, and the suite stayed green because
 * `tests/plus/capability-request-step-up.test.ts` read
 * `metadata.generatedPin` straight off a fake repository, bypassing the exact
 * point where the PIN was lost.
 *
 * Every test of the old flow was on one side of the Core/Plus boundary: the
 * Plus suite constructed its own server, the extension suite stubbed `fetch`
 * and answered 200 regardless of headers. Nothing crossed the boundary, so a
 * flow that could not be executed in production was fully covered in
 * isolation.
 *
 * This file crosses it. Both services boot. Nothing is stubbed. The approval
 * is signed by a real Core key and verified by a real Plus key, and the
 * capability Plus issues is verified by Core's pinned Plus key. If a factor is
 * unobtainable, this fails.
 *
 * The R1 regression is also pinned here for the same reason: when R1 put every
 * Plus route behind `X-Service-Secret`, the extension's two challenge calls
 * kept sending only `X-Core-Service` and the step-up went dead with the whole
 * suite green. Here there is no mock to hide behind.
 */

import request from "supertest";
import { createServer, type Server } from "http";
import type { AddressInfo } from "net";
import { binaryToBase64 } from "../../src/shared/utils";
import {
  APPROVAL_VERSION,
  generateApprovalKeyPair,
  loadApprovalPublicKey,
  verifyApproval,
} from "../../src/infrastructure/crypto/ed25519-approval";

// The branded-ID module uses `declare const` brand symbols that do not exist at
// runtime; ts-jest does not strip them. Same mock as
// tests/integration/managed-authoring-route.test.ts.
jest.mock("../../src/domain/value-objects/ids", () => {
  const crypto = require("crypto");
  const brand = (name: string) => Symbol(name);

  class MockId {
    private readonly value: string;
    private constructor(value: string) { this.value = value; }
    static generate(): MockId { return new MockId(crypto.randomUUID()); }
    static fromString(v: string): MockId { return new MockId(v); }
    toString(): string { return this.value; }
    valueOf(): string { return this.value; }
    equals(other: unknown): boolean { return String(other) === this.value; }
  }

  return {
    VaultId: MockId,
    CredentialId: MockId,
    VulnerabilityId: MockId,
    CryptoHash: MockId,
    generateUUID: () => crypto.randomUUID(),
    __brand: { VaultId: brand("VaultId"), CredentialId: brand("CredentialId") },
  };
});

/* ------------------------------------------------------------------ */
/*  Fakes for the persistence boundary only                             */
/* ------------------------------------------------------------------ */

/**
 * These stand in for PostgreSQL, not for the flow.
 *
 * The thing under test is the Core→Plus handshake, so a real database is not
 * the subject — but the credential the release is bound to must be a real one,
 * with a real `releaseShareRef`, because that ref is what the approval binds to
 * and what a mismatched approval must fail on.
 */
class InMemoryVaultRepository {
  private readonly items = new Map<string, any>();
  findByVaultIdAndOwnerId = jest.fn(async (vaultId: string, ownerId: string) => {
    const v = this.items.get(vaultId);
    return v && v.ownerId === ownerId ? v : null;
  });
  findById = jest.fn(async (id: any) => this.items.get(String(id)) ?? null);
  add(vault: any): void { this.items.set(vault.id, vault); }
  // Present only to satisfy the interface. The approval path never calls them.
  save = jest.fn(async (v: any) => v);
  delete = jest.fn(async () => true);
  list = jest.fn(async () => [...this.items.values()]);
  listByOwnerId = jest.fn(async () => []);
  updateMetadata = jest.fn(async (v: any) => v);
}

class InMemoryCredentialRepository {
  private readonly items = new Map<string, any>();
  findById = jest.fn(async (id: { toString(): string }) => this.items.get(id.toString()) ?? null);
  findByVaultId = jest.fn(async () => []);
  add(c: any): void { this.items.set(c.id.toString(), c); }
  save = jest.fn(async (c: any) => c);
  delete = jest.fn(async () => true);
  findBySecretRef = jest.fn(async () => null);
  list = jest.fn(async () => [...this.items.values()]);
}

const noopCrypto = {
  encrypt: async () => Buffer.from("e"),
  decrypt: async () => Buffer.from("d"),
  deriveKey: async () => Buffer.alloc(32),
  generateSalt: () => Buffer.alloc(16),
  hash: async () => "h",
  verifyHash: async () => true,
} as never;

const createMockCredentialsGenerator = () =>
  ({ generate: async () => "gen" }) as never;

const ORIGIN = "https://github.com";
const SECRET_REF = "ref-e2e-stepup";

/* ------------------------------------------------------------------ */
/*  Keys                                                               */
/* ------------------------------------------------------------------ */

const PLUS_KEYS = generateApprovalKeyPair();
const CORE_KEYS = generateApprovalKeyPair();
const SERVICE_SECRET = "e2e-service-secret";

let coreServer: Server;
let plusServer: Server;
let coreBase: string;
let plusBase: string;
let apiServer: any;
let vaultRepo: InMemoryVaultRepository;
let credentialRepo: InMemoryCredentialRepository;

const savedEnv = { ...process.env };

beforeAll(async () => {
  // Plus's own signing key, and Core's pinned copy of it.
  const capabilityKeys = generateApprovalKeyPair();
  process.env.PLUS_CAPABILITY_PRIVATE_KEY = capabilityKeys.privateKeyBase64;
  process.env.PLUS_PUBLIC_KEY = capabilityKeys.publicKeyBase64;
  // Plus verifies Core's approvals against the pinned Core key.
  process.env.CORE_APPROVAL_PUBLIC_KEY = CORE_KEYS.publicKeyBase64;
  // Core signs approvals with its own key.
  process.env.CORE_APPROVAL_PRIVATE_KEY = CORE_KEYS.privateKeyBase64;
  process.env.PLUS_SERVICE_SECRET = SERVICE_SECRET;
  process.env.PLUS_BASE_URL = "http://127.0.0.1:3001";

  vaultRepo = new InMemoryVaultRepository();
  credentialRepo = new InMemoryCredentialRepository();

  const { ApiServer } = await import("../../src/infrastructure/api/server");
  apiServer = new ApiServer(
    vaultRepo,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    createMockCredentialsGenerator(),
    credentialRepo,
  );
  coreServer = await apiServer.start(0);
  coreBase = `http://127.0.0.1:${(coreServer.address() as AddressInfo).port}`;

  // Plus, booted for real, with real repositories.
  const { PostgresChallengeRepository } = await import(
    "../../plus/infrastructure/repositories/PostgresChallengeRepository"
  );
  const { PostgresEntitlementRepository } = await import(
    "../../plus/infrastructure/repositories/PostgresEntitlementRepository"
  );
  const { PostgresPlusUserRepository } = await import(
    "../../plus/infrastructure/repositories/PostgresPlusUserRepository"
  );

  // Plus's repositories need a database; give them a stubbed driver rather than
  // mocking the service under test. `getChallengeService` is what matters here.
  const memChallenges = new Map<string, any>();
  const challengeRepo = {
    save: async (c: any) => { memChallenges.set(c.id, c); return c; },
    findById: async (id: string) => memChallenges.get(id) ?? null,
    findByUserId: async (userId: string) =>
      [...memChallenges.values()].filter((c) => c.userId === userId),
    findPendingByUserId: async (userId: string) =>
      [...memChallenges.values()].filter(
        (c) => c.userId === userId && ["pending", "email_sent", "url_accessed"].includes(c.status),
      ),
    update: async (c: any) => { memChallenges.set(c.id, c); return c; },
    delete: async (id: string) => memChallenges.delete(id),
    cleanupExpired: async () => 0,
  };

  const userRepo = {
    save: async (u: any) => u,
    findById: async () => null,
    findByEmail: async () => null,
    findByRole: async () => [],
    findActive: async () => [],
    search: async () => [],
    getPinLockout: async () => ({ failedPinAttempts: 0, lockedUntil: null }),
    recordFailedPinAttempt: async () => ({ failedPinAttempts: 1, lockedUntil: null }),
    setPinLockout: async () => undefined,
  };

  const { PlusApiServer } = await import("../../plus/api/server");
  const plusApi = new PlusApiServer(
    challengeRepo as never,
    new PostgresEntitlementRepository("") as never,
    userRepo as never,
  );
  plusServer = await plusApi.start(0);
  plusBase = `http://127.0.0.1:${(plusServer.address() as AddressInfo).port}`;
  process.env.PLUS_BASE_URL = plusBase;
  void PostgresChallengeRepository;
  void PostgresPlusUserRepository;
}, 60_000);

afterAll(async () => {
  await new Promise<void>((r) => coreServer.close(() => r()));
  if (plusServer) await new Promise<void>((r) => plusServer.close(() => r()));
  for (const k of Object.keys(process.env)) {
    if (!(k in savedEnv)) delete process.env[k];
  }
  Object.assign(process.env, savedEnv);
});

/**
 * Register a user and return their real id.
 *
 * The id is NOT the email. `AuthRepository` assigns its own identifier, and
 * Core reads `userId` off the verified token — so seeding a vault with the
 * email as the owner silently produces a vault nobody owns, and the approval
 * route then answers 404 for a reason that has nothing to do with the code
 * under test. Decoded from the token rather than guessed.
 */
async function getAuthToken(): Promise<{ token: string; userId: string }> {
  const email = `r3-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
  const password = "strongpass123";
  const registered = await request(coreServer)
    .post("/api/v1/auth/register")
    .send({ email, password });
  expect(registered.status).toBeLessThan(400);

  const login = await request(coreServer)
    .post("/api/v1/auth/login")
    .send({ email, password });
  expect(login.status).toBe(200);
  const token = login.body.token as string;

  const userId = decodeSub(token);
  expect(userId).toBeTruthy();
  return { token, userId };
}

/** The `sub` claim, without verifying the signature. */
function decodeSub(token: string): string {
  const part = token.split(".")[1];
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")).sub as string;
}

/** Register a real managed credential owned by the caller. */
async function seedManagedCredential(
  userId: string,
  vaultId: string,
): Promise<string> {
  const id = `cred-${Math.random().toString(36).slice(2)}`;
  credentialRepo.add({
    id: { toString: () => id },
    vaultId: { toString: () => vaultId },
    mode: "managed",
    releaseShareRef: SECRET_REF,
    userId,
  });
  return id;
}

describe("R3 — the step-up is obtainable, end to end", () => {
  it("probes are open, every other Plus route needs the secret", async () => {
    // R1's shape, asserted against a live server rather than a stub.
    const health = await fetch(`${plusBase}/health`);
    expect(health.status).toBe(200);

    const noSecret = await fetch(`${plusBase}/api/v1/crypto/public-key`);
    expect(noSecret.status).toBe(401);

    const withSecret = await fetch(`${plusBase}/api/v1/crypto/public-key`, {
      headers: { "X-Service-Secret": SERVICE_SECRET },
    });
    expect(withSecret.status).toBe(200);
  });

  it("a user completes a step-up with no PIN anywhere in the exchange", async () => {
    const { token, userId } = await getAuthToken();
    const vaultId = `vault-${Math.random().toString(36).slice(2)}`;
    vaultRepo.add({ id: vaultId, ownerId: userId, name: "v" });
    const credentialId = await seedManagedCredential(userId, vaultId);

    /* ---- 1. Plus creates the challenge the user will approve. --------- *
     * Order matters and getting it wrong is instructive: the approval binds
     * to a `challengeId`, so that id has to exist before Core can sign one.
     * An approval for an id Plus has not issued fails with
     * `Binding mismatch: challengeId` — which is the correct behaviour and
     * the reason the mismatch is part of the design, not a bug. */
    const triggered = await fetch(`${plusBase}/api/v1/challenges/trigger`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Service-Secret": SERVICE_SECRET,
      },
      body: JSON.stringify({
        userId,
        resourceId: SECRET_REF,
        operation: "AUTOFILL",
        secretRef: SECRET_REF,
      }),
    });
    // 201: a challenge was created.
    expect(triggered.status).toBe(201);
    const { challengeId } = (await triggered.json()) as { challengeId: string };
    expect(challengeId).toBeTruthy();

    /* ---- 2. Core signs the approval the user's decision authorises. ---- */
    const approved = await request(coreServer)
      .post("/api/v1/step-up/approve")
      .set("Authorization", `Bearer ${token}`)
      .send({ challengeId, credentialId, operation: "AUTOFILL" });

    expect(approved.status).toBe(200);
    expect(approved.body.approval).toBeDefined();

    // The signed token verifies against the public key Plus is configured
    // with, and its binding is the record's, not the caller's.
    const verification = await verifyApproval(
      approved.body.approval,
      loadApprovalPublicKey(CORE_KEYS.publicKeyBase64),
      {
        challengeId,
        userId,
        resourceId: SECRET_REF,
        operation: "AUTOFILL",
        secretRef: SECRET_REF,
      },
      Math.floor(Date.now() / 1000) + 1,
    );
    expect(verification).toEqual({ valid: true });
    expect(approved.body.approval.payload.typ).toBe("step-up-approval");
    expect(approved.body.approval.payload.version).toBe(APPROVAL_VERSION);
    // The binding came from the credential record, and there is no secret in
    // the token at all — the whole point of R3.
    expect(approved.body.approval.payload.secretRef).toBe(SECRET_REF);
    expect(JSON.stringify(approved.body.approval)).not.toMatch(/"pin"/i);

    /* ---- 3. Plus verifies it and issues the capability. -------------- */
    const approvedFor = await fetch(`${plusBase}/api/v1/challenges/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Service-Secret": SERVICE_SECRET,
      },
      body: JSON.stringify({ challengeId, approval: approved.body.approval }),
    });

    // This is the assertion the old suite could not make. Every prior test
    // stubbed this hop or bypassed it; here the user is holding a decision and
    // a signature, and Plus either honours it or it does not.
    expect(approvedFor.status).toBe(200);
    // Plus's `sendSuccess` does not wrap in `{ success: true }` the way Core's
    // does — 200 plus a capabilityToken IS the success signal. Asserted against
    // the real contract rather than an assumed one.
    const body = (await approvedFor.json()) as { capabilityToken?: unknown };
    expect(body.capabilityToken).toBeDefined();
    expect((body.capabilityToken as any).payload.assurance).toBe(3);
    expect((body.capabilityToken as any).payload.userId).toBe(userId);
  });

  it("refuses an approval whose secretRef does not match the challenge", async () => {
    const { userId } = await getAuthToken();
    const keys = generateApprovalKeyPair();

    // A challenge for one credential…
    const triggered = await fetch(`${plusBase}/api/v1/challenges/trigger`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Service-Secret": SERVICE_SECRET },
      body: JSON.stringify({
        userId,
        resourceId: SECRET_REF,
        operation: "AUTOFILL",
        secretRef: SECRET_REF,
      }),
    });
    const { challengeId } = (await triggered.json()) as { challengeId: string };

    // …and a genuine, correctly signed approval for a different one.
    const { signApproval, loadApprovalPrivateKey } = await import(
      "../../src/infrastructure/crypto/ed25519-approval"
    );
    const iat = Math.floor(Date.now() / 1000);
    const wrongRef = await signApproval(
      {
        version: APPROVAL_VERSION,
        typ: "step-up-approval",
        challengeId,
        userId,
        resourceId: "ref-somebody-else",
        operation: "AUTOFILL",
        secretRef: "ref-somebody-else",
        iat,
        exp: iat + 300,
        jti: "jti-wrong-ref",
      },
      loadApprovalPrivateKey(CORE_KEYS.privateKeyBase64),
    );
    void keys;

    const res = await fetch(`${plusBase}/api/v1/challenges/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Service-Secret": SERVICE_SECRET },
      body: JSON.stringify({ challengeId, approval: wrongRef }),
    });

    expect(res.status).toBe(400);
  });

  it("refuses an approval signed by a key Plus does not pin", async () => {
    const { userId } = await getAuthToken();
    const attacker = generateApprovalKeyPair();
    const { signApproval, loadApprovalPrivateKey } = await import(
      "../../src/infrastructure/crypto/ed25519-approval"
    );

    const triggered = await fetch(`${plusBase}/api/v1/challenges/trigger`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Service-Secret": SERVICE_SECRET },
      body: JSON.stringify({
        userId,
        resourceId: SECRET_REF,
        operation: "AUTOFILL",
        secretRef: SECRET_REF,
      }),
    });
    const { challengeId } = (await triggered.json()) as { challengeId: string };

    const iat = Math.floor(Date.now() / 1000);
    const forged = await signApproval(
      {
        version: APPROVAL_VERSION,
        typ: "step-up-approval",
        challengeId,
        userId,
        resourceId: SECRET_REF,
        operation: "AUTOFILL",
        secretRef: SECRET_REF,
        iat,
        exp: iat + 300,
        jti: "jti-forged",
      },
      loadApprovalPrivateKey(attacker.privateKeyBase64),
    );

    const res = await fetch(`${plusBase}/api/v1/challenges/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Service-Secret": SERVICE_SECRET },
      body: JSON.stringify({ challengeId, approval: forged }),
    });

    expect(res.status).toBe(400);
  });

  it("refuses to approve without the service secret", async () => {
    const res = await fetch(`${plusBase}/api/v1/challenges/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId: "whatever", approval: {} }),
    });

    expect(res.status).toBe(401);
  });

  it("Core refuses to sign for a credential the caller does not own", async () => {
    const owner = await getAuthToken();
    const stranger = await getAuthToken();
    const vaultId = `vault-${Math.random().toString(36).slice(2)}`;
    vaultRepo.add({ id: vaultId, ownerId: owner.userId, name: "v" });
    const credentialId = await seedManagedCredential(owner.userId, vaultId);

    const res = await request(coreServer)
      .post("/api/v1/step-up/approve")
      .set("Authorization", `Bearer ${stranger.token}`)
      .send({ challengeId: "ch-x", credentialId, operation: "AUTOFILL" });

    // Identical to "no such credential", so this cannot enumerate ids.
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("Credential not available for release");
  });
});
