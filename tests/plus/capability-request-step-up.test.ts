/**
 * WU-4 — the step-up / third-factor flow, end to end over real HTTP.
 *
 * This suite starts the real `PlusApiServer` on an ephemeral port and talks to
 * it with plain `fetch`. Nothing on the Plus side is mocked: the entitlement
 * repository, the user repository, the challenge repository and the email
 * service are in-memory implementations of the real ports, but the route, the
 * adaptive risk engine, `ChallengeService`, `CapabilityIssuer` and the signing
 * key are the production ones. That is the point — the defect was in the route,
 * so a test that bypassed the route would prove nothing.
 *
 * What is under test:
 *   1. `POST /api/v1/capabilities/request` decides BEFORE it signs.
 *   2. A `step_up` entitlement (and a risk-triggered request) hands back
 *      `challengeRequired: true` plus a challenge id and expiry, and NO
 *      capability.
 *   3. The challenge is bound to (userId, resourceId, operation, secretRef) and
 *      is reused rather than re-issued, so one binding gets one challenge.
 *   4. Only a completed challenge unlocks issuance, and only for ITS binding.
 *   5. `POST /api/v1/challenges/approve` accepts ONLY an approval Core signed
 *      with the pinned key — there is no PIN anywhere in this suite — and the
 *      capability it produces verifies against the public key the same server
 *      publishes on `/api/v1/crypto/public-key`.
 *   6. Deny paths (`closed`, unknown entitlement, disallowed operation) still
 *      deny with 403 and no token.
 */

import type { Server } from "http";
import type { AddressInfo } from "net";

import { PlusApiServer } from "../../plus/api/server";
import type {
  IChallengeRepository,
  IEntitlementRepository,
  IPlusUserRepository,
} from "../../plus/domain/repositories";
import type { IEmailService } from "../../plus/domain/services/email-service";
import { setRiskEngine } from "../../plus/domain/services/risk-engine";
import { Entitlement, type PestilloState } from "../../plus/domain/entities/entitlement";
import { PlusUser, type PinLockoutState } from "../../plus/domain/entities/user";
import {
  loadEd25519PublicKey,
  verifyCapability,
  type CapabilityOperation,
} from "../../src/infrastructure/crypto/ed25519-capability";
import {
  APPROVAL_VERSION,
  CORE_APPROVAL_PUBLIC_KEY_ENV,
  generateApprovalKeyPair,
  loadApprovalPrivateKey,
  signApproval,
  type ApprovalPayload,
  type Ed25519ApprovalKeyPair,
} from "../../src/infrastructure/crypto/ed25519-approval";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_ID = "user-stepup";
const RESOURCE_ID = "res-stepup";
const SECRET_REF = "ref-stepup";
const SECOND_RESOURCE_ID = "res-other";
const SECOND_SECRET_REF = "ref-other";
const BENIGN_DEVICE = "device-known";
const KNOWN_COUNTRY = "US";

/**
 * The two shapes the risk engine was measured against on the default policy:
 * a habitual-country AUTOFILL scores 11 (allow) and an ADMIN from a
 * non-habitual, high-risk country on an unknown device scores 35 (challenge).
 * The gap is deliberate — a benign request must not become the cost of a
 * hostile one.
 */
const BENIGN_CONTEXT = {
  country: KNOWN_COUNTRY,
  deviceId: BENIGN_DEVICE,
  timestamp: Date.parse("2026-09-28T12:00:00Z"),
};
const HOSTILE_CONTEXT = {
  country: "KP",
  deviceId: "device-unknown",
  timestamp: Date.parse("2026-09-28T03:00:00Z"),
};

// ---------------------------------------------------------------------------
// In-memory implementations of the real ports
// ---------------------------------------------------------------------------

interface StoredChallenge {
  id: string;
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  status: string;
  expiresAt: number;
  attempts: number;
  maxAttempts: number;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Challenges are held by reference rather than copied: `ChallengeService`
 * mutates a challenge in place (`attempts`, `status`) and then persists it, and
 * the assertions in this file read the same object the service just changed.
 */
class MemoryChallengeRepo implements IChallengeRepository {
  private readonly items = new Map<string, StoredChallenge>();

  async save(challenge: StoredChallenge): Promise<StoredChallenge> {
    this.items.set(challenge.id, challenge);
    return challenge;
  }

  async findById(id: string): Promise<StoredChallenge | null> {
    return this.items.get(id) ?? null;
  }

  async findByUserId(userId: string): Promise<StoredChallenge[]> {
    return [...this.items.values()].filter((c) => c.userId === userId);
  }

  async findPendingByUserId(userId: string): Promise<StoredChallenge[]> {
    return (await this.findByUserId(userId)).filter((c) =>
      ["pending", "email_sent", "url_accessed"].includes(c.status),
    );
  }

  async update(challenge: StoredChallenge): Promise<StoredChallenge> {
    this.items.set(challenge.id, challenge);
    return challenge;
  }

  async delete(id: string): Promise<boolean> {
    return this.items.delete(id);
  }

  async cleanupExpired(): Promise<number> {
    const now = Date.now();
    let removed = 0;
    for (const [id, challenge] of this.items) {
      if (challenge.expiresAt < now) {
        this.items.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /**
   * The PIN helper that used to live here read `metadata.generatedPin` straight
   * out of this fake repository, which is exactly why the original defect —
   * a PIN that was generated and then discarded before it ever reached anyone —
   * could not fail a test. It is gone. Completing a challenge now requires an
   * approval signed by Core's key, which no fake repository can invent.
   */
  get(challengeId: string): StoredChallenge {
    const challenge = this.items.get(challengeId);
    if (!challenge) throw new Error(`no stored challenge ${challengeId}`);
    return challenge;
  }
}

class MemoryEntitlementRepo implements IEntitlementRepository {
  private readonly items = new Map<string, Entitlement>();

  async save(entitlement: Entitlement): Promise<Entitlement> {
    this.items.set(entitlement.id, entitlement);
    return entitlement;
  }

  async findById(id: string): Promise<Entitlement | null> {
    return this.items.get(id) ?? null;
  }

  async findByUserId(userId: string): Promise<Entitlement[]> {
    return [...this.items.values()].filter((e) => e.userId === userId);
  }

  async findByResourceId(resourceId: string): Promise<Entitlement[]> {
    return [...this.items.values()].filter((e) => e.resourceId === resourceId);
  }

  async findByUserAndResource(
    userId: string,
    resourceId: string,
  ): Promise<Entitlement | null> {
    return (
      [...this.items.values()].find(
        (e) => e.userId === userId && e.resourceId === resourceId,
      ) ?? null
    );
  }

  async findByPestilloState(state: PestilloState): Promise<Entitlement[]> {
    return [...this.items.values()].filter((e) => e.pestilloState === state);
  }

  async findExpiringSoon(): Promise<Entitlement[]> {
    return [];
  }

  async search(criteria: {
    userId?: string;
    resourceId?: string;
    pestilloState?: PestilloState;
    activeOnly?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ entitlements: Entitlement[]; total: number }> {
    const entitlements = [...this.items.values()].filter(
      (e) =>
        (criteria.userId === undefined || e.userId === criteria.userId) &&
        (criteria.resourceId === undefined ||
          e.resourceId === criteria.resourceId),
    );
    return { entitlements, total: entitlements.length };
  }

  async delete(id: string): Promise<boolean> {
    return this.items.delete(id);
  }

  async list(): Promise<Entitlement[]> {
    return [...this.items.values()];
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    /* in-memory */
  }
}

class MemoryUserRepo implements IPlusUserRepository {
  private readonly items = new Map<string, PlusUser>();

  async save(user: PlusUser): Promise<PlusUser> {
    this.items.set(user.id, user);
    return user;
  }

  async findById(id: string): Promise<PlusUser | null> {
    return this.items.get(id) ?? null;
  }

  async findByEmail(email: string): Promise<PlusUser | null> {
    const lower = email.toLowerCase();
    return (
      [...this.items.values()].find((u) => u.email === lower) ?? null
    );
  }

  async findByRole(role: string): Promise<PlusUser[]> {
    return [...this.items.values()].filter((u) => u.role === role);
  }

  async findActive(): Promise<PlusUser[]> {
    return [...this.items.values()].filter((u) => u.isActive());
  }

  async search(criteria: {
    name?: string;
    email?: string;
    role?: string;
    active?: boolean;
    habitualCountry?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ users: PlusUser[]; total: number }> {
    const users = [...this.items.values()].filter(
      (u) =>
        (criteria.name === undefined ||
          u.name.toLowerCase().includes(criteria.name.toLowerCase())) &&
        (criteria.email === undefined ||
          u.email.includes(criteria.email.toLowerCase())),
    );
    return { users, total: users.length };
  }

  async delete(id: string): Promise<boolean> {
    return this.items.delete(id);
  }

  async list(): Promise<PlusUser[]> {
    return [...this.items.values()];
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    /* in-memory */
  }

  // R4 — the per-user failed-PIN lockout, on the user row rather than on the
  // challenge, so a fresh challenge cannot hand a fresh guess budget.
  private readonly lockouts = new Map<string, PinLockoutState>();

  async getPinLockout(userId: string): Promise<PinLockoutState> {
    return this.lockouts.get(userId) ?? { failedPinAttempts: 0, lockedUntil: null };
  }

  async recordFailedPinAttempt(userId: string): Promise<PinLockoutState> {
    const current = await this.getPinLockout(userId);
    const next: PinLockoutState = {
      failedPinAttempts: current.failedPinAttempts + 1,
      lockedUntil: current.lockedUntil,
    };
    this.lockouts.set(userId, next);
    return next;
  }

  async setPinLockout(userId: string, state: PinLockoutState): Promise<void> {
    this.lockouts.set(userId, state);
  }
}

/** Records every challenge email instead of sending it. */
class RecordingEmailService implements IEmailService {
  readonly sent: Array<{ to: string; url: string; expiresInMinutes: number }> = [];

  async sendChallengeEmail(
    to: string,
    challengeUrl: string,
    expiresInMinutes: number,
  ): Promise<void> {
    this.sent.push({ to, url: challengeUrl, expiresInMinutes });
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let challengeRepo: MemoryChallengeRepo;
let entitlementRepo: MemoryEntitlementRepo;
let userRepo: MemoryUserRepo;
let emailService: RecordingEmailService;
let server: Server | undefined;
let base: string;
/**
 * Core's approval key pair for this run. Only the PUBLIC half is pinned into
 * the process; every approval the suite submits is signed with the private
 * half, exactly as Core's `POST /api/v1/step-up/approve` would.
 */
let coreKeyPair!: Ed25519ApprovalKeyPair;
let previousPinnedKey: string | undefined;

/**
 * R1: every route except /health and /ready now requires the service secret,
 * so the caller has to present the same value the extension sends. The default
 * matches PLUS_CONFIG.serviceSecret when PLUS_SERVICE_SECRET is unset.
 */
const SERVICE_SECRET = process.env.PLUS_SERVICE_SECRET || "dev-secret-change-in-production";

async function post(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Service-Secret": SERVICE_SECRET,
    },
    body: JSON.stringify(body),
  });
  let parsed: any = null;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed };
}

async function get(path: string): Promise<{ status: number; body: any }> {
  const response = await fetch(`${base}${path}`, {
    headers: { "X-Service-Secret": SERVICE_SECRET },
  });
  return { status: response.status, body: await response.json() };
}

/** The capability request body, with the release-share reference as the binding. */
function capabilityBody(overrides: Record<string, unknown> = {}) {
  return {
    userId: USER_ID,
    resourceId: RESOURCE_ID,
    operation: "AUTOFILL",
    secretRef: SECRET_REF,
    assurance: 2,
    ...overrides,
  };
}

/**
 * The approval body for `POST /api/v1/challenges/approve`.
 *
 * Every binding field is read off the STORED challenge, which is where the
 * real flow gets them: Core signs the same four values Plus already holds, so
 * an approval for one release can never satisfy another. `overrides` exists
 * so a case can forge one field; `signer` so a case can sign with the wrong
 * key.
 */
function approvalBodyFor(
  challenge: StoredChallenge,
  overrides: Partial<ApprovalPayload> = {},
  signer: Ed25519ApprovalKeyPair = coreKeyPair,
) {
  const iat = Math.floor(Date.now() / 1000);
  return signApproval(
    {
      version: APPROVAL_VERSION,
      typ: "step-up-approval",
      challengeId: challenge.id,
      userId: challenge.userId,
      resourceId: challenge.resourceId,
      operation: challenge.operation as ApprovalPayload["operation"],
      secretRef: challenge.secretRef,
      iat,
      exp: iat + 300,
      jti: crypto.randomUUID(),
      ...overrides,
    },
    loadApprovalPrivateKey(signer.privateKeyBase64),
  );
}

/** POST an approval for a stored challenge, the way the extension does. */
async function approve(challengeId: string, approval: unknown) {
  return post("/api/v1/challenges/approve", { challengeId, approval });
}

function seedEntitlement(options: {
  userId?: string;
  resourceId: string;
  pestilloState: PestilloState;
  operations: CapabilityOperation[];
}): Entitlement {
  const entitlement = Entitlement.create({
    userId: options.userId ?? USER_ID,
    resourceId: options.resourceId,
    pestilloState: options.pestilloState,
    allowedOperations: options.operations,
    createdBy: "test",
  });
  void entitlementRepo.save(entitlement);
  return entitlement;
}

beforeEach(async () => {
  challengeRepo = new MemoryChallengeRepo();
  entitlementRepo = new MemoryEntitlementRepo();
  userRepo = new MemoryUserRepo();
  emailService = new RecordingEmailService();

  // R3: Plus verifies approvals against a key it pinned itself. Supplying it
  // here is the deployment step; the suite then proves that anything signed
  // by a DIFFERENT key is refused.
  coreKeyPair = generateApprovalKeyPair();
  previousPinnedKey = process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
  process.env[CORE_APPROVAL_PUBLIC_KEY_ENV] = coreKeyPair.publicKeyBase64;

  await userRepo.save(
    PlusUser.create({
      id: USER_ID,
      email: "operator@example.com",
      name: "Step-Up Operator",
      role: "operator",
      habitualCountries: [KNOWN_COUNTRY],
    }),
  );

  // A fresh engine per test: `AdaptiveRiskEngine.evaluate` records the user's
  // last known location, so carrying one across cases would let an earlier
  // assertion change a later score.
  setRiskEngine(null);

  const api = new PlusApiServer(
    challengeRepo,
    entitlementRepo,
    userRepo,
    emailService,
  );
  server = await api.start(0);
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  if (previousPinnedKey === undefined) {
    delete process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
  } else {
    process.env[CORE_APPROVAL_PUBLIC_KEY_ENV] = previousPinnedKey;
  }
  if (!server) return;
  // `fetch` keeps sockets alive; without dropping them `close()` would not
  // return until the keep-alive window expired.
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
});

// ---------------------------------------------------------------------------
// POST /api/v1/capabilities/request
// ---------------------------------------------------------------------------

describe("POST /api/v1/capabilities/request — the step-up gate", () => {
  it("withholds the capability and asks for a challenge when the pestillo is step_up", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "step_up",
      operations: ["AUTOFILL"],
    });

    const { status, body } = await post("/api/v1/capabilities/request", capabilityBody());

    expect(status).toBe(200);
    expect(body.challengeRequired).toBe(true);
    expect(typeof body.challengeId).toBe("string");
    expect(body.challengeId.length).toBeGreaterThan(0);
    expect(body.challengeExpiresAt).toBeGreaterThan(Date.now());
    // The whole point: nothing signed while the third factor is outstanding.
    expect(body.capabilityToken).toBeUndefined();
    expect(emailService.sent).toHaveLength(1);
  });

  it("binds the challenge to the user, the resource, the operation and the secret reference", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "step_up",
      operations: ["AUTOFILL"],
    });

    const { body } = await post("/api/v1/capabilities/request", capabilityBody());

    const stored = challengeRepo.get(body.challengeId);
    expect(stored.userId).toBe(USER_ID);
    expect(stored.resourceId).toBe(RESOURCE_ID);
    expect(stored.operation).toBe("AUTOFILL");
    expect(stored.secretRef).toBe(SECRET_REF);
    expect(stored.expiresAt).toBeGreaterThan(Date.now());
    expect(stored.maxAttempts).toBe(3);

    // R3 — the PIN concept is gone from the stored record, not merely hidden.
    // There is no `pinHmac`, no `pinSalt`, no `metadata.generatedPin` and no
    // `pin` field, on the record or in the response. The two random fields are
    // split off before the plaintext scan so a base64 nonce can never be
    // mistaken for a 6-digit PIN; everything else is scanned as-is.
    expect(stored).not.toHaveProperty("pinHmac");
    expect(stored).not.toHaveProperty("pinSalt");
    expect(stored.metadata?.generatedPin).toBeUndefined();
    expect(Object.keys(stored)).not.toContain("pin");
    expect(Object.keys(body)).not.toContain("pin");
    const { nonce, id, ...deterministic } = stored;
    expect(nonce).toEqual(expect.any(String));
    expect(id).toEqual(expect.any(String));
    expect(JSON.stringify(deterministic)).not.toMatch(/\b\d{6}\b/);
  });

  it("reuses one outstanding challenge across repeat requests and the trigger route", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "step_up",
      operations: ["AUTOFILL"],
    });

    const first = await post("/api/v1/capabilities/request", capabilityBody());
    expect(first.status).toBe(200);
    expect(emailService.sent).toHaveLength(1);

    // A second capability request must not mint a second challenge: the user
    // has no way to enter a PIN yet, and a completion recorded against one
    // challenge would never unlock the other.
    const second = await post("/api/v1/capabilities/request", capabilityBody());
    expect(second.status).toBe(200);
    expect(second.body.challengeId).toBe(first.body.challengeId);
    expect(second.body.capabilityToken).toBeUndefined();

    // The extension's START_STEP_UP leg asks for the same binding. It must land
    // on the SAME challenge, and must not send a second email.
    const trigger = await post("/api/v1/challenges/trigger", {
      userId: USER_ID,
      resourceId: RESOURCE_ID,
      operation: "AUTOFILL",
      secretRef: SECRET_REF,
      type: "step_up",
    });
    expect(trigger.status).toBe(201);
    expect(trigger.body.challengeId).toBe(first.body.challengeId);
    expect(emailService.sent).toHaveLength(1);
    expect(emailService.sent[0].url).toContain(first.body.challengeId);
  });

  it("denies a closed pestillo with 403 and no token", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "closed",
      operations: ["AUTOFILL"],
    });

    const { status, body } = await post("/api/v1/capabilities/request", capabilityBody());

    expect(status).toBe(403);
    expect(body.error).toBe("Pestillo is closed");
    expect(body.capabilityToken).toBeUndefined();
    expect(body.challengeRequired).toBeUndefined();
  });

  it("issues to a benign request on an enabled entitlement", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "enabled",
      operations: ["AUTOFILL"],
    });

    const { status, body } = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ context: BENIGN_CONTEXT }),
    );

    expect(status).toBe(201);
    expect(typeof body.capabilityToken).toBe("object");
    expect(body.capabilityToken.payload.assurance).toBe(2);
    expect(body.capabilityToken.payload.resourceId).toBe(RESOURCE_ID);
    expect(body.capabilityToken.payload.secretRef).toBe(SECRET_REF);
    expect(body.expiresAt).toBeGreaterThan(Date.now());
    // Benign must not pay the step-up tax.
    expect(body.challengeRequired).toBeUndefined();
  });

  it("challenges a hostile request on an enabled entitlement", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "enabled",
      operations: ["AUTOFILL", "ADMIN"],
    });

    const { status, body } = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ operation: "ADMIN", context: HOSTILE_CONTEXT }),
    );

    expect(status).toBe(200);
    expect(body.challengeRequired).toBe(true);
    expect(body.capabilityToken).toBeUndefined();
    expect(challengeRepo.get(body.challengeId).operation).toBe("ADMIN");
  });

  it("denies an operation the entitlement does not allow", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "enabled",
      operations: ["AUTOFILL"],
    });

    const { status, body } = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ operation: "VIEW" }),
    );

    expect(status).toBe(403);
    expect(body.error).toBe("Operation not allowed");
    expect(body.capabilityToken).toBeUndefined();
  });

  it("denies a request for a resource the user holds no entitlement for", async () => {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "enabled",
      operations: ["AUTOFILL"],
    });

    const { status, body } = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ resourceId: "res-unknown", secretRef: "ref-unknown" }),
    );

    expect(status).toBe(403);
    expect(body.error).toBe("No entitlement found");
    expect(body.capabilityToken).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/challenges/approve — the third factor itself
// ---------------------------------------------------------------------------

describe("POST /api/v1/challenges/approve — proving the third factor", () => {
  async function startChallenge(): Promise<StoredChallenge> {
    seedEntitlement({
      resourceId: RESOURCE_ID,
      pestilloState: "step_up",
      operations: ["AUTOFILL"],
    });
    const { body } = await post("/api/v1/capabilities/request", capabilityBody());
    expect(body.challengeRequired).toBe(true);
    return challengeRepo.get(body.challengeId);
  }

  it("issues a capability on an approval Core signed, and it verifies against this server's public key", async () => {
    const challenge = await startChallenge();
    const approval = await approvalBodyFor(challenge);

    const { status, body } = await approve(challenge.id, approval);

    expect(status).toBe(200);
    expect(body.capabilityToken).toBeDefined();

    const publicKey = await get("/api/v1/crypto/public-key");
    expect(publicKey.status).toBe(200);
    expect(publicKey.body.algorithm).toBe("Ed25519");

    // This is the assertion the single-signing-key fix exists for: the key the
    // server PUBLISHES has to be the key it SIGNED with, or Core rejects every
    // capability an accepted approval produced.
    const verification = await verifyCapability(
      body.capabilityToken,
      loadEd25519PublicKey(publicKey.body.publicKey),
    );
    expect(verification.valid).toBe(true);

    expect(body.capabilityToken.payload.assurance).toBe(3);
    expect(body.capabilityToken.payload.userId).toBe(USER_ID);
    expect(body.capabilityToken.payload.resourceId).toBe(RESOURCE_ID);
    expect(body.capabilityToken.payload.secretRef).toBe(SECRET_REF);

    expect(challengeRepo.get(challenge.id).status).toBe("completed");
  });

  it("refuses a request that carries no approval at all", async () => {
    const challenge = await startChallenge();

    const { status, body } = await post("/api/v1/challenges/approve", {
      challengeId: challenge.id,
    });

    expect(status).toBe(400);
    expect(body.error).toBe("challengeId and approval required");
    expect(body.capabilityToken).toBeUndefined();
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });

  it("refuses an approval signed with any key other than the pinned one", async () => {
    const challenge = await startChallenge();
    const impostor = generateApprovalKeyPair();

    const { status, body } = await approve(
      challenge.id,
      await approvalBodyFor(challenge, {}, impostor),
    );

    expect(status).toBe(400);
    expect(body.error).toBe("Invalid signature");
    expect(body.capabilityToken).toBeUndefined();
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });

  it("refuses an approval signed for a different secret reference", async () => {
    const challenge = await startChallenge();

    // Correctly signed by Core's pinned key, but bound to another credential:
    // a valid token must not release the wrong secret.
    const { status, body } = await approve(
      challenge.id,
      await approvalBodyFor(challenge, { secretRef: SECOND_SECRET_REF, resourceId: SECOND_RESOURCE_ID }),
    );

    expect(status).toBe(400);
    expect(body.error).toContain("secretRef");
    expect(body.capabilityToken).toBeUndefined();
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });

  it("refuses an approval signed for a different challenge id", async () => {
    const challenge = await startChallenge();

    const { status, body } = await approve(
      challenge.id,
      await approvalBodyFor(challenge, { challengeId: "some-other-challenge" }),
    );

    expect(status).toBe(400);
    expect(body.error).toContain("challengeId");
    expect(body.capabilityToken).toBeUndefined();
  });

  it("refuses a replay of an approval that was already accepted", async () => {
    const challenge = await startChallenge();
    const approval = await approvalBodyFor(challenge);

    const first = await approve(challenge.id, approval);
    expect(first.status).toBe(200);

    // The challenge is spent, so this is refused on status first; either way
    // nothing is signed twice.
    const second = await approve(challenge.id, approval);
    expect(second.status).toBe(400);
    expect(second.body.capabilityToken).toBeUndefined();
    expect(second.body.error).toContain("not in valid state");
  });

  it("fails closed when the Core approval public key is not pinned", async () => {
    const challenge = await startChallenge();
    const approval = await approvalBodyFor(challenge);

    // The deployment step missing: Plus has nothing to verify against, so it
    // refuses rather than accepting an approval it cannot check.
    delete process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];

    const { status, body } = await approve(challenge.id, approval);

    expect(status).toBe(400);
    expect(body.error).toBe("Core approval public key is not configured");
    expect(body.capabilityToken).toBeUndefined();
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });

  it("lets a proven challenge unlock the capability request at assurance 3", async () => {
    const challenge = await startChallenge();
    const approved = await approve(challenge.id, await approvalBodyFor(challenge));
    expect(approved.status).toBe(200);
    const challengeId = challenge.id;

    // Presenting the challenge id that was proven…
    const withChallengeId = await post(
      "/api/v1/capabilities/request",
      capabilityBody({
        assurance: 3,
        context: { challengeId, ...BENIGN_CONTEXT },
      }),
    );
    expect(withChallengeId.status).toBe(201);
    expect(withChallengeId.body.capabilityToken.payload.assurance).toBe(3);

    // …and omitting it: the server's own record of the proof is what authorizes,
    // the presented id is only checked when one is supplied.
    const withoutChallengeId = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ assurance: 3, context: BENIGN_CONTEXT }),
    );
    expect(withoutChallengeId.status).toBe(201);
    expect(withoutChallengeId.body.capabilityToken.payload.assurance).toBe(3);
  });

  it("refuses a challenge id that was not proven for this binding", async () => {
    const challenge = await startChallenge();
    await approve(challenge.id, await approvalBodyFor(challenge));

    // A completed challenge for a DIFFERENT release must not unlock this one.
    seedEntitlement({
      resourceId: SECOND_RESOURCE_ID,
      pestilloState: "step_up",
      operations: ["AUTOFILL"],
    });
    const other = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ resourceId: SECOND_RESOURCE_ID, secretRef: SECOND_SECRET_REF }),
    );
    expect(other.status).toBe(200);
    expect(other.body.challengeRequired).toBe(true);
    expect(other.body.challengeId).not.toBe(challenge.id);

    // Naming SOMEONE ELSE's challenge on this binding is a denial, not a pass:
    // `other`'s challenge belongs to the second release and is not proven for
    // this one, so it must not be able to stand in for the proof that was.
    const spoofed = await post(
      "/api/v1/capabilities/request",
      capabilityBody({ assurance: 3, context: { challengeId: other.body.challengeId } }),
    );
    expect(spoofed.status).toBe(403);
    expect(spoofed.body.error).toBe("Challenge not satisfied");
    expect(spoofed.body.capabilityToken).toBeUndefined();
  });

  it("no longer serves the retired PIN route", async () => {
    const challenge = await startChallenge();

    const { status } = await post("/api/v1/challenges/verify", {
      challengeId: challenge.id,
      pin: "123456",
    });

    expect(status).toBe(404);
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });
});

/* ==========================================================================
 * R1 — the service secret and the rate limit are now real
 * ========================================================================== */

describe("R1 — authentication and rate limiting", () => {
  const raw = (path: string, method: string, headers: Record<string, string>) =>
    fetch(`${base}${path}`, { method, headers });

  it("leaves /health and /ready open, because a probe carries no credential", async () => {
    for (const probe of ["/health", "/ready"]) {
      const res = await raw(probe, "GET", {});
      expect(res.status).toBe(200);
    }
  });

  it("refuses a request with no X-Service-Secret at all", async () => {
    const res = await raw(
      "/api/v1/entitlements/check",
      "POST",
      { "Content-Type": "application/json" },
    );

    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("Missing X-Service-Secret");
  });

  it("refuses a wrong secret without echoing it back", async () => {
    const res = await raw(
      "/api/v1/entitlements/check",
      "POST",
      { "Content-Type": "application/json", "X-Service-Secret": "guess" },
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("Invalid X-Service-Secret");
    expect(JSON.stringify(body)).not.toContain("guess");
    expect(JSON.stringify(body)).not.toContain(SERVICE_SECRET);
  });

  it("refuses every credential-minting route when unauthenticated", async () => {
    const routes = [
      "/api/v1/capabilities/request",
      "/api/v1/entitlements/check",
      "/api/v1/challenges/trigger",
      "/api/v1/challenges/approve",
      "/api/v1/audit",
    ];

    for (const route of routes) {
      const res = await raw(route, "POST", { "Content-Type": "application/json" });
      expect(`${route} ${res.status}`).toBe(`${route} 401`);
    }
  });

  it("refuses the public-key route too — it is not merely informational", async () => {
    // Serving the signing key to any origin is how an attacker learns the key
    // Core pins, so it is behind the same secret as the routes that use it.
    const res = await raw("/api/v1/crypto/public-key", "GET", {});

    expect(res.status).toBe(401);
  });

  it("still serves an authenticated request", async () => {
    const res = await raw("/api/v1/crypto/public-key", "GET", {
      "X-Service-Secret": SERVICE_SECRET,
    });

    expect(res.status).toBe(200);
    expect((await res.json()).publicKey).toEqual(expect.any(String));
  });

  it("rate-limits instead of accepting unbounded traffic", async () => {
    // The limit is 60 per minute per IP; loopback is a single IP here.
    const seen: number[] = [];
    for (let i = 0; i < 75; i++) {
      const res = await raw("/api/v1/crypto/public-key", "GET", {
        "X-Service-Secret": SERVICE_SECRET,
      });
      seen.push(res.status);
      if (res.status === 429) {
        expect(res.headers.get("retry-after")).toMatch(/^\d+$/);
        break;
      }
    }

    expect(seen).toContain(429);
    expect(seen.filter((s) => s === 200).length).toBe(60);
  });
});
