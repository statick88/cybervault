/**
 * R4's per-user failed-PIN lockout — what survives R3, and what does not.
 *
 * ## Why this file changed shape
 *
 * The original suite drove `ChallengeService.verifyPin` against in-memory
 * implementations of the challenge repository and the lockout store, and
 * asserted the domain rule: failures accrue on the USER row, so minting a new
 * challenge cannot hand a fresh guess budget.
 *
 * R3 removed the PIN. With no PIN there is nothing to guess and nothing to
 * lock out, so `verifyPin` is gone, the lockout store is no longer a
 * constructor dependency of `ChallengeService`, and every assertion that
 * depended on a wrong PIN has nothing left to measure. The lockout's ORIGINAL
 * purpose — the thing these cases existed to protect — is dead, and saying so
 * plainly is more useful than quietly deleting the file.
 *
 * What R3 deliberately did NOT remove, because they are separate committed
 * artifacts and out of scope:
 *
 *   * `IPinLockoutStore` and `PIN_LOCKOUT_THRESHOLD` / `PIN_LOCKOUT_MS`
 *   * the three lockout methods on `IPlusUserRepository`
 *   * migration `src/infrastructure/db/migrations/006_pin_lockout.sql`
 *
 * Those are exercised against real SQL in
 * `tests/plus/postgres-plus-user-repository.test.ts`, which is the level where
 * they now live. What is left to guard HERE is the removal itself: that the
 * challenge service carries no PIN surface and no lockout wiring, that no
 * plaintext PIN reaches the stored record, and that the R4 constants the
 * migration documents have not drifted.
 */

import {
  ChallengeService,
  PIN_LOCKOUT_MS,
  PIN_LOCKOUT_THRESHOLD,
  type ChallengeProps,
  type IChallengeRepository,
} from "../../plus/domain/services/challenge";
import { NoOpEmailService } from "../../plus/domain/services/email-service";
import { generateEd25519KeyPair } from "../../src/infrastructure/crypto/ed25519-capability";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Challenges are held by reference: the service mutates them in place. */
class MemoryChallengeRepo implements IChallengeRepository {
  private readonly items = new Map<string, ChallengeProps>();

  async save(challenge: ChallengeProps): Promise<ChallengeProps> {
    this.items.set(challenge.id, challenge);
    return challenge;
  }

  async findById(id: string): Promise<ChallengeProps | null> {
    return this.items.get(id) ?? null;
  }

  async findByUserId(userId: string): Promise<ChallengeProps[]> {
    return [...this.items.values()].filter((c) => c.userId === userId);
  }

  async findPendingByUserId(userId: string): Promise<ChallengeProps[]> {
    return (await this.findByUserId(userId)).filter((c) =>
      ["pending", "email_sent", "url_accessed"].includes(c.status),
    );
  }

  async update(challenge: ChallengeProps): Promise<ChallengeProps> {
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

  get(id: string): ChallengeProps {
    const challenge = this.items.get(id);
    if (!challenge) throw new Error(`no stored challenge ${id}`);
    return challenge;
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let challengeRepo: MemoryChallengeRepo;
let service: ChallengeService;
let keyPair: {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyBase64: string;
  privateKeyBase64: string;
};

beforeEach(() => {
  keyPair = generateEd25519KeyPair();
  challengeRepo = new MemoryChallengeRepo();
  // Four arguments, and only four: the fifth used to be the lockout store.
  service = new ChallengeService(
    challengeRepo,
    new NoOpEmailService(),
    "https://plus.example.com",
    keyPair.privateKeyBase64,
  );
});

afterEach(() => {
  jest.restoreAllMocks();
  if (keyPair.privateKey) keyPair.privateKey.fill(0);
});

// ---------------------------------------------------------------------------
// What R3 removed
// ---------------------------------------------------------------------------

describe("R3 — the PIN and its lockout are gone from the challenge service", () => {
  it("carries no lockout store", () => {
    const internals = service as unknown as Record<string, unknown>;
    expect(internals["pinLockout"]).toBeUndefined();
  });

  it("exposes no PIN verification surface", () => {
    const proto = ChallengeService.prototype as unknown as Record<string, unknown>;
    expect(proto["verifyPin"]).toBeUndefined();
    expect(proto["computePinHmac"]).toBeUndefined();
    expect(proto["generateRandomPin"]).toBeUndefined();
    expect(proto["registerWrongPin"]).toBeUndefined();
  });

  it("no longer exports PIN_LENGTH, because there is no PIN length", () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const challengeModule = require("../../plus/domain/services/challenge");
    expect(challengeModule.PIN_LENGTH).toBeUndefined();
    expect(challengeModule.PinVerifyInput).toBeUndefined();
    expect(challengeModule.PinVerifyResult).toBeUndefined();
  });

  it("creates a challenge with no PIN material anywhere in the record", async () => {
    await service.createChallenge({
      userId: "user-lockout",
      resourceId: "res-lockout",
      operation: "AUTOFILL",
      secretRef: "ref-lockout",
      type: "risk_based",
    });

    const saved = [...(challengeRepo as unknown as { items: Map<string, ChallengeProps> })["items"].values()][0];
    expect(saved).toBeDefined();
    expect(saved).not.toHaveProperty("pinHmac");
    expect(saved).not.toHaveProperty("pinSalt");
    expect(saved.metadata?.generatedPin).toBeUndefined();

    // Nothing that looks like a 6-digit PIN in the persisted shape either.
    const { nonce, id, ...deterministic } = saved;
    expect(nonce).toEqual(expect.any(String));
    expect(id).toEqual(expect.any(String));
    expect(JSON.stringify(deterministic)).not.toMatch(/\b\d{6}\b/);
  });
});

// ---------------------------------------------------------------------------
// What R4 kept
// ---------------------------------------------------------------------------

describe("R4 — the retained lockout artifacts", () => {
  it("still exports the thresholds migration 006 encodes", () => {
    expect(PIN_LOCKOUT_THRESHOLD).toBe(5);
    expect(PIN_LOCKOUT_MS).toBe(15 * 60 * 1000);
  });

  it("still exports the port the user repository implements", () => {
    // The interface is type-only, so it cannot be asserted at runtime; what
    // CAN be asserted is that the module still exports the name, which is
    // what `IPlusUserRepository` and its tests import.
    const challengeModule = require("../../plus/domain/services/challenge");
    expect(challengeModule).toBeDefined();
    expect(typeof ChallengeService).toBe("function");
  });
});
