/**
 * R4 — the per-user failed-PIN lockout.
 *
 * The per-challenge counter (`challenges.attempts`, `maxAttempts` 3) is a
 * brake on ONE challenge, and a challenge is free to mint: with the R1 rate
 * limit alone that is ~180 PIN guesses a minute against a 6-digit space. The
 * fix moves the brake onto the USER row, where recreating a challenge does
 * not recreate the budget — which is what these cases pin down.
 *
 * Everything here drives `ChallengeService.verifyPin` directly against
 * in-memory implementations of the two ports it depends on (the challenge
 * repository and the lockout store), so the assertions are about the domain
 * rule. The SQL shape lives in `tests/plus/postgres-plus-user-repository.test.ts`
 * and the HTTP wiring in `tests/plus/capability-request-step-up.test.ts`.
 */

import {
  ChallengeService,
  PIN_LENGTH,
  PIN_LOCKOUT_MS,
  PIN_LOCKOUT_THRESHOLD,
  type ChallengeProps,
  type IChallengeRepository,
  type IPinLockoutStore,
} from "../../plus/domain/services/challenge";
import { NoOpEmailService } from "../../plus/domain/services/email-service";
import type { PinLockoutState } from "../../plus/domain/entities/user";
import { generateEd25519KeyPair } from "../../src/infrastructure/crypto/ed25519-capability";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_ID = "user-lockout";
const OTHER_USER_ID = "user-other";
const PIN = "123456";
const WRONG_PIN = "654321";

/** Challenges are held by reference: the service mutates `attempts` in place. */
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

/**
 * The lockout store, in memory for the test only — production runs against
 * `PostgresPlusUserRepository`, because a lockout that dies with the process
 * is the R4 bug in a different costume.
 */
class MemoryLockoutStore implements IPinLockoutStore {
  private readonly states = new Map<string, PinLockoutState>();

  async getPinLockout(userId: string): Promise<PinLockoutState> {
    return this.states.get(userId) ?? { failedPinAttempts: 0, lockedUntil: null };
  }

  async recordFailedPinAttempt(userId: string): Promise<PinLockoutState> {
    const current = await this.getPinLockout(userId);
    const next: PinLockoutState = {
      failedPinAttempts: current.failedPinAttempts + 1,
      lockedUntil: current.lockedUntil,
    };
    this.states.set(userId, next);
    return next;
  }

  async setPinLockout(userId: string, state: PinLockoutState): Promise<void> {
    this.states.set(userId, state);
  }

  seed(userId: string, state: PinLockoutState): void {
    this.states.set(userId, state);
  }

  stateOf(userId: string): PinLockoutState {
    return this.states.get(userId) ?? { failedPinAttempts: 0, lockedUntil: null };
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let challengeRepo: MemoryChallengeRepo;
let lockout: MemoryLockoutStore;
let service: ChallengeService;
let keyPair: {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyBase64: string;
  privateKeyBase64: string;
};
let challengeSeq = 0;

/**
 * A challenge whose PIN is known, exactly as `createChallenge` would leave it:
 * HMAC + salt in the row, plaintext only in the development metadata field.
 */
async function makeChallenge(
  options: { userId?: string; pin?: string } = {},
): Promise<ChallengeProps> {
  const userId = options.userId ?? USER_ID;
  const pin = options.pin ?? PIN;
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const pinKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pin),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", pinKey, salt);

  const now = Date.now();
  const challenge: ChallengeProps = {
    id: `challenge-${++challengeSeq}`,
    userId,
    resourceId: "res-lockout",
    operation: "AUTOFILL",
    secretRef: "ref-lockout",
    type: "risk_based",
    status: "email_sent",
    nonce: "test-nonce",
    pinHmac: btoa(String.fromCharCode(...new Uint8Array(signature))),
    pinSalt: btoa(String.fromCharCode(...salt)),
    expiresAt: now + 10 * 60 * 1000,
    attempts: 0,
    maxAttempts: 3,
    assuranceLevel: 3,
    createdAt: now,
    updatedAt: now,
    metadata: { generatedPin: pin },
  };
  await challengeRepo.save(challenge);
  return challenge;
}

/** Spy on the HMAC step so a case can prove it never ran. */
function hmacSpy(): jest.SpyInstance<Promise<string>, [string, string]> {
  return jest.spyOn(
    service as unknown as { computePinHmac(pin: string, salt: string): Promise<string> },
    "computePinHmac",
  );
}

beforeEach(() => {
  keyPair = generateEd25519KeyPair();
  challengeRepo = new MemoryChallengeRepo();
  lockout = new MemoryLockoutStore();
  service = new ChallengeService(
    challengeRepo,
    new NoOpEmailService(),
    "https://plus.example.com",
    keyPair.privateKeyBase64,
    lockout,
  );
});

afterEach(() => {
  jest.restoreAllMocks();
  if (keyPair.privateKey) keyPair.privateKey.fill(0);
});

// ---------------------------------------------------------------------------
// The lockout
// ---------------------------------------------------------------------------

describe("R4 — the per-user failed-PIN lockout", () => {
  it(`arms the lockout at ${PIN_LOCKOUT_THRESHOLD} failed PINs, for 15 minutes`, async () => {
    // Three wrong PINs exhaust ONE challenge's own budget…
    const first = await makeChallenge();
    for (let i = 0; i < 3; i++) {
      const attempt = await service.verifyPin({ challengeId: first.id, pin: WRONG_PIN });
      expect(attempt.success).toBe(false);
      expect(attempt.error).toBe("Invalid PIN");
    }
    expect(challengeRepo.get(first.id).attempts).toBe(3);
    expect(lockout.stateOf(USER_ID)).toEqual({ failedPinAttempts: 3, lockedUntil: null });

    // …and the remaining guesses come from a SECOND challenge: the exact
    // recreation that used to hand over a fresh budget every time.
    const second = await makeChallenge();
    await service.verifyPin({ challengeId: second.id, pin: WRONG_PIN });
    await service.verifyPin({ challengeId: second.id, pin: WRONG_PIN });

    const state = lockout.stateOf(USER_ID);
    expect(state.failedPinAttempts).toBe(PIN_LOCKOUT_THRESHOLD);
    expect(state.lockedUntil).not.toBeNull();
    expect(state.lockedUntil!).toBeGreaterThan(Date.now() + PIN_LOCKOUT_MS - 5_000);
    expect(state.lockedUntil!).toBeLessThanOrEqual(Date.now() + PIN_LOCKOUT_MS + 5_000);
  });

  it("keeps the per-challenge attempt limit as defence in depth", async () => {
    const challenge = await makeChallenge();
    for (let i = 0; i < 3; i++) {
      await service.verifyPin({ challengeId: challenge.id, pin: WRONG_PIN });
    }

    const exhausted = await service.verifyPin({ challengeId: challenge.id, pin: WRONG_PIN });

    expect(exhausted.success).toBe(false);
    expect(exhausted.error).toBe("Maximum attempts exceeded");
    expect(challengeRepo.get(challenge.id).status).toBe("failed");
    // An exhausted challenge is refused BEFORE the PIN is judged, so it adds
    // nothing to the user's budget: still the three failures that got it here.
    expect(lockout.stateOf(USER_ID)).toEqual({ failedPinAttempts: 3, lockedUntil: null });
  });

  it("refuses a locked user even with the CORRECT pin, indistinguishably", async () => {
    lockout.seed(USER_ID, {
      failedPinAttempts: PIN_LOCKOUT_THRESHOLD,
      lockedUntil: Date.now() + PIN_LOCKOUT_MS,
    });
    const challenge = await makeChallenge(); // the correct PIN, baked in
    const spy = hmacSpy();

    const withCorrectPin = await service.verifyPin({ challengeId: challenge.id, pin: PIN });
    const withWrongPin = await service.verifyPin({ challengeId: challenge.id, pin: WRONG_PIN });

    // No HMAC, therefore no timing or content oracle for the right PIN…
    expect(spy).not.toHaveBeenCalled();
    // …and the two answers are the same answer, so "locked" cannot be told
    // apart from "wrong PIN" by the response either.
    expect(withCorrectPin.success).toBe(false);
    expect(withCorrectPin.capabilityToken).toBeUndefined();
    expect(withCorrectPin.error).toBe(withWrongPin.error);
    expect(withCorrectPin.error).toBe("Invalid PIN");
    // The refusal consumed nothing on the challenge either.
    expect(challengeRepo.get(challenge.id).attempts).toBe(0);
    expect(challengeRepo.get(challenge.id).status).toBe("email_sent");
  });

  it("clears the budget on a correct PIN", async () => {
    // One below the threshold: armed, but not yet locked.
    lockout.seed(USER_ID, { failedPinAttempts: PIN_LOCKOUT_THRESHOLD - 1, lockedUntil: null });
    const challenge = await makeChallenge();

    const result = await service.verifyPin({ challengeId: challenge.id, pin: PIN });

    expect(result.success).toBe(true);
    expect(result.capabilityToken).toBeDefined();
    expect(lockout.stateOf(USER_ID)).toEqual({ failedPinAttempts: 0, lockedUntil: null });
  });

  it("stays refused on a brand-new challenge for the same user while locked", async () => {
    // Armed the long way — through real wrong PINs — because the point of the
    // test is that CHALLENGE recreation does not reset the counter.
    const first = await makeChallenge();
    for (let i = 0; i < 3; i++) {
      await service.verifyPin({ challengeId: first.id, pin: WRONG_PIN });
    }
    const second = await makeChallenge();
    await service.verifyPin({ challengeId: second.id, pin: WRONG_PIN });
    await service.verifyPin({ challengeId: second.id, pin: WRONG_PIN });

    const fresh = await makeChallenge(); // attempts 0, correct PIN, same user
    const result = await service.verifyPin({ challengeId: fresh.id, pin: PIN });

    expect(result.success).toBe(false);
    expect(result.error).toBe("Invalid PIN");
    expect(result.capabilityToken).toBeUndefined();
    expect(lockout.stateOf(USER_ID).lockedUntil).toBeGreaterThan(Date.now());
  });

  it("locks only the user the challenge belongs to", async () => {
    lockout.seed(USER_ID, {
      failedPinAttempts: PIN_LOCKOUT_THRESHOLD,
      lockedUntil: Date.now() + PIN_LOCKOUT_MS,
    });
    const otherUsersChallenge = await makeChallenge({ userId: OTHER_USER_ID });

    const result = await service.verifyPin({
      challengeId: otherUsersChallenge.id,
      pin: PIN,
    });

    expect(result.success).toBe(true);
    expect(lockout.stateOf(OTHER_USER_ID)).toEqual({
      failedPinAttempts: 0,
      lockedUntil: null,
    });
  });

  it("rejects a PIN that is not exactly 6 characters, without hashing or counting it", async () => {
    const challenge = await makeChallenge();
    const spy = hmacSpy();

    const malformed: unknown[] = [
      "12345", // one short
      "1234567", // one long
      "", // empty
      123456, // a JSON number, not a string
      ["1", "2", "3", "4", "5", "6"], // an array of characters
    ];
    for (const pin of malformed) {
      const result = await service.verifyPin({
        challengeId: challenge.id,
        pin: pin as string,
      });
      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid PIN format");
    }

    // Rejected before the HMAC: no CPU handed to the caller.
    expect(spy).not.toHaveBeenCalled();
    // Not counted either — otherwise five garbage requests would lock an
    // account, which turns the lockout into a denial-of-service tool.
    expect(challengeRepo.get(challenge.id).attempts).toBe(0);
    expect(lockout.stateOf(USER_ID)).toEqual({ failedPinAttempts: 0, lockedUntil: null });
    // And the challenge is still usable with a PIN of the right shape.
    expect(PIN.length).toBe(PIN_LENGTH);
    await expect(
      service.verifyPin({ challengeId: challenge.id, pin: PIN }),
    ).resolves.toMatchObject({ success: true });
  });

  it("releases an expired lock: a correct PIN is accepted once locked_until passes", async () => {
    lockout.seed(USER_ID, {
      failedPinAttempts: PIN_LOCKOUT_THRESHOLD,
      lockedUntil: Date.now() - 1,
    });
    const challenge = await makeChallenge();

    const result = await service.verifyPin({ challengeId: challenge.id, pin: PIN });

    expect(result.success).toBe(true);
    expect(lockout.stateOf(USER_ID)).toEqual({ failedPinAttempts: 0, lockedUntil: null });
  });

  it("never hands back a full budget: the next mistake after expiry re-arms the lock", async () => {
    lockout.seed(USER_ID, {
      failedPinAttempts: PIN_LOCKOUT_THRESHOLD,
      lockedUntil: Date.now() - 1,
    });
    const challenge = await makeChallenge();

    const result = await service.verifyPin({ challengeId: challenge.id, pin: WRONG_PIN });

    // The PIN was judged (the lock had lapsed)…
    expect(result.error).toBe("Invalid PIN");
    // …and the sticky counter re-armed the lock instead of starting over at 1.
    const state = lockout.stateOf(USER_ID);
    expect(state.failedPinAttempts).toBe(PIN_LOCKOUT_THRESHOLD + 1);
    expect(state.lockedUntil).toBeGreaterThan(Date.now());
  });
});
