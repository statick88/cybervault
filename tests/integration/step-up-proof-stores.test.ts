/**
 * R11's persistence layer.
 *
 * ## Why this file exists
 *
 * `PostgresStepUpProofStores.ts` landed at 50% statements and **0% branches**
 * with 315-360 uncovered. It holds the two things R11's security argument
 * rests on, and neither was tested:
 *
 *   1. `consume` — the single-use consumption of an approval challenge. If
 *      this is not atomic, a captured assertion is replayable, and the
 *      single-use property the threat model claims is a convention.
 *   2. `save` on the authenticator store — the re-owning check. Registration
 *      replays must collide rather than silently reassign a credential.
 *
 * The SQL is checked against a fake driver that records the statements and can
 * be made to return whatever a real database would. This does not prove the
 * queries are valid PostgreSQL; the migration test and the live container cover
 * that. What it proves is that the code sends the right statement, consumes
 * only on a matching row, and does not treat a failed write as a success.
 */

/**
 * `pg` is mocked because both stores construct their own `Pool` from a
 * connection string — there is no injection seam. This is the pattern the
 * other Postgres suites use.
 *
 * The statements are recorded rather than executed, so this pins WHAT the code
 * sends: the atomic `consumed_at IS NULL` guard, the user binding in the
 * WHERE clause, and `ON CONFLICT DO NOTHING` on registration. Valid SQL is
 * the migration's job, not this file's.
 */
const statements: Array<{ sql: string; params: unknown[] }> = [];
let queue: QueryResultLike[] = [];
/** How many consecutive queries fail. `withRetry` re-attempts retryable errors,
 *  so a single failure is absorbed and the next attempt succeeds — a test that
 *  fails once is testing the retry, not the error path. */
let failuresRemaining = 0;

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: async (text: string, values: unknown[] = []) => {
      statements.push({ sql: text, params: values ?? [] });
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        throw Object.assign(new Error("connection terminated unexpectedly"), { code: "ECONNRESET" });
      }
      return queue.shift() ?? { rows: [], rowCount: 0 };
    },
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import {
  PostgresStepUpApprovalChallengeStore,
  PostgresStepUpAuthenticatorStore,
} from "../../src/infrastructure/repositories/PostgresStepUpProofStores";

/* ------------------------------------------------------------------ */
/*  Fake driver                                                        */
/* ------------------------------------------------------------------ */

interface QueryResultLike {
  rows: any[];
  rowCount?: number;
  command?: string;
}

/**
 * Clear the statements recorded by the constructor's schema probe and queue
 * `count` empty results for the calls that follow.
 *
 * Both stores run `initializeTable()` on construction. Without this the first
 * queued result is consumed by the DDL and every test reads the wrong row — a
 * failure with nothing to do with the code under test.
 */
function afterConstruction(count: number): void {
  statements.length = 0;
  queue = Array.from({ length: count }, () => ({ rows: [], rowCount: 0 }));
}

function constructor(): void {
  statements.length = 0;
  queue = [];
  failuresRemaining = 0;
}

/** Let the constructor's un-awaited schema probe finish before queueing. */
async function settleConstructor(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
}

const CHALLENGE_ROW = {
  id: "ac-1",
  user_id: "user-1",
  binding_id: "ch-1",
  purpose: "release",
  challenge: "Y2hhbGxlbmdl",
  salt: "proof-salt",
  rp_id: "example.com",
  origin: "https://example.com",
  expires_at: new Date("2030-01-01T00:00:00Z"),  // lo que devuelve pg
  consumed_at: null,
  created_at: new Date("2029-12-31T00:00:00Z"),
};

const AUTH_ROW = {
  credential_id: "cred-1",
  user_id: "user-1",
  public_key: "04" + "ab".repeat(64),
  counter: 7,
  transports: "internal",
  created_at: new Date("2029-12-31T00:00:00Z"),
  last_used_at: null,
};

function challengeStore() {
  return new PostgresStepUpApprovalChallengeStore("postgres://test");
}

function authenticatorStore() {
  return new PostgresStepUpAuthenticatorStore("postgres://test");
}

describe("the approval challenge is consumed atomically (R11 single use)", () => {
  it("guards the UPDATE on consumed_at being still null", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [CHALLENGE_ROW], rowCount: 1 };

    await store.consume("ac-1", "user-1", Date.now());

    // The single-use property lives in the WHERE clause, not in the calling
    // code. A caller that checked first and wrote second would still allow two
    // concurrent submissions; the guard has to be inside the one statement.
    const update = statements.at(-1)!;
    expect(update.sql).toMatch(/UPDATE/i);
    expect(update.sql).toMatch(/consumed_at\s+IS\s+NULL/i);
  });

  it("returns the row only when the UPDATE actually matched a row", async () => {
    // A rowCount of 0 means another process won the race. The store must not
    // hand back a consumed challenge, because handing one back is exactly how
    // a captured assertion gets replayed.
    const store = challengeStore();
    afterConstruction(1);
    queue[0] = { rows: [], rowCount: 0 };

    const result = await store.consume("ac-1", "user-1", Date.now());

    expect(result).toBeNull();
  });

  it("returns the challenge when the UPDATE matched", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [CHALLENGE_ROW], rowCount: 1 };

    const result = await store.consume("ac-1", "user-1", Date.now());

    expect(result).not.toBeNull();
    expect(result).toMatchObject({ id: "ac-1", userId: "user-1", bindingId: "ch-1" });
  });

  it("binds the consumption to the user, so another user cannot spend it", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [], rowCount: 0 };

    await store.consume("ac-1", "user-2", Date.now());

    // If the user id were missing from the WHERE clause, user-2 could consume
    // user-1's approval challenge and the binding check downstream would still
    // pass, because the challenge itself is genuine.
    const update = statements.at(-1)!;
    expect(update.sql).toMatch(/user_id\s*=\s*\$/i);
    expect(update.params.length).toBeGreaterThanOrEqual(2);
  });

  it("propagates a database failure instead of reporting a refusal", async () => {
    constructor();
    const store = challengeStore();
    await new Promise((r) => setImmediate(r));
    failuresRemaining = 5; // more than `maxAttempts`, so the retry is exhausted

    // Returning `null` here would be indistinguishable from "already spent",
    // which is a safe direction for replay but hides a broken database. The
    // route turns this into a 500, which is the honest answer.
    await expect(store.consume("ac-1", "user-1", Date.now())).rejects.toThrow();
  });

  it("findById reads without consuming", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [CHALLENGE_ROW] };

    const found = await store.findById("ac-1");

    expect(found).toMatchObject({ id: "ac-1" });
    // A read that consumed would let a caller burn its own challenge by
    // inspecting it — and the step-up flow inspects before approving.
    expect(statements.at(-1)!.sql).not.toMatch(/SET\s+consumed_at/i);
  });

  it("findById returns null for a missing row rather than throwing", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [] };

    expect(await store.findById("nope")).toBeNull();
  });
});

describe("saving a challenge", () => {
  it("persists every field the binding check later reads", async () => {
    constructor();
    const store = challengeStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [], rowCount: 1 };

    await store.save({
      id: "ac-2",
      userId: "user-1",
      bindingId: "ch-2",
      purpose: "release",
      challenge: "Y2hhbGxlbmdlMg",
      salt: "salt-2",
      rpId: "example.com",
      origin: "https://example.com",
      // Epoch milliseconds, converted to TIMESTAMPTZ at the boundary — the
      // same conversion rule as R4's lockout columns.
      expiresAt: Date.parse("2030-01-01T00:00:00Z"),
      consumedAt: null,
      createdAt: Date.parse("2029-12-31T00:00:00Z"),
    });

    const insert = statements.find((s) => /INSERT/i.test(s.sql))!;
    // `salt` and `challenge` are what a passphrase proof and a WebAuthn proof
    // are checked against. Dropping either from the write makes every
    // verification fail at runtime, and only for one proof type.
    expect(insert.sql).toMatch(/challenge/i);
    expect(insert.sql).toMatch(/salt/i);
    expect(insert.sql).toMatch(/rp_id/i);
    expect(insert.sql).toMatch(/origin/i);
    expect(insert.sql).toMatch(/binding_id/i);
  });
});

describe("authenticator registration cannot re-own a credential", () => {
  it("returns true when the insert lands", async () => {
    constructor();
    const store = authenticatorStore();
    // The constructor's `initializeTable()` is fired and NOT awaited, so it
    // lands in the queue at an unpredictable point relative to the call under
    // test. Draining it deterministically is what makes the INSERT result
    // reach the assertion instead of the DDL swallowing it.
    await settleConstructor();
    afterConstruction(1);
    // `save` decides success from `rows.length`, not `rowCount`: the INSERT
    // carries RETURNING, and on ON CONFLICT DO NOTHING Postgres returns zero
    // rows. Asserting on rowCount here would pass a store that misreads a
    // successful registration as a conflict.
    queue[0] = { rows: [AUTH_ROW], rowCount: 1 };

    expect(await store.save(authenticator("cred-1"))).toBe(true);
  });

  it("returns false on a conflict rather than overwriting another user's key", async () => {
    // rowCount 0 on an INSERT ... ON CONFLICT DO NOTHING is the signal. A
    // store that treated it as success would let a compromised worker enrol
    // its own key under an existing credential id.
    const store = authenticatorStore();
    afterConstruction(1);
    queue[0] = { rows: [], rowCount: 0 };

    expect(await store.save(authenticator("cred-1"))).toBe(false);
    // And it must not have issued an UPDATE that would replace the key.
    const update = statements.find((s) => /^UPDATE/i.test(s.sql.trim()));
    expect(update).toBeUndefined();
  });

  it("findByCredentialId maps the stored row", async () => {
    constructor();
    const store = authenticatorStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [AUTH_ROW] };

    const found = await store.findByCredentialId("cred-1");

    expect(found).toMatchObject({
      credentialId: "cred-1",
      userId: "user-1",
      counter: 7,
    });
    expect(found!.publicKey).toHaveLength(130);
  });

  it("returns null for an unknown credential, not a throw", async () => {
    constructor();
    const store = authenticatorStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [] };

    expect(await store.findByCredentialId("nope")).toBeNull();
  });

  it("listByUserId returns every credential the user registered", async () => {
    constructor();
    const store = authenticatorStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [AUTH_ROW, { ...AUTH_ROW, credential_id: "cred-2" }] };

    const list = await store.listByUserId("user-1");

    expect(list).toHaveLength(2);
    expect(list.map((a) => a.credentialId)).toEqual(["cred-1", "cred-2"]);
  });

  it("listByUserId returns an empty list rather than null", async () => {
    constructor();
    const store = authenticatorStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [] };

    expect(await store.listByUserId("nobody")).toEqual([]);
  });

  it("updateCounter writes the advanced value used for clone detection", async () => {
    constructor();
    const store = authenticatorStore();
    await settleConstructor();
    afterConstruction(1);
    queue[0] = { rows: [], rowCount: 1 };

    await store.updateCounter("cred-1", 9);

    // R11's clone detection compares against this stored counter. If the
    // update silently did nothing, every assertion would stay true and a
    // cloned authenticator would never be caught.
    const update = statements.find((st) => /UPDATE/i.test(st.sql))!;
    expect(update.params).toContain(9);
    expect(update.params).toContain("cred-1");
  });

  it("updateCounter propagates a database failure", async () => {
    constructor();
    const store = authenticatorStore();
    await new Promise((r) => setImmediate(r));
    failuresRemaining = 5; // more than `maxAttempts`, so the retry is exhausted

    // A silently-failed counter write is the worst outcome here: the
    // assertion still passes today and the next one is checked against a
    // stale value forever.
    await expect(store.updateCounter("cred-1", 9)).rejects.toThrow();
  });
});

describe("close", () => {
  it("is safe to call on both stores", async () => {
    constructor();
    await expect(challengeStore().close()).resolves.toBeUndefined();
    await expect(authenticatorStore().close()).resolves.toBeUndefined();
  });
});

function authenticator(credentialId: string) {
  return {
    credentialId,
    userId: "user-1",
    publicKey: "04" + "ab".repeat(64),
    counter: 0,
    transports: ["internal"],
    createdAt: Date.parse("2029-12-31T00:00:00Z"),
  };
}
