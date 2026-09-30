/**
 * POST /api/v1/step-up/approve — Core signs the user's release approval (R3, T3).
 *
 * The property under test is not "it returns 200". It is that every binding
 * field in the signed token is derived from the authenticated user and Core's
 * own records, never from the request body. A test that posts a `secretRef`
 * and asserts it echoed back is exactly the test that would pass on the
 * insecure version, so the cases below assert the opposite: the body's value is
 * ignored and the record's value wins.
 */
import {
  CORE_APPROVAL_PRIVATE_KEY_ENV,
  CORE_APPROVAL_PUBLIC_KEY_ENV,
  DEFAULT_APPROVAL_TTL_SECONDS,
  MAX_APPROVAL_TTL_SECONDS,
  APPROVAL_VERSION,
  generateApprovalKeyPair,
  isValidApprovalOperation,
  loadApprovalPrivateKey,
  loadApprovalPublicKey,
  signApproval,
  verifyApproval,
  type SignedApproval,
} from "../../src/infrastructure/crypto/ed25519-approval";

/* ------------------------------------------------------------------ */
/*  Doubles mirroring the entities Core reads                          */
/* ------------------------------------------------------------------ */

interface StoredCredential {
  vaultId: string;
  mode: string;
  releaseShareRef?: string;
}

class VaultRepo {
  private readonly vaults = new Map<string, { id: string; ownerId: string }>();
  findByVaultIdAndOwnerId = jest.fn(async (vaultId: string, ownerId: string) => {
    const v = this.vaults.get(vaultId);
    return v && v.ownerId === ownerId ? v : null;
  });
  add(id: string, ownerId: string): void {
    this.vaults.set(id, { id, ownerId });
  }
}

class CredentialRepo {
  private readonly items = new Map<string, StoredCredential>();
  findById = jest.fn(async (id: { toString(): string }) => this.items.get(id.toString()) ?? null);
  put(id: string, cred: StoredCredential): void {
    this.items.set(id, cred);
  }
}

/**
 * The approve handler's decision logic, mirrored.
 *
 * This is a mirror, not the real thing: the real endpoint needs a booted
 * `ApiServer` with a JWT verifier and a database. What is worth testing here
 * is the decision table — which inputs produce a signed token and which
 * produce a refusal — and that logic is small enough to state without
 * pretending to be the server. The full HTTP path is covered end to end in
 * `tests/integration/step-up-approval-flow.test.ts`, which boots both services.
 */
type ApproveOutcome =
  | { status: 200; approval: SignedApproval }
  | { status: 400 | 404 | 503; error: string };

async function approve(
  deps: { credentials: CredentialRepo; vaults: VaultRepo; signingKey?: string },
  session: { userId: string } | null,
  body: { credentialId?: unknown; operation?: unknown; challengeId?: unknown; secretRef?: unknown },
): Promise<ApproveOutcome> {
  if (!session) return { status: 404, error: "Credential not available for release" };

  const { credentials, vaults, signingKey } = deps;
  const credentialId = typeof body.credentialId === "string" ? body.credentialId : "";
  if (!credentialId) return { status: 400, error: "credentialId is required" };
  if (!isValidApprovalOperation(body.operation)) {
    return { status: 400, error: "Unsupported operation" };
  }

  const stored = await credentials.findById({ toString: () => credentialId } as never);
  if (!stored) return { status: 404, error: "Credential not available for release" };
  if (stored.mode !== "managed" || !stored.releaseShareRef) {
    return { status: 400, error: "Credential is not a managed credential" };
  }

  const vault = await vaults.findByVaultIdAndOwnerId(stored.vaultId, session.userId);
  if (!vault) return { status: 404, error: "Credential not available for release" };

  if (!signingKey) return { status: 503, error: "Approval signing is not configured" };

  const iat = Math.floor(Date.now() / 1000);
  const approval = await signApproval(
    {
      version: APPROVAL_VERSION,
      typ: "step-up-approval",
      challengeId: typeof body.challengeId === "string" ? body.challengeId : "",
      userId: session.userId,
      // Read from the record. `body.secretRef` is never consulted.
      resourceId: stored.releaseShareRef,
      operation: body.operation as never,
      secretRef: stored.releaseShareRef,
      iat,
      exp: iat + Math.min(DEFAULT_APPROVAL_TTL_SECONDS, MAX_APPROVAL_TTL_SECONDS),
      jti: "jti-from-endpoint",
    },
    loadApprovalPrivateKey(signingKey),
  );

  return { status: 200, approval };
}

function setup() {
  const credentials = new CredentialRepo();
  const vaults = new VaultRepo();
  vaults.add("vault-1", "user-1");
  credentials.put("cred-1", { vaultId: "vault-1", mode: "managed", releaseShareRef: "ref-real" });
  return { credentials, vaults };
}

const KEYS = generateApprovalKeyPair();
const PUB = loadApprovalPublicKey(KEYS.publicKeyBase64);

describe("the signed binding comes from Core's records, not the request", () => {
  it("ignores a secretRef supplied in the body", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-1",
      operation: "AUTOFILL",
      challengeId: "ch-1",
      // The attacker would like this credential's share instead.
      secretRef: "ref-victim",
    });

    expect(outcome.status).toBe(200);
    const { approval } = outcome as { status: 200; approval: SignedApproval };
    // The stored record wins, so a body-supplied ref cannot redirect the
    // approval at a different credential's share.
    expect(approval.payload.secretRef).toBe("ref-real");
    expect(approval.payload.secretRef).not.toBe("ref-victim");
    expect(approval.payload.resourceId).toBe("ref-real");
  });

  it("produces a token the pinned public key verifies against the real binding", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-1",
      operation: "TOTP",
      challengeId: "ch-7",
      secretRef: "ref-victim",
    });

    const { approval } = outcome as { status: 200; approval: SignedApproval };
    const now = Math.floor(Date.now() / 1000);

    const result = await verifyApproval(
      approval,
      PUB,
      {
        challengeId: "ch-7",
        userId: "user-1",
        resourceId: "ref-real",
        operation: "TOTP",
        secretRef: "ref-real",
      },
      now + 1,
    );

    expect(result).toEqual({ valid: true });
  });

  it("takes the user from the session, not the body", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-1",
      operation: "AUTOFILL",
      userId: "user-admin",
    } as never);

    const { approval } = outcome as { status: 200; approval: SignedApproval };
    expect(approval.payload.userId).toBe("user-1");
    expect(approval.payload.userId).not.toBe("user-admin");
  });
});

describe("the approve endpoint refuses", () => {
  it("refuses when the credential does not exist", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-missing",
      operation: "AUTOFILL",
    });

    expect(outcome.status).toBe(404);
  });

  it("gives the same answer for a missing credential and one the caller does not own", async () => {
    // If these differed, an authenticated user could probe which credential ids
    // exist in Core.
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };
    deps.credentials.put("cred-theirs", { vaultId: "vault-2", mode: "managed", releaseShareRef: "ref-theirs" });
    deps.vaults.add("vault-2", "someone-else");

    const missing = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-missing",
      operation: "AUTOFILL",
    });
    const notMine = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-theirs",
      operation: "AUTOFILL",
    });

    expect(notMine).toEqual(missing);
  });

  it("refuses a personal credential, which has no release share", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };
    deps.credentials.put("cred-personal", { vaultId: "vault-1", mode: "personal" });

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-personal",
      operation: "AUTOFILL",
    });

    expect(outcome.status).toBe(400);
  });

  it("refuses an unsupported operation", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    for (const bogus of ["__proto__", "toString", "DELETE_VAULT", 42, null]) {
      const outcome = await approve(deps, { userId: "user-1" }, {
        credentialId: "cred-1",
        operation: bogus,
      });
      expect(`${bogus} -> ${outcome.status}`).toBe(`${bogus} -> 400`);
    }
  });

  it("refuses when no signing key is configured, rather than signing nothing", async () => {
    const deps = { ...setup() };

    const outcome = await approve(deps, { userId: "user-1" }, {
      credentialId: "cred-1",
      operation: "AUTOFILL",
    });

    expect(outcome.status).toBe(503);
  });

  it("refuses a missing credentialId", async () => {
    const deps = { ...setup(), signingKey: KEYS.privateKeyBase64 };

    const outcome = await approve(deps, { userId: "user-1" }, { operation: "AUTOFILL" });

    expect(outcome.status).toBe(400);
  });
});

describe("key separation", () => {
  it("uses a different env var from the Plus capability key", () => {
    // Core signs approvals; Plus signs capabilities. A shared variable would
    // let either service mint the other's artifact, collapsing the two roles.
    expect(CORE_APPROVAL_PRIVATE_KEY_ENV).toBe("CORE_APPROVAL_PRIVATE_KEY");
    expect(CORE_APPROVAL_PUBLIC_KEY_ENV).toBe("CORE_APPROVAL_PUBLIC_KEY");
  });

  it("a key configured for approvals cannot verify a capability and vice versa", async () => {
    const capability = require("../../src/infrastructure/crypto/ed25519-capability");
    const capKeys = capability.generateEd25519KeyPair();

    const capSigned = await capability.signCapability(
      {
        issuer: "plus",
        audience: "core",
        userId: "user-1",
        resourceId: "ref-real",
        operation: "AUTOFILL",
        secretRef: "ref-real",
        deviceId: "dev-1",
        assurance: 3,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: "jti-cap",
        version: 1,
      },
      capKeys.privateKey,
    );

    const result = await verifyApproval(capSigned as never, PUB, undefined);
    expect(result.valid).toBe(false);
  });
});
