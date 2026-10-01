/**
 * ManagedReleaseUseCase / GetCredentialWithCapabilityUseCase — the refusals.
 *
 * `tests/application/managed-authoring.test.ts` proves the happy round trip
 * (author → capability → release → derive → decrypt) and the two pinning
 * guards. What it does not touch is the OTHER half of this module:
 * `GetCredentialWithCapabilityUseCase` was never executed by a single test, and
 * the negative branches of `ManagedReleaseUseCase` — the validity-window
 * refusal, the operation allow-list, the vault binding gate, the "credential is
 * not managed" gate, the empty-store refusal and the top-level catch — all sat
 * at 0.
 *
 * These are the branches where the file fails closed, so each one is asserted
 * on its exact message: a refusal that silently becomes a different refusal
 * still passes a `success === false` assertion, which is exactly how a
 * weakened test hides a defect.
 */

import {
  ManagedReleaseUseCase,
  GetCredentialWithCapabilityUseCase,
} from "../../src/application/use-cases/managed-release.use-case";
import { InMemoryReleaseShareStore } from "../../src/infrastructure/repositories/InMemoryReleaseShareStore";
import {
  generateEd25519KeyPair,
  createCapabilityPayload,
  signCapability,
} from "../../src/infrastructure/crypto/ed25519-capability";
import type {
  CapabilityPayload,
  CapabilityOperation,
  CapabilityBindingContext,
  Ed25519KeyPair,
  SignedCapability,
} from "../../src/infrastructure/crypto/ed25519-capability";
import { InMemoryJtiStore } from "../../src/infrastructure/crypto/jti-store";
import type { IJtiStore } from "../../src/infrastructure/crypto/jti-store";
import { Credential } from "../../src/domain/entities/credential";
import { VaultId } from "../../src/domain/value-objects/ids";
import type { ICredentialRepository } from "../../src/domain/repositories";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const VAULT_ID = VaultId.generate().toString();
const SECRET_REF = crypto.randomUUID();
const OTHER_REF = crypto.randomUUID();
const USER_ID = "user-1";
const DEVICE_ID = "device-1";

let keyPair: Ed25519KeyPair;
let pinnedKey: Uint8Array;
let jtiStore: InMemoryJtiStore;
let store: InMemoryReleaseShareStore;
let serverSecret: Uint8Array;

beforeEach(() => {
  keyPair = generateEd25519KeyPair();
  pinnedKey = base64ToBinary(keyPair.publicKeyBase64);
  jtiStore = new InMemoryJtiStore();
  store = new InMemoryReleaseShareStore();
  serverSecret = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  serverSecret.fill(0);
  await jtiStore.close();
});

function credentialFixture(opts: {
  mode: "personal" | "managed";
  releaseShareRef?: string;
  id?: string;
  vaultId?: string;
}): Credential {
  return Credential.fromPlainObject({
    id: opts.id ?? crypto.randomUUID(),
    vaultId: opts.vaultId ?? VAULT_ID,
    title: "Fixture credential",
    username: "alice@example.com",
    encryptedPassword: "ciphertext-not-plaintext",
    mode: opts.mode,
    salt: binaryToBase64(crypto.getRandomValues(new Uint8Array(32))),
    version: 1,
    releaseShareRef: opts.releaseShareRef,
    tags: [],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
}

function repositoryWith(
  credentials: Credential[],
  opts: { throwOnLookup?: boolean } = {},
): ICredentialRepository {
  return {
    save: jest.fn(async (credential: Credential) => credential),
    findById: jest.fn(async () => null),
    findByVaultId: jest.fn(async () => credentials),
    findBySecretRef: jest.fn(async (secretRef: string) => {
      if (opts.throwOnLookup) throw new Error("credential lookup exploded");
      return credentials.find((c) => c.releaseShareRef === secretRef) ?? null;
    }),
    delete: jest.fn(async () => false),
    list: jest.fn(async () => credentials),
  };
}

/** A store that holds nothing — the "share was never minted" configuration. */
function emptyShareStore(): InMemoryReleaseShareStore {
  return new InMemoryReleaseShareStore();
}

/** A JTI store that refuses every consume — a permanent replay verdict. */
function denyingJtiStore(): IJtiStore {
  return {
    tryConsume: jest.fn(async () => false),
    isConsumed: jest.fn(async () => true),
    close: jest.fn(async () => undefined),
  };
}

async function signPayload(payload: CapabilityPayload): Promise<SignedCapability> {
  return signCapability(payload, keyPair.privateKey);
}

async function capabilityFor(
  secretRef: string,
  operation: CapabilityOperation = "AUTOFILL",
  opts: { vaultId?: string; assurance?: 1 | 2 | 3; deviceId?: string } = {},
): Promise<SignedCapability> {
  return signPayload(
    createCapabilityPayload({
      userId: USER_ID,
      resourceId: secretRef,
      operation,
      secretRef,
      deviceId: opts.deviceId ?? DEVICE_ID,
      assurance: opts.assurance ?? 2,
    }),
  );
}

function bindingsOf(token: SignedCapability): CapabilityBindingContext {
  return {
    userId: token.payload.userId,
    resourceId: token.payload.resourceId,
    secretRef: token.payload.secretRef,
    deviceId: token.payload.deviceId ?? "",
  };
}

function releaseInput(
  token: SignedCapability,
  vaultId: string = VAULT_ID,
): {
  capabilityToken: SignedCapability;
  expected: CapabilityBindingContext;
  vaultId: string;
} {
  return { capabilityToken: token, expected: bindingsOf(token), vaultId };
}

function releaseUseCase(
  repository: ICredentialRepository,
  overrides: {
    shareStore?: InMemoryReleaseShareStore | null;
    secret?: Uint8Array | null;
    plusPublicKey?: Uint8Array | null;
    jtiStore?: IJtiStore;
  } = {},
): ManagedReleaseUseCase {
  return new ManagedReleaseUseCase(
    repository,
    overrides.jtiStore ?? jtiStore,
    overrides.shareStore === undefined ? store : overrides.shareStore,
    overrides.secret === undefined ? serverSecret : overrides.secret,
    overrides.plusPublicKey === undefined ? pinnedKey : overrides.plusPublicKey,
  );
}

function getCredentialUseCase(
  repository: ICredentialRepository,
  overrides: { plusPublicKey?: Uint8Array | null; jtiStore?: IJtiStore } = {},
): GetCredentialWithCapabilityUseCase {
  return new GetCredentialWithCapabilityUseCase(
    repository,
    overrides.jtiStore ?? jtiStore,
    overrides.plusPublicKey === undefined ? pinnedKey : overrides.plusPublicKey,
  );
}

function getCredentialInput(
  token: SignedCapability,
  credentialId: string,
): {
  capabilityToken: SignedCapability;
  expected: CapabilityBindingContext;
  credentialId: string;
} {
  return { capabilityToken: token, expected: bindingsOf(token), credentialId };
}

/**
 * A capability whose validity window is not positive.
 *
 * `exp` and `iat` are both pushed into the future by the SAME amount and the
 * payload is re-signed, so the signature still verifies (`exp >= now`,
 * `iat <= now + 60`) — but `exp - iat` collapses to 0, the case
 * `capabilityTtlSeconds` refuses rather than letting a non-positive TTL reach
 * the replay store. This models a degenerate issuer, which is exactly the
 * input the consumer has to defend itself against.
 */
async function withZeroWindow(token: SignedCapability): Promise<SignedCapability> {
  const window = token.payload.iat + 50;
  return signPayload({ ...token.payload, iat: window, exp: window });
}

/* -------------------------------------------------------------------------- */
/* ManagedReleaseUseCase — refusals the happy-path suite never reaches          */
/* -------------------------------------------------------------------------- */

describe("ManagedReleaseUseCase refusals", () => {
  it("refuses a capability whose validity window is not positive", async () => {
    const credential = credentialFixture({
      mode: "managed",
      releaseShareRef: SECRET_REF,
    });
    const token = await withZeroWindow(await capabilityFor(SECRET_REF));

    const release = await releaseUseCase(repositoryWith([credential])).execute(
      releaseInput(token),
    );

    expect(release.success).toBe(false);
    expect(release.releaseShare).toBeUndefined();
    expect(release.error).toBe("Capability has an invalid validity window");
  });

  it("refuses an operation Plus accepts but the release flow does not allow", async () => {
    const credential = credentialFixture({
      mode: "managed",
      releaseShareRef: SECRET_REF,
    });
    // ADMIN is a legal CapabilityOperation, so the signature verifies — the
    // refusal has to come from the use case's own allow-list.
    const token = await capabilityFor(SECRET_REF, "ADMIN");

    const release = await releaseUseCase(repositoryWith([credential])).execute(
      releaseInput(token),
    );

    expect(release.success).toBe(false);
    expect(release.error).toBe("Operation ADMIN not allowed for managed release");
  });

  it("refuses an empty vault binding before it resolves anything", async () => {
    const credential = credentialFixture({
      mode: "managed",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF);

    const release = await releaseUseCase(repositoryWith([credential])).execute(
      releaseInput(token, ""),
    );

    expect(release.success).toBe(false);
    expect(release.error).toBe("Managed release refused: vault binding missing");
  });

  it("refuses a personal credential even when the secretRef matches", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF);

    const release = await releaseUseCase(repositoryWith([credential])).execute(
      releaseInput(token),
    );

    expect(release.success).toBe(false);
    expect(release.error).toBe(
      "Credential is not managed (requires Plus authorization)",
    );
  });

  it("refuses when the Release Share was never stored, instead of falling back", async () => {
    const credential = credentialFixture({
      mode: "managed",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF);

    const release = await releaseUseCase(repositoryWith([credential]), {
      shareStore: emptyShareStore(),
    }).execute(releaseInput(token));

    expect(release.success).toBe(false);
    expect(release.releaseShare).toBeUndefined();
    expect(release.error).toBe("Release Share not found for secretRef");
  });

  it("reports a repository failure through the top-level catch", async () => {
    const token = await capabilityFor(SECRET_REF);

    const release = await releaseUseCase(
      repositoryWith([], { throwOnLookup: true }),
    ).execute(releaseInput(token));

    expect(release.success).toBe(false);
    expect(release.error).toBe("Managed release failed: credential lookup exploded");
  });
});

/* -------------------------------------------------------------------------- */
/* GetCredentialWithCapabilityUseCase — never exercised before                 */
/* -------------------------------------------------------------------------- */

describe("GetCredentialWithCapabilityUseCase", () => {
  it("refuses without a pinned key and names the missing variable", async () => {
    const repository = repositoryWith([
      credentialFixture({ mode: "personal", releaseShareRef: SECRET_REF }),
    ]);
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(repository, {
      plusPublicKey: null,
    }).execute(getCredentialInput(token, "any-id"));

    expect(result.success).toBe(false);
    expect(result.credential).toBeUndefined();
    expect(result.error).toContain("PLUS_PUBLIC_KEY is not configured");
  });

  it("refuses a missing binding context rather than skipping the check", async () => {
    const repository = repositoryWith([
      credentialFixture({ mode: "personal", releaseShareRef: SECRET_REF }),
    ]);
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(repository).execute({
      capabilityToken: token,
      expected: undefined as unknown as CapabilityBindingContext,
      credentialId: "any-id",
    });

    expect(result.success).toBe(false);
    expect(result.error).toBe(
      "Get credential refused: capability binding context missing",
    );
  });

  it("returns the credential the capability authorizes", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const repository = repositoryWith([credential]);
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(repository).execute(
      getCredentialInput(token, credential.id.toString()),
    );

    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.credential?.id).toBe(credential.id.toString());
    expect(result.credential?.releaseShareRef).toBe(SECRET_REF);
    expect(repository.findBySecretRef).toHaveBeenCalledWith(SECRET_REF);
  });

  it("refuses a capability signed by a key that is not the pinned one", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF, "VIEW");
    const rogue = generateEd25519KeyPair();

    const result = await getCredentialUseCase(repositoryWith([credential])).execute({
      ...getCredentialInput(token, credential.id.toString()),
      capabilityToken: {
        ...token,
        signature: (await signCapability(token.payload, rogue.privateKey)).signature,
      },
    });

    expect(result.success).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("refuses a capability whose validity window is not positive", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await withZeroWindow(await capabilityFor(SECRET_REF, "VIEW"));

    const result = await getCredentialUseCase(repositoryWith([credential])).execute(
      getCredentialInput(token, credential.id.toString()),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Capability has an invalid validity window");
  });

  it("refuses a replayed JTI", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(repositoryWith([credential]), {
      jtiStore: denyingJtiStore(),
    }).execute(getCredentialInput(token, credential.id.toString()));

    expect(result.success).toBe(false);
    expect(result.error).toBe("Replay detected: JTI already consumed");
  });

  it("refuses a secretRef the credential store does not know", async () => {
    const token = await capabilityFor(OTHER_REF, "VIEW");

    const result = await getCredentialUseCase(repositoryWith([])).execute(
      getCredentialInput(token, "any-id"),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Credential not found for secretRef");
  });

  it("refuses when the caller names a credential the capability does not authorize", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(repositoryWith([credential])).execute(
      getCredentialInput(token, crypto.randomUUID()),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Credential does not match the capability");
  });

  it("refuses an operation a managed credential does not support", async () => {
    const credential = credentialFixture({
      mode: "managed",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF, "ADMIN");

    const result = await getCredentialUseCase(repositoryWith([credential])).execute(
      getCredentialInput(token, credential.id.toString()),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Operation is not permitted for this credential");
  });

  it("refuses a non-VIEW operation against a personal credential", async () => {
    const credential = credentialFixture({
      mode: "personal",
      releaseShareRef: SECRET_REF,
    });
    const token = await capabilityFor(SECRET_REF, "AUTOFILL");

    const result = await getCredentialUseCase(repositoryWith([credential])).execute(
      getCredentialInput(token, credential.id.toString()),
    );

    expect(result.success).toBe(false);
    expect(result.error).toBe("Operation is not permitted for a personal credential");
  });

  it("reports a repository failure through the top-level catch", async () => {
    const token = await capabilityFor(SECRET_REF, "VIEW");

    const result = await getCredentialUseCase(
      repositoryWith([], { throwOnLookup: true }),
    ).execute(getCredentialInput(token, "any-id"));

    expect(result.success).toBe(false);
    expect(result.error).toBe("Get credential failed: credential lookup exploded");
  });
});
