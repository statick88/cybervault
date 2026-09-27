/**
 * O5.8 — Server-side managed authoring + real Release Share release.
 *
 * THE POINT OF THIS FILE
 * ----------------------
 * Defect D1 (odd/tasks/cybervault-final-security-architecture.md): every
 * existing suite passed while the managed path could not work end to end,
 * because no test ever drove a REAL Release Share through authoring →
 * capability → release → decrypt. Managed authoring was refused client-side, so
 * nothing ever minted a share, and `ManagedReleaseUseCase` returned
 * `credential.releaseShareRef` — the opaque reference — where the share belongs.
 *
 * The first test here is therefore a genuine round trip: it authors on the
 * server, releases through `ManagedReleaseUseCase` with a signed capability,
 * derives `HKDF(VEK || ReleaseShare, salt, context)` on the "client" side from
 * the returned share, opens the AES-GCM envelope and asserts the ORIGINAL
 * username and password come back. Against the pre-fix code it fails at
 * `expect(release.releaseShare).not.toBe(secretRef)`.
 *
 * Capabilities are signed with the same helpers the Plus suite uses
 * (`generateEd25519KeyPair` / `createCapabilityPayload` / `signCapability`) —
 * no second crypto path.
 */

import { ManagedAuthoringUseCase } from "../../src/application/use-cases/managed-authoring.use-case";
import { ManagedReleaseUseCase } from "../../src/application/use-cases/managed-release.use-case";
import { InMemoryReleaseShareStore } from "../../src/infrastructure/repositories/InMemoryReleaseShareStore";
import { deriveManagedEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import {
  deriveReleaseShareKek,
  loadReleaseShareKekSecret,
  ReleaseShareKekError,
  RELEASE_SHARE_KEK_INFO,
} from "../../src/infrastructure/crypto/release-share-kek";
import {
  generateEd25519KeyPair,
  createCapabilityPayload,
  signCapability,
} from "../../src/infrastructure/crypto/ed25519-capability";
import type {
  Ed25519KeyPair,
  SignedCapability,
  CapabilityBindingContext,
} from "../../src/infrastructure/crypto/ed25519-capability";
import { InMemoryJtiStore } from "../../src/infrastructure/crypto/jti-store";
import { Credential } from "../../src/domain/entities/credential";
import { VaultId } from "../../src/domain/value-objects/ids";
import type {
  ICredentialRepository,
} from "../../src/domain/repositories";
import type { AuthoredCredentialRecord } from "../../src/domain/services/autofill/credential-authoring";
import { base32ToBytes } from "../../src/domain/services/autofill/credential-authoring";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const USERNAME = "alice@example.com";
const PASSWORD = "correct-horse-battery-staple-9!";
const TOTP_SEED = "JBSWY3DPEHPK3PXP";
/** Raw user input; canonical form is `https://github.com:443`. */
const ORIGIN_INPUT = "https://github.com";
const ORIGIN_CANONICAL = "https://github.com:443";
const TITLE = "GitHub (corp)";
const VAULT_ID = VaultId.generate().toString();

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Client-side AES-GCM open — the exact `salt(32) | iv(12) | ciphertext+tag`
 * layout implemented by `src/ui/content-scripts/managed-decrypt.ts`. Kept as a
 * local copy for the same reason `tests/crypto/managed-decrypt.test.ts` does:
 * the production helper is not exported.
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

/** Rebuild the Credential entity exactly as a Core handler would persist it. */
function persistedCredential(record: AuthoredCredentialRecord): Credential {
  return Credential.fromPlainObject({
    id: record.id,
    vaultId: VAULT_ID,
    title: record.title,
    // Redacted hint, never the plaintext username.
    username: record.usernameHint,
    encryptedPassword: record.encryptedSecret,
    mode: "managed",
    salt: record.salt,
    version: record.version,
    releaseShareRef: record.releaseShareRef as string,
    // Deliberately NO `url`: the origin is never persisted server-side, only
    // folded into the opaque lookup token.
    tags: [],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
}

function repositoryWith(credentials: Credential[]): ICredentialRepository {
  return {
    save: jest.fn(async (credential: Credential) => credential),
    findById: jest.fn(async () => null),
    findByVaultId: jest.fn(async () => []),
    findBySecretRef: jest.fn(
      async (secretRef: string) =>
        credentials.find((c) => c.releaseShareRef === secretRef) ?? null,
    ),
    delete: jest.fn(async () => false),
    list: jest.fn(async () => credentials),
  };
}

/* -------------------------------------------------------------------------- */

describe("O5.8 server-side managed authoring (defect D1)", () => {
  let serverSecret: Uint8Array;
  let wrongServerSecret: Uint8Array;
  let vek: Uint8Array;
  let keyPair: Ed25519KeyPair;
  let store: InMemoryReleaseShareStore;
  let jtiStore: InMemoryJtiStore;
  let authoring: ManagedAuthoringUseCase;
  let secretRef: string;

  beforeEach(() => {
    serverSecret = crypto.getRandomValues(new Uint8Array(32));
    wrongServerSecret = crypto.getRandomValues(new Uint8Array(32));
    vek = crypto.getRandomValues(new Uint8Array(32));
    keyPair = generateEd25519KeyPair();
    store = new InMemoryReleaseShareStore();
    jtiStore = new InMemoryJtiStore();
    authoring = new ManagedAuthoringUseCase(store, serverSecret);
    secretRef = crypto.randomUUID();
  });

  afterEach(() => {
    vek.fill(0);
    serverSecret.fill(0);
    wrongServerSecret.fill(0);
    void jtiStore.close();
  });

  async function author(overrides: Record<string, unknown> = {}) {
    return authoring.execute({
      origin: ORIGIN_INPUT,
      username: USERNAME,
      password: PASSWORD,
      title: TITLE,
      totpSeedBase32: TOTP_SEED,
      vek,
      secretRef,
      id: crypto.randomUUID(),
      ...overrides,
    } as Parameters<ManagedAuthoringUseCase["execute"]>[0]);
  }

  async function signCapabilityFor(
    capabilitySecretRef: string,
  ): Promise<SignedCapability> {
    const payload = createCapabilityPayload({
      userId: "user-1",
      resourceId: capabilitySecretRef,
      operation: "AUTOFILL",
      secretRef: capabilitySecretRef,
      deviceId: "device-1",
      assurance: 2,
    });
    return signCapability(payload, keyPair.privateKey);
  }

  /**
   * Build the release input exactly as the route does: the token plus a
   * server-derived binding context and the vault named in the URL. By
   * default the context mirrors the capability (the "requested" resource IS
   * the capability's `secretRef`); negative tests override individual fields
   * to prove each binding is enforced independently.
   */
  function releaseInputFor(
    capabilityToken: SignedCapability,
    overrides: Partial<CapabilityBindingContext> = {},
  ) {
    return {
      capabilityToken,
      expected: {
        userId: capabilityToken.payload.userId,
        resourceId: capabilityToken.payload.resourceId,
        secretRef: capabilityToken.payload.secretRef,
        deviceId: capabilityToken.payload.deviceId ?? "",
        ...overrides,
      },
      vaultId: VAULT_ID,
    };
  }

  function releaseUseCase(
    repository: ICredentialRepository,
    secret: Uint8Array | null | undefined = serverSecret,
    withStore: InMemoryReleaseShareStore | null = store,
    plusPublicKey: Uint8Array | null = base64ToBinary(keyPair.publicKeyBase64),
  ): ManagedReleaseUseCase {
    return new ManagedReleaseUseCase(repository, jtiStore, withStore, secret, plusPublicKey);
  }

  /* ---------------------------------------------------------------------- */
  /* 1. The round trip — proves the defect and the fix                       */
  /* ---------------------------------------------------------------------- */

  it("authors server-side, releases the REAL Release Share and decrypts to the original credentials", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);
    const repository = repositoryWith([credential]);

    const capability = await signCapabilityFor(secretRef);
    const release = await releaseUseCase(repository).execute({
      ...releaseInputFor(capability),
    });

    // Defect D1: the pre-fix implementation returned the opaque reference here.
    expect(release.success).toBe(true);
    expect(release.releaseShare).toBeDefined();
    expect(release.releaseShare).not.toBe(secretRef);
    expect(release.releaseShare).not.toBe(result.record.releaseShareRef);
    expect(release.credentialId).toBe(credential.id.toString());

    /* ---- Client side: VEK + released share -> EntryKey -> plaintext ---- */
    const releaseShare = base64ToBinary(release.releaseShare as string);
    expect(releaseShare.byteLength).toBe(32);
    // The share must not be the reference bytes either.
    expect(binaryToBase64(releaseShare)).not.toBe(secretRef);

    const derived = await deriveManagedEntryKey(
      new Uint8Array(vek),
      releaseShare,
      base64ToBinary(result.record.salt),
      credential.id.toString(),
      result.record.version,
    );

    const plaintext = await decryptAESGCM(result.record.encryptedSecret, derived.keyBase64);
    expect(plaintext).not.toBeNull();

    const envelope = JSON.parse(plaintext as string) as { u: string; p: string };
    expect(envelope.u).toBe(USERNAME);
    expect(envelope.p).toBe(PASSWORD);
  });

  it("round-trips the optional TOTP seed through the same envelope", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.record.encryptedTotpSecret).toBeDefined();

    const credential = persistedCredential(result.record);
    const release = await releaseUseCase(repositoryWith([credential])).execute({
      ...releaseInputFor(await signCapabilityFor(secretRef)),
    });
    expect(release.success).toBe(true);

    const derived = await deriveManagedEntryKey(
      new Uint8Array(vek),
      base64ToBinary(release.releaseShare as string),
      base64ToBinary(result.record.salt),
      credential.id.toString(),
      result.record.version,
    );
    const plaintext = await decryptAESGCM(
      result.record.encryptedTotpSecret as string,
      derived.keyBase64,
    );
    expect(plaintext).not.toBeNull();

    // The stored plaintext is base64(seedBytes), exactly as the client path seals it.
    const decoded = base64ToBinary(plaintext as string);
    expect(binaryToBase64(decoded)).toBe(binaryToBase64(base32ToBytes(TOTP_SEED)));
  });

  it("never returns the Release Share at authoring time", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const serialized = JSON.stringify(result.record) + JSON.stringify(result.index);
    expect(serialized).not.toBe("");
    // The record carries only the opaque reference, never 32 bytes of share.
    expect(result.record.releaseShareRef).toBe(secretRef);
    expect(JSON.stringify(result.record)).not.toContain("releaseShare:");
    expect(store.snapshot()).toHaveLength(1);
    // What the store holds is ciphertext, not the share.
    expect(base64ToBinary(store.snapshot()[0].wrappedShare).byteLength).toBeGreaterThan(32);
  });

  /* ---------------------------------------------------------------------- */
  /* 2. Client-side derivation failures                                      */
  /* ---------------------------------------------------------------------- */

  it("decrypt returns null when the client uses the wrong VEK", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);
    const release = await releaseUseCase(repositoryWith([credential])).execute({
      ...releaseInputFor(await signCapabilityFor(secretRef)),
    });
    expect(release.success).toBe(true);

    const wrongVek = crypto.getRandomValues(new Uint8Array(32));
    const derived = await deriveManagedEntryKey(
      wrongVek,
      base64ToBinary(release.releaseShare as string),
      base64ToBinary(result.record.salt),
      credential.id.toString(),
      result.record.version,
    );
    expect(await decryptAESGCM(result.record.encryptedSecret, derived.keyBase64)).toBeNull();
  });

  /* ---------------------------------------------------------------------- */
  /* 3. Capability / authorization refusals                                  */
  /* ---------------------------------------------------------------------- */

  it("refuses a capability whose secretRef does not match the credential", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);

    // (a) Strict repository: the foreign reference simply does not resolve.
    const strictRepo = repositoryWith([credential]);
    const strict = await releaseUseCase(strictRepo).execute({
      ...releaseInputFor(await signCapabilityFor(crypto.randomUUID())),
    });
    expect(strict.success).toBe(false);
    expect(strict.error).toBe("Credential not found for secretRef");
    expect(strict.releaseShare).toBeUndefined();

    // (b) Defence in depth: even if lookup hands back the credential, the
    //     reference equality check must refuse the mismatched capability.
    const looseRepo = repositoryWith([credential]);
    (looseRepo.findBySecretRef as jest.Mock).mockResolvedValue(credential);
    const loose = await releaseUseCase(looseRepo).execute({
      ...releaseInputFor(await signCapabilityFor(crypto.randomUUID())),
    });
    expect(loose.success).toBe(false);
    expect(loose.error).toBe("Secret reference mismatch");
    expect(loose.releaseShare).toBeUndefined();
  });

  it("refuses to release with an already-consumed JTI (replay)", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);
    const repository = repositoryWith([credential]);
    const capability = await signCapabilityFor(secretRef);

    const first = await releaseUseCase(repository).execute({
      ...releaseInputFor(capability),
    });
    expect(first.success).toBe(true);

    const replay = await releaseUseCase(repository).execute({
      ...releaseInputFor(capability),
    });
    expect(replay.success).toBe(false);
    expect(replay.error).toContain("Replay");
    expect(replay.releaseShare).toBeUndefined();
  });

  /* ---------------------------------------------------------------------- */
  /* 4. Wrong Release Share KEK — fail closed, no fallback                   */
  /* ---------------------------------------------------------------------- */

  it("refuses release when the Release Share KEK secret is wrong, with no fallback to the reference", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);
    const repository = repositoryWith([credential]);

    const wrongKeyRelease = await releaseUseCase(repository, wrongServerSecret).execute({
      ...releaseInputFor(await signCapabilityFor(secretRef)),
    });

    expect(wrongKeyRelease.success).toBe(false);
    expect(wrongKeyRelease.releaseShare).toBeUndefined();
    expect(wrongKeyRelease.error).toContain("unwrapping failed");
    // The old defect handed back the opaque reference; make sure nothing does.
    expect(wrongKeyRelease.error).not.toContain(secretRef);
    expect(wrongKeyRelease.releaseShare).not.toBe(secretRef);

    // The same capability shape still refuses when no store is wired at all.
    const unconfigured = await releaseUseCase(repository, serverSecret, null).execute({
      ...releaseInputFor(await signCapabilityFor(secretRef)),
    });
    expect(unconfigured.success).toBe(false);
    expect(unconfigured.releaseShare).toBeUndefined();
    expect(unconfigured.error).toContain("not configured");
    expect(unconfigured.error).not.toContain(secretRef);
  });

  it("refuses release when the Release Share KEK secret is missing, with no default used", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);
    const release = await releaseUseCase(repositoryWith([credential]), null).execute({
      ...releaseInputFor(await signCapabilityFor(secretRef)),
    });

    expect(release.success).toBe(false);
    expect(release.releaseShare).toBeUndefined();
    expect(release.error).toContain("not configured");
  });

  /* ---------------------------------------------------------------------- */
  /* 5. Release Share KEK configuration — typed, fail-closed                 */
  /* ---------------------------------------------------------------------- */

  describe("Release Share KEK secret validation", () => {
    it("throws a typed SECRET_MISSING error when the secret is absent", async () => {
      await expect(deriveReleaseShareKek(undefined)).rejects.toMatchObject({
        name: "ReleaseShareKekError",
        code: "SECRET_MISSING",
      });
      await expect(deriveReleaseShareKek(null)).rejects.toBeInstanceOf(ReleaseShareKekError);
      await expect(deriveReleaseShareKek(new Uint8Array(0))).rejects.toMatchObject({
        code: "SECRET_MISSING",
      });
    });

    it("throws a typed SECRET_WRONG_LENGTH error for a short secret", async () => {
      await expect(deriveReleaseShareKek(new Uint8Array(16))).rejects.toMatchObject({
        name: "ReleaseShareKekError",
        code: "SECRET_WRONG_LENGTH",
      });
      await expect(deriveReleaseShareKek(new Uint8Array(31))).rejects.toMatchObject({
        code: "SECRET_WRONG_LENGTH",
      });
      // A 32-byte secret is accepted — nothing else is.
      await expect(deriveReleaseShareKek(new Uint8Array(32))).resolves.toBeInstanceOf(Uint8Array);
    });

    it("uses an HKDF info string distinct from the domain-index and entry-key contexts", () => {
      expect(RELEASE_SHARE_KEK_INFO).toBe("cybervault|release-share-kek|v1");
      expect(RELEASE_SHARE_KEK_INFO).not.toContain("domain-index");
      expect(RELEASE_SHARE_KEK_INFO).not.toContain("entry");
    });

    it("loadReleaseShareKekSecret accepts only base64 of exactly 32 bytes", () => {
      const good = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));
      expect(loadReleaseShareKekSecret(good)).toBeInstanceOf(Uint8Array);
      expect(loadReleaseShareKekSecret(undefined)).toBeNull();
      expect(loadReleaseShareKekSecret("")).toBeNull();
      expect(loadReleaseShareKekSecret("   ")).toBeNull();
      expect(loadReleaseShareKekSecret(binaryToBase64(new Uint8Array(16)))).toBeNull();
      expect(loadReleaseShareKekSecret("not base64 !!!")).toBeNull();
    });

    it("authoring refuses a missing/short KEK secret before touching the store", async () => {
      const shortSecretStore = new InMemoryReleaseShareStore();
      const shortAuthoring = new ManagedAuthoringUseCase(shortSecretStore, new Uint8Array(16));

      const rejected = await shortAuthoring.execute({
        origin: ORIGIN_INPUT,
        username: USERNAME,
        password: PASSWORD,
        title: TITLE,
        vek,
        secretRef: crypto.randomUUID(),
      });

      expect(rejected.ok).toBe(false);
      if (rejected.ok) return;
      expect(rejected.reason).toBe("RELEASE_SHARE_KEK_INVALID");
      expect(rejected.detail).toContain("32 bytes");
      expect(shortSecretStore.snapshot()).toHaveLength(0);

      const missingAuthoring = new ManagedAuthoringUseCase(shortSecretStore, null);
      const missing = await missingAuthoring.execute({
        origin: ORIGIN_INPUT,
        username: USERNAME,
        password: PASSWORD,
        title: TITLE,
        vek,
        secretRef: crypto.randomUUID(),
      });
      expect(missing.ok).toBe(false);
      if (missing.ok) return;
      expect(missing.reason).toBe("RELEASE_SHARE_KEK_INVALID");
      expect(shortSecretStore.snapshot()).toHaveLength(0);
    });
  });

  /* ---------------------------------------------------------------------- */
  /* 6. No plaintext at rest                                                 */
  /* ---------------------------------------------------------------------- */

  it("persists no plaintext username, password, TOTP seed or origin", async () => {
    const result = await author();
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const credential = persistedCredential(result.record);

    // Everything Core would actually write down: the credential row, the
    // wrapped Release Share and the opaque index.
    const persisted = JSON.stringify({
      credential: credential.toPlainObject(),
      releaseShares: store.snapshot(),
      index: result.index,
      lookupToken: result.lookupToken,
    });

    expect(persisted).not.toContain(USERNAME);
    expect(persisted).not.toContain(PASSWORD);
    expect(persisted).not.toContain(TOTP_SEED);
    expect(persisted).not.toContain(binaryToBase64(base32ToBytes(TOTP_SEED)));
    expect(persisted).not.toContain(ORIGIN_CANONICAL);
    expect(persisted).not.toContain(ORIGIN_INPUT);
    expect(persisted).not.toContain("github.com");

    // Username is encrypted with the password; only a redacted hint is stored.
    expect(credential.username).toBe(result.record.usernameHint);
    expect(credential.username).not.toBe(USERNAME);
    expect(credential.username).not.toContain("alice");
    expect(credential.toPlainObject().url).toBeUndefined();

    // The ciphertext itself must not leak the secrets either.
    expect(result.record.encryptedSecret).not.toContain(PASSWORD);
    expect(result.record.encryptedSecret).not.toContain(USERNAME);

    // `record.origin` is returned for ExactMatch binding by design, but it is
    // NOT part of what was persisted above — assert that split explicitly.
    expect(result.record.origin).toBe(ORIGIN_CANONICAL);
    expect(persisted).not.toContain(result.record.origin);

    // The lookup token is an opaque 256-bit HMAC, not the origin.
    expect(result.lookupToken).toMatch(/^[0-9a-f]{64}$/);
    expect(result.index.byToken[result.lookupToken]).toContain(result.record.id);
  });

  /* ---------------------------------------------------------------------- */
  /* 7. Origin validation — identical semantics to the client path           */
  /* ---------------------------------------------------------------------- */

  describe("origin validation", () => {
    it("rejects a non-absolute origin", async () => {
      const bare = await author({ origin: "github.com", secretRef: crypto.randomUUID() });
      expect(bare.ok).toBe(false);
      if (bare.ok) return;
      expect(bare.reason).toBe("ORIGIN_NOT_ABSOLUTE");

      const schemeless = await author({ origin: "https//github.com", secretRef: crypto.randomUUID() });
      expect(schemeless.ok).toBe(false);
      if (schemeless.ok) return;
      expect(schemeless.reason).toBe("ORIGIN_NOT_ABSOLUTE");

      const empty = await author({ origin: "   ", secretRef: crypto.randomUUID() });
      expect(empty.ok).toBe(false);
      if (empty.ok) return;
      expect(empty.reason).toBe("ORIGIN_MISSING");

      expect(store.snapshot()).toHaveLength(0);
    });

    it("rejects a non-http(s) scheme", async () => {
      const ftp = await author({ origin: "ftp://example.com", secretRef: crypto.randomUUID() });
      expect(ftp.ok).toBe(false);
      if (ftp.ok) return;
      expect(ftp.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

      const js = await author({
        origin: "javascript://alert(1)",
        secretRef: crypto.randomUUID(),
      });
      expect(js.ok).toBe(false);
      if (js.ok) return;
      expect(js.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

      const file = await author({ origin: "file:///etc/passwd", secretRef: crypto.randomUUID() });
      expect(file.ok).toBe(false);
      if (file.ok) return;
      expect(file.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");

      expect(store.snapshot()).toHaveLength(0);
    });

    it("accepts an absolute http/https origin and canonicalizes it", async () => {
      const result = await author({ origin: "  https://GitHub.com:443/  " });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.record.origin).toBe(ORIGIN_CANONICAL);
      expect(store.snapshot()).toHaveLength(1);
      expect(store.snapshot()[0].secretRef).toBe(secretRef);
    });
  });

  /* ---------------------------------------------------------------------- */
  /* 8. Input hygiene                                                        */
  /* ---------------------------------------------------------------------- */

  it("keeps the caller's VEK intact (it zeroizes its own copy)", async () => {
    const before = binaryToBase64(vek);
    const result = await author();
    expect(result.ok).toBe(true);
    expect(binaryToBase64(vek)).toBe(before);
  });

  it("refuses a missing secretRef, username, password and VEK", async () => {
    const noRef = await author({ secretRef: "" });
    expect(noRef.ok).toBe(false);
    if (!noRef.ok) expect(noRef.reason).toBe("SECRET_REF_REQUIRED");

    const noUser = await author({ username: "  ", secretRef: crypto.randomUUID() });
    if (!noUser.ok) expect(noUser.reason).toBe("USERNAME_REQUIRED");

    const noPass = await author({ password: "", secretRef: crypto.randomUUID() });
    if (!noPass.ok) expect(noPass.reason).toBe("PASSWORD_REQUIRED");

    const noVek = await author({ vek: null, secretRef: crypto.randomUUID() });
    if (!noVek.ok) expect(noVek.reason).toBe("VEK_MISSING");

    const badTotp = await author({
      totpSeedBase32: "!!!",
      secretRef: crypto.randomUUID(),
    });
    if (!badTotp.ok) expect(badTotp.reason).toBe("TOTP_SEED_INVALID");

    expect(store.snapshot()).toHaveLength(0);
  });

  /* ---------------------------------------------------------------------- */
  /* 9. CRITICAL-1 (WU-1): pinned verification key + declared bindings       */
  /* ---------------------------------------------------------------------- */

  describe("capability key pinning and bindings (CRITICAL-1)", () => {
    async function authoredCredential(): Promise<Credential> {
      const result = await author();
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("authoring failed");
      return persistedCredential(result.record);
    }

    it("rejects a capability signed by a key that is not the pinned one", async () => {
      const credential = await authoredCredential();
      const foreign = generateEd25519KeyPair();

      const release = await releaseUseCase(
        repositoryWith([credential]),
        serverSecret,
        store,
        base64ToBinary(foreign.publicKeyBase64),
      ).execute(releaseInputFor(await signCapabilityFor(secretRef)));

      expect(release.success).toBe(false);
      expect(release.error).toBe("Invalid signature");
      expect(release.releaseShare).toBeUndefined();
    });

    it("refuses when PLUS_PUBLIC_KEY is absent instead of falling back to any key", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential]), serverSecret, store, null)
        .execute(releaseInputFor(await signCapabilityFor(secretRef)));

      expect(release.success).toBe(false);
      expect(release.error).toContain("PLUS_PUBLIC_KEY");
      expect(release.releaseShare).toBeUndefined();
    });

    it("rejects a mismatched userId (binding 1 of 4)", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential])).execute(
        releaseInputFor(await signCapabilityFor(secretRef), { userId: "user-2" }),
      );

      expect(release.success).toBe(false);
      expect(release.error).toContain("userId");
      expect(release.releaseShare).toBeUndefined();
    });

    it("rejects a mismatched resourceId (binding 2 of 4)", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential])).execute(
        releaseInputFor(await signCapabilityFor(secretRef), { resourceId: crypto.randomUUID() }),
      );

      expect(release.success).toBe(false);
      expect(release.error).toContain("resourceId");
      expect(release.releaseShare).toBeUndefined();
    });

    it("rejects a mismatched secretRef (binding 3 of 4)", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential])).execute(
        releaseInputFor(await signCapabilityFor(secretRef), { secretRef: crypto.randomUUID() }),
      );

      expect(release.success).toBe(false);
      expect(release.error).toContain("secretRef");
      expect(release.releaseShare).toBeUndefined();
    });

    it("rejects a mismatched deviceId (binding 4 of 4)", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential])).execute(
        releaseInputFor(await signCapabilityFor(secretRef), { deviceId: "device-9" }),
      );

      expect(release.success).toBe(false);
      expect(release.error).toContain("deviceId");
      expect(release.releaseShare).toBeUndefined();
    });

    it("refuses an incomplete or absent binding context instead of skipping the check", async () => {
      const credential = await authoredCredential();
      const capability = await signCapabilityFor(secretRef);

      const noContext = await releaseUseCase(repositoryWith([credential])).execute({
        capabilityToken: capability,
        expected: undefined as unknown as CapabilityBindingContext,
        vaultId: VAULT_ID,
      });
      expect(noContext.success).toBe(false);
      expect(noContext.error).toContain("binding context missing");

      const incomplete = await releaseUseCase(repositoryWith([credential])).execute({
        capabilityToken: capability,
        expected: {
          userId: "user-1",
          resourceId: secretRef,
          secretRef,
        } as unknown as CapabilityBindingContext,
        vaultId: VAULT_ID,
      });
      expect(incomplete.success).toBe(false);
      expect(incomplete.error).toContain("incomplete");
      expect(incomplete.releaseShare).toBeUndefined();
    });

    it("rejects a credential that lives in a different vault than the one in the URL", async () => {
      const credential = await authoredCredential();

      const release = await releaseUseCase(repositoryWith([credential])).execute({
        ...releaseInputFor(await signCapabilityFor(secretRef)),
        vaultId: VaultId.generate().toString(),
      });

      expect(release.success).toBe(false);
      expect(release.error).toBe("Credential does not belong to the requested vault");
      expect(release.releaseShare).toBeUndefined();
    });
  });
});
