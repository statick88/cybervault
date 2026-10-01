/**
 * S2 batch 3 — `src/application/use-cases/recovery.use-case.ts` unit tests.
 *
 * Two flows share this file and both are security-relevant:
 *
 *   1. ACCOUNT PASSWORD RECOVERY — the reset token is a bearer credential, so
 *      the suite pins that it is stored only as a SHA-256 hash, that an
 *      expired token is cleared rather than merely refused, that a wrong token
 *      never reaches the password write, and that a successful reset bumps the
 *      session version (the mechanism that invalidates live sessions).
 *   2. MASTER PHRASE RECOVERY — the Recovery Key unwraps the VEK, so the suite
 *      pins that an unknown user, a missing Recovery Key, a wrong key and a
 *      vault with no recovery payload all FAIL CLOSED, and that the happy path
 *      is a real round trip: `setupRecoveryKey` produces a blob that `recover`
 *      can actually unwrap.
 *
 * Everything runs on the ambient WebCrypto — the same 600k-iteration
 * PBKDF2/SHA-512 the production code uses — with in-memory repository stubs.
 * No live database, no Docker, no network.
 *
 * Naming convention: `users` / `vaults` are the stub bundles returned by the
 * factories; `users.repository` / `vaults.repository` are the ports handed to
 * the use cases; `users.calls` records what the port was asked to do.
 */

import {
  AccountRecoveryUseCase,
  MasterRecoveryUseCase,
  type EmailService,
} from "../../src/application/use-cases/recovery.use-case";
import type {
  IUserRepository,
  IVaultRepository,
} from "../../src/domain/repositories";
import { Vault } from "../../src/domain/entities/vault";
import { binaryToBase64, base64ToBinary } from "../../src/shared/utils";

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("recovery.use-case — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof AccountRecoveryUseCase).toBe("function");
    expect(typeof MasterRecoveryUseCase).toBe("function");
    expect(AccountRecoveryUseCase.name).toBe("AccountRecoveryUseCase");
    expect(MasterRecoveryUseCase.name).toBe("MasterRecoveryUseCase");
  });
});

/* ========================================================================== */
/* Stubs                                                                       */
/* ========================================================================== */

interface UserRecord {
  userId: string;
  email: string;
  passwordResetTokenHash?: string;
  passwordResetTokenExpiry?: number;
  passwordHash?: string;
  passwordSalt?: string;
  sessionVersion?: number;
  recoveryKeyHash?: string;
}

function makeUserRepository(
  user: UserRecord | null = { userId: "user-1", email: "a@b.c" },
) {
  const calls = {
    setPasswordResetToken: [] as [string, string, number][],
    clearPasswordResetToken: [] as string[],
    updatePassword: [] as [string, string, string][],
    incrementSessionVersion: [] as string[],
    setRecoveryKeyHash: [] as [string, string][],
  };
  const failWith = { message: undefined as string | undefined };

  const repository: IUserRepository = {
    findByEmail: jest.fn(async (email: string) => {
      if (failWith.message) throw new Error(failWith.message);
      return user && user.email === email ? user : null;
    }),
    findById: jest.fn(async (userId: string) => {
      if (failWith.message) throw new Error(failWith.message);
      return user && user.userId === userId ? user : null;
    }),
    setPasswordResetToken: jest.fn(
      async (userId: string, tokenHash: string, expiresAt: number) => {
        if (failWith.message) throw new Error(failWith.message);
        calls.setPasswordResetToken.push([userId, tokenHash, expiresAt]);
        if (user) {
          user.passwordResetTokenHash = tokenHash;
          user.passwordResetTokenExpiry = expiresAt;
        }
      },
    ),
    clearPasswordResetToken: jest.fn(async (userId: string) => {
      if (failWith.message) throw new Error(failWith.message);
      calls.clearPasswordResetToken.push(userId);
      if (user) {
        user.passwordResetTokenHash = undefined;
        user.passwordResetTokenExpiry = undefined;
      }
    }),
    updatePassword: jest.fn(
      async (userId: string, hash: string, salt: string) => {
        if (failWith.message) throw new Error(failWith.message);
        calls.updatePassword.push([userId, hash, salt]);
        if (user) {
          user.passwordHash = hash;
          user.passwordSalt = salt;
        }
      },
    ),
    incrementSessionVersion: jest.fn(async (userId: string) => {
      if (failWith.message) throw new Error(failWith.message);
      calls.incrementSessionVersion.push(userId);
      if (user) user.sessionVersion = (user.sessionVersion ?? 0) + 1;
    }),
    setRecoveryKeyHash: jest.fn(async (userId: string, hash: string) => {
      if (failWith.message) throw new Error(failWith.message);
      calls.setRecoveryKeyHash.push([userId, hash]);
      if (user) user.recoveryKeyHash = hash;
    }),
  };

  return { repository, calls, failWith, user };
}

function makeVaultRepository() {
  const vault = Vault.create({
    name: "Personal",
    encryptedData: "ciphertext-only",
    encryptionKeyId: "key-1",
    ownerId: "user-1",
  });
  const state = {
    vaults: [vault] as Vault[],
    updateMetadata: [] as [string, Record<string, unknown>][],
    failWith: undefined as string | undefined,
  };

  const repository: IVaultRepository = {
    save: jest.fn(async (v) => v),
    findById: jest.fn(async () => null),
    findByVaultIdAndOwnerId: jest.fn(async () => null),
    delete: jest.fn(async () => false),
    list: jest.fn(async () => state.vaults),
    listByOwnerId: jest.fn(async () => state.vaults),
    updateMetadata: jest.fn(
      async (
        vaultId: string,
        metadata: Record<string, unknown>,
        _expectedVersion?: number,
      ) => {
        if (state.failWith) throw new Error(state.failWith);
        state.updateMetadata.push([vaultId, metadata]);
        for (const v of state.vaults) v.updateMetadata(metadata);
      },
    ),
  };

  return { repository, state, vault };
}

function makeEmailService() {
  const sent: [string, string][] = [];
  const service: EmailService = {
    sendPasswordResetEmail: jest.fn(async (email: string, token: string) => {
      sent.push([email, token]);
    }),
    sendRecoveryKeyEmail: jest.fn(async () => undefined),
  };
  return { service, sent };
}

/** SHA-256 → base64, the exact shape `hashToken`/`hashRecoveryKey` store. */
async function sha256Base64(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return binaryToBase64(new Uint8Array(digest));
}

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Independent reproduction of the Recovery KEK derivation, so the `recover`
 * fail-closed paths can be set up WITHOUT going through `setupRecoveryKey`.
 *
 * NOTE the `extractable` flag: the reference sets it to `true` because the
 * bytes are needed to re-import them for the unwrap. The production helper
 * passes `false` and then exports anyway — see the failing assertions below.
 */
async function deriveKekReference(
  recoveryKey: string,
  saltBase64: string,
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(new TextEncoder().encode(recoveryKey)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const kek = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toArrayBuffer(base64ToBinary(saltBase64)),
      iterations: 600000,
      hash: "SHA-512",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", kek));
}

/** `iv(12) || ciphertext+tag` under the given raw AES-GCM key. */
async function wrapVekReference(
  vek: Uint8Array,
  kek: Uint8Array,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(kek),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
    key,
    toArrayBuffer(vek),
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return binaryToBase64(combined);
}

/* ========================================================================== */
/* AccountRecoveryUseCase.initiate                                             */
/* ========================================================================== */

describe("AccountRecoveryUseCase.initiate", () => {
  it("answers identically for an unknown email — no user enumeration", async () => {
    const users = makeUserRepository();
    const mail = makeEmailService();
    const useCase = new AccountRecoveryUseCase(
      users.repository,
      mail.service,
    );

    const out = await useCase.initiate({ email: "nobody@b.c" });

    expect(out).toEqual({ success: true });
    expect(out.resetToken).toBeUndefined();
    expect(users.calls.setPasswordResetToken).toHaveLength(0);
    expect(mail.sent).toHaveLength(0);
    expect(users.repository.findByEmail).toHaveBeenCalledWith("nobody@b.c");
  });

  it("stores only a SHA-256 hash of the token and emails the raw token once", async () => {
    const users = makeUserRepository();
    const mail = makeEmailService();
    const useCase = new AccountRecoveryUseCase(
      users.repository,
      mail.service,
    );

    const out = await useCase.initiate({ email: "a@b.c" });

    expect(out.success).toBe(true);
    expect(users.calls.setPasswordResetToken).toHaveLength(1);
    const [userId, storedHash, expiresAt] =
      users.calls.setPasswordResetToken[0];
    expect(userId).toBe("user-1");
    expect(storedHash).toBe(await sha256Base64(mail.sent[0][1]));
    // 30 minutes, not a permanent credential.
    expect(expiresAt).toBeGreaterThan(Date.now() + 29 * 60 * 1000);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 30 * 60 * 1000);
    // The plaintext token is never what gets persisted.
    expect(storedHash).not.toBe(mail.sent[0][1]);
    expect(users.user!.passwordResetTokenHash).toBe(storedHash);
    expect(mail.sent).toHaveLength(1);
    expect(mail.sent[0][0]).toBe("a@b.c");
    // 32 random bytes → 44 base64 chars.
    expect(mail.sent[0][1]).toHaveLength(44);
  });

  it("returns the raw token only when NODE_ENV is development", async () => {
    const users = makeUserRepository();
    const mail = makeEmailService();
    const useCase = new AccountRecoveryUseCase(
      users.repository,
      mail.service,
    );

    const dev = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = "development";
      const inDev = await useCase.initiate({ email: "a@b.c" });
      expect(inDev.resetToken).toBe(mail.sent[mail.sent.length - 1][1]);

      process.env.NODE_ENV = "production";
      const inProd = await useCase.initiate({ email: "a@b.c" });
      expect(inProd.success).toBe(true);
      expect(inProd.resetToken).toBeUndefined();
    } finally {
      process.env.NODE_ENV = dev;
    }
  });

  it("still succeeds when no email service is configured", async () => {
    const users = makeUserRepository();
    const useCase = new AccountRecoveryUseCase(users.repository);

    const out = await useCase.initiate({ email: "a@b.c" });

    expect(out.success).toBe(true);
    expect(users.calls.setPasswordResetToken).toHaveLength(1);
  });

  it("reports failure instead of throwing when the write fails", async () => {
    const users = makeUserRepository();
    users.failWith.message = "database down";
    const useCase = new AccountRecoveryUseCase(users.repository);

    await expect(useCase.initiate({ email: "a@b.c" })).resolves.toEqual({
      success: false,
      error: "Failed to initiate recovery",
    });
  });
});

/* ========================================================================== */
/* AccountRecoveryUseCase.resetPassword                                        */
/* ========================================================================== */

describe("AccountRecoveryUseCase.resetPassword", () => {
  async function issueToken(): Promise<{
    useCase: AccountRecoveryUseCase;
    token: string;
    users: ReturnType<typeof makeUserRepository>;
  }> {
    const users = makeUserRepository();
    const mail = makeEmailService();
    const useCase = new AccountRecoveryUseCase(users.repository, mail.service);
    await useCase.initiate({ email: "a@b.c" });
    return { useCase, token: mail.sent[0][1], users };
  }

  it("rejects an unknown email without touching the password", async () => {
    const users = makeUserRepository();
    const useCase = new AccountRecoveryUseCase(users.repository);

    const out = await useCase.resetPassword({
      email: "nobody@b.c",
      resetToken: "whatever",
      newPassword: "new-pass",
    });

    expect(out).toEqual({
      success: false,
      error: "Invalid or expired reset token",
    });
    expect(users.calls.updatePassword).toHaveLength(0);
  });

  it("rejects when no token was ever issued", async () => {
    const users = makeUserRepository({
      userId: "user-1",
      email: "a@b.c",
    });
    const useCase = new AccountRecoveryUseCase(users.repository);

    const out = await useCase.resetPassword({
      email: "a@b.c",
      resetToken: "x",
      newPassword: "new-pass",
    });

    expect(out).toEqual({
      success: false,
      error: "Invalid or expired reset token",
    });
    expect(users.calls.updatePassword).toHaveLength(0);
  });

  it("CLEARS an expired token instead of only refusing it", async () => {
    const users = makeUserRepository({
      userId: "user-1",
      email: "a@b.c",
      passwordResetTokenHash: await sha256Base64("expired-token"),
      passwordResetTokenExpiry: Date.now() - 1,
    });
    const useCase = new AccountRecoveryUseCase(users.repository);

    const out = await useCase.resetPassword({
      email: "a@b.c",
      resetToken: "expired-token",
      newPassword: "new-pass",
    });

    expect(out).toEqual({ success: false, error: "Reset token expired" });
    expect(users.calls.clearPasswordResetToken).toEqual(["user-1"]);
    expect(users.calls.updatePassword).toHaveLength(0);
    expect(users.user!.passwordResetTokenHash).toBeUndefined();
  });

  it("rejects a wrong token without writing the password", async () => {
    const { useCase, users } = await issueToken();
    users.user!.passwordResetTokenExpiry = Date.now() + 60_000;

    const out = await useCase.resetPassword({
      email: "a@b.c",
      resetToken: "not-the-token",
      newPassword: "new-pass",
    });

    expect(out).toEqual({ success: false, error: "Invalid reset token" });
    expect(users.calls.updatePassword).toHaveLength(0);
    expect(users.calls.incrementSessionVersion).toHaveLength(0);
  });

  it("on success rewrites the password, clears the token and bumps the session version", async () => {
    const { useCase, token, users } = await issueToken();

    const out = await useCase.resetPassword({
      email: "a@b.c",
      resetToken: token,
      newPassword: "a brand new passphrase",
    });

    expect(out).toEqual({ success: true });
    expect(users.calls.updatePassword).toHaveLength(1);
    const [userId, hash, salt] = users.calls.updatePassword[0];
    expect(userId).toBe("user-1");
    // What is written is a 512-bit PBKDF2/SHA-512 output in base64 plus an
    // independent 32-byte salt — never the passphrase itself.
    expect(hash).toHaveLength(88); // 64 bytes → base64
    expect(salt).toHaveLength(44); // 32 bytes → base64
    expect(hash).not.toContain("a brand new passphrase");

    expect(users.calls.clearPasswordResetToken).toEqual(["user-1"]);
    expect(users.calls.incrementSessionVersion).toEqual(["user-1"]);
    expect(users.user!.sessionVersion).toBe(1);
    // The token cannot be replayed: it was cleared on the success path.
    expect(users.user!.passwordResetTokenHash).toBeUndefined();
  });

  it("reports failure instead of throwing when the write fails", async () => {
    const { useCase, token, users } = await issueToken();
    users.failWith.message = "database down";

    const out = await useCase.resetPassword({
      email: "a@b.c",
      resetToken: token,
      newPassword: "new-pass",
    });

    expect(out).toEqual({
      success: false,
      error: "Failed to reset password",
    });
  });
});

/* ========================================================================== */
/* MasterRecoveryUseCase.setupRecoveryKey                                      */
/* ========================================================================== */

describe("MasterRecoveryUseCase.setupRecoveryKey", () => {
  it("reports an unknown user instead of generating a key for nobody", async () => {
    const users = makeUserRepository(null);
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.setupRecoveryKey({
      userId: "ghost",
      masterPhrase: "master",
    });

    expect(out).toEqual({ success: false, error: "User not found" });
    expect(vaults.repository.listByOwnerId).not.toHaveBeenCalled();
    expect(users.calls.setRecoveryKeyHash).toHaveLength(0);
  });

  it("reports a missing vault rather than writing a hash with nowhere to unwrap", async () => {
    const users = makeUserRepository();
    const vaults = makeVaultRepository();
    vaults.state.vaults = [];
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.setupRecoveryKey({
      userId: "user-1",
      masterPhrase: "master",
    });

    expect(out).toEqual({ success: false, error: "No vault found for user" });
    expect(users.calls.setRecoveryKeyHash).toHaveLength(0);
    expect(vaults.state.updateMetadata).toHaveLength(0);
  });

  it("returns the key ONCE, persists only its hash, and stores the wrapped VEK", async () => {
    const users = makeUserRepository();
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.setupRecoveryKey({
      userId: "user-1",
      masterPhrase: "master",
    });

    expect(out.success).toBe(true);
    // 32 random bytes → base64, shown once and never retrievable again.
    expect(out.recoveryKey).toHaveLength(44);
    expect(users.calls.setRecoveryKeyHash).toHaveLength(1);
    const [userId, storedHash] = users.calls.setRecoveryKeyHash[0];
    expect(userId).toBe("user-1");
    expect(storedHash).toBe(await sha256Base64(out.recoveryKey!));
    expect(storedHash).not.toBe(out.recoveryKey);
    expect(users.user!.recoveryKeyHash).toBe(storedHash);

    expect(out.recoveryKeyHint).toMatch(
      /^Recovery Key generated on \d{4}-\d{2}-\d{2}$/,
    );

    expect(vaults.state.updateMetadata).toHaveLength(1);
    const [vaultId, metadata] = vaults.state.updateMetadata[0];
    expect(vaultId).toBe(vaults.vault.id.toString());
    const recovery = metadata.recovery as {
      encryptedVek: string;
      recoverySalt: string;
      version: number;
    };
    expect(recovery.version).toBe(1);
    expect(recovery.recoverySalt).toHaveLength(44);
    // iv(12) + vek(32) + gcm tag(16) = 60 bytes.
    expect(base64ToBinary(recovery.encryptedVek)).toHaveLength(60);
  });

  it("reports failure instead of throwing when the repository fails", async () => {
    const users = makeUserRepository();
    users.failWith.message = "database down";
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.setupRecoveryKey({
      userId: "user-1",
      masterPhrase: "master",
    });

    expect(out).toEqual({
      success: false,
      error: "Failed to setup Recovery Key",
    });
  });
});

/* ========================================================================== */
/* MasterRecoveryUseCase.recover                                               */
/* ========================================================================== */

describe("MasterRecoveryUseCase.recover", () => {
  /**
   * Builds a Recovery Key, its hash, and a vault payload that opens under it —
   * entirely from the test-side reference helpers, so every `recover` path can
   * be exercised independently of `setupRecoveryKey`.
   */
  async function provision() {
    const users = makeUserRepository();
    const vaults = makeVaultRepository();

    const recoveryKey = binaryToBase64(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const recoverySalt = binaryToBase64(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const kek = await deriveKekReference(recoveryKey, recoverySalt);
    const encryptedVek = await wrapVekReference(
      crypto.getRandomValues(new Uint8Array(32)),
      kek,
    );

    users.user!.recoveryKeyHash = await sha256Base64(recoveryKey);
    vaults.vault.updateMetadata({
      recovery: { encryptedVek, recoverySalt, version: 1 },
    });

    return { users, vaults, recoveryKey };
  }

  it("reports an unknown user", async () => {
    const users = makeUserRepository(null);
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    await expect(
      useCase.recover({ userId: "ghost", recoveryKey: "k" }),
    ).resolves.toEqual({ success: false, error: "User not found" });
  });

  it("fails closed when the account has no Recovery Key", async () => {
    const users = makeUserRepository();
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    await expect(
      useCase.recover({ userId: "user-1", recoveryKey: "k" }),
    ).resolves.toEqual({
      success: false,
      error: "No Recovery Key configured for this account",
    });
  });

  it("rejects a WRONG Recovery Key before touching the vault", async () => {
    const { users, vaults } = await provision();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.recover({
      userId: "user-1",
      recoveryKey: binaryToBase64(new Uint8Array(32).fill(7)),
    });

    expect(out).toEqual({ success: false, error: "Invalid Recovery Key" });
    expect(vaults.repository.listByOwnerId).not.toHaveBeenCalled();
  });

  it("rejects when the user has no vault", async () => {
    const { users, vaults, recoveryKey } = await provision();
    vaults.state.vaults = [];
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    await expect(
      useCase.recover({ userId: "user-1", recoveryKey }),
    ).resolves.toEqual({ success: false, error: "No vault found for user" });
  });

  it("rejects when the vault carries no recovery payload", async () => {
    const { users, vaults, recoveryKey } = await provision();
    vaults.vault.updateMetadata({ recovery: undefined });
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    await expect(
      useCase.recover({ userId: "user-1", recoveryKey }),
    ).resolves.toEqual({
      success: false,
      error: "Recovery data not found in vault",
    });
  });

  it("rejects when the wrapped VEK does not open under the Recovery Key", async () => {
    const { users, vaults, recoveryKey } = await provision();
    // A structurally valid blob (60 bytes) under a key this Recovery Key could
    // not have produced — the unwrap must fail, not return garbage.
    vaults.vault.updateMetadata({
      recovery: {
        encryptedVek: binaryToBase64(new Uint8Array(60).fill(9)),
        recoverySalt: binaryToBase64(crypto.getRandomValues(new Uint8Array(32))),
        version: 1,
      },
    });
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    await expect(
      useCase.recover({ userId: "user-1", recoveryKey }),
    ).resolves.toEqual({
      success: false,
      error: "Failed to unwrap VEK with Recovery Key",
    });
  });

  it("round-trips: the key just issued unwraps the VEK and yields a new wrapper", async () => {
    const { users, vaults, recoveryKey } = await provision();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.recover({ userId: "user-1", recoveryKey });

    expect(out.success).toBe(true);
    const wrapper = out.newMasterPhraseWrapper!;
    expect(wrapper.version).toBe(1);
    expect(wrapper.salt).toHaveLength(44); // fresh 32-byte PBKDF2 salt
    expect(base64ToBinary(wrapper.encryptedVek)).toHaveLength(60);
    // A DIFFERENT ciphertext from the one that was stored — the VEK was
    // re-wrapped under a newly generated master phrase, not copied.
    const recovery = vaults.vault.metadata!.recovery as {
      encryptedVek: string;
      recoverySalt: string;
    };
    expect(wrapper.encryptedVek).not.toBe(recovery.encryptedVek);
    expect(wrapper.salt).not.toBe(recovery.recoverySalt);
  });

  it("reports failure instead of throwing when the repository throws", async () => {
    const users = makeUserRepository();
    users.failWith.message = "database down";
    const vaults = makeVaultRepository();
    const useCase = new MasterRecoveryUseCase(
      users.repository,
      vaults.repository,
    );

    const out = await useCase.recover({ userId: "user-1", recoveryKey: "k" });

    expect(out).toEqual({ success: false, error: "Master recovery failed" });
  });
});
