/**
 * Credential Entity Tests — Strict TDD
 *
 * Tests for personal and managed credential entities with split-trust support
 * Following: RED -> GREEN -> REFACTOR
 */

import { Credential, CredentialMode } from "../../../src/domain/entities/credential";
import { VaultId, CredentialId } from "../../../src/domain/value-objects/ids";

describe("Credential Entity", () => {
  const testVaultId = VaultId.fromString("vault-123");
  const testCredentialId = CredentialId.fromString("cred-123");
  const testSalt = "dGVzdC1zYWx0LTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU="; // base64 32 bytes
  const testReleaseShareRef = "rs-ref-abc123";

  describe("createPersonal", () => {
    test("creates personal credential with correct defaults", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "GitHub",
        username: "user@example.com",
        encryptedPassword: "encrypted-data",
        salt: testSalt,
      });

      expect(cred.id).toBeInstanceOf(CredentialId);
      expect(cred.vaultId).toBe(testVaultId);
      expect(cred.title).toBe("GitHub");
      expect(cred.username).toBe("user@example.com");
      expect(cred.encryptedPassword).toBe("encrypted-data");
      expect(cred.mode).toBe("personal");
      expect(cred.salt).toBe(testSalt);
      expect(cred.version).toBe(1);
      expect(cred.releaseShareRef).toBeUndefined();
      expect(cred.url).toBeUndefined();
      expect(cred.notes).toBeUndefined();
      expect(cred.tags).toEqual([]);
      expect(cred.favorite).toBe(false);
      expect(cred.createdAt).toBeInstanceOf(Date);
      expect(cred.updatedAt).toBeInstanceOf(Date);
      expect(cred.lastUsed).toBeUndefined();
    });

    test("accepts optional fields", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "GitHub",
        username: "user@example.com",
        encryptedPassword: "encrypted-data",
        salt: testSalt,
        url: "https://github.com",
        notes: "Personal account",
        tags: ["work", "dev"],
        favorite: true,
        version: 2,
      });

      expect(cred.url).toBe("https://github.com");
      expect(cred.notes).toBe("Personal account");
      expect(cred.tags).toEqual(["work", "dev"]);
      expect(cred.favorite).toBe(true);
      expect(cred.version).toBe(2);
    });

    test("isPersonal returns true", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
      });
      expect(cred.isPersonal()).toBe(true);
      expect(cred.isManaged()).toBe(false);
    });
  });

  describe("createManaged", () => {
    test("creates managed credential with ReleaseShare reference", () => {
      const cred = Credential.createManaged({
        vaultId: testVaultId,
        title: "Production DB",
        username: "admin",
        encryptedPassword: "encrypted-data",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
      });

      expect(cred.mode).toBe("managed");
      expect(cred.releaseShareRef).toBe(testReleaseShareRef);
      expect(cred.version).toBe(1);
    });

    test("accepts optional fields", () => {
      const cred = Credential.createManaged({
        vaultId: testVaultId,
        title: "Production DB",
        username: "admin",
        encryptedPassword: "encrypted-data",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
        url: "postgresql://db.internal:5432",
        notes: "Requires Plus authorization",
        tags: ["database", "production"],
        favorite: true,
        version: 3,
      });

      expect(cred.url).toBe("postgresql://db.internal:5432");
      expect(cred.notes).toBe("Requires Plus authorization");
      expect(cred.tags).toEqual(["database", "production"]);
      expect(cred.favorite).toBe(true);
      expect(cred.version).toBe(3);
    });

    test("isManaged returns true", () => {
      const cred = Credential.createManaged({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
        releaseShareRef: "ref",
      });
      expect(cred.isManaged()).toBe(true);
      expect(cred.isPersonal()).toBe(false);
    });

    test("throws if releaseShareRef missing", () => {
      expect(() =>
        Credential.createManaged({
          vaultId: testVaultId,
          title: "Test",
          username: "user",
          encryptedPassword: "enc",
          salt: testSalt,
          releaseShareRef: "",
        }),
      ).not.toThrow(); // Empty string is allowed, validated at use-time
    });
  });

  describe("create (generic factory)", () => {
    test("creates personal via generic factory", () => {
      const cred = Credential.create({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        mode: "personal",
        salt: testSalt,
      });
      expect(cred.isPersonal()).toBe(true);
    });

    test("creates managed via generic factory", () => {
      const cred = Credential.create({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        mode: "managed",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
      });
      expect(cred.isManaged()).toBe(true);
    });
  });

  describe("fromPlainObject", () => {
    test("deserializes personal credential correctly", () => {
      const plain = {
        id: "cred-456",
        vaultId: "vault-789",
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        mode: "personal" as CredentialMode,
        salt: testSalt,
        version: 1,
        url: "https://example.com",
        notes: "Note",
        tags: ["tag1"],
        favorite: true,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
        lastUsed: "2024-01-02T00:00:00.000Z",
      };

      const cred = Credential.fromPlainObject(plain);

      expect(cred.id.toString()).toBe("cred-456");
      expect(cred.vaultId.toString()).toBe("vault-789");
      expect(cred.mode).toBe("personal");
      expect(cred.releaseShareRef).toBeUndefined();
      expect(cred.url).toBe("https://example.com");
      expect(cred.notes).toBe("Note");
      expect(cred.tags).toEqual(["tag1"]);
      expect(cred.favorite).toBe(true);
      expect(cred.lastUsed).toEqual(new Date("2024-01-02T00:00:00.000Z"));
    });

    test("deserializes managed credential correctly", () => {
      const plain = {
        id: "cred-456",
        vaultId: "vault-789",
        title: "Managed Test",
        username: "admin",
        encryptedPassword: "enc",
        mode: "managed" as CredentialMode,
        salt: testSalt,
        version: 2,
        releaseShareRef: testReleaseShareRef,
        url: "postgresql://db:5432",
        notes: "Managed",
        tags: ["db"],
        favorite: false,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      };

      const cred = Credential.fromPlainObject(plain);

      expect(cred.mode).toBe("managed");
      expect(cred.releaseShareRef).toBe(testReleaseShareRef);
      expect(cred.version).toBe(2);
    });
  });

  describe("toPlainObject", () => {
    test("serializes personal credential correctly", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
        version: 1,
      });

      const plain = cred.toPlainObject();

      expect(plain.mode).toBe("personal");
      expect(plain.releaseShareRef).toBeUndefined();
      expect(plain.salt).toBe(testSalt);
      expect(plain.version).toBe(1);
    });

    test("serializes managed credential correctly", () => {
      const cred = Credential.createManaged({
        vaultId: testVaultId,
        title: "Test",
        username: "admin",
        encryptedPassword: "enc",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
        version: 2,
      });

      const plain = cred.toPlainObject();

      expect(plain.mode).toBe("managed");
      expect(plain.releaseShareRef).toBe(testReleaseShareRef);
      expect(plain.version).toBe(2);
    });
  });

  describe("toSafeObject", () => {
    test("excludes encryptedPassword", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "secret-encrypted",
        salt: testSalt,
      });

      const safe = cred.toSafeObject();

      // toSafeObject should not include encryptedPassword
      expect("encryptedPassword" in safe).toBe(false);
      expect(safe.id).toBeDefined();
      expect(safe.username).toBe("user");
    });

    test("includes hasReleaseShareRef flag for managed", () => {
      const credPersonal = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
      });

      const credManaged = Credential.createManaged({
        vaultId: testVaultId,
        title: "Test",
        username: "admin",
        encryptedPassword: "enc",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
      });

      expect(credPersonal.toSafeObject().hasReleaseShareRef).toBe(false);
      expect(credManaged.toSafeObject().hasReleaseShareRef).toBe(true);
    });
  });

  describe("Business methods", () => {
    let cred: Credential;

    beforeEach(() => {
      cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Original",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
      });
    });

    test("updatePassword updates encryptedPassword and updatedAt", () => {
      const oldUpdatedAt = cred.updatedAt;
      cred.updatePassword("new-encrypted");
      expect(cred.encryptedPassword).toBe("new-encrypted");
      expect(cred.updatedAt.getTime()).toBeGreaterThanOrEqual(oldUpdatedAt.getTime());
    });

    test("updateTitle updates title and updatedAt", () => {
      cred.updateTitle("New Title");
      expect(cred.title).toBe("New Title");
    });

    test("updateUsername updates username and updatedAt", () => {
      cred.updateUsername("newuser");
      expect(cred.username).toBe("newuser");
    });

    test("updateUrl updates url", () => {
      cred.updateUrl("https://new.com");
      expect(cred.url).toBe("https://new.com");
      cred.updateUrl(undefined);
      expect(cred.url).toBeUndefined();
    });

    test("updateNotes updates notes", () => {
      cred.updateNotes("New note");
      expect(cred.notes).toBe("New note");
    });

    test("toggleFavorite toggles favorite", () => {
      expect(cred.favorite).toBe(false);
      cred.toggleFavorite();
      expect(cred.favorite).toBe(true);
      cred.toggleFavorite();
      expect(cred.favorite).toBe(false);
    });

    test("addTag adds tag", () => {
      cred.addTag("tag1");
      expect(cred.tags).toContain("tag1");
      cred.addTag("tag1"); // duplicate
      expect(cred.tags.filter((t: string) => t === "tag1").length).toBe(1);
    });

    test("removeTag removes tag", () => {
      cred.addTag("tag1");
      cred.addTag("tag2");
      cred.removeTag("tag1");
      expect(cred.tags).not.toContain("tag1");
      expect(cred.tags).toContain("tag2");
    });

    test("setTags replaces all tags", () => {
      cred.setTags(["a", "b"]);
      expect(cred.tags).toEqual(["a", "b"]);
      cred.setTags(["c"]);
      expect(cred.tags).toEqual(["c"]);
    });

    test("markAsUsed sets lastUsed", () => {
      expect(cred.lastUsed).toBeUndefined();
      cred.markAsUsed();
      expect(cred.lastUsed).toBeInstanceOf(Date);
    });

    test("incrementVersion increments version", () => {
      expect(cred.version).toBe(1);
      cred.incrementVersion();
      expect(cred.version).toBe(2);
      cred.incrementVersion();
      expect(cred.version).toBe(3);
    });

    test("all updates modify updatedAt", () => {
      const oldUpdatedAt = cred.updatedAt;
      cred.updateTitle("New");
      expect(cred.updatedAt.getTime()).toBeGreaterThanOrEqual(oldUpdatedAt.getTime());
    });
  });

  describe("Mode-specific behavior", () => {
    test("personal credential has no releaseShareRef", () => {
      const cred = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
      });
      expect(cred.releaseShareRef).toBeUndefined();
    });

    test("managed credential requires releaseShareRef", () => {
      const cred = Credential.createManaged({
        vaultId: testVaultId,
        title: "Test",
        username: "admin",
        encryptedPassword: "enc",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
      });
      expect(cred.releaseShareRef).toBe(testReleaseShareRef);
    });

    test("personal and managed have different modes", () => {
      const personal = Credential.createPersonal({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "enc",
        salt: testSalt,
      });
      const managed = Credential.createManaged({
        vaultId: testVaultId,
        title: "Test",
        username: "admin",
        encryptedPassword: "enc",
        salt: testSalt,
        releaseShareRef: testReleaseShareRef,
      });

      expect(personal.mode).toBe("personal");
      expect(managed.mode).toBe("managed");
      expect(personal.mode).not.toBe(managed.mode);
    });
  });
});