import { Credential } from "@/src/domain/entities/credential";
import { CredentialId, VaultId } from "@/src/domain/value-objects/ids";

describe("Credential Entity", () => {
  // Helpers
  const createTestVaultId = (): VaultId =>
    VaultId.fromString("550e8400-e29b-41d4-a716-446655440000");
  const createTestCredentialId = (): CredentialId =>
    CredentialId.fromString("660e8400-e29b-41d4-a716-446655440000");

  describe("Factory Method create()", () => {
    it("creates credential with minimal props → generates id, current dates, default values", () => {
      const vaultId = createTestVaultId();
      const beforeCreation = new Date();

      const credential = Credential.create({
        vaultId,
        title: "Test Title",
        username: "testuser",
        encryptedPassword: "encrypted123",
      });

      const afterCreation = new Date();

      expect(credential.id).toBeInstanceOf(CredentialId);
      expect(credential.vaultId.equals(vaultId)).toBe(true);
      expect(credential.title).toBe("Test Title");
      expect(credential.username).toBe("testuser");
      expect(credential.encryptedPassword).toBe("encrypted123");
      expect(credential.tags).toEqual([]);
      expect(credential.favorite).toBe(false);
      expect(credential.createdAt.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime(),
      );
      expect(credential.createdAt.getTime()).toBeLessThanOrEqual(
        afterCreation.getTime(),
      );
      expect(credential.updatedAt.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime(),
      );
      expect(credential.updatedAt.getTime()).toBeLessThanOrEqual(
        afterCreation.getTime(),
      );
      expect(credential.lastUsed).toBeUndefined();
    });

    it("creates credential with all props → respects all values", () => {
      const vaultId = createTestVaultId();
      const id = createTestCredentialId();
      const createdAt = new Date("2024-01-01T00:00:00.000Z");
      const tags = ["work", "personal"];

      const credential = Credential.create({
        vaultId,
        title: "Complete Credential",
        username: "completeuser",
        encryptedPassword: "encryptedcomplete",
        url: "https://example.com",
        notes: "Some notes",
        tags,
        favorite: true,
      });

      // Since create() generates its own id and dates, we verify the provided props
      expect(credential.vaultId.equals(vaultId)).toBe(true);
      expect(credential.title).toBe("Complete Credential");
      expect(credential.username).toBe("completeuser");
      expect(credential.encryptedPassword).toBe("encryptedcomplete");
      expect(credential.url).toBe("https://example.com");
      expect(credential.notes).toBe("Some notes");
      expect(credential.tags).toEqual(tags);
      expect(credential.favorite).toBe(true);
    });

    it("verifies that tags default is [] (not undefined)", () => {
      const vaultId = createTestVaultId();

      const credential = Credential.create({
        vaultId,
        title: "No Tags",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(credential.tags).toBeDefined();
      expect(credential.tags).toEqual([]);
      expect(Array.isArray(credential.tags)).toBe(true);
    });

    it("verifies that favorite default is false", () => {
      const vaultId = createTestVaultId();

      const credential = Credential.create({
        vaultId,
        title: "Not Favorite",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(credential.favorite).toBe(false);
    });

    it("verifies that createdAt and updatedAt are equal when creating", () => {
      const vaultId = createTestVaultId();

      const credential = Credential.create({
        vaultId,
        title: "Equal Dates",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(credential.createdAt.getTime()).toBe(
        credential.updatedAt.getTime(),
      );
    });
  });

  describe("fromPlainObject()", () => {
    const createPlainObject = (overrides = {}) => ({
      id: "770e8400-e29b-41d4-a716-446655440000",
      vaultId: "880e8400-e29b-41d4-a716-446655440000",
      title: "Plain Object Test",
      username: "plainuser",
      encryptedPassword: "encryptedpass",
      tags: ["tag1", "tag2"],
      favorite: false,
      createdAt: "2024-01-01T00:00:00.000Z",
      updatedAt: "2024-01-02T00:00:00.000Z",
      ...overrides,
    });

    it("deserializes complete plain object → correct credential", () => {
      const plain = createPlainObject();

      const credential = Credential.fromPlainObject(plain);

      expect(credential.id.toString()).toBe(plain.id);
      expect(credential.vaultId.toString()).toBe(plain.vaultId);
      expect(credential.title).toBe(plain.title);
      expect(credential.username).toBe(plain.username);
      expect(credential.encryptedPassword).toBe(plain.encryptedPassword);
      expect(credential.url).toBeUndefined();
      expect(credential.notes).toBeUndefined();
      expect(credential.tags).toEqual(plain.tags);
      expect(credential.favorite).toBe(plain.favorite);
      expect(credential.createdAt.toISOString()).toBe(plain.createdAt);
      expect(credential.updatedAt.toISOString()).toBe(plain.updatedAt);
      expect(credential.lastUsed).toBeUndefined();
    });

    it("deserializes with optional lastUsed → handles undefined", () => {
      const plain = createPlainObject({ lastUsed: "2024-01-15T00:00:00.000Z" });

      const credential = Credential.fromPlainObject(plain);

      expect(credential.lastUsed).not.toBeUndefined();
      expect(credential.lastUsed?.toISOString()).toBe(plain.lastUsed);
    });

    it("fails with invalid ID (should fail in CredentialId.fromString)", () => {
      const plain = createPlainObject({ id: "invalid-id" });

      expect(() => Credential.fromPlainObject(plain)).toThrow(
        "CredentialId inválido",
      );
    });

    it("fails with invalid vaultId", () => {
      const plain = createPlainObject({ vaultId: "not-a-uuid" });

      expect(() => Credential.fromPlainObject(plain)).toThrow(
        "VaultId inválido",
      );
    });
  });

  describe("toPlainObject()", () => {
    const createCredential = (overrides = {}) => {
      const vaultId = createTestVaultId();
      const id = createTestCredentialId();
      const createdAt = new Date("2024-01-01T00:00:00.000Z");
      const updatedAt = new Date("2024-01-02T00:00:00.000Z");

      return Credential.fromPlainObject({
        id: id.toString(),
        vaultId: vaultId.toString(),
        title: "Serialization Test",
        username: "serialuser",
        encryptedPassword: "serialpass",
        tags: ["ser tag1", "ser tag2"],
        favorite: true,
        createdAt: createdAt.toISOString(),
        updatedAt: updatedAt.toISOString(),
        ...overrides,
      });
    };

    it("serializes complete credential → correct plain object", () => {
      const credential = createCredential({
        url: "https://test.com",
        notes: "Test notes",
      });

      const plain = credential.toPlainObject();

      expect(plain.id).toBe(credential.id.toString());
      expect(plain.vaultId).toBe(credential.vaultId.toString());
      expect(plain.title).toBe(credential.title);
      expect(plain.username).toBe(credential.username);
      expect(plain.encryptedPassword).toBe(credential.encryptedPassword);
      expect(plain.url).toBe("https://test.com");
      expect(plain.notes).toBe("Test notes");
      expect(plain.tags).toEqual(credential.tags);
      expect(plain.favorite).toBe(true);
    });

    it("verifies that strings are ISO strings (toISOString)", () => {
      const credential = createCredential();

      const plain = credential.toPlainObject();

      expect(() => new Date(plain.createdAt)).not.toThrow();
      expect(() => new Date(plain.updatedAt)).not.toThrow();
      expect(plain.createdAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/,
      );
      expect(plain.updatedAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/,
      );

      if (plain.lastUsed) {
        expect(plain.lastUsed).toMatch(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/,
        );
      }
    });

    it("verifies that tags is a copy (not reference)", () => {
      const credential = createCredential();

      const plain = credential.toPlainObject();

      plain.tags.push("new-tag");

      expect(credential.tags).not.toContain("new-tag");
      expect(plain.tags).toContain("new-tag");
    });

    it("serializes without lastUsed → omitted from object", () => {
      const credential = createCredential(); // No lastUsed

      const plain = credential.toPlainObject();

      expect(plain.lastUsed).toBeUndefined();
    });
  });

  describe("Getters (immutability)", () => {
    const createTestCredential = () => {
      const vaultId = createTestVaultId();
      return Credential.create({
        vaultId,
        title: "Getter Test",
        username: "getteruser",
        encryptedPassword: "getterpass",
        tags: ["tag1", "tag2"],
        favorite: true,
      });
    };

    it("get id → returns CredentialId", () => {
      const credential = createTestCredential();

      expect(credential.id).toBeInstanceOf(CredentialId);
    });

    it("get vaultId → returns VaultId", () => {
      const credential = createTestCredential();

      expect(credential.vaultId).toBeInstanceOf(VaultId);
    });

    it("get title → string", () => {
      const credential = createTestCredential();

      expect(typeof credential.title).toBe("string");
      expect(credential.title).toBe("Getter Test");
    });

    it("verifies that getters do NOT modify props", () => {
      const credential = createTestCredential();

      const originalTitle = credential.title;
      const originalUsername = credential.username;
      const originalTags = credential.tags;
      const originalFavorite = credential.favorite;

      // Access all getters
      void credential.id;
      void credential.vaultId;
      void credential.title;
      void credential.username;
      void credential.encryptedPassword;
      void credential.url;
      void credential.notes;
      void credential.tags;
      void credential.favorite;
      void credential.createdAt;
      void credential.updatedAt;
      void credential.lastUsed;

      expect(credential.title).toBe(originalTitle);
      expect(credential.username).toBe(originalUsername);
      expect(credential.tags).toEqual(originalTags);
      expect(credential.favorite).toBe(originalFavorite);
    });
  });

  describe("Mutator methods (updatedAt)", () => {
    let credential: Credential;
    let vaultId: VaultId;

    beforeEach(() => {
      vaultId = createTestVaultId();
      const beforeCreation = new Date();

      credential = Credential.create({
        vaultId,
        title: "Original Title",
        username: "originaluser",
        encryptedPassword: "originalpass",
        tags: ["tag1"],
        favorite: false,
      });

      // Freeze updatedAt to a known time for testing
      const fixedUpdatedAt = new Date("2024-01-01T00:00:00.000Z");
      (credential as any).props.updatedAt = fixedUpdatedAt;
    });

    it("updatePassword() → changes encryptedPassword and updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const newPassword = "newencryptedpassword";

      credential.updatePassword(newPassword);

      expect(credential.encryptedPassword).toBe(newPassword);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("updateTitle() → changes title and updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const newTitle = "New Title";

      credential.updateTitle(newTitle);

      expect(credential.title).toBe(newTitle);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("updateUsername() → changes username and updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const newUsername = "newusername";

      credential.updateUsername(newUsername);

      expect(credential.username).toBe(newUsername);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("toggleFavorite() → toggles favorite and updates updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const originalFavorite = credential.favorite;

      credential.toggleFavorite();

      expect(credential.favorite).toBe(!originalFavorite);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("addTag() → adds tag if not exists, updates updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const newTag = "newtag";

      credential.addTag(newTag);

      expect(credential.tags).toContain(newTag);
      expect(credential.tags).toHaveLength(2);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("addTag() with existing tag → no duplicate, updatedAt unchanged", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const existingTag = "tag1";

      credential.addTag(existingTag);

      expect(credential.tags).toHaveLength(1);
      expect(credential.tags).toContain(existingTag);
      expect(credential.updatedAt.getTime()).toBe(originalUpdatedAt);
    });

    it("removeTag() → removes tag if exists, updates updatedAt", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();

      credential.removeTag("tag1");

      expect(credential.tags).not.toContain("tag1");
      expect(credential.tags).toHaveLength(0);
      expect(credential.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("removeTag() with non-existent tag → no changes", () => {
      const originalUpdatedAt = credential.updatedAt.getTime();
      const originalTags = [...credential.tags];

      credential.removeTag("nonexistent");

      expect(credential.tags).toEqual(originalTags);
      expect(credential.tags).toHaveLength(1);
      expect(credential.updatedAt.getTime()).toBe(originalUpdatedAt);
    });

    it("markAsUsed() → sets lastUsed to now", () => {
      const beforeMark = new Date();

      credential.markAsUsed();

      const afterMark = new Date();

      expect(credential.lastUsed).not.toBeUndefined();
      expect(credential.lastUsed?.getTime()).toBeGreaterThanOrEqual(
        beforeMark.getTime(),
      );
      expect(credential.lastUsed?.getTime()).toBeLessThanOrEqual(
        afterMark.getTime(),
      );
    });
  });

  describe("Array immutability", () => {
    let credential: Credential;

    beforeEach(() => {
      const vaultId = createTestVaultId();
      credential = Credential.create({
        vaultId,
        title: "Array Test",
        username: "arrayuser",
        encryptedPassword: "arraypass",
        tags: ["original1", "original2"],
      });
    });

    it("verifies that tags getter returns copy (mutating external array does not affect internal)", () => {
      const tags = credential.tags;
      tags.push("external-modification");

      expect(credential.tags).not.toContain("external-modification");
      expect(credential.tags).toHaveLength(2);
    });

    it("verifies that toPlainObject().tags is a copy", () => {
      const plain = credential.toPlainObject();
      plain.tags.push("modified-external");

      expect(credential.tags).not.toContain("modified-external");
      expect(plain.tags).toContain("modified-external");
    });
  });

  describe("Edge cases", () => {
    const vaultId = createTestVaultId();

    it("creates with empty title → allowed (no validation)", () => {
      expect(() =>
        Credential.create({
          vaultId,
          title: "",
          username: "user",
          encryptedPassword: "pass",
        }),
      ).not.toThrow();

      const credential = Credential.create({
        vaultId,
        title: "",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(credential.title).toBe("");
    });

    it("creates with empty username → allowed (no validation)", () => {
      expect(() =>
        Credential.create({
          vaultId,
          title: "Title",
          username: "",
          encryptedPassword: "pass",
        }),
      ).not.toThrow();

      const credential = Credential.create({
        vaultId,
        title: "Title",
        username: "",
        encryptedPassword: "pass",
      });

      expect(credential.username).toBe("");
    });

    it("allows tags with duplicates in input → creates as provided", () => {
      const credential = Credential.create({
        vaultId,
        title: "Dup Tags",
        username: "user",
        encryptedPassword: "pass",
        tags: ["tag1", "tag1", "tag2"],
      });

      expect(credential.tags).toHaveLength(3);
      expect(credential.tags.filter((t) => t === "tag1")).toHaveLength(2);
    });

    it("addTag() is case-sensitive", () => {
      const credential = Credential.create({
        vaultId,
        title: "Case Test",
        username: "user",
        encryptedPassword: "pass",
        tags: ["Tag"],
      });

      credential.addTag("tag");

      expect(credential.tags).toHaveLength(2);
      expect(credential.tags).toContain("Tag");
      expect(credential.tags).toContain("tag");
    });

    it("removeTag() removes all occurrences of exact match", () => {
      const credential = Credential.fromPlainObject({
        id: "990e8400-e29b-41d4-a716-446655440000",
        vaultId: vaultId.toString(),
        title: "Remove Multiple",
        username: "user",
        encryptedPassword: "pass",
        tags: ["tag", "tag", "tag"],
        favorite: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      credential.removeTag("tag");

      expect(credential.tags).toHaveLength(0);
    });
  });
});
