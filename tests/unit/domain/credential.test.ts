import { Credential } from "../../../src/domain/entities/credential";
import { VaultId } from "../../../src/domain/value-objects/ids";

describe("Credential entity", () => {
  const vaultId = VaultId.generate();

  describe("create (factory method)", () => {
    it("creates a Credential with generated id and defaults", () => {
      const cred = Credential.create({
        vaultId,
        title: "GitHub",
        username: "dev",
        encryptedPassword: "enc-pass",
      });

      expect(cred.title).toBe("GitHub");
      expect(cred.username).toBe("dev");
      expect(cred.encryptedPassword).toBe("enc-pass");
      expect(cred.tags).toEqual([]);
      expect(cred.favorite).toBe(false);
      expect(cred.url).toBeUndefined();
      expect(cred.notes).toBeUndefined();
      expect(cred.lastUsed).toBeUndefined();
      expect(cred.createdAt).toBeInstanceOf(Date);
      expect(cred.updatedAt).toBeInstanceOf(Date);
    });

    it("includes optional fields when provided", () => {
      const cred = Credential.create({
        vaultId,
        title: "AWS",
        username: "admin",
        encryptedPassword: "enc",
        url: "https://aws.amazon.com",
        notes: "Root account",
        tags: ["cloud", "aws"],
        favorite: true,
      });

      expect(cred.url).toBe("https://aws.amazon.com");
      expect(cred.notes).toBe("Root account");
      expect(cred.tags).toEqual(["cloud", "aws"]);
      expect(cred.favorite).toBe(true);
    });
  });

  describe("getters return defensive copies", () => {
    it("tags returns a copy that does not affect the entity", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
        tags: ["a"],
      });
      const tags = cred.tags;
      tags.push("mutated");

      expect(cred.tags).toEqual(["a"]);
    });
  });

  describe("business methods", () => {
    it("updatePassword replaces password and bumps updatedAt", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "old",
      });
      const before = cred.updatedAt.getTime();

      cred.updatePassword("new-enc");
      expect(cred.encryptedPassword).toBe("new-enc");
      expect(cred.updatedAt.getTime()).toBeGreaterThanOrEqual(before);
    });

    it("updateTitle replaces title", () => {
      const cred = Credential.create({
        vaultId,
        title: "Old",
        username: "u",
        encryptedPassword: "p",
      });
      cred.updateTitle("New");
      expect(cred.title).toBe("New");
    });

    it("updateUsername replaces username", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "old",
        encryptedPassword: "p",
      });
      cred.updateUsername("new");
      expect(cred.username).toBe("new");
    });

    it("toggleFavorite flips the value", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
      });
      expect(cred.favorite).toBe(false);
      cred.toggleFavorite();
      expect(cred.favorite).toBe(true);
      cred.toggleFavorite();
      expect(cred.favorite).toBe(false);
    });

    it("addTag prevents duplicates", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
      });
      cred.addTag("work");
      cred.addTag("work");
      expect(cred.tags).toEqual(["work"]);
    });

    it("removeTag removes the tag", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
        tags: ["a", "b", "c"],
      });
      cred.removeTag("b");
      expect(cred.tags).toEqual(["a", "c"]);
    });

    it("removeTag is a no-op for non-existent tag", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
        tags: ["x"],
      });
      cred.removeTag("missing");
      expect(cred.tags).toEqual(["x"]);
    });

    it("markAsUsed sets lastUsed", () => {
      const cred = Credential.create({
        vaultId,
        title: "T",
        username: "u",
        encryptedPassword: "p",
      });
      expect(cred.lastUsed).toBeUndefined();
      cred.markAsUsed();
      expect(cred.lastUsed).toBeInstanceOf(Date);
    });
  });

  describe("toPlainObject / fromPlainObject round-trip", () => {
    it("serializes and deserializes correctly", () => {
      const original = Credential.create({
        vaultId,
        title: "Prod DB",
        username: "admin",
        encryptedPassword: "enc123",
        url: "https://db.prod",
        notes: "Production",
        tags: ["prod", "db"],
        favorite: true,
      });
      original.markAsUsed();

      const plain = original.toPlainObject();
      const restored = Credential.fromPlainObject(plain);

      expect(restored.id.equals(original.id)).toBe(true);
      expect(restored.vaultId.equals(original.vaultId)).toBe(true);
      expect(restored.title).toBe(original.title);
      expect(restored.username).toBe(original.username);
      expect(restored.encryptedPassword).toBe(original.encryptedPassword);
      expect(restored.url).toBe(original.url);
      expect(restored.notes).toBe(original.notes);
      expect(restored.tags).toEqual(original.tags);
      expect(restored.favorite).toBe(true);
      expect(restored.lastUsed?.toISOString()).toBe(original.lastUsed?.toISOString());
    });

    it("handles undefined optional fields in round-trip", () => {
      const original = Credential.create({
        vaultId,
        title: "Minimal",
        username: "u",
        encryptedPassword: "p",
      });

      const plain = original.toPlainObject();
      expect(plain.url).toBeUndefined();
      expect(plain.notes).toBeUndefined();
      expect(plain.lastUsed).toBeUndefined();

      const restored = Credential.fromPlainObject(plain);
      expect(restored.url).toBeUndefined();
      expect(restored.notes).toBeUndefined();
      expect(restored.lastUsed).toBeUndefined();
    });
  });
});
