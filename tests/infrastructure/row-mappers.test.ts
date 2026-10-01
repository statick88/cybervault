import { Vault } from "../../src/domain/entities/vault";
import { Credential } from "../../src/domain/entities/credential";
import { VaultId } from "../../src/domain/value-objects/ids";
import {
  mapCredentialRow,
  mapVaultRow,
} from "../../src/infrastructure/repositories/row-mappers";
import type {
  CredentialRow,
  VaultRow,
} from "../../src/infrastructure/repositories/row-mappers";

/**
 * Regression guard for the Core snake_case → camelCase read defect
 * (`odd/tasks/core-postgres-row-mapping.md`, 2026-09-28).
 *
 * `PostgresVaultRepository` and `PostgresCredentialRepository` read rows with
 * an all-snake_case column list and passed them to
 * `<Entity>.fromPlainObject({ ...row, <a few camelCase overrides> })`.
 * `fromPlainObject` expects camelCase keys, so every field missing from the
 * override list arrived `undefined` — `encryptedData` and `encryptionKeyId`
 * (both `NOT NULL` on `vaults`) and `releaseShareRef` (the H3 round-trip) in
 * particular. The vault reads also double-parsed an already-parsed `jsonb`
 * `metadata`, throwing `SyntaxError: "[object Object]" is not valid JSON` on
 * any row with non-NULL metadata.
 *
 * Every fixture below is shaped exactly as `pg` returns it: `TIMESTAMPTZ` as a
 * `Date`, `TEXT[]` as a JS array, `jsonb` as an already-parsed object, SQL NULL
 * as `null`, `BIGINT` as a string (node-postgres' default). No database is
 * required.
 */

const VAULT_ROW: VaultRow = {
  id: "v-1",
  name: "Personal",
  description: "Main vault",
  encrypted_data: "ciphertext-blob",
  encryption_key_id: "key-2026-01",
  owner_id: "user-1",
  // JSONB — the driver's OID 3802 parser has already produced an object.
  metadata: { client: "web", pinned: true },
  created_at: new Date("2026-01-02T10:30:00.000Z"),
  updated_at: new Date("2026-01-03T11:45:00.000Z"),
  // BIGINT — node-postgres returns it as a string by default.
  lock_version: "4",
};

const CREDENTIAL_ROW: CredentialRow = {
  id: "c-1",
  vault_id: "v-1",
  title: "Prod DB",
  username: "alice",
  encrypted_password: "c2FsdA==|aXZf|Y3Q=",
  mode: "managed",
  salt: "c2FsdC1ieXRlcy0zMg==",
  version: 3,
  release_share_ref: "rsr_9f2c4b7a5d1e",
  url: "https://db.example.com",
  notes: "rotated quarterly",
  tags: ["prod", "db"],
  favorite: true,
  created_at: new Date("2026-01-02T10:30:00.000Z"),
  updated_at: new Date("2026-01-03T11:45:00.000Z"),
  last_used: new Date("2026-01-04T08:00:00.000Z"),
  lock_version: "2",
};

/** Rebuild the row `pg` would return for a vault the application wrote. */
function rowForVault(vault: Vault, lockVersion: string | number = 1): VaultRow {
  const plain = vault.toPlainObject();
  return {
    id: plain.id,
    name: plain.name,
    description: plain.description ?? null,
    encrypted_data: plain.encryptedData,
    encryption_key_id: plain.encryptionKeyId,
    owner_id: plain.ownerId ?? null,
    metadata: plain.metadata ?? null,
    created_at: new Date(plain.createdAt),
    updated_at: new Date(plain.updatedAt),
    lock_version: lockVersion,
  };
}

/** Rebuild the row `pg` would return for a credential the application wrote. */
function rowForCredential(
  credential: Credential,
  lockVersion: string | number = 1,
): CredentialRow {
  const plain = credential.toPlainObject();
  return {
    id: plain.id,
    vault_id: plain.vaultId,
    title: plain.title,
    username: plain.username,
    encrypted_password: plain.encryptedPassword,
    mode: plain.mode,
    salt: plain.salt,
    version: plain.version,
    release_share_ref: plain.releaseShareRef ?? null,
    url: plain.url ?? null,
    notes: plain.notes ?? null,
    tags: plain.tags,
    favorite: plain.favorite,
    created_at: new Date(plain.createdAt),
    updated_at: new Date(plain.updatedAt),
    last_used: plain.lastUsed ? new Date(plain.lastUsed) : null,
    lock_version: lockVersion,
  };
}

describe("mapVaultRow", () => {
  it("maps every column of `vaults` to its camelCase field", () => {
    const plain = mapVaultRow(VAULT_ROW);

    // Exact key set: nothing snake_case survives, nothing is left behind.
    expect(Object.keys(plain).sort()).toEqual(
      [
        "id",
        "name",
        "description",
        "encryptedData",
        "encryptionKeyId",
        "ownerId",
        "metadata",
        "createdAt",
        "updatedAt",
        "lockVersion",
      ].sort(),
    );

    expect(plain.id).toBe("v-1");
    expect(plain.name).toBe("Personal");
    expect(plain.description).toBe("Main vault");
    expect(plain.encryptedData).toBe("ciphertext-blob");
    expect(plain.encryptionKeyId).toBe("key-2026-01");
    expect(plain.ownerId).toBe("user-1");
    expect(plain.metadata).toEqual({ client: "web", pinned: true });
    expect(plain.createdAt).toBe("2026-01-02T10:30:00.000Z");
    expect(plain.updatedAt).toBe("2026-01-03T11:45:00.000Z");
    expect(plain.lockVersion).toBe("4");
  });

  it("REGRESSION: encryptedData and encryptionKeyId are defined and equal to what was written", () => {
    const written = Vault.create({
      name: "Personal",
      description: "Main vault",
      encryptedData: "ciphertext-blob",
      encryptionKeyId: "key-2026-01",
      ownerId: "user-1",
      metadata: { client: "web" },
    });

    const readBack = Vault.fromPlainObject(mapVaultRow(rowForVault(written, 1)));

    expect(readBack.encryptedData).toBeDefined();
    expect(readBack.encryptedData).toBe(written.encryptedData);
    expect(readBack.encryptionKeyId).toBeDefined();
    expect(readBack.encryptionKeyId).toBe(written.encryptionKeyId);
    expect(readBack.name).toBe(written.name);
    expect(readBack.ownerId).toBe(written.ownerId);
    expect(readBack.metadata).toEqual({ client: "web" });
    expect(readBack.lockVersion).toBe(1);
    expect(readBack.createdAt.getTime()).toBe(written.createdAt.getTime());
  });

  it("REGRESSION: the previous {...row} spread left both NOT NULL fields undefined", () => {
    // `pg` hands repositories rows typed as `any`, which is why the old spread
    // compiled: TypeScript never checked the keys. Reproduced verbatim here.
    // The row carries NULL metadata on purpose: the legacy code dies on the
    // jsonb double-parse first (see the metadata regression below), and this
    // test exists to isolate the FIELD-mapping defect.
    const driverRow: any = { ...VAULT_ROW, metadata: null };
    const legacy = Vault.fromPlainObject({
      ...driverRow,
      ownerId: driverRow.owner_id ?? undefined,
      metadata: driverRow.metadata ? JSON.parse(driverRow.metadata) : undefined,
      createdAt: driverRow.created_at,
      updatedAt: driverRow.updated_at,
      lockVersion: driverRow.lock_version,
    });

    expect(legacy.encryptedData).toBeUndefined();
    expect(legacy.encryptionKeyId).toBeUndefined();
    // ...while the mapper supplies them.
    expect(mapVaultRow(VAULT_ROW).encryptedData).toBe("ciphertext-blob");
    expect(mapVaultRow(VAULT_ROW).encryptionKeyId).toBe("key-2026-01");
  });

  it("REGRESSION: a row with non-NULL metadata does not throw (jsonb is already parsed)", () => {
    // The exact call that threw against PostgreSQL 16:
    //     JSON.parse({client:"web"}) -> SyntaxError: "[object Object]" is not valid JSON
    expect(() => JSON.parse(VAULT_ROW.metadata as string)).toThrow(SyntaxError);

    // The legacy vault read path, reproduced verbatim, throws on this row...
    const legacyDriverRow: any = { ...VAULT_ROW };
    expect(() =>
      Vault.fromPlainObject({
        ...legacyDriverRow,
        ownerId: legacyDriverRow.owner_id ?? undefined,
        metadata: legacyDriverRow.metadata
          ? JSON.parse(legacyDriverRow.metadata)
          : undefined,
        createdAt: legacyDriverRow.created_at,
        updatedAt: legacyDriverRow.updated_at,
        lockVersion: legacyDriverRow.lock_version,
      }),
    ).toThrow(SyntaxError);

    // ...while the mapper reads it back untouched.
    expect(() => Vault.fromPlainObject(mapVaultRow(VAULT_ROW))).not.toThrow();
    expect(mapVaultRow(VAULT_ROW).metadata).toEqual({
      client: "web",
      pinned: true,
    });

    // A NULL metadata column normalises to undefined, not null.
    const plain = mapVaultRow({ ...VAULT_ROW, metadata: null });
    expect(Object.prototype.hasOwnProperty.call(plain, "metadata")).toBe(true);
    expect(plain.metadata).toBeUndefined();
    expect(() => Vault.fromPlainObject(plain)).not.toThrow();
  });

  it("normalises SQL NULL optionals to undefined, not null", () => {
    const plain = mapVaultRow({
      ...VAULT_ROW,
      description: null,
      owner_id: null,
    });

    expect(Object.prototype.hasOwnProperty.call(plain, "description")).toBe(true);
    expect(plain.description).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(plain, "ownerId")).toBe(true);
    expect(plain.ownerId).toBeUndefined();

    const vault = Vault.fromPlainObject(plain);
    expect(vault.description).toBeUndefined();
    expect(vault.ownerId).toBeUndefined();
  });

  it("accepts BIGINT lock_version as the string pg returns or as a number", () => {
    expect(mapVaultRow({ ...VAULT_ROW, lock_version: "4" }).lockVersion).toBe("4");
    expect(mapVaultRow({ ...VAULT_ROW, lock_version: 4 }).lockVersion).toBe(4);

    // The entity is what converts; both arrive as the same number.
    expect(Vault.fromPlainObject(mapVaultRow({ ...VAULT_ROW, lock_version: "4" })).lockVersion).toBe(4);
    expect(Vault.fromPlainObject(mapVaultRow({ ...VAULT_ROW, lock_version: 4 })).lockVersion).toBe(4);
  });

  it("passes a timestamp through whether the driver decoded it or not", () => {
    // Default `pg`: TIMESTAMPTZ → Date.
    expect(mapVaultRow(VAULT_ROW).createdAt).toBe("2026-01-02T10:30:00.000Z");
    // Driver with the timestamp type parser disabled: raw text, unchanged.
    expect(
      mapVaultRow({ ...VAULT_ROW, created_at: "2026-01-02T10:30:00.000Z" }).createdAt,
    ).toBe("2026-01-02T10:30:00.000Z");
  });
});

describe("mapCredentialRow", () => {
  it("maps every column of `credentials` to its camelCase field", () => {
    const plain = mapCredentialRow(CREDENTIAL_ROW);

    // Exact key set: nothing snake_case survives, nothing is left behind.
    expect(Object.keys(plain).sort()).toEqual(
      [
        "id",
        "vaultId",
        "title",
        "username",
        "encryptedPassword",
        "mode",
        "salt",
        "version",
        "releaseShareRef",
        "url",
        "notes",
        "tags",
        "favorite",
        "createdAt",
        "updatedAt",
        "lastUsed",
        "lockVersion",
      ].sort(),
    );

    expect(plain.id).toBe("c-1");
    expect(plain.vaultId).toBe("v-1");
    expect(plain.title).toBe("Prod DB");
    expect(plain.username).toBe("alice");
    expect(plain.encryptedPassword).toBe("c2FsdA==|aXZf|Y3Q=");
    expect(plain.mode).toBe("managed");
    expect(plain.salt).toBe("c2FsdC1ieXRlcy0zMg==");
    expect(plain.version).toBe(3);
    expect(plain.releaseShareRef).toBe("rsr_9f2c4b7a5d1e");
    expect(plain.url).toBe("https://db.example.com");
    expect(plain.notes).toBe("rotated quarterly");
    expect(plain.tags).toEqual(["prod", "db"]);
    expect(plain.favorite).toBe(true);
    expect(plain.createdAt).toBe("2026-01-02T10:30:00.000Z");
    expect(plain.updatedAt).toBe("2026-01-03T11:45:00.000Z");
    expect(plain.lastUsed).toBe("2026-01-04T08:00:00.000Z");
    expect(plain.lockVersion).toBe("2");
  });

  it("REGRESSION: releaseShareRef, mode, salt and version round-trip and equal what was written", () => {
    const written = Credential.createManaged({
      vaultId: VaultId.generate(),
      title: "Prod DB",
      username: "alice",
      encryptedPassword: "c2FsdA==|aXZf|Y3Q=",
      salt: "c2FsdC1ieXRlcy0zMg==",
      releaseShareRef: "rsr_9f2c4b7a5d1e",
      url: "https://db.example.com",
      notes: "rotated quarterly",
      tags: ["prod", "db"],
      favorite: true,
      version: 3,
    });

    const readBack = Credential.fromPlainObject(
      mapCredentialRow(rowForCredential(written, 1)),
    );

    // The H3 server-minted secret ref survives the read.
    expect(readBack.releaseShareRef).toBeDefined();
    expect(readBack.releaseShareRef).toBe(written.releaseShareRef);
    expect(readBack.toSafeObject().hasReleaseShareRef).toBe(true);
    // The managed-release / managed-authoring discriminators survive too.
    expect(readBack.mode).toBe("managed");
    expect(readBack.isManaged()).toBe(true);
    expect(readBack.salt).toBe(written.salt);
    expect(readBack.version).toBe(written.version);
    expect(readBack.encryptedPassword).toBe(written.encryptedPassword);
    expect(readBack.tags).toEqual(written.tags);
    expect(readBack.favorite).toBe(true);
    expect(readBack.lockVersion).toBe(1);
    expect(readBack.lastUsed).toBeUndefined();
    expect(readBack.createdAt.getTime()).toBe(written.createdAt.getTime());
  });

  it("REGRESSION: the previous {...row} spread dropped releaseShareRef (H3)", () => {
    // `pg` hands repositories rows typed as `any`; this is the verbatim
    // override list both Core repositories used before the mappers.
    const driverRow: any = { ...CREDENTIAL_ROW };
    const legacy = Credential.fromPlainObject({
      ...driverRow,
      tags: driverRow.tags || [],
      vaultId: driverRow.vault_id,
      encryptedPassword: driverRow.encrypted_password,
      createdAt: driverRow.created_at,
      updatedAt: driverRow.updated_at,
      lastUsed: driverRow.last_used,
      lockVersion: driverRow.lock_version,
    });

    // The column and the UNIQUE index `uq_credentials_release_share_ref`
    // exist, but the value never made it back from the read.
    expect(legacy.releaseShareRef).toBeUndefined();
    expect(legacy.toSafeObject().hasReleaseShareRef).toBe(false);

    // ...while the mapper supplies it.
    expect(mapCredentialRow(CREDENTIAL_ROW).releaseShareRef).toBe("rsr_9f2c4b7a5d1e");
    expect(
      Credential.fromPlainObject(mapCredentialRow(CREDENTIAL_ROW)).toSafeObject()
        .hasReleaseShareRef,
    ).toBe(true);
  });

  it("defaults a NULL tags (TEXT[]) to [] and NULL favorite to false", () => {
    const plain = mapCredentialRow({
      ...CREDENTIAL_ROW,
      tags: null,
      favorite: null,
    });

    expect(plain.tags).toEqual([]);
    expect(plain.favorite).toBe(false);

    const credential = Credential.fromPlainObject(plain);
    expect(credential.tags).toEqual([]);
    // `.includes()` / spread on undefined is the crash this pattern fixed.
    expect(() => credential.addTag("new")).not.toThrow();
    expect(credential.favorite).toBe(false);
    expect(() => credential.toggleFavorite()).not.toThrow();
    expect(credential.favorite).toBe(true);
  });

  it("normalises SQL NULL optionals to undefined, not null", () => {
    const plain = mapCredentialRow({
      ...CREDENTIAL_ROW,
      url: null,
      notes: null,
      release_share_ref: null,
      last_used: null,
    });

    for (const key of ["url", "notes", "releaseShareRef", "lastUsed"] as const) {
      expect(Object.prototype.hasOwnProperty.call(plain, key)).toBe(true);
      expect(plain[key]).toBeUndefined();
    }

    const credential = Credential.fromPlainObject(plain);
    expect(credential.url).toBeUndefined();
    expect(credential.notes).toBeUndefined();
    expect(credential.releaseShareRef).toBeUndefined();
    expect(credential.lastUsed).toBeUndefined();
    expect(credential.toSafeObject().hasReleaseShareRef).toBe(false);
  });

  it("reads a NULL mode/salt/version (nullable, domain-required) as the column defaults", () => {
    // `mode VARCHAR(20) DEFAULT 'personal'` and `version INTEGER DEFAULT 1`
    // are nullable; `salt TEXT` (migration 003) has no default at all, so a
    // row that predates the migration can hold NULL there.
    const plain = mapCredentialRow({
      ...CREDENTIAL_ROW,
      mode: null,
      salt: null,
      version: null,
    });

    expect(plain.mode).toBe("personal");
    expect(plain.version).toBe(1);
    expect(plain.salt).toBe("");

    // The domain requires all three; mapping NULL must not blow up a read.
    const credential = Credential.fromPlainObject(plain);
    expect(credential.mode).toBe("personal");
    expect(credential.isPersonal()).toBe(true);
    expect(credential.version).toBe(1);
    expect(credential.salt).toBe("");
  });

  it("accepts BIGINT lock_version as the string pg returns or as a number", () => {
    expect(mapCredentialRow({ ...CREDENTIAL_ROW, lock_version: "2" }).lockVersion).toBe("2");
    expect(mapCredentialRow({ ...CREDENTIAL_ROW, lock_version: 2 }).lockVersion).toBe(2);

    // The entity converts; both arrive as the same number.
    expect(
      Credential.fromPlainObject(mapCredentialRow({ ...CREDENTIAL_ROW, lock_version: "2" }))
        .lockVersion,
    ).toBe(2);
    expect(
      Credential.fromPlainObject(mapCredentialRow({ ...CREDENTIAL_ROW, lock_version: 2 }))
        .lockVersion,
    ).toBe(2);
  });
});
