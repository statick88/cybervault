/**
 * S2 — `ChromeStorageVaultRepository` unit tests (mocked `chrome.storage`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * This is the extension-side `IVaultRepository`: it reads and writes a single
 * vault under `chrome.storage.local["vault_data"]` through the extension
 * global. Jest runs in a bare Node environment and `tests/jest.setup.js`
 * installs no global `chrome`, so this suite installs its OWN `chrome` in
 * `beforeEach` and deletes it in `afterEach` — the discipline of
 * `tests/extension/lock-semantics.test.ts` — so the global cannot leak into a
 * suite that expects it to be absent. No extension runtime, no network.
 *
 * WHAT IS PINNED HERE
 * 1. The ownership boundary. The repository stores exactly ONE vault, so an
 *    id that matches but an `ownerId` that does not must return `null` — a
 *    mismatched owner is the same as "no such vault". The mirror case (owner
 *    matches, id does not) is pinned too, and so is `listByOwnerId`.
 * 2. Round-trip fidelity: what `save()` writes under `vault_data` is the exact
 *    `toPlainObject()` shape, `encryptedData` and `encryptionKeyId` included —
 *    both are non-optional on `Vault` and a repository that dropped them would
 *    hand back an unusable entity.
 * 3. Deletes are id-scoped: a foreign id must NOT remove the stored vault.
 * 4. `updateMetadata` throws "Vault not found" both when storage is empty and
 *    when the id is foreign, and persists the MERGE rather than a replacement.
 * 5. Empty storage reads as `null` / `[]` / `false` — never as a throw.
 *
 * NOT PINNED: `VaultId.generate()` output, `Vault.updateMetadata` merge
 * semantics as such (covered by `tests/unit/domain/vault.test.ts`), and the
 * `chrome.storage` quota behaviour, which the mock cannot reproduce.
 */

type Stored = Record<string, unknown>;

interface Area {
  get: jest.Mock;
  set: jest.Mock;
  remove: jest.Mock;
}

function createArea(store: Map<string, unknown>): Area {
  const get = jest.fn(async (keys: string | string[]) => {
    const list = Array.isArray(keys) ? keys : [keys];
    const out: Stored = {};
    for (const key of list) if (store.has(key)) out[key] = store.get(key);
    return out;
  });
  const set = jest.fn(async (items: Stored) => {
    for (const [key, value] of Object.entries(items)) store.set(key, value);
  });
  const remove = jest.fn(async (keys: string | string[]) => {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list) store.delete(key);
  });
  return { get, set, remove };
}

const STORAGE_KEY = "vault_data";

let store = new Map<string, unknown>();
let local: Area;

import { ChromeStorageVaultRepository } from "../../src/infrastructure/repositories/ChromeStorageVaultRepository";
import { Vault } from "../../src/domain/entities/vault";
import { VaultId } from "../../src/domain/value-objects/ids";

function newRepo(): ChromeStorageVaultRepository {
  store = new Map();
  local = createArea(store);
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local },
  };
  return new ChromeStorageVaultRepository();
}

afterEach(() => {
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
});

function makeVault(overrides: Partial<Parameters<typeof Vault.create>[0]> = {}): Vault {
  return Vault.create({
    name: "My Vault",
    description: "creds",
    encryptedData: "ciphertext-blob",
    encryptionKeyId: "key-2026-01",
    ownerId: "user-1",
    metadata: { color: "blue" },
    ...overrides,
  });
}

/** What `save()` should have persisted under `vault_data`. */
function persisted(): Record<string, unknown> {
  return store.get(STORAGE_KEY) as Record<string, unknown>;
}

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("ChromeStorageVaultRepository.save", () => {
  it("persists the full plain object, ciphertext fields included", async () => {
    const repo = newRepo();
    const vault = makeVault();

    const returned = await repo.save(vault);

    expect(returned).toBe(vault);
    expect(local.set).toHaveBeenCalledTimes(1);
    expect(persisted()).toEqual(vault.toPlainObject());
    // The two non-optional columns the row mapper used to drop.
    expect(persisted().encryptedData).toBe("ciphertext-blob");
    expect(persisted().encryptionKeyId).toBe("key-2026-01");
    expect(persisted().ownerId).toBe("user-1");
  });

  it("overwrites the previous vault — the storage holds exactly one", async () => {
    const repo = newRepo();
    const first = makeVault({ name: "First" });
    const second = makeVault({ name: "Second" });

    await repo.save(first);
    await repo.save(second);

    expect(persisted().name).toBe("Second");
    await expect(repo.list()).resolves.toHaveLength(1);
  });
});

/* ========================================================================== */
/* findById                                                                    */
/* ========================================================================== */

describe("ChromeStorageVaultRepository.findById", () => {
  it("returns the vault when the id matches", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    const found = await repo.findById(vault.id);

    expect(found).not.toBeNull();
    expect(found!.id.equals(vault.id)).toBe(true);
    expect(found!.encryptedData).toBe("ciphertext-blob");
    expect(found!.encryptionKeyId).toBe("key-2026-01");
    expect(found!.metadata).toEqual({ color: "blue" });
    expect(found!.lockVersion).toBeUndefined(); // never read a version here
  });

  it("returns null for a foreign id even though a vault is stored", async () => {
    const repo = newRepo();
    await repo.save(makeVault());

    await expect(repo.findById(VaultId.generate())).resolves.toBeNull();
  });

  it("returns null when nothing is stored", async () => {
    const repo = newRepo();
    await expect(repo.findById(VaultId.generate())).resolves.toBeNull();
  });
});

/* ========================================================================== */
/* findByVaultIdAndOwnerId — the ownership boundary                            */
/* ========================================================================== */

describe("ChromeStorageVaultRepository.findByVaultIdAndOwnerId", () => {
  it("returns the vault when BOTH the id and the owner match", async () => {
    const repo = newRepo();
    const vault = makeVault({ ownerId: "alice" });
    await repo.save(vault);

    const found = await repo.findByVaultIdAndOwnerId(vault.id.toString(), "alice");

    expect(found).not.toBeNull();
    expect(found!.ownerId).toBe("alice");
  });

  it("returns null when the owner does not match — the id being right is not enough", async () => {
    const repo = newRepo();
    const vault = makeVault({ ownerId: "alice" });
    await repo.save(vault);

    await expect(
      repo.findByVaultIdAndOwnerId(vault.id.toString(), "bob"),
    ).resolves.toBeNull();
  });

  it("returns null when the id does not match even though the owner does", async () => {
    const repo = newRepo();
    await repo.save(makeVault({ ownerId: "alice" }));

    await expect(
      repo.findByVaultIdAndOwnerId(VaultId.generate().toString(), "alice"),
    ).resolves.toBeNull();
  });

  it("returns null when the stored vault has no owner at all", async () => {
    const repo = newRepo();
    const vault = makeVault({ ownerId: undefined });
    await repo.save(vault);

    await expect(
      repo.findByVaultIdAndOwnerId(vault.id.toString(), "alice"),
    ).resolves.toBeNull();
  });

  it("returns null when storage is empty", async () => {
    const repo = newRepo();
    await expect(
      repo.findByVaultIdAndOwnerId("any", "alice"),
    ).resolves.toBeNull();
  });
});

/* ========================================================================== */
/* list / listByOwnerId                                                        */
/* ========================================================================== */

describe("ChromeStorageVaultRepository listings", () => {
  it("list returns the single stored vault, or [] when storage is empty", async () => {
    const repo = newRepo();
    await expect(repo.list()).resolves.toEqual([]);

    const vault = makeVault();
    await repo.save(vault);

    const all = await repo.list();
    expect(all).toHaveLength(1);
    expect(all[0].id.equals(vault.id)).toBe(true);
    expect(all[0].name).toBe("My Vault");
  });

  it("listByOwnerId filters on the owner", async () => {
    const repo = newRepo();
    await expect(repo.listByOwnerId("alice")).resolves.toEqual([]);

    await repo.save(makeVault({ ownerId: "alice" }));

    await expect(repo.listByOwnerId("alice")).resolves.toHaveLength(1);
    await expect(repo.listByOwnerId("bob")).resolves.toEqual([]);
  });

  it("listByOwnerId excludes an ownerless vault", async () => {
    const repo = newRepo();
    await repo.save(makeVault({ ownerId: undefined }));

    await expect(repo.listByOwnerId("alice")).resolves.toEqual([]);
    await expect(repo.list()).resolves.toHaveLength(1);
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("ChromeStorageVaultRepository.delete", () => {
  it("removes the stored vault when the id matches", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    await expect(repo.delete(vault.id)).resolves.toBe(true);

    expect(local.remove).toHaveBeenCalledWith(STORAGE_KEY);
    expect(store.has(STORAGE_KEY)).toBe(false);
    await expect(repo.list()).resolves.toEqual([]);
  });

  it("refuses to delete a vault it does not own the id for", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    await expect(repo.delete(VaultId.generate())).resolves.toBe(false);

    // The stored vault must still be there — a foreign id is not a delete.
    expect(store.has(STORAGE_KEY)).toBe(true);
    expect(local.remove).not.toHaveBeenCalled();
  });

  it("returns false when storage is empty", async () => {
    const repo = newRepo();
    await expect(repo.delete(VaultId.generate())).resolves.toBe(false);
    expect(local.remove).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* updateMetadata                                                              */
/* ========================================================================== */

describe("ChromeStorageVaultRepository.updateMetadata", () => {
  it("merges the new metadata into the stored vault and persists it", async () => {
    const repo = newRepo();
    const vault = makeVault({ metadata: { color: "blue" } });
    await repo.save(vault);

    await repo.updateMetadata(vault.id.toString(), { pinned: true });

    expect(persisted().metadata).toEqual({ color: "blue", pinned: true });
    expect(persisted().encryptedData).toBe("ciphertext-blob");
    const reloaded = await repo.findById(vault.id);
    expect(reloaded!.metadata).toEqual({ color: "blue", pinned: true });
  });

  it("throws 'Vault not found' when storage is empty", async () => {
    const repo = newRepo();
    await expect(repo.updateMetadata("any", { a: 1 })).rejects.toThrow("Vault not found");
    expect(local.set).not.toHaveBeenCalled();
  });

  it("throws 'Vault not found' for a foreign id and writes nothing", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);
    const before = persisted();

    await expect(
      repo.updateMetadata(VaultId.generate().toString(), { a: 1 }),
    ).rejects.toThrow("Vault not found");

    expect(persisted()).toBe(before);
    expect(local.set).toHaveBeenCalledTimes(1); // only the original save
  });
});

/* ========================================================================== */
/* A storage outage is not "no vault"                                          */
/* ========================================================================== */

describe("ChromeStorageVaultRepository — storage failures propagate", () => {
  it("read paths reject instead of resolving to null / []", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    local.get.mockRejectedValue(new Error("storage unavailable"));

    const outcomes = await Promise.allSettled([
      repo.findById(vault.id),
      repo.list(),
      repo.listByOwnerId("user-1"),
      repo.findByVaultIdAndOwnerId(vault.id.toString(), "user-1"),
    ]);
    for (const outcome of outcomes) expect(outcome.status).toBe("rejected");
  });

  it("save and updateMetadata reject instead of reporting a persisted write", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    local.set.mockRejectedValueOnce(new Error("storage unavailable"));
    await expect(repo.save(vault)).rejects.toThrow("storage unavailable");

    local.set.mockRejectedValueOnce(new Error("storage unavailable"));
    await expect(repo.updateMetadata(vault.id.toString(), { a: 1 })).rejects.toThrow(
      "storage unavailable",
    );
  });

  it("delete rejects instead of reporting a failed removal as false", async () => {
    const repo = newRepo();
    const vault = makeVault();
    await repo.save(vault);

    local.remove.mockRejectedValueOnce(new Error("storage unavailable"));
    await expect(repo.delete(vault.id)).rejects.toThrow("storage unavailable");
    expect(store.has(STORAGE_KEY)).toBe(true);
  });
});
