/**
 * T6 — real-database round-trip for the Core Postgres repositories.
 *
 * The unit tests use hand-built fixtures, which is exactly why this defect class
 * survived: the mappers only break against rows that PostgreSQL actually
 * returns. This script writes real rows through the repositories and reads them
 * back, asserting the fields that were silently lost.
 *
 * Run from the repo root with DATABASE_URL pointed at a real PostgreSQL 16.
 * Not part of the Jest suite: it needs a live database by design.
 */
import { PostgresVaultRepository } from "../src/infrastructure/repositories/PostgresVaultRepository";
import { PostgresCredentialRepository } from "../src/infrastructure/repositories/PostgresCredentialRepository";
import { Vault } from "../src/domain/entities/vault";
import { Credential } from "../src/domain/entities/credential";

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
const dbUrl: string = DATABASE_URL;

let failures = 0;
function check(label: string, actual: unknown, expected: unknown): void {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  const shown = typeof actual === "string" && actual.length > 24 ? `${actual.slice(0, 24)}…` : actual;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}: ${JSON.stringify(shown)}`);
}

async function main(): Promise<void> {
  const vaults = new PostgresVaultRepository(dbUrl);
  const credentials = new PostgresCredentialRepository(dbUrl);

  const suffix = Date.now().toString(36);

  // --- Vault: encryptedData / encryptionKeyId were never mapped and arrived undefined.
  console.log("\nVault round-trip (PostgresVaultRepository)");
  const vault = Vault.create({
    name: `t6-vault-${suffix}`,
    description: "T6 round-trip",
    encryptedData: "ENCRYPTED-CIPHERTEXT-ABC123",
    encryptionKeyId: "key-id-xyz789",
  });
  await vaults.save(vault);
  const readVault = await vaults.findById(vault.id);
  if (!readVault) throw new Error("vault not found after save");
  check("encryptedData", readVault.encryptedData, "ENCRYPTED-CIPHERTEXT-ABC123");
  check("encryptionKeyId", readVault.encryptionKeyId, "key-id-xyz789");
  check("name", readVault.name, `t6-vault-${suffix}`);
  // save() bumps the optimistic-locking counter, so equality with the pre-save
  // value is the wrong assertion. What H5 actually needs is that it round-trips
  // as a number the repository can compare against.
  check("lockVersion is a number >= 1", typeof readVault.lockVersion === "number" && readVault.lockVersion >= 1, true);

  // --- Credential: releaseShareRef never round-tripped (H3 claimed fixed; it was not).
  console.log("\nCredential round-trip (PostgresCredentialRepository) — managed");
  const secretRef = `sr-t6-${suffix}`;
  const credential = Credential.createManaged({
    vaultId: vault.id as never,
    title: "T6 managed credential",
    username: "t6-user",
    encryptedPassword: "ENCRYPTED-PASSWORD-XYZ",
    salt: "c2FsdC10Ni1zYWx0",
    releaseShareRef: secretRef,
    url: "https://example.test",
    tags: ["t6"],
    favorite: true,
  });
  await credentials.save(credential);
  const readCredential = await credentials.findById(credential.id);
  if (!readCredential) throw new Error("credential not found after save");
  check("releaseShareRef", readCredential.releaseShareRef, secretRef);
  check("encryptedPassword", readCredential.encryptedPassword, "ENCRYPTED-PASSWORD-XYZ");
  check("salt", readCredential.salt, "c2FsdC10Ni1zYWx0");
  check("mode", readCredential.mode, credential.mode);
  check("version", readCredential.version, credential.version);
  check("tags", readCredential.tags, ["t6"]);

  // The lookup that depends on the field H3 added.
  const bySecretRef = await credentials.findBySecretRef(secretRef);
  check("findBySecretRef(secretRef) resolves", bySecretRef?.id, credential.id);

  // --- Cleanup: leave no test rows behind.
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: dbUrl });
  await pool.query("DELETE FROM credentials WHERE id = $1", [credential.id]);
  await pool.query("DELETE FROM vaults WHERE id = $1", [vault.id]);
  await pool.end();

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error("T6 failed:", error instanceof Error ? error.message : error);
  process.exit(1);
});
