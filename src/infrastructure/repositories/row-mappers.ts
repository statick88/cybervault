/**
 * Row → domain mappers — Core Infrastructure
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `PostgresVaultRepository` and `PostgresCredentialRepository` read with an
 * explicit column list (all snake_case) and used to hand the row straight to
 *
 *     <Entity>.fromPlainObject({ ...row, <a few camelCase overrides> })
 *
 * `fromPlainObject` expects camelCase keys, so every field missing from the
 * override list arrived `undefined` — or, worse, arrived only by COINCIDENCE:
 * single-word columns (`mode`, `salt`, `version`, `favorite`, `url`, `notes`,
 * `tags`, `title`, `username`, `id`) happen to be spelled identically in both
 * cases, so the spread carried them by accident while every multi-word column
 * did not:
 *
 *     encrypted_data   ->  encryptedData     UNDEFINED  (Vault, NOT NULL column)
 *     encryption_key_id->  encryptionKeyId   UNDEFINED  (Vault, NOT NULL column)
 *     release_share_ref->  releaseShareRef    UNDEFINED  (Credential, H3 round-trip)
 *     owner_id         ->  ownerId           unmapped (handled by override list)
 *     created_at/...   ->  createdAt/...     unmapped (handled by override list)
 *
 * Against a real database the vault case surfaces as a `Vault` whose
 * `encryptedData` is `undefined` on the FIRST read (both columns are
 * `NOT NULL`, so the entity's type contract is violated before any query
 * runs), and the credential case breaks the H3 secret-ref round-trip:
 * migration 003 created `release_share_ref` plus the UNIQUE index
 * `uq_credentials_release_share_ref`, but the read mapper never recovered the
 * value, so a server-minted ref did not survive a read.
 *
 * WHAT THE MAPPERS GUARANTEE
 * --------------------------
 * - Every column in the table is renamed explicitly — no `...row` spread, so
 *   a new column can never leak through unmapped and a renamed domain field
 *   cannot silently become `undefined`.
 * - `TEXT[]` columns (`tags`) arrive from `pg` as JS arrays; a SQL NULL
 *   becomes `[]`, because `.includes()` / `[...tags]` on `undefined` is the
 *   class of crash this pattern already fixed in Plus.
 * - SQL NULL on a domain-optional column becomes `undefined`, not `null`.
 * - Columns that are nullable but REQUIRED by the domain take the column's
 *   own `DEFAULT` (see `mode`, `version`, `salt` below) rather than a value
 *   that would silently change behaviour.
 * - `metadata` goes through `parseJsonbColumn` (`src/shared/jsonb.ts`,
 *   shared with Plus): `pg` has already parsed OID 3802, so
 *   `JSON.parse(row.metadata)` would be a double parse that throws
 *   `SyntaxError: "[object Object]" is not valid JSON` on any non-NULL value.
 * - `TIMESTAMPTZ` columns arrive as `Date`; `fromPlainObject` re-parses with
 *   `new Date(...)`, so the mapper emits the ISO string its signature declares
 *   (a string already produced by the driver is passed through untouched).
 * - `lock_version BIGINT` arrives from `pg` as a STRING; it is passed through
 *   unchanged and `fromPlainObject` runs `Number(...)` on it — the same
 *   handling the entities have always applied.
 *
 * WRITES ARE NOT INVOLVED
 * -----------------------
 * The INSERT / UPDATE parameter arrays read `plain.encryptedData`,
 * `plain.mode`, `plain.releaseShareRef`… — domain-shaped camelCase input bound
 * positionally to snake_case columns, which is correct. Only the READ side was
 * broken and only the read side is touched here.
 *
 * Style mirrors `plus/infrastructure/repositories/row-mappers.ts`.
 */

import type { Credential, CredentialMode } from "../../domain/entities/credential";
import type { Vault } from "../../domain/entities/vault";
import { parseJsonbColumn } from "../../shared/jsonb";

/**
 * `TIMESTAMPTZ` → the plain representation `fromPlainObject` accepts.
 *
 * `pg` returns a `Date`; a driver configured without the timestamp type
 * parser returns the raw text, which is passed through so `new Date(...)`
 * inside the entity sees exactly what it saw before.
 */
function toPlainTimestamp(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : value;
}

/** Same, for a nullable `TIMESTAMPTZ`: SQL NULL / undefined → undefined. */
function toOptionalPlainTimestamp(value: Date | string | null | undefined): string | undefined {
  if (value === null || value === undefined) return undefined;
  return toPlainTimestamp(value);
}

/**
 * One row of `vaults`, spelled the way PostgreSQL returns it.
 *
 * Ground truth: PostgreSQL 16 (`id, name, description, encrypted_data,
 * encryption_key_id, owner_id, metadata, created_at, updated_at, lock_version`).
 *
 * A `type` alias (not an interface) so it satisfies pg's `QueryResultRow`
 * constraint through the implicit index signature.
 */
export type VaultRow = {
  id: string;
  name: string;
  /** `TEXT` — nullable. */
  description: string | null;
  /** `TEXT NOT NULL`. */
  encrypted_data: string;
  /** `VARCHAR(255) NOT NULL`. */
  encryption_key_id: string;
  /** `VARCHAR(255)` — nullable. */
  owner_id: string | null;
  /** `JSONB` — already parsed by the driver's OID 3802 type parser. */
  metadata: unknown;
  /** `TIMESTAMPTZ` — arrives as a `Date`. */
  created_at: Date | string;
  /** `TIMESTAMPTZ` — arrives as a `Date`. */
  updated_at: Date | string;
  /** `BIGINT NOT NULL` — `pg` returns BIGINT as a string. */
  lock_version: string | number;
};

/**
 * One row of `credentials`, spelled the way PostgreSQL returns it.
 *
 * Ground truth: PostgreSQL 16 (`id, vault_id, title, username,
 * encrypted_password, url, notes, tags, favorite, created_at, updated_at,
 * last_used, mode, salt, version, release_share_ref, lock_version`).
 */
export type CredentialRow = {
  id: string;
  vault_id: string;
  title: string;
  username: string;
  /** `TEXT NOT NULL`. */
  encrypted_password: string;
  /** `VARCHAR(20) DEFAULT 'personal'` — nullable, no NOT NULL. */
  mode: string | null;
  /** `TEXT` — nullable; migration 003 added it with NO default. */
  salt: string | null;
  /** `INTEGER DEFAULT 1` — nullable, no NOT NULL. */
  version: number | null;
  /** `VARCHAR(255)` — nullable, UNIQUE via `uq_credentials_release_share_ref`. */
  release_share_ref: string | null;
  /** `TEXT` — nullable. */
  url: string | null;
  /** `TEXT` — nullable. */
  notes: string | null;
  /** `TEXT[] DEFAULT '{}'` — already a JS array; SQL NULL when the column is NULL. */
  tags: string[] | null;
  /** `BOOLEAN DEFAULT FALSE` — nullable. */
  favorite: boolean | null;
  /** `TIMESTAMPTZ` — arrives as a `Date`. */
  created_at: Date | string;
  /** `TIMESTAMPTZ` — arrives as a `Date`. */
  updated_at: Date | string;
  /** `TIMESTAMPTZ` — nullable. */
  last_used: Date | string | null;
  /** `BIGINT NOT NULL` — `pg` returns BIGINT as a string. */
  lock_version: string | number;
};

/** The exact argument shape `Vault.fromPlainObject` expects. */
export type VaultPlain = Parameters<typeof Vault.fromPlainObject>[0];

/** The exact argument shape `Credential.fromPlainObject` expects. */
export type CredentialPlain = Parameters<typeof Credential.fromPlainObject>[0];

/**
 * Map a `vaults` row to the camelCase plain object `Vault.fromPlainObject`
 * expects.
 *
 * The two `NOT NULL` columns that the old spread left `undefined`
 * (`encrypted_data`, `encryption_key_id`) are mapped here by name — that is
 * the defect this function exists to close.
 */
export function mapVaultRow(row: VaultRow): VaultPlain {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    encryptedData: row.encrypted_data,
    encryptionKeyId: row.encryption_key_id,
    ownerId: row.owner_id ?? undefined,
    // jsonb is ALREADY parsed by `pg`; JSON.parse here would throw.
    metadata: parseJsonbColumn(row.metadata),
    createdAt: toPlainTimestamp(row.created_at),
    updatedAt: toPlainTimestamp(row.updated_at),
    // BIGINT → string from the driver; the entity converts with Number().
    lockVersion: row.lock_version,
  };
}

/**
 * Map a `credentials` row to the camelCase plain object
 * `Credential.fromPlainObject` expects.
 *
 * `release_share_ref` → `releaseShareRef` is the H3 round-trip the old spread
 * dropped: the column and its UNIQUE index exist, but the value never came
 * back from a read.
 */
export function mapCredentialRow(row: CredentialRow): CredentialPlain {
  return {
    id: row.id,
    vaultId: row.vault_id,
    title: row.title,
    username: row.username,
    encryptedPassword: row.encrypted_password,
    // `DEFAULT 'personal'`: a NULL can only come from a hand-inserted row;
    // fall back to the column default so a credential is never "mode-less".
    mode: (row.mode ?? "personal") as CredentialMode,
    // Nullable with NO default (migration 003 `ADD COLUMN ... salt TEXT`).
    // The domain requires a string; "" derives an HKDF key that can never
    // match ciphertext written with a real salt, so a legacy NULL row fails
    // closed on decrypt instead of throwing a TypeError on read.
    salt: row.salt ?? "",
    // `DEFAULT 1`.
    version: row.version ?? 1,
    // The H3 secret ref: SQL NULL means "not a managed/shared credential".
    releaseShareRef: row.release_share_ref ?? undefined,
    url: row.url ?? undefined,
    notes: row.notes ?? undefined,
    // NULL → [] : `.includes()` / `[...tags]` on undefined is the crash.
    tags: row.tags ?? [],
    // `favorite BOOLEAN DEFAULT FALSE` is nullable; NULL reads as false.
    favorite: row.favorite ?? false,
    createdAt: toPlainTimestamp(row.created_at),
    updatedAt: toPlainTimestamp(row.updated_at),
    lastUsed: toOptionalPlainTimestamp(row.last_used),
    // BIGINT → string from the driver; the entity converts with Number().
    lockVersion: row.lock_version,
  };
}
