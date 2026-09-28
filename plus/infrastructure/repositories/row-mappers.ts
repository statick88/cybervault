/**
 * Row → domain mappers — Plus Infrastructure
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The three Plus repositories read with `SELECT *`, which hands back
 * snake_case column names (`user_id`, `allowed_operations`, `created_at`…),
 * and used to pass that row straight to
 *
 *     <Entity>.fromPlainObject({ ...row, <a few camelCase overrides> })
 *
 * `fromPlainObject` expects camelCase keys, so every field not in the
 * override list arrived `undefined`:
 *
 *     { ...row }                ->  { user_id: "u1", allowed_operations: […] }
 *     obj.userId                ->  undefined
 *     obj.allowedOperations     ->  undefined
 *
 * Against a real database that surfaces as
 *
 *     TypeError: Cannot read properties of undefined (reading 'includes')
 *
 * the first time `Entitlement.isOperationAllowed()` or `.addOperation()` runs,
 * because `this.props.allowedOperations` is `undefined`. The entitlement layer
 * gates every Plus capability, so the whole authorization path was dead.
 *
 * WHAT THE MAPPERS GUARANTEE
 * --------------------------
 * - Every column in the table is renamed explicitly — no `...row` spread, so
 *   a new column can never leak through unmapped and a renamed domain field
 *   cannot silently become `undefined`.
 * - `TEXT[]` columns (`allowed_operations`, `habitual_countries`, `tags`)
 *   arrive from `pg` as JS arrays; a SQL NULL becomes `[]`, because
 *   `.includes()` on `undefined` is exactly the crash being fixed.
 * - SQL NULL on a domain-optional column becomes `undefined`, not `null`.
 * - `metadata` goes through `parseJsonbColumn` (`src/shared/jsonb.ts`, shared
 *   with Core): `pg` has already parsed OID 3802, so `JSON.parse(row.metadata)`
 *   would be a double parse that throws on any non-NULL value.
 * - `TIMESTAMPTZ` columns arrive as `Date`; `fromPlainObject` re-parses with
 *   `new Date(...)`, so the mapper emits the ISO string its signature declares
 *   (a string already produced by the driver is passed through untouched).
 *
 * WRITES ARE NOT INVOLVED
 * -----------------------
 * The INSERT parameter arrays read `plain.userId`, `plain.pestilloState`,
 * `plain.habitualCountries`… — domain-shaped input bound positionally to
 * snake_case columns, which is correct. Only the READ side was broken and only
 * the read side is touched here.
 *
 * Style mirrors `PostgresChallengeRepository`'s `ChallengeRow` /
 * `toChallengeProps`.
 */

import type {
  CapabilityOperation,
  Entitlement,
  PestilloState,
} from "../../domain/entities/entitlement";
import type { PlusUser, UserRole } from "../../domain/entities/user";
import type {
  Resource,
  ResourceCriticality,
  ResourceEnvironment,
  ResourceType,
} from "../../domain/entities/resource";
import { parseJsonbColumn } from "@/shared/jsonb";

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
 * The `active` columns are `BOOLEAN DEFAULT TRUE` with no `NOT NULL`, so a
 * hand-inserted row can hold NULL. The domain requires a boolean; a NULL
 * activity flag must never read as "active", so it maps to `false` (the same
 * falsy value the previous spread produced at runtime).
 */
function toActiveFlag(value: boolean | null | undefined): boolean {
  return value ?? false;
}

/**
 * One row of `plus_entitlements`, spelled the way PostgreSQL returns it.
 *
 * A `type` alias (not an interface) so it satisfies pg's `QueryResultRow`
 * constraint through the implicit index signature.
 */
export type EntitlementRow = {
  id: string;
  user_id: string;
  resource_id: string;
  pestillo_state: string;
  /** `TEXT[]` — already a JS array; SQL NULL when the column is NULL. */
  allowed_operations: string[] | null;
  valid_from: Date | string | null;
  valid_until: Date | string | null;
  /** `JSONB` — already parsed by the driver's OID 3802 type parser. */
  metadata: unknown;
  created_by: string;
  created_at: Date | string;
  updated_at: Date | string;
};

/** One row of `plus_users`, spelled the way PostgreSQL returns it. */
export type PlusUserRow = {
  id: string;
  email: string;
  name: string;
  role: string;
  /** `TEXT[]` — already a JS array; SQL NULL when the column is NULL. */
  habitual_countries: string[] | null;
  timezone: string;
  active: boolean | null;
  metadata: unknown;
  created_at: Date | string;
  updated_at: Date | string;
  last_login_at: Date | string | null;
};

/** One row of `plus_resources`, spelled the way PostgreSQL returns it. */
export type ResourceRow = {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  environment: string;
  criticality: string;
  description: string | null;
  /** `TEXT[]` — already a JS array; SQL NULL when the column is NULL. */
  tags: string[] | null;
  owner_team: string | null;
  metadata: unknown;
  active: boolean | null;
  created_at: Date | string;
  updated_at: Date | string;
};

/** The exact argument shape `Entitlement.fromPlainObject` expects. */
export type EntitlementPlain = Parameters<typeof Entitlement.fromPlainObject>[0];

/** The exact argument shape `PlusUser.fromPlainObject` expects. */
export type PlusUserPlain = Parameters<typeof PlusUser.fromPlainObject>[0];

/** The exact argument shape `Resource.fromPlainObject` expects. */
export type ResourcePlain = Parameters<typeof Resource.fromPlainObject>[0];

/**
 * Map a `plus_entitlements` row to the camelCase plain object
 * `Entitlement.fromPlainObject` expects.
 */
export function mapEntitlementRow(row: EntitlementRow): EntitlementPlain {
  return {
    id: row.id,
    userId: row.user_id,
    resourceId: row.resource_id,
    pestilloState: row.pestillo_state as PestilloState,
    // NULL → [] : `.includes()` on undefined is the crash this fixes.
    allowedOperations: (row.allowed_operations ?? []) as CapabilityOperation[],
    validFrom: toOptionalPlainTimestamp(row.valid_from),
    validUntil: toOptionalPlainTimestamp(row.valid_until),
    metadata: parseJsonbColumn(row.metadata),
    createdBy: row.created_by,
    createdAt: toPlainTimestamp(row.created_at),
    updatedAt: toPlainTimestamp(row.updated_at),
  };
}

/**
 * Map a `plus_users` row to the camelCase plain object
 * `PlusUser.fromPlainObject` expects.
 */
export function mapPlusUserRow(row: PlusUserRow): PlusUserPlain {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role as UserRole,
    // NULL → [] : `isCountryHabitual()` calls `.includes()` on this.
    habitualCountries: row.habitual_countries ?? [],
    timezone: row.timezone,
    active: toActiveFlag(row.active),
    metadata: parseJsonbColumn(row.metadata),
    createdAt: toPlainTimestamp(row.created_at),
    updatedAt: toPlainTimestamp(row.updated_at),
    lastLoginAt: toOptionalPlainTimestamp(row.last_login_at),
  };
}

/**
 * Map a `plus_resources` row to the camelCase plain object
 * `Resource.fromPlainObject` expects.
 */
export function mapResourceRow(row: ResourceRow): ResourcePlain {
  return {
    id: row.id,
    name: row.name,
    type: row.type as ResourceType,
    endpoint: row.endpoint,
    environment: row.environment as ResourceEnvironment,
    criticality: row.criticality as ResourceCriticality,
    description: row.description ?? undefined,
    // NULL → [] : `addTag()` / `removeTag()` call `.includes()` on this.
    tags: row.tags ?? [],
    ownerTeam: row.owner_team ?? undefined,
    metadata: parseJsonbColumn(row.metadata),
    active: toActiveFlag(row.active),
    createdAt: toPlainTimestamp(row.created_at),
    updatedAt: toPlainTimestamp(row.updated_at),
  };
}
