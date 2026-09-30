import { Entitlement } from "../../plus/domain/entities/entitlement";
import { PlusUser } from "../../plus/domain/entities/user";
import { Resource } from "../../plus/domain/entities/resource";
import {
  mapEntitlementRow,
  mapPlusUserRow,
  mapResourceRow,
} from "../../plus/infrastructure/repositories/row-mappers";
import type {
  EntitlementRow,
  PlusUserRow,
  ResourceRow,
} from "../../plus/infrastructure/repositories/row-mappers";
import { parseJsonbColumn } from "../../src/shared/jsonb";

/**
 * Regression guard for the snake_case → camelCase read defect found during the
 * Plus runtime work (2026-09-28).
 *
 * All three Plus repositories read with `SELECT *` — which returns snake_case
 * column names — and passed the row to `<Entity>.fromPlainObject({ ...row,
 * <a few camelCase overrides> })`. `fromPlainObject` expects camelCase keys, so
 * every field not in the override list arrived `undefined`. The visible crash
 * was:
 *
 *     TypeError: Cannot read properties of undefined (reading 'includes')
 *     at Entitlement.isOperationAllowed() / Entitlement.addOperation()
 *
 * because `allowedOperations` — the `TEXT[]` column — kept its snake_case key.
 * The entitlement layer gates every Plus capability, so the whole authorization
 * path was dead against a real database.
 *
 * Every fixture below is shaped exactly as `pg` returns it: `TIMESTAMPTZ` as a
 * `Date`, `TEXT[]` as a JS array, `jsonb` as an already-parsed object, SQL NULL
 * as `null`. No database is required.
 */

const ENTITLEMENT_ROW: EntitlementRow = {
  id: "u-1:db-prod-001",
  user_id: "u-1",
  resource_id: "db-prod-001",
  pestillo_state: "enabled",
  // TEXT[] — the driver decodes this into a JS array, never a comma string.
  allowed_operations: ["READ", "CONNECT", "TOTP"],
  valid_from: new Date("2026-01-01T00:00:00.000Z"),
  valid_until: null,
  // JSONB — the driver's OID 3802 parser has already produced an object.
  metadata: { maxAssurance: 3, conditions: { network: "corp" } },
  created_by: "admin-1",
  created_at: new Date("2026-01-02T10:30:00.000Z"),
  updated_at: new Date("2026-01-03T11:45:00.000Z"),
};

const USER_ROW: PlusUserRow = {
  id: "u-1",
  email: "ops@example.com",
  name: "Ops One",
  role: "operator",
  habitual_countries: ["EC", "US"],
  timezone: "America/Guayaquil",
  active: true,
  metadata: { badge: "A-1" },
  created_at: new Date("2026-01-02T10:30:00.000Z"),
  updated_at: new Date("2026-01-03T11:45:00.000Z"),
  last_login_at: new Date("2026-01-04T08:00:00.000Z"),
  // R4 lockout columns (006_pin_lockout.sql).
  failed_pin_attempts: 4,
  locked_until: null,
};

const RESOURCE_ROW: ResourceRow = {
  id: "db-prod-001",
  name: "Primary PostgreSQL",
  type: "database",
  endpoint: "db01.internal.example:5432",
  environment: "production",
  criticality: "critical",
  description: "Customer data",
  tags: ["pci", "postgres"],
  owner_team: "platform",
  metadata: { seats: 12 },
  active: true,
  created_at: new Date("2026-01-02T10:30:00.000Z"),
  updated_at: new Date("2026-01-03T11:45:00.000Z"),
};

describe("mapEntitlementRow", () => {
  it("maps every column of plus_entitlements to its camelCase field", () => {
    const plain = mapEntitlementRow(ENTITLEMENT_ROW);

    // Exact key set: nothing snake_case survives, nothing is left behind.
    expect(Object.keys(plain).sort()).toEqual(
      [
        "id",
        "userId",
        "resourceId",
        "pestilloState",
        "allowedOperations",
        "validFrom",
        "validUntil",
        "metadata",
        "createdBy",
        "createdAt",
        "updatedAt",
      ].sort(),
    );

    expect(plain.id).toBe("u-1:db-prod-001");
    expect(plain.userId).toBe("u-1");
    expect(plain.resourceId).toBe("db-prod-001");
    expect(plain.pestilloState).toBe("enabled");
    expect(plain.allowedOperations).toEqual(["READ", "CONNECT", "TOTP"]);
    expect(plain.validFrom).toBe("2026-01-01T00:00:00.000Z");
    expect(plain.validUntil).toBeUndefined();
    expect(plain.metadata).toEqual({ maxAssurance: 3, conditions: { network: "corp" } });
    expect(plain.createdBy).toBe("admin-1");
    expect(plain.createdAt).toBe("2026-01-02T10:30:00.000Z");
    expect(plain.updatedAt).toBe("2026-01-03T11:45:00.000Z");
  });

  it("REGRESSION: produces an entity whose allowedOperations .includes() does not throw", () => {
    const entitlement = Entitlement.fromPlainObject(mapEntitlementRow(ENTITLEMENT_ROW));

    expect(Array.isArray(entitlement.allowedOperations)).toBe(true);
    expect(entitlement.allowedOperations).toEqual(["READ", "CONNECT", "TOTP"]);
    // The exact call that crashed live against PostgreSQL 16.
    expect(() => entitlement.isOperationAllowed("READ")).not.toThrow();
    expect(entitlement.isOperationAllowed("READ")).toBe(true);
    expect(entitlement.isOperationAllowed("ADMIN")).toBe(false);
    // addOperation() runs `.includes()` too.
    expect(() => entitlement.addOperation("TOTP")).not.toThrow();
    expect(entitlement.addOperation("DELETE_SECRET")).toBeUndefined();
    expect(entitlement.allowedOperations).toContain("DELETE_SECRET");
    // The setter path spreads the same array.
    expect(() => entitlement.setOperations(["VIEW"])).not.toThrow();
    expect(entitlement.allowedOperations).toEqual(["VIEW"]);
  });

  it("REGRESSION: the previous {...row} spread threw exactly the observed TypeError", () => {
    // `pg` hands repositories rows typed as `any`, which is why the old spread
    // compiled: TypeScript never checked the keys. Reproduced verbatim here.
    const driverRow: any = { ...ENTITLEMENT_ROW };
    const legacy = Entitlement.fromPlainObject({
      ...driverRow,
      validFrom: driverRow.valid_from ?? undefined,
      validUntil: driverRow.valid_until ?? undefined,
      metadata: parseJsonbColumn(driverRow.metadata),
      createdAt: driverRow.created_at,
      updatedAt: driverRow.updated_at,
    });

    // Construction succeeds; the first capability check is where it died.
    expect(() => legacy.isOperationAllowed("READ")).toThrow(TypeError);
    expect(() => legacy.isOperationAllowed("READ")).toThrow(/includes/);
    expect(() => legacy.addOperation("READ")).toThrow(/includes/);
  });

  it("defaults a NULL allowed_operations (TEXT[]) to [] rather than undefined", () => {
    const entitlement = Entitlement.fromPlainObject(
      mapEntitlementRow({ ...ENTITLEMENT_ROW, allowed_operations: null }),
    );

    expect(entitlement.allowedOperations).toEqual([]);
    expect(() => entitlement.isOperationAllowed("READ")).not.toThrow();
    expect(entitlement.isOperationAllowed("READ")).toBe(false);
    expect(() => entitlement.addOperation("READ")).not.toThrow();
  });

  it("normalises SQL NULL optionals to undefined, not null", () => {
    const plain = mapEntitlementRow({
      ...ENTITLEMENT_ROW,
      valid_from: null,
      valid_until: null,
      metadata: null,
    });

    // The keys still exist — the row had the columns — but they are undefined.
    expect(Object.prototype.hasOwnProperty.call(plain, "validFrom")).toBe(true);
    expect(plain.validFrom).toBeUndefined();
    expect(plain.validUntil).toBeUndefined();
    expect(plain.metadata).toBeUndefined();

    const entitlement = Entitlement.fromPlainObject(plain);
    expect(entitlement.validFrom).toBeUndefined();
    expect(entitlement.validUntil).toBeUndefined();
    expect(entitlement.metadata).toBeUndefined();
  });

  it("reads jsonb metadata as the object the driver already parsed", () => {
    // Passing an object where `JSON.parse` expected a string is what the old
    // `JSON.parse(row.metadata)` did wrong; the mapper must not repeat it.
    const plain = mapEntitlementRow(ENTITLEMENT_ROW);
    expect(() => Entitlement.fromPlainObject(plain)).not.toThrow();
    expect(plain.metadata).toEqual(ENTITLEMENT_ROW.metadata);
  });
});

describe("mapPlusUserRow", () => {
  it("maps every column of plus_users to its camelCase field", () => {
    const plain = mapPlusUserRow(USER_ROW);

    expect(Object.keys(plain).sort()).toEqual(
      [
        "id",
        "email",
        "name",
        "role",
        "habitualCountries",
        "timezone",
        "active",
        "metadata",
        "createdAt",
        "updatedAt",
        "lastLoginAt",
        "failedPinAttempts",
        "lockedUntil",
      ].sort(),
    );

    expect(plain.id).toBe("u-1");
    expect(plain.email).toBe("ops@example.com");
    expect(plain.name).toBe("Ops One");
    expect(plain.role).toBe("operator");
    expect(plain.habitualCountries).toEqual(["EC", "US"]);
    expect(plain.timezone).toBe("America/Guayaquil");
    expect(plain.active).toBe(true);
    expect(plain.metadata).toEqual({ badge: "A-1" });
    expect(plain.createdAt).toBe("2026-01-02T10:30:00.000Z");
    expect(plain.updatedAt).toBe("2026-01-03T11:45:00.000Z");
    expect(plain.lastLoginAt).toBe("2026-01-04T08:00:00.000Z");
    expect(plain.failedPinAttempts).toBe(4);
    // NULL locked_until means "not locked" — undefined, never null.
    expect(plain.lockedUntil).toBeUndefined();
  });

  it("maps an armed lock, and defaults a row from before migration 006", () => {
    const locked = mapPlusUserRow({
      ...USER_ROW,
      failed_pin_attempts: 5,
      locked_until: new Date("2026-01-05T09:30:00.000Z"),
    });
    expect(locked.failedPinAttempts).toBe(5);
    expect(locked.lockedUntil).toBe("2026-01-05T09:30:00.000Z");

    // A table 006 has not touched yet has no key at all, and a NULL counter
    // reads the same way: a clean budget, an unlocked user.
    const legacy: PlusUserRow = { ...USER_ROW } as PlusUserRow;
    delete (legacy as Record<string, unknown>).failed_pin_attempts;
    delete (legacy as Record<string, unknown>).locked_until;
    expect(mapPlusUserRow(legacy).failedPinAttempts).toBe(0);
    expect(mapPlusUserRow(legacy).lockedUntil).toBeUndefined();
    expect(mapPlusUserRow({ ...USER_ROW, failed_pin_attempts: null }).failedPinAttempts).toBe(0);

    // The entity must accept the mapped shape without throwing.
    expect(() => PlusUser.fromPlainObject(mapPlusUserRow(legacy))).not.toThrow();
    expect(PlusUser.fromPlainObject(mapPlusUserRow(legacy)).failedPinAttempts).toBe(0);
  });

  it("REGRESSION: habitualCountries .includes() does not throw", () => {
    const user = PlusUser.fromPlainObject(mapPlusUserRow(USER_ROW));

    expect(Array.isArray(user.habitualCountries)).toBe(true);
    expect(() => user.isCountryHabitual("EC")).not.toThrow();
    expect(user.isCountryHabitual("ec")).toBe(true);
    expect(user.isCountryHabitual("DE")).toBe(false);
    expect(() => user.addHabitualCountry("DE")).not.toThrow();
    expect(user.habitualCountries).toContain("DE");
  });

  it("defaults a NULL habitual_countries (TEXT[]) to [] and null optionals to undefined", () => {
    const plain = mapPlusUserRow({
      ...USER_ROW,
      habitual_countries: null,
      last_login_at: null,
      metadata: null,
    });

    expect(plain.habitualCountries).toEqual([]);
    expect(plain.lastLoginAt).toBeUndefined();
    expect(plain.metadata).toBeUndefined();

    const user = PlusUser.fromPlainObject(plain);
    expect(user.habitualCountries).toEqual([]);
    expect(() => user.isCountryHabitual("EC")).not.toThrow();
    expect(user.isCountryHabitual("EC")).toBe(false);
    expect(user.lastLoginAt).toBeUndefined();
  });

  it("reads a NULL active flag as false so an unknown user is never active", () => {
    // `active BOOLEAN DEFAULT TRUE` has no NOT NULL, so NULL is reachable.
    expect(mapPlusUserRow({ ...USER_ROW, active: null }).active).toBe(false);
    expect(mapPlusUserRow(USER_ROW).active).toBe(true);
  });
});

describe("mapResourceRow", () => {
  it("maps every column of plus_resources to its camelCase field", () => {
    const plain = mapResourceRow(RESOURCE_ROW);

    expect(Object.keys(plain).sort()).toEqual(
      [
        "id",
        "name",
        "type",
        "endpoint",
        "environment",
        "criticality",
        "description",
        "tags",
        "ownerTeam",
        "metadata",
        "active",
        "createdAt",
        "updatedAt",
      ].sort(),
    );

    expect(plain.id).toBe("db-prod-001");
    expect(plain.name).toBe("Primary PostgreSQL");
    expect(plain.type).toBe("database");
    expect(plain.endpoint).toBe("db01.internal.example:5432");
    expect(plain.environment).toBe("production");
    expect(plain.criticality).toBe("critical");
    expect(plain.description).toBe("Customer data");
    expect(plain.tags).toEqual(["pci", "postgres"]);
    expect(plain.ownerTeam).toBe("platform");
    expect(plain.metadata).toEqual({ seats: 12 });
    expect(plain.active).toBe(true);
    expect(plain.createdAt).toBe("2026-01-02T10:30:00.000Z");
    expect(plain.updatedAt).toBe("2026-01-03T11:45:00.000Z");
  });

  it("REGRESSION: tags .includes() does not throw", () => {
    const resource = Resource.fromPlainObject(mapResourceRow(RESOURCE_ROW));

    expect(Array.isArray(resource.tags)).toBe(true);
    expect(() => resource.addTag("pci")).not.toThrow();
    expect(resource.addTag("ha")).toBeUndefined();
    expect(resource.tags).toEqual(["pci", "postgres", "ha"]);
    expect(() => resource.removeTag("pci")).not.toThrow();
    expect(resource.tags).toEqual(["postgres", "ha"]);
  });

  it("defaults a NULL tags (TEXT[]) to [] and null optionals to undefined", () => {
    const plain = mapResourceRow({
      ...RESOURCE_ROW,
      tags: null,
      description: null,
      owner_team: null,
      metadata: null,
    });

    expect(plain.tags).toEqual([]);
    expect(plain.description).toBeUndefined();
    expect(plain.ownerTeam).toBeUndefined();
    expect(plain.metadata).toBeUndefined();

    const resource = Resource.fromPlainObject(plain);
    expect(resource.tags).toEqual([]);
    expect(() => resource.addTag("pci")).not.toThrow();
    expect(resource.description).toBeUndefined();
    expect(resource.ownerTeam).toBeUndefined();
  });

  it("reads a NULL active flag as false so an unknown resource is never active", () => {
    expect(mapResourceRow({ ...RESOURCE_ROW, active: null }).active).toBe(false);
    expect(mapResourceRow(RESOURCE_ROW).active).toBe(true);
  });
});
