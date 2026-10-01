/**
 * S2 batch 3 — `plus/domain/operations.ts` registry tests.
 *
 * This module is pure data plus five lookup helpers, which makes it look
 * trivial — and that is exactly why it is cheap to pin and expensive to break
 * silently: `OPERATIONS_REGISTRY` is the single source of truth for risk,
 * step-up policy and audit category across the capability gate, so a typo in a
 * key or a policy flag that flips is a policy change nobody notices.
 *
 * The assertions are therefore written as INVARIANTS over the whole registry
 * rather than as spot checks of individual entries:
 *   - the derived collections (`ALL_OPERATIONS`, `OPERATIONS_BY_CATEGORY`,
 *     `DEFAULT_STEP_UP_OPERATIONS`) agree with the registry — no key is lost,
 *     duplicated or invented;
 *   - step-up is required for exactly the high/critical operations (the
 *     security invariants the capability gate relies on);
 *   - every entry is complete and self-consistent.
 */

import {
  ALL_OPERATIONS,
  DEFAULT_DENIED_OPERATIONS,
  DEFAULT_STEP_UP_OPERATIONS,
  OPERATIONS_BY_CATEGORY,
  OPERATIONS_REGISTRY,
  getAuditCategory,
  getDefaultRiskLevel,
  getOperationMetadata,
  getOperationsByCategory,
  isValidOperation,
  requiresStepUpByDefault,
  type CapabilityOperation,
} from "../../plus/domain/operations";

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("plus/domain/operations — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof OPERATIONS_REGISTRY).toBe("object");
    expect(OPERATIONS_REGISTRY).not.toBeNull();
    expect(Object.keys(OPERATIONS_REGISTRY).length).toBeGreaterThan(0);
  });
});

/* ========================================================================== */
/* Completeness of the registry                                                */
/* ========================================================================== */

describe("OPERATIONS_REGISTRY", () => {
  const keys = Object.keys(OPERATIONS_REGISTRY) as CapabilityOperation[];

  it("declares every operation in the union and nothing else", () => {
    expect(keys.sort()).toEqual(
      [
        "ADMIN",
        "AUTOFILL",
        "BACKUP",
        "CONNECT",
        "DELETE_SECRET",
        "EDIT_SECRET",
        "EXPORT_SECRET",
        "READ",
        "RESTORE",
        "ROTATE_SECRET",
        "TOTP",
        "VIEW",
      ].sort(),
    );
  });

  it("gives every entry a complete, well-formed metadata record", () => {
    const categories = [
      "credential",
      "connection",
      "administrative",
      "backup",
      "secret",
    ];
    const risks = ["low", "medium", "high", "critical"];

    for (const key of keys) {
      const meta = OPERATIONS_REGISTRY[key];
      expect(meta.operation).toBe(key); // the entry must be under its own name
      expect(typeof meta.displayName).toBe("string");
      expect(meta.displayName.length).toBeGreaterThan(0);
      expect(typeof meta.description).toBe("string");
      expect(meta.description.length).toBeGreaterThan(0);
      expect(categories).toContain(meta.category);
      expect(risks).toContain(meta.defaultRiskLevel);
      expect(typeof meta.requiresStepUpByDefault).toBe("boolean");
      expect(typeof meta.auditCategory).toBe("string");
      expect(meta.auditCategory.length).toBeGreaterThan(0);
    }
  });

  it("is a plain own-key map — every entry is reachable as an own property", () => {
    // `as const` is type-level only; this pins the runtime shape the lookup
    // helpers depend on (`operation in OPERATIONS_REGISTRY`), including that
    // no entry is inherited from Object.prototype.
    for (const key of Object.keys(OPERATIONS_REGISTRY)) {
      expect(Object.prototype.hasOwnProperty.call(OPERATIONS_REGISTRY, key)).toBe(
        true,
      );
    }
    expect(OPERATIONS_REGISTRY.hasOwnProperty("toString")).toBe(false);
  });
});

/* ========================================================================== */
/* Derived collections agree with the registry                                 */
/* ========================================================================== */

describe("derived collections", () => {
  it("ALL_OPERATIONS lists exactly the registry keys", () => {
    expect([...ALL_OPERATIONS].sort()).toEqual(
      (Object.keys(OPERATIONS_REGISTRY) as CapabilityOperation[]).sort(),
    );
    expect(new Set(ALL_OPERATIONS).size).toBe(ALL_OPERATIONS.length);
  });

  it("OPERATIONS_BY_CATEGORY partitions the registry with no loss or overlap", () => {
    const grouped = Object.values(OPERATIONS_BY_CATEGORY).flat();
    expect([...grouped].sort()).toEqual([...ALL_OPERATIONS].sort());
    expect(new Set(grouped).size).toBe(grouped.length);

    for (const [category, ops] of Object.entries(OPERATIONS_BY_CATEGORY)) {
      for (const op of ops) {
        expect(OPERATIONS_REGISTRY[op].category).toBe(category);
      }
    }
  });

  it("DEFAULT_STEP_UP_OPERATIONS is exactly the set flagged for step-up", () => {
    const expected = ALL_OPERATIONS.filter(
      (op) => OPERATIONS_REGISTRY[op].requiresStepUpByDefault,
    );
    expect([...DEFAULT_STEP_UP_OPERATIONS].sort()).toEqual(expected.sort());
  });

  it("starts with no operations denied by default", () => {
    expect(DEFAULT_DENIED_OPERATIONS).toEqual([]);
  });
});

/* ========================================================================== */
/* Security invariants                                                         */
/* ========================================================================== */

describe("step-up policy invariants", () => {
  it("requires step-up for every high or critical operation", () => {
    const highOrCritical = ALL_OPERATIONS.filter((op) =>
      ["high", "critical"].includes(OPERATIONS_REGISTRY[op].defaultRiskLevel),
    );
    expect(highOrCritical.length).toBeGreaterThan(0);
    for (const op of highOrCritical) {
      expect(`${op}: ${requiresStepUpByDefault(op)}`).toBe(`${op}: true`);
    }
  });

  it("never demands step-up for a low or medium operation", () => {
    const lowish = ALL_OPERATIONS.filter((op) =>
      ["low", "medium"].includes(OPERATIONS_REGISTRY[op].defaultRiskLevel),
    );
    expect(lowish.length).toBeGreaterThan(0);
    for (const op of lowish) {
      expect(`${op}: ${requiresStepUpByDefault(op)}`).toBe(`${op}: false`);
    }
  });

  it("requires step-up for every destructive secret operation", () => {
    for (const op of [
      "DELETE_SECRET",
      "EXPORT_SECRET",
      "ROTATE_SECRET",
      "EDIT_SECRET",
      "ADMIN",
      "RESTORE",
      "BACKUP",
    ] as CapabilityOperation[]) {
      expect(requiresStepUpByDefault(op)).toBe(true);
    }
  });

  it("keeps AUTOFILL, VIEW, TOTP and READ usable without a third factor", () => {
    for (const op of ["AUTOFILL", "VIEW", "TOTP", "READ"] as CapabilityOperation[]) {
      expect(requiresStepUpByDefault(op)).toBe(false);
    }
  });
});

/* ========================================================================== */
/* Lookup helpers                                                              */
/* ========================================================================== */

describe("lookup helpers", () => {
  it("getOperationMetadata returns the registry entry", () => {
    expect(getOperationMetadata("ADMIN")).toBe(OPERATIONS_REGISTRY.ADMIN);
    expect(getOperationMetadata("AUTOFILL").displayName).toBe(
      "Auto-fill Credentials",
    );
  });

  it("getDefaultRiskLevel reads the registry", () => {
    expect(getDefaultRiskLevel("VIEW")).toBe("low");
    expect(getDefaultRiskLevel("AUTOFILL")).toBe("medium");
    expect(getDefaultRiskLevel("BACKUP")).toBe("high");
    expect(getDefaultRiskLevel("RESTORE")).toBe("critical");
  });

  it("getOperationsByCategory returns the group and [] for an unknown one", () => {
    expect(getOperationsByCategory("secret")).toEqual([
      "ROTATE_SECRET",
      "EDIT_SECRET",
      "DELETE_SECRET",
      "EXPORT_SECRET",
    ]);
    expect(getOperationsByCategory("credential")).toEqual([
      "AUTOFILL",
      "VIEW",
      "TOTP",
    ]);
    expect(getOperationsByCategory("nope")).toEqual([]);
  });

  it("getAuditCategory reads the registry", () => {
    expect(getAuditCategory("ADMIN")).toBe("admin_action");
    expect(getAuditCategory("READ")).toBe("data_access");
    expect(getAuditCategory("TOTP")).toBe("credential_access");
  });

  it("isValidOperation accepts declared codes and rejects everything else", () => {
    for (const op of ALL_OPERATIONS) {
      expect(isValidOperation(op)).toBe(true);
    }
    expect(isValidOperation("admin")).toBe(false); // case sensitive
    expect(isValidOperation("PURGE")).toBe(false);
    expect(isValidOperation("")).toBe(false);
    expect(isValidOperation("__proto__")).toBe(false);
    expect(isValidOperation("toString")).toBe(false);
    expect(isValidOperation("constructor")).toBe(false);
  });

  it("isValidOperation narrows the type for the caller", () => {
    const candidate: string = "TOTP";
    if (isValidOperation(candidate)) {
      // Compiles only because of the type predicate; runs the narrowing too.
      expect(getOperationMetadata(candidate).operation).toBe("TOTP");
    } else {
      throw new Error("expected TOTP to validate");
    }
  });
});
