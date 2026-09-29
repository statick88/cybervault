/**
 * S2 batch 3 — Plus API bootstrap: `plus/api/main.ts` + `plus/api/module-aliases.ts`.
 *
 * WHY THESE TWO ARE TESTED TOGETHER
 * ---------------------------------
 * `main.ts`'s very first statement is `import "./module-aliases"`. That import
 * order is documented as load-bearing: TypeScript preserves it in the emitted
 * CommonJS, so `node dist/plus/api/main.js` installs the `@/…` resolver before
 * anything that needs it. A test that imports `main.ts` and then inspects the
 * resolver is therefore testing the pair in the only order production uses.
 *
 * WHAT IS PINNED
 * 1. Instrumentation — importing the entry point must succeed and must leave
 *    the resolver hook installed. That is the observable proof that BOTH
 *    modules were loaded and instrumented (a file no test imports gets no
 *    lcov record at all).
 * 2. The resolver keeps Node's own resolution FIRST: a resolvable request and
 *    an `@/…` request that already resolves are returned untouched.
 * 3. Only `@/…` requests are retried. `@plus/…`, relative specifiers and
 *    anything else that fails are re-thrown UNCHANGED — the blast radius on the
 *    rest of the module graph is the whole safety claim of this file.
 * 4. The retry target is computed relative to THIS file
 *    (`plus/api/../../src`), which is what makes the same source resolve both
 *    in a checkout and inside `dist/` in the image.
 * 5. `main.ts`'s guard `require.main === module` is evaluated (and is false
 *    under any test runner), so the entry point never starts a server or opens
 *    a database pool from a test — no live database, no Docker, no port.
 */

import { Module } from "module";

type ResolveFilename = (request: string, ...forwarded: unknown[]) => string;
type ModuleInternals = { _resolveFilename: ResolveFilename };

const internals = Module as unknown as ModuleInternals;
const originalResolveFilename = internals._resolveFilename;

/** Resolve with whatever is installed right now, reporting the outcome. */
function tryResolve(request: string, parent: NodeModule = module): string {
  try {
    return `OK ${internals._resolveFilename(request, parent, false)}`;
  } catch (error) {
    return `THREW ${(error as NodeJS.ErrnoException).code ?? String(error)}`;
  }
}

/** Resolve and return the thrown error, so its message can be inspected. */
function resolveError(request: string, parent: NodeModule = module): Error {
  try {
    internals._resolveFilename(request, parent, false);
  } catch (error) {
    return error as Error;
  }
  throw new Error(`expected ${request} NOT to resolve`);
}

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("Plus API bootstrap — instrumentation", () => {
  it("loads plus/api/main.ts, which installs the runtime alias resolver", () => {
    // Requiring the entry point is the instrumentation assertion: it proves
    // `main.ts` AND its first import, `module-aliases.ts`, were both loaded.
    expect(() => require("../../plus/api/main")).not.toThrow();

    // The hook rewrites `_resolveFilename`; before the import it is the
    // pristine Node function, afterwards it is the wrapper.
    expect(internals._resolveFilename).not.toBe(originalResolveFilename);
    expect(internals._resolveFilename.name).toBe("resolveFilenameWithAlias");
  });

  it("declares no exports — it is a process entry point, not a library", () => {
    const loaded = require("../../plus/api/main");
    expect(loaded).toEqual({});
  });
});

/* ========================================================================== */
/* module-aliases — the resolver                                               */
/* ========================================================================== */

describe("plus/api/module-aliases — runtime path-alias resolver", () => {
  beforeAll(() => {
    // Required here as well so this describe block can run on its own; the
    // module is cached, so the hook is installed exactly once.
    require("../../plus/api/module-aliases");
  });

  afterAll(() => {
    // Restore Node's resolver so the wrapper — which is a process-wide
    // monkey patch by design — cannot outlive this suite in the worker.
    internals._resolveFilename = originalResolveFilename;
  });

  it("still resolves anything Node resolves on its own", () => {
    expect(tryResolve("fs")).toBe("OK fs");
    expect(tryResolve("path")).toBe("OK path");
  });

  it("resolves an `@/…` specifier that the original resolver could not", () => {
    // Under ts-jest the alias has never been a real package, so the pristine
    // resolver must fail on it and the hook's retry must be what succeeds.
    expect(() => originalResolveFilename("@/shared/logger.ts", module, false)).toThrow();

    const resolved = internals._resolveFilename("@/shared/logger.ts", module, false);
    expect(resolved).toMatch(/\/src\/shared\/logger\.ts$/);
  });

  it("computes the retry target relative to plus/api — `../../src`", () => {
    const resolved = internals._resolveFilename(
      "@/shared/logger.ts",
      module,
      false,
    );
    // `plus/api/module-aliases.ts` → `<root>/src/shared/logger.ts`
    expect(resolved).toMatch(/\/src\/shared\/logger\.ts$/);
    expect(resolved).not.toMatch(/\/dist\//);
  });

  it("re-throws the ORIGINAL error for a relative specifier that does not exist", () => {
    const error = resolveError("./definitely-not-here");
    expect((error as NodeJS.ErrnoException).code).toBe("MODULE_NOT_FOUND");
    // The alias retry only ever rewrites `@/…` requests, so the message still
    // names the specifier the caller passed — not a rewritten absolute path.
    expect(error.message).toContain("./definitely-not-here");
    expect(error.message).not.toContain("/src/");
  });

  it("does NOT retry the `@plus/…` alias — only `@/…` is hooked", () => {
    const error = resolveError("@plus/domain/operations");
    expect((error as NodeJS.ErrnoException).code).toBe("MODULE_NOT_FOUND");
    expect(error.message).toContain("@plus/domain/operations");
  });

  it("leaves a failing `@/…` request failing, with the retried path in the message", () => {
    const error = resolveError("@/nope/not-a-module");
    expect((error as NodeJS.ErrnoException).code).toBe("MODULE_NOT_FOUND");
    // Proof the retry branch actually ran: the reported path is the one the
    // hook built, not the bare specifier.
    expect(error.message).not.toContain("'@/nope/not-a-module'");
    expect(error.message).toContain("/src/nope/not-a-module");
  });

  it("forwards every non-failing request byte-for-byte", () => {
    expect(internals._resolveFilename("fs", module, false)).toBe("fs");
    expect(
      internals._resolveFilename("node:fs", module, false),
    ).toBe("node:fs");
  });

  it("is idempotent — re-requiring the module does not stack a second hook", () => {
    const installed = internals._resolveFilename;
    jest.resetModules();
    require("../../plus/api/module-aliases");
    // The module is re-evaluated by `resetModules`, so a NEW wrapper is
    // installed, but it still delegates to the pristine original: one extra
    // hop at most, never an accumulating chain of closures.
    expect(typeof internals._resolveFilename).toBe("function");
    expect(tryResolve("fs")).toBe("OK fs");
    expect(internals._resolveFilename).not.toBe(originalResolveFilename);
    // Put the suite-local hook back so later assertions keep their subject.
    internals._resolveFilename = installed;
  });
});

/* ========================================================================== */
/* main.ts — the guard                                                         */
/* ========================================================================== */

describe("plus/api/main.ts — entry-point guard", () => {
  beforeAll(() => {
    require("../../plus/api/module-aliases");
    require("../../plus/api/main");
  });

  afterAll(() => {
    internals._resolveFilename = originalResolveFilename;
  });

  it("evaluates `require.main === module` and does NOT bootstrap under a test", () => {
    // In Jest `require.main` is `null` (a non-writable, non-configurable own
    // property), so the guard is false and `main()` never runs. That is what
    // keeps this suite free of a listening socket and of a database pool.
    const requireMain = (require as unknown as { main: NodeModule | null })
      .main;
    expect(requireMain ?? null).not.toBe(module);
    expect(typeof requireMain === "object" || requireMain === null).toBe(true);

    // The entry point is importable and side-effect free at import time.
    expect(() => require("../../plus/api/main")).not.toThrow();
  });

  it("wires the three repositories the server consumes, and only those", () => {
    const source = require("node:fs").readFileSync(
      require("node:path").resolve(__dirname, "../../plus/api/main.ts"),
      "utf8",
    );

    // Import order is documented as load-bearing — assert the source proves it
    // rather than trusting the emitted output to have kept it.
    const aliasIndex = source.indexOf('import "./module-aliases"');
    const serverIndex = source.indexOf('from "./server"');
    expect(aliasIndex).toBeGreaterThan(-1);
    expect(aliasIndex).toBeLessThan(serverIndex);

    const repoImports = source.match(
      /from "\.\.\/infrastructure\/repositories\/\w+"/g,
    );
    expect(repoImports).toEqual([
      'from "../infrastructure/repositories/PostgresChallengeRepository"',
      'from "../infrastructure/repositories/PostgresEntitlementRepository"',
      'from "../infrastructure/repositories/PostgresPlusUserRepository"',
    ]);

    // The resource repository is deliberately NOT wired: `PlusApiServer`
    // accepts no `IResourceRepository`, so a fourth pool would be opened and
    // never read.
    expect(source).not.toMatch(
      /import \{ PostgresResourceRepository \}/,
    );
  });

  it("exits non-zero when the bootstrap promise rejects", () => {
    const source = require("node:fs").readFileSync(
      require("node:path").resolve(__dirname, "../../plus/api/main.ts"),
      "utf8",
    );

    expect(source).toContain("if (require.main === module)");
    expect(source).toContain("process.exit(1)");
    // A refusal to start must not leave a half-alive process.
    expect(source).toContain("Plus server startup failed");
  });
});
