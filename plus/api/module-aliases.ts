/**
 * Runtime resolver for the TypeScript `paths` aliases used by `plus/**`.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * `tsconfig.json` declares `"paths": { "@/*": ["src/*"], "@plus/*": ["plus/*"] }`.
 * TypeScript honours that at COMPILE time and then emits the specifier
 * untouched: `dist/plus/api/server.js` literally contains
 * `require("@/shared/logger")`, which plain Node cannot resolve — there is no
 * `@/shared` package. Starting the compiled Plus API with `node` therefore
 * died with `MODULE_NOT_FOUND` before a single socket was bound.
 *
 * Core never hit this because every file under `src/` uses relative imports
 * (`dist/src/**` contains zero `@/` requires). Plus does use the alias, and
 * rewriting six source files is out of scope for the runtime task, so the
 * bootstrap owns the problem instead.
 *
 * HOW
 * ---
 * Node documents `Module._resolveFilename(request, parent, isMain, options)`;
 * `@types/node@20` does not declare it, hence the hand-written signature and
 * the single `as unknown as` below — deliberately NOT `any`, and deliberately
 * not a `@ts-ignore`.
 *
 * The hook keeps Node's own resolution FIRST and only retries when it
 * already threw, and only for `@/…` requests. Everything else — including the
 * `@plus/…` alias, which no emitted file currently uses — is forwarded
 * untouched, so the blast radius on the rest of the module graph is nil.
 *
 * Under `tsx` (the dev runner) `tsx` resolves `paths` itself, so the retry
 * branch never fires; under `node dist/plus/api/main.js` (the container) it is
 * what makes the process boot. The fallback target is written relative to
 * this file, so it lands on `dist/src` in the image and on `src` in a
 * checkout — the same sources either way.
 *
 * MUST BE IMPORTED FIRST: `main.ts` imports this module before anything that
 * (transitively) requires an aliased specifier, and TypeScript preserves
 * import order in the emitted CommonJS.
 */

import { Module } from "module";
import { join } from "path";

/** Node's signature, minus the parts this wrapper does not inspect. */
type ResolveFilename = (request: string, ...forwarded: unknown[]) => string;

/** The undocumented-but-documented-in-Node-API surface we are hooking. */
type ModuleInternals = {
  _resolveFilename: ResolveFilename;
};

const ALIAS_PREFIX = "@/";

const internals = Module as unknown as ModuleInternals;
const originalResolveFilename = internals._resolveFilename;

internals._resolveFilename = function resolveFilenameWithAlias(
  request: string,
  ...forwarded: unknown[]
): string {
  try {
    return originalResolveFilename(request, ...forwarded);
  } catch (error) {
    if (!request.startsWith(ALIAS_PREFIX)) {
      throw error;
    }
    // `plus/api/…` → `<root>/src/…`, and `dist/plus/api/…` → `dist/src/…`.
    const target = join(__dirname, "..", "..", "src", request.slice(ALIAS_PREFIX.length));
    return originalResolveFilename(target, ...forwarded);
  }
};
