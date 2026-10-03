/**
 * Declared-but-non-functional commands: a `scripts` entry that names a file
 * that does not exist.
 *
 * ## Why this file exists
 *
 * Six entries in `package.json` pointed at `./infra/...` — a directory that
 * has never existed on this branch's history. `build:docker` named
 * `infra/docker/Dockerfile.api` while the file sat at `docker/Dockerfile.api`;
 * `infra:start`, `infra:stop`, `test:docker` and `test:kubernetes` named
 * scripts that exist nowhere; `infra:scan` named a scanner whose only
 * real-world counterpart is a *different tool*. Nothing in CI, nothing in the
 * suite, and no type-checker reads those strings, so every one of them shipped
 * green. The class is: **a declared thing that does not exist** — a
 * disagreement between `package.json` and the file tree, the same shape this
 * repository's port-consistency suite catches between the extension and
 * Compose, one layer out.
 *
 * All six have been removed or fixed. The expectation below pins an empty
 * set: a new dangling script turns this red.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(__dirname, "..", "..");
const pkg = JSON.parse(readFileSync(resolve(repoRoot, "package.json"), "utf8")) as {
  scripts: Record<string, string>;
};
const scripts = pkg.scripts;

/** Build outputs: absent on a fresh clone by design, so not repo paths here. */
const GENERATED_ROOTS = new Set(["dist", "node_modules", "coverage"]);

/** Path-like tokens in a script command (see header for the filtering rules). */
function pathTokens(command: string): string[] {
  return command
    .split(/\s+/)
    .filter(
      (t) =>
        t.includes("/") &&
        !t.startsWith("-") &&
        !t.includes(":") &&
        !t.includes("$") &&
        !/[`'"]/.test(t),
    );
}

/** `<name>` targets of every `npm run <name>` in a command. */
function npmRunTargets(command: string): string[] {
  return [...command.matchAll(/\bnpm\s+run\s+([^\s&|;]+)/g)].map((m) => m[1]);
}

/** Every declared repo path that fails to resolve, one entry per miss. */
function danglingPaths(): Array<{ script: string; missing: string }> {
  const dangling: Array<{ script: string; missing: string }> = [];
  for (const [name, command] of Object.entries(scripts)) {
    for (const token of pathTokens(command)) {
      const rel = token.replace(/^\.\//, "");
      if (GENERATED_ROOTS.has(rel.split("/")[0])) continue;
      if (!existsSync(resolve(repoRoot, rel))) dangling.push({ script: name, missing: token });
    }
  }
  return dangling;
}

describe("package.json scripts resolve to files that exist", () => {
  // Extraction must not be vacuous — if the filters stop matching, every case
  // below would pass against a package.json full of dangling paths.
  it("extracts repo paths from the scripts it is about to check", () => {
    expect(pathTokens(scripts["build:docker"])).toContain("docker/Dockerfile.api");
    expect(pathTokens(scripts["build:ext"])).toContain("scripts/build-extension.mjs");
    expect(pathTokens(scripts["security:audit"])).toContain("./scripts/security-audit.sh");
    expect(Object.keys(scripts).length).toBeGreaterThan(10);
  });

  it("resolves every path a script names — no dangling entries allowed", () => {
    expect(danglingPaths()).toEqual([]);
  });

  it("every `npm run <name>` target is declared", () => {
    const references = Object.entries(scripts).flatMap(([name, command]) =>
      npmRunTargets(command).map((target) => ({ from: name, target })),
    );
    // build:all runs `npm run build && npm run build:ext` — a reference that
    // only exists if the extractor above found it.
    expect(references).toEqual(
      expect.arrayContaining([
        { from: "build:all", target: "build" },
        { from: "build:all", target: "build:ext" },
      ]),
    );
    for (const ref of references) {
      expect({ ...ref, declared: scripts[ref.target] }).toEqual({
        ...ref,
        declared: expect.any(String),
      });
    }
  });
});
