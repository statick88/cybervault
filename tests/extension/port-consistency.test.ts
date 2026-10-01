/**
 * R10 — the extension's defaults must match the ports Compose publishes.
 *
 * ## Why this file exists
 *
 * A fresh clone did not work. The extension's fallback for Plus was
 * `http://localhost:3011`, a port that appears nowhere: not in `docker-compose.yml`,
 * not in `.env`, not in the container. And the step-up was worse — it read a
 * module-level `STEP_UP_PLUS_URL` constant directly, so the entire step-up
 * ignored the `plus_base_url` setting every other Plus call honours. A
 * configurable endpoint pinned in one call site is worse than a wrong default:
 * there is no way to point it anywhere else.
 *
 * ## Why a test rather than a read
 *
 * The failure is a *disagreement between two files*, and either one can change
 * without the other. A comment is not a contract. These cases compare the
 * extension's fallbacks against what Compose and `.env` actually declare, so
 * a port bump on either side turns this red instead of producing a fresh clone
 * that silently cannot reach its own services.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(__dirname, "..", "..");
const read = (rel: string): string => readFileSync(resolve(repoRoot, rel), "utf8");

const compose = read("docker-compose.yml");
const env = read(".env");
const auditor = read("src/background/auditor.ts");
const popup = read("src/ui/popup/popup.ts");

/** `KEY=1234` in `.env`, or `KEY:-1234` as a compose default. */
function envPort(key: string): string | undefined {
  const fromEnv = env.match(new RegExp(`^${key}=(\\d+)`, "m"));
  if (fromEnv) return fromEnv[1];
  const fromCompose = compose.match(new RegExp(`\\$\\{${key}:-(\\d+)\\}`));
  return fromCompose?.[1];
}

/** Every `http://localhost:PORT` literal in a source file. */
function localhostPorts(source: string): number[] {
  return [...source.matchAll(/http:\/\/localhost:(\d+)/g)].map((m) => Number(m[1]));
}

describe("R10 — extension defaults agree with the deployed ports", () => {
  it("resolves the API and Plus ports the way the stack publishes them", () => {
    // If these are missing the whole file is vacuous, and a vacuous security
    // test is worse than none.
    expect(envPort("API_PORT")).toBeDefined();
    expect(envPort("PLUS_PORT")).toBeDefined();
  });

  it("the background worker defaults to the deployed Plus port", () => {
    const plusPort = envPort("PLUS_PORT")!;
    const ports = localhostPorts(auditor);

    // Every localhost literal in the worker must be a port the stack actually
    // serves. A literal naming anything else is a fresh clone that cannot
    // reach its own services.
    const served = new Set(
      [envPort("API_PORT"), envPort("PLUS_PORT")].filter((p): p is string => Boolean(p)),
    );
    for (const port of ports) {
      expect({ port, served: [...served] }).toEqual({ port, served: expect.arrayContaining([String(port)]) });
    }
    expect(ports).toContain(Number(plusPort));
  });

  it("the popup defaults to the deployed API port", () => {
    const apiPort = envPort("API_PORT")!;

    expect(localhostPorts(popup)).toContain(Number(apiPort));
  });

  it("no Plus call site bypasses the plus_base_url setting", () => {
    // The defect behind R10: `STEP_UP_PLUS_URL` was read directly by the two
    // step-up calls, so the whole step-up ignored the configured endpoint. The
    // constant must not come back, whatever value it carries.
    expect(auditor).not.toMatch(/STEP_UP_PLUS_URL/);
    // And the fallback must be a named constant rather than an inline literal,
    // so there is exactly one place to change when the port moves.
    expect(auditor).toMatch(/const DEFAULT_PLUS_BASE_URL = "http:\/\/localhost:\d+"/);
    // Two constants, not one: the API default and the Plus default. Each
    // appears exactly once as a literal, and every other site names it.
    expect(auditor).toMatch(/const DEFAULT_CORE_BASE_URL = "http:\/\/localhost:\d+"/);
    expect(auditor.match(/"http:\/\/localhost:3010"|DEFAULT_CORE_BASE_URL/g)?.length).toBeGreaterThan(0);
    // Two literals total in the file: the two constants.
    expect(localhostPorts(auditor).length).toBe(2);
  });

  it("every Plus call site resolves the URL from storage or that constant", () => {
    const callSites = [...auditor.matchAll(/api\/v1\/challenges\/(?:trigger|approve)/g)];
    expect(callSites.length).toBeGreaterThanOrEqual(2);

    for (const site of callSites) {
      const before = auditor.slice(Math.max(0, site.index - 400), site.index);
      // Either the storage lookup or the named fallback, in the lines above.
      expect(before).toMatch(/plus_base_url|DEFAULT_PLUS_BASE_URL/);
    }
  });
});
