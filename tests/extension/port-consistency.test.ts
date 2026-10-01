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
 *
 * ## The same drift, one layer out
 *
 * Moving a published host port is only half a change: every URL a *host*
 * consumer builds has to move with it. `17c7899` moved `API_PORT` to 3010 and
 * `PLUS_PORT` to 3003 and left the host-facing defaults naming 3001 — the
 * compose `PLUS_BASE_URL` / `PLUS_CHALLENGE_BASE_URL`, the fallbacks in
 * `plus/api/server.ts`, the `plus/admin` client and its dev proxy, and the
 * `openapi.yaml` server URL. The stack still started, so nothing failed
 * loudly; the step-up email just linked to a port nothing served. The second
 * `describe` reads those files and holds each host-facing URL to the port the
 * same stack publishes.
 *
 * ## `.env` is not the contract
 *
 * `.env` is gitignored, so it is absent on a fresh clone and in CI. Reading it
 * unconditionally made this suite throw ENOENT there, which is the mirror image
 * of the bug it exists to catch: the failure was invisible locally because the
 * developer's `.env` was present. `.env.example` is the committed contract, and
 * `envPort` below already falls back to the compose defaults, so the committed
 * file resolves every port without it.
 *
 * Note what that fallback hides: `.env.example` declares **neither `API_PORT`
 * nor `PLUS_PORT`** — nor `PLUS_BASE_URL` / `PLUS_CHALLENGE_BASE_URL` — even
 * though the compose comments used to say those keys live in `.env`, a file
 * that exists on no clone. So for a fresh clone and in CI `envPort()` survives
 * on the compose fallback alone, and `docker-compose.yml` is the whole
 * contract. That is deliberate, and it is why the assertions below read the
 * compose file rather than trusting the comment beside it.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(__dirname, "..", "..");
const read = (rel: string): string => readFileSync(resolve(repoRoot, rel), "utf8");

const compose = read("docker-compose.yml");
// `.env` is gitignored, so it is absent on a fresh clone and in CI. Reading it
// unconditionally made this suite throw ENOENT there, which is the mirror image
// of the bug it exists to catch: the failure was invisible locally because the
// developer's `.env` was present. `.env.example` is the committed contract, and
// `envPort` below already falls back to the compose defaults, so the committed
// file resolves every port without it.
const envPath = existsSync(resolve(repoRoot, ".env")) ? ".env" : ".env.example";
const env = read(envPath);
const auditor = read("src/background/auditor.ts");
const popup = read("src/ui/popup/popup.ts");
const plusServer = read("plus/api/server.ts");
const plusAdminApi = read("plus/admin/src/services/api.ts");
const viteConfig = read("plus/admin/vite.config.ts");
const openapi = read("openapi.yaml");

/** `KEY=1234` in `.env`, or `KEY:-1234` as a compose default. */
function envPort(key: string): string | undefined {
  const fromEnv = env.match(new RegExp(`^${key}=(\\d+)`, "m"));
  if (fromEnv) return fromEnv[1];
  const fromCompose = compose.match(new RegExp(`\\$\\{${key}:-([^}]+)\\}`));
  return fromCompose?.[1];
}

/**
 * The same resolution as `envPort`, for values that are not a bare number —
 * a URL, for instance. Compose is asked twice because the two answers matter
 * independently: a local `.env` may override `PLUS_BASE_URL`, and when it does,
 * that override *is* what the container is told and what the browser must be
 * able to reach. `envPort` cannot carry it: its regex only matches digits.
 *
 * Falls through to the compose default on an empty value, which is what
 * Compose's `:-` does.
 */
function envValue(key: string): string | undefined {
  // `.+`, not `.*`: an empty `KEY=` in `.env` must fall through to the compose
  // default, which is what Compose's `:-` does. Matching empty here would hand
  // the assertions a URL that names no port at all.
  const fromEnv = env.match(new RegExp(`^${key}=(.+)$`, "m"));
  if (fromEnv) return fromEnv[1].trim().replace(/^["']|["']$/g, "");
  const fromCompose = compose.match(new RegExp(`\\$\\{${key}:-([^}]+)\\}`));
  return fromCompose?.[1];
}

/** Every `http://localhost:PORT` literal in a source file. */
function localhostPorts(source: string): number[] {
  return [...source.matchAll(/http:\/\/localhost:(\d+)/g)].map((m) => Number(m[1]));
}

/** The localhost port a single URL names, or `undefined` when it names none. */
function localhostPort(url: string): number | undefined {
  return localhostPorts(url)[0];
}

/** The `process.env.KEY || "http://localhost:PORT"` fallback in `server.ts`. */
function serverFallback(key: string): string | undefined {
  return plusServer.match(new RegExp(`process\\.env\\.${key} \\|\\| "([^"]+)"`))?.[1];
}

/** The `REACT_APP_PLUS_API_URL || "http://localhost:PORT"` admin fallback. */
function adminApiFallback(): string | undefined {
  return plusAdminApi.match(/REACT_APP_PLUS_API_URL \|\| "([^"]+)"/)?.[1];
}

/** The Vite dev proxy `target` — the dev server runs on the host. */
function viteProxyTarget(): string | undefined {
  return viteConfig.match(/target:\s*"([^"]+)"/)?.[1];
}

/** `servers[0].url`, the base every consumer of the spec builds on. */
function openapiServerUrl(): string | undefined {
  return openapi.match(/^\s*- url: (\S+)$/m)?.[1];
}

/**
 * Every host port `docker-compose.yml` publishes, every profile included.
 *
 * A profile-gated service's port collides on the host whether or not its
 * profile is currently up — and the admin console and profile `dev` are used
 * together by definition. Env overrides resolve through `envPort`, so a local
 * `.env` re-pointing a service moves this set with it, exactly as it moves
 * what Compose actually publishes.
 */
function composeHostPorts(): number[] {
  const ports = new Set<number>();
  // `- "${KEY:-3010}:3000"` — the env-overridable form.
  for (const m of compose.matchAll(/-\s*"\$\{([A-Z_]+):-(\d+)\}:\d+"/g)) {
    ports.add(Number(envPort(m[1]) ?? m[2]));
  }
  // `- "5001:5001"` — the fixed form (ipfs).
  for (const m of compose.matchAll(/-\s*"(\d+):\d+"/g)) {
    ports.add(Number(m[1]));
  }
  return [...ports];
}

/**
 * The port the `plus/admin` Vite dev server *binds* on the host. Not a URL:
 * nothing dials it, which is precisely why the URL comparisons above never
 * saw it.
 */
function viteDevPort(): number | undefined {
  const raw = viteConfig.match(/server:\s*\{[\s\S]*?\bport:\s*(\d+)/)?.[1];
  return raw === undefined ? undefined : Number(raw);
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

/**
 * The drift class above, seen from the other side of the boundary.
 *
 * The first `describe` asks "does the extension dial the port the stack
 * publishes?". These ask the same question of everything *else* that builds a
 * URL for a host: Compose's own env defaults, the Plus server's fallbacks, the
 * admin client, and the OpenAPI contract. Each is a plain literal that only a
 * human keeps in step, which is exactly the shape `17c7899` got wrong — it
 * moved the published port and left every one of these naming the old one.
 */
describe("R10 — host-facing URLs name the ports the stack publishes", () => {
  // Extraction is the precondition for every case below. If a regex stops
  // matching, the comparisons would throw or compare `undefined` to
  // `undefined` — a green that means nothing. A vacuous check is worse than
  // none, so pin the inputs first.
  it("extracts every host-facing URL it is about to compare", () => {
    expect(envPort("API_PORT")).toBeDefined();
    expect(envPort("PLUS_PORT")).toBeDefined();
    expect(envValue("PLUS_BASE_URL")).toBeDefined();
    expect(envValue("PLUS_CHALLENGE_BASE_URL")).toBeDefined();
    expect(serverFallback("PLUS_BASE_URL")).toBeDefined();
    expect(serverFallback("PLUS_CHALLENGE_BASE_URL")).toBeDefined();
    expect(adminApiFallback()).toBeDefined();
    expect(viteProxyTarget()).toBeDefined();
    expect(openapiServerUrl()).toBeDefined();
  });

  it("Compose tells the browser and the challenge email the published Plus port", () => {
    const published = Number(envPort("PLUS_PORT"));

    // `challenge.ts` builds the emailed link as `${baseUrl}/challenge/${id}`,
    // and the browser opens `PLUS_BASE_URL` directly. Both must be reachable
    // *from the host*, so both name the published port — never the container
    // port that only the docker network can see.
    for (const key of ["PLUS_BASE_URL", "PLUS_CHALLENGE_BASE_URL"]) {
      const url = envValue(key)!;
      expect({ key, url, port: localhostPort(url), published }).toEqual({
        key,
        url,
        port: published,
        published,
      });
    }
  });

  it("plus/api/server.ts falls back to the published Plus port", () => {
    const published = Number(envPort("PLUS_PORT"));

    // The same two URLs, as the code's own fallback when the variable is
    // unset — the value a run outside Compose ends up with.
    for (const key of ["PLUS_BASE_URL", "PLUS_CHALLENGE_BASE_URL"]) {
      const url = serverFallback(key)!;
      expect({ key, url, port: localhostPort(url), published }).toEqual({
        key,
        url,
        port: published,
        published,
      });
    }
  });

  it("the plus/admin client and its dev proxy dial the published Plus port", () => {
    const published = Number(envPort("PLUS_PORT"));

    // Both run on the host: the browser loads the admin UI, and the Vite dev
    // server proxies `/api` onward. Neither can use the container port.
    const hostFacing: Array<[string, string]> = [
      ["plus/admin/src/services/api.ts", adminApiFallback()!],
      ["plus/admin/vite.config.ts", viteProxyTarget()!],
    ];
    for (const [source, url] of hostFacing) {
      expect({ source, url, port: localhostPort(url), published }).toEqual({
        source,
        url,
        port: published,
        published,
      });
    }
  });

  it("openapi.yaml's server URL is the published API port", () => {
    const published = Number(envPort("API_PORT"));
    const url = openapiServerUrl()!;

    // Swagger UI's "Try it out" and every generated client build their
    // requests from this line, and both run on the host.
    expect({ url, port: localhostPort(url), published }).toEqual({
      url,
      port: published,
      published,
    });
  });
});

/**
 * The bind port: the drift class the two describes above structurally cannot
 * see.
 *
 * They compare URLs a host *dials*; the admin dev server's `server.port` is
 * never dialed, so when it shipped on 3002 — the very host port Compose
 * publishes for `adminer` under profile `dev` — every comparison above stayed
 * green while the admin console and the adminer UI fought over one port.
 *
 * Both sides move independently: a bump in `plus/admin/vite.config.ts`, or a
 * new `ADMINER_PORT` / `API_PORT` / `PLUS_PORT` / `SWAGGER_PORT` default in
 * Compose. This case reads the bind port out of the Vite config and every
 * published host port out of Compose and asserts the two sets are disjoint,
 * so either bump turns it red.
 */
describe("R10 — the admin dev server binds no port the stack publishes", () => {
  it("the Vite dev port collides with nothing Compose publishes to the host", () => {
    const devPort = viteDevPort();
    const published = composeHostPorts();

    // Extraction guards: an `undefined` dev port or an empty published set
    // would satisfy disjointness vacuously, and a vacuous check is worse
    // than none. The four env-port lookups also prove the profile-gated
    // services (swagger, adminer) made it into the set — the collision this
    // case exists to catch lived exactly there.
    expect(devPort).toBeDefined();
    expect(published).toEqual(
      expect.arrayContaining([
        Number(envPort("API_PORT")),
        Number(envPort("PLUS_PORT")),
        Number(envPort("SWAGGER_PORT")),
        Number(envPort("ADMINER_PORT")),
      ]),
    );

    // The property: whatever Compose publishes, the admin dev server binds
    // something else. The collisions array is reported rather than just
    // asserted empty so a red names the port that took the other one.
    expect({ devPort, collisions: published.filter((p) => p === devPort) }).toEqual({
      devPort,
      collisions: [],
    });
  });
});
