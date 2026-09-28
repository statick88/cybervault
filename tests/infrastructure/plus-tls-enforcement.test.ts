/**
 * H6 (Plus scope) — `plus/api/server.ts` carried the exact fail-open TLS
 * defect that was fixed in Core, deliberately left out of the original
 * finding: "OUT OF SCOPE (reported, deliberately not fixed here):
 * `plus/api/server.ts` carries the same `HTTPS_ENABLED` default and the same
 * 'falling back to HTTP' catch."
 *
 * WHY PLUS MATTERS MORE THAN A CONVENIENCE
 * ----------------------------------------
 * Plus is the authorization service: it issues capabilities, drives the
 * step-up challenges and verifies PINs. A Plus process that serves
 * `POST /api/v1/challenges/verify` or `/api/v1/capabilities/request` over
 * plaintext hands the whole authorization protocol to the network.
 *
 * THE DEFECTS
 * -----------
 * 1. `HTTPS_ENABLED` defaulted to `false` via the module-load snapshot in
 *    `SECURITY_CONFIG`, so a production Plus deployment that never set the
 *    variable booted a plaintext HTTP server without a word.
 * 2. With `HTTPS_ENABLED=true` but an unreadable key or certificate, `start()`
 *    logged `warn("HTTPS certificates not found, falling back to HTTP")` and
 *    started a PLAINTEXT server anyway — the operator asked for TLS and
 *    silently got the opposite, on the authorization API.
 *
 * THE FIX (mirrors Core's `ApiServer.assertTlsConfiguration()` exactly)
 * ----------------------------------------------------------------------
 * `PlusApiServer.assertTlsConfiguration()` runs at the top of `start()`,
 * re-reading the environment at STARTUP (not the frozen `SECURITY_CONFIG`
 * snapshot), and THROWS:
 *
 *  * `NODE_ENV=production` with `HTTPS_ENABLED` not exactly `"true"` → refuses.
 *  * `HTTPS_ENABLED=true` with unreadable key/cert → refuses, in ANY
 *    environment. There is no "warning + plaintext" branch left to regress to.
 *
 * NON-PRODUCTION POLICY (the choice this fix mirrors from Core): development
 * and test keep starting plain HTTP when TLS was never requested. Only the
 * "asked for TLS and could not honour it" case is refused everywhere —
 * refusing a development box that never asked for TLS would break every local
 * workflow without buying any security.
 *
 * WHAT THIS CANNOT REFUSE: these are SERVER STARTUP guards, not request
 * handlers, so no request that previously succeeded changes status. The only
 * behaviour that changes is that a misconfigured Plus process fails to boot
 * instead of leaking.
 *
 * OUT OF SCOPE: `PLUS_PUBLIC_KEY` pinning is a separate concern and is
 * deliberately untouched here.
 */

import * as fs from "fs";
import * as path from "path";
import * as http from "http";
import * as https from "https";
import { PlusApiServer } from "../../plus/api/server";

/** Minimal server: `start()` never touches a repository before it binds. */
function buildServer(): PlusApiServer {
  return new PlusApiServer({} as any, {} as any, {} as any);
}

const MISSING_TLS_PATH = path.join(__dirname, "definitely-not-here", "server.key");

const savedEnv = {
  NODE_ENV: process.env.NODE_ENV,
  HTTPS_ENABLED: process.env.HTTPS_ENABLED,
  TLS_KEY_PATH: process.env.TLS_KEY_PATH,
  TLS_CERT_PATH: process.env.TLS_CERT_PATH,
};

function setEnv(entries: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

afterEach(() => {
  setEnv(savedEnv);
  jest.restoreAllMocks();
});

const readSource = (relative: string): string =>
  fs.readFileSync(path.join(__dirname, "../..", relative), "utf-8");

/** Removes `//` and `/* *\/` comments so assertions only see executable code. */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

/** Closes a server the happy-path tests started. */
async function close(server: http.Server): Promise<void> {
  if (server instanceof https.Server) {
    server.closeAllConnections?.();
  }
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/* -------------------------------------------------------------------------- */
/* Production refuses to run without TLS                                       */
/* -------------------------------------------------------------------------- */

describe("Plus: production refuses to start without TLS", () => {
  it("refuses when HTTPS_ENABLED is not set at all", async () => {
    setEnv({
      NODE_ENV: "production",
      HTTPS_ENABLED: undefined,
      TLS_KEY_PATH: undefined,
      TLS_CERT_PATH: undefined,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      /Refusing to start: NODE_ENV is "production" but HTTPS is not enabled/,
    );
  });

  it("refuses when HTTPS_ENABLED is explicitly false", async () => {
    setEnv({ NODE_ENV: "production", HTTPS_ENABLED: "false" });

    await expect(buildServer().start(0)).rejects.toThrow(
      /HTTPS is not enabled/,
    );
  });

  it("refuses for any value that is not exactly \"true\"", async () => {
    // A typo must fail CLOSED, not silently downgrade the authorization API.
    for (const value of ["True", "TRUE", "1", "yes", ""]) {
      setEnv({ NODE_ENV: "production", HTTPS_ENABLED: value });
      await expect(buildServer().start(0)).rejects.toThrow(/HTTPS is not enabled/);
    }
  });

  it("names the three variables the operator has to set", async () => {
    setEnv({ NODE_ENV: "production", HTTPS_ENABLED: undefined });

    await expect(buildServer().start(0)).rejects.toThrow(
      /HTTPS_ENABLED=true[\s\S]*TLS_CERT_PATH[\s\S]*TLS_KEY_PATH/,
    );
  });
});

/* -------------------------------------------------------------------------- */
/* Unreadable TLS material refuses to start instead of falling back            */
/* -------------------------------------------------------------------------- */

describe("Plus: unreadable TLS material refuses to start instead of falling back", () => {
  it("refuses in production when HTTPS is on but the key/cert cannot be read", async () => {
    setEnv({
      NODE_ENV: "production",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      /HTTPS_ENABLED=true but the TLS key or certificate could not be read/,
    );
  });

  it("refuses outside production too — there is no \"fallback\" branch left", async () => {
    setEnv({
      NODE_ENV: "development",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      /could not be read/,
    );
  });

  it("reports which paths it tried to read", async () => {
    setEnv({
      NODE_ENV: "production",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      new RegExp(`key=${MISSING_TLS_PATH.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
  });

  it("does NOT create an HTTP server when it refuses", async () => {
    setEnv({
      NODE_ENV: "production",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    // Spy on the shared `http` module object (the same one
    // `plus/api/server.ts` resolves), so the plaintext branch would be
    // observable even if it ran. The guard throws BEFORE the Promise that
    // binds anything, so nothing may be constructed at all.
    const httpCreate = jest.spyOn(require("http"), "createServer");
    const httpsCreate = jest.spyOn(require("https"), "createServer");

    const outcome = await buildServer()
      .start(0)
      .then(() => "resolved")
      .catch(() => "rejected");

    expect(outcome).toBe("rejected");
    expect(httpCreate).not.toHaveBeenCalled();
    expect(httpsCreate).not.toHaveBeenCalled();
  });
});

/* -------------------------------------------------------------------------- */
/* Non-production behaviour: the policy that was deliberately KEPT              */
/* -------------------------------------------------------------------------- */

describe("Plus: non-production still starts plain HTTP when TLS is not requested", () => {
  it("starts an HTTP server when HTTPS_ENABLED is unset outside production", async () => {
    setEnv({
      NODE_ENV: "development",
      HTTPS_ENABLED: undefined,
      TLS_KEY_PATH: undefined,
      TLS_CERT_PATH: undefined,
    });

    const server = await buildServer().start(0);
    try {
      expect(server).toBeInstanceOf(http.Server);
      expect(server).not.toBeInstanceOf(https.Server);
      expect(server.listening).toBe(true);
    } finally {
      await close(server);
    }
  });

  it("starts an HTTP server for HTTPS_ENABLED=false outside production", async () => {
    setEnv({ NODE_ENV: "development", HTTPS_ENABLED: "false" });

    const server = await buildServer().start(0);
    try {
      expect(server).toBeInstanceOf(http.Server);
    } finally {
      await close(server);
    }
  });
});

/* -------------------------------------------------------------------------- */
/* The fail-open text and the startup decision are gone                        */
/* -------------------------------------------------------------------------- */

describe("Plus: the fail-open path is gone", () => {
  it("no longer logs \"falling back to HTTP\"", () => {
    // Comments may still DESCRIBE the old behaviour (that is documentation);
    // executable code must not.
    const source = stripComments(readSource("plus/api/server.ts"));
    expect(source).not.toMatch(/falling back to HTTP/i);
    expect(source).not.toMatch(/certificates not found/i);
    expect(source).not.toMatch(/logger\.warn\([^)]*HTTP/i);
  });

  it("decides TLS at startup, not from the module-load snapshot", () => {
    const source = readSource("plus/api/server.ts");
    // The guard must re-read process.env; SECURITY_CONFIG.HTTPS_ENABLED is a
    // value frozen when the module was first imported.
    expect(source).toMatch(/assertTlsConfiguration\(\)/);
    expect(source).toMatch(/process\.env\.HTTPS_ENABLED === "true"/);
    expect(source).toMatch(/process\.env\.NODE_ENV === "production"/);
    // ...and start() must consult the guard rather than the snapshot.
    expect(source).toMatch(/const \{[^}]*httpsEnabled[^}]*\} = this\.assertTlsConfiguration\(\);/);
    expect(source).not.toMatch(/if \(SECURITY_CONFIG\.HTTPS_ENABLED\)/);
  });

  it("documents the Plus TLS requirement in .env.example", () => {
    const envExample = readSource(".env.example");
    expect(envExample).toMatch(/^HTTPS_ENABLED=/m);
    expect(envExample).toMatch(/^TLS_CERT_PATH=/m);
    expect(envExample).toMatch(/^TLS_KEY_PATH=/m);
    // Core's block is documented; Plus must be called out by name so an
    // operator knows BOTH processes enforce the same policy.
    expect(envExample).toMatch(/plus\/api\/server\.ts/);
    expect(envExample).toMatch(/Plus/);
  });
});
