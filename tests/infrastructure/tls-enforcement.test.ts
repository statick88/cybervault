/**
 * H6 — TLS fail-open: the server would happily serve credentials over
 * plaintext HTTP, and would do so MOSTLY when it had been told to use TLS.
 *
 * TWO DEFECTS
 * -----------
 * 1. `HTTPS_ENABLED` defaulted to `false`. A production deployment that simply
 *    never set the variable booted an HTTP server and said nothing — every
 *    credential, token and TSV export crossed the network in the clear.
 * 2. With `HTTPS_ENABLED=true` but a key or certificate that could not be read,
 *    `start()` logged `warn("HTTPS certificates not found, falling back to
 *    HTTP")` and started a PLAINTEXT server anyway. The operator asked for TLS
 *    and silently got the exact opposite.
 *
 * THE FIX
 * -------
 * `ApiServer.assertTlsConfiguration()` runs at the top of `start()`, reading
 * the environment at STARTUP (not the module-load snapshot in
 * `SECURITY_CONFIG`), and THROWS:
 *
 *  * `NODE_ENV=production` with `HTTPS_ENABLED` not exactly `"true"` → refuses.
 *  * `HTTPS_ENABLED=true` with unreadable key/cert → refuses, in ANY
 *    environment. Falling back would defeat the setting, so there is no
 *    version of "warning + plaintext" left to regress to.
 *
 * `require.main === module` now exits non-zero when startup is refused, so a
 * rejected guard cannot leave a half-alive process behind.
 *
 * WHAT THIS CANNOT REFUSE: these are SERVER STARTUP guards, not request
 * handlers, so no request that previously succeeded changes status. The only
 * behaviour that changes is that a misconfigured production process fails to
 * boot instead of leaking.
 *
 * OUT OF SCOPE (reported, deliberately not fixed here): `plus/api/server.ts`
 * carries the same `HTTPS_ENABLED` default and the same "falling back to HTTP"
 * catch. The finding scoped the fix to Core.
 */

import * as fs from "fs";
import * as path from "path";
import * as http from "http";
import * as https from "https";
import { ApiServer } from "../../src/infrastructure/api/server";

const noopCrypto = {} as any;

/** Minimal server: `start()` never touches a repository before it binds. */
function buildServer(): ApiServer {
  return new ApiServer(
    {} as any,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    {} as any,
    {} as any,
  );
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
});

const readSource = (relative: string): string =>
  fs.readFileSync(path.join(__dirname, "../..", relative), "utf-8");

/** Removes `//` and `/* *\/` comments so assertions only see executable code. */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

/* -------------------------------------------------------------------------- */
/* Production refuses to run without TLS                                       */
/* -------------------------------------------------------------------------- */

describe("H6: production refuses to start without TLS", () => {
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
    // A typo must fail CLOSED, not silently downgrade.
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
/* Unreadable TLS material refuses to start                                    */
/* -------------------------------------------------------------------------- */

describe("H6: unreadable TLS material refuses to start instead of falling back", () => {
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
      NODE_ENV: "development",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      new RegExp(`key=${MISSING_TLS_PATH.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
  });

  it("does not bind anything when it refuses", async () => {
    setEnv({
      NODE_ENV: "production",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: MISSING_TLS_PATH,
      TLS_CERT_PATH: MISSING_TLS_PATH,
    });

    // `start()` throws BEFORE `new Promise(...)`/`listen()`, so no Server
    // object is ever produced and nothing is left listening.
    const outcome = await buildServer()
      .start(0)
      .then(() => "resolved")
      .catch(() => "rejected");
    expect(outcome).toBe("rejected");
  });
});

/* -------------------------------------------------------------------------- */
/* The happy path is unchanged                                                  */
/* -------------------------------------------------------------------------- */

describe("H6: development still starts plain HTTP when TLS is not requested", () => {
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
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("starts an HTTP server for HTTPS_ENABLED=false outside production", async () => {
    setEnv({ NODE_ENV: "development", HTTPS_ENABLED: "false" });

    const server = await buildServer().start(0);
    try {
      expect(server).toBeInstanceOf(http.Server);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

/* -------------------------------------------------------------------------- */
/* The fail-open text and the process lifecycle                                 */
/* -------------------------------------------------------------------------- */

describe("H6: the fail-open paths are gone", () => {
  it("no longer logs \"falling back to HTTP\" anywhere in Core", () => {
    // Comments may still DESCRIBE the old behaviour (that is documentation);
    // executable code must not.
    const source = stripComments(readSource("src/infrastructure/api/server.ts"));
    expect(source).not.toMatch(/falling back to HTTP/i);
    expect(source).not.toMatch(/certificates not found/i);
    expect(source).not.toMatch(/logger\.warn\([^)]*HTTP/i);
  });

  it("decides TLS at startup, not from the module-load snapshot", () => {
    const source = readSource("src/infrastructure/api/server.ts");
    // The guard must re-read process.env; SECURITY_CONFIG.HTTPS_ENABLED is a
    // value frozen when the module was first imported.
    expect(source).toMatch(/assertTlsConfiguration\(\)/);
    expect(source).toMatch(/process\.env\.HTTPS_ENABLED === "true"/);
    expect(source).toMatch(/process\.env\.NODE_ENV === "production"/);
    // ...and start() must consult the guard rather than the snapshot.
    expect(source).toMatch(/const \{[^}]*httpsEnabled[^}]*\} = this\.assertTlsConfiguration\(\);/);
    expect(source).not.toMatch(/if \(SECURITY_CONFIG\.HTTPS_ENABLED\)/);
  });

  it("exits non-zero when startup is refused, instead of logging and living on", () => {
    const source = readSource("src/infrastructure/api/server.ts");
    expect(source).toMatch(/startServer\(\{ port \}\)\.catch\(\(err\) => \{/);
    expect(source).toMatch(/process\.exit\(1\);/);
  });

  it("documents HTTPS_ENABLED in .env.example", () => {
    const envExample = readSource(".env.example");
    expect(envExample).toMatch(/^HTTPS_ENABLED=/m);
    expect(envExample).toMatch(/^TLS_CERT_PATH=/m);
    expect(envExample).toMatch(/^TLS_KEY_PATH=/m);
  });

  it("does not add HTTPS_ENABLED to docker-compose.yml (deployment-owned)", () => {
    // The finding scoped configuration documentation to `.env.example`; the
    // compose file is deployment-owned and was left alone deliberately.
    const compose = readSource("docker-compose.yml");
    expect(compose).not.toMatch(/HTTPS_ENABLED/);
  });
});
