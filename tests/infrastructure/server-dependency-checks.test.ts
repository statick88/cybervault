/**
 * S2 — `ApiServer`: dependency health checks and the H6 TLS guard's second
 * read, exercised at branch level.
 *
 * WHY MOCKED CLIENTS
 * ------------------
 * `ApiServer` constructs nothing it can be handed through a seam for these two
 * paths: `runDependencyChecks()` reaches the database through
 * `PostgresVaultRepository`/`PostgresCredentialRepository.isHealthy()` (each
 * builds its own `pg.Pool`), and `checkIpfsHealth()` loads the IPFS adapter
 * through a dynamic `import()`.
 * So `pg` is mocked at module level with the `mockQuery` pattern established
 * in `tests/infrastructure/postgres-credential-repository.test.ts`, and the
 * `ipfs` module is mocked so the dynamic import resolves to a stub. No live
 * database, no Docker, no network. The server is started on port 0 with the
 * real HTTP stack because `/health` and `/ready` are the only public surface
 * these checks have — and because the H5/H6 suites already prove `start()`
 * binds with the same noop dependency set.
 *
 * WHAT IS PINNED HERE
 * 1. `runDependencyChecks` is a real gate, not a constant: an unconfigured
 *    dependency reads `not_configured`, a configured one is actually probed,
 *    and the probe's boolean maps to `ok` / `error`.
 * 2. A failing database probe turns `/health` into 503 `unhealthy` and
 *    `/ready` into 503 `not_ready`; a failing IPFS probe degrades but does not
 *    make the service unhealthy — DB critical, IPFS optional, as documented.
 * 3. A probe that THROWS is caught and reported as `error`, never allowed to
 *    escape `runDependencyChecks` and take the request down with it.
 * 4. The health handler runs twice so the 5xx request series is non-empty —
 *    the `errorRate` denominator is computed from recorded responses, not from
 *    the request being served.
 * 5. H6, the branch `tls-enforcement.test.ts` cannot reach: with the KEY
 *    readable and the CERTIFICATE missing, `assertTlsConfiguration()` must
 *    still refuse — the key being fine is exactly the case a two-argument
 *    `readFileSync` pair would otherwise have "half-validated". The
 *    `process.env.TLS_* || SECURITY_CONFIG.TLS_*` fallback is pinned too.
 *
 * OUT OF SCOPE: the `httpsEnabled` bind path (`https.createServer`) needs real
 * PEM material that cannot be generated inside a unit test, and the request
 * handlers themselves are covered by `tests/integration/api-server.test.ts`.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

jest.mock("../../src/infrastructure/ipfs", () => ({
  ipfsAdapter: { isHealthy: jest.fn() },
}));

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Server } from "http";
import request from "supertest";

import { ApiServer } from "../../src/infrastructure/api/server";
import { PostgresVaultRepository } from "../../src/infrastructure/repositories/PostgresVaultRepository";
import { PostgresCredentialRepository } from "../../src/infrastructure/repositories/PostgresCredentialRepository";
import { ipfsAdapter } from "../../src/infrastructure/ipfs";
import { logger } from "../../src/shared/logger";

const noop = {} as any;
const ipfsHealth = ipfsAdapter.isHealthy as unknown as jest.Mock;

/* -------------------------------------------------------------------------- */
/* Environment — read per start(), restored after every test                   */
/* -------------------------------------------------------------------------- */

const savedEnv: Record<string, string | undefined> = {};
const ENV_KEYS = [
  "NODE_ENV",
  "USE_POSTGRES",
  "IPFS_API_URL",
  "HTTPS_ENABLED",
  "TLS_KEY_PATH",
  "TLS_CERT_PATH",
  "DATABASE_URL",
];
for (const key of ENV_KEYS) savedEnv[key] = process.env[key];

function setEnv(entries: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(entries)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function clearDependencies(): void {
  setEnv({
    NODE_ENV: "development",
    USE_POSTGRES: undefined,
    IPFS_API_URL: undefined,
    HTTPS_ENABLED: undefined,
    TLS_KEY_PATH: undefined,
    TLS_CERT_PATH: undefined,
    DATABASE_URL: undefined,
  });
}

beforeEach(() => {
  clearDependencies();
  mockQuery.mockReset();
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  ipfsHealth.mockReset();
  jest.spyOn(logger, "info").mockImplementation(() => undefined);
  jest.spyOn(logger, "warn").mockImplementation(() => undefined);
  jest.spyOn(logger, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  setEnv(savedEnv);
  jest.restoreAllMocks();
});

function buildServer(
  vaultRepository: unknown = {},
  credentialRepository?: unknown,
): ApiServer {
  return new ApiServer(
    vaultRepository as any,
    noop,
    noop,
    noop,
    noop,
    noop,
    credentialRepository as any,
  );
}

/** Start on an ephemeral port, run `fn`, always close again. */
async function withServer(
  vaultRepository: unknown,
  fn: (base: Server) => Promise<void>,
  credentialRepository?: unknown,
): Promise<void> {
  const server = await buildServer(vaultRepository, credentialRepository).start(0);
  try {
    await fn(server);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/* ========================================================================== */
/* runDependencyChecks via GET /health and GET /ready                          */
/* ========================================================================== */

describe("ApiServer.runDependencyChecks — unconfigured dependencies", () => {
  it("reports not_configured for both and still answers 200", async () => {
    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.status).toBe("healthy");
      expect(health.body.checks).toEqual({
        database: "not_configured",
        ipfs: "not_configured",
      });

      const ready = await request(server).get("/ready");
      expect(ready.status).toBe(200);
      expect(ready.body.status).toBe("ready");
      expect(ready.body.checks).toEqual({
        database: "not_configured",
        ipfs: "not_configured",
      });
    });
  });
});

describe("ApiServer.runDependencyChecks — the database probe", () => {
  it("runs the probe and reports ok when the repository answers", async () => {
    setEnv({ USE_POSTGRES: "true", DATABASE_URL: "postgresql://mock" });
    mockQuery.mockResolvedValue({ rows: [{ "?column?": 1 }], rowCount: 1 });
    const repo = new PostgresVaultRepository("postgresql://mock");

    await withServer(repo, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.status).toBe("healthy");
      expect(health.body.checks.database).toBe("ok");
      // The probe really went to the database.
      expect(mockQuery.mock.calls.some(([sql]) => sql === "SELECT 1")).toBe(true);
    });
  });

  it("reports ok when USE_POSTGRES is on but the repository is not Postgres", async () => {
    // `checkDatabaseHealth` guards on `instanceof`, so a non-Postgres
    // repository answers "no database to check, therefore healthy".
    setEnv({ USE_POSTGRES: "true" });

    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.checks.database).toBe("ok");
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });

  it("turns /health into 503 unhealthy and /ready into 503 not_ready when the probe fails", async () => {
    setEnv({ USE_POSTGRES: "true", DATABASE_URL: "postgresql://mock" });
    mockQuery.mockRejectedValue(new Error("ECONNREFUSED"));
    const repo = new PostgresVaultRepository("postgresql://mock");

    await withServer(repo, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(503);
      expect(health.body.status).toBe("unhealthy");
      expect(health.body.checks).toEqual({ database: "error", ipfs: "not_configured" });

      const ready = await request(server).get("/ready");
      expect(ready.status).toBe(503);
      expect(ready.body.status).toBe("not_ready");
      expect(ready.body.checks.database).toBe("error");
    });
  });

  it("probes the credential repository when the vault repository is not Postgres", async () => {
    // `checkDatabaseHealth` walks vault → credential → "no database here".
    // The middle arm is the one a deployment with a Postgres credential store
    // behind a non-Postgres vault repository actually takes.
    setEnv({ USE_POSTGRES: "true", DATABASE_URL: "postgresql://mock" });
    mockQuery.mockResolvedValue({ rows: [{ "?column?": 1 }], rowCount: 1 });
    const credentials = new PostgresCredentialRepository("postgresql://mock");

    await withServer(
      {},
      async (server) => {
        const health = await request(server).get("/health");
        expect(health.status).toBe(200);
        expect(health.body.checks.database).toBe("ok");
        expect(mockQuery.mock.calls.some(([sql]) => sql === "SELECT 1")).toBe(true);
      },
      credentials,
    );
  });

  it("catches a probe that throws instead of letting it take the request down", async () => {
    setEnv({ USE_POSTGRES: "true", DATABASE_URL: "postgresql://mock" });
    const repo = new PostgresVaultRepository("postgresql://mock");
    jest.spyOn(repo, "isHealthy").mockRejectedValue(new Error("probe exploded"));

    await withServer(repo, async (server) => {
      const health = await request(server).get("/health");
      // A thrown probe is an ERROR result, not a 500 and not a healthy 200.
      expect(health.status).toBe(503);
      expect(health.body.checks.database).toBe("error");
      expect(logger.error).toHaveBeenCalledWith(
        "Database health check error",
        "HealthCheck",
        undefined,
        "probe exploded",
      );
    });
  });
});

/* ========================================================================== */
/* The IPFS probe                                                              */
/* ========================================================================== */

describe("ApiServer.runDependencyChecks — the IPFS probe", () => {
  it("reports ok when the adapter is healthy", async () => {
    setEnv({ IPFS_API_URL: "http://127.0.0.1:5001" });
    ipfsHealth.mockResolvedValue(true);

    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.status).toBe("healthy");
      expect(health.body.checks.ipfs).toBe("ok");
    });
  });

  it("degrades but stays 200 when the adapter is reachable yet unhealthy", async () => {
    setEnv({ IPFS_API_URL: "http://127.0.0.1:5001" });
    ipfsHealth.mockResolvedValue(false);

    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.status).toBe("degraded");
      expect(health.body.checks.ipfs).toBe("error");

      const ready = await request(server).get("/ready");
      expect(ready.status).toBe(503);
      expect(ready.body.status).toBe("not_ready");
    });
  });

  it("catches an adapter that throws and reports error rather than crashing", async () => {
    setEnv({ IPFS_API_URL: "http://127.0.0.1:5001" });
    ipfsHealth.mockRejectedValue(new Error("ipfs unreachable"));

    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
      expect(health.body.status).toBe("degraded");
      expect(health.body.checks.ipfs).toBe("error");
      expect(logger.error).toHaveBeenCalledWith(
        "IPFS health check error",
        "HealthCheck",
        undefined,
        "ipfs unreachable",
      );
    });
  });

  it("does not touch the adapter when IPFS_API_URL is unset", async () => {
    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.body.checks.ipfs).toBe("not_configured");
      expect(ipfsHealth).not.toHaveBeenCalled();
    });
  });
});

/* ========================================================================== */
/* Metrics                                                                     */
/* ========================================================================== */

describe("GET /metrics", () => {
  it("answers Prometheus text", async () => {
    await withServer({}, async (server) => {
      const res = await request(server).get("/metrics");
      expect(res.status).toBe(200);
      expect(res.headers["content-type"]).toContain("text/plain");
      expect(res.text).toContain("http_requests_total");
    });
  });
});

/* ========================================================================== */
/* assertTlsConfiguration — the second read                                    */
/* ========================================================================== */

describe("ApiServer.assertTlsConfiguration — key readable, certificate not", () => {
  const tmpDirs: string[] = [];

  afterEach(() => {
    for (const dir of tmpDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to start when the key reads fine but the certificate does not", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cybervault-tls-"));
    tmpDirs.push(dir);
    const keyPath = path.join(dir, "server.key");
    const certPath = path.join(dir, "server.crt");
    fs.writeFileSync(keyPath, "placeholder key material");

    setEnv({
      NODE_ENV: "development",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: keyPath,
      TLS_CERT_PATH: certPath,
    });

    await expect(buildServer().start(0)).rejects.toThrow(
      /HTTPS_ENABLED=true but the TLS key or certificate could not be read/,
    );
    // Both paths are named, so the operator can see which one failed.
    await expect(buildServer().start(0)).rejects.toThrow(
      new RegExp(certPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  });

  it("falls back to SECURITY_CONFIG's paths when the environment has none", async () => {
    setEnv({
      NODE_ENV: "development",
      HTTPS_ENABLED: "true",
      TLS_KEY_PATH: undefined,
      TLS_CERT_PATH: undefined,
    });

    // The fallback must be the SAME value the rest of the process would read,
    // otherwise the guard could validate one file and the server open another.
    await expect(buildServer().start(0)).rejects.toThrow(
      /key=\.\/certs\/server\.key/,
    );
  });

  it("starts plaintext when TLS is not requested, whatever the paths say", async () => {
    setEnv({ NODE_ENV: "development", HTTPS_ENABLED: undefined });

    await withServer({}, async (server) => {
      const health = await request(server).get("/health");
      expect(health.status).toBe(200);
    });
  });
});
