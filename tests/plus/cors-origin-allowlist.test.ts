/**
 * RQ5 mutation test — R1 origin check (CORS allow-list).
 *
 * The mutant: `PlusApiServer.isAllowedOrigin` returns `true` unconditionally,
 * so `Access-Control-Allow-Origin` is echoed for ANY browser origin —
 * including an unconfigured one, and including `evil.example` while the
 * allow-list names only `app.example.com`.
 *
 * What that breaks: the extension authenticates with `X-Service-Secret`, and
 * the browser will not send that header cross-origin unless the response
 * admits the caller. Echoing an arbitrary origin is what turns a same-origin
 * API into a callable one from anywhere (R1).
 *
 * The assertion that pins it, over real HTTP against the production route:
 *   1. Empty allow-list (the default) admits NOTHING — an unset
 *      `PLUS_ALLOWED_ORIGINS` fails closed, it does not fail open.
 *   2. A configured allow-list admits ONLY the exact entry; a different origin
 *      gets no `Access-Control-Allow-Origin` (exact match, never suffix).
 *
 * Probed with OPTIONS because the CORS block runs before rate limiting and
 * before any route, so this crosses no dependency beyond the server itself.
 * Verified by reverting the mutant — this test goes red with `return true`.
 */

import type { Server } from "http";
import type { AddressInfo } from "net";
import * as http from "http";

import { PlusApiServer } from "../../plus/api/server";
import type {
  IChallengeRepository,
  IEntitlementRepository,
  IPlusUserRepository,
} from "../../plus/domain/repositories";

const ALLOWED = "https://app.example.com";

function probe(port: number, origin: string): Promise<{ status: number; acao: string | undefined }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "OPTIONS", path: "/api/v1/health", headers: { Origin: origin } },
      (res) => {
        const acao = res.headers["access-control-allow-origin"];
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0, acao }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function withServer(envOrigins: string | undefined, fn: (port: number) => Promise<void>): Promise<void> {
  const previous = process.env.PLUS_ALLOWED_ORIGINS;
  if (envOrigins === undefined) delete process.env.PLUS_ALLOWED_ORIGINS;
  else process.env.PLUS_ALLOWED_ORIGINS = envOrigins;

  let server: Server | undefined;
  try {
    const api = new PlusApiServer(
      {} as IChallengeRepository,
      {} as IEntitlementRepository,
      {} as IPlusUserRepository,
    );
    server = await api.start(0);
    await fn((server.address() as AddressInfo).port);
  } finally {
    if (server) {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server!.close(() => resolve()));
    }
    if (previous === undefined) delete process.env.PLUS_ALLOWED_ORIGINS;
    else process.env.PLUS_ALLOWED_ORIGINS = previous;
  }
}

describe("R1 — the CORS origin allow-list fails closed", () => {
  it("admits NO origin when PLUS_ALLOWED_ORIGINS is unset", async () => {
    await withServer(undefined, async (port) => {
      const res = await probe(port, "https://evil.example");
      expect(res.status).toBe(204);
      // The whole property: an unconfigured allow-list emits no ACAO header.
      expect(res.acao).toBeUndefined();
    });
  });

  it("admits NO origin when the configured allow-list is empty", async () => {
    await withServer("", async (port) => {
      const res = await probe(port, "https://evil.example");
      expect(res.acao).toBeUndefined();
    });
  });

  it("echoes ONLY the exact allow-listed origin, never a different one", async () => {
    await withServer(ALLOWED, async (port) => {
      const allowed = await probe(port, ALLOWED);
      expect(allowed.acao).toBe(ALLOWED);

      const evil = await probe(port, "https://evil.example");
      expect(evil.acao).toBeUndefined();

      // Exact match, never suffix: a look-alike must not ride the entry above.
      const lookalike = await probe(port, "https://app.example.com.evil.example");
      expect(lookalike.acao).toBeUndefined();
    });
  });
});
