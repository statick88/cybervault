/**
 * H2 — the `Content-Security-Policy` header must be valid CSP.
 *
 * THE DEFECT
 * ----------
 * `security-headers.ts` declared its directives as camelCase object KEYS
 * (`defaultSrc`, `scriptSrc`, `connectSrc`, …) and then did
 *
 *     Object.entries(CSP).map(([key, values]) => `${key} ${values.join(" ")}`)
 *
 * `Object.entries` returns the key VERBATIM, so the header literally read
 *
 *     defaultSrc 'self'; scriptSrc 'self'; styleSrc 'self' 'unsafe-inline'; …
 *
 * `defaultSrc` is not a CSP directive, so a browser discards it — and because
 * EVERY directive was camelCase, the browser discarded the ENTIRE policy. The
 * header was present on the wire (which is why a `grep Content-Security-Policy`
 * looked healthy) and enforced nothing. The header was NOT disabled here; the
 * emitted key names were corrected.
 *
 * WHAT IS PINNED HERE
 * 1. The emitted string contains `default-src` (kebab) and no camelCase token.
 * 2. A policy parser accepts it — every directive name is a valid CSP token,
 *    every source expression is a valid source, `default-src` exists.
 * 3. The header is actually written by `applySecurityHeaders` AND actually
 *    reaches the wire over a real HTTP socket.
 * 4. The restrictive sources were not weakened while being renamed.
 */

import request from "supertest";
import { createServer, type Server } from "http";
import type { ServerResponse } from "http";
import {
  applySecurityHeaders,
  buildContentSecurityPolicy,
  CSP_DIRECTIVES,
} from "../../../src/infrastructure/api/middleware/security-headers";

/* -------------------------------------------------------------------------- */
/* Minimal CSP parser — enough of the grammar to prove the policy is parseable */
/* -------------------------------------------------------------------------- */

const DIRECTIVE_NAME = /^[a-z][a-z0-9-]*$/;
const KEYWORD_SOURCE =
  /^'(?:self|none|unsafe-inline|unsafe-eval|unsafe-hashes|strict-dynamic|report-sample|inline-speculation-rules|nonce-[A-Za-z0-9+/=_-]+|sha256-[A-Za-z0-9+/=_-]+|sha384-[A-Za-z0-9+/=_-]+|sha512-[A-Za-z0-9+/=_-]+)'$/;
const SCHEME_SOURCE = /^[a-z][a-z0-9+.-]*:$/;
const HOST_SOURCE = /^(?:\*|\*\.|https?:\/\/|\[)[^\s]*$|^[a-z0-9.-]+(?::\d+)?(?:\/\S*)?$/;

interface ParsedPolicy {
  directives: Map<string, string[]>;
}

function isValidSource(token: string): boolean {
  return (
    KEYWORD_SOURCE.test(token) ||
    SCHEME_SOURCE.test(token) ||
    HOST_SOURCE.test(token) ||
    token === "*"
  );
}

/** Returns the parsed policy, or throws with the first reason it is invalid. */
function parseContentSecurityPolicy(policy: string): ParsedPolicy {
  const directives = new Map<string, string[]>();

  const clauses = policy
    .split(";")
    .map((clause) => clause.trim())
    .filter((clause) => clause !== "");

  if (clauses.length === 0) {
    throw new Error("policy has no directives");
  }

  for (const clause of clauses) {
    const firstSpace = clause.indexOf(" ");
    if (firstSpace <= 0) {
      throw new Error(`directive without a source list: ${JSON.stringify(clause)}`);
    }
    const name = clause.slice(0, firstSpace);
    const sources = clause.slice(firstSpace + 1).trim().split(/\s+/);

    if (!DIRECTIVE_NAME.test(name)) {
      throw new Error(`invalid directive name: ${JSON.stringify(name)}`);
    }
    if (directives.has(name)) {
      throw new Error(`duplicate directive: ${name}`);
    }
    for (const source of sources) {
      if (!isValidSource(source)) {
        throw new Error(`invalid source ${JSON.stringify(source)} in ${name}`);
      }
    }
    directives.set(name, sources);
  }

  return { directives };
}

const REQUIRED_DIRECTIVES = [
  "default-src",
  "script-src",
  "style-src",
  "connect-src",
  "object-src",
  "frame-src",
] as const;

/* -------------------------------------------------------------------------- */

function captureHeaders(): { res: ServerResponse; headers: Map<string, string> } {
  const headers = new Map<string, string>();
  const res = {
    setHeader: (name: string, value: string) => {
      headers.set(name.toLowerCase(), value);
    },
  } as unknown as ServerResponse;
  return { res, headers };
}

describe("H2: Content-Security-Policy is a valid policy", () => {
  it("emits kebab-case directive names, not camelCase object keys", () => {
    const policy = buildContentSecurityPolicy();

    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("script-src 'self'");
    expect(policy).toContain("connect-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("frame-src 'none'");

    // The exact regression: `defaultSrc` / `scriptSrc` / … must never appear.
    expect(policy).not.toMatch(/defaultSrc|scriptSrc|connectSrc/);
    expect(policy).not.toMatch(/\b[a-z]+[A-Z][a-zA-Z]*\b/);
  });

  it("a CSP parser accepts the emitted policy", () => {
    const parsed = parseContentSecurityPolicy(buildContentSecurityPolicy());

    for (const directive of REQUIRED_DIRECTIVES) {
      expect(parsed.directives.has(directive)).toBe(true);
    }
    // `default-src` is what a browser falls back to; without a parseable one
    // the policy is unusable.
    expect(parsed.directives.get("default-src")).toEqual(["'self'"]);
  });

  it("does not weaken the directives while renaming them", () => {
    const parsed = parseContentSecurityPolicy(buildContentSecurityPolicy());

    expect(parsed.directives.get("script-src")).toEqual(["'self'"]);
    expect(parsed.directives.get("object-src")).toEqual(["'none'"]);
    expect(parsed.directives.get("frame-src")).toEqual(["'none'"]);
    expect(parsed.directives.get("connect-src")).toEqual(["'self'"]);
    // No blanket relaxation anywhere in the policy.
    for (const [, sources] of parsed.directives) {
      expect(sources).not.toContain("'unsafe-eval'");
      expect(sources).not.toContain("*");
    }
    expect(Object.keys(CSP_DIRECTIVES)).toContain("default-src");
  });

  it("applySecurityHeaders writes the parsed policy as Content-Security-Policy", () => {
    const { res, headers } = captureHeaders();

    applySecurityHeaders(res);

    const policy = headers.get("content-security-policy");
    expect(policy).toBeDefined();
    expect(policy).toBe(buildContentSecurityPolicy());
    expect(() => parseContentSecurityPolicy(policy as string)).not.toThrow();
    expect(headers.get("x-content-type-options")).toBe("nosniff");
    expect(headers.get("x-frame-options")).toBe("DENY");
    expect(headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
  });

  it("the policy reaches the wire over a real HTTP response", async () => {
    const server: Server = createServer((_req, res) => {
      applySecurityHeaders(res);
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });

    await new Promise<void>((resolve) => server.listen(0, resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;

    try {
      const response = await request(`http://127.0.0.1:${port}`).get("/");
      expect(response.status).toBe(200);

      const policy = response.headers["content-security-policy"] as string;
      expect(policy).toBeDefined();
      expect(policy).toContain("default-src");
      expect(() => parseContentSecurityPolicy(policy)).not.toThrow();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
