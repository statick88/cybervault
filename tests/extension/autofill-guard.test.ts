/**
 * Autofill Guard tests — ExactMatch, form.action, iframe and submit binding.
 *
 * The canonical origin is https://github.com for every case, matching the
 * acceptance criteria. Vectors are taken from the specification, not from the
 * implementation, so a PASS means the guard enforces the stated rule rather
 * than agreeing with itself.
 */

import {
  evaluateAutofill,
  mayReleaseSecret,
  type AutofillGuardRequest,
  type AutofillBlockReason,
} from "../../src/domain/services/autofill/autofill-guard";
import {
  compareAbsoluteOrigins,
  parseAbsoluteOrigin,
  normalizeHostname,
  resolveAgainstOrigin,
  originFromLocation,
} from "../../src/domain/services/autofill/origin";

const CREDENTIAL_ORIGIN = "https://github.com";

function request(overrides: Partial<AutofillGuardRequest> = {}): AutofillGuardRequest {
  return {
    operation: "AUTOFILL",
    credentialOrigin: CREDENTIAL_ORIGIN,
    documentOrigin: CREDENTIAL_ORIGIN,
    ...overrides,
  };
}

function expectBlock(
  req: AutofillGuardRequest,
  reason: AutofillBlockReason,
): void {
  const decision = evaluateAutofill(req);
  expect(decision.allowed).toBe(false);
  if (decision.allowed) throw new Error("unreachable");
  expect(decision.reason).toBe(reason);
}

describe("Autofill Guard", () => {
  describe("§23.4 / §7 ExactMatch — the one allowed case", () => {
    it("ALLOWS the exact credential origin", () => {
      const decision = evaluateAutofill(request());
      expect(decision.allowed).toBe(true);
      if (!decision.allowed) throw new Error("unreachable");
      expect(decision.origin.serialized).toBe("https://github.com:443");
    });

    it("treats an omitted port as the scheme default", () => {
      expect(
        evaluateAutofill(
          request({ credentialOrigin: "https://github.com", documentOrigin: "https://github.com" }),
        ).allowed,
      ).toBe(true);
    });

    it("treats an explicit default port as equal to omitting it", () => {
      expect(
        evaluateAutofill(
          request({
            credentialOrigin: "https://github.com:443",
            documentOrigin: "https://github.com",
          }),
        ).allowed,
      ).toBe(true);
    });

    it("is case-insensitive on scheme and host", () => {
      expect(
        evaluateAutofill(
          request({
            credentialOrigin: "https://GitHub.com",
            documentOrigin: "HTTPS://GITHUB.COM",
          }),
        ).allowed,
      ).toBe(true);
    });

    it("ignores a single trailing root dot", () => {
      expect(
        evaluateAutofill(
          request({
            credentialOrigin: "https://github.com",
            documentOrigin: "https://github.com.",
          }),
        ).allowed,
      ).toBe(true);
    });

    it("ignores a fragment or query on the page URL", () => {
      expect(
        evaluateAutofill(
          request({ documentOrigin: "https://github.com/login?next=/x#frag" }),
        ).allowed,
      ).toBe(true);
    });
  });

  describe("§7 / §23.4 ExactMatch — every blocked case", () => {
    it("BLOCKS scheme downgrade to http", () => {
      expectBlock(
        request({ documentOrigin: "http://github.com" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS the www subdomain", () => {
      expectBlock(
        request({ documentOrigin: "https://www.github.com" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS any other subdomain", () => {
      expectBlock(
        request({ documentOrigin: "https://gist.github.com" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS a typosquat (githab.com)", () => {
      expectBlock(
        request({ documentOrigin: "https://githab.com" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS the suffix attack github.com.evil.example", () => {
      expectBlock(
        request({ documentOrigin: "https://github.com.evil.example" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS the prefix lookalike github-login.example", () => {
      expectBlock(
        request({ documentOrigin: "https://github-login.example" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS a different port", () => {
      expectBlock(
        request({ documentOrigin: "https://github.com:8443" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS a lookalike that merely ends with the credential host", () => {
      expectBlock(
        request({ documentOrigin: "https://notgithub.com" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("BLOCKS a completely unrelated origin", () => {
      expectBlock(
        request({ documentOrigin: "https://evil.example" }),
        "EXACT_MATCH_FAILED",
      );
    });

    it("never authorizes on similarity alone", () => {
      // Every one of these is "close enough" to github.com for a human, and
      // every one must still be refused.
      const nearMisses = [
        "https://github.co",         // truncated TLD
        "https://github.com.br",     // appended TLD
        "https://xn--github-3m3a.com", // punycode lookalike shape
        "https://github.com:443/",   // trailing slash only -> allowed, control
      ];
      for (const origin of nearMisses.slice(0, 3)) {
        expectBlock(request({ documentOrigin: origin }), "EXACT_MATCH_FAILED");
      }
      // control: the trailing-slash form IS the same origin
      expect(evaluateAutofill(request({ documentOrigin: "https://github.com:443/" })).allowed).toBe(
        true,
      );
    });
  });

  describe("§23.5 form.action", () => {
    it("ALLOWS a form posting to the credential origin", () => {
      expect(
        evaluateAutofill(request({ formAction: "https://github.com/login" })).allowed,
      ).toBe(true);
    });

    it("ALLOWS a form posting to a path on the credential origin", () => {
      expect(
        evaluateAutofill(request({ formAction: "https://github.com/session" })).allowed,
      ).toBe(true);
    });

    it("ALLOWS a form with no action attribute (self-submit)", () => {
      expect(evaluateAutofill(request({ formAction: undefined })).allowed).toBe(true);
      expect(evaluateAutofill(request({ formAction: null })).allowed).toBe(true);
    });

    it("ALLOWS an empty action attribute (self-submit)", () => {
      expect(evaluateAutofill(request({ formAction: "" })).allowed).toBe(true);
    });

    it("ALLOWS a relative action that resolves to the credential origin", () => {
      expect(evaluateAutofill(request({ formAction: "/session" })).allowed).toBe(true);
    });

    it("BLOCKS form.action pointing at an unauthorized origin", () => {
      // This is the headline §23.5 case.
      expectBlock(
        request({ formAction: "https://evil.example" }),
        "FORM_ACTION_ORIGIN_MISMATCH",
      );
    });

    it("BLOCKS a relative action that escapes to another origin", () => {
      // "//evil.example/x" is protocol-relative and resolves cross-origin.
      expectBlock(
        request({ formAction: "//evil.example/collect" }),
        "FORM_ACTION_ORIGIN_MISMATCH",
      );
    });

    it("BLOCKS a form.action that only downgrades the scheme", () => {
      expectBlock(
        request({ formAction: "http://github.com/login" }),
        "FORM_ACTION_ORIGIN_MISMATCH",
      );
    });

    it("BLOCKS a form.action on a subdomain of the credential origin", () => {
      expectBlock(
        request({ formAction: "https://www.github.com/login" }),
        "FORM_ACTION_ORIGIN_MISMATCH",
      );
    });

    it("treats a malformed-scheme action as a relative path, i.e. a self-submit", () => {
      // "ht!tp://[" is not a scheme, so URL resolution treats it as a relative
      // path on the current origin. The form therefore posts to github.com and
      // is safe. Refusing here would be a false positive, not a security win.
      const decision = evaluateAutofill(request({ formAction: "ht!tp://[" }));
      expect(decision.allowed).toBe(true);
      if (!decision.allowed) throw new Error("unreachable");
      expect(decision.checksPassed).toContain("form-action-origin");
    });

    it.each([
      ["http://["],
      ["//["],
      ["https://"],
    ])("BLOCKS an unresolvable form.action (%s) instead of ignoring it", (formAction) => {
      // Fail closed: an action we cannot resolve must never be treated as
      // "unrestricted", because we cannot prove where it posts.
      expectBlock(request({ formAction }), "FORM_ACTION_UNRESOLVABLE");
    });
  });

  describe("submit target (formaction on the button)", () => {
    it("ALLOWS a submit target on the credential origin", () => {
      expect(
        evaluateAutofill(request({ submitOrigin: "https://github.com/login" })).allowed,
      ).toBe(true);
    });

    it("BLOCKS a submit target on another origin", () => {
      expectBlock(
        request({ submitOrigin: "https://evil.example/collect" }),
        "SUBMIT_ORIGIN_MISMATCH",
      );
    });

    it("BLOCKS a submit target that only downgrades the scheme", () => {
      expectBlock(
        request({ submitOrigin: "http://github.com/login" }),
        "SUBMIT_ORIGIN_MISMATCH",
      );
    });

    it("checks both form.action and submit.target when both are present", () => {
      // A safe form.action must not launder an unsafe submit target.
      expectBlock(
        request({
          formAction: "https://github.com/login",
          submitOrigin: "https://evil.example",
        }),
        "SUBMIT_ORIGIN_MISMATCH",
      );
    });
  });

  describe("§7 iframe and top-level frame", () => {
    it("ALLOWS a top-level fill with no frame context supplied", () => {
      expect(evaluateAutofill(request()).allowed).toBe(true);
    });

    it("ALLOWS a same-origin iframe whose top-level is the credential origin", () => {
      expect(
        evaluateAutofill(
          request({
            frameOrigin: CREDENTIAL_ORIGIN,
            topLevelOrigin: CREDENTIAL_ORIGIN,
          }),
        ).allowed,
      ).toBe(true);
    });

    it("BLOCKS a credential harvested by a hostile top-level page", () => {
      // The core iframe threat: evil.example embeds github.com and tries to
      // collect what we inject. Top-level is not the credential origin.
      expectBlock(
        request({
          frameOrigin: CREDENTIAL_ORIGIN,
          topLevelOrigin: "https://evil.example",
        }),
        "UNAUTHORIZED_FRAME",
      );
    });

    it("BLOCKS a frame whose own origin is not the credential origin", () => {
      expectBlock(
        request({
          frameOrigin: "https://evil.example",
          topLevelOrigin: "https://evil.example",
        }),
        "UNAUTHORIZED_FRAME",
      );
    });

    it("BLOCKS when frameOrigin is supplied without topLevelOrigin", () => {
      // Half a frame context is an untrustworthy frame context.
      expectBlock(
        request({ frameOrigin: CREDENTIAL_ORIGIN }),
        "FRAME_CONTEXT_INCONSISTENT",
      );
    });

    it("BLOCKS when topLevelOrigin is supplied without frameOrigin", () => {
      expectBlock(
        request({ topLevelOrigin: CREDENTIAL_ORIGIN }),
        "FRAME_CONTEXT_INCONSISTENT",
      );
    });

    it("BLOCKS an unparseable frame origin rather than assuming safety", () => {
      expect(
        evaluateAutofill(
          request({
            frameOrigin: "not a url",
            topLevelOrigin: CREDENTIAL_ORIGIN,
          }),
        ).allowed,
      ).toBe(false);
    });
  });

  describe("fail-closed on unusable input", () => {
    it("BLOCKS a credential with no origin bound", () => {
      expectBlock(request({ credentialOrigin: null }), "CREDENTIAL_ORIGIN_MISSING");
      expectBlock(request({ credentialOrigin: undefined }), "CREDENTIAL_ORIGIN_MISSING");
      expectBlock(request({ credentialOrigin: "" }), "CREDENTIAL_ORIGIN_MISSING");
      expectBlock(request({ credentialOrigin: "   " }), "CREDENTIAL_ORIGIN_MISSING");
    });

    it("BLOCKS an unusable credential origin", () => {
      expectBlock(request({ credentialOrigin: "not a url" }), "CREDENTIAL_ORIGIN_INVALID");
    });

    it("BLOCKS a non-credential scheme as the credential origin", () => {
      expectBlock(
        request({ credentialOrigin: "javascript:alert(1)" }),
        "CREDENTIAL_ORIGIN_INVALID",
      );
    });

    it("BLOCKS an unusable document origin", () => {
      expectBlock(request({ documentOrigin: "" }), "DOCUMENT_ORIGIN_INVALID");
    });

    it("BLOCKS an operation that may not touch a page", () => {
      expectBlock(
        // @ts-expect-error deliberately passing a non-releasable operation
        request({ operation: "EXPORT_SECRET" }),
        "OPERATION_NOT_RELEASABLE",
      );
      expectBlock(
        // @ts-expect-error deliberately passing a non-releasable operation
        request({ operation: "DELETE_SECRET" }),
        "OPERATION_NOT_RELEASABLE",
      );
    });
  });

  describe("auditability", () => {
    it("records which checks passed on the allow path", () => {
      const decision = evaluateAutofill(request());
      expect(decision.allowed).toBe(true);
      if (!decision.allowed) throw new Error("unreachable");
      expect(decision.checksPassed).toEqual([
        "operation-releasable",
        "credential-origin-present",
        "credential-origin-valid",
        "document-origin-valid",
        "exact-match",
        "form-action-origin",
      ]);
    });

    it("includes the submit check only when a submit target was supplied", () => {
      const withSubmit = evaluateAutofill(
        request({ submitOrigin: "https://github.com/login" }),
      );
      expect(withSubmit.allowed).toBe(true);
      if (!withSubmit.allowed) throw new Error("unreachable");
      expect(withSubmit.checksPassed).toContain("submit-origin");
    });

    it("stops recording checks at the point of refusal", () => {
      const decision = evaluateAutofill(request({ documentOrigin: "https://evil.example" }));
      expect(decision.allowed).toBe(false);
      if (decision.allowed) throw new Error("unreachable");
      expect(decision.checksPassed).not.toContain("exact-match");
      expect(decision.checksPassed).toContain("credential-origin-valid");
    });

    it("never leaks secret material in the reason text", () => {
      const decision = evaluateAutofill(request({ formAction: "https://evil.example" }));
      expect(decision.allowed).toBe(false);
      if (decision.allowed) throw new Error("unreachable");
      expect(decision.detail).not.toMatch(/password|secret|token|key/i);
    });

    it("mayReleaseSecret agrees with evaluateAutofill", () => {
      expect(mayReleaseSecret(request())).toBe(true);
      expect(mayReleaseSecret(request({ documentOrigin: "https://evil.example" }))).toBe(false);
    });
  });
});

describe("Canonical origin authority", () => {
  describe("parseAbsoluteOrigin", () => {
    it("canonicalizes scheme, host and port", () => {
      const result = parseAbsoluteOrigin("HTTPS://GitHub.COM:443/x?y#z");
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");
      expect(result.origin.serialized).toBe("https://github.com:443");
    });

    it("fills in the default port per scheme", () => {
      expect(parseAbsoluteOrigin("https://a.example")).toMatchObject({
        ok: true,
        origin: { port: 443 },
      });
      expect(parseAbsoluteOrigin("http://a.example")).toMatchObject({
        ok: true,
        origin: { port: 80 },
      });
    });

    it.each([
      ["", "EMPTY"],
      ["   ", "EMPTY"],
      ["not a url", "UNPARSEABLE"],
      ["ftp://a.example", "UNSUPPORTED_SCHEME"],
      ["file:///etc/passwd", "UNSUPPORTED_SCHEME"],
      ["data:text/html,<h1>x", "UNSUPPORTED_SCHEME"],
      ["blob:https://a.example/x", "UNSUPPORTED_SCHEME"],
      ["javascript:alert(1)", "UNSUPPORTED_SCHEME"],
    ])("rejects %s as %s", (input, reason) => {
      const result = parseAbsoluteOrigin(input);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason).toBe(reason);
    });

    it("rejects a non-string input instead of coercing it", () => {
      const result = parseAbsoluteOrigin(undefined as unknown as string);
      expect(result.ok).toBe(false);
    });
  });

  describe("normalizeHostname", () => {
    it("lowercases and drops one trailing dot", () => {
      expect(normalizeHostname("EXAMPLE.COM.")).toBe("example.com");
      expect(normalizeHostname(" example.com ")).toBe("example.com");
    });

    it("keeps a bare dot-host intact rather than emptying it", () => {
      expect(normalizeHostname(".")).toBe(".");
    });
  });

  describe("compareAbsoluteOrigins", () => {
    it("reports which component differed", () => {
      expect(compareAbsoluteOrigins("https://a.example", "http://a.example")).toMatchObject({
        equal: false,
        reason: expect.stringContaining("scheme"),
      });
      expect(compareAbsoluteOrigins("https://a.example", "https://b.example")).toMatchObject({
        equal: false,
        reason: expect.stringContaining("hostname"),
      });
      expect(compareAbsoluteOrigins("https://a.example", "https://a.example:8443")).toMatchObject({
        equal: false,
        reason: expect.stringContaining("port"),
      });
    });

    it("treats unusable input as unequal rather than throwing", () => {
      expect(compareAbsoluteOrigins("nope", "https://a.example").equal).toBe(false);
      expect(compareAbsoluteOrigins("https://a.example", "nope").equal).toBe(false);
      expect(compareAbsoluteOrigins("nope", "nope").equal).toBe(false);
    });
  });

  describe("resolveAgainstOrigin", () => {
    it("resolves a relative path against the base", () => {
      const result = resolveAgainstOrigin("/login", "https://github.com");
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");
      expect(result.origin.serialized).toBe("https://github.com:443");
    });

    it("resolves a protocol-relative URL against the base scheme", () => {
      const result = resolveAgainstOrigin("//evil.example/x", "https://github.com");
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");
      expect(result.origin.serialized).toBe("https://evil.example:443");
    });

    it("treats null, undefined and empty as self", () => {
      for (const value of [null, undefined, "", "   "]) {
        const result = resolveAgainstOrigin(value, "https://github.com");
        expect(result.ok).toBe(true);
        if (!result.ok) throw new Error("unreachable");
        expect(result.origin.serialized).toBe("https://github.com:443");
      }
    });
  });

  describe("originFromLocation", () => {
    it("assembles an origin from a location-like object", () => {
      expect(originFromLocation({ protocol: "https:", hostname: "github.com", port: "" })).toBe(
        "https://github.com",
      );
      expect(
        originFromLocation({ protocol: "https:", hostname: "github.com", port: "8443" }),
      ).toBe("https://github.com:8443");
    });
  });
});
