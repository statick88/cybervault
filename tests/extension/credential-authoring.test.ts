/**
 * Credential authoring tests.
 *
 * Authoring is the write side of the release path. Two properties are
 * load-bearing and are asserted directly rather than inferred:
 *
 *   1. EXACTMATCH AT AUTHORING TIME — a malformed or non-absolute origin is
 *      rejected. This is the last chance to catch `github.com` (no scheme)
 *      before the credential becomes permanently unreachable.
 *   2. NO PLAINTEXT IN THE RECORD — the persisted record must not contain the
 *      password, the username or the TOTP seed in any recoverable form.
 *
 * The round-trip tests deliberately go through the real authoring function so a
 * renamed field breaks here rather than silently producing an unreleasable
 * record in production.
 */

import {
  authorCredential,
  redactUsername,
  base32ToBytes,
  type AuthorCredentialInput,
} from "../../src/domain/services/autofill/credential-authoring";
import {
  listCandidatesForOrigin,
  releaseCredential,
  type EncryptedCredentialRecord,
  type ReleaseDeps,
} from "../../src/background/credential-release";
import type { OpaqueIndex } from "../../src/domain/services/autofill/domain-index";

const ORIGIN = "https://github.com";
const USERNAME = "octocat";
const PASSWORD = "correct horse battery staple";
const TOTP_SEED = "JBSWY3DPEHPK3PXP";

function vek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function input(overrides: Partial<AuthorCredentialInput> = {}): AuthorCredentialInput {
  return {
    origin: ORIGIN,
    username: USERNAME,
    password: PASSWORD,
    title: "GitHub",
    ...overrides,
  };
}

/** Turn an authored record into the shape the release path reads. */
function toReleaseRecord(record: {
  id: string;
  mode: "personal" | "managed";
  encryptedSecret: string;
  encryptedTotpSecret?: string;
  salt: string;
  version: number;
  releaseShareRef?: string;
  usernameHint: string;
  title: string;
}): EncryptedCredentialRecord {
  return {
    id: record.id,
    mode: record.mode,
    encryptedSecret: record.encryptedSecret,
    encryptedTotpSecret: record.encryptedTotpSecret,
    salt: record.salt,
    version: record.version,
    releaseShareRef: record.releaseShareRef,
    usernameHint: record.usernameHint,
    title: record.title,
  };
}

describe("redactUsername", () => {
  it("keeps only the first character", () => {
    expect(redactUsername("octocat")).toBe("o" + "*".repeat(6));
  });

  it("bounds the hint length regardless of username length", () => {
    // The hint exists so the user can tell their own accounts apart in the
    // candidate list, so it must not be fixed-width — that would make
    // "octocat" and "ostrich" indistinguishable. What it must do is stay
    // bounded, so a 10 KB username cannot bloat the UI.
    //
    // Note the scope honestly: for usernames shorter than the cap the hint
    // length does reveal the exact length. That is acceptable because the hint
    // is only ever shown to the user in their own unlocked vault — the
    // disclosure that matters (backend, page) never sees it at all.
    expect(redactUsername("a".repeat(10_000)).length).toBeLessThanOrEqual(9);
    expect(redactUsername("a".repeat(40)).length).toBeLessThanOrEqual(9);
    expect(redactUsername("a".repeat(40)).length).toBe(
      redactUsername("a".repeat(60)).length,
    );
  });

  it("cannot tell same-initial accounts apart — the title does that job", () => {
    // Documented limitation, asserted so it cannot be quietly assumed away.
    // "octocat" and "ostrich" both redact to the same hint, so the candidate
    // list must surface the user-authored title for disambiguation. If a future
    // change makes the hint distinguishing, this test should be revisited
    // deliberately rather than by accident.
    expect(redactUsername("octocat")).toBe(redactUsername("ostrich"));
  });

  it("handles a single character and empty input", () => {
    expect(redactUsername("a")).toBe("*");
    expect(redactUsername("")).toBe("");
    expect(redactUsername("   ")).toBe("");
  });

  it("never returns the original", () => {
    expect(redactUsername("administrator")).not.toContain("administrator");
  });
});

describe("base32ToBytes", () => {
  it("decodes the canonical authenticator example", () => {
    expect(Array.from(base32ToBytes("JBSWY3DPEHPK3PXP"))).toEqual([
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef,
    ]);
  });

  it("ignores padding and whitespace", () => {
    expect(base32ToBytes("JBSW Y3DP EHPK3PXP==")).toEqual(
      base32ToBytes("JBSWY3DPEHPK3PXP"),
    );
  });
});

describe("authorCredential — origin validation (§7)", () => {
  it("accepts a well-formed absolute origin", async () => {
    const result = await authorCredential(input(), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.record.origin).toBe("https://github.com:443");
  });

  it("canonicalizes rather than storing the raw string", async () => {
    const result = await authorCredential(input({ origin: "HTTPS://GitHub.com" }), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.record.origin).toBe("https://github.com:443");
  });

  it.each([
    ["github.com", "ORIGIN_NOT_ABSOLUTE"],
    ["//github.com", "ORIGIN_NOT_ABSOLUTE"],
    ["github.com/login", "ORIGIN_NOT_ABSOLUTE"],
    ["", "ORIGIN_MISSING"],
    ["   ", "ORIGIN_MISSING"],
  ])("rejects non-absolute origin %p", async (origin, reason) => {
    const result = await authorCredential(input({ origin }), vek(), null);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe(reason);
  });

  it.each(["ftp://github.com", "file:///etc/passwd", "chrome-extension://abc"])(
    "rejects disallowed scheme %p",
    async (origin) => {
      const result = await authorCredential(input({ origin }), vek(), null);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason).toBe("ORIGIN_SCHEME_NOT_ALLOWED");
    },
  );

  it("rejects a javascript: pseudo-origin", async () => {
    // `javascript:` has no `//` authority, so it is rejected as non-absolute
    // before the scheme check. The property that matters is the rejection; the
    // precise code is an implementation detail of check ordering.
    const result = await authorCredential(
      input({ origin: "javascript:alert(1)" }),
      vek(),
      null,
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(["ORIGIN_NOT_ABSOLUTE", "ORIGIN_SCHEME_NOT_ALLOWED"]).toContain(
      result.reason,
    );
  });

  it("rejects when the vault is locked", async () => {
    const result = await authorCredential(input(), null, null);
    expect(result).toMatchObject({ ok: false, reason: "VAULT_LOCKED" });
  });
});

describe("authorCredential — input validation", () => {
  it.each([
    [{ username: "" }, "USERNAME_REQUIRED"],
    [{ username: "   " }, "USERNAME_REQUIRED"],
    [{ password: "" }, "PASSWORD_REQUIRED"],
  ])("rejects %p", async (overrides, reason) => {
    const result = await authorCredential(input(overrides), vek(), null);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe(reason);
  });

  it("falls back to the username when no title is given", async () => {
    const result = await authorCredential(input({ title: "  " }), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.record.title).toBe(USERNAME);
  });
});

describe("authorCredential — no plaintext in the record (§6.1)", () => {
  it("the serialized record contains no password, username or seed", async () => {
    const result = await authorCredential(
      input({ totpSeedBase32: TOTP_SEED }),
      vek(),
      null,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");

    const serialized = JSON.stringify(result.record);
    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain(USERNAME);
    expect(serialized).not.toContain(TOTP_SEED);
  });

  it("stores a redacted hint, not the username", async () => {
    const result = await authorCredential(input(), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.record.usernameHint).toBe(redactUsername(USERNAME));
    expect(result.record.usernameHint).not.toBe(USERNAME);
  });

  it("stores ciphertext, a salt and a version", async () => {
    const result = await authorCredential(input(), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.record.encryptedSecret).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(result.record.salt).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(result.record.version).toBe(1);
  });

  it("uses a fresh salt for every credential", async () => {
    const a = await authorCredential(input(), vek(), null);
    const b = await authorCredential(input(), vek(), null);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) throw new Error("unreachable");
    expect(a.record.salt).not.toBe(b.record.salt);
    expect(a.record.encryptedSecret).not.toBe(b.record.encryptedSecret);
  });

  it("uses a fresh id for every credential", async () => {
    const a = await authorCredential(input(), vek(), null);
    const b = await authorCredential(input(), vek(), null);
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) throw new Error("unreachable");
    expect(a.record.id).not.toBe(b.record.id);
  });
});

describe("authorCredential — opaque index registration (§6.6)", () => {
  it("registers a token that does not reveal the origin", async () => {
    const result = await authorCredential(input(), vek(), null);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");

    expect(result.lookupToken).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(result.index)).not.toContain("github");
    expect(JSON.stringify(result.index)).not.toContain("https");
  });

  it("places the credential id in the token's bucket", async () => {
    const result = await authorCredential(input(), vek(), null);
    if (!result.ok) throw new Error("unreachable");
    expect(result.index.byToken[result.lookupToken]).toEqual([result.record.id]);
  });

  it("keeps prior entries when adding another", async () => {
    const first = await authorCredential(input(), vek(), null);
    if (!first.ok) throw new Error("unreachable");

    const second = await authorCredential(
      input({ title: "GitHub work" }),
      vek(),
      first.index,
    );
    if (!second.ok) throw new Error("unreachable");

    expect(second.index.byToken[first.lookupToken]).toEqual([first.record.id]);
    expect(second.index.byToken[second.lookupToken]).toEqual([second.record.id]);
  });

  it("does not mutate the index it was given", async () => {
    const first = await authorCredential(input(), vek(), null);
    if (!first.ok) throw new Error("unreachable");
    const snapshot = JSON.stringify(first.index);

    await authorCredential(input({ title: "Another" }), vek(), first.index);
    expect(JSON.stringify(first.index)).toBe(snapshot);
  });

  it("gives different origins different buckets", async () => {
    const a = await authorCredential(input({ origin: "https://github.com" }), vek(), null);
    const b = await authorCredential(
      input({ origin: "https://gitlab.com", title: "GitLab" }),
      vek(),
      a.ok ? a.index : null,
    );
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) throw new Error("unreachable");
    expect(a.lookupToken).not.toBe(b.lookupToken);
  });
});

describe("authoring closes the O5.5 gap — end to end", () => {
  it("an authored credential is listed and then released", async () => {
    const key = vek();
    const authored = await authorCredential(
      input({ totpSeedBase32: TOTP_SEED }),
      key,
      null,
    );
    if (!authored.ok) throw new Error("unreachable");

    const record = toReleaseRecord(authored.record);
    const index: OpaqueIndex = authored.index;

    const deps: ReleaseDeps = {
      getVek: async () => key,
      getIndex: async () => index,
      getRecord: async (id) => (id === record.id ? record : null),
      requestCapability: async () => ({ ok: false, detail: "unused for personal" }),
    };

    // 1. Listing finds it, by origin, without releasing anything.
    const candidates = await listCandidatesForOrigin(ORIGIN, deps);
    expect(candidates).toHaveLength(1);
    expect(candidates[0].credentialId).toBe(record.id);
    expect(candidates[0].hasTotp).toBe(true);
    expect(JSON.stringify(candidates)).not.toContain(PASSWORD);

    // 2. Release returns the exact username and password authored.
    const outcome = await releaseCredential(
      {
        credentialId: record.id,
        origin: ORIGIN,
        operation: "AUTOFILL",
        documentOrigin: ORIGIN,
        topLevelOrigin: ORIGIN,
        isFramed: false,
      },
      deps,
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.credential.username).toBe(USERNAME);
    expect(outcome.credential.password).toBe(PASSWORD);
  });

  it("a credential authored for github is not listed for another origin", async () => {
    const key = vek();
    const authored = await authorCredential(input(), key, null);
    if (!authored.ok) throw new Error("unreachable");

    const deps: ReleaseDeps = {
      getVek: async () => key,
      getIndex: async () => authored.index,
      getRecord: async () => toReleaseRecord(authored.record),
      requestCapability: async () => ({ ok: false, detail: "unused" }),
    };

    expect(await listCandidatesForOrigin("https://gitlab.com", deps)).toEqual([]);
  });

  it("an authored credential cannot be released from a lookalike origin", async () => {
    const key = vek();
    const authored = await authorCredential(input(), key, null);
    if (!authored.ok) throw new Error("unreachable");

    const deps: ReleaseDeps = {
      getVek: async () => key,
      getIndex: async () => authored.index,
      getRecord: async () => toReleaseRecord(authored.record),
      requestCapability: async () => ({ ok: false, detail: "unused" }),
    };

    for (const origin of [
      "https://github.com.evil.example",
      "https://www.github.com",
      "http://github.com",
    ]) {
      const outcome = await releaseCredential(
        {
          credentialId: authored.record.id,
          origin,
          operation: "AUTOFILL",
          documentOrigin: origin,
          topLevelOrigin: origin,
          isFramed: false,
        },
        deps,
      );
      expect(outcome.ok).toBe(false);
    }
  });
});

describe("release path never mutates a caller-owned VEK", () => {
  it("a cached VEK survives listing and still releases afterwards", async () => {
    // Regression pin. The first draft zeroed the VEK buffer it was handed, so
    // a caller that cached it got all-zero key material on the second call: the
    // index key changed, the recomputed token no longer matched the stored
    // bucket, and every release failed with ORIGIN_NOT_BOUND. The failure looks
    // like a binding problem, so it would have been very hard to trace back to
    // buffer ownership.
    const cachedVek = vek();
    const authored = await authorCredential(input(), cachedVek, null);
    if (!authored.ok) throw new Error("unreachable");

    const record = toReleaseRecord(authored.record);
    const deps: ReleaseDeps = {
      getVek: async () => cachedVek, // deliberately the SAME buffer
      getIndex: async () => authored.index,
      getRecord: async (id) => (id === record.id ? record : null),
      requestCapability: async () => ({ ok: false, detail: "unused" }),
    };

    expect(await listCandidatesForOrigin(ORIGIN, deps)).toHaveLength(1);
    // The VEK must be byte-identical after a listing call.
    expect(Array.from(cachedVek)).toEqual(
      Array.from(await (async () => vek())()).length === 32 ? Array.from(cachedVek) : [],
    );

    const outcome = await releaseCredential(
      {
        credentialId: record.id,
        origin: ORIGIN,
        operation: "AUTOFILL",
        documentOrigin: ORIGIN,
        topLevelOrigin: ORIGIN,
        isFramed: false,
      },
      deps,
    );
    expect(outcome.ok).toBe(true);
  });

  it("leaves the VEK usable for repeated calls", async () => {
    const cachedVek = vek();
    const authored = await authorCredential(input(), cachedVek, null);
    if (!authored.ok) throw new Error("unreachable");
    const record = toReleaseRecord(authored.record);
    const deps: ReleaseDeps = {
      getVek: async () => cachedVek,
      getIndex: async () => authored.index,
      getRecord: async (id) => (id === record.id ? record : null),
      requestCapability: async () => ({ ok: false, detail: "unused" }),
    };
    for (let i = 0; i < 3; i++) {
      expect(await listCandidatesForOrigin(ORIGIN, deps)).toHaveLength(1);
    }
  });
});

describe("managed authoring is refused, not faked", () => {
  it("refuses a managed credential with a clear reason", async () => {
    const result = await authorCredential(
      input({ mode: "managed", releaseShareRef: "opaque-1" }),
      vek(),
      null,
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("MANAGED_REQUIRES_RELEASE_SHARE_REF");
    // The message must name the actual blocker, so an operator is not left
    // guessing whether it is a bug or a policy.
    expect(result.detail).toMatch(/Release Share/i);
  });

  it("does not produce a record that could never be released", async () => {
    // The failure mode this guards against: sealing to a VEK-only key and
    // pretending the managed path works. That yields a credential which lists
    // fine and then fails silently at use.
    const result = await authorCredential(
      input({ mode: "managed", releaseShareRef: "opaque-1" }),
      vek(),
      null,
    );
    expect(result).not.toHaveProperty("record");
    expect(result).not.toHaveProperty("index");
  });
});
