/**
 * Domain index tests — opaque origin lookup.
 *
 * The property that matters most is negative: the persisted index must not
 * contain, or permit recovery of, any origin the user stored a credential for.
 * Several tests below assert that directly rather than only checking that
 * lookups work.
 */

import {
  deriveDomainIndexKey,
  computeLookupToken,
  verifyTokenForOrigin,
  addToIndex,
  removeFromIndex,
  lookupIndex,
  emptyIndex,
  indexEntryMatchesOrigin,
  type OpaqueIndex,
} from "../../src/domain/services/autofill/domain-index";

const ORIGIN = "https://github.com";

async function indexKeyFor(seed = 1): Promise<CryptoKey> {
  const vek = new Uint8Array(32).fill(seed);
  return deriveDomainIndexKey(vek);
}

describe("Domain index — opaque origin lookup", () => {
  describe("deriveDomainIndexKey", () => {
    it("is deterministic for the same VEK", async () => {
      const vek = new Uint8Array(32).fill(7);
      const a = await computeLookupToken(ORIGIN, await deriveDomainIndexKey(vek));
      const b = await computeLookupToken(ORIGIN, await deriveDomainIndexKey(vek));
      expect(a.ok && b.ok && a.token).toBe(b.ok ? b.token : null);
    });

    it("differs for a different VEK", async () => {
      const a = await computeLookupToken(ORIGIN, await indexKeyFor(1));
      const b = await computeLookupToken(ORIGIN, await indexKeyFor(2));
      expect(a.ok && b.ok).toBe(true);
      if (a.ok && b.ok) expect(a.token).not.toBe(b.token);
    });
  });

  describe("computeLookupToken", () => {
    it("produces a fixed-length hex token", async () => {
      const result = await computeLookupToken(ORIGIN, await indexKeyFor());
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");
      expect(result.token).toMatch(/^[0-9a-f]{64}$/);
    });

    it("is deterministic across calls", async () => {
      const key = await indexKeyFor();
      const a = await computeLookupToken(ORIGIN, key);
      const b = await computeLookupToken(ORIGIN, key);
      expect(a.ok && b.ok && a.token).toBe(b.ok ? b.token : null);
    });

    it("canonicalizes the origin, so equivalent spellings share a token", async () => {
      const key = await indexKeyFor();
      const forms = [
        "https://github.com",
        "https://github.com:443",
        "https://GitHub.com",
        "https://github.com.",
        "https://github.com/login?x=1#f",
        "HTTPS://GITHUB.COM",
      ];
      const tokens = new Set<string>();
      for (const form of forms) {
        const r = await computeLookupToken(form, key);
        expect(r.ok).toBe(true);
        if (r.ok) tokens.add(r.token);
      }
      expect(tokens.size).toBe(1);
    });

    it("gives different origins different tokens", async () => {
      const key = await indexKeyFor();
      const seen = new Map<string, string>();
      for (const origin of [
        "https://github.com",
        "http://github.com",
        "https://www.github.com",
        "https://github.com:8443",
        "https://gitlab.com",
      ]) {
        const r = await computeLookupToken(origin, key);
        expect(r.ok).toBe(true);
        if (r.ok) {
          expect(seen.has(r.token)).toBe(false);
          seen.set(r.token, origin);
        }
      }
      expect(seen.size).toBe(5);
    });

    it("fails closed without an index key", async () => {
      const result = await computeLookupToken(ORIGIN, null);
      expect(result).toEqual({ ok: false, reason: "INDEX_KEY_MISSING" });
    });

    it("fails closed for an unusable origin", async () => {
      const key = await indexKeyFor();
      for (const bad of ["", "   ", "not a url", "javascript:alert(1)"]) {
        const r = await computeLookupToken(bad, key);
        expect(r).toEqual({ ok: false, reason: "ORIGIN_UNUSABLE" });
      }
    });
  });

  describe("disclosure property — §6.6", () => {
    it("the persisted index contains no origin and no secret", async () => {
      const key = await indexKeyFor();
      const token = (await computeLookupToken(ORIGIN, key)).ok
        ? ((await computeLookupToken(ORIGIN, key)) as { token: string }).token
        : "";

      let index = emptyIndex();
      index = addToIndex(index, token, "cred-1");
      index = addToIndex(index, token, "cred-2");

      const serialized = JSON.stringify(index);

      // No origin, in any spelling, may be recoverable from the index.
      expect(serialized).not.toContain("github");
      expect(serialized).not.toContain("github.com");
      expect(serialized).not.toContain("https");
      expect(serialized).not.toContain(ORIGIN);

      // Only opaque tokens and internal ids.
      expect(Object.keys(index.byToken)).toEqual([token]);
      expect(index.byToken[token]).toEqual(["cred-1", "cred-2"]);
    });

    it("tokens do not encode the origin reversibly", async () => {
      const key = await indexKeyFor();
      const r = await computeLookupToken(ORIGIN, key);
      expect(r.ok).toBe(true);
      if (!r.ok) throw new Error("unreachable");
      // A hex digest cannot contain the ASCII of the origin.
      expect(r.token).toMatch(/^[0-9a-f]+$/);
      expect(Buffer.from(r.token, "hex").toString("latin1")).not.toContain("github");
    });
  });

  describe("verifyTokenForOrigin", () => {
    it("accepts a token it produced for that origin", async () => {
      const key = await indexKeyFor();
      const r = await computeLookupToken(ORIGIN, key);
      if (!r.ok) throw new Error("unreachable");
      await expect(verifyTokenForOrigin(ORIGIN, key, r.token)).resolves.toBe(true);
    });

    it("rejects a token minted for a different origin", async () => {
      const key = await indexKeyFor();
      const other = await computeLookupToken("https://evil.example", key);
      if (!other.ok) throw new Error("unreachable");
      await expect(verifyTokenForOrigin(ORIGIN, key, other.token)).resolves.toBe(false);
    });

    it("rejects a token minted under a different VEK", async () => {
      const good = await computeLookupToken(ORIGIN, await indexKeyFor(1));
      if (!good.ok) throw new Error("unreachable");
      await expect(
        verifyTokenForOrigin(ORIGIN, await indexKeyFor(2), good.token),
      ).resolves.toBe(false);
    });

    it("rejects a tampered token", async () => {
      const key = await indexKeyFor();
      const r = await computeLookupToken(ORIGIN, key);
      if (!r.ok) throw new Error("unreachable");
      const flipped = r.token.replace(/^./, r.token[0] === "a" ? "b" : "a");
      await expect(verifyTokenForOrigin(ORIGIN, key, flipped)).resolves.toBe(false);
    });

    it("rejects a truncated or empty token", async () => {
      const key = await indexKeyFor();
      const r = await computeLookupToken(ORIGIN, key);
      if (!r.ok) throw new Error("unreachable");
      await expect(verifyTokenForOrigin(ORIGIN, key, r.token.slice(0, 32))).resolves.toBe(false);
      await expect(verifyTokenForOrigin(ORIGIN, key, "")).resolves.toBe(false);
    });

    it("fails closed without a key", async () => {
      await expect(verifyTokenForOrigin(ORIGIN, null, "deadbeef")).resolves.toBe(false);
    });
  });

  describe("index mutation", () => {
    it("adds and reads back", () => {
      const index = addToIndex(addToIndex(emptyIndex(), "t1", "a"), "t1", "b");
      expect(lookupIndex(index, "t1")).toEqual(["a", "b"]);
    });

    it("is idempotent for the same credential", () => {
      let index = addToIndex(emptyIndex(), "t1", "a");
      index = addToIndex(index, "t1", "a");
      expect(lookupIndex(index, "t1")).toEqual(["a"]);
    });

    it("returns empty for an unknown token", () => {
      expect(lookupIndex(emptyIndex(), "nope")).toEqual([]);
    });

    it("removes a credential and prunes the empty bucket", () => {
      let index = addToIndex(addToIndex(emptyIndex(), "t1", "a"), "t1", "b");
      index = removeFromIndex(index, "t1", "a");
      expect(lookupIndex(index, "t1")).toEqual(["b"]);
      index = removeFromIndex(index, "t1", "b");
      expect(lookupIndex(index, "t1")).toEqual([]);
      expect(Object.keys(index.byToken)).toEqual([]);
    });

    it("does not mutate the input index", () => {
      const before = addToIndex(emptyIndex(), "t1", "a");
      const snapshot = JSON.stringify(before);
      addToIndex(before, "t1", "b");
      removeFromIndex(before, "t1", "a");
      expect(JSON.stringify(before)).toBe(snapshot);
    });

    it("keeps buckets independent", () => {
      let index = addToIndex(emptyIndex(), "t1", "a");
      index = addToIndex(index, "t2", "b");
      index = removeFromIndex(index, "t1", "a");
      expect(lookupIndex(index, "t2")).toEqual(["b"]);
    });
  });

  describe("indexEntryMatchesOrigin — anti-injection", () => {
    let index: OpaqueIndex;
    let key: CryptoKey;
    let token: string;

    beforeEach(async () => {
      key = await indexKeyFor();
      const r = await computeLookupToken(ORIGIN, key);
      if (!r.ok) throw new Error("unreachable");
      token = r.token;
      index = addToIndex(emptyIndex(), token, "cred-1");
    });

    it("accepts a genuine entry for its own origin", async () => {
      await expect(
        indexEntryMatchesOrigin(index, token, "cred-1", ORIGIN, key),
      ).resolves.toBe(true);
    });

    it("rejects a genuine token presented for a different origin", async () => {
      // This is the compromised-backend case: it hands us a valid token but
      // claims it belongs to a page we are not on.
      await expect(
        indexEntryMatchesOrigin(index, token, "cred-1", "https://evil.example", key),
      ).resolves.toBe(false);
    });

    it("rejects a credential id that is not in the bucket", async () => {
      await expect(
        indexEntryMatchesOrigin(index, token, "cred-unknown", ORIGIN, key),
      ).resolves.toBe(false);
    });

    it("rejects without a key", async () => {
      await expect(
        indexEntryMatchesOrigin(index, token, "cred-1", ORIGIN, null),
      ).resolves.toBe(false);
    });
  });
});
