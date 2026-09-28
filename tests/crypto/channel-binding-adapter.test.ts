/**
 * H7 — `SubtleCryptoChannelBindingAdapter` sign/verify round trip.
 *
 * THE DEFECT
 * ----------
 * `signChannelBinding` and `verifyChannelBinding` both called
 * `getSessionKey()` WITHOUT `await`, but `getSessionKey` is async
 * (`master-key-manager.ts`). A Promise is always truthy, so
 * `if (!sessionKey)` never fired, and `fromBase64(Promise)` fed
 * `atob("[object Promise]")` to the HKDF path:
 *
 *   - `signChannelBinding` THREW — the only `IChannelBindingProtocol`
 *     implementation could not produce a binding at all;
 *   - `verifyChannelBinding` caught it and returned `false` — every genuine
 *     binding was reported as invalid.
 *
 * It is the ONLY implementation of the port and it failed in the wrong
 * direction, so this suite pins the round trip plus a tampered-binding
 * refusal.
 *
 * The session key is installed through a `chrome.storage.session` mock, the
 * same way `tests/crypto/master-key-manager.test.ts` does it — the adapter
 * reads it through `getSessionKey`, so the mock exercises the real async path.
 */

import { SubtleCryptoChannelBindingAdapter } from "../../src/infrastructure/crypto/subtle-crypto-channel-binding-adapter";
import type { ChannelBindingContext } from "../../src/domain/ports/interfaces/i-channel-binding-protocol";
import { BindingSignature } from "../../src/domain/value-objects/binding-signature";
import { binaryToBase64 } from "../../src/shared/utils";

type Store = Map<string, unknown>;

function createArea(store: Store) {
  return {
    get: async (keys: string | string[]): Promise<Record<string, unknown>> => {
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const key of list) {
        if (store.has(key)) out[key] = store.get(key);
      }
      return out;
    },
    set: async (items: Record<string, unknown>): Promise<void> => {
      for (const [key, value] of Object.entries(items)) store.set(key, value);
    },
    remove: async (keys: string | string[]): Promise<void> => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const key of list) store.delete(key);
    },
    clear: async (): Promise<void> => {
      store.clear();
    },
  };
}

/** Session key (base64, 32 bytes) + a fresh unlock time, exactly as unlock writes them. */
function unlockSession(sessionKeyB64: string): void {
  const session: Store = new Map();
  session.set("cybervault_session_key", sessionKeyB64);
  session.set("cybervault_unlock_time", Date.now());
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: createArea(new Map()), session: createArea(session) },
  };
}

function lockSession(): void {
  const empty: Store = new Map();
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: createArea(new Map()), session: createArea(empty) },
  };
}

const SESSION_KEY_B64 = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));

function contextFor(adapter: SubtleCryptoChannelBindingAdapter): ChannelBindingContext {
  return {
    domain: "https://example.com",
    timestamp: Date.now(),
    nonce: adapter.generateNonce(),
  };
}

/** Flip one bit of the signature payload so the base64 stays decodable. */
function tamper(signature: string): string {
  const bytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  bytes[0] ^= 0xff;
  return btoa(String.fromCharCode(...bytes));
}

describe("H7: SubtleCryptoChannelBindingAdapter", () => {
  let adapter: SubtleCryptoChannelBindingAdapter;

  beforeEach(() => {
    unlockSession(SESSION_KEY_B64);
    adapter = new SubtleCryptoChannelBindingAdapter();
  });

  afterEach(() => {
    lockSession();
  });

  it("signs then verifies a channel binding (round trip)", async () => {
    const context = contextFor(adapter);

    const signature = await adapter.signChannelBinding(context);

    expect(signature.domain).toBe("https://example.com");
    expect(signature.nonce).not.toBe("");
    expect(signature.signature).not.toBe("");

    await expect(
      adapter.verifyChannelBinding(signature, context),
    ).resolves.toBe(true);
  });

  it("fails verification for a tampered binding", async () => {
    const context = contextFor(adapter);
    const signature = await adapter.signChannelBinding(context);

    const tampered = BindingSignature.create(
      signature.domain,
      signature.timestamp,
      signature.nonce,
      tamper(signature.signature),
    );

    await expect(
      adapter.verifyChannelBinding(tampered, context),
    ).resolves.toBe(false);
  });

  it("fails verification for a binding signed over a different nonce", async () => {
    const context = contextFor(adapter);
    const signature = await adapter.signChannelBinding(context);

    const otherContext: ChannelBindingContext = {
      ...context,
      nonce: adapter.generateNonce(),
    };

    await expect(
      adapter.verifyChannelBinding(signature, otherContext),
    ).resolves.toBe(false);
  });

  it("refuses to sign when the vault is locked instead of treating a Promise as a key", async () => {
    lockSession();

    await expect(adapter.signChannelBinding(contextFor(adapter))).rejects.toThrow(
      /Vault must be unlocked/,
    );
  });

  it("returns false when verifying with a locked vault", async () => {
    const context = contextFor(adapter);
    const signature = await adapter.signChannelBinding(context);

    lockSession();

    await expect(adapter.verifyChannelBinding(signature, context)).resolves.toBe(false);
  });
});
