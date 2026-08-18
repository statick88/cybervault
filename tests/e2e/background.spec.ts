import { test, expect, skipIfNoChrome } from "./helpers/extension-fixture";

test.describe("Background Service Worker", () => {
  test.beforeEach(async () => {
    test.skip(skipIfNoChrome(), "Google Chrome is required for extension E2E tests");
  });

  test("service worker loads successfully", async ({ serviceWorker }) => {
    expect(serviceWorker).not.toBeNull();

    if (serviceWorker) {
      const url = serviceWorker.url();
      expect(url).toMatch(/^chrome-extension:\/\//);
    }
  });

  test("responds to VALIDATE_DOMAIN message", async ({ openPopup }) => {
    const popup = await openPopup();

    const result = await popup.evaluate(() => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          {
            type: "VALIDATE_DOMAIN",
            hostname: "example.com",
            expectedDomain: "example.com",
          },
          (response: unknown) => {
            resolve(response);
          },
        );
      });
    });

    expect(result).toBeTruthy();
    expect((result as { ok: boolean }).ok).toBe(true);
  });

  test("responds to GET_TRUST_STATUS message", async ({ openPopup }) => {
    const popup = await openPopup();

    const result = await popup.evaluate(() => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          {
            type: "GET_TRUST_STATUS",
            domain: "example.com",
          },
          (response: unknown) => {
            resolve(response);
          },
        );
      });
    });

    expect(result).toBeTruthy();
    expect((result as { ok: boolean }).ok).toBe(true);
  });

  test("responds to UNLOCK_VAULT message", async ({ openPopup }) => {
    const popup = await openPopup();

    const result = await popup.evaluate(() => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          {
            type: "UNLOCK_VAULT",
            vaultId: "test-vault-001",
            passphrase: "test-passphrase",
          },
          (response: unknown) => {
            resolve(response);
          },
        );
      });
    });

    expect(result).toBeTruthy();
    const resp = result as { ok: boolean; data?: { unlocked: boolean } };
    expect(resp.ok).toBe(true);
    expect(resp.data?.unlocked).toBe(true);
  });

  test("returns error for unknown message type", async ({ openPopup }) => {
    const popup = await openPopup();

    const result = await popup.evaluate(() => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: "UNKNOWN_MESSAGE_TYPE" },
          (response: unknown) => {
            resolve(response);
          },
        );
      });
    });

    expect(result).toBeTruthy();
    const resp = result as { ok: boolean; error?: string };
    expect(resp.ok).toBe(false);
    expect(resp.error).toContain("Unknown message type");
  });
});
