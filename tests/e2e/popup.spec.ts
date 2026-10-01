import { test, expect, skipIfNoChrome } from "./helpers/extension-fixture";

test.describe("Popup UI", () => {
  test.beforeEach(async () => {
    test.skip(skipIfNoChrome(), "Google Chrome is required for extension E2E tests");
  });

  test("popup opens successfully", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    // "🛡️ CyberVault", not "CyberVault": the ISCD branding commit added the
    // shield and this expectation was never updated, because the e2e job had
    // not run green since before it.
    await expect(popup.locator("h1.header__title")).toHaveText("🛡️ CyberVault");
    await expect(popup.locator("#lock-toggle")).toBeVisible();
    await expect(popup.locator("#options-link")).toBeVisible();
  });

  test("shows the login view on a profile with no session", async ({ openPopup }) => {
    const popup = await openPopup();

    // A fresh e2e profile holds no AUTH_TOKEN, and checkAuthState() shows the
    // login view in that case — unlocking before authenticating is not a state
    // the popup can reach. This spec still assumed the pre-auth two-view
    // layout and asserted the lock screen on open.
    const loginView = popup.locator("#login-view");
    await expect(loginView).toBeVisible();
    await expect(popup.locator("#locked-view")).toBeHidden();

    const emailInput = popup.locator("#login-email");
    await expect(emailInput).toBeVisible();
    await expect(emailInput).toHaveAttribute("type", "email");

    const passwordInput = popup.locator("#login-password");
    await expect(passwordInput).toBeVisible();
    await expect(passwordInput).toHaveAttribute("type", "password");

    await expect(popup.locator("#login-btn")).toBeVisible();
  });

  test("shows the lock screen once the profile holds a session", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    const lockedView = popup.locator("#locked-view");
    await expect(lockedView).toBeVisible();

    const passphraseInput = popup.locator("#passphrase-input");
    await expect(passphraseInput).toBeVisible();
    await expect(passphraseInput).toHaveAttribute("type", "password");

    const unlockBtn = popup.locator("#unlock-btn");
    await expect(unlockBtn).toBeVisible();
    await expect(unlockBtn).toHaveText("Unlock");
  });

  test("shows a generic error when the unlock cannot reach a vault", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    await popup.locator("#passphrase-input").fill("test-passphrase");
    await popup.locator("#unlock-btn").click();

    const lockError = popup.locator("#lock-error");
    await expect(lockError).toBeVisible();
    // The generic decrypt failure, not "No vault found". This case has no
    // backend at all, so it exercises the unreachable-vault path; the
    // empty-vault-list branch needs a stubbed API that answers with an empty
    // array, and is therefore not covered here.
    //
    // Keeping the generic message is also the safer assertion: distinguishing
    // "no vault exists" from "wrong passphrase" tells an attacker whether an
    // account holds a vault.
    await expect(lockError).toContainText("Frase maestra incorrecta");
  });

  test("unlocked view is hidden initially", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    const unlockedView = popup.locator("#unlocked-view");
    await expect(unlockedView).toBeHidden();
  });

  test("lock icon shows locked state", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    const lockIcon = popup.locator("#lock-icon");
    await expect(lockIcon).toHaveText("🔒");
  });

  test("clicking lock toggle shows lock screen", async ({ openPopupWithSession }) => {
    const popup = await openPopupWithSession();

    await popup.locator("#lock-toggle").click();
    await expect(popup.locator("#passphrase-input")).toBeFocused();
  });

  test("settings link is present", async ({ openPopup }) => {
    const popup = await openPopup();

    const settingsLink = popup.locator("#options-link");
    await expect(settingsLink).toBeVisible();
    await expect(settingsLink).toHaveText("Settings");
  });

  test("add button exists in unlocked view structure", async ({ openPopup }) => {
    const popup = await openPopup();

    const addBtn = popup.locator("#add-btn");
    await expect(addBtn).toHaveCount(1);
  });

  test("add form elements exist", async ({ openPopup }) => {
    const popup = await openPopup();

    await expect(popup.locator("#add-title")).toHaveCount(1);
    await expect(popup.locator("#add-username")).toHaveCount(1);
    await expect(popup.locator("#add-password")).toHaveCount(1);
    await expect(popup.locator("#add-url")).toHaveCount(1);
    await expect(popup.locator("#add-save")).toHaveCount(1);
    await expect(popup.locator("#add-cancel")).toHaveCount(1);
  });
});
