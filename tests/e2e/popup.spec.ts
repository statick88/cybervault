import { test, expect, skipIfNoChrome } from "./helpers/extension-fixture";

test.describe("Popup UI", () => {
  test.beforeEach(async () => {
    test.skip(skipIfNoChrome(), "Google Chrome is required for extension E2E tests");
  });

  test("popup opens successfully", async ({ openPopup }) => {
    const popup = await openPopup();

    await expect(popup.locator("h1.header__title")).toHaveText("CyberVault");
    await expect(popup.locator("#lock-toggle")).toBeVisible();
    await expect(popup.locator("#options-link")).toBeVisible();
  });

  test("shows lock screen with password input", async ({ openPopup }) => {
    const popup = await openPopup();

    const lockedView = popup.locator("#locked-view");
    await expect(lockedView).toBeVisible();

    const passphraseInput = popup.locator("#passphrase-input");
    await expect(passphraseInput).toBeVisible();
    await expect(passphraseInput).toHaveAttribute("type", "password");

    const unlockBtn = popup.locator("#unlock-btn");
    await expect(unlockBtn).toBeVisible();
    await expect(unlockBtn).toHaveText("Unlock");
  });

  test("shows error when unlocking without vault", async ({ openPopup }) => {
    const popup = await openPopup();

    await popup.locator("#passphrase-input").fill("test-passphrase");
    await popup.locator("#unlock-btn").click();

    const lockError = popup.locator("#lock-error");
    await expect(lockError).toBeVisible();
    await expect(lockError).toContainText("No vault found");
  });

  test("unlocked view is hidden initially", async ({ openPopup }) => {
    const popup = await openPopup();

    const unlockedView = popup.locator("#unlocked-view");
    await expect(unlockedView).toBeHidden();
  });

  test("lock icon shows locked state", async ({ openPopup }) => {
    const popup = await openPopup();

    const lockIcon = popup.locator("#lock-icon");
    await expect(lockIcon).toHaveText("🔒");
  });

  test("clicking lock toggle shows lock screen", async ({ openPopup }) => {
    const popup = await openPopup();

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
