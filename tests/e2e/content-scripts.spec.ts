import { test, expect, skipIfNoChrome } from "./helpers/extension-fixture";

test.describe("Content Scripts — inject.ts", () => {
  test.beforeEach(async () => {
    test.skip(skipIfNoChrome(), "Google Chrome is required for extension E2E tests");
  });

  test("detects login forms on the page", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const form = page.locator("#login-form");
    await expect(form).toBeVisible();

    const passwordInput = page.locator("#password");
    await expect(passwordInput).toHaveAttribute("type", "password");

    const usernameInput = page.locator("#username");
    await expect(usernameInput).toBeVisible();
  });

  test("submit button triggers form submit event", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    await page.locator("#username").fill("testuser");
    await page.locator("#password").fill("testpass");

    await page.locator("#submit-btn").click();

    await expect(page.locator("#result")).toBeVisible();
    await expect(page.locator("#result")).toContainText("Form submitted successfully");
  });

  test("page has correct form structure for content script detection", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const forms = await page.locator("form").count();
    expect(forms).toBeGreaterThanOrEqual(1);

    const passwordInputs = await page.locator('input[type="password"]').count();
    expect(passwordInputs).toBeGreaterThanOrEqual(1);

    const textInputs = await page.locator('input[type="text"]').count();
    expect(textInputs).toBeGreaterThanOrEqual(1);
  });

  test("form has proper input names for field detection", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const usernameInput = page.locator("#username");
    await expect(usernameInput).toHaveAttribute("name", "username");
    await expect(usernameInput).toHaveAttribute("autocomplete", "username");

    const passwordInput = page.locator("#password");
    await expect(passwordInput).toHaveAttribute("name", "password");
    await expect(passwordInput).toHaveAttribute("autocomplete", "current-password");
  });
});

test.describe("Content Scripts — autocomplete.ts", () => {
  test.beforeEach(async () => {
    test.skip(skipIfNoChrome(), "Google Chrome is required for extension E2E tests");
  });

  test("detects credential fields in a login form", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const emailLike = page.locator('input[type="text"], input[type="email"]');
    const passwordFields = page.locator('input[type="password"]');

    expect(await emailLike.count()).toBeGreaterThanOrEqual(1);
    expect(await passwordFields.count()).toBeGreaterThanOrEqual(1);
  });

  test("password field has expected attributes", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const passwordInput = page.locator("#password");
    await expect(passwordInput).toHaveAttribute("type", "password");
    await expect(passwordInput).toHaveAttribute("autocomplete", "current-password");
  });

  test("username field has user-related attributes for detection", async ({ openTestPage }) => {
    const page = await openTestPage("test-page.html");

    const usernameInput = page.locator("#username");
    const name = await usernameInput.getAttribute("name");
    const id = await usernameInput.getAttribute("id");
    const autocomplete = await usernameInput.getAttribute("autocomplete");

    const hasUserSignal =
      name?.includes("user") ||
      id?.includes("user") ||
      autocomplete?.includes("email") ||
      autocomplete?.includes("username");

    expect(hasUserSignal).toBeTruthy();
  });
});
