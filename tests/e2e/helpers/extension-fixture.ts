/**
 * Playwright fixture for Chrome Extension testing.
 *
 * Uses `chromium.launchPersistentContext()` with `--load-extension`
 * so the extension is loaded in a real browser profile.
 *
 * REQUIRES: a Chromium binary. `npx playwright install` provides the bundled
 * one this fixture prefers, so it works on a fresh CI runner and on a
 * developer machine without a system Chrome.
 */

import { test as base, chromium, type BrowserContext, type Page } from "@playwright/test";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { execSync } from "child_process";
import { existsSync } from "fs";

const EXTENSION_DIST = path.join(__dirname, "../../../dist");

/* ------------------------------------------------------------------ */
/*  Environment detection                                             */
/* ------------------------------------------------------------------ */

/**
 * Resolve a Chromium binary that actually exists on this machine.
 *
 * Three sources, in order of reliability:
 *
 *  1. `CHROME_PATH`, set by CI and by most Chrome install wrappers.
 *  2. Playwright's own bundled Chromium, via `chromium.executablePath()`. The
 *     workflow already runs `npx playwright install --with-deps`, so this is
 *     present on CI by construction — it is the one source guaranteed to agree
 *     with the Playwright version driving the test.
 *  3. A system binary, for developers who have Chrome but no `playwright install`.
 *
 * Guessing names on PATH is not enough: `browser-actions/setup-chrome` installs
 * to `/opt/hostedtoolcache/setup-chrome/chromium/stable/x64/chrome`, which is
 * neither `google-chrome-stable` nor on PATH. An earlier version probed only
 * PATH names, found nothing, and every case failed with "executable doesn't
 * exist at google-chrome-stable".
 */
function findChromeBinary(): string | null {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }

  try {
    const bundled = chromium.executablePath();
    if (bundled && existsSync(bundled)) return bundled;
  } catch {
    // Playwright reports this when its browser was never downloaded.
  }

  const candidates = [
    "google-chrome-stable",
    "google-chrome",
    "chromium-browser",
    "chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ];
  for (const bin of candidates) {
    try {
      execSync(`which "${bin}"`, { stdio: "ignore" });
      return bin;
    } catch {
      // not found, continue
    }
  }
  return null;
}

const chromeBinary = findChromeBinary();
const CAN_LOAD_EXTENSIONS = !!chromeBinary;

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/**
 * Wait for the extension service worker to register and return it.
 * Uses the context's `serviceworker` event.
 */
async function waitForServiceWorker(context: BrowserContext): Promise<Page> {
  const existing = context.serviceWorkers()[0];
  if (existing) return existing as unknown as Page;

  const sw = await new Promise<Page>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Service worker did not register within 10s")),
      10_000,
    );
    context.once("serviceworker", (worker) => {
      clearTimeout(timeout);
      resolve(worker as unknown as Page);
    });
  });

  return sw;
}

/**
 * Extract the extension ID from a service worker's URL.
 */
function getExtensionIdFromWorker(sw: Page): string {
  const url = (sw as unknown as { url(): string }).url();
  const match = url.match(/chrome-extension:\/\/([^/]+)\//);
  if (!match) throw new Error(`Could not extract extension ID from: ${url}`);
  return match[1];
}

/**
 * Open the extension popup page via chrome-extension:// URL.
 */
async function openPopup(context: BrowserContext): Promise<Page> {
  const sw = context.serviceWorkers()[0];
  if (!sw) throw new Error("No service worker found — extension may not have loaded");

  const extId = getExtensionIdFromWorker(sw as unknown as Page);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extId}/ui/popup/popup.html`);
  return popup;
}

/* ------------------------------------------------------------------ */
/*  Fixture types                                                     */
/* ------------------------------------------------------------------ */

interface ExtensionFixtures {
  /** Browser context with the extension loaded */
  extensionContext: BrowserContext;
  /** The extension's background service worker page */
  serviceWorker: Page | null;
  /** Extension ID extracted from the service worker URL */
  extensionId: string;
  /** Helper: open the popup */
  openPopup: () => Promise<Page>;
  /** Helper: open a test page by filename from fixtures/ */
  openTestPage: (filename: string) => Promise<Page>;
}

/* ------------------------------------------------------------------ */
/*  Test fixture                                                      */
/* ------------------------------------------------------------------ */

export const test = base.extend<ExtensionFixtures>({
  extensionContext: async ({}, use) => {
    // Skip if Chrome is not available (extensions need Chrome, not Chromium)
    if (!CAN_LOAD_EXTENSIONS) {
      // Use a dummy context — tests should check and skip themselves
      const context = await chromium.launch({ headless: true });
      const browserContext = await context.newContext();
      await use(browserContext);
      await browserContext.close();
      await context.close();
      return;
    }

    // Ensure extension is built
    if (!fs.existsSync(path.join(EXTENSION_DIST, "manifest.json"))) {
      throw new Error(
        "Extension not built. Run `npm run build:ext` first.",
      );
    }

    // Use a temp directory for the Chrome user profile
    const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cybervault-e2e-"));

    const context = await chromium.launchPersistentContext(userDataDir, {
      // Extensions do not load in Playwright's headless mode — the service
      // worker never registers, so every case times out waiting for it. This
      // launch needs a real display; on Linux CI the workflow supplies one with
      // `xvfb-run`. Set E2E_HEADLESS=1 only to reproduce that failure.
      headless: process.env.E2E_HEADLESS === "1",
      // `channel: "chrome"` resolves to a hardcoded `google-chrome-stable`
      // path and takes precedence over `executablePath`, so passing both made
      // Playwright look for a binary that `setup-chrome` never creates under
      // that name — every case then failed with "executable doesn't exist".
      // Setting one or the other: an explicit path wins when we found one.
      ...(chromeBinary
        ? { executablePath: chromeBinary }
        : { channel: "chrome" as const }),
      args: [
        `--load-extension=${EXTENSION_DIST}`,
        "--disable-blink-features=AutomationControlled",
      ],
      ignoreDefaultArgs: ["--enable-automation"],
    });

    try {
      await waitForServiceWorker(context);
      await use(context);
    } finally {
      await context.close();
      try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  },

  serviceWorker: async ({ extensionContext }, use) => {
    const sw = extensionContext.serviceWorkers()[0] ?? null;
    await use(sw as unknown as Page);
  },

  extensionId: async ({ extensionContext }, use) => {
    if (!CAN_LOAD_EXTENSIONS) {
      await use("");
      return;
    }
    const sw = await waitForServiceWorker(extensionContext);
    await use(getExtensionIdFromWorker(sw));
  },

  openPopup: async ({ extensionContext }, use) => {
    const fn = async () => {
      if (!CAN_LOAD_EXTENSIONS) {
        throw new Error("Chrome not available — cannot load extension");
      }
      return openPopup(extensionContext);
    };
    await use(fn);
  },

  openTestPage: async ({ extensionContext }, use) => {
    const fn = async (filename: string) => {
      const filePath = path.join(__dirname, "../fixtures", filename);
      const page = await extensionContext.newPage();
      await page.goto(`file://${filePath}`);
      return page;
    };
    await use(fn);
  },
});

export const skipIfNoChrome = () => {
  if (!CAN_LOAD_EXTENSIONS) {
    return true; // caller should: test.skip(skipIfNoChrome(), "Chrome not available");
  }
  return false;
};

export { expect } from "@playwright/test";
