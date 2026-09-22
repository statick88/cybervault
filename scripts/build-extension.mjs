/**
 * Build script for Chrome Extension
 * Bundles background scripts with esbuild and copies static files
 */

import * as esbuild from "esbuild";
import * as fs from "fs";
import { copyFileSync, mkdirSync, existsSync, readdirSync, rmSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "..");
const distDir = join(rootDir, "dist");
const srcDir = join(rootDir, "src");

// Clean ONLY extension-specific directories in dist/ (NOT the entire dist/)
// This preserves tsc output (infrastructure/, domain/, etc.) needed by the API server
const extDirs = ["background", "ui", "icons"];
const extFiles = ["manifest.json"];
for (const dir of extDirs) {
  const target = join(distDir, dir);
  if (existsSync(target)) rmSync(target, { recursive: true });
}
for (const file of extFiles) {
  const target = join(distDir, file);
  if (existsSync(target)) rmSync(target);
}
// Ensure directories exist
for (const dir of extDirs) {
  mkdirSync(join(distDir, dir), { recursive: true });
}

// Shared define replacements — injected at build-time so Chrome
// Service Workers / content scripts never see `process.env.*`
const buildDefines = {
  "process.env.NODE_ENV": '"production"',
  "process.env.LOG_LEVEL": '"info"',
  "process.env.LOG_FORMAT": '"json"',
};

// 1. Build background script with esbuild (bundle into single file)
await esbuild.build({
  entryPoints: [join(srcDir, "background/auditor.ts")],
  bundle: true,
  outfile: join(distDir, "background/auditor.js"),
  platform: "browser",
  target: "chrome120",
  format: "iife",
  minify: false,
  sourcemap: true,
  alias: {
    "@noble/hashes/utils": "@noble/hashes/utils.js",
    "@noble/hashes/sha2": "@noble/hashes/sha2.js",
  },
  define: buildDefines,
});

console.log("✓ Background script bundled");

// 2. Build popup with esbuild (IIFE format for browser)
await esbuild.build({
  entryPoints: [join(srcDir, "ui/popup/popup.ts")],
  bundle: true,
  outfile: join(distDir, "ui/popup/popup.js"),
  platform: "browser",
  target: "chrome120",
  format: "iife",
  minify: false,
  sourcemap: true,
  define: buildDefines,
});

console.log("✓ Popup built");

// 3. Build content script (no imports, can be iife)
await esbuild.build({
  entryPoints: [join(srcDir, "ui/content-scripts/inject.ts")],
  bundle: true,
  outfile: join(distDir, "ui/content-scripts/inject.js"),
  platform: "browser",
  target: "chrome120",
  format: "iife",
  minify: false,
  sourcemap: true,
});

console.log("✓ Content script built");

// 3.1 Build autocomplete content script
await esbuild.build({
  entryPoints: [join(srcDir, "ui/content-scripts/autocomplete.ts")],
  bundle: true,
  outfile: join(distDir, "ui/content-scripts/autocomplete.js"),
  platform: "browser",
  target: "chrome120",
  format: "iife",
  minify: false,
  sourcemap: true,
});

console.log("✓ Autocomplete content script built");

// 4. Build options page — use IIFE (not ESM) because the source wraps
//    everything in an IIFE; esbuild would otherwise emit an invalid
//    `export default require_options()` mixing CommonJS + ESM.
await esbuild.build({
  entryPoints: [join(srcDir, "ui/options/options.ts")],
  bundle: true,
  outfile: join(distDir, "ui/options/options.js"),
  platform: "browser",
  target: "chrome120",
  format: "iife",
  minify: false,
  sourcemap: true,
  define: buildDefines,
});

console.log("✓ Options page built");

// 5. Copy static files recursively
async function copyDir(src, dest) {
  if (!existsSync(src)) return;

  const stat = await fs.promises.stat(src);
  if (stat.isDirectory()) {
    mkdirSync(dest, { recursive: true });
    for (const entry of readdirSync(src)) {
      const srcPath = join(src, entry);
      const destPath = join(dest, entry);
      await copyDir(srcPath, destPath);
    }
  } else {
    if (
      src.endsWith(".ts") ||
      src.endsWith(".js") ||
      src.endsWith(".json") ||
      src.endsWith(".map")
    ) {
      // Skip - handled by esbuild
      return;
    }
    copyFileSync(src, dest);
  }
}

// Copy icons
mkdirSync(join(distDir, "icons"), { recursive: true });
const iconsDir = join(srcDir, "icons");
if (existsSync(iconsDir)) {
  for (const file of readdirSync(iconsDir)) {
    if (file.endsWith(".png")) {
      copyFileSync(join(iconsDir, file), join(distDir, "icons", file));
    }
  }
}
console.log("✓ Icons copied");

// Copy HTML and CSS files
await copyDir(join(srcDir, "ui/popup"), join(distDir, "ui/popup"));
await copyDir(join(srcDir, "ui/options"), join(distDir, "ui/options"));

// Copy manifest
const manifestSrc = join(rootDir, "src/infrastructure/manifest/manifest.json");
if (existsSync(manifestSrc)) {
  copyFileSync(manifestSrc, join(distDir, "manifest.json"));
}

console.log("✓ Static files copied");
console.log("✓ Build complete!");
