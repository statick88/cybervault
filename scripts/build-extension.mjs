/**
 * Build script for Chrome Extension
 * Bundles background scripts with esbuild and copies static files
 */

import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync, existsSync, readdirSync, rmSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "..");
const distDir = join(rootDir, "dist");
const srcDir = join(rootDir, "src");

// Clean dist
if (existsSync(distDir)) {
  rmSync(distDir, { recursive: true });
}
mkdirSync(distDir, { recursive: true });

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
  define: {
    "process.env.NODE_ENV": '"production"',
  },
});

console.log("✓ Background script bundled");

// 2. Build popup with esbuild (needs to be module for imports)
await esbuild.build({
  entryPoints: [join(srcDir, "ui/popup/popup.ts")],
  bundle: true,
  outfile: join(distDir, "ui/popup/popup.js"),
  platform: "browser",
  target: "chrome120",
  format: "esm",
  minify: false,
  sourcemap: true,
  define: {
    "process.env.NODE_ENV": '"production"',
  },
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

// 4. Build options page
await esbuild.build({
  entryPoints: [join(srcDir, "ui/options/options.ts")],
  bundle: true,
  outfile: join(distDir, "ui/options/options.js"),
  platform: "browser",
  target: "chrome120",
  format: "esm",
  minify: false,
  sourcemap: true,
});

console.log("✓ Options page built");

// 5. Copy static files
function copyDir(src, dest) {
  if (!existsSync(src)) return;
  mkdirSync(dest, { recursive: true });

  for (const entry of readdirSync(src)) {
    const srcPath = join(src, entry);
    const destPath = join(dest, entry);

    if (
      entry.endsWith(".ts") ||
      entry.endsWith(".js") ||
      entry.endsWith(".json")
    ) {
      // Skip - handled by esbuild
      continue;
    }

    copyFileSync(srcPath, destPath);
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
copyDir(join(srcDir, "ui/popup"), join(distDir, "ui/popup"));
copyDir(join(srcDir, "ui/options"), join(distDir, "ui/options"));

// Copy manifest
const manifestSrc = join(rootDir, "src/infrastructure/manifest/manifest.json");
if (existsSync(manifestSrc)) {
  copyFileSync(manifestSrc, join(distDir, "manifest.json"));
}

console.log("✓ Static files copied");
console.log("✓ Build complete!");
