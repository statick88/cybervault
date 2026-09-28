import type { IncomingMessage, ServerResponse } from "http";
import { readFileSync, existsSync } from "fs";
import { resolve as resolvePath } from "path";

/**
 * This module is loaded from two different places, and the distance from this
 * file to the app root is not the same in both:
 *
 *  - compiled: tsconfig.json uses "rootDir": ".", so this file is emitted at
 *    <root>/dist/src/infrastructure/api/ and the root is four levels up.
 *  - from source (ts-jest, tsx): the file stays at <root>/src/infrastructure/api/
 *    and the root is three levels up.
 *
 * A single __dirname-relative depth is therefore wrong in one of the two, and
 * guessing wrong makes this module throw ENOENT at import time, which takes the
 * whole API server down. Resolve the root by probing, and only fail if no
 * candidate actually contains the assets.
 */
function resolveAppRoot(relativeAsset: string): string {
  const candidates = [
    resolvePath(__dirname, "../../../../"), // compiled: dist/src/infrastructure/api
    resolvePath(__dirname, "../../../"), // from source: src/infrastructure/api
    resolvePath(process.cwd()), // container WORKDIR /app, repo root in dev
  ];

  for (const candidate of candidates) {
    if (existsSync(resolvePath(candidate, relativeAsset))) return candidate;
  }

  throw new Error(
    `Unable to locate ${relativeAsset}. Searched: ${candidates.join(", ")}. ` +
      `The runtime image must copy static/ and openapi.yaml to the app root.`,
  );
}

const APP_ROOT = resolveAppRoot("static/swagger/swagger-ui.css");
const STATIC_DIR = resolvePath(APP_ROOT, "static/swagger");

const SWAGGER_CSS = readFileSync(resolvePath(STATIC_DIR, "swagger-ui.css"), "utf-8");
const SWAGGER_JS_BUNDLE = readFileSync(resolvePath(STATIC_DIR, "swagger-ui-bundle.js"), "utf-8");
const SWAGGER_JS_STANDALONE = readFileSync(resolvePath(STATIC_DIR, "swagger-ui-standalone-preset.js"), "utf-8");

const SWAGGER_UI_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CyberVault API Docs</title>
  <link rel="stylesheet" href="/api/docs/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api/docs/swagger-ui-bundle.js"></script>
  <script src="/api/docs/swagger-ui-standalone-preset.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/docs/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
      layout: 'BaseLayout'
    });
  </script>
</body>
</html>`;

let cachedSpec: string | null = null;

function loadSpec(): string {
  if (cachedSpec) return cachedSpec;
  cachedSpec = readFileSync(resolvePath(APP_ROOT, "openapi.yaml"), "utf-8");
  return cachedSpec;
}

function yamlToJson(yaml: string): Record<string, unknown> {
  const lines = yaml.split("\n");
  const result: Record<string, unknown> = {};
  const stack: { obj: Record<string, unknown>; indent: number }[] = [{ obj: result, indent: -1 }];

  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith("#")) continue;

    const indent = line.search(/\S/);
    const trimmed = line.trim();

    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();

    const parent = stack[stack.length - 1].obj;

    if (!value) {
      const child: Record<string, unknown> = {};
      parent[key] = child;
      stack.push({ obj: child, indent });
    } else {
      parent[key] = parseYamlValue(value);
    }
  }

  return result;
}

function parseYamlValue(value: string): unknown {
  if (value === "true") return true;
  if (value === "false") return false;
  if (value === "null") return null;
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  if (value.startsWith("[")) {
    try { return JSON.parse(value); } catch { return value; }
  }
  return value;
}

const STATIC_ASSETS: Record<string, { content: string; contentType: string }> = {
  "/api/docs/swagger-ui.css": { content: SWAGGER_CSS, contentType: "text/css; charset=utf-8" },
  "/api/docs/swagger-ui-bundle.js": { content: SWAGGER_JS_BUNDLE, contentType: "application/javascript; charset=utf-8" },
  "/api/docs/swagger-ui-standalone-preset.js": { content: SWAGGER_JS_STANDALONE, contentType: "application/javascript; charset=utf-8" },
};

export function swaggerMiddleware(req: IncomingMessage, res: ServerResponse): boolean {
  const url = new URL(req.url || "", `http://${req.headers.host}`);

  const asset = STATIC_ASSETS[url.pathname];
  if (asset && req.method === "GET") {
    res.writeHead(200, { "Content-Type": asset.contentType });
    res.end(asset.content);
    return true;
  }

  if (url.pathname === "/api/docs" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(SWAGGER_UI_HTML);
    return true;
  }

  if (url.pathname === "/api/docs/openapi.json" && req.method === "GET") {
    try {
      const yaml = loadSpec();
      const spec = yamlToJson(yaml);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(spec));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to load OpenAPI spec" }));
    }
    return true;
  }

  return false;
}
