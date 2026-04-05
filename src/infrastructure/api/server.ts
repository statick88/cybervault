/**
 * API Server para Cyber Vault
 * Servidor HTTP/HTTPS con seguridad mejorada
 */

import { createServer, IncomingMessage, ServerResponse } from "http";
import * as https from "https";
import { readFileSync } from "fs";
import { resolve } from "path";
import { CryptoService } from "../crypto/crypto-service";
import { Vault } from "../../domain/entities/vault";
import { CredentialsGenerator } from "../../domain/services/autocompletado/credentials-generator";
import { authenticate } from "./auth";

// Configuración de seguridad
const SECURITY_CONFIG = {
  HTTPS_ENABLED: process.env.HTTPS_ENABLED === "true",
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || "./certs/server.crt",
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || "./certs/server.key",
  CSP: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
};

// Configuración JWT
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn(
    "⚠️  JWT_SECRET not set - authentication will be disabled (development mode)",
  );
}

// Rate limiting configuration
const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutos

/**
 * Verifica si una IP ha excedido el límite de requests
 */
function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = requestCounts.get(ip);

  if (!record) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  // Reset si ha pasado el tiempo ventana
  if (now > record.resetTime) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  // Incrementar contador
  record.count++;

  if (record.count > RATE_LIMIT_MAX) {
    return false; // Rate limit excedido
  }

  return true;
}

/**
 * Limpia registros de rate limiting expirados
 */
function cleanupRateLimits(): void {
  const now = Date.now();
  requestCounts.forEach((record, ip) => {
    if (now > record.resetTime) {
      requestCounts.delete(ip);
    }
  });
}

// Limpiar cada 5 minutos
setInterval(cleanupRateLimits, 5 * 60 * 1000);

// Inicializar servicios
const cryptoService = new CryptoService();
const credentialsGenerator = new CredentialsGenerator(cryptoService);

/**
 * Handler para health checks
 */
function handleHealth(_req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      status: "healthy",
      timestamp: new Date().toISOString(),
      service: "cyber-vault-api",
    }),
  );
}

/**
 * Handler para readiness checks
 */
function handleReady(_req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(
    JSON.stringify({
      status: "ready",
      timestamp: new Date().toISOString(),
    }),
  );
}

/**
 * Handler para crear vault (demo)
 */
async function handleCreateVault(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  let body = "";

  req.on("data", (chunk: Buffer) => {
    body += chunk.toString();
  });

  req.on("end", async () => {
    try {
      const data = JSON.parse(body);

      // Encriptar datos
      const keyPair = await cryptoService.generateKeyPair();
      const encryptedData = await cryptoService.encrypt(
        data.secret,
        keyPair.publicKey,
      );

      // Crear vault
      const vault = Vault.create({
        name: data.name || "Demo Vault",
        description: data.description,
        encryptedData: encryptedData,
        encryptionKeyId: "demo-key-id",
        metadata: {
          encryptedWith: "AES-GCM-256",
          keyType: "ECDSA-P-256",
        },
      });

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: vault.id.toString(),
          name: vault.name,
          createdAt: vault.createdAt.toISOString(),
        }),
      );
    } catch (error) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid request" }));
    }
  });
}

/**
 * Handler para generar credenciales con sal y pimienta
 */
async function handleGenerateCredentials(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  let body = "";

  req.on("data", (chunk: Buffer) => {
    body += chunk.toString();
  });

  req.on("end", async () => {
    try {
      const data = JSON.parse(body);
      const domain = data.domain;

      if (!domain) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Domain is required" }));
        return;
      }

      // Generar credenciales
      const credentials =
        await credentialsGenerator.generateCredentials(domain);

      // Analizar calidad de las credenciales
      const qualityAnalysis =
        credentialsGenerator.analyzeCredentialsQuality(credentials);

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          email: credentials.email,
          password: credentials.password,
          originalEmail: credentials.originalEmail,
          originalPassword: credentials.originalPassword,
          domain: domain,
          quality: {
            isValid: qualityAnalysis.isValid,
            entropy: qualityAnalysis.entropyAnalysis,
            warnings: qualityAnalysis.warnings,
          },
          timestamp: new Date().toISOString(),
        }),
      );
    } catch (error: any) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: error.message || "Invalid request",
          code: error.code || "UNKNOWN_ERROR",
        }),
      );
    }
  });
}

/**
 * Handler para extraer credenciales originales
 */
async function handleExtractCredentials(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  let body = "";

  req.on("data", (chunk: Buffer) => {
    body += chunk.toString();
  });

  req.on("end", async () => {
    try {
      const data = JSON.parse(body);
      const { email, password } = data;

      if (!email || !password) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Email and password are required" }));
        return;
      }

      // Extraer credenciales originales
      const original = await credentialsGenerator.extractOriginalCredentials(
        email,
        password,
      );

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          email: original.email,
          password: original.password,
          timestamp: new Date().toISOString(),
        }),
      );
    } catch (error: any) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: error.message || "Invalid request",
          code: error.code || "UNKNOWN_ERROR",
        }),
      );
    }
  });
}

/**
 * Handler para validar formato de credenciales
 */
function handleValidateCredentials(
  req: IncomingMessage,
  res: ServerResponse,
): void {
  const url = new URL(req.url || "", `http://${req.headers.host}`);
  const email = url.searchParams.get("email");
  const password = url.searchParams.get("password");

  if (!email && !password) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Email or password parameter required" }));
    return;
  }

  const result: any = {};

  if (email) {
    result.email = {
      isValid: credentialsGenerator.isValidEmailWithSalt(email),
      hasSalt: credentialsGenerator.isValidEmailWithSalt(email),
    };
  }

  if (password) {
    result.password = {
      isValid: credentialsGenerator.isValidPasswordWithPepper(password),
      hasPepper: credentialsGenerator.isValidPasswordWithPepper(password),
    };
  }

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(result));
}

/**
 * Handler principal
 */
async function requestHandler(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // Configurar headers de seguridad
  const cspString = Object.entries(SECURITY_CONFIG.CSP)
    .map(([key, values]) => `${key} ${values.join(" ")}`)
    .join("; ");

  res.setHeader("Content-Security-Policy", cspString);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Aplicar rate limiting a todos los endpoints
  const ip = req.socket?.remoteAddress || "unknown";
  if (!checkRateLimit(ip)) {
    res.writeHead(429, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Rate limit exceeded" }));
    return;
  }

  const url = new URL(req.url || "", `http://${req.headers.host}`);

  try {
    switch (url.pathname) {
      case "/health":
        handleHealth(req, res);
        break;

      case "/ready":
        handleReady(req, res);
        break;

      case "/api/v1/vaults":
        if (req.method === "POST") {
          // Verificar si JWT está habilitado
          if (JWT_SECRET) {
            authenticate(req, res, () => {
              handleCreateVault(req, res);
            });
          } else {
            await handleCreateVault(req, res);
          }
        } else {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Method not allowed" }));
        }
        break;

      case "/api/v1/credentials/generate":
        if (req.method === "POST") {
          if (JWT_SECRET) {
            authenticate(req, res, () => {
              handleGenerateCredentials(req, res);
            });
          } else {
            await handleGenerateCredentials(req, res);
          }
        } else {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Method not allowed" }));
        }
        break;

      case "/api/v1/credentials/extract":
        if (req.method === "POST") {
          if (JWT_SECRET) {
            authenticate(req, res, () => {
              handleExtractCredentials(req, res);
            });
          } else {
            await handleExtractCredentials(req, res);
          }
        } else {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Method not allowed" }));
        }
        break;

      case "/api/v1/credentials/validate":
        if (req.method === "GET") {
          handleValidateCredentials(req, res);
        } else {
          res.writeHead(405, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Method not allowed" }));
        }
        break;

      default:
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
    }
  } catch (error) {
    console.error("Error handling request:", error);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Internal server error" }));
  }
}

/**
 * Iniciar servidor
 */
export function startServer(port: number = 3000) {
  let server: any;

  if (SECURITY_CONFIG.HTTPS_ENABLED) {
    try {
      const options = {
        key: readFileSync(resolve(SECURITY_CONFIG.TLS_KEY_PATH)),
        cert: readFileSync(resolve(SECURITY_CONFIG.TLS_CERT_PATH)),
      };
      server = https.createServer(options, requestHandler);
      console.log(`🔒 HTTPS Server started on port ${port}`);
    } catch (error) {
      console.warn("HTTPS certificates not found, falling back to HTTP");
      server = createServer(requestHandler);
      console.log(`⚠️  HTTP Server started on port ${port} (no HTTPS)`);
    }
  } else {
    server = createServer(requestHandler);
    console.log(`🌐 HTTP Server started on port ${port}`);
  }

  server.listen(port, () => {
    console.log(`🚀 Cyber Vault API ready at http://localhost:${port}`);
    console.log(`   Health check: http://localhost:${port}/health`);
    console.log(`   Ready check: http://localhost:${port}/ready`);
    if (JWT_SECRET) {
      console.log(`   🔐 Authentication: ENABLED`);
    } else {
      console.log(`   🔓 Authentication: DISABLED (development mode)`);
    }
    console.log(
      `   📊 Rate limit: ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW / 60000} minutes`,
    );
  });

  return server;
}

// Iniciar servidor si ejecutado directamente
if (require.main === module) {
  const port = parseInt(process.env.PORT || "3000", 10);
  startServer(port);
}
