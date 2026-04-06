/**
 * API Server para Cyber Vault
 * Servidor HTTP/HTTPS con seguridad mejorada
 * Arquitectura Limpia: Use Cases y Repositorios
 */

import { createServer, Server, IncomingMessage, ServerResponse } from "http";
import * as https from "https";
import { readFileSync } from "fs";
import { resolve as resolvePath } from "path";

import { IVaultRepository } from "../../domain/repositories";
import { CryptoService } from "../../infrastructure/crypto/crypto-service";
import { CredentialsGenerator } from "../../domain/services/autocompletado/credentials-generator";
import { authenticate } from "./auth";

// Use Cases
import { CreateVaultUseCase } from "../../application/use-cases/create-vault.use-case";
import { GenerateCredentialsUseCase } from "../../application/use-cases/generate-credentials.use-case";
import { ExtractCredentialsUseCase } from "../../application/use-cases/extract-credentials.use-case";

// Repositorios
import { ChromeStorageVaultRepository } from "../../infrastructure/repositories";

// Tipos fuertes para credenciales
import { CredentialsTypeFactory } from "../../domain/services/autocompletado/credentials-types";
import {
  EmailWithSalt,
  PasswordWithPepper,
} from "../../domain/services/autocompletado/credentials-types";

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

/**
 * Limpia completamente el rate limit map (solo para tests)
 */
export function _clearRateLimitForTests(): void {
  requestCounts.clear();
}

// Limpiar cada 5 minutos
setInterval(cleanupRateLimits, 5 * 60 * 1000);

/**
 * API Server con Clean Architecture
 */
export class ApiServer {
  private createVaultUseCase: CreateVaultUseCase;
  private generateCredentialsUseCase: GenerateCredentialsUseCase;
  private extractCredentialsUseCase: ExtractCredentialsUseCase;
  private credentialsGenerator: CredentialsGenerator;

  constructor(
    vaultRepository: IVaultRepository,
    _cryptoService: CryptoService,
    credentialsGenerator: CredentialsGenerator,
  ) {
    // Inicializar Use Cases
    this.createVaultUseCase = new CreateVaultUseCase(vaultRepository);
    this.generateCredentialsUseCase = new GenerateCredentialsUseCase(
      credentialsGenerator,
    );
    this.extractCredentialsUseCase = new ExtractCredentialsUseCase(
      credentialsGenerator,
    );
    this.credentialsGenerator = credentialsGenerator;
  }

  /**
   * Parsea el body JSON de la petición
   */
  private async parseJsonBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (error) {
          reject(error);
        }
      });
      req.on("error", reject);
    });
  }

  /**
   * Handler para health checks
   */
  private handleHealth(_req: IncomingMessage, res: ServerResponse): void {
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
  private handleReady(_req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ready",
        timestamp: new Date().toISOString(),
      }),
    );
  }

  /**
   * Handler para crear vault (uso de Use Case)
   */
  private async handleCreateVault(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const { name, description, encryptionKeyId } = data;

      if (!name || !encryptionKeyId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Name and encryptionKeyId are required" }),
        );
        return;
      }

      const vault = await this.createVaultUseCase.execute({
        name,
        description,
        encryptionKeyId,
      });

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify(vault.toPlainObject()));
    } catch (error: any) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message || "Invalid request" }));
    }
  }

  /**
   * Handler para generar credenciales (uso de Use Case)
   */
  private async handleGenerateCredentials(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const domain = data.domain;

      if (!domain) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Domain is required" }));
        return;
      }

      // Use Case: generar credenciales
      const credentials = await this.generateCredentialsUseCase.execute(domain);

      // Analizar calidad de las credenciales (domains service)
      const qualityAnalysis =
        this.credentialsGenerator.analyzeCredentialsQuality(credentials);

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
  }

  /**
   * Handler para extraer credenciales originales (uso de Use Case)
   */
  private async handleExtractCredentials(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const { email, password } = data;

      if (!email || !password) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Email and password are required" }));
        return;
      }

      // Convertir a tipos fuertes
      const storedEmail: EmailWithSalt =
        CredentialsTypeFactory.createEmailWithSalt(email);
      const storedPassword: PasswordWithPepper =
        CredentialsTypeFactory.createPasswordWithPepper(password);

      // Use Case: extraer credenciales originales
      const original = await this.extractCredentialsUseCase.execute(
        storedEmail,
        storedPassword,
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
  }

  /**
   * Handler para validar formato de credenciales
   */
  private handleValidateCredentials(
    req: IncomingMessage,
    res: ServerResponse,
  ): void {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const email = url.searchParams.get("email");
    const password = url.searchParams.get("password");

    if (!email && !password) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Email or password parameter required" }),
      );
      return;
    }

    const result: any = {};

    if (email) {
      result.email = {
        isValid: this.credentialsGenerator.isValidEmailWithSalt(email),
        hasSalt: this.credentialsGenerator.isValidEmailWithSalt(email),
      };
    }

    if (password) {
      result.password = {
        isValid: this.credentialsGenerator.isValidPasswordWithPepper(password),
        hasPepper:
          this.credentialsGenerator.isValidPasswordWithPepper(password),
      };
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  }

  /**
   * Request principal - routing y middlewares
   */
  private async handleRequest(
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
          this.handleHealth(req, res);
          break;

        case "/ready":
          this.handleReady(req, res);
          break;

        case "/api/v1/vaults":
          if (req.method === "POST") {
            // Verificar si JWT está habilitado
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleCreateVault(req, res);
              });
            } else {
              await this.handleCreateVault(req, res);
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
                this.handleGenerateCredentials(req, res);
              });
            } else {
              await this.handleGenerateCredentials(req, res);
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
                this.handleExtractCredentials(req, res);
              });
            } else {
              await this.handleExtractCredentials(req, res);
            }
          } else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Method not allowed" }));
          }
          break;

        case "/api/v1/credentials/validate":
          if (req.method === "GET") {
            this.handleValidateCredentials(req, res);
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
   * Inicia el servidor HTTP/HTTPS
   */
  public async start(port: number = 3000): Promise<Server> {
    return new Promise((resolvePromise, reject) => {
      let server: any;

      if (SECURITY_CONFIG.HTTPS_ENABLED) {
        try {
          const options = {
            key: readFileSync(resolvePath(SECURITY_CONFIG.TLS_KEY_PATH)),
            cert: readFileSync(resolvePath(SECURITY_CONFIG.TLS_CERT_PATH)),
          };
          server = https.createServer(options, (req, res) =>
            this.handleRequest(req, res),
          );
          console.log(`🔒 HTTPS Server started on port ${port}`);
        } catch (error) {
          console.warn("HTTPS certificates not found, falling back to HTTP");
          server = createServer((req, res) => this.handleRequest(req, res));
          console.log(`⚠️  HTTP Server started on port ${port} (no HTTPS)`);
        }
      } else {
        server = createServer((req, res) => this.handleRequest(req, res));
        console.log(`🌐 HTTP Server started on port ${port}`);
      }

      server
        .listen(port, () => {
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
          resolvePromise(server);
        })
        .on("error", reject);
    });
  }
}

/**
 * Función de conveniencia para iniciar el servidor con dependencias por defecto
 */
export async function startServer(port: number = 3000) {
  // Dependencias por defecto (Composition Root)
  const vaultRepository = new ChromeStorageVaultRepository();
  const cryptoService = new CryptoService();
  const credentialsGenerator = new CredentialsGenerator(cryptoService);

  const apiServer = new ApiServer(
    vaultRepository,
    cryptoService,
    credentialsGenerator,
  );
  return apiServer.start(port);
}

// Iniciar servidor si ejecutado directamente
if (require.main === module) {
  const port = parseInt(process.env.PORT || "3000", 10);
  startServer(port).catch(console.error);
}
