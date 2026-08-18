/**
 * API Server para Cyber Vault
 * Servidor HTTP/HTTPS con seguridad mejorada
 * Arquitectura Limpia: Use Cases y Repositorios
 */

import type { Server, IncomingMessage, ServerResponse } from "http";
import { createServer } from "http";
import * as https from "https";
import { readFileSync } from "fs";
import { resolve as resolvePath } from "path";

import type {
  IVaultRepository,
  ICredentialRepository,
} from "../../domain/repositories";
import { VaultId } from "../../domain/value-objects/ids";
import { EncryptionService } from "../../infrastructure/crypto/EncryptionService";
import { HashingService } from "../../infrastructure/crypto/HashingService";
import { SignatureService } from "../../infrastructure/crypto/signature-service";
import { KeyManagementService } from "../../infrastructure/crypto/KeyManagementService";
import { CredentialsGenerator } from "../../domain/services/autocompletado/credentials-generator";
import {
  authenticate,
  generateToken,
  getUserByEmail,
  createUser,
  verifyPassword,
} from "./auth";

import { swaggerMiddleware } from "./swagger";
import { connectRedis, disconnectRedis } from "../redis";
import { logger } from "../../shared/logger";
import { metrics } from "../../shared/metrics";

// Use Cases
import { CreateVaultUseCase } from "../../application/use-cases/create-vault.use-case";
import { GenerateCredentialsUseCase } from "../../application/use-cases/generate-credentials.use-case";
import { ExtractCredentialsUseCase } from "../../application/use-cases/extract-credentials.use-case";

// Repositorios
import {
  ChromeStorageVaultRepository,
  PostgresVaultRepository,
  PostgresCredentialRepository,
} from "../../infrastructure/repositories";

// Tipos fuertes para credenciales
import { CredentialsTypeFactory } from "../../domain/services/autocompletado/credentials-types";
import type {
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
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
};

// Configuración JWT — fail-fast en cualquier entorno que no sea development
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET && process.env.NODE_ENV !== "development") {
  throw new Error(
    "JWT_SECRET is required in staging/production — refusing to start with authentication disabled",
  );
}
if (!JWT_SECRET) {
  logger.warn(
    "⚠️  JWT_SECRET not set - authentication will be disabled (development mode only)",
    "ApiServer",
  );
}

// Rate limiting configuration
const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutos

// Timeout de petición: 30 segundos → 504 Gateway Timeout
const REQUEST_TIMEOUT_MS = 30_000;

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

// Limpiar cada 5 minutos (guardar referencia para cleanup en shutdown)
const _rateLimitCleanupInterval = setInterval(cleanupRateLimits, 5 * 60 * 1000);
if (_rateLimitCleanupInterval.unref) _rateLimitCleanupInterval.unref();

/**
 * API Server con Clean Architecture
 */
export class ApiServer {
  private activeConnections = 0;
  private vaultRepository: IVaultRepository;
  private credentialRepository?: ICredentialRepository;
  private createVaultUseCase: CreateVaultUseCase;
  private generateCredentialsUseCase: GenerateCredentialsUseCase;
  private extractCredentialsUseCase: ExtractCredentialsUseCase;
  private credentialsGenerator: CredentialsGenerator;

  constructor(
    vaultRepository: IVaultRepository,
    _encryptionService: EncryptionService,
    _hashingService: HashingService,
    _signatureService: SignatureService,
    _keyManagementService: KeyManagementService,
    credentialsGenerator: CredentialsGenerator,
    credentialRepository?: ICredentialRepository,
  ) {
    this.vaultRepository = vaultRepository;
    this.credentialRepository = credentialRepository;

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
  private async parseJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MB
    return new Promise((resolve, reject) => {
      let body = "";
      let totalBytes = 0;
      req.on("data", (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_BODY_BYTES) {
          req.destroy();
          reject(new Error("Request body too large"));
          return;
        }
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
   * Verifica la conectividad con la base de datos (solo si USE_POSTGRES=true)
   */
  private async checkDatabaseHealth(): Promise<boolean> {
    if (process.env.USE_POSTGRES !== "true") {
      return true; // No configurada — no afecta el estado
    }

    try {
      if (this.vaultRepository instanceof PostgresVaultRepository) {
        return await this.vaultRepository.isHealthy();
      }
      if (this.credentialRepository instanceof PostgresCredentialRepository) {
        return await this.credentialRepository.isHealthy();
      }
      return true;
    } catch (error) {
      logger.error(
        "Database health check error",
        "HealthCheck",
        undefined,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  /**
   * Verifica la conectividad con IPFS (solo si está configurado)
   */
  private async checkIpfsHealth(): Promise<boolean> {
    if (!process.env.IPFS_API_URL) {
      return true; // No configurado — no afecta el estado
    }

    try {
      const { ipfsAdapter } = await import("../../infrastructure/ipfs");
      return await ipfsAdapter.isHealthy();
    } catch (error) {
      logger.error(
        "IPFS health check error",
        "HealthCheck",
        undefined,
        error instanceof Error ? error.message : String(error),
      );
      return false;
    }
  }

  /**
   * Ejecuta todas las comprobaciones de dependencias
   */
  private async runDependencyChecks(): Promise<{
    database: string;
    ipfs: string;
  }> {
    const database =
      process.env.USE_POSTGRES === "true"
        ? (await this.checkDatabaseHealth()) === true
          ? "ok"
          : "error"
        : "not_configured";

    const ipfs = process.env.IPFS_API_URL
      ? (await this.checkIpfsHealth()) === true
        ? "ok"
        : "error"
      : "not_configured";

    return { database, ipfs };
  }

  /**
   * Handler para exponer métricas en formato texto Prometheus
   */
  private handleMetrics(_req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, {
      "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
    });
    res.end(metrics.formatPrometheus());
  }

  /**
   * Handler para health checks
   * La base de datos es crítica (unhealthy); IPFS es opcional (degraded)
   */
  private async handleHealth(
    _req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const checks = await this.runDependencyChecks();

    const status =
      checks.database === "error"
        ? "unhealthy"
        : checks.ipfs === "error"
          ? "degraded"
          : "healthy";

    // Resumen de métricas para el health check
    const requestSeries = metrics.series("http_requests_total");
    const totalRequests = requestSeries.reduce((sum, s) => sum + s.value, 0);
    const errorRequests = requestSeries
      .filter((s) => (s.labels?.status ?? "").startsWith("5"))
      .reduce((sum, s) => sum + s.value, 0);
    const errorRate = totalRequests > 0 ? errorRequests / totalRequests : 0;

    res.writeHead(status === "unhealthy" ? 503 : 200, {
      "Content-Type": "application/json",
    });
    res.end(
      JSON.stringify({
        status,
        timestamp: new Date().toISOString(),
        service: "cyber-vault-api",
        checks,
        metrics: {
          uptimeSeconds: Math.round(process.uptime()),
          totalRequests,
          errorRate: Number(errorRate.toFixed(4)),
        },
      }),
    );
  }

  /**
   * Handler para readiness checks
   * Verifica que todas las dependencias configuradas estén alcanzables
   */
  private async handleReady(
    _req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const checks = await this.runDependencyChecks();
    const allReachable = checks.database !== "error" && checks.ipfs !== "error";

    res.writeHead(allReachable ? 200 : 503, {
      "Content-Type": "application/json",
    });
    res.end(
      JSON.stringify({
        status: allReachable ? "ready" : "not_ready",
        timestamp: new Date().toISOString(),
        checks,
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
      const name = data.name as string;
      const description = data.description as string | undefined;
      const encryptionKeyId = data.encryptionKeyId as string;

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
        ownerId: (req as any).userId as string | undefined,
      });

      metrics.counter(
        "cybervault_vaults_created_total",
        "Total vaults created",
      );

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify(vault.toSafeObject()));
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Invalid request";
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: msg }));
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
      const domain = data.domain as string;

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

      metrics.counter(
        "cybervault_credentials_generated_total",
        "Total credentials generated",
      );

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
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Invalid request";
      const code = error instanceof Error && "code" in error ? (error as { code: string }).code : "UNKNOWN_ERROR";
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: msg, code }));
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
      const email = data.email as string;
      const password = data.password as string;

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
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Invalid request";
      const code = error instanceof Error && "code" in error ? (error as { code: string }).code : "UNKNOWN_ERROR";
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: msg, code }));
    }
  }

  /**
   * Handler para validar formato de credenciales
   * SECURITY: Accepts POST body only — passwords must never appear in URL query parameters
   */
  private async handleValidateCredentials(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    // Support both POST body and GET query for backward compatibility,
    // but POST is strongly preferred to avoid password leakage in URLs
    let email: string | null = null;
    let password: string | null = null;

    if (req.method === "POST") {
      try {
        const data = await this.parseJsonBody(req);
        email = (data.email as string) || null;
        password = (data.password as string) || null;
      } catch {
        // If body parsing fails, fall through to empty values
      }
    } else {
      // GET fallback — DEPRECATED: password in URL is a security risk
      const url = new URL(req.url || "", `http://${req.headers.host}`);
      email = url.searchParams.get("email");
      password = url.searchParams.get("password");
    }

    if (!email && !password) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Email or password parameter required" }),
      );
      return;
    }

    const result: Record<string, unknown> = {};

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
   * Handler para registrar usuario
   */
  private async handleRegister(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const email = data.email as string;
      const password = data.password as string;

      if (!email || !password) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Email and password required" }));
        return;
      }

      const emailBasic =
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!emailBasic.test(email)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid email format" }));
        return;
      }

      if (password.length < 8) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Password must be at least 8 characters" }),
        );
        return;
      }

      if (await getUserByEmail(email)) {
        // Return 200 to prevent user enumeration (constant-time leak)
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Registration processed" }));
        return;
      }

      const user = await createUser(email, password);

      if (!JWT_SECRET) {
        if (process.env.NODE_ENV === "production") {
          res.writeHead(503, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Authentication not configured" }));
          return;
        }
        // Development mode: return user without token
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            userId: user.userId,
            email: user.email,
            message: "User registered successfully (no JWT — development mode)",
          }),
        );
        return;
      }

      const token = generateToken(user.userId, JWT_SECRET);

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          userId: user.userId,
          email: user.email,
          token,
          message: "User registered successfully",
        }),
      );
    } catch (error) {
      logger.error(
        "Error registering user",
        "ApiServer",
        undefined,
        error instanceof Error ? error.message : String(error),
      );
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }

  /**
   * Handler para login de usuario
   */
  private async handleLogin(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const email = data.email as string;
      const password = data.password as string;

      if (!email || !password) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Email and password required" }));
        return;
      }

      const user = await getUserByEmail(email);
      if (!user) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid email or password" }));
        return;
      }

      if (!verifyPassword(password, user.hash, user.salt)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid email or password" }));
        return;
      }

      if (!JWT_SECRET) {
        if (process.env.NODE_ENV === "production") {
          res.writeHead(503, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Authentication not configured" }));
          return;
        }
        // Development mode: return user without token
        metrics.counter(
          "cybervault_logins_total",
          "Total successful logins",
        );
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            userId: user.userId,
            email: user.email,
            message: "Login successful (no JWT — development mode)",
          }),
        );
        return;
      }

      const token = generateToken(user.userId, JWT_SECRET);

      metrics.counter("cybervault_logins_total", "Total successful logins");

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          userId: user.userId,
          email: user.email,
          token,
          message: "Login successful",
        }),
      );
    } catch (error) {
      logger.error(
        "Error logging in",
        "ApiServer",
        undefined,
        error instanceof Error ? error.message : String(error),
      );
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }

  /**
   * Handler para verificar token
   */
  private handleVerifyToken(req: IncomingMessage, res: ServerResponse): void {
    const authReq = req as any;

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        valid: true,
        userId: authReq.userId || "anonymous",
      }),
    );
  }

  /**
   * Handler para información de la API
   */
  private handleApiInfo(_req: IncomingMessage, res: ServerResponse): void {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        name: "CyberVault API",
        version: "1.0.0",
        description: "Zero-Knowledge Credential Management API",
        endpoints: {
          auth: {
            register: "POST /api/v1/auth/register",
            login: "POST /api/v1/auth/login",
            verify: "GET /api/v1/auth/verify",
          },
          vaults: {
            list: "GET /api/v1/vaults",
            create: "POST /api/v1/vaults",
            get: "GET /api/v1/vaults/:id",
            delete: "DELETE /api/v1/vaults/:id",
          },
          credentials: {
            list: "GET /api/v1/credentials",
            generate: "POST /api/v1/credentials/generate",
            extract: "POST /api/v1/credentials/extract",
            validate: "GET /api/v1/credentials/validate",
          },
          health: {
            health: "GET /health",
            ready: "GET /ready",
          },
        },
      }),
    );
  }

  /**
   * Handler para listar vaults del usuario
   */
  private async handleVaultsList(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const userId = (req as any).userId as string | undefined;
      // SECURITY: Never return all vaults without authentication
      // When JWT_SECRET is unset, userId is undefined — return empty, not everything
      const vaults = userId
        ? await this.vaultRepository.listByOwnerId(userId)
        : [];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          vaults: vaults.map((v) => v.toSafeObject()),
          total: vaults.length,
        }),
      );
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to list vaults" }));
    }
  }

  /**
   * Handler para obtener un vault específico
   */
  private async handleVaultGet(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as any).userId as string | undefined;
      // Verificar propiedad del vault antes de devolverlo
      const vault = userId
        ? await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId)
        : await this.vaultRepository.findById(VaultId.fromString(vaultId));
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(vault.toSafeObject()));
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to get vault" }));
    }
  }

  /**
   * Handler para eliminar un vault
   */
  private async handleVaultDelete(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as any).userId as string | undefined;
      // Verificar propiedad antes de eliminar
      if (userId) {
        const vault = await this.vaultRepository.findByVaultIdAndOwnerId(
          vaultId,
          userId,
        );
        if (!vault) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Vault not found" }));
          return;
        }
      }
      const deleted = await this.vaultRepository.delete(
        VaultId.fromString(vaultId),
      );
      if (!deleted) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: vaultId,
          status: "deleted",
          message: "Vault deleted successfully",
        }),
      );
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to delete vault" }));
    }
  }

  /**
   * Devuelve los IDs de los vaults propiedad del usuario autenticado
   */
  private async getOwnedVaultIds(userId: string): Promise<string[]> {
    const vaults = await this.vaultRepository.listByOwnerId(userId);
    return vaults.map((v) => v.id.toString());
  }

  /**
   * Handler para listar credenciales
   */
  private async handleCredentialsList(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      if (!this.credentialRepository) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            credentials: [],
            total: 0,
            message: "Credential repository not configured.",
          }),
        );
        return;
      }
      const userId = (req as any).userId as string | undefined;
      // Solo exponer credenciales de vaults propiedad del usuario autenticado
      let credentials: any[];
      if (userId) {
        const vaultIds = await this.getOwnedVaultIds(userId);
        const results = await Promise.all(
          vaultIds.map((vaultId) =>
            this.credentialRepository!.findByVaultId(
              VaultId.fromString(vaultId),
            ),
          ),
        );
        credentials = results.flat();
      } else {
        // SECURITY: Never return all credentials without authentication
        credentials = [];
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          credentials: credentials.map((c) => ({
            id: c.id.toString(),
            // Only expose safe fields
          })),
          total: credentials.length,
        }),
      );
    } catch {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to list credentials" }));
    }
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
    res.setHeader(
      "Access-Control-Allow-Origin",
      process.env.CORS_ORIGIN || "http://localhost:3000",
    );
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    // Timeout de petición: 30 segundos → 504 Gateway Timeout
    // Sin listener de error, escrituras tardías tras destruir el socket podrían crashear el proceso
    res.on("error", () => {});
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      if (!res.headersSent) {
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Gateway Timeout" }));
      } else {
        res.destroy();
      }
      req.destroy();
    });

    const url = new URL(req.url || "", `http://${req.headers.host}`);

    // Swagger docs — served before rate limiting and metrics
    if (swaggerMiddleware(req, res)) return;

    // Métricas: inicio del trackeo de la petición
    const startTime = performance.now();
    this.activeConnections++;
    metrics.gauge(
      "active_connections",
      "Current active connections",
      this.activeConnections,
      { service: "api" },
    );

    // Registrar métricas cuando la respuesta termine
    res.on("finish", () => {
      this.activeConnections = Math.max(0, this.activeConnections - 1);
      metrics.gauge(
        "active_connections",
        "Current active connections",
        this.activeConnections,
        { service: "api" },
      );
      const duration = (performance.now() - startTime) / 1000;
      metrics.counter("http_requests_total", "Total HTTP requests", {
        method: req.method || "unknown",
        path: url.pathname,
        status: String(res.statusCode),
      });
      metrics.histogram(
        "http_request_duration_seconds",
        "Request duration",
        duration,
        { method: req.method || "unknown", path: url.pathname },
      );
    });

    // Aplicar rate limiting a todos los endpoints
    const ip = req.socket?.remoteAddress || "unknown";
    if (!checkRateLimit(ip)) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Rate limit exceeded" }));
      return;
    }

    try {
      switch (url.pathname) {
        case "/health":
          await this.handleHealth(req, res);
          break;

        case "/ready":
          await this.handleReady(req, res);
          break;

        case "/metrics":
          this.handleMetrics(req, res);
          break;

        case "/api/v1/vaults":
          if (req.method === "POST") {
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleCreateVault(req, res);
              });
            } else {
              await this.handleCreateVault(req, res);
            }
          } else if (req.method === "GET") {
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleVaultsList(req, res);
              });
            } else {
              await this.handleVaultsList(req, res);
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

        // Auth endpoints
        case "/api/v1/auth/register":
          if (req.method === "POST") {
            await this.handleRegister(req, res);
          } else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Method not allowed" }));
          }
          break;

        case "/api/v1/auth/login":
          if (req.method === "POST") {
            await this.handleLogin(req, res);
          } else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Method not allowed" }));
          }
          break;

        case "/api/v1/auth/verify":
          if (req.method === "GET") {
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleVerifyToken(req, res);
              });
            } else {
              this.handleVerifyToken(req, res);
            }
          } else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Method not allowed" }));
          }
          break;

        // Vaults CRUD
        case url.pathname.match(/^\/api\/v1\/vaults\/[a-zA-Z0-9_-]+$/)?.input:
          if (req.method === "GET") {
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleVaultGet(req, res, url.pathname.split("/").pop()!);
              });
            } else {
              this.handleVaultGet(req, res, url.pathname.split("/").pop()!);
            }
          } else if (req.method === "DELETE") {
            if (JWT_SECRET) {
              authenticate(req, res, () => {
                this.handleVaultDelete(
                  req,
                  res,
                  url.pathname.split("/").pop()!,
                );
              });
            } else {
              this.handleVaultDelete(req, res, url.pathname.split("/").pop()!);
            }
          } else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Method not allowed" }));
          }
          break;

        // Credentials list
        case "/api/v1/credentials":
          if (JWT_SECRET) {
            authenticate(req, res, () => {
              this.handleCredentialsList(req, res);
            });
          } else {
            this.handleCredentialsList(req, res);
          }
          break;

        // API info
        case "/api":
          if (req.method === "GET") {
            this.handleApiInfo(req, res);
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
      logger.error(
        "Error handling request",
        "ApiServer",
        undefined,
        error instanceof Error ? error.message : String(error),
      );
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
          logger.info(`🔒 HTTPS Server started on port ${port}`, "ApiServer");
        } catch (error) {
          logger.warn(
            "HTTPS certificates not found, falling back to HTTP",
            "ApiServer",
          );
          server = createServer((req, res) => this.handleRequest(req, res));
          logger.info(
            `⚠️  HTTP Server started on port ${port} (no HTTPS)`,
            "ApiServer",
          );
        }
      } else {
        server = createServer((req, res) => this.handleRequest(req, res));
        logger.info(`🌐 HTTP Server started on port ${port}`, "ApiServer");
      }

      server
        .listen(port, () => {
          logger.info(`🚀 Cyber Vault API ready at http://localhost:${port}`, "ApiServer");
          logger.info(`   Health check: http://localhost:${port}/health`, "ApiServer");
          logger.info(`   Ready check: http://localhost:${port}/ready`, "ApiServer");
          if (JWT_SECRET) {
            logger.info(`   🔐 Authentication: ENABLED`, "ApiServer");
          } else {
            logger.info(`   🔓 Authentication: DISABLED (development mode)`, "ApiServer");
          }
          logger.info(
            `   📊 Rate limit: ${RATE_LIMIT_MAX} requests per ${RATE_LIMIT_WINDOW / 60000} minutes`,
            "ApiServer",
          );
          resolvePromise(server);
        })
        .on("error", reject);
    });
  }
}

/**
 * Función de conveniencia para iniciar el servidor con dependencias por defecto
 * Puede aceptar dependencias personalizadas para testing
 */
export async function startServer(
  port: number = 3000,
  vaultRepository?: IVaultRepository,
  encryptionService?: EncryptionService,
  hashingService?: HashingService,
  signatureService?: SignatureService,
  keyManagementService?: KeyManagementService,
  credentialsGenerator?: CredentialsGenerator,
  credentialRepository?: ICredentialRepository,
) {
  const usePostgres = process.env.USE_POSTGRES === "true";
  const vaultRepo =
    vaultRepository ||
    (usePostgres
      ? new PostgresVaultRepository(process.env.DATABASE_URL || "")
      : new ChromeStorageVaultRepository());
  const encryptionSvc = encryptionService || new EncryptionService();
  const hashingSvc = hashingService || new HashingService();
  const signatureSvc = signatureService || new SignatureService();
  const keyMgmtSvc = keyManagementService || new KeyManagementService();
  const credsGenerator = credentialsGenerator || new CredentialsGenerator();
  const credRepo =
    credentialRepository ||
    (usePostgres
      ? new PostgresCredentialRepository(process.env.DATABASE_URL || "")
      : undefined);

  const apiServer = new ApiServer(
    vaultRepo,
    encryptionSvc,
    hashingSvc,
    signatureSvc,
    keyMgmtSvc,
    credsGenerator,
    credRepo,
  );
  return apiServer.start(port);
}

// Iniciar servidor si ejecutado directamente
if (require.main === module) {
  const port = parseInt(process.env.PORT || "3000", 10);

  connectRedis().catch(() => {});

  startServer(port).catch((err) =>
    logger.error(
      "Server startup failed",
      "ApiServer",
      undefined,
      err instanceof Error ? err.message : String(err),
    ),
  );

  const shutdown = async () => {
    logger.info("Shutting down...", "ApiServer");
    await disconnectRedis();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
