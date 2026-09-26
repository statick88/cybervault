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
  generateRefreshToken,
  verifyToken,
  getUserByEmail,
  createUser,
  verifyPassword,
  type AuthenticatedRequest,
} from "./auth";

import { swaggerMiddleware } from "./swagger";
import { connectRedis, disconnectRedis } from "../redis";
import { logger } from "../../shared/logger";
import { metrics } from "../../shared/metrics";
import { applyCorsHeaders } from "./middleware/cors";
import { applySecurityHeaders } from "./middleware/security-headers";
import {
  checkRateLimit,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW,
  _clearRateLimitForTests,
} from "./middleware/rate-limiter";
import { loginRateLimiter } from "./login-rate-limiter";
export { _clearRateLimitForTests };

// Use Cases
import { CreateVaultUseCase } from "../../application/use-cases/create-vault.use-case";
import { GenerateCredentialsUseCase } from "../../application/use-cases/generate-credentials.use-case";
import { ExtractCredentialsUseCase } from "../../application/use-cases/extract-credentials.use-case";

// Repositorios
import {
  ChromeStorageVaultRepository,
  PostgresVaultRepository,
  PostgresCredentialRepository,
  InMemoryReleaseShareStore,
} from "../../infrastructure/repositories";
import { loadReleaseShareKekSecret } from "../../infrastructure/crypto/release-share-kek";
import { secureZero } from "../../infrastructure/crypto/secure-memory";
import { base64ToBinary } from "../../shared/utils";
import { Credential } from "../../domain/entities/credential";
import type { ManagedAuthoringRejection } from "../../application/use-cases/managed-authoring.use-case";

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

// Timeout de petición: 30 segundos → 504 Gateway Timeout
const REQUEST_TIMEOUT_MS = 30_000;

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
  /** Wrapped Release Shares for managed credentials (dumb store, no key material). */
  private releaseShareStore: InMemoryReleaseShareStore;
  /** Base64 32-byte secret behind the Release Share KEK. Null => release refuses. */
  private releaseShareKekSecret: Uint8Array | null;

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

    this.releaseShareStore = new InMemoryReleaseShareStore();
    this.releaseShareKekSecret = loadReleaseShareKekSecret(
      process.env.RELEASE_SHARE_KEK_SECRET,
    );
    if (!this.releaseShareKekSecret) {
      // Fail closed at request time, not at boot: the process must still start.
      logger.warn(
        "RELEASE_SHARE_KEK_SECRET missing or not 32-byte base64 - managed release will refuse every request",
        "ApiServer",
      );
    }

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

    // Validate Content-Type header
    const contentType = req.headers["content-type"] || "";
    if (!contentType.includes("application/json")) {
      throw new Error("Invalid Content-Type: expected application/json");
    }

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
    const [database, ipfs] = await Promise.all([
      this.evaluateHealthCheck(
        process.env.USE_POSTGRES === "true",
        this.checkDatabaseHealth,
      ),
      this.evaluateHealthCheck(
        !!process.env.IPFS_API_URL,
        this.checkIpfsHealth,
      ),
    ]);

    return { database, ipfs };
  }

  private evaluateHealthCheck(enabled: boolean, checkFn: () => Promise<boolean>): Promise<string> {
    if (!enabled) return Promise.resolve("not_configured");
    return checkFn().then((result) => (result === true ? "ok" : "error"));
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

  // Response helper methods to reduce cognitive complexity in handlers
  private sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
    res.writeHead(statusCode, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  }

  private sendError(res: ServerResponse, statusCode: number, error: string): void {
    this.sendJson(res, statusCode, { error });
  }

  private sendSuccess(res: ServerResponse, statusCode: number, data: Record<string, unknown>): void {
    this.sendJson(res, statusCode, data);
  }

  private handleJsonError(res: ServerResponse, error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes("Invalid Content-Type")) {
      this.sendError(res, 400, "Invalid Content-Type: expected application/json");
      return;
    }
    if (message.includes("is not valid JSON") || message.includes("Unexpected token")) {
      this.sendError(res, 400, "Invalid JSON in request body");
      return;
    }

    logger.error("Request error", "ApiServer", undefined, message);
    this.sendError(res, 500, "Internal server error");
  }

  private validateRegistrationInput(email: string, password: string): string | null {
    if (!email || !password) return "Email and password required";

    const emailRegex =
      /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!emailRegex.test(email)) return "Invalid email format";

    if (password.length < 8) return "Password must be at least 8 characters";

    return null;
  }

  private async createUserResponse(
    res: ServerResponse,
    user: { userId: string; email: string },
  ): Promise<void> {
    if (!JWT_SECRET) {
      if (process.env.NODE_ENV === "production") {
        this.sendError(res, 503, "Authentication not configured");
        return;
      }
      this.sendSuccess(res, 201, {
        userId: user.userId,
        email: user.email,
        message: "User registered successfully (no JWT — development mode)",
      });
      return;
    }

    const token = generateToken(user.userId, JWT_SECRET);
    const refreshToken = generateRefreshToken(user.userId, JWT_SECRET);

    this.sendSuccess(res, 201, {
      userId: user.userId,
      email: user.email,
      token,
      refreshToken,
      message: "User registered successfully",
    });
  }

  // Request routing helpers to reduce cognitive complexity in handleRequest
  private setupRequestTracking(req: IncomingMessage, res: ServerResponse): { startTime: number; url: URL } {
    const startTime = performance.now();
    this.activeConnections++;
    metrics.gauge("active_connections", "Current active connections", this.activeConnections, { service: "api" });

    res.on("finish", () => {
      this.activeConnections = Math.max(0, this.activeConnections - 1);
      metrics.gauge("active_connections", "Current active connections", this.activeConnections, { service: "api" });
      const duration = (performance.now() - startTime) / 1000;
      metrics.counter("http_requests_total", "Total HTTP requests", {
        method: req.method || "unknown",
        path: url.pathname,
        status: String(res.statusCode),
      });
      metrics.histogram("http_request_duration_seconds", "Request duration", duration, {
        method: req.method || "unknown",
        path: url.pathname,
      });
    });

    const url = new URL(req.url || "", `http://${req.headers.host}`);
    return { startTime, url };
  }

  private checkRateLimitOrError(res: ServerResponse, ip: string): boolean {
    if (!checkRateLimit(ip)) {
      this.sendError(res, 429, "Rate limit exceeded");
      return false;
    }
    return true;
  }

  private async handleAuthRoute(req: IncomingMessage, res: ServerResponse, handler: () => Promise<void>): Promise<void> {
    if (JWT_SECRET) {
      authenticate(req, res, handler);
    } else {
      await handler();
    }
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

    const status = this.computeHealthStatus(checks);

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

  private computeHealthStatus(checks: { database: string; ipfs: string }): string {
    if (checks.database === "error") return "unhealthy";
    if (checks.ipfs === "error") return "degraded";
    return "healthy";
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
        ownerId: (req as AuthenticatedRequest).userId,
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
    let email: string | null = null;
    let password: string | null = null;

    try {
      const data = await this.parseJsonBody(req);
      email = (data.email as string) || null;
      password = (data.password as string) || null;
    } catch {
      // If body parsing fails, fall through to empty values
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

      const validationError = this.validateRegistrationInput(email, password);
      if (validationError) {
        this.sendError(res, 400, validationError);
        return;
      }

      if (await getUserByEmail(email)) {
        // Return 200 to prevent user enumeration (constant-time leak)
        this.sendSuccess(res, 200, { message: "Registration processed" });
        return;
      }

      const user = await createUser(email, password);
      await this.createUserResponse(res, user);
    } catch (error) {
      this.handleJsonError(res, error);
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
        this.sendError(res, 400, "Email and password required");
        return;
      }

      // Brute-force protection: check if email is locked out
      const lockout = loginRateLimiter.isLocked(email);
      if (lockout.locked) {
        this.sendJson(res, 429, {
          error: "Too many failed attempts. Try again later.",
          retryAfter: Math.ceil((lockout.retryAfterMs ?? 60_000) / 1000),
        });
        return;
      }

      const user = await getUserByEmail(email);
      if (!user) {
        loginRateLimiter.recordFailure(email);
        this.sendError(res, 401, "Invalid email or password");
        return;
      }

      if (!verifyPassword(password, user.hash, user.salt)) {
        loginRateLimiter.recordFailure(email);
        this.sendError(res, 401, "Invalid email or password");
        return;
      }

      // Successful login — clear any failed attempts
      loginRateLimiter.recordSuccess(email);

      if (!JWT_SECRET) {
        if (process.env.NODE_ENV === "production") {
          this.sendError(res, 503, "Authentication not configured");
          return;
        }
        // Development mode: return user without token
        metrics.counter("cybervault_logins_total", "Total successful logins");
        this.sendSuccess(res, 200, {
          userId: user.userId,
          email: user.email,
          message: "Login successful (no JWT — development mode)",
        });
        return;
      }

      const token = generateToken(user.userId, JWT_SECRET);
      const refreshToken = generateRefreshToken(user.userId, JWT_SECRET);

      metrics.counter("cybervault_logins_total", "Total successful logins");

      this.sendSuccess(res, 200, {
        userId: user.userId,
        email: user.email,
        token,
        refreshToken,
        message: "Login successful",
      });
    } catch (error) {
      this.handleJsonError(res, error);
    }
  }

  /**
   * Handler para refresh token — intercambia un refresh token válido por un nuevo access token
   */
  private async handleRefreshToken(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    try {
      const data = await this.parseJsonBody(req);
      const refreshToken = data.refreshToken as string;

      if (!refreshToken) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "refreshToken is required" }));
        return;
      }

      if (!JWT_SECRET) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication not configured" }));
        return;
      }

      const decoded = verifyToken(refreshToken, JWT_SECRET);
      if (!decoded || decoded.type !== "refresh") {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid or expired refresh token" }));
        return;
      }

      // Issue new access token + rotate refresh token
      const newAccessToken = generateToken(decoded.userId, JWT_SECRET);
      const newRefreshToken = generateRefreshToken(decoded.userId, JWT_SECRET);

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          token: newAccessToken,
          refreshToken: newRefreshToken,
          message: "Tokens refreshed successfully",
        }),
      );
    } catch (error) {
      logger.error(
        "Error refreshing token",
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
  private async handleVerifyToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const authReq = req as AuthenticatedRequest;

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
  private async handleApiInfo(_req: IncomingMessage, res: ServerResponse): Promise<void> {
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
            validate: "POST /api/v1/credentials/validate",
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
      const userId = (req as AuthenticatedRequest).userId;
      // SECURITY: Never return all vaults without authentication
      // When JWT_SECRET is unset, userId is undefined — return empty, not everything
      const vaults = userId
        ? await this.vaultRepository.listByOwnerId(userId)
        : [];
      const body = JSON.stringify({
        vaults: vaults.map((v) => v.toSafeObject()),
        total: vaults.length,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to list vaults" }));
      }
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
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication required" }));
        return;
      }
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId);
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      const body = JSON.stringify(vault.toSafeObject());
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to get vault" }));
      }
    }
  }

  /**
   * Handler para obtener encryptedData de un vault (para descifrado client-side)
   * NOTA: El passphrase NUNCA se envía al backend. El descifrado es local.
   */
  private async handleVaultUnlock(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication required" }));
        return;
      }
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId);
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      // Return encrypted data — client will decrypt with passphrase locally
      const body = JSON.stringify({
        vaultId: vault.id.toString(),
        name: vault.name,
        encryptedData: vault.encryptedData,
        encryptionKeyId: vault.encryptionKeyId,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to unlock vault" }));
      }
    }
  }

  /**
   * Handler para managed release (Core↔Plus bridge)
   * Verifies capability token from Plus and returns ReleaseShare for managed credential
   */
  private async handleVaultManagedRelease(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication required" }));
        return;
      }

      // Verify vault ownership
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId);
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }

      // Parse capability token from request body
      const data = await this.parseJsonBody(req);
      const capabilityToken = data.capabilityToken as {
        payload: any;
        signature: string;
        protectedHeader: string;
      };
      const plusPublicKey = data.plusPublicKey as string;

      if (!capabilityToken || !capabilityToken.payload || !capabilityToken.signature || !plusPublicKey) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "capabilityToken and plusPublicKey required" }));
        return;
      }

      // Use the managed release use case
      // Note: In production, this would be injected via constructor
      const { ManagedReleaseUseCase } = await import("../../application/use-cases/managed-release.use-case");
      const useCase = new ManagedReleaseUseCase(
        this.credentialRepository!,
        /* jtiStore: undefined => global store */ undefined,
        this.releaseShareStore,
        this.releaseShareKekSecret,
      );

      const result = await useCase.execute({
        capabilityToken,
        plusPublicKey,
      });

      if (!result.success) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: result.error }));
        return;
      }

      const body = JSON.stringify({
        success: true,
        releaseShare: result.releaseShare,
        credentialId: result.credentialId,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    } catch (error) {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to process managed release" }));
      }
    }
  }

  /**
   * Handler for managed credential authoring (ODD "Option C").
   *
   * Mirrors `handleVaultManagedRelease`: same auth/ownership checks, same
   * shape, same store and the same Release Share KEK secret, so a share
   * written here resolves there for the same `secretRef`.
   *
   * SECURITY — the domain index (`domain/services/autofill/domain-index.ts`)
   * exists so the backend never learns which origins a user has credentials
   * for: that list is a map of their infrastructure. The use case returns
   * `record.origin` for ExactMatch binding, and this handler persists the
   * credential WITHOUT `url`/origin — the origin leaves Core only in this
   * response. `Credential.username` receives the redacted hint, never the
   * plaintext username.
   *
   * The session VEK comes from the caller: Core has no VEK of its own (vault
   * unlock returns ciphertext only), so a missing `vek` fails closed with the
   * use case's `VEK_MISSING` — this handler never generates or derives one.
   */
  private async handleVaultManagedCredential(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication required" }));
        return;
      }

      // Verify vault ownership
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId);
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }

      // Refuse BEFORE authoring: without a repository the wrapped share would
      // be written and the credential row would not exist.
      if (!this.credentialRepository) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Credential repository not configured" }));
        return;
      }

      // Parse authoring input from the request body
      const data = await this.parseJsonBody(req);

      // The session VEK is supplied by the only party that holds it. Decode
      // it here; an undecodable value is a malformed body, and an absent one
      // is left null so the use case refuses with VEK_MISSING.
      let vek: Uint8Array | null = null;
      if (typeof data.vek === "string" && data.vek.trim() !== "") {
        try {
          vek = base64ToBinary(data.vek.trim());
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "vek must be base64-encoded" }));
          return;
        }
        if (vek.byteLength === 0) vek = null;
      }

      try {
        // Same store instance and same KEK secret as the release route.
        const { ManagedAuthoringUseCase } = await import(
          "../../application/use-cases/managed-authoring.use-case"
        );
        const useCase = new ManagedAuthoringUseCase(
          this.releaseShareStore,
          this.releaseShareKekSecret,
        );

        const result = await useCase.execute({
          origin: typeof data.origin === "string" ? data.origin : "",
          username: typeof data.username === "string" ? data.username : "",
          password: typeof data.password === "string" ? data.password : "",
          title: typeof data.title === "string" ? data.title : "",
          totpSeedBase32:
            typeof data.totpSeedBase32 === "string" ? data.totpSeedBase32 : undefined,
          secretRef: typeof data.secretRef === "string" ? data.secretRef : "",
          vek,
        });

        if (!result.ok) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: this.managedAuthoringError(result.reason, result.detail),
              reason: result.reason,
              detail: result.detail,
            }),
          );
          return;
        }

        // SECURITY: build the row from the record and drop the origin —
        // no `url`, no `origin` field exists on the entity at all. Username
        // is the redacted hint; the plaintext lives only inside ciphertext.
        const credential = Credential.fromPlainObject({
          id: result.record.id,
          vaultId,
          title: result.record.title,
          username: result.record.usernameHint,
          encryptedPassword: result.record.encryptedSecret,
          mode: "managed",
          salt: result.record.salt,
          version: result.record.version,
          releaseShareRef: result.record.releaseShareRef as string,
          tags: [],
          favorite: false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });

        const persisted = await this.credentialRepository.save(credential);

        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            success: true,
            credentialId: persisted.id.toString(),
            // The canonical origin travels ONLY here, so the client can bind
            // ExactMatch; it is never written to the credential row.
            record: result.record,
            lookupToken: result.lookupToken,
            index: result.index,
          }),
        );
      } finally {
        // The caller (this request) owns the decoded VEK copy.
        if (vek) secureZero(vek);
      }
    } catch (error) {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to process managed authoring" }));
      }
    }
  }

  /**
   * Refusal message for managed authoring. A missing Release Share KEK names
   * the environment variable that is actually missing, so the operator sees
   * the real blocker instead of a generic failure.
   */
  private managedAuthoringError(reason: ManagedAuthoringRejection, detail: string): string {
    if (reason === "RELEASE_SHARE_KEK_INVALID") {
      return `${detail} — RELEASE_SHARE_KEK_SECRET (base64 of 32 random bytes) must be configured`;
    }
    return detail;
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
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Authentication required" }));
        return;
      }
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(
        vaultId,
        userId,
      );
      if (!vault) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      const deleted = await this.vaultRepository.delete(
        VaultId.fromString(vaultId),
      );
      if (!deleted) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Vault not found" }));
        return;
      }
      const body = JSON.stringify({
        id: vaultId,
        status: "deleted",
        message: "Vault deleted successfully",
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to delete vault" }));
      }
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
      const userId = (req as AuthenticatedRequest).userId;
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
    applySecurityHeaders(res);
    applyCorsHeaders(res);

    // Timeout de petición: 30 segundos → 504 Gateway Timeout
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

    // Swagger docs — served before rate limiting and metrics
    if (swaggerMiddleware(req, res)) return;

    // Setup request tracking and get URL
    const { url } = this.setupRequestTracking(req, res);

    // Aplicar rate limiting a todos los endpoints
    const ip = req.socket?.remoteAddress || "unknown";
    if (!this.checkRateLimitOrError(res, ip)) return;

    try {
      await this.routeRequest(req, res, url);
    } catch (error) {
      this.handleJsonError(res, error);
    }
  }

  private async routeRequest(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
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
        await this.routeVaults(req, res);
        break;

      case "/api/v1/credentials/generate":
        await this.routeGenerateCredentials(req, res);
        break;

      case "/api/v1/credentials/extract":
        await this.routeExtractCredentials(req, res);
        break;

      case "/api/v1/credentials/validate":
        await this.routeValidateCredentials(req, res);
        break;

      case "/api/v1/auth/register":
        await this.handleRegister(req, res);
        break;

      case "/api/v1/auth/login":
        await this.handleLogin(req, res);
        break;

      case "/api/v1/auth/refresh":
        await this.handleRefreshToken(req, res);
        break;

      case "/api/v1/auth/verify":
        await this.routeVerifyToken(req, res);
        break;

      // Vaults CRUD
      case url.pathname.match(/^\/api\/v1\/vaults\/[a-zA-Z0-9_-]+$/)?.input:
        await this.routeVaultItem(req, res, url);
        break;

      // Vault unlock
      case url.pathname.match(/^\/api\/v1\/vaults\/[a-zA-Z0-9_-]+\/unlock$/)?.input:
        await this.routeVaultUnlock(req, res, url);
        break;

      // Vault managed release
      case url.pathname.match(/^\/api\/v1\/vaults\/[a-zA-Z0-9_-]+\/managed-release$/)?.input:
        await this.routeVaultManagedRelease(req, res, url);
        break;

      // Vault managed credential authoring (Option C)
      case url.pathname.match(/^\/api\/v1\/vaults\/[a-zA-Z0-9_-]+\/managed-credentials$/)?.input:
        await this.routeVaultManagedCredential(req, res, url);
        break;

      // Credentials list
      case "/api/v1/credentials":
        await this.routeCredentialsList(req, res);
        break;

      // API info
      case "/api":
        await this.routeApiInfo(req, res);
        break;

      default:
        // Serve static files from dist/ directory
        await this.handleStaticFile(req, res, url.pathname);
    }
  }

  private async routeVaults(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleCreateVault(req, res));
    } else if (req.method === "GET") {
      await this.handleAuthRoute(req, res, () => this.handleVaultsList(req, res));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeGenerateCredentials(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleGenerateCredentials(req, res));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeExtractCredentials(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleExtractCredentials(req, res));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeValidateCredentials(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "POST") {
      await this.handleValidateCredentials(req, res);
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeVerifyToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "GET") {
      await this.handleAuthRoute(req, res, () => this.handleVerifyToken(req, res));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeVaultItem(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const vaultId = url.pathname.split("/").pop()!;
    if (req.method === "GET") {
      await this.handleAuthRoute(req, res, () => this.handleVaultGet(req, res, vaultId));
    } else if (req.method === "DELETE") {
      await this.handleAuthRoute(req, res, () => this.handleVaultDelete(req, res, vaultId));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeVaultUnlock(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const vaultId = url.pathname.split("/")[4];
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleVaultUnlock(req, res, vaultId));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeVaultManagedRelease(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const vaultId = url.pathname.split("/")[4];
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleVaultManagedRelease(req, res, vaultId));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeVaultManagedCredential(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const vaultId = url.pathname.split("/")[4];
    if (req.method === "POST") {
      await this.handleAuthRoute(req, res, () => this.handleVaultManagedCredential(req, res, vaultId));
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  private async routeCredentialsList(req: IncomingMessage, res: ServerResponse): Promise<void> {
    await this.handleAuthRoute(req, res, () => this.handleCredentialsList(req, res));
  }

  private async routeApiInfo(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "GET") {
      this.handleApiInfo(req, res);
    } else {
      this.sendError(res, 405, "Method not allowed");
    }
  }

  /**
   * Serve static files from dist/ directory
   */
  private async handleStaticFile(
    req: IncomingMessage,
    res: ServerResponse,
    pathname: string,
  ): Promise<void> {
    const { readFileSync: readFS, existsSync } = await import("fs");
    const { join } = await import("path");

    // Security: only serve specific static files
    const allowedFiles = ["/auth.html", "/vault.html", "/test-plugin.html"];
    if (!allowedFiles.includes(pathname)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    const filePath = join(process.cwd(), "dist", pathname);
    if (!existsSync(filePath)) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    const content = readFS(filePath);
    const contentType = pathname.endsWith(".html")
      ? "text/html"
      : "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
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
export interface StartServerOptions {
  port?: number;
  vaultRepository?: IVaultRepository;
  encryptionService?: EncryptionService;
  hashingService?: HashingService;
  signatureService?: SignatureService;
  keyManagementService?: KeyManagementService;
  credentialsGenerator?: CredentialsGenerator;
  credentialRepository?: ICredentialRepository;
}

export async function startServer(options: StartServerOptions = {}): Promise<
  Server<typeof IncomingMessage, typeof ServerResponse>
> {
  const {
    port = 3000,
    vaultRepository,
    encryptionService,
    hashingService,
    signatureService,
    keyManagementService,
    credentialsGenerator,
    credentialRepository,
  } = options;
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

  startServer({ port }).catch((err) =>
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
