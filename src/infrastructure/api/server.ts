/**
 * API Server para Cyber Vault
 * Servidor HTTP/HTTPS con seguridad mejorada
 * Arquitectura Limpia: Use Cases y Repositorios
 */

import type { Server, IncomingMessage, ServerResponse } from "http";
import { createServer } from "http";
import { randomBytes, randomUUID } from "crypto";
import * as https from "https";
import { readFileSync } from "fs";
import { resolve as resolvePath } from "path";

import type {
  IVaultRepository,
  ICredentialRepository,
  IReleaseShareStore,
  IStepUpApprovalChallengeStore,
  IStepUpAuthenticatorStore,
  StepUpApprovalChallenge,
} from "../../domain/repositories";
import { VaultId, CredentialId } from "../../domain/value-objects/ids";
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
  getUserById,
  createUser,
  verifyPassword,
  type AuthenticatedRequest,
} from "./auth";
import {
  precheckProofShape,
  readWebAuthnConfig,
  verifyStepUpProof,
} from "./step-up-approval";
import {
  APPROVAL_CHALLENGE_TTL_MS,
  bytesToBase64Url,
  type StepUpProof,
} from "../crypto/step-up-proof";
import type { ApprovalOperation } from "../crypto/ed25519-approval";

import { swaggerMiddleware } from "./swagger";
import { connectRedis, disconnectRedis } from "../redis";
import { logger } from "../../shared/logger";
import { metrics } from "../../shared/metrics";
import { applyCorsHeaders } from "./middleware/cors";
import { applySecurityHeaders } from "./middleware/security-headers";
import {
  checkRateLimit,
  checkValidateRateLimit,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW,
  _clearRateLimitForTests,
} from "./middleware/rate-limiter";
import { loginRateLimiter } from "./login-rate-limiter";
import { rateLimitMode } from "../rate-limit/shared-store";
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
  createReleaseShareStore,
  createStepUpProofStores,
} from "../../infrastructure/repositories";
import { loadReleaseShareKekSecret } from "../../infrastructure/crypto/release-share-kek";
import {
  loadPlusPublicKey,
  type CapabilityBindingContext,
} from "../../infrastructure/crypto/ed25519-capability";
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
  /**
   * Wrapped Release Shares for managed credentials (dumb store, no key
   * material). Selected from the environment by `createReleaseShareStore`
   * (Postgres when configured, in-memory otherwise) — there is deliberately no
   * extra constructor parameter for it: the selection rule lives with the
   * factory, which is unit-tested on its own.
   */
  private releaseShareStore: IReleaseShareStore;
  /** Base64 32-byte secret behind the Release Share KEK. Null => release refuses. */
  private releaseShareKekSecret: Uint8Array | null;
  /**
   * R11 — the one-time approval challenges (WebAuthn challenge + passphrase
   * salt) and the user's registered authenticators. Same factory rule as the
   * Release Share store: Postgres when configured, in-memory otherwise, and
   * no constructor parameter for them — the selection logic lives with the
   * factory, which is unit-tested on its own.
   */
  private stepUpChallenges: IStepUpApprovalChallengeStore;
  private stepUpAuthenticators: IStepUpAuthenticatorStore;
  /**
   * PINNED Ed25519 capability verification key (`PLUS_PUBLIC_KEY`). Loaded once
   * from configuration, never from a request. Null => every managed release
   * refuses with the missing variable named.
   */
  private plusPublicKey: Uint8Array | null;

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

    this.releaseShareStore = createReleaseShareStore();
    const stepUpStores = createStepUpProofStores();
    this.stepUpChallenges = stepUpStores.challenges;
    this.stepUpAuthenticators = stepUpStores.authenticators;
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

    this.plusPublicKey = loadPlusPublicKey(process.env.PLUS_PUBLIC_KEY);
    if (!this.plusPublicKey) {
      // Fail closed at request time, not at boot: the process must still start,
      // but no capability can be verified against a key taken from anywhere
      // but this configuration.
      logger.warn(
        "PLUS_PUBLIC_KEY missing or not 32-byte base64 - managed release will refuse every request",
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
    // Arrow functions, not bare method references: evaluateHealthCheck invokes
    // checkFn() with no receiver, so a detached `this.checkDatabaseHealth` runs
    // with `this === undefined` and the health check can never succeed.
    const [database, ipfs] = await Promise.all([
      this.evaluateHealthCheck(
        process.env.USE_POSTGRES === "true",
        () => this.checkDatabaseHealth(),
      ),
      this.evaluateHealthCheck(
        !!process.env.IPFS_API_URL,
        () => this.checkIpfsHealth(),
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

  /**
   * `async` because R7 moved the counter to a shared store.
   *
   * It was `if (!checkRateLimit(ip))` while the function returned a Promise,
   * and a Promise is always truthy — so the limit would have been silently
   * disabled, and the code would still have compiled. `await` is what makes the
   * check real; a future caller that forgets it gets a type error rather than
   * a silently absent limit.
   */
  private async checkRateLimitOrError(res: ServerResponse, ip: string): Promise<boolean> {
    if (!(await checkRateLimit(ip))) {
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
        // R7: which store each rate limit is actually using. An operator whose
        // limit silently degraded to per-process has no other way to tell, and
        // that degradation is invisible in every other signal — the service is
        // healthy, the requests are served, the only difference is that three
        // replicas are each handing out a full budget.
        rateLimitMode: rateLimitMode(),
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
    // This endpoint is unauthenticated and takes a raw password, so it is a
    // policy oracle and a credential-stuffing aid. A dedicated limiter was
    // written for it (checkValidateRateLimit, 20 requests / 5 minutes) but was
    // never wired, leaving only the global 100/15min limit. Enforce it here.
    const ip = req.socket?.remoteAddress || "unknown";
    // `await` is load-bearing: the function is async since R7 and a Promise is
    // truthy, so without it this check is `if (!truthy)` and never fires.
    if (!(await checkValidateRateLimit(ip))) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ error: "Too many validation requests" }),
      );
      return;
    }

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

    // Only `isValid` is returned. The previous response also carried `hasSalt`
    // and `hasPepper` set to the exact same value as `isValid`, so they added
    // no information while confirming to an unauthenticated caller that the
    // backend uses salted emails and peppered passwords.
    if (email) {
      result.email = {
        isValid: this.credentialsGenerator.isValidEmailWithSalt(email),
      };
    }

    if (password) {
      result.password = {
        isValid: this.credentialsGenerator.isValidPasswordWithPepper(password),
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
   * Verifies a Plus-signed capability against the PINNED `PLUS_PUBLIC_KEY`
   * (never a request-supplied key), binds it to the authenticated user, the
   * requested credential and this vault, and returns the ReleaseShare.
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

      // Parse the request body. SECURITY (ODD CRITICAL-1): the Ed25519
      // verification key is NOT part of this contract and is never read from
      // the request — it comes from pinned configuration (`PLUS_PUBLIC_KEY`)
      // loaded in the constructor. A caller-supplied key is ignored.
      const data = await this.parseJsonBody(req);
      const capabilityToken = data.capabilityToken as {
        payload: any;
        signature: string;
        protectedHeader: string;
      };

      if (!capabilityToken || !capabilityToken.payload || !capabilityToken.signature) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "capabilityToken required" }));
        return;
      }

      if (!this.credentialRepository) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Credential repository not configured" }));
        return;
      }

      // The request must name the credential it wants released. Core derives
      // the requested secret from ITS OWN store, inside the vault the caller
      // has already proved they own above — never from the capability and
      // never from the body's key material.
      const credentialId = typeof data.credentialId === "string" ? data.credentialId.trim() : "";
      if (!credentialId) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "credentialId required" }));
        return;
      }

      const requested = await this.credentialRepository.findById(
        CredentialId.fromString(credentialId),
      );
      // Scoped to this vault: an id from another vault is indistinguishable
      // from a non-existent one, so no cross-vault existence is revealed.
      if (!requested || requested.vaultId.toString() !== vaultId) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Credential not found" }));
        return;
      }
      const requestedSecretRef = requested.releaseShareRef;
      if (!requestedSecretRef) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ error: "Credential is not managed (requires Plus authorization)" }),
        );
        return;
      }

      // The device THIS request declares. "" means the deployment binds no
      // device, so a device-bound capability is refused unless the request
      // names the same device — a binding is never silently skipped.
      const deviceId = typeof data.deviceId === "string" ? data.deviceId : "";

      // Server-derived bindings: authenticated user + the requested resource
      // and secret as Core itself stores them.
      const expected: CapabilityBindingContext = {
        userId,
        resourceId: requestedSecretRef,
        secretRef: requestedSecretRef,
        deviceId,
      };

      // Use the managed release use case, wired to the PINNED key.
      // Note: In production, this would be injected via constructor
      const { ManagedReleaseUseCase } = await import("../../application/use-cases/managed-release.use-case");
      const useCase = new ManagedReleaseUseCase(
        this.credentialRepository,
        /* jtiStore: undefined => global store */ undefined,
        this.releaseShareStore,
        this.releaseShareKekSecret,
        this.plusPublicKey,
      );

      const result = await useCase.execute({
        capabilityToken,
        expected,
        vaultId,
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
  /**
   * Decode the caller-supplied session VEK from a managed-authoring body.
   *
   * EXTRACTED VERBATIM from `handleVaultManagedCredential`: an undecodable
   * value is a malformed body, and an absent/empty one is left null so the
   * use case refuses with VEK_MISSING.
   */
  private decodeManagedVek(
    data: Record<string, unknown>,
  ): { readonly vek: Uint8Array | null } | { readonly error: string } {
    if (typeof data.vek === "string" && data.vek.trim() !== "") {
      let vek: Uint8Array;
      try {
        vek = base64ToBinary(data.vek.trim());
      } catch {
        return { error: "vek must be base64-encoded" };
      }
      return { vek: vek.byteLength === 0 ? null : vek };
    }
    return { vek: null };
  }

  private async handleVaultManagedCredential(
    req: IncomingMessage,
    res: ServerResponse,
    vaultId: string,
  ): Promise<void> {
    try {
      const userId = (req as AuthenticatedRequest).userId;
      if (!userId) {
        this.sendError(res, 401, "Authentication required");
        return;
      }

      // Verify vault ownership
      const vault = await this.vaultRepository.findByVaultIdAndOwnerId(vaultId, userId);
      if (!vault) {
        this.sendError(res, 404, "Vault not found");
        return;
      }

      // Refuse BEFORE authoring: without a repository the wrapped share would
      // be written and the credential row would not exist.
      if (!this.credentialRepository) {
        this.sendError(res, 503, "Credential repository not configured");
        return;
      }

      // Parse authoring input from the request body
      const data = await this.parseJsonBody(req);

      // The session VEK is supplied by the only party that holds it.
      const decodedVek = this.decodeManagedVek(data);
      if ("error" in decodedVek) {
        this.sendError(res, 400, decodedVek.error);
        return;
      }
      const vek = decodedVek.vek;

      try {
        // Same store instance and same KEK secret as the release route.
        const { ManagedAuthoringUseCase } = await import(
          "../../application/use-cases/managed-authoring.use-case"
        );
        const useCase = new ManagedAuthoringUseCase(
          this.releaseShareStore,
          this.releaseShareKekSecret,
        );

        // H3 — THE REFERENCE IS MINTED HERE, NOT TAKEN FROM THE BODY.
        // `secretRef` used to be read straight out of the request and stored:
        // an authenticated attacker could choose the value another user's
        // credential was already using, and the release-share store's
        // `ON CONFLICT DO UPDATE` would then overwrite that user's wrapped
        // Release Share with this one. The body's `secretRef` is now IGNORED
        // — deliberately ignored rather than rejected, so a client that still
        // sends one gets a normal 201 with the server-chosen reference in
        // `record.releaseShareRef` instead of a new failure mode.
        const secretRef = randomUUID();

        const result = await useCase.execute({
          origin: typeof data.origin === "string" ? data.origin : "",
          username: typeof data.username === "string" ? data.username : "",
          password: typeof data.password === "string" ? data.password : "",
          title: typeof data.title === "string" ? data.title : "",
          totpSeedBase32:
            typeof data.totpSeedBase32 === "string" ? data.totpSeedBase32 : undefined,
          secretRef,
          vek,
        });

        if (!result.ok) {
          this.sendJson(res, 403, {
            error: this.managedAuthoringError(result.reason, result.detail),
            reason: result.reason,
            detail: result.detail,
          });
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

        this.sendJson(res, 201, {
          success: true,
          credentialId: persisted.id.toString(),
          // The canonical origin travels ONLY here, so the client can bind
          // ExactMatch; it is never written to the credential row.
          record: result.record,
          lookupToken: result.lookupToken,
          index: result.index,
        });
      } finally {
        // The caller (this request) owns the decoded VEK copy.
        if (vek) secureZero(vek);
      }
    } catch (error) {
      if (!res.headersSent) {
        this.sendError(res, 500, "Failed to process managed authoring");
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
    if (!(await this.checkRateLimitOrError(res, ip))) return;

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

      // Step-up approval (R3). Core signs the user's decision; Plus verifies
      // it. Deliberately not vault-scoped in the path: the binding names the
      // credential and the vault is checked through the credential itself, so
      // a URL cannot name a vault the credential does not belong to.
      case "/api/v1/step-up/approve":
        await this.routeStepUpApprove(req, res);
        break;

      // R11 — the one-time challenge a human-presence proof is bound to.
      // Issued per request, never accepted without being consumed.
      case "/api/v1/step-up/approval-challenge":
        await this.routeStepUpApprovalChallenge(req, res);
        break;

      // R11 — register an approval authenticator. Proof-gated like approve:
      // without it a stolen bearer token could enroll its own key and defeat
      // R11 in a single request.
      case "/api/v1/step-up/authenticator/register":
        await this.routeStepUpAuthenticatorRegister(req, res);
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

  private async routeStepUpApprove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }
    await this.handleAuthRoute(req, res, () => this.handleStepUpApprove(req, res));
  }

  private async routeStepUpApprovalChallenge(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }
    await this.handleAuthRoute(req, res, () => this.handleApprovalChallenge(req, res));
  }

  private async routeStepUpAuthenticatorRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }
    await this.handleAuthRoute(req, res, () => this.handleRegisterAuthenticator(req, res));
  }

  /**
   * POST /api/v1/step-up/approval-challenge — issue the one-time material a
   * human-presence proof is bound to (R11, T3).
   *
   * The response carries everything the CLIENT needs to build a proof without
   * the proof ever being trustable on its own:
   *
   *   - `challenge`/`salt`     — per-row random material, never derived from
   *     anything an attacker controls;
   *   - `userSalt`             — `users.salt`, so the client can reproduce
   *     `users.hash` from the passphrase locally. The passphrase itself never
   *     travels to Core, and `userSalt` alone is worthless without it;
   *   - `rpId`/`credentialIds` — what `navigator.credentials.get` needs,
   *     present only when WebAuthn is configured (fail closed otherwise);
   *   - `hasAuthenticator`     — false when unconfigured OR the user has not
   *     registered one, so the popup never offers a path that cannot verify.
   *
   * `purpose` distinguishes a release approval from an authenticator
   * enrollment. Both are proof-gated; a proof minted for one can never be
   * consumed by the other (the purpose is checked at verification).
   */
  private async handleApprovalChallenge(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const userId = (req as AuthenticatedRequest).userId;
    if (!userId) {
      this.sendError(res, 401, "Authentication required");
      return;
    }

    const data = await this.parseJsonBody(req);
    const challengeId = typeof data.challengeId === "string" ? data.challengeId : "";
    const purpose = data.purpose;
    if (!challengeId) {
      this.sendError(res, 400, "challengeId is required");
      return;
    }
    if (purpose !== "release" && purpose !== "enroll") {
      this.sendError(res, 400, "Unsupported purpose");
      return;
    }

    const user = await getUserById(userId);
    if (!user) {
      // A valid access token whose subject no longer exists: no KDF material
      // to offer, and no proof could ever verify. Fail closed.
      this.sendError(res, 503, "Approval unavailable");
      return;
    }

    const webauthn = readWebAuthnConfig();
    const registered = await this.stepUpAuthenticators.listByUserId(userId);
    // Credential ids are only advertised when assertions can actually be
    // verified — an unconfigured rpId/origin must not present a usable path.
    const credentialIds = webauthn.configured
      ? registered.map((authenticator) => authenticator.credentialId)
      : [];

    const id = randomUUID();
    const now = Date.now();
    const row: StepUpApprovalChallenge = {
      id,
      // Release proofs bind to the release challengeId (the R3/Plus binding);
      // enroll proofs have no release yet, so they bind to their own row id —
      // the id Core itself minted, therefore not attacker-chosen.
      bindingId: purpose === "release" ? challengeId : id,
      userId,
      purpose,
      challenge: bytesToBase64Url(randomBytes(32)),
      salt: randomBytes(32).toString("hex"),
      rpId: webauthn.configured ? webauthn.rpId : null,
      origin: webauthn.configured ? webauthn.origin : null,
      createdAt: now,
      expiresAt: now + APPROVAL_CHALLENGE_TTL_MS,
      consumedAt: null,
    };
    await this.stepUpChallenges.save(row);

    this.sendSuccess(res, 200, {
      approvalChallenge: {
        approvalChallengeId: row.id,
        challengeId: row.bindingId,
        purpose: row.purpose,
        challenge: row.challenge,
        salt: row.salt,
        userSalt: user.salt,
        rpId: row.rpId,
        hasAuthenticator: credentialIds.length > 0,
        credentialIds,
        expiresAt: row.expiresAt,
      },
    });
  }

  /**
   * Structural validation of the `authenticator/register` body.
   *
   * The reason these checks run BEFORE the challenge is consumed: a malformed
   * request must not burn a legitimate in-flight enrollment challenge. Kept
   * apart from the handler so the consume/verify half stays readable as one
   * story — the refusals below are about the SHAPE of the body, and none of
   * them may reach the store.
   *
   * Returns the parsed fields, or `null` after writing the refusal to `res`;
   * the caller has nothing left to do in the `null` case.
   */
  private readRegisterAuthenticatorRequest(
    res: ServerResponse,
    data: Record<string, unknown>,
  ): { credentialId: string; publicKey: string; transports: string[] } | null {
    const credentialId = typeof data.credentialId === "string" ? data.credentialId : "";
    const publicKey = typeof data.publicKey === "string" ? data.publicKey : "";
    if (!credentialId || !publicKey) {
      this.sendError(res, 400, "credentialId and publicKey are required");
      return null;
    }
    if (data.alg !== -7) {
      // Only ES256 (-7): the COSE reader and the P-256 verifier exist for
      // exactly this algorithm; anything else would be stored and then never
      // verify.
      this.sendError(res, 400, "Unsupported algorithm");
      return null;
    }
    const transports = Array.isArray(data.transports)
      ? data.transports.filter((t): t is string => typeof t === "string")
      : [];
    return { credentialId, publicKey, transports };
  }

  /**
   * POST /api/v1/step-up/authenticator/register — enroll a WebAuthn
   * credential for R11 (T4).
   *
   * Proof-gated for the same reason approve is: an endpoint that trusts the
   * bearer token alone would let a compromised worker enroll ITS OWN P-256
   * key in one request and then mint assertions at will — R11 defeated from
   * the inside. The proof is a passphrase (first authenticator) or an
   * assertion from an already-registered one (subsequent authenticators),
   * verified through the same `verifyStepUpProof` approve uses.
   *
   * The public key arrives as the DER SubjectPublicKeyInfo
   * `AuthenticatorAttestationResponse.getPublicKey()` returns (WebAuthn
   * Level 3), is normalized here to the raw `04||x||y` point, and is stored
   * with the credential — never trusted as-is from an arbitrary encoding.
   */
  private async handleRegisterAuthenticator(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const userId = (req as AuthenticatedRequest).userId;
    if (!userId) {
      this.sendError(res, 401, "Authentication required");
      return;
    }

    const data = await this.parseJsonBody(req);

    // Structural checks BEFORE the challenge is consumed: a malformed request
    // must not burn a legitimate in-flight enrollment challenge.
    if (data.proof === null || typeof data.proof !== "object") {
      this.sendError(res, 403, "Approval proof required");
      return;
    }
    // No release challengeId exists for enroll — the binding is the row's own
    // id, which verifyStepUpProof re-checks against the consumed row.
    const shape = precheckProofShape(data.proof, null);
    if ("status" in shape) {
      this.sendError(res, shape.status, shape.error);
      return;
    }
    const proof = shape.proof;

    const fields = this.readRegisterAuthenticatorRequest(res, data);
    if (!fields) return;
    const { credentialId, publicKey, transports } = fields;

    const webauthn = readWebAuthnConfig();
    if (!webauthn.configured) {
      // Fail closed: a credential registered without a configured rpId/origin
      // could never produce a verifiable assertion.
      this.sendError(res, 503, "Authenticator registration is not configured");
      return;
    }

    const user = await getUserById(userId);
    if (!user) {
      this.sendError(res, 503, "Approval unavailable");
      return;
    }

    // Validated now so a malformed key is refused at registration rather than
    // at the first approval attempt, months later, when the user cannot tell
    // why their authenticator stopped working.
    const { parseP256PublicKey, bytesToBase64Url } = await import("../crypto/step-up-proof");
    const rawPoint = parseP256PublicKey(publicKey);
    if (!rawPoint) {
      this.sendError(res, 400, "Invalid public key");
      return;
    }
    const storedKey = bytesToBase64Url(rawPoint);

    const row = await this.stepUpChallenges.consume(proof.approvalChallengeId, userId, Date.now());
    if (!row) {
      // Unknown, expired, already spent, or another user's row — one answer.
      this.sendError(res, 403, "Approval proof rejected");
      return;
    }
    const verification = await verifyStepUpProof(
      proof,
      row,
      user,
      "enroll",
      this.stepUpAuthenticators,
      webauthn,
    );
    if (!verification.ok) {
      this.sendError(res, verification.status, verification.error);
      return;
    }

    const saved = await this.stepUpAuthenticators.save({
      credentialId,
      userId,
      publicKey: storedKey,
      counter: 0,
      transports,
      createdAt: Date.now(),
    });
    if (!saved) {
      // The id already belongs to someone else. Re-owning it would swap the
      // public key under a stranger's authenticator.
      this.sendError(res, 409, "This authenticator is already registered to another account");
      return;
    }

    this.sendSuccess(res, 200, { registered: true, credentialId });
  }

  /**
   * Structural validation of the `step-up/approve` body.
   *
   * Split out of `handleStepUpApprove` so the handler keeps the order that
   * matters visible at a glance — shape, then proof gate, then ownership,
   * then signing — while everything that only looks at the REQUEST body lives
   * here. None of these refusals may consume a challenge or touch Core's
   * records.
   *
   * Returns the parsed fields, or `null` after writing the refusal to `res`.
   */
  private async readStepUpApproveRequest(
    res: ServerResponse,
    data: Record<string, unknown>,
  ): Promise<{
    credentialId: string;
    operation: ApprovalOperation;
    challengeId: string;
    proof: StepUpProof;
  } | null> {
    const credentialId = typeof data.credentialId === "string" ? data.credentialId : "";
    const operation = data.operation;

    if (!credentialId) {
      this.sendError(res, 400, "credentialId is required");
      return null;
    }

    const { isValidApprovalOperation } = await import("../../infrastructure/crypto/ed25519-approval");
    if (!isValidApprovalOperation(operation)) {
      this.sendError(res, 400, "Unsupported operation");
      return null;
    }

    const challengeId = typeof data.challengeId === "string" ? data.challengeId : "";
    if (!challengeId) {
      this.sendError(res, 400, "challengeId is required");
      return null;
    }

    // R11 — human presence proof gate. BEFORE any credential ownership work:
    // a stolen bearer token must die here on a missing/foreign proof instead
    // of reaching approval bookkeeping, and refusing early leaves no
    // enumeration oracle (the answer is the same whether the credential id
    // exists or not).
    const shape = precheckProofShape(data.proof, challengeId);
    if ("status" in shape) {
      this.sendError(res, shape.status, shape.error);
      return null;
    }
    return { credentialId, operation, challengeId, proof: shape.proof };
  }

  /**
   * Consume the approval challenge and verify the human-presence proof — the
   * R11 gate for `POST /api/v1/step-up/approve`.
   *
   * Returns `true` once the proof is accepted. On `false` the refusal has
   * ALREADY been written to `res` and the caller must stop; nothing past this
   * point may run on a proof that did not verify.
   */
  private async consumeAndVerifyStepUpProof(
    res: ServerResponse,
    userId: string,
    proof: StepUpProof,
  ): Promise<boolean> {
    const user = await getUserById(userId);
    if (!user) {
      // Valid token, deleted subject: no KDF material, no proof could verify.
      this.sendError(res, 503, "Approval unavailable");
      return false;
    }

    // Consume BEFORE verification: a captured assertion (or a guessing
    // attacker) burns the row on the first failed attempt, so it can never be
    // retried — the user simply requests a fresh challenge. Atomic and
    // single-statement: two concurrent submissions race the guard, exactly
    // one wins, both proof failures and replays end in the same 403.
    const row = await this.stepUpChallenges.consume(proof.approvalChallengeId, userId, Date.now());
    if (!row) {
      // Unknown, expired, already spent, or another user's row — one answer.
      this.sendError(res, 403, "Approval proof rejected");
      return false;
    }

    const verification = await verifyStepUpProof(
      proof,
      row,
      user,
      "release",
      this.stepUpAuthenticators,
      readWebAuthnConfig(),
    );
    if (!verification.ok) {
      this.sendError(res, verification.status, verification.error);
      return false;
    }
    if (verification.credentialId && verification.signCount && verification.signCount > 0) {
      // Advance the clone-detection counter on success only; implementations
      // that never increment (platform authenticators) keep it at 0.
      await this.stepUpAuthenticators.updateCounter(verification.credentialId, verification.signCount);
    }
    return true;
  }

  /**
   * POST /api/v1/step-up/approve — sign a user's approval to release one
   * managed credential (R3, T3).
   *
   * Core is the signer and Plus is the verifier. That inversion is the point:
   * the user is already authenticated here, Core is the party that owns vault
   * and credential records, and Core therefore can answer "does this user own
   * this credential" without trusting anything in the request. Plus cannot,
   * and never gets to decide it.
   *
   * Every binding field is derived from the authenticated user plus Core's own
   * records. The request contributes exactly one thing — which credential and
   * which operation — and a caller cannot name a `secretRef` for a credential
   * it does not own, because the secretRef is read from the stored record and
   * never from the body.
   */
  private async handleStepUpApprove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const userId = (req as AuthenticatedRequest).userId;
    if (!userId) {
      this.sendError(res, 401, "Authentication required");
      return;
    }

    if (!this.credentialRepository) {
      // Fail closed: without the repository there is no way to prove
      // ownership, and an approval signed on an unproven binding authorises
      // nothing while looking exactly like one that does.
      this.sendError(res, 503, "Approval unavailable");
      return;
    }

    const data = await this.parseJsonBody(req);

    const request = await this.readStepUpApproveRequest(res, data);
    if (!request) return;
    const { credentialId, operation, challengeId, proof } = request;

    const accepted = await this.consumeAndVerifyStepUpProof(res, userId, proof);
    if (!accepted) return;

    const { CredentialId } = await import("../../domain/value-objects/ids");
    const credential = await this.credentialRepository.findById(CredentialId.fromString(credentialId));
    if (!credential) {
      // Same answer as "not yours". A 404 here would let an authenticated user
      // probe which credential ids exist in Core.
      this.sendError(res, 404, "Credential not available for release");
      return;
    }

    const releaseShareRef = credential.releaseShareRef;
    if (credential.mode !== "managed" || !releaseShareRef) {
      // A personal credential has no Release Share, so there is nothing to
      // step up for. Refuse before signing rather than mint a capability
      // Plus would reject later.
      this.sendError(res, 400, "Credential is not a managed credential");
      return;
    }

    const vault = await this.vaultRepository.findByVaultIdAndOwnerId(
      credential.vaultId.toString(),
      userId,
    );
    if (!vault) {
      this.sendError(res, 404, "Credential not available for release");
      return;
    }

    const {
      APPROVAL_VERSION,
      CORE_APPROVAL_PRIVATE_KEY_ENV,
      DEFAULT_APPROVAL_TTL_SECONDS,
      MAX_APPROVAL_TTL_SECONDS,
      loadApprovalPrivateKey,
      signApproval,
    } = await import("../../infrastructure/crypto/ed25519-approval");

    const secret = process.env[CORE_APPROVAL_PRIVATE_KEY_ENV];
    if (!secret) {
      // No key configured means no approvals. Plus would refuse to verify
      // anything anyway; failing here makes the misconfiguration loud instead
      // of producing a token that silently never works.
      this.sendError(res, 503, "Approval signing is not configured");
      return;
    }

    const iat = Math.floor(Date.now() / 1000);

    const signed = await signApproval(
      {
        version: APPROVAL_VERSION,
        typ: "step-up-approval",
        challengeId,
        userId,
        // The secretRef is read from the stored record, not the request. A
        // caller cannot point an approval at a different credential's share.
        resourceId: releaseShareRef,
        operation,
        secretRef: releaseShareRef,
        iat,
        exp: iat + Math.min(DEFAULT_APPROVAL_TTL_SECONDS, MAX_APPROVAL_TTL_SECONDS),
        jti: crypto.randomUUID(),
      },
      loadApprovalPrivateKey(secret),
    );

    this.sendSuccess(res, 200, { approval: signed });
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
   * H6 — TLS is decided HERE, from the environment as it is at STARTUP, and a
   * failure to honour it REFUSES to start instead of degrading.
   *
   * Two fail-open paths existed:
   *
   *  1. `HTTPS_ENABLED` defaulted to `false`, so a production deployment that
   *     simply forgot the variable served every credential over plaintext
   *     HTTP with no complaint.
   *  2. With `HTTPS_ENABLED=true` but an unreadable key or certificate, the
   *     `catch` logged a warning and started a PLAINTEXT HTTP server anyway —
   *     "falling back to HTTP". The operator asked for TLS and got the exact
   *     opposite, silently.
   *
   * Both now throw. Reading the environment here rather than consulting
   * `SECURITY_CONFIG` (frozen when the module was first imported) means the
   * decision follows `start()` and can be exercised per test case.
   *
   * This guards SERVER STARTUP, not a request, so no previously-valid request
   * is refused — the only behaviour that changes is that a misconfigured
   * production process now fails to boot instead of leaking.
   */
  private assertTlsConfiguration(): {
    httpsEnabled: boolean;
    tlsKeyPath: string;
    tlsCertPath: string;
  } {
    // Re-read at startup: SECURITY_CONFIG is a snapshot taken when the module
    // was first imported, so it cannot see a value set afterwards — and the
    // paths have to come from the SAME place as the check, otherwise the guard
    // could validate one file while the server reads another.
    const httpsEnabled = process.env.HTTPS_ENABLED === "true";
    const isProduction = process.env.NODE_ENV === "production";
    const tlsKeyPath = process.env.TLS_KEY_PATH || SECURITY_CONFIG.TLS_KEY_PATH;
    const tlsCertPath = process.env.TLS_CERT_PATH || SECURITY_CONFIG.TLS_CERT_PATH;

    if (isProduction && !httpsEnabled) {
      throw new Error(
        "Refusing to start: NODE_ENV is \"production\" but HTTPS is not enabled. " +
          "Set HTTPS_ENABLED=true and configure TLS_CERT_PATH and TLS_KEY_PATH, " +
          "or terminate TLS in front of this process and say so explicitly. " +
          "Serving credentials over plaintext HTTP is not an acceptable fallback.",
      );
    }

    if (httpsEnabled) {
      try {
        readFileSync(resolvePath(tlsKeyPath));
        readFileSync(resolvePath(tlsCertPath));
      } catch (error) {
        throw new Error(
          "Refusing to start: HTTPS_ENABLED=true but the TLS key or certificate " +
            `could not be read (key=${tlsKeyPath}, cert=${tlsCertPath}). ` +
            "Serving plaintext HTTP instead would defeat the setting, so startup is aborted. " +
            `Underlying error: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    return { httpsEnabled, tlsKeyPath, tlsCertPath };
  }

  /**
   * Inicia el servidor HTTP/HTTPS
   */
  public async start(port: number = 3000): Promise<Server> {
    const { httpsEnabled, tlsKeyPath, tlsCertPath } = this.assertTlsConfiguration();

    return new Promise((resolvePromise, reject) => {
      let server: any;

      if (httpsEnabled) {
        try {
          const options = {
            // Same paths the guard just validated — never the frozen snapshot.
            key: readFileSync(resolvePath(tlsKeyPath)),
            cert: readFileSync(resolvePath(tlsCertPath)),
          };
          server = https.createServer(options, (req, res) =>
            this.handleRequest(req, res),
          );
          logger.info(`🔒 HTTPS Server started on port ${port}`, "ApiServer");
        } catch (error) {
          // Unreachable for a bad path — assertTlsConfiguration() already
          // refused. Kept as a hard failure rather than a fallback so this
          // branch can never regress into serving plaintext.
          reject(
            new Error(
              `Refusing to start: TLS material became unreadable while binding the HTTPS server: ${
                error instanceof Error ? error.message : String(error)
              }`,
            ),
          );
          return;
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

  startServer({ port }).catch((err) => {
    // H6: a refused startup must not leave a half-alive process. The TLS guard
    // throws precisely when serving would be unsafe, so exiting non-zero is the
    // only correct response — logging and carrying on would keep the process
    // (and whatever it already bound) around in the unsafe state.
    logger.error(
      "Server startup failed",
      "ApiServer",
      undefined,
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  });

  const shutdown = async () => {
    logger.info("Shutting down...", "ApiServer");
    await disconnectRedis();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
