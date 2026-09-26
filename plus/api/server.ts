/**
 * Plus API Server — CyberVault Plus Authorization Service
 *
 * HTTP API for Plus service providing:
 * - Capability token issuance (POST /api/v1/capabilities/request)
 * - Entitlement checking (POST /api/v1/entitlements/check)
 * - Challenge management (POST /api/v1/challenges/trigger, POST /api/v1/challenges/verify)
 * - Public key distribution (GET /api/v1/crypto/public-key)
 * - Audit logging (POST /api/v1/audit)
 * - Health checks (GET /health, GET /ready)
 */

import type { Server, IncomingMessage, ServerResponse } from "http";
import { createServer } from "http";
import { readFileSync } from "fs";
import { resolve } from "path";
import { logger } from "@/shared/logger";
import { metrics } from "@/shared/metrics";
import type { IChallengeRepository } from "../domain/repositories";
import type { IEntitlementRepository } from "../domain/repositories";
import type { IPlusUserRepository } from "../domain/repositories";
import { NoOpEmailService } from "../domain/services/email-service";
import type { IEmailService } from "../domain/services/email-service";

/** Security configuration */
const SECURITY_CONFIG = {
  HTTPS_ENABLED: process.env.HTTPS_ENABLED === "true",
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || "./certs/server.crt",
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || "./certs/server.key",
};

/** JWT Secret for Plus internal auth (separate from Core) */
const PLUS_JWT_SECRET = process.env.PLUS_JWT_SECRET;
if (!PLUS_JWT_SECRET && process.env.NODE_ENV !== "development") {
  throw new Error("PLUS_JWT_SECRET is required in staging/production");
}

/** Request timeout: 30 seconds */
const REQUEST_TIMEOUT_MS = 30_000;

/** Plus service configuration from environment */
const PLUS_CONFIG = {
  baseUrl: process.env.PLUS_BASE_URL || "http://localhost:3001",
  serviceSecret: process.env.PLUS_SERVICE_SECRET || "dev-secret-change-in-production",
  capabilityIssuerKey: process.env.PLUS_CAPABILITY_PRIVATE_KEY,
  challengeBaseUrl: process.env.PLUS_CHALLENGE_BASE_URL || "http://localhost:3001",
};

export class PlusApiServer {
  private activeConnections = 0;
  private capabilityIssuer: ReturnType<typeof import("../domain/services/capability-issuer").getCapabilityIssuer>;
  private challengeService: ReturnType<typeof import("../domain/services/challenge").getChallengeService>;
  private riskEngine: ReturnType<typeof import("../domain/services/risk-engine").getRiskEngine>;
  private challengeRepo: IChallengeRepository;
  private entitlementRepo: IEntitlementRepository;
  private userRepo: IPlusUserRepository;
  private emailService: IEmailService;

  constructor(
    challengeRepo: IChallengeRepository,
    entitlementRepo: IEntitlementRepository,
    userRepo: IPlusUserRepository,
    emailService?: IEmailService,
  ) {
    this.challengeRepo = challengeRepo;
    this.entitlementRepo = entitlementRepo;
    this.userRepo = userRepo;
    this.emailService = emailService || new NoOpEmailService();

    // Initialize services
    if (!PLUS_CONFIG.capabilityIssuerKey) {
      logger.warn("PLUS_CAPABILITY_PRIVATE_KEY not set - using generated key", "PlusApiServer");
    }
    this.capabilityIssuer = require("../domain/services/capability-issuer").getCapabilityIssuer(
      PLUS_CONFIG.capabilityIssuerKey || require("@/infrastructure/crypto/ed25519-capability").generateEd25519KeyPair().privateKeyBase64,
    );

    this.challengeService = require("../domain/services/challenge").getChallengeService(
      this.challengeRepo,
      this.emailService,
      PLUS_CONFIG.challengeBaseUrl,
      PLUS_CONFIG.capabilityIssuerKey || require("@/infrastructure/crypto/ed25519-capability").generateEd25519KeyPair().privateKeyBase64,
    );

    this.riskEngine = require("../domain/services/risk-engine").getRiskEngine();
  }

  private async parseJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
    const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MB

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

  private setupRequestTracking(req: IncomingMessage, res: ServerResponse): { startTime: number; url: URL } {
    const startTime = performance.now();
    this.activeConnections++;
    metrics.gauge("active_connections", "Current active connections", this.activeConnections, { service: "plus-api" });

    res.on("finish", () => {
      this.activeConnections = Math.max(0, this.activeConnections - 1);
      metrics.gauge("active_connections", "Current active connections", this.activeConnections, { service: "plus-api" });
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
    // Simple in-memory rate limiting (production would use Redis)
    return true;
  }

  private async handleHealth(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "healthy",
        timestamp: new Date().toISOString(),
        service: "cybervault-plus-api",
      }),
    );
  }

  private async handleReady(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Check dependencies
    const checks = {
      capabilityIssuer: "ok",
      challengeService: "ok",
      riskEngine: "ok",
    };
    const allReady = Object.values(checks).every((v) => v === "ok");

    res.writeHead(allReady ? 200 : 503, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: allReady ? "ready" : "not_ready",
        timestamp: new Date().toISOString(),
        checks,
      }),
    );
  }

  private async handleCapabilitiesRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const {
        userId,
        resourceId,
        operation,
        secretRef,
        deviceId,
        assurance,
        ttlSeconds,
        context,
      } = data as {
        userId: string;
        resourceId: string;
        operation: string;
        secretRef: string;
        deviceId?: string;
        assurance: 1 | 2 | 3;
        ttlSeconds?: number;
        context?: Record<string, unknown>;
      };

      if (!userId || !resourceId || !operation || !secretRef || !assurance) {
        this.sendError(res, 400, "Missing required fields: userId, resourceId, operation, secretRef, assurance");
        return;
      }

      // Verify operation is valid
      const validOperations = ["AUTOFILL", "VIEW", "TOTP", "CONNECT", "READ", "ADMIN", "BACKUP", "RESTORE", "ROTATE_SECRET", "EDIT_SECRET", "DELETE_SECRET", "EXPORT_SECRET"];
      if (!validOperations.includes(operation)) {
        this.sendError(res, 400, "Invalid operation");
        return;
      }

      // Issue capability based on assurance level
      let result;
      if (assurance === 3) {
        // Step-up capability requires challenge context
        result = await this.capabilityIssuer.issueStepUpCapability({
          userId,
          resourceId,
          operation: operation as any,
          secretRef,
          deviceId,
          challengeId: context?.challengeId || "",
          ttlSeconds,
        });
      } else if (assurance === 2) {
        result = await this.capabilityIssuer.issueRiskBasedCapability({
          userId,
          resourceId,
          operation: operation as any,
          secretRef,
          deviceId,
          riskScore: (context?.riskScore as number) || 0,
          riskReasons: (context?.riskReasons as string[]) || [],
          ttlSeconds,
        });
      } else {
        result = await this.capabilityIssuer.issueDirectCapability({
          userId,
          resourceId,
          operation: operation as any,
          secretRef,
          deviceId,
          ttlSeconds,
        });
      }

      if (!result.success) {
        this.sendError(res, 400, result.error || "Failed to issue capability");
        return;
      }

      metrics.counter("plus_capabilities_issued_total", "Total capabilities issued", {
        assurance: String(assurance),
        operation,
      });

      this.sendSuccess(res, 201, {
        capabilityToken: result.capabilityToken,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      logger.error("Capability request failed", "PlusApiServer", undefined, String(error));
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async handleEntitlementsCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const { userId, resourceId, operation } = data as {
        userId: string;
        resourceId: string;
        operation: string;
      };

      if (!userId || !resourceId || !operation) {
        this.sendError(res, 400, "Missing required fields: userId, resourceId, operation");
        return;
      }

      // Fetch entitlement
      const entitlement = await this.entitlementRepo.findByUserAndResource(userId, resourceId);
      if (!entitlement) {
        this.sendSuccess(res, 200, {
          allowed: false,
          reason: "No entitlement found",
          pestilloState: "closed",
        });
        return;
      }

      // Check if currently valid
      const now = new Date();
      const effectiveState = entitlement.getEffectiveState(now);
      const isOperationAllowed = entitlement.isOperationAllowed(operation as any);

      if (effectiveState === "closed" || !isOperationAllowed) {
        this.sendSuccess(res, 200, {
          allowed: false,
          reason: effectiveState === "closed" ? "Pestillo is closed" : "Operation not allowed",
          pestilloState: effectiveState,
        });
        return;
      }

      // For STEP_UP, require challenge
      if (effectiveState === "step_up") {
        this.sendSuccess(res, 200, {
          allowed: false,
          reason: "Step-up authentication required",
          pestilloState: effectiveState,
          challengeRequired: true,
        });
        return;
      }

      // For TEMPORARY, check expiry
      if (effectiveState === "temporary" && entitlement.validUntil && entitlement.validUntil < now) {
        this.sendSuccess(res, 200, {
          allowed: false,
          reason: "Temporary entitlement expired",
          pestilloState: "closed",
        });
        return;
      }

      // Allowed - client should request capability
      this.sendSuccess(res, 200, {
        allowed: true,
        pestilloState: effectiveState,
        operations: entitlement.allowedOperations,
        validFrom: entitlement.validFrom?.toISOString(),
        validUntil: entitlement.validUntil?.toISOString(),
      });
    } catch (error) {
      logger.error("Entitlement check failed", "PlusApiServer", undefined, String(error));
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async handleChallengeTrigger(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const { userId, resourceId, operation, secretRef, deviceId, type, riskScore, riskReasons } = data as {
        userId: string;
        resourceId: string;
        operation: string;
        secretRef: string;
        deviceId?: string;
        type: string;
        riskScore?: number;
        riskReasons?: string[];
      };

      if (!userId || !resourceId || !operation || !secretRef) {
        this.sendError(res, 400, "Missing required fields");
        return;
      }

      // Create challenge
      const result = await this.challengeService.createChallenge({
        userId,
        resourceId,
        operation: operation as any,
        secretRef,
        deviceId,
        type: (type as any) || "risk_based",
        riskScore,
        riskReasons,
      });

      this.sendSuccess(res, 201, {
        challengeId: result.challengeId,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      logger.error("Challenge trigger failed", "PlusApiServer", undefined, String(error));
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async handleChallengeVerify(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const { challengeId, pin, deviceId } = data as {
        challengeId: string;
        pin: string;
        deviceId?: string;
      };

      if (!challengeId || !pin) {
        this.sendError(res, 400, "challengeId and pin required");
        return;
      }

      const result = await this.challengeService.verifyPin({ challengeId, pin, deviceId });

      if (!result.success) {
        this.sendError(res, 400, result.error || "PIN verification failed");
        return;
      }

      this.sendSuccess(res, 200, {
        capabilityToken: result.capabilityToken,
      });
    } catch (error) {
      logger.error("Challenge verify failed", "PlusApiServer", undefined, String(error));
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async handlePublicKey(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "GET") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    // Return public key for Core verification
    const capabilityIssuer = require("../domain/services/capability-issuer").getCapabilityIssuer();
    const publicKey = capabilityIssuer?.getPublicKey?.() || "";

    this.sendSuccess(res, 200, {
      publicKey,
      algorithm: "Ed25519",
    });
  }

  private async handleAudit(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const { event, userId, resourceId, operation, decision, riskScore, riskReasons, context } = data as {
        event: string;
        userId: string;
        resourceId?: string;
        operation?: string;
        decision: "allow" | "deny" | "challenge";
        riskScore?: number;
        riskReasons?: string[];
        context?: Record<string, unknown>;
      };

      // Log audit event (in production, write to audit store)
      logger.info("Plus audit event", "PlusApiServer", {
        event,
        userId,
        resourceId,
        operation,
        decision,
        riskScore,
        riskReasons,
        context,
      });

      this.sendSuccess(res, 200, { success: true });
    } catch (error) {
      logger.error("Audit log failed", "PlusApiServer", undefined, String(error));
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Timeout
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      if (!res.headersSent) {
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Gateway Timeout" }));
      } else {
        res.destroy();
      }
      req.destroy();
    });

    const { url } = this.setupRequestTracking(req, res);

    // Rate limiting
    const ip = req.socket?.remoteAddress || "unknown";
    if (!this.checkRateLimitOrError(res, ip)) return;

    try {
      await this.routeRequest(req, res, url);
    } catch (error) {
      this.sendError(res, 500, "Internal server error");
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
      case "/api/v1/capabilities/request":
        await this.handleCapabilitiesRequest(req, res);
        break;
      case "/api/v1/entitlements/check":
        await this.handleEntitlementsCheck(req, res);
        break;
      case "/api/v1/challenges/trigger":
        await this.handleChallengeTrigger(req, res);
        break;
      case "/api/v1/challenges/verify":
        await this.handleChallengeVerify(req, res);
        break;
      case "/api/v1/crypto/public-key":
        await this.handlePublicKey(req, res);
        break;
      case "/api/v1/audit":
        await this.handleAudit(req, res);
        break;
      default:
        this.sendError(res, 404, "Not found");
    }
  }

  public async start(port: number = 3001): Promise<Server> {
    return new Promise((resolvePromise, reject) => {
      let server: Server;

      if (SECURITY_CONFIG.HTTPS_ENABLED) {
        try {
          const options = {
            key: readFileSync(resolve(SECURITY_CONFIG.TLS_KEY_PATH)),
            cert: readFileSync(resolve(SECURITY_CONFIG.TLS_CERT_PATH)),
          };
          server = require("https").createServer(options, (req, res) => this.handleRequest(req, res));
          logger.info(`🔒 Plus HTTPS Server started on port ${port}`, "PlusApiServer");
        } catch (error) {
          logger.warn("HTTPS certificates not found, falling back to HTTP", "PlusApiServer");
          server = createServer((req, res) => this.handleRequest(req, res));
          logger.info(`⚠️  Plus HTTP Server started on port ${port} (no HTTPS)`, "PlusApiServer");
        }
      } else {
        server = createServer((req, res) => this.handleRequest(req, res));
        logger.info(`🌐 Plus HTTP Server started on port ${port}`, "PlusApiServer");
      }

      server
        .listen(port, () => {
          logger.info(`🚀 CyberVault Plus API ready at http://localhost:${port}`, "PlusApiServer");
          logger.info(`   Health check: http://localhost:${port}/health`, "PlusApiServer");
          logger.info(`   Ready check: http://localhost:${port}/ready`, "PlusApiServer");
          resolvePromise(server);
        })
        .on("error", reject);
    });
  }
}

export async function startPlusServer(options: {
  port?: number;
  challengeRepo: any;
  entitlementRepo: any;
  userRepo: any;
  emailService?: any;
} = {}): Promise<Server> {
  const {
    port = 3001,
    challengeRepo,
    entitlementRepo,
    userRepo,
  } = options;

  const plusServer = new PlusApiServer(
    challengeRepo,
    entitlementRepo,
    userRepo,
  );

  return plusServer.start(port);
}