/**
 * Plus API Server — CyberVault Plus Authorization Service
 *
 * HTTP API for Plus service providing:
 * - Capability token issuance (POST /api/v1/capabilities/request)
 * - Entitlement checking (POST /api/v1/entitlements/check)
 * - Challenge management (POST /api/v1/challenges/trigger, POST /api/v1/challenges/approve)
 * - Public key distribution (GET /api/v1/crypto/public-key)
 * - Audit logging (POST /api/v1/audit)
 * - Health checks (GET /health, GET /ready)
 */

import type { Server, IncomingMessage, ServerResponse } from "http";
import { createServer } from "http";
import { createServer as createHttpsServer } from "https";
import { readFileSync } from "fs";
import { timingSafeEqual } from "crypto";
import { resolve } from "path";
import { logger } from "@/shared/logger";
import { metrics } from "@/shared/metrics";
import type { IChallengeRepository } from "../domain/repositories";
import type { IEntitlementRepository } from "../domain/repositories";
import type { IPlusUserRepository } from "../domain/repositories";
import { PostgresChallengeRepository } from "../infrastructure/repositories/PostgresChallengeRepository";
import { PostgresEntitlementRepository } from "../infrastructure/repositories/PostgresEntitlementRepository";
import { PostgresPlusUserRepository } from "../infrastructure/repositories/PostgresPlusUserRepository";
import { NoOpEmailService } from "../domain/services/email-service";
import { getRateLimiter } from "@/infrastructure/rate-limit/shared-store";
import type { IEmailService } from "../domain/services/email-service";
import type { SignedApproval } from "@/infrastructure/crypto/ed25519-approval";
import type { CapabilityOperation } from "../domain/operations";
import { Resource } from "../domain/entities/resource";

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

/** Read a non-empty string out of the untyped `context` of a request body. */
function contextString(context: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = context?.[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Read a finite number out of the untyped `context` of a request body. */
function contextNumber(context: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = context?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/**
 * The `Resource` handed to the risk engine.
 *
 * This route has no resource repository injected, so the stand-in is
 * deliberately NEUTRAL: `criticality: "medium"` carries multiplier 1.0, which
 * makes resource criticality contribute exactly nothing instead of being
 * guessed either way. `AdaptiveRiskEngine` reads only `resource.id` and
 * `resource.criticality`.
 */
function neutralResource(resourceId: string): Resource {
  return Resource.create({
    id: resourceId,
    name: resourceId,
    type: "other",
    endpoint: "",
    environment: "production",
    criticality: "medium",
  });
}

/** Verdict of the pre-issuance authorization gate. */
type CapabilityAuthorization =
  | { readonly kind: "deny"; readonly reason: string }
  | { readonly kind: "challenge"; readonly challengeId: string; readonly challengeExpiresAt: number }
  | { readonly kind: "allow" };

/** The request fields the pre-issuance authorization gate reads. */
type CapabilityGateRequest = {
  userId: string;
  resourceId: string;
  operation: string;
  secretRef: string;
  deviceId?: string;
  assurance: 1 | 2 | 3;
  context?: Record<string, unknown>;
};

/** The binding the gate — and any challenge it raises — is scoped to. */
type CapabilityGateBinding = {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
};

/** Scored outcome the risk engine hands back for one request. */
type RiskEvaluation = import("../domain/services/risk-engine").RiskEvaluation;

/** Plus service configuration from environment */
const PLUS_CONFIG = {
  // Host-facing, so both defaults name the port Compose *publishes* (3003),
  // not the port the container listens on (3001). `challengeBaseUrl` is the
  // one that reaches a user: it becomes `${baseUrl}/challenge/${id}` in the
  // step-up email, and nothing answers on a host port the stack does not
  // publish. `npx tsx plus/api/main.ts` still listens on 3001 — set
  // PLUS_BASE_URL / PLUS_CHALLENGE_BASE_URL when running outside Compose.
  baseUrl: process.env.PLUS_BASE_URL || "http://localhost:3003",
  serviceSecret: process.env.PLUS_SERVICE_SECRET || "dev-secret-change-in-production",
  capabilityIssuerKey: process.env.PLUS_CAPABILITY_PRIVATE_KEY,
  challengeBaseUrl: process.env.PLUS_CHALLENGE_BASE_URL || "http://localhost:3003",
};

/**
 * Rate limit for the credential-minting endpoints, per client IP.
 * R1: `checkRateLimitOrError` was a stub returning `true`, so capability
 * issuance and challenge creation accepted unlimited traffic.
 */
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 60;


export class PlusApiServer {
  private activeConnections = 0;
  /** Exact-match browser origin allow-list. Empty means no browser is allowed. */
  private readonly allowedOrigins: string[];
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
    this.allowedOrigins = (process.env.PLUS_ALLOWED_ORIGINS || "")
      .split(",")
      .map((o) => o.trim())
      .filter((o) => o.length > 0);

    // Initialize services.
    //
    // ONE signing key for the whole server. The issuer and the challenge
    // service used to be handed `PLUS_CAPABILITY_PRIVATE_KEY || <a freshly
    // generated key>` in two separate expressions, so with the variable unset
    // they each generated their OWN key: `/api/v1/crypto/public-key` then
    // published the issuer's key while `/api/v1/challenges/approve` signed with
    // the other one, and every capability an accepted approval produced was
    // signed with a key Core had never pinned. The step-up completion was
    // therefore unusable even when the approval was valid. The singletons are
    // reset here so this constructor — and only this constructor — decides the
    // key.
    const signingKey =
      PLUS_CONFIG.capabilityIssuerKey ||
      require("@/infrastructure/crypto/ed25519-capability").generateEd25519KeyPair().privateKeyBase64;
    if (!PLUS_CONFIG.capabilityIssuerKey) {
      logger.warn("PLUS_CAPABILITY_PRIVATE_KEY not set - using generated key", "PlusApiServer");
    }
    require("../domain/services/capability-issuer").setCapabilityIssuer(null);
    require("../domain/services/challenge").setChallengeService(null);

    this.capabilityIssuer = require("../domain/services/capability-issuer").getCapabilityIssuer(signingKey);

    // R3: the fourth argument is the last one. The fifth used to be the R4
    // per-user PIN lockout store; with no PIN there is nothing to lock out, so
    // the constructor no longer accepts it.
    this.challengeService = require("../domain/services/challenge").getChallengeService(
      this.challengeRepo,
      this.emailService,
      PLUS_CONFIG.challengeBaseUrl,
      signingKey,
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

  /**
   * R1: `routeRequest` had no auth step at all. `PLUS_SERVICE_SECRET` was
   * declared in the config and the extension sent it as `X-Service-Secret`,
   * but nothing ever compared the two — so any anonymous caller could drive
   * challenge creation, probe entitlements for an arbitrary `userId`, and
   * submit a challenge approval.
   *
   * `/health` and `/ready` stay open because a readiness probe has no business
   * carrying a service credential. Everything else requires the secret.
   *
   * Compared in constant time: a byte-wise comparison leaks the length and the
   * matching prefix of the secret through response timing.
   */
  private authenticateServiceRequest(req: IncomingMessage, res: ServerResponse): boolean {
    const presented = req.headers["x-service-secret"];
    const expected = PLUS_CONFIG.serviceSecret;

    if (typeof presented !== "string" || presented.length === 0) {
      this.sendError(res, 401, "Missing X-Service-Secret");
      return false;
    }

    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    // timingSafeEqual throws on a length mismatch, so reject first.
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      this.sendError(res, 401, "Invalid X-Service-Secret");
      return false;
    }

    return true;
  }

  /**
   * Real per-IP fixed-window limit. This was a stub returning `true`, so the
   * endpoints that mint capabilities and challenges — the expensive, abusable
   * ones — accepted unlimited traffic from a single caller.
   *
   * In-process, and therefore per-replica. Documented in the threat model as
   * R7: behind more than one Plus instance the effective limit multiplies.
   */
  /**
   * R1 follow-up: the allow-list for browser origins.
   *
   * Chrome extensions send `Origin: chrome-extension://<id>`, so the id must
   * be configured. `PLUS_ALLOWED_ORIGINS` is a comma-separated list; entries
   * are matched exactly, never by suffix, so `evil.com` cannot be admitted by
   * listing `example.com`. An unset value admits nothing, which fails closed
   * — a native caller such as the service worker is unaffected by CORS.
   */
  private isAllowedOrigin(origin: string): boolean {
    if (this.allowedOrigins.length === 0) return false;
    return this.allowedOrigins.includes(origin);
  }

  /**
   * R1 added this as an in-process sliding window. R7 makes it shared, so the
   * 60/min budget is one budget across every Plus replica rather than 60 each.
   *
   * The limit and the `Retry-After` header are unchanged — R1 pinned those
   * deliberately. The window becomes a fixed one, which permits a burst across
   * a boundary; that trade is recorded in the threat model rather than hidden.
   */
  private async checkRateLimitOrError(res: ServerResponse, ip: string): Promise<boolean> {
    const decision = await getRateLimiter(
      "plus-api",
      RATE_LIMIT_MAX,
      RATE_LIMIT_WINDOW_MS,
    ).consume(ip);

    if (!decision.allowed) {
      res.setHeader("Retry-After", String(decision.retryAfterSeconds));
      this.sendError(res, 429, "Rate limit exceeded");
      return false;
    }
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

  /**
   * Decide whether a capability may be issued for this request — BEFORE any
   * key is used.
   *
   * WHY THIS EXISTS
   * ---------------
   * The extension's release path only ever posts to
   * `/api/v1/capabilities/request`, and this handler used to go straight from
   * body validation to signing: it never read the entitlement, never ran the
   * risk engine and never touched a challenge. The ONLY place that ever
   * produced `challengeRequired` was `/api/v1/entitlements/check`, which no
   * client calls. So a `step_up` pestillo, a risk score over the challenge
   * threshold and a `CLOSED` gate all yielded a signed capability — the
   * third-factor flow was implemented, tested against a fetch mock, and
   * unreachable against the real server.
   *
   * FAIL-CLOSED ORDER
   * -----------------
   * 1. No entitlement, `closed` effective state or a disallowed operation → deny.
   * 2. An unknown principal → deny (risk cannot be scored without one).
   * 3. The risk engine runs for EVERY surviving request, including `enabled`.
   *    A `deny` verdict denies; the client may only RAISE the score it is
   *    judged by, never lower it below what the server computed.
   * 4. A third factor is required when the pestillo says so, when the risk
   *    verdict says so, or when the caller claims assurance 3 (an assertion
   *    that must be backed by a proven challenge, not taken on trust).
   * 5. While a challenge for the binding is outstanding, NO capability is
   *    issued: the route hands back a challenge id and an expiry instead.
   */
  private async authorizeCapabilityRequest(args: CapabilityGateRequest): Promise<CapabilityAuthorization> {
    const binding: CapabilityGateBinding = {
      userId: args.userId,
      resourceId: args.resourceId,
      operation: args.operation as CapabilityOperation,
      secretRef: args.secretRef,
    };

    const entitlement = await this.entitlementRepo.findByUserAndResource(args.userId, args.resourceId);
    if (!entitlement) {
      return { kind: "deny", reason: "No entitlement found" };
    }

    const state = entitlement.getEffectiveState(new Date());
    if (state === "closed") {
      return { kind: "deny", reason: "Pestillo is closed" };
    }
    if (!entitlement.isOperationAllowed(binding.operation)) {
      return { kind: "deny", reason: "Operation not allowed" };
    }

    const user = await this.userRepo.findById(args.userId);
    if (!user) {
      return { kind: "deny", reason: "Unknown user" };
    }

    const evaluation = this.riskEngine.evaluate({
      user,
      resource: neutralResource(args.resourceId),
      operation: binding.operation,
      pestilloState: state,
      clientContext: {
        country: contextString(args.context, "country"),
        ip: contextString(args.context, "ip"),
        deviceId: args.deviceId,
        userAgent: contextString(args.context, "userAgent"),
        timestamp: contextNumber(args.context, "timestamp") ?? Date.now(),
      },
      policy: this.riskEngine.getPolicy(),
    });

    // `context.riskScore` is a floor, not an authority: a caller may declare
    // risk the server did not observe, but it can never declare the risk away.
    const clientScore = contextNumber(args.context, "riskScore") ?? 0;
    const thresholds = this.riskEngine.getPolicy().thresholds;
    const decision =
      evaluation.decision === "allow" && clientScore > thresholds.allow ? "challenge" : evaluation.decision;
    if (decision === "deny") {
      return { kind: "deny", reason: "Risk policy denied the request" };
    }

    const thirdFactorRequired = state === "step_up" || decision === "challenge" || args.assurance === 3;
    if (!thirdFactorRequired) {
      return { kind: "allow" };
    }

    // Steps 4–5: satisfy the third factor, or hand back the challenge it has
    // to answer. Extracted so the gate above reads top to bottom; the order of
    // the two checks below is unchanged.
    return this.resolveThirdFactor(args, binding, state, evaluation);
  }

  /**
   * Steps 4–5 of the fail-closed order documented on
   * `authorizeCapabilityRequest`: while no challenge for this binding has been
   * proven, the route answers with a challenge id and an expiry instead of a
   * capability; a caller that NAMES a challenge must name the proven one.
   */
  private async resolveThirdFactor(
    args: CapabilityGateRequest,
    binding: CapabilityGateBinding,
    state: string,
    evaluation: RiskEvaluation,
  ): Promise<CapabilityAuthorization> {
    const proven = await this.challengeService.findCompletedChallenge(binding);
    if (!proven) {
      const challenge = await this.challengeService.createChallenge({
        ...binding,
        deviceId: args.deviceId,
        type: state === "step_up" ? "step_up" : "risk_based",
        riskScore: evaluation.totalScore,
        riskReasons: evaluation.factors.filter((factor) => factor.score > 0).map((factor) => factor.reason),
      });
      return {
        kind: "challenge",
        challengeId: challenge.challengeId,
        challengeExpiresAt: challenge.expiresAt,
      };
    }

    // A challenge id presented by the caller must be the one that was proven
    // for THIS binding. Omitting it is fine (the completed challenge on the
    // server is what authorizes); naming a different one is not.
    const presented = contextString(args.context, "challengeId");
    if (presented !== undefined && presented !== proven.id) {
      return { kind: "deny", reason: "Challenge not satisfied" };
    }

    return { kind: "allow" };
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

      // Authorization BEFORE issuance. Nothing below this line signs anything
      // until the entitlement, the risk engine and any outstanding challenge
      // have all had their say.
      const authorization = await this.authorizeCapabilityRequest({
        userId,
        resourceId,
        operation,
        secretRef,
        deviceId,
        assurance,
        context,
      });

      if (authorization.kind === "deny") {
        this.sendError(res, 403, authorization.reason);
        return;
      }

      if (authorization.kind === "challenge") {
        // HTTP 200: the request was understood and processed, and the answer
        // is "not yet — prove the third factor first". Both the extension's
        // `fetchPlusMaterial` and `PlusBridge.requestCapability` only read the
        // body on a 2xx, so a non-2xx here would arrive as a generic denial
        // instead of as the challenge the flow is built around.
        this.sendSuccess(res, 200, {
          success: false,
          error: "Step-up authentication required",
          challengeRequired: true,
          challengeId: authorization.challengeId,
          challengeExpiresAt: authorization.challengeExpiresAt,
        });
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
          // `context` is `Record<string, unknown>`; `context?.challengeId` is
          // therefore `unknown` and `unknown || ""` is `{}` at the type level,
          // which is why this used to fail to compile. `contextString` is the
          // read helper this route already uses for every other body field: it
          // returns the value only when it is a non-empty string, and `?? ""`
          // preserves the old "no challenge context yet" behaviour.
          challengeId: contextString(context, "challengeId") ?? "",
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

  /**
   * POST /api/v1/challenges/approve — accept Core's signed approval and issue
   * the capability (R3, T4).
   *
   * The body carries the challenge id and the `SignedApproval` Core returned
   * from `POST /api/v1/step-up/approve`. It deliberately does NOT carry a
   * public key: verification runs against the Core approval key pinned in
   * `CORE_APPROVAL_PUBLIC_KEY`, which is read inside `verifyApproval` from the
   * process environment. A key supplied by the caller would make every check
   * in this route meaningless, so no body field other than the token itself is
   * trusted, and every binding field is rebuilt from the stored challenge.
   */
  private async handleChallengeApprove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") {
      this.sendError(res, 405, "Method not allowed");
      return;
    }

    try {
      const data = await this.parseJsonBody(req);
      const { challengeId, approval, deviceId } = data as {
        challengeId: string;
        approval?: unknown;
        deviceId?: string;
      };

      if (!challengeId || !approval || typeof approval !== "object") {
        this.sendError(res, 400, "challengeId and approval required");
        return;
      }

      const result = await this.challengeService.verifyApproval({
        challengeId,
        approval: approval as SignedApproval,
        deviceId,
      });

      if (!result.success) {
        this.sendError(res, 400, result.error || "Approval verification failed");
        return;
      }

      // `success: true` is explicit rather than implied by a 200. The
      // extension's `handleApproveStepUp` decides whether to record a
      // completion from this flag, and when it was absent the flag read
      // `undefined` — so every real approval was reported back to the user as
      // refused while the capability had in fact been issued. Every Jest stub
      // returned `success: true`, which is why no test caught it.
      this.sendSuccess(res, 200, {
        success: true,
        capabilityToken: result.capabilityToken,
      });
    } catch (error) {
      logger.error("Challenge approve failed", "PlusApiServer", undefined, String(error));
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

    // CORS. The wildcard was wrong twice over now that R1 is fixed: the
    // extension authenticates with `X-Service-Secret`, so an origin allow-list
    // is required for a browser to be able to send it at all, and echoing an
    // arbitrary origin is what turns a same-origin API into a callable one
    // from anywhere. No header is emitted for an origin that is not configured.
    const origin = req.headers.origin;
    if (typeof origin === "string" && this.isAllowedOrigin(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Service-Secret");

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
    if (!(await this.checkRateLimitOrError(res, ip))) return;

    try {
      await this.routeRequest(req, res, url);
    } catch (error) {
      this.sendError(res, 500, "Internal server error");
    }
  }

  private async routeRequest(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    // R1: the only two unauthenticated routes are the probes. Everything else
    // requires the service secret the extension already sends.
    const isProbe = url.pathname === "/health" || url.pathname === "/ready";
    if (!isProbe && !this.authenticateServiceRequest(req, res)) {
      return;
    }

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
      case "/api/v1/challenges/approve":
        await this.handleChallengeApprove(req, res);
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

  /**
   * H6 (Plus) — TLS is decided HERE, from the environment as it is at
   * STARTUP, and a failure to honour it REFUSES to start instead of degrading.
   *
   * Two fail-open paths existed, the same ones fixed in Core:
   *
   *  1. `HTTPS_ENABLED` defaulted to `false` through the `SECURITY_CONFIG`
   *     snapshot frozen when this module was first imported, so a production
   *     deployment that simply forgot the variable served the whole
   *     authorization API (capabilities, challenges, approval verification) over
   *     plaintext HTTP with no complaint.
   *  2. With `HTTPS_ENABLED=true` but an unreadable key or certificate, the
   *     `catch` logged a warning and started a PLAINTEXT HTTP server anyway —
   *     "falling back to HTTP". The operator asked for TLS and got the exact
   *     opposite, silently, on the service that issues capabilities.
   *
   * Both now throw. Reading the environment here rather than consulting
   * `SECURITY_CONFIG` (frozen when the module was first imported) means the
   * decision follows `start()` and can be exercised per test case.
   *
   * Outside production the behaviour is unchanged: a process that never asked
   * for TLS still starts plain HTTP. Only "asked for TLS and could not honour
   * it" is refused in every environment, because falling back would defeat
   * the setting.
   *
   * This guards SERVER STARTUP, not a request, so no previously-valid request
   * is refused — the only behaviour that changes is that a misconfigured
   * Plus process now fails to boot instead of leaking.
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
        readFileSync(resolve(tlsKeyPath));
        readFileSync(resolve(tlsCertPath));
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

  public async start(port: number = 3001): Promise<Server> {
    const { httpsEnabled, tlsKeyPath, tlsCertPath } = this.assertTlsConfiguration();

    return new Promise((resolvePromise, reject) => {
      let server: Server;

      if (httpsEnabled) {
        try {
          const options = {
            // Same paths the guard just validated — never the frozen snapshot.
            key: readFileSync(resolve(tlsKeyPath)),
            cert: readFileSync(resolve(tlsCertPath)),
          };
          // A static import rather than `require("https")`: the untyped
          // `require()` returned `any`, so the callback's `req`/`res`
          // parameters had no contextual type and both were implicit `any`.
          // `createHttpsServer` is `https.createServer`, so the emitted call is
          // still a property lookup on the `https` module object and the TLS
          // tests' `jest.spyOn(require("https"), "createServer")` still
          // observes it.
          server = createHttpsServer(options, (req, res) => this.handleRequest(req, res));
          logger.info(`🔒 Plus HTTPS Server started on port ${port}`, "PlusApiServer");
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

/**
 * Everything `startPlusServer()` can be handed.
 *
 * Every field is optional ON PURPOSE. The previous signature declared
 * `challengeRepo`, `entitlementRepo` and `userRepo` as REQUIRED while the
 * function's own default parameter was `= {}`, so the one call the type
 * advertised — `startPlusServer()` — was exactly the call TypeScript rejected
 * (TS2739 on the declaration). The type was wrong, not the callers.
 *
 * A caller may now supply any subset. Whatever is omitted falls back to the
 * Postgres implementation bound to `DATABASE_URL`, the same arrangement
 * Core's `startServer()` uses for its repositories — supply your own (tests,
 * embedders) or let it default (a real deployment).
 */
export interface StartPlusServerOptions {
  port?: number;
  challengeRepo?: IChallengeRepository;
  entitlementRepo?: IEntitlementRepository;
  userRepo?: IPlusUserRepository;
  emailService?: IEmailService;
}

export async function startPlusServer(options: StartPlusServerOptions = {}): Promise<Server> {
  // Read even when unused: the destructuring defaults below are only
  // EVALUATED for properties the caller left `undefined`, so a caller that
  // passes repositories never opens a pool here.
  const connectionString = process.env.DATABASE_URL || "";
  const {
    port = 3001,
    challengeRepo = new PostgresChallengeRepository(connectionString),
    entitlementRepo = new PostgresEntitlementRepository(connectionString),
    userRepo = new PostgresPlusUserRepository(connectionString),
    emailService,
  } = options;

  const plusServer = new PlusApiServer(
    challengeRepo,
    entitlementRepo,
    userRepo,
    emailService,
  );

  return plusServer.start(port);
}