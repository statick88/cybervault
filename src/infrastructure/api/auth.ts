/**
 * Módulo de autenticación JWT para Cyber Vault API
 *
 * Supports two storage backends:
 * - Postgres (production): via PostgresUserRepository
 * - In-memory (development): fallback when USE_POSTGRES !== "true"
 */

import * as jwt from "jsonwebtoken";
import * as crypto from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import { PostgresUserRepository } from "../repositories/PostgresUserRepository";
import { logger } from "../../shared/logger";

const HASH_ITERATIONS = 600_000;
const HASH_KEY_LENGTH = 64;
const HASH_DIGEST = "sha512";

export interface StoredUser {
  userId: string;
  email: string;
  hash: string;
  salt: string;
}

/* ------------------------------------------------------------------ */
/*  Storage backend                                                    */
/* ------------------------------------------------------------------ */

// In-memory store with TTL (dev fallback only)
const INMEMORY_MAX_SIZE = 10_000;
const INMEMORY_TTL_MS = 60 * 60 * 1000; // 1 hour
const inMemoryStore = new Map<string, { user: StoredUser; createdAt: number }>();

function cleanupInMemory(): void {
  const now = Date.now();
  for (const [key, entry] of inMemoryStore) {
    if (now - entry.createdAt > INMEMORY_TTL_MS) {
      inMemoryStore.delete(key);
    }
  }
  // Evict oldest if over limit
  if (inMemoryStore.size > INMEMORY_MAX_SIZE) {
    const oldest = inMemoryStore.keys().next().value;
    if (oldest) inMemoryStore.delete(oldest);
  }
}
let postgresRepo: PostgresUserRepository | null = null;

function getRepo(): PostgresUserRepository | null {
  if (process.env.USE_POSTGRES === "true" && !postgresRepo) {
    const conn = process.env.DATABASE_URL || "postgresql://localhost:5432/cybervault";
    postgresRepo = new PostgresUserRepository(conn);
  }
  return postgresRepo;
}

/* ------------------------------------------------------------------ */
/*  Password hashing                                                   */
/* ------------------------------------------------------------------ */

export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(32).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_DIGEST)
    .toString("hex");
  return { hash, salt };
}

export function verifyPassword(
  password: string,
  storedHash: string,
  salt: string,
): boolean {
  const hash = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_DIGEST)
    .toString("hex");
  // Constant-time comparison to prevent timing attacks
  const hashBuf = Buffer.from(hash, "hex");
  const storedBuf = Buffer.from(storedHash, "hex");
  if (hashBuf.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(hashBuf, storedBuf);
}

/* ------------------------------------------------------------------ */
/*  User CRUD — Postgres or in-memory fallback                         */
/* ------------------------------------------------------------------ */

export async function getUserByEmail(email: string): Promise<StoredUser | undefined> {
  const repo = getRepo();
  if (repo) {
    const user = await repo.findByEmail(email);
    return user ?? undefined;
  }
  const entry = inMemoryStore.get(email);
  return entry?.user;
}

/**
 * Look up the caller behind a verified access token (R11).
 *
 * The proof verification for `POST /api/v1/step-up/approve` needs the
 * stored `hash`/`salt` of the AUTHENTICATED user — the token proves who is
 * asking; this supplies the material the passphrase proof is checked
 * against. Fails closed at the caller: an unknown userId is refused, never
 * treated as "no proof required".
 *
 * The in-memory backend is keyed by email (the login shape), so a userId
 * lookup scans — acceptable for the dev/test fallback it serves, where the
 * map is small and approvals are rare.
 */
export async function getUserById(userId: string): Promise<StoredUser | undefined> {
  const repo = getRepo();
  if (repo) {
    const user = await repo.findById(userId);
    return user ?? undefined;
  }
  for (const entry of inMemoryStore.values()) {
    if (entry.user.userId === userId) return entry.user;
  }
  return undefined;
}

export async function createUser(
  email: string,
  password: string,
): Promise<StoredUser> {
  const userId = crypto.randomUUID();
  const { hash, salt } = hashPassword(password);
  const user: StoredUser = { userId, email, hash, salt };

  const repo = getRepo();
  if (repo) {
    await repo.create(user);
  } else {
    cleanupInMemory();
    inMemoryStore.set(email, { user, createdAt: Date.now() });
  }

  return user;
}

/**
 * Interfaz para IncomingMessage con propiedad userId añadida por el middleware
 */
export interface AuthenticatedRequest extends IncomingMessage {
  userId?: string;
}

/**
 * Genera un token JWT para un usuario (access token — short-lived)
 */
export function generateToken(userId: string, secret: string): string {
  const payload = {
    sub: userId,
    jti: crypto.randomUUID(),
    type: "access",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 15 * 60, // 15 minutes
  };

  return jwt.sign(payload, secret);
}

/**
 * Genera un refresh token (long-lived, used to obtain new access tokens)
 */
export function generateRefreshToken(userId: string, secret: string): string {
  const payload = {
    sub: userId,
    jti: crypto.randomUUID(),
    type: "refresh",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
  };

  return jwt.sign(payload, secret);
}

/**
 * Verifica un token JWT y devuelve el userId si es válido.
 *
 * This is a SIGNATURE/EXPIRY check only — it deliberately does not decide
 * whether the token may be used for a given purpose, because the refresh
 * endpoint must be able to inspect a `type === "refresh"` token. Authorization
 * over the token kind lives in `authenticate` (access tokens only) and in
 * `handleRefreshToken` (refresh tokens only).
 */
export function verifyToken(
  token: string,
  secret: string,
): { userId: string; type?: string } | null {
  try {
    const decoded = jwt.verify(token, secret) as { sub: string; type?: string };
    return { userId: decoded.sub, type: decoded.type };
  } catch (error) {
    logger.warn("JWT token verification failed", "Auth", {
      reason: error instanceof Error ? error.message : "invalid token",
    });
    return null;
  }
}

/**
 * The only token kind that may authenticate a request.
 *
 * Access tokens live 15 minutes; refresh tokens live 7 days and exist solely
 * to be exchanged at `/api/v1/auth/refresh`. Before this check existed a
 * 7-day refresh token was accepted by `authenticate` exactly like a 15-minute
 * access token, so a stolen refresh token gave a full week of API access
 * instead of the exchange-for-a-new-access-token flow it was minted for.
 *
 * Fail closed: anything that is not explicitly an access token — a refresh
 * token, or a token minted without a `type` claim — is refused.
 */
const ACCESS_TOKEN_TYPE = "access";

/**
 * Middleware de autenticación para proteger endpoints
 */
export function authenticate(
  req: AuthenticatedRequest,
  res: ServerResponse,
  next: () => void,
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "No token provided" }));
    return;
  }

  const token = authHeader.slice(7); // Quitar 'Bearer '
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "JWT_SECRET not configured" }));
    return;
  }

  const decoded = verifyToken(token, secret);

  // A refresh token must never authenticate: it is only valid at the refresh
  // endpoint, and it outlives an access token by a factor of ~672.
  if (!decoded || decoded.type !== ACCESS_TOKEN_TYPE) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid token" }));
    return;
  }

  // Adjuntar userId al request para uso en handlers
  req.userId = decoded.userId;

  next();
}
