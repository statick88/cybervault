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
 * Genera un token JWT para un usuario
 */
export function generateToken(userId: string, secret: string): string {
  const payload = {
    sub: userId,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 horas
  };

  return jwt.sign(payload, secret);
}

/**
 * Verifica un token JWT y devuelve el userId si es válido
 */
export function verifyToken(
  token: string,
  secret: string,
): { userId: string } | null {
  try {
    const decoded = jwt.verify(token, secret) as { sub: string };
    return { userId: decoded.sub };
  } catch (error) {
    logger.warn("JWT token verification failed", "Auth", {
      reason: error instanceof Error ? error.message : "invalid token",
    });
    return null;
  }
}

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

  if (!decoded) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Invalid token" }));
    return;
  }

  // Adjuntar userId al request para uso en handlers
  req.userId = decoded.userId;

  next();
}
