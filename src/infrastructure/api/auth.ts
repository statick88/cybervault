/**
 * Módulo de autenticación JWT para Cyber Vault API
 */

import * as jwt from "jsonwebtoken";
import { IncomingMessage, ServerResponse } from "http";

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
