import { CacheService } from "./cache-service";
import { logger } from "../../shared/logger";

const SESSION_TTL = 1800; // 30 minutes
const SESSION_PREFIX = "cybervault:sessions";

export interface SessionData {
  userId: string;
  username: string;
  loginTime: string;
}

export class SessionStore {
  private cache: CacheService;

  constructor(ttl = SESSION_TTL) {
    this.cache = new CacheService(SESSION_PREFIX, ttl);
  }

  async create(
    sessionId: string,
    data: SessionData,
  ): Promise<boolean> {
    try {
      const success = await this.cache.set(sessionId, data, SESSION_TTL);
      if (success) {
        logger.debug("Session created", "SessionStore", {
          sessionId,
          userId: data.userId,
        });
      }
      return success;
    } catch (err) {
      logger.error(
        "Session create error",
        "SessionStore",
        { sessionId },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }

  async get(sessionId: string): Promise<SessionData | null> {
    try {
      return await this.cache.get<SessionData>(sessionId);
    } catch (err) {
      logger.error(
        "Session get error",
        "SessionStore",
        { sessionId },
        err instanceof Error ? err.message : String(err),
      );
      return null;
    }
  }

  async destroy(sessionId: string): Promise<boolean> {
    try {
      const deleted = await this.cache.del(sessionId);
      logger.debug("Session destroyed", "SessionStore", { sessionId });
      return deleted > 0;
    } catch (err) {
      logger.error(
        "Session destroy error",
        "SessionStore",
        { sessionId },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }

  async refresh(sessionId: string): Promise<boolean> {
    try {
      const data = await this.cache.get<SessionData>(sessionId);
      if (!data) return false;
      return await this.cache.set(sessionId, data, SESSION_TTL);
    } catch (err) {
      logger.error(
        "Session refresh error",
        "SessionStore",
        { sessionId },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }
}

export const sessionStore = new SessionStore();
