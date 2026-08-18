import Redis, { type RedisOptions } from "ioredis";
import { REDIS_CONFIG } from "../../shared/config";
import { logger } from "../../shared/logger";

let client: Redis | null = null;
let connecting = false;

function createRedisClient(): Redis {
  const clientOptions: RedisOptions = {
    lazyConnect: true,
    retryStrategy(times: number): number | null {
      if (times > 3) {
        logger.warn(
          "Redis max retry attempts reached",
          "RedisClient",
          { attempts: times },
        );
        return null;
      }
      const delay = Math.min(times * 200, 2000);
      logger.debug(
        `Redis retry attempt ${times}, waiting ${delay}ms`,
        "RedisClient",
      );
      return delay;
    },
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    connectTimeout: 5000,
  };

  if (REDIS_CONFIG.password) {
    clientOptions.password = REDIS_CONFIG.password;
  }

  const redis = new Redis({
    host: REDIS_CONFIG.host,
    port: REDIS_CONFIG.port,
    db: REDIS_CONFIG.db,
    ...clientOptions,
  });

  redis.on("error", (err: Error) => {
    logger.error(
      "Redis connection error",
      "RedisClient",
      { host: REDIS_CONFIG.host, port: REDIS_CONFIG.port },
      err.message,
    );
  });

  redis.on("connect", () => {
    logger.info("Redis connected", "RedisClient", {
      host: REDIS_CONFIG.host,
      port: REDIS_CONFIG.port,
    });
  });

  redis.on("ready", () => {
    logger.info("Redis ready", "RedisClient");
  });

  redis.on("close", () => {
    logger.info("Redis connection closed", "RedisClient");
  });

  return redis;
}

export async function connectRedis(): Promise<void> {
  if (!process.env.REDIS_HOST) {
    logger.info(
      "REDIS_HOST not set — Redis disabled",
      "RedisClient",
    );
    return;
  }

  if (client?.status === "ready" || connecting) {
    return;
  }

  connecting = true;
  try {
    client = createRedisClient();
    await client.connect();
    connecting = false;
  } catch (err) {
    connecting = false;
    logger.warn(
      "Redis unavailable — server continues without cache",
      "RedisClient",
      { host: REDIS_CONFIG.host, port: REDIS_CONFIG.port, error: err instanceof Error ? err.message : String(err) },
    );
    client = null;
  }
}

export async function disconnectRedis(): Promise<void> {
  if (client) {
    try {
      await client.quit();
      logger.info("Redis disconnected gracefully", "RedisClient");
    } catch {
      logger.warn("Redis disconnect error (forced)", "RedisClient");
      client.disconnect();
    }
    client = null;
  }
}

export function getRedisClient(): Redis | null {
  return client;
}

export function isRedisConnected(): boolean {
  return client?.status === "ready";
}
