/**
 * IPFS Adapter — Real IPFS HTTP API integration via ipfs-http-client.
 *
 * Connects to a Kubo RPC API (default http://127.0.0.1:5001).
 * Falls back to an in-memory store when the node is unreachable so that the
 * rest of the application keeps working without IPFS.
 */

import type { IIPFSService } from "../../domain/services";
import { EncryptionService } from "../crypto/EncryptionService";
import { HashingService } from "../crypto/HashingService";
import { withRetry } from "../../shared/retry";
import { logger } from "../../shared/logger";
import { CircuitBreaker } from "../../shared/circuit-breaker";
import * as crypto from "crypto";

// Errores de red que justifican reintentar la operación IPFS
const IPFS_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "fetch failed"];

export interface IPFSConfig {
  host: string;
  port: number;
  protocol: "http" | "https";
  apiPath?: string;
}

interface IPFSClient {
  add(data: Uint8Array | string, options?: { pin?: boolean }): Promise<{ cid: { toString(): string }; path: string; size: number }>;
  cat(cid: string): AsyncIterable<Uint8Array>;
  pin: {
    add(cid: string): Promise<{ cid: { toString(): string } }>;
    rm(cid: string): Promise<void>;
    ls(): AsyncIterable<{ cid: { toString(): string } }>;
  };
  id(): Promise<{ id: string }>;
}

function buildApiUrl(config: IPFSConfig): string {
  const base = `${config.protocol}://${config.host}:${config.port}`;
  return config.apiPath ? `${base}${config.apiPath}` : `${base}/api/v0`;
}

class IPFSAdapter implements IIPFSService {
  private encryptionService: EncryptionService;
  private hashingService: HashingService;
  private config: IPFSConfig;
  private clientPromise: Promise<IPFSClient | null>;
  private circuitBreaker: CircuitBreaker;
  private memoryStore = new Map<string, string>();
  /** Encryption key per CID — needed to decrypt content on download */
  private keyByCid = new Map<string, string>();

  constructor(
    config: IPFSConfig,
    encryptionService?: EncryptionService,
    hashingService?: HashingService,
  ) {
    this.config = config;
    this.encryptionService = encryptionService || new EncryptionService();
    this.hashingService = hashingService || new HashingService();
    this.circuitBreaker = new CircuitBreaker();
    this.clientPromise = this.createClient();
  }

  private async createClient(): Promise<IPFSClient | null> {
    try {
      const mod = (await import("ipfs-http-client")) as unknown as {
        create: (opts?: any) => IPFSClient;
      };

      const url = buildApiUrl(this.config);
      const client = mod.create({ url });

      await client.id();
      return client;
    } catch (err) {
      logger.warn(
        `[IPFS] Unable to connect to ${buildApiUrl(this.config)} — using in-memory fallback.`,
        "IPFS",
      );
      return null;
    }
  }

  private async getClient(): Promise<IPFSClient | null> {
    return this.clientPromise;
  }

  /**
   * Verifica que el nodo IPFS esté accesible
   */
  async isHealthy(): Promise<boolean> {
    // Circuit OPEN → node is failing; report unhealthy without probing
    if (this.circuitBreaker.getState() === "open") {
      return false;
    }

    const client = await this.getClient();
    if (!client) {
      return false;
    }

    try {
      // Health check runs through the breaker so failures also count toward
      // opening the circuit
      await this.circuitBreaker.execute(() => client.id());
      return true;
    } catch {
      return false;
    }
  }

  async upload(
    data: string | Uint8Array,
    encrypt: boolean = true,
  ): Promise<string> {
    let processedData: string;
    let key: string | undefined;

    if (encrypt) {
      // Generate a proper random 256-bit key instead of a predictable timestamp
      const keyBytes = new Uint8Array(32);
      crypto.getRandomValues(keyBytes);
      key = Array.from(keyBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      processedData = await this.encryptionService.encrypt(
        typeof data === "string" ? data : new TextDecoder().decode(data),
        key,
      );
    } else {
      processedData =
        typeof data === "string" ? data : new TextDecoder().decode(data);
    }

    const client = await this.getClient();
    if (!client) {
      const cid = await this.hashingService.hash(processedData);
      this.memoryStore.set(cid, processedData);
      if (key) this.keyByCid.set(cid, key);
      return cid;
    }

    const encoder = new TextEncoder();
    const cid = await this.circuitBreaker
      .execute(() =>
        withRetry(
          async () => {
            const result = await client.add(encoder.encode(processedData), {
              pin: true,
            });
            return result.cid.toString();
          },
          { maxAttempts: 3, retryableErrors: IPFS_RETRYABLE_ERRORS },
        ),
      )
      .catch(async () => {
        // Fallback: almacenar en memoria si el nodo IPFS no responde tras los
        // reintentos o si el circuit breaker está OPEN (degradación controlada)
        const fallbackCid = await this.hashingService.hash(processedData);
        this.memoryStore.set(fallbackCid, processedData);
        if (key) this.keyByCid.set(fallbackCid, key);
        return fallbackCid;
      });
    if (key) this.keyByCid.set(cid, key);
    return cid;
  }

  async download(cid: string, decrypt: boolean = true): Promise<string> {
    const client = await this.getClient();
    let data: string;

    if (!client) {
      const stored = this.memoryStore.get(cid);
      if (!stored) {
        throw new Error("Data not found");
      }
      data = stored;
    } else {
      try {
        data = await this.circuitBreaker.execute(() =>
          withRetry(
            async () => {
              const chunks: Uint8Array[] = [];
              for await (const chunk of client.cat(cid)) {
                chunks.push(chunk);
              }

              const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
              const merged = new Uint8Array(totalLength);
              let offset = 0;
              for (const chunk of chunks) {
                merged.set(chunk, offset);
                offset += chunk.length;
              }

              return new TextDecoder().decode(merged);
            },
            { maxAttempts: 3, retryableErrors: IPFS_RETRYABLE_ERRORS },
          ),
        );
      } catch {
        // Fallback: leer desde memoria si el nodo IPFS no responde tras los
        // reintentos o si el circuit breaker está OPEN (degradación controlada)
        const stored = this.memoryStore.get(cid);
        if (!stored) {
          throw new Error("Data not found");
        }
        data = stored;
      }
    }

    if (decrypt) {
      const key = this.keyByCid.get(cid);
      if (key) {
        return this.encryptionService.decrypt(data, key);
      }
      // No key available for this CID — data was either uploaded without
      // encryption or encrypted by a different process. Return as-is rather
      // than corrupting it with a wrong-key decrypt attempt.
      return data;
    }

    return data;
  }

  async delete(cid: string): Promise<boolean> {
    const client = await this.getClient();
    if (!client) {
      return this.memoryStore.delete(cid);
    }

    try {
      await client.pin.rm(cid);
      return true;
    } catch {
      return false;
    }
  }

  async list(): Promise<string[]> {
    const client = await this.getClient();
    if (!client) {
      return Array.from(this.memoryStore.keys());
    }

    const cids: string[] = [];
    for await (const pin of client.pin.ls()) {
      cids.push(pin.cid.toString());
    }
    return cids;
  }

  async sync(): Promise<{ uploaded: number; downloaded: number }> {
    const client = await this.getClient();
    if (!client) {
      return { uploaded: 0, downloaded: 0 };
    }

    const remoteCids = await this.list();
    const localCids = Array.from(this.memoryStore.keys());

    const onlyOnRemote = remoteCids.filter((c) => !localCids.includes(c));
    const onlyOnLocal = localCids.filter((c) => !remoteCids.includes(c));

    let downloaded = 0;
    for (const cid of onlyOnRemote) {
      try {
        const data = await this.download(cid, false);
        this.memoryStore.set(cid, data);
        downloaded++;
      } catch {
        // skip unreachable CIDs
      }
    }

    let uploaded = 0;
    for (const cid of onlyOnLocal) {
      try {
        const data = this.memoryStore.get(cid);
        if (data) {
          const encoder = new TextEncoder();
          await client.add(encoder.encode(data), { pin: true });
          uploaded++;
        }
      } catch {
        // skip failed uploads
      }
    }

    return { uploaded, downloaded };
  }
}

function createIPFSAdapter(config?: Partial<IPFSConfig>): IPFSAdapter {
  const envUrl = process.env.IPFS_API_URL;

  let resolvedConfig: IPFSConfig;

  if (envUrl) {
    try {
      const parsed = new URL(envUrl);
      resolvedConfig = {
        host: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === "https:" ? 443 : 5001,
        protocol: parsed.protocol.replace(":", "") as "http" | "https",
        apiPath: parsed.pathname !== "/" ? parsed.pathname : undefined,
      };
    } catch {
      resolvedConfig = {
        host: "127.0.0.1",
        port: 5001,
        protocol: "http",
      };
    }
  } else {
    resolvedConfig = {
      host: "127.0.0.1",
      port: 5001,
      protocol: "http",
    };
  }

  if (config) {
    resolvedConfig = { ...resolvedConfig, ...config };
  }

  return new IPFSAdapter(resolvedConfig);
}

export { IPFSAdapter, createIPFSAdapter };

export const ipfsAdapter = createIPFSAdapter();
