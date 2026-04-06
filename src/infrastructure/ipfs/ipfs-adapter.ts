/**
 * IPFS Adapter - Simplified for MVP
 */

import { IIPFSService } from "../../domain/services";
import { EncryptionService } from "../crypto/EncryptionService";
import { HashingService } from "../crypto/HashingService";

export interface IPFSConfig {
  host: string;
  port: number;
  protocol: "http" | "https";
  apiPath?: string;
}

class IPFSAdapter implements IIPFSService {
  private encryptionService: EncryptionService;
  private hashingService: HashingService;
  private gatewayUrl: string;

  constructor(
    config: IPFSConfig,
    encryptionService?: EncryptionService,
    hashingService?: HashingService,
  ) {
    this.encryptionService = encryptionService || new EncryptionService();
    this.hashingService = hashingService || new HashingService();
    this.gatewayUrl = `${config.protocol}://${config.host}:${config.port}`;
  }

  async upload(
    data: string | Uint8Array,
    encrypt: boolean = true,
  ): Promise<string> {
    const dataBytes =
      typeof data === "string" ? new TextEncoder().encode(data) : data;

    let processedData: string;

    if (encrypt) {
      const key = await this.hashingService.hash(Date.now().toString());
      processedData = await this.encryptionService.encrypt(
        typeof data === "string" ? data : new TextDecoder().decode(data),
        key,
      );
    } else {
      processedData =
        typeof data === "string" ? data : new TextDecoder().decode(data);
    }

    const cid = await this.hashingService.hash(processedData);

    await chrome.storage.local.set({ [`ipfs:${cid}`]: processedData });

    return cid;
  }

  async download(cid: string, decrypt: boolean = true): Promise<string> {
    const stored = await chrome.storage.local.get(`ipfs:${cid}`);
    const data = stored[`ipfs:${cid}`] as string;

    if (!data) {
      throw new Error("Data not found");
    }

    if (decrypt) {
      return data;
    }

    return data;
  }

  async delete(cid: string): Promise<boolean> {
    await chrome.storage.local.remove(`ipfs:${cid}`);
    return true;
  }

  async list(): Promise<string[]> {
    const all = await chrome.storage.local.get(null);
    return Object.keys(all)
      .filter((k) => k.startsWith("ipfs:"))
      .map((k) => k.replace("ipfs:", ""));
  }

  async sync(): Promise<{ uploaded: number; downloaded: number }> {
    return { uploaded: 0, downloaded: 0 };
  }
}

export { IPFSAdapter };
export const ipfsAdapter = new IPFSAdapter({
  host: "ipfs.io",
  port: 443,
  protocol: "https",
});
