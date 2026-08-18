export type { ICryptoService, EncryptedPayload, SignedPayload } from "../ports/ICryptoService";

export interface IIPFSService {
  upload(data: string | Uint8Array, encrypt?: boolean): Promise<string>;
  download(cid: string, decrypt?: boolean): Promise<string>;
  delete(cid: string): Promise<boolean>;
  list(): Promise<string[]>;
  sync(): Promise<{ uploaded: number; downloaded: number }>;
}
