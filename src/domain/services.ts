// Domain Service Interfaces - Simplified for MVP
// Contratos para servicios de infraestructura

/**
 * Servicio de Criptografía - MVP Version
 */
export interface ICryptoService {
  encrypt(data: string, key: string): Promise<string>;
  decrypt(encryptedData: string, key: string): Promise<string>;
  hash(data: string): Promise<string>;
  deriveKey(password: string, salt: string): Promise<string>;
}

/**
 * Servicio de Almacenamiento IPFS - MVP Version
 */
export interface IIPFSService {
  upload(data: string | Uint8Array, encrypt?: boolean): Promise<string>;
  download(cid: string, decrypt?: boolean): Promise<string>;
  delete(cid: string): Promise<boolean>;
  list(): Promise<string[]>;
  sync(): Promise<{ uploaded: number; downloaded: number }>;
}

/**
 * Servicio de Auditoría de Seguridad
 */
export interface IAuditService {
  scanVault(vaultId: string): Promise<SecurityReport>;
  scanSystem(): Promise<SecurityReport>;
  verifySecurityConfig(): Promise<SecurityConfigCheck>;
}

export interface SecurityReport {
  vulnerabilities: {
    title: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    description: string;
    recommendation?: string;
  }[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scannedAt: Date;
}

export interface SecurityConfigCheck {
  passed: boolean;
  checks: {
    name: string;
    status: "PASS" | "FAIL" | "WARN";
    message?: string;
  }[];
}
