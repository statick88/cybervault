export interface ValidationRequest {
  readonly url: string;
  readonly timestamp: number;
}

export interface ValidationResponse {
  readonly status: 'valid' | 'suspicious' | 'malicious';
  readonly reason: string;
  readonly latencyMs: number;
  readonly step: string;
}