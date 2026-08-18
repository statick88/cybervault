/**
 * AiTM Protection Modules — Barrel Export
 */

export { AiTMDetector } from './aitm-detector';
export type {
  AiTMDetectionResult,
  DetectionSignal,
} from './types';

export { DomainValidator } from './domain-validator';
export { ContentFingerprinter } from './content-fingerprinter';
export type { PageFingerprint } from './content-fingerprinter';
export { DOMIntegrityChecker } from './dom-integrity-checker';
export type { DOMAnomaly, DOMIntegrityResult } from './dom-integrity-checker';
