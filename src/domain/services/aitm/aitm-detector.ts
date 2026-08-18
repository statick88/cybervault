/**
 * AiTM Detector — Detección de Ataques Adversario-en-el-Medio
 *
 * Valida la autenticidad de la página actual usando múltiples señales:
 * 1. Hostname validation (contra dominios registrados)
 * 2. Content fingerprinting (SHA-256 del DOM normalizado)
 * 3. Timing analysis (detección de proxy por latencia)
 * 4. DOM integrity (detección de scripts/formularios modificados)
 * 5. Cookie security
 * 6. Integrity Score (aggregated multi-vector assessment)
 * 7. Fingerprint Anomalies (baseline deviation detection)
 *
 * Retorna: { isLegitimate, riskScore, signals, recommendation }
 * Uses centralized types from ./types.ts for consistency
 */

import type { PageFingerprint } from './content-fingerprinter';
import { ContentFingerprinter } from './content-fingerprinter';
import { DOMIntegrityChecker } from './dom-integrity-checker';
import type { DetectionSignal, AiTMDetectionResult, DetectionSignalType, DetectionSignalStatus } from './types';
import { computeRiskScore, getRecommendation, THRESHOLDS } from './types';

export class AiTMDetector {
  private fingerprinter: ContentFingerprinter;
  private integrityChecker: DOMIntegrityChecker;
  private timingSamples: number[] = [];
  private knownFingerprints: Map<string, PageFingerprint> = new Map();

  constructor() {
    this.fingerprinter = new ContentFingerprinter();
    this.integrityChecker = new DOMIntegrityChecker();
  }

  /**
   * Registra un fingerprint conocido de una página legítima
   */
  registerKnownFingerprint(domain: string, fingerprint: PageFingerprint): void {
    this.knownFingerprints.set(domain, fingerprint);
  }

  /**
   * Valida la página actual contra el dominio esperado
   * Uses centralized types and computeRiskScore for consistency
   */
  async validatePage(
    expectedDomain: string,
    options?: { skipContentCheck?: boolean; skipDOMCheck?: boolean }
  ): Promise<AiTMDetectionResult> {
    const url = window.location.href;
    const startTime = performance.now();
    const signals: DetectionSignal[] = [];

    // 1. Hostname Validation (siempre)
    const hostnameSignal = this.validateHostname(expectedDomain);
    signals.push(hostnameSignal);

    // 2. Content Fingerprinting (opcional)
    if (!options?.skipContentCheck) {
      const contentSignal = await this.validateContentFingerprint(expectedDomain);
      signals.push(contentSignal);
    }

    // 3. DOM Integrity (opcional)
    if (!options?.skipDOMCheck) {
      const domSignal = this.validateDOMIntegrity();
      signals.push(domSignal);
    }

    // 4. Timing Analysis
    const endTime = performance.now();
    const validationTime = endTime - startTime;
    this.timingSamples.push(validationTime);
    const timingSignal = this.validateTiming(validationTime);
    signals.push(timingSignal);

    // 5. Cookie Security Check
    const cookieSignal = this.validateCookieSecurity();
    signals.push(cookieSignal);

    // Calculate aggregate risk score using centralized computeRiskScore
    const riskScore = computeRiskScore(signals);
    const recommendation = getRecommendation(riskScore);

    return {
      riskScore,
      signals,
      recommendation,
      evaluatedAt: Date.now(),
    };
  }

  /**
   * Validación de hostname contra dominio esperado
   * Returns DetectionSignal with score (0-100 risk) for computeRiskScore integration
   */
  private validateHostname(expectedDomain: string): DetectionSignal {
    const currentHostname = window.location.hostname.toLowerCase();
    const normalizedExpected = expectedDomain.toLowerCase();

    // Exact match
    if (currentHostname === normalizedExpected) {
      return {
        type: 'hostname',
        status: 'pass',
        score: 0,
        confidence: 1.0,
        weight: 0.25,
        details: `Hostname matches exactly: ${currentHostname}`,
      };
    }

    // Subdomain match (e.g., www.google.com vs google.com)
    if (currentHostname.endsWith(`.${normalizedExpected}`)) {
      return {
        type: 'hostname',
        status: 'warn',
        score: 25,
        confidence: 0.8,
        weight: 0.25,
        details: `Subdomain match: ${currentHostname} → ${normalizedExpected}`,
      };
    }

    // No match — possible AiTM or phishing
    return {
      type: 'hostname',
      status: 'fail',
      score: 100,
      confidence: 0.95,
      weight: 0.25,
      details: `Hostname mismatch: ${currentHostname} ≠ ${normalizedExpected}`,
    };
  }

  /**
   * Validación de fingerprint de contenido
   */
  private async validateContentFingerprint(
    expectedDomain: string
  ): Promise<DetectionSignal> {
    try {
      const fingerprint = await this.fingerprinter.generateFingerprint();
      const known = this.knownFingerprints.get(expectedDomain);

      if (!known) {
        // No fingerprint known — first visit or domain not registered
        return {
          type: 'content-hash',
          status: 'warn',
          score: 30,
          confidence: 0.5,
          weight: 0.30,
          details: 'No known fingerprint for this domain (first visit)',
        };
      }

      const similarity = this.fingerprinter.compareFingerprints(
        fingerprint,
        known
      );

      if (similarity >= 0.9) {
        return {
          type: 'content-hash',
          status: 'pass',
          score: 0,
          confidence: 0.9,
          weight: 0.30,
          details: `Content fingerprint matches (similarity: ${(similarity * 100).toFixed(1)}%)`,
        };
      } else if (similarity >= 0.7) {
        return {
          type: 'content-hash',
          status: 'warn',
          score: 50,
          confidence: 0.7,
          weight: 0.30,
          details: `Content fingerprint partially matches (similarity: ${(similarity * 100).toFixed(1)}%)`,
        };
      } 
        return {
          type: 'content-hash',
          status: 'fail',
          score: 100,
          confidence: 0.85,
          weight: 0.30,
          details: `Content fingerprint mismatch (similarity: ${(similarity * 100).toFixed(1)}%)`,
        };
      
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return {
        type: 'content-hash',
        status: 'warn',
        score: 50,
        confidence: 0.3,
        weight: 0.30,
        details: `Content fingerprinting failed: ${msg}`,
      };
    }
  }

  /**
   * Validación de integridad del DOM
   */
  private validateDOMIntegrity(): DetectionSignal {
    try {
      const result = this.integrityChecker.checkPageIntegrity();

      if (result.isIntact) {
        return {
          type: 'dom-integrity',
          status: 'pass',
          score: 0,
          confidence: 0.85,
          weight: 0.20,
          details: 'DOM integrity verified — no anomalies detected',
        };
      }

      const criticalAnomalies = result.anomalies.filter(
        (a) => a.severity === 'critical'
      );
      const warnings = result.anomalies.filter(
        (a) => a.severity === 'warning'
      );

      if (criticalAnomalies.length > 0) {
        return {
          type: 'dom-integrity',
          status: 'fail',
          score: 100,
          confidence: 0.9,
          weight: 0.20,
          details: `Critical DOM anomalies: ${criticalAnomalies.map((a) => a.type).join(', ')}`,
        };
      } else if (warnings.length > 0) {
        return {
          type: 'dom-integrity',
          status: 'warn',
          score: 50,
          confidence: 0.7,
          weight: 0.20,
          details: `DOM warnings: ${warnings.map((a) => a.type).join(', ')}`,
        };
      }

      return {
        type: 'dom-integrity',
        status: 'pass',
        score: 10,
        confidence: 0.8,
        weight: 0.20,
        details: 'DOM integrity check passed with minor anomalies',
      };
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return {
        type: 'dom-integrity',
        status: 'warn',
        score: 50,
        confidence: 0.3,
        weight: 0.20,
        details: `DOM integrity check failed: ${msg}`,
      };
    }
  }

  /**
   * Análisis de timing para detección de proxy
   */
  private validateTiming(validationTime: number): DetectionSignal {
    // Proxy AiTM típicamente añade 100-500ms de latencia
    const PROXY_THRESHOLD = 200; // ms

    if (validationTime < PROXY_THRESHOLD) {
      return {
        type: 'timing',
        status: 'pass',
        score: 0,
        confidence: 0.8,
        weight: 0.15,
        details: `Validation completed in ${validationTime.toFixed(1)}ms (normal)`,
      };
    } else if (validationTime < PROXY_THRESHOLD * 2) {
      return {
        type: 'timing',
        status: 'warn',
        score: 50,
        confidence: 0.5,
        weight: 0.15,
        details: `Validation took ${validationTime.toFixed(1)}ms (elevated — possible proxy)`,
      };
    } 
      return {
        type: 'timing',
        status: 'fail',
        score: 100,
        confidence: 0.7,
        weight: 0.15,
        details: `Validation took ${validationTime.toFixed(1)}ms (high latency — likely proxy)`,
      };
    
  }

  /**
   * Validación de seguridad de cookies
   */
  private validateCookieSecurity(): DetectionSignal {
    try {
      // Verificar cookies existentes
      const cookieString = document.cookie || '';
      
      // Verificar SameSite attribute si hay cookies
      const hasSameSite = cookieString.includes('SameSite=');

      // Verificar que no hay scripts externos accediendo a cookies
      const scripts = document.querySelectorAll('script');
      let externalScriptAccess = false;

      for (const script of Array.from(scripts)) {
        const src = script.getAttribute('src') || '';
        if (src && !src.startsWith(window.location.origin)) {
          externalScriptAccess = true;
          break;
        }
      }

      if (externalScriptAccess) {
        return {
          type: 'cookie-security',
          status: 'warn',
          score: 50,
          confidence: 0.6,
          weight: 0.10,
          details: 'External scripts detected — potential cookie theft vector',
        };
      }

      // Verificar protección SameSite
      if (cookieString && !hasSameSite) {
        return {
          type: 'cookie-security',
          status: 'warn',
          score: 30,
          confidence: 0.5,
          weight: 0.10,
          details: 'Cookies without SameSite attribute detected',
        };
      }

      return {
        type: 'cookie-security',
        status: 'pass',
        score: 0,
        confidence: 0.7,
        weight: 0.10,
        details: 'No obvious cookie security issues detected',
      };
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return {
        type: 'cookie-security',
        status: 'warn',
        score: 50,
        confidence: 0.3,
        weight: 0.10,
        details: `Cookie security check incomplete: ${msg}`,
      };
    }
  }

  /**
   * Obtiene estadísticas de validación para logging
   */
  getValidationStats(): {
    sampleCount: number;
    avgLatency: number;
    maxLatency: number;
    minLatency: number;
  } {
    if (this.timingSamples.length === 0) {
      return { sampleCount: 0, avgLatency: 0, maxLatency: 0, minLatency: 0 };
    }

    const sum = this.timingSamples.reduce((a, b) => a + b, 0);
    return {
      sampleCount: this.timingSamples.length,
      avgLatency: sum / this.timingSamples.length,
      maxLatency: Math.max(...this.timingSamples),
      minLatency: Math.min(...this.timingSamples),
    };
  }
}
