import type {
	IBrowserIntegrityEvaluator,
	BrowserIntegrityEvaluationResult,
	IntegrityEvaluationContext,
} from '../../domain/ports/interfaces/IBrowserIntegrityEvaluator.js';
import type { PageFingerprint, AiTMDetectionResult, DetectionSignal } from '../../domain/services/aitm/types.js';
import { IntegrityScore } from '../../domain/value-objects/integrity-score.js';
import { FingerprintAnomaly } from '../../domain/value-objects/fingerprint-anomaly.js';
import { computeRiskScore, getRecommendation } from '../../domain/services/aitm/types.js';

import { DOMIntegrityChecker } from '../../domain/services/aitm/dom-integrity-checker.js';
import { TimingAnalyzer } from '../security/TimingAnalyzer.js';

export class BrowserIntegrityEvaluatorAdapter implements IBrowserIntegrityEvaluator {
	private readonly domIntegrityChecker: DOMIntegrityChecker;
	private readonly timingAnalyzer: TimingAnalyzer;
	private readonly _evaluatorId = 'browser-integrity-evaluator-v1';
	private readonly _version = '1.0.0';

	constructor() {
		this.domIntegrityChecker = new DOMIntegrityChecker();
		this.timingAnalyzer = new TimingAnalyzer();
	}

	get evaluatorId(): string {
		return this._evaluatorId;
	}

	get version(): string {
		return this._version;
	}

	async evaluate(context: IntegrityEvaluationContext): Promise<BrowserIntegrityEvaluationResult> {
		const { currentFingerprint, baselineFingerprint, timestamp } = context;

		const timingSignals = await this.timingAnalyzer.analyzeNativeFunctionTiming();
		const domCheckResult = this.domIntegrityChecker.checkPageIntegrity();
		const domScore = this.computeDOMScore(domCheckResult);
		const fingerprintAnomalies = this.compareFingerprints(currentFingerprint, baselineFingerprint);

		const signals: DetectionSignal[] = [
			{
				type: 'hostname',
				status: this.getSignalStatus(currentFingerprint.url, baselineFingerprint?.url),
				score: this.scoreHostname(currentFingerprint.url, baselineFingerprint?.url),
				confidence: 0.9,
				weight: 0.25,
				details: `Hostname comparison: ${currentFingerprint.url}`,
			},
			{
				type: 'content-hash',
				status: this.getSignalStatus(
					currentFingerprint.contentHash,
					baselineFingerprint?.contentHash,
				),
				score: this.scoreContentHash(currentFingerprint.contentHash, baselineFingerprint?.contentHash),
				confidence: 0.95,
				weight: 0.30,
				details: `Content hash: ${currentFingerprint.contentHash.slice(0, 16)}...`,
			},
			{
				type: 'timing',
				status: this.getTimingSignalStatus(timingSignals),
				score: this.scoreTiming(timingSignals),
				confidence: 0.8,
				weight: 0.15,
				details: `Timing analysis: ${timingSignals.length} native functions measured`,
			},
			{
				type: 'dom-integrity',
				status: this.getDOMSignalStatus(domCheckResult),
				score: domScore,
				confidence: 0.85,
				weight: 0.20,
				details: `DOM anomalies: ${domCheckResult.anomalies.length}`,
			},
			{
				type: 'cookie-security',
				status: this.getCookieSignalStatus(),
				score: this.scoreCookieSecurity(),
				confidence: 0.7,
				weight: 0.10,
				details: 'Cookie security assessment',
			},
		];

		const riskScore = computeRiskScore(signals);
		const recommendation = getRecommendation(riskScore);

		const integrityScore = IntegrityScore.create({
			hostname: signals.find(s => s.type === 'hostname')?.score ?? 0,
			contentHash: signals.find(s => s.type === 'content-hash')?.score ?? 0,
			timing: signals.find(s => s.type === 'timing')?.score ?? 0,
			domIntegrity: signals.find(s => s.type === 'dom-integrity')?.score ?? 0,
			cookieSecurity: signals.find(s => s.type === 'cookie-security')?.score ?? 0,
		}, timestamp);

		const baseResult: AiTMDetectionResult = {
			riskScore,
			signals,
			recommendation,
			evaluatedAt: timestamp,
		};

		return {
			...baseResult,
			integrityScore,
			fingerprintAnomalies,
			evaluationContext: context,
		};
	}

	async quickEvaluate(fingerprint: PageFingerprint): Promise<AiTMDetectionResult> {
		const context: IntegrityEvaluationContext = {
			currentFingerprint: fingerprint,
			url: fingerprint.url,
			timestamp: Date.now(),
		};
		const result = await this.evaluate(context);
		return {
			riskScore: result.riskScore,
			signals: result.signals,
			recommendation: result.recommendation,
			evaluatedAt: result.evaluatedAt,
		};
	}

	private compareFingerprints(
		current: PageFingerprint,
		baseline?: PageFingerprint,
	): FingerprintAnomaly[] {
		if (!baseline) return [];

		const anomalies: FingerprintAnomaly[] = [];
		const detectedAt = Date.now();

		if (current.contentHash !== baseline.contentHash) {
			anomalies.push(
				FingerprintAnomaly.create(
					'content-hash-mismatch',
					'critical',
					baseline.contentHash,
					current.contentHash,
					'Page content hash differs from baseline — possible DOM poisoning or content injection',
					detectedAt,
				),
			);
		}

		if (current.formStructure !== baseline.formStructure) {
			anomalies.push(
				FingerprintAnomaly.create(
					'form-structure-modified',
					'critical',
					baseline.formStructure,
					current.formStructure,
					'Form structure has been modified — possible credential harvesting injection',
					detectedAt,
				),
			);
		}

		if (current.scriptCount !== baseline.scriptCount) {
			const severity = Math.abs(current.scriptCount - baseline.scriptCount) > 3 ? 'critical' : 'warning';
			anomalies.push(
				FingerprintAnomaly.create(
					'script-count-anomaly',
					severity,
					String(baseline.scriptCount),
					String(current.scriptCount),
					`Script count changed from ${baseline.scriptCount} to ${current.scriptCount} — possible script injection`,
					detectedAt,
				),
			);
		}

		const unexpectedResources = current.externalResources.filter(
			r => !baseline.externalResources.includes(r),
		);
		for (const resource of unexpectedResources) {
			anomalies.push(
				FingerprintAnomaly.create(
					'unexpected-external-resource',
					'warning',
					'none',
					resource,
					`Unexpected external resource loaded: ${resource}`,
					detectedAt,
				),
			);
		}

		const missingResources = baseline.externalResources.filter(
			r => !current.externalResources.includes(r),
		);
		for (const resource of missingResources) {
			anomalies.push(
				FingerprintAnomaly.create(
					'missing-expected-resource',
					'warning',
					resource,
					'none',
					`Expected external resource missing: ${resource}`,
					detectedAt,
				),
			);
		}

		const timestampDiff = Math.abs(current.timestamp - baseline.timestamp);
		if (timestampDiff > 300000) {
			anomalies.push(
				FingerprintAnomaly.create(
					'timestamp-skew',
					'info',
					String(baseline.timestamp),
					String(current.timestamp),
					`Large timestamp difference between fingerprints: ${timestampDiff}ms`,
					detectedAt,
				),
			);
		}

		return anomalies;
	}

	private getSignalStatus(current: string, baseline?: string): DetectionSignal['status'] {
		if (!baseline) return 'pass';
		return current === baseline ? 'pass' : 'fail';
	}

	private scoreHostname(current: string, baseline?: string): number {
		if (!baseline) return 100;
		try {
			const currentHost = new URL(current).hostname;
			const baselineHost = new URL(baseline).hostname;
			return currentHost === baselineHost ? 100 : 0;
		} catch {
			return 0;
		}
	}

	private scoreContentHash(current: string, baseline?: string): number {
		if (!baseline) return 100;
		return current === baseline ? 100 : 0;
	}

	private getTimingSignalStatus(timingSignals: Awaited<ReturnType<TimingAnalyzer['analyzeNativeFunctionTiming']>>): DetectionSignal['status'] {
		const hasCritical = timingSignals.some(s => s.severity === 'critical');
		const hasWarning = timingSignals.some(s => s.severity === 'warning');
		if (hasCritical) return 'fail';
		if (hasWarning) return 'warn';
		return 'pass';
	}

	private scoreTiming(timingSignals: Awaited<ReturnType<TimingAnalyzer['analyzeNativeFunctionTiming']>>): number {
		if (timingSignals.length === 0) return 100;
		const criticalCount = timingSignals.filter(s => s.severity === 'critical').length;
		const warningCount = timingSignals.filter(s => s.severity === 'warning').length;
		const baseScore = 100 - (criticalCount * 30) - (warningCount * 10);
		return Math.max(0, baseScore);
	}

	private getDOMSignalStatus(domResult: { anomalies: { severity: string }[]; isIntact: boolean; riskLevel: string }): DetectionSignal['status'] {
		const hasCritical = domResult.anomalies.some(a => a.severity === 'critical');
		const hasWarning = domResult.anomalies.some(a => a.severity === 'warning');
		if (hasCritical) return 'fail';
		if (hasWarning) return 'warn';
		return 'pass';
	}

	private computeDOMScore(domResult: { anomalies: { severity: string }[]; isIntact: boolean; riskLevel: string }): number {
		if (domResult.isIntact) return 100;
		const criticalCount = domResult.anomalies.filter(a => a.severity === 'critical').length;
		const warningCount = domResult.anomalies.filter(a => a.severity === 'warning').length;
		const infoCount = domResult.anomalies.filter(a => a.severity === 'info').length;
		const baseScore = 100 - (criticalCount * 25) - (warningCount * 10) - (infoCount * 2);
		return Math.max(0, baseScore);
	}

	private getCookieSignalStatus(): DetectionSignal['status'] {
		return 'pass';
	}

	private scoreCookieSecurity(): number {
		return 100;
	}
}