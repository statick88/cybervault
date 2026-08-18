import { TIMING_THRESHOLDS } from '../../domain/services/aitm/types.js';

export interface TimingMeasurement {
	readonly functionName: string;
	readonly executionTime: number;
	readonly baseline?: number;
	readonly deviation: number;
	readonly severity: 'info' | 'warning' | 'critical';
	readonly timestamp: number;
}

export interface TimingAnalysisConfig {
	readonly iterations: number;
	readonly warmupIterations: number;
	readonly functionsToMeasure: readonly string[];
}

export class TimingAnalyzer {
	private readonly config: TimingAnalysisConfig;
	private readonly baselineCache = new Map<string, number>();

	constructor(config?: Partial<TimingAnalysisConfig>) {
		this.config = {
			iterations: config?.iterations ?? 100,
			warmupIterations: config?.warmupIterations ?? 10,
			functionsToMeasure: config?.functionsToMeasure ?? [
				'crypto.subtle.digest',
				'crypto.subtle.sign',
				'crypto.subtle.verify',
				'crypto.subtle.encrypt',
				'crypto.subtle.decrypt',
				'crypto.subtle.deriveKey',
				'crypto.subtle.generateKey',
				'crypto.subtle.importKey',
				'crypto.subtle.exportKey',
				'crypto.subtle.wrapKey',
				'crypto.subtle.unwrapKey',
				'performance.now',
				'Date.now',
				'Math.random',
				'JSON.parse',
				'JSON.stringify',
			],
		};
	}

	async analyzeNativeFunctionTiming(): Promise<TimingMeasurement[]> {
		const results: TimingMeasurement[] = [];

		for (const funcName of this.config.functionsToMeasure) {
			try {
				const measurement = await this.measureFunction(funcName);
				if (measurement) {
					results.push(measurement);
				}
			} catch {
				// Function not available or measurement failed, skip
			}
		}

		return results;
	}

	async measureFunction(functionName: string): Promise<TimingMeasurement | null> {
		const fn = this.resolveFunction(functionName);
		if (!fn) return null;

		await this.warmup(fn);

		const baseline = this.baselineCache.get(functionName) ?? (await this.establishBaseline(fn));
		this.baselineCache.set(functionName, baseline);

		const times: number[] = [];
		for (let i = 0; i < this.config.iterations; i++) {
			const start = performance.now();
			await this.executeFunction(fn);
			const end = performance.now();
			times.push(end - start);
		}

		const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
		const deviation = Math.abs(avgTime - baseline) / baseline;

		let severity: TimingMeasurement['severity'] = 'info';
		if (deviation > TIMING_THRESHOLDS.critical / 1000) {
			severity = 'critical';
		} else if (deviation > TIMING_THRESHOLDS.warning / 1000) {
			severity = 'warning';
		}

		return {
			functionName,
			executionTime: avgTime,
			baseline,
			deviation,
			severity,
			timestamp: Date.now(),
		};
	}

	private resolveFunction(name: string): ((...args: unknown[]) => Promise<unknown>) | null {
		const parts = name.split('.');
		let obj: unknown = globalThis;

		for (const part of parts) {
			if (obj && typeof obj === 'object' && part in obj) {
				obj = (obj as Record<string, unknown>)[part];
			} else {
				return null;
			}
		}

		if (typeof obj === 'function') {
			return obj.bind(globalThis);
		}

		return null;
	}

	private async warmup(fn: (...args: unknown[]) => Promise<unknown>): Promise<void> {
		for (let i = 0; i < this.config.warmupIterations; i++) {
			try {
				await fn();
			} catch {
				// Ignore warmup errors
			}
		}
	}

	private async establishBaseline(fn: (...args: unknown[]) => Promise<unknown>): Promise<number> {
		const times: number[] = [];
		for (let i = 0; i < 50; i++) {
			const start = performance.now();
			await this.executeFunction(fn);
			const end = performance.now();
			times.push(end - start);
		}
		return times.reduce((a, b) => a + b, 0) / times.length;
	}

	private async executeFunction(fn: (...args: unknown[]) => Promise<unknown>): Promise<unknown> {
		switch (fn.name) {
			case 'digest':
				return fn('SHA-256', new TextEncoder().encode('test'));
			case 'sign':
			case 'verify':
			case 'encrypt':
			case 'decrypt':
			case 'deriveKey':
			case 'generateKey':
			case 'importKey':
			case 'exportKey':
			case 'wrapKey':
			case 'unwrapKey':
				return Promise.resolve();
			case 'now':
				return fn();
			default:
				return fn();
		}
	}

	async detectAutomatedExecution(): Promise<{
		isAutomated: boolean;
		evidence: TimingMeasurement[];
		confidence: number;
	}> {
		const measurements = await this.analyzeNativeFunctionTiming();
		const anomalies = measurements.filter(m => m.severity === 'critical' || m.severity === 'warning');

		const criticalCount = measurements.filter(m => m.severity === 'critical').length;
		const warningCount = measurements.filter(m => m.severity === 'warning').length;

		const isAutomated = criticalCount > 0 || warningCount > 2;
		const confidence = Math.min(1, (criticalCount * 0.3 + warningCount * 0.15));

		return {
			isAutomated,
			evidence: anomalies,
			confidence,
		};
	}

	async measureCrossOriginTiming(url: string): Promise<number> {
		const start = performance.now();
		try {
			await fetch(url, { method: 'HEAD', mode: 'no-cors', cache: 'no-cache' });
		} catch {
			// Expected to fail for cross-origin, we only care about timing
		}
		return performance.now() - start;
	}

	clearBaselineCache(): void {
		this.baselineCache.clear();
	}

	getBaseline(functionName: string): number | undefined {
		return this.baselineCache.get(functionName);
	}
}