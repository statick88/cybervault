/**
 * Domain Validation Benchmark
 * Reproduces the experimental results from the paper v1.0
 *
 * Paper metrics:
 *   - 96.15% detection rate on synthetic attacks (47 scenarios)
 *   - 100% detection on real-world phishing (26 domains)
 *   - <0.001ms exact-match latency
 *   - 0.19ms similarity analysis latency
 *   - 22,177,080 exact-match comparisons/s
 *   - 5,242 similarity comparisons/s
 *
 * Run:
 *   npx tsx benchmarks/domain-validation.bench.ts
 *   npx tsx benchmarks/domain-validation.bench.ts --iterations 50000
 *   npx tsx benchmarks/domain-validation.bench.ts --warmup 1000
 */

import { PipelineOrchestrator } from '../src/domain/services/aitm/pipeline-orchestrator';
import { ExactMatchStep } from '../src/domain/services/aitm/steps/exact-match-step';
import { ConfusableDetectionStep } from '../src/domain/services/aitm/steps/confusable-detection-step';
import { TyposquattingStep } from '../src/domain/services/aitm/steps/typosquatting-step';
import type { RiskLevel } from '../src/domain/services/aitm/domain-validation-pipeline';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
function flag(name: string, fallback: number): number {
  const idx = args.indexOf(name);
  return idx !== -1 ? Number(args[idx + 1]) || fallback : fallback;
}

const EXACT_ITERATIONS = flag('--iterations', 100_000);
const SIMILARITY_ITERATIONS = flag('--similarity-iterations', 10_000);
const WARMUP_ITERATIONS = flag('--warmup', 1_000);

// ---------------------------------------------------------------------------
// Datasets
// ---------------------------------------------------------------------------
const synthetic = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'datasets/synthetic.json'), 'utf-8'),
);
const realWorld = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'datasets/real-world.json'), 'utf-8'),
);

// ---------------------------------------------------------------------------
// Pipeline factory
// ---------------------------------------------------------------------------
function createPipeline(): PipelineOrchestrator {
  const pipeline = new PipelineOrchestrator({
    phaseTimeoutMs: 100,
    totalTimeoutMs: 500,
  });
  pipeline.addStep(new ExactMatchStep());
  pipeline.addStep(new ConfusableDetectionStep());
  pipeline.addStep(new TyposquattingStep(0.85));
  return pipeline;
}

// ---------------------------------------------------------------------------
// Verdict mapping — RiskLevel → allow/block
// ---------------------------------------------------------------------------
function riskToVerdict(risk: RiskLevel): 'allow' | 'block' {
  return risk === 'low' ? 'allow' : 'block';
}

// ---------------------------------------------------------------------------
// Micro-benchmarks
// ---------------------------------------------------------------------------
interface BenchResult {
  latencyMs: number;
  throughput: number;
  iterations: number;
}

async function benchExactMatch(iterations: number): Promise<BenchResult> {
  const pipeline = createPipeline();

  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await pipeline.validate('google.com', 'google.com');
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await pipeline.validate('google.com', 'google.com');
  }
  const elapsed = performance.now() - start;

  return {
    latencyMs: elapsed / iterations,
    throughput: Math.round(iterations / (elapsed / 1000)),
    iterations,
  };
}

async function benchSimilarity(iterations: number): Promise<BenchResult> {
  const pipeline = createPipeline();

  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await pipeline.validate('gooogle.com', 'google.com');
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await pipeline.validate('gooogle.com', 'google.com');
  }
  const elapsed = performance.now() - start;

  return {
    latencyMs: elapsed / iterations,
    throughput: Math.round(iterations / (elapsed / 1000)),
    iterations,
  };
}

// ---------------------------------------------------------------------------
// Dataset evaluation
// ---------------------------------------------------------------------------
interface EvalResult {
  correct: number;
  total: number;
  accuracy: number;
  results: Array<{
    id: string;
    category: string;
    hostname: string;
    expectedDomain: string;
    expectedVerdict: 'allow' | 'block';
    actualVerdict: 'allow' | 'block';
    isCorrect: boolean;
    overallRisk: RiskLevel;
    totalTimeMs: number;
  }>;
}

async function evaluateDataset(
  dataset: { scenarios: Array<{ id: string; category: string; hostname: string; expectedDomain: string; expectedVerdict: string }> },
  pipeline: PipelineOrchestrator,
): Promise<EvalResult> {
  const results: EvalResult['results'] = [];

  for (const scenario of dataset.scenarios) {
    const result = await pipeline.validate(scenario.hostname, scenario.expectedDomain);
    const actualVerdict = riskToVerdict(result.overallRisk);
    const isCorrect = actualVerdict === scenario.expectedVerdict;

    results.push({
      id: scenario.id,
      category: scenario.category,
      hostname: scenario.hostname,
      expectedDomain: scenario.expectedDomain,
      expectedVerdict: scenario.expectedVerdict as 'allow' | 'block',
      actualVerdict,
      isCorrect,
      overallRisk: result.overallRisk,
      totalTimeMs: result.totalTimeMs,
    });
  }

  const correct = results.filter((r) => r.isCorrect).length;
  return {
    correct,
    total: results.length,
    accuracy: Number(((correct / results.length) * 100).toFixed(2)),
    results,
  };
}

// ---------------------------------------------------------------------------
// Category aggregation
// ---------------------------------------------------------------------------
function computeByCategory(
  results: EvalResult['results'],
): Record<string, { correct: number; total: number; accuracy: number }> {
  const byCategory: Record<string, { correct: number; total: number; accuracy: number }> = {};
  for (const r of results) {
    if (!byCategory[r.category]) {
      byCategory[r.category] = { correct: 0, total: 0, accuracy: 0 };
    }
    byCategory[r.category].total++;
    if (r.isCorrect) byCategory[r.category].correct++;
  }
  for (const cat of Object.keys(byCategory)) {
    const s = byCategory[cat];
    s.accuracy = Number(((s.correct / s.total) * 100).toFixed(2));
  }
  return byCategory;
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------
interface BenchmarkReport {
  timestamp: string;
  environment: {
    nodeVersion: string;
    platform: string;
    arch: string;
  };
  config: {
    exactMatchIterations: number;
    similarityIterations: number;
    warmupIterations: number;
  };
  performance: {
    exactMatch: BenchResult;
    similarity: BenchResult;
  };
  synthetic: {
    accuracy: number;
    correct: number;
    total: number;
    byCategory: Record<string, { correct: number; total: number; accuracy: number }>;
  };
  realWorld: {
    accuracy: number;
    correct: number;
    total: number;
    byCategory: Record<string, { correct: number; total: number; accuracy: number }>;
  };
  failedScenarios: Array<{
    id: string;
    category: string;
    hostname: string;
    expectedDomain: string;
    expectedVerdict: string;
    actualVerdict: string;
  }>;
}

function buildReport(
  exactMatch: BenchResult,
  similarity: BenchResult,
  synthEval: EvalResult,
  realEval: EvalResult,
): BenchmarkReport {
  const categorize = (evalResult: EvalResult) => {
    const byCategory: Record<string, { correct: number; total: number; accuracy: number }> = {};
    for (const r of evalResult.results) {
      if (!byCategory[r.category]) {
        byCategory[r.category] = { correct: 0, total: 0, accuracy: 0 };
      }
      byCategory[r.category].total++;
      if (r.isCorrect) byCategory[r.category].correct++;
    }
    for (const cat of Object.keys(byCategory)) {
      const s = byCategory[cat];
      s.accuracy = Number(((s.correct / s.total) * 100).toFixed(2));
    }
    return byCategory;
  };

  const allResults = [...synthEval.results, ...realEval.results];
  const failed = allResults.filter((r) => !r.isCorrect).map((r) => ({
    id: r.id,
    category: r.category,
    hostname: r.hostname,
    expectedDomain: r.expectedDomain,
    expectedVerdict: r.expectedVerdict,
    actualVerdict: r.actualVerdict,
  }));

  return {
    timestamp: new Date().toISOString(),
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    config: {
      exactMatchIterations: EXACT_ITERATIONS,
      similarityIterations: SIMILARITY_ITERATIONS,
      warmupIterations: WARMUP_ITERATIONS,
    },
    performance: {
      exactMatch,
      similarity,
    },
    synthetic: {
      accuracy: synthEval.accuracy,
      correct: synthEval.correct,
      total: synthEval.total,
      byCategory: categorize(synthEval),
    },
    realWorld: {
      accuracy: realEval.accuracy,
      correct: realEval.correct,
      total: realEval.total,
      byCategory: categorize(realEval),
    },
    failedScenarios: failed,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  console.log('=== CyberVault Domain Validation Benchmark ===');
  console.log(`Node ${process.version} | ${process.platform} ${process.arch}\n`);

  // --- Performance benchmarks ---
  console.log('--- Performance Benchmarks ---');
  console.log(`Exact-match: ${EXACT_ITERATIONS.toLocaleString()} iterations (+ ${WARMUP_ITERATIONS.toLocaleString()} warmup)`);
  const exactMatch = await benchExactMatch(EXACT_ITERATIONS);
  console.log(`  Latency:    ${exactMatch.latencyMs.toFixed(4)} ms/op`);
  console.log(`  Throughput: ${exactMatch.throughput.toLocaleString()} comparisons/s`);

  console.log(`Similarity: ${SIMILARITY_ITERATIONS.toLocaleString()} iterations (+ ${WARMUP_ITERATIONS.toLocaleString()} warmup)`);
  const similarity = await benchSimilarity(SIMILARITY_ITERATIONS);
  console.log(`  Latency:    ${similarity.latencyMs.toFixed(4)} ms/op`);
  console.log(`  Throughput: ${similarity.throughput.toLocaleString()} comparisons/s`);

  // --- Synthetic dataset ---
  console.log('\n--- Synthetic Dataset Evaluation ---');
  const pipeline = createPipeline();
  const synthEval = await evaluateDataset(synthetic, pipeline);
  console.log(`Accuracy: ${synthEval.accuracy}% (${synthEval.correct}/${synthEval.total})`);

  for (const [cat, stats] of Object.entries(computeByCategory(synthEval.results))) {
    const pad = cat.padEnd(20);
    console.log(`  ${pad} ${stats.correct}/${stats.total} (${stats.accuracy}%)`);
  }

  // --- Real-world dataset ---
  console.log('\n--- Real-World Phishing Dataset Evaluation ---');
  const realEval = await evaluateDataset(realWorld, pipeline);
  console.log(`Accuracy: ${realEval.accuracy}% (${realEval.correct}/${realEval.total})`);

  for (const [cat, stats] of Object.entries(computeByCategory(realEval.results))) {
    const pad = cat.padEnd(22);
    console.log(`  ${pad} ${stats.correct}/${stats.total} (${stats.accuracy}%)`);
  }

  // --- Failed scenarios ---
  const report = buildReport(exactMatch, similarity, synthEval, realEval);
  if (report.failedScenarios.length > 0) {
    console.log(`\n--- Failed Scenarios (${report.failedScenarios.length}) ---`);
    for (const f of report.failedScenarios) {
      console.log(`  ${f.id} ${f.hostname} → expected ${f.expectedVerdict}, got ${f.actualVerdict}`);
    }
  }

  // --- Paper comparison ---
  console.log('\n--- Paper Comparison ---');
  console.log(`  Paper exact-match latency: <0.001 ms    Measured: ${exactMatch.latencyMs.toFixed(4)} ms`);
  console.log(`  Paper similarity latency:   0.19 ms    Measured: ${similarity.latencyMs.toFixed(4)} ms`);
  console.log(`  Paper exact-match throughput: 22,177,080/s  Measured: ${exactMatch.throughput.toLocaleString()}/s`);
  console.log(`  Paper similarity throughput:   5,242/s  Measured: ${similarity.throughput.toLocaleString()}/s`);
  console.log(`  Paper synthetic accuracy:     96.15%    Measured: ${synthEval.accuracy}%`);
  console.log(`  Paper real-world accuracy:   100.00%    Measured: ${realEval.accuracy}%`);

  // --- Save report ---
  const resultsDir = path.join(__dirname, 'results');
  fs.mkdirSync(resultsDir, { recursive: true });
  const reportPath = path.join(resultsDir, 'benchmark-report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\nReport saved to ${reportPath}`);
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
