# CyberVault Domain Validation Benchmarks

Reproducible benchmark suite for the domain validation pipeline, aligned with the metrics reported in the paper:

> "Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage" v1.0

## Quick Start

```bash
npm install   # ensure tsx is available
npm run bench
```

Or run directly:

```bash
npx tsx benchmarks/domain-validation.bench.ts
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--iterations` | 100,000 | Exact-match throughput iterations |
| `--similarity-iterations` | 10,000 | Similarity analysis iterations |
| `--warmup` | 1,000 | Warmup iterations before measurement |

```bash
# Quick run (10x fewer iterations)
npm run bench:quick

# Custom iterations
npx tsx benchmarks/domain-validation.bench.ts --iterations 500000 --warmup 5000
```

## Output

Console output shows:

1. **Performance benchmarks** — latency and throughput for exact-match and similarity analysis
2. **Synthetic dataset evaluation** — accuracy across 47 scenarios by category
3. **Real-world dataset evaluation** — accuracy across 28 phishing domains by category
4. **Paper comparison** — measured values side-by-side with published metrics

A JSON report is saved to `benchmarks/results/benchmark-report.json` after each run.

## Datasets

### Synthetic Dataset (`datasets/synthetic.json`)

47 scenarios testing all detection pathways:

| Category | Count | Description |
|----------|-------|-------------|
| `legitimate` | 20 | 10 exact-match domains + 10 valid subdomains |
| `typosquatting` | 20 | Extra chars, missing chars, char substitution across 5 brands |
| `homograph` | 4 | Cyrillic glyph substitution (о→o, а→a) |
| `unknown` | 3 | Completely unrelated domains |

Each scenario specifies the `hostname` to validate, the `expectedDomain` it impersonates, and the expected `allow`/`block` verdict.

### Real-World Dataset (`datasets/real-world.json`)

28 real-world phishing patterns observed in the wild:

| Category | Count | Examples |
|----------|-------|----------|
| `brand-impersonation` | 15 | paypal-secure.com, apple-verify.org |
| `subdomain-abuse` | 3 | login.google.com.phishing.com |
| `unicode-cyrillic` | 3 | gооgle.com (Cyrillic о) |
| `typosquatting` | 5 | g00gle.com, faceb00k.com |
| `punycode-idn` | 2 | xn--80ak6aa92e.com |

## Paper Metric Mapping

| Paper Metric | Benchmark Code | Expected |
|--------------|----------------|----------|
| Exact-match latency | `benchExactMatch()` | <0.001 ms |
| Similarity latency | `benchSimilarity()` | ~0.19 ms |
| Exact-match throughput | `benchExactMatch()` | >22M comparisons/s |
| Similarity throughput | `benchSimilarity()` | >5,000 comparisons/s |
| Synthetic detection rate | `evaluateDataset(synthetic)` | 96.15% |
| Real-world detection rate | `evaluateDataset(realWorld)` | 100% |

## Report Schema

`benchmarks/results/benchmark-report.json` contains:

```typescript
{
  timestamp: string;
  environment: { nodeVersion, platform, arch };
  config: { exactMatchIterations, similarityIterations, warmupIterations };
  performance: { exactMatch: BenchResult, similarity: BenchResult };
  synthetic: { accuracy, correct, total, byCategory };
  realWorld: { accuracy, correct, total, byCategory };
  failedScenarios: Array<{ id, category, hostname, expectedDomain, expectedVerdict, actualVerdict }>;
}
```

Use this directly in paper v2 for reproducibility claims.

## Architecture

The benchmark exercises the real 3-phase pipeline:

```
ExactMatchStep → ConfusableDetectionStep → TyposquattingStep
```

- **ExactMatch**: RFC 1035 normalization + subdomain check via `dnsNormalize()`
- **ConfusableDetection**: Unicode TR39 homograph detection via `detectConfusables()`
- **Typosquatting**: Levenshtein similarity on registrable domains (threshold: 0.85)

All steps are the production code in `src/domain/services/aitm/steps/`. No mocking.
