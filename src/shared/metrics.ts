/**
 * Lightweight in-memory metrics collector
 * Exposes Prometheus-compatible text format without requiring Prometheus running
 */

type MetricType = "counter" | "gauge" | "histogram";

interface MetricEntry {
  type: MetricType;
  help: string;
  value: number;
  labels?: Record<string, string>;
}

class MetricsCollector {
  private metrics = new Map<string, MetricEntry>();
  private histograms = new Map<string, { values: number[]; buckets: number[] }>();

  counter(name: string, help: string, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    const existing = this.metrics.get(key);
    if (existing) {
      existing.value++;
    } else {
      this.metrics.set(key, { type: "counter", help, value: 1, labels });
    }
  }

  gauge(name: string, help: string, value: number, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    this.metrics.set(key, { type: "gauge", help, value, labels });
  }

  histogram(name: string, help: string, value: number, labels?: Record<string, string>): void {
    const key = this.key(name, labels);
    let hist = this.histograms.get(key);
    if (!hist) {
      hist = { values: [], buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] };
      this.histograms.set(key, hist);
      this.metrics.set(key, { type: "histogram", help, value: 0, labels });
    }
    hist.values.push(value);
  }

  private key(name: string, labels?: Record<string, string>): string {
    if (!labels) return name;
    const sorted = Object.entries(labels).sort().map(([k, v]) => `${k}="${v}"`).join(",");
    return `${name}{${sorted}}`;
  }

  private labelStr(labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) return "";
    const sorted = Object.entries(labels).sort().map(([k, v]) => `${k}="${v}"`).join(",");
    return `{${sorted}}`;
  }

  formatPrometheus(): string {
    const lines: string[] = [];
    const seenHelp = new Set<string>();

    for (const [key, metric] of this.metrics) {
      const baseName = key.split("{")[0];
      if (!seenHelp.has(baseName)) {
        lines.push(`# HELP ${baseName} ${metric.help}`);
        lines.push(`# TYPE ${baseName} ${metric.type}`);
        seenHelp.add(baseName);
      }

      if (metric.type === "histogram") {
        const hist = this.histograms.get(key);
        if (hist && hist.values.length > 0) {
          const sorted = [...hist.values].sort((a, b) => a - b);
          const sum = sorted.reduce((a, b) => a + b, 0);
          const count = sorted.length;
          const base = baseName;
          const labelPrefix = this.labelStr(metric.labels);

          // The `le` label must be merged into the existing label set
          // (single `{...}` group) to keep valid Prometheus text format
          for (const bucket of hist.buckets) {
            const le = sorted.filter((v) => v <= bucket).length;
            const labels = labelPrefix
              ? `${labelPrefix.slice(0, -1)},le="${bucket}"}`
              : `{le="${bucket}"}`;
            lines.push(`${base}_bucket${labels} ${le}`);
          }
          const infLabels = labelPrefix
            ? `${labelPrefix.slice(0, -1)},le="+Inf"}`
            : `{le="+Inf"}`;
          lines.push(`${base}_bucket${infLabels} ${count}`);
          lines.push(`${base}_sum${labelPrefix} ${sum.toFixed(6)}`);
          lines.push(`${base}_count${labelPrefix} ${count}`);
        }
      } else {
        lines.push(`${key} ${metric.value}`);
      }
    }

    return lines.join("\n") + "\n";
  }

  /**
   * Returns the series recorded for a metric family (label sets + values).
   * Used by the health check summary and diagnostics.
   */
  series(
    name: string,
  ): Array<{ labels?: Record<string, string>; value: number }> {
    const result: Array<{ labels?: Record<string, string>; value: number }> = [];
    for (const [key, metric] of this.metrics) {
      if (key === name || key.startsWith(`${name}{`)) {
        result.push({ labels: metric.labels, value: metric.value });
      }
    }
    return result;
  }

  reset(): void {
    this.metrics.clear();
    this.histograms.clear();
  }
}

export const metrics = new MetricsCollector();