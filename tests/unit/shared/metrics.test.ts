import { metrics } from "../../../src/shared/metrics";

describe("MetricsCollector", () => {
  beforeEach(() => {
    metrics.reset();
  });

  describe("counter", () => {
    it("creates a counter with value 1 on first call", () => {
      metrics.counter("http_requests", "Total HTTP requests");

      const output = metrics.formatPrometheus();
      expect(output).toContain("# HELP http_requests Total HTTP requests");
      expect(output).toContain("# TYPE http_requests counter");
      expect(output).toContain("http_requests 1");
    });

    it("increments counter on subsequent calls", () => {
      metrics.counter("http_requests", "Total HTTP requests");
      metrics.counter("http_requests", "Total HTTP requests");
      metrics.counter("http_requests", "Total HTTP requests");

      const output = metrics.formatPrometheus();
      expect(output).toContain("http_requests 3");
    });

    it("tracks counters with different labels separately", () => {
      metrics.counter("http_requests", "Total", { method: "GET" });
      metrics.counter("http_requests", "Total", { method: "POST" });
      metrics.counter("http_requests", "Total", { method: "GET" });

      const output = metrics.formatPrometheus();
      expect(output).toContain('http_requests{method="GET"} 2');
      expect(output).toContain('http_requests{method="POST"} 1');
    });
  });

  describe("gauge", () => {
    it("sets gauge value", () => {
      metrics.gauge("active_connections", "Active connections", 5);

      const output = metrics.formatPrometheus();
      expect(output).toContain("# TYPE active_connections gauge");
      expect(output).toContain("active_connections 5");
    });

    it("overwrites gauge value on subsequent calls", () => {
      metrics.gauge("active_connections", "Active connections", 5);
      metrics.gauge("active_connections", "Active connections", 10);

      const output = metrics.formatPrometheus();
      expect(output).toContain("active_connections 10");
    });

    it("tracks gauges with labels independently", () => {
      metrics.gauge("queue_depth", "Queue depth", 3, { queue: "email" });
      metrics.gauge("queue_depth", "Queue depth", 7, { queue: "sms" });

      const output = metrics.formatPrometheus();
      expect(output).toContain('queue_depth{queue="email"} 3');
      expect(output).toContain('queue_depth{queue="sms"} 7');
    });
  });

  describe("histogram", () => {
    it("records observations and produces bucket output", () => {
      metrics.histogram("request_duration", "Request duration", 0.05);
      metrics.histogram("request_duration", "Request duration", 0.15);
      metrics.histogram("request_duration", "Request duration", 0.5);

      const output = metrics.formatPrometheus();
      expect(output).toContain("# TYPE request_duration histogram");
      expect(output).toContain("request_duration_bucket{le=\"0.01\"} 0");
      expect(output).toContain("request_duration_bucket{le=\"0.05\"} 1");
      expect(output).toContain("request_duration_bucket{le=\"0.1\"} 1");
      expect(output).toContain("request_duration_bucket{le=\"0.25\"} 2");
      expect(output).toContain("request_duration_bucket{le=\"0.5\"} 3");
      expect(output).toContain('request_duration_bucket{le="+Inf"} 3');
      expect(output).toContain("request_duration_count 3");
    });

    it("calculates sum correctly", () => {
      metrics.histogram("request_duration", "Request duration", 0.1);
      metrics.histogram("request_duration", "Request duration", 0.2);

      const output = metrics.formatPrometheus();
      expect(output).toContain("request_duration_sum 0.300000");
    });

    it("tracks histograms with labels", () => {
      metrics.histogram("request_duration", "Duration", 0.1, { endpoint: "/api" });
      metrics.histogram("request_duration", "Duration", 0.5, { endpoint: "/api" });

      const output = metrics.formatPrometheus();
      expect(output).toContain('request_duration_bucket{endpoint="/api",le="0.01"} 0');
      expect(output).toContain('request_duration_bucket{endpoint="/api",le="0.1"} 1');
      expect(output).toContain('request_duration_bucket{endpoint="/api",le="0.5"} 2');
      expect(output).toContain('request_duration_count{endpoint="/api"} 2');
    });
  });

  describe("formatPrometheus", () => {
    it("produces valid Prometheus text format with HELP and TYPE", () => {
      metrics.counter("requests", "Total requests");
      metrics.gauge("temperature", "Current temperature", 22.5);

      const output = metrics.formatPrometheus();
      const lines = output.trim().split("\n");

      expect(lines[0]).toBe("# HELP requests Total requests");
      expect(lines[1]).toBe("# TYPE requests counter");
      expect(lines[2]).toBe("requests 1");

      // Find the gauge lines
      const helpLine = lines.findIndex((l) => l.startsWith("# HELP temperature"));
      expect(helpLine).toBeGreaterThanOrEqual(0);
      expect(lines[helpLine + 1]).toBe("# TYPE temperature gauge");
    });

    it("only emits HELP/TYPE once per metric family", () => {
      metrics.counter("requests", "Total requests");
      metrics.counter("requests", "Total requests");

      const output = metrics.formatPrometheus();
      const helpCount = (output.match(/# HELP requests/g) || []).length;
      const typeCount = (output.match(/# TYPE requests/g) || []).length;

      expect(helpCount).toBe(1);
      expect(typeCount).toBe(1);
    });

    it("returns empty string when no metrics exist", () => {
      const output = metrics.formatPrometheus();
      expect(output).toBe("\n");
    });
  });

  describe("reset", () => {
    it("clears all metrics", () => {
      metrics.counter("requests", "Total requests");
      metrics.gauge("connections", "Active", 5);
      metrics.histogram("duration", "Duration", 0.1);

      metrics.reset();

      const output = metrics.formatPrometheus();
      expect(output).not.toContain("requests");
      expect(output).not.toContain("connections");
      expect(output).not.toContain("duration");
    });
  });

  describe("series", () => {
    it("returns series data for a named metric", () => {
      metrics.counter("hits", "Total hits", { path: "/a" });
      metrics.counter("hits", "Total hits", { path: "/b" });

      const series = metrics.series("hits");
      expect(series).toHaveLength(2);
      expect(series.map((s) => s.value).sort()).toEqual([1, 1]);
    });
  });
});
