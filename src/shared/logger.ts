/**
 * Structured logger for CyberVault
 * Replaces console.log/warn/error with structured JSON logging
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: string;
  data?: Record<string, unknown>;
  error?: string;
}

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const MIN_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL as LogLevel] ?? LOG_LEVELS.info;

function formatEntry(entry: LogEntry): string {
  if (process.env.LOG_FORMAT === "json") {
    return JSON.stringify(entry);
  }
  // Human-readable format for development
  const ctx = entry.context ? `[${entry.context}]` : "";
  const data = entry.data ? ` ${JSON.stringify(entry.data)}` : "";
  const err = entry.error ? ` error=${entry.error}` : "";
  return `${entry.timestamp} ${entry.level.toUpperCase().padEnd(5)} ${ctx} ${entry.message}${data}${err}`;
}

function log(level: LogLevel, message: string, context?: string, data?: Record<string, unknown>, error?: string): void {
  if (LOG_LEVELS[level] < MIN_LEVEL) return;

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    context,
    data,
    error,
  };

  const formatted = formatEntry(entry);

  switch (level) {
    case "error":
      console.error(formatted);
      break;
    case "warn":
      console.warn(formatted);
      break;
    default:
      console.log(formatted);
  }
}

export const logger = {
  debug: (message: string, context?: string, data?: Record<string, unknown>) =>
    log("debug", message, context, data),
  info: (message: string, context?: string, data?: Record<string, unknown>) =>
    log("info", message, context, data),
  warn: (message: string, context?: string, data?: Record<string, unknown>) =>
    log("warn", message, context, data),
  error: (message: string, context?: string, data?: Record<string, unknown>, error?: string) =>
    log("error", message, context, data, error),
};