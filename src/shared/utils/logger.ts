// Logger utility for CyberVault
// Proporciona logging estructurado con niveles y contexto

import { format } from "date-fns";

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LoggerOptions {
  prefix?: string;
  timestamp?: boolean;
  level?: LogLevel;
}

/**
 * Logger simple pero efectivo para la aplicación
 */
export class Logger {
  private readonly prefix: string;
  private readonly timestampEnabled: boolean;
  private readonly minLevel: LogLevel;

  private static readonly LEVELS: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  constructor(prefix: string = "", options: LoggerOptions = {}) {
    this.prefix = options.prefix || prefix;
    this.timestampEnabled = options.timestamp ?? true;
    this.minLevel = options.level ?? "info";
  }

  private shouldLog(level: LogLevel): boolean {
    return Logger.LEVELS[level] >= Logger.LEVELS[this.minLevel];
  }

  private formatMessage(level: LogLevel, message: string, meta?: any): string {
    const timestamp = this.timestampEnabled
      ? `[${format(new Date(), "yyyy-MM-dd HH:mm:ss.SSS")}]`
      : "";

    const prefix = this.prefix ? `[${this.prefix}]` : "";
    const levelStr = `[${level.toUpperCase()}]`;

    let msg = `${timestamp} ${prefix} ${levelStr} ${message}`;

    if (meta && Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }

    return msg.trim();
  }

  debug(message: string, meta?: any): void {
    if (this.shouldLog("debug")) {
      console.debug(this.formatMessage("debug", message, meta));
    }
  }

  info(message: string, meta?: any): void {
    if (this.shouldLog("info")) {
      console.info(this.formatMessage("info", message, meta));
    }
  }

  warn(message: string, meta?: any): void {
    if (this.shouldLog("warn")) {
      console.warn(this.formatMessage("warn", message, meta));
    }
  }

  error(message: string, meta?: any): void {
    if (this.shouldLog("error")) {
      console.error(this.formatMessage("error", message, meta));
    }
  }
}

// Logger por defecto para la aplicación
export const defaultLogger = new Logger("cybervault");
