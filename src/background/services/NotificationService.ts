/**
 * NotificationService para Background
 * Envía notificaciones nativas de Chrome
 */

export type NotificationSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface NotificationParams {
  type: string;
  title: string;
  message: string;
  severity: NotificationSeverity;
}

export class NotificationService {
  async send(params: NotificationParams): Promise<void> {
    try {
      if (!params.title || !params.message) {
        console.warn("[NotificationService] skipped: missing params");
        return;
      }

      const priority = params.severity === "CRITICAL" ? 2 : 1;

      await chrome.notifications.create({
        type: "basic",
        title: params.title,
        message: params.message,
        priority,
        iconUrl: "icon48.png",
      });
    } catch (error) {
      console.warn("[NotificationService] error:", error);
    }
  }
}
