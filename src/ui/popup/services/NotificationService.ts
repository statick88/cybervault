/**
 * NotificationService
 * Servicio para mostrar notificaciones en el popup con cola y animaciones.
 */

interface Notification {
  message: string;
  type: "success" | "error" | "warning" | "info";
  duration: number;
}

export class NotificationService {
  private queue: Notification[] = [];
  private currentNotification: HTMLElement | null = null;
  private timer: number | null = null;
  private container: HTMLElement | null = null;

  constructor() {
    this.initContainer();
  }

  /**
   * Inicializa o obtiene el contenedor de notificaciones.
   */
  private initContainer(): void {
    this.container = document.getElementById("notification-container");

    if (!this.container) {
      this.container = document.createElement("div");
      this.container.id = "notification-container";
      document.body.appendChild(this.container);
    }
  }

  /**
   * Muestra una notificación.
   * Si ya hay una visible, se encola para mostrar después.
   */
  public showNotification(
    message: string,
    type: "success" | "error" | "warning" | "info" = "info",
    duration: number = 3000,
  ): void {
    this.queue.push({ message, type, duration });
    this.processQueue();
  }

  /**
   * Procesa la cola: si no hay notificación visible, muestra la siguiente.
   */
  private processQueue(): void {
    if (this.currentNotification || this.queue.length === 0) {
      return;
    }

    const notification = this.queue.shift();
    if (!notification) {
      return;
    }

    this.displayNotification(notification);
  }

  /**
   * Crea y muestra una notificación en el DOM.
   */
  private displayNotification(notification: Notification): void {
    if (!this.container) {
      return;
    }

    const element = document.createElement("div");
    element.className = `notification notification-${notification.type}`;
    element.textContent = notification.message;

    element.addEventListener("click", () => {
      this.dismissNotification();
    });

    this.container.appendChild(element);
    this.currentNotification = element;

    this.timer = window.setTimeout(() => {
      this.dismissNotification();
    }, notification.duration);
  }

  /**
   * Descartar la notificación actual y mostrar la siguiente en cola.
   */
  private dismissNotification(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.currentNotification) {
      this.currentNotification.classList.add("fade-out");

      this.currentNotification.addEventListener(
        "animationend",
        () => {
          if (this.currentNotification && this.currentNotification.parentNode) {
            this.currentNotification.parentNode.removeChild(
              this.currentNotification,
            );
          }
          this.currentNotification = null;
          this.processQueue();
        },
        { once: true },
      );
    }
  }

  /**
   * Limpia todas las notificaciones pendientes y la actual.
   */
  public clearAll(): void {
    this.queue = [];

    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.currentNotification && this.currentNotification.parentNode) {
      this.currentNotification.parentNode.removeChild(this.currentNotification);
      this.currentNotification = null;
    }
  }

  /**
   * Obtiene el número de notificaciones en cola.
   */
  public getQueueLength(): number {
    return this.queue.length;
  }

  /**
   * Verifica si hay una notificación visible actualmente.
   */
  public isShowing(): boolean {
    return this.currentNotification !== null;
  }
}

export const notificationService = new NotificationService();
