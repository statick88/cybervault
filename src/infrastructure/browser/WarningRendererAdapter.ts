import type { IWarningRenderer } from '../../domain/ports/IWarningRenderer';

export class WarningRendererAdapter implements IWarningRenderer {
  private alertElement: HTMLElement | null = null;
  private readonly shadowRoot: ShadowRoot;

  constructor() {
    const container = document.createElement('div');
    container.style.all = 'initial';
    this.shadowRoot = container.attachShadow({ mode: 'closed' });
    document.documentElement.appendChild(container);
  }

  renderBlockingAlert(reason: string): void {
    this.clearAlert();

    const alert = document.createElement('div');
    alert.style.cssText = `
      all: initial;
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: #dc2626;
      color: white;
      padding: 16px 24px;
      font: 600 14px/1.5 system-ui, -apple-system, sans-serif;
      text-align: center;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      border-bottom: 3px solid #991b1b;
    `;
    alert.textContent = `🛡️ CyberVault: Envío bloqueado — ${reason}`;

    const dismiss = document.createElement('button');
    dismiss.textContent = 'Entendido';
    dismiss.style.cssText = `
      all: initial;
      margin-left: 16px;
      padding: 6px 12px;
      background: white;
      color: #dc2626;
      border-radius: 4px;
      font: 600 12px system-ui;
      cursor: pointer;
    `;
    dismiss.onclick = () => this.clearAlert();
    alert.appendChild(dismiss);

    this.shadowRoot.appendChild(alert);
    this.alertElement = alert;
  }

  clearAlert(): void {
    if (this.alertElement) {
      this.alertElement.remove();
      this.alertElement = null;
    }
  }
}