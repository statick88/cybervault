export interface IWarningRenderer {
  renderBlockingAlert(reason: string): void;
  clearAlert(): void;
}