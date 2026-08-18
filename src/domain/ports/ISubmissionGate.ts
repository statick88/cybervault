export interface ISubmissionGate {
  register(): void;
  unregister(): void;
  onValidSubmission(handler: (form: HTMLFormElement) => void): void;
  onBlockedSubmission(handler: (reason: string, form: HTMLFormElement) => void): void;
  setValidator(fn: (url: string) => Promise<{ status: 'valid' | 'suspicious' | 'malicious'; reason: string }>): void;
  submitForm(form: HTMLFormElement): void;
}