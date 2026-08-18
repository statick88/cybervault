import type { ISubmissionGate } from '../../domain/ports/ISubmissionGate';

export class SubmissionGateAdapter implements ISubmissionGate {
  private boundHandler: ((event: SubmitEvent) => void) | null = null;
  private validHandler: ((form: HTMLFormElement) => void) | null = null;
  private blockedHandler: ((reason: string, form: HTMLFormElement) => void) | null = null;
  private readonly interceptorId = Symbol('cybervault-interceptor');
  private validator: ((url: string) => Promise<{ status: 'valid' | 'suspicious' | 'malicious'; reason: string }>) | null = null;
  private originalSubmit: ((this: HTMLFormElement) => void) | null = null;

  register(): void {
    if (this.boundHandler) return;

    this.boundHandler = this.handleSubmit.bind(this);

    document.documentElement.addEventListener('submit', this.boundHandler, {
      capture: true,
      passive: false
    });

    this.patchNativeSubmit();
  }

  unregister(): void {
    if (this.boundHandler) {
      document.documentElement.removeEventListener('submit', this.boundHandler, true);
      this.boundHandler = null;
    }
    this.restoreNativeSubmit();
  }

  onValidSubmission(handler: (form: HTMLFormElement) => void): void {
    this.validHandler = handler;
  }

  onBlockedSubmission(handler: (reason: string, form: HTMLFormElement) => void): void {
    this.blockedHandler = handler;
  }

  setValidator(fn: (url: string) => Promise<{ status: 'valid' | 'suspicious' | 'malicious'; reason: string }>): void {
    this.validator = fn;
  }

  submitForm(form: HTMLFormElement): void {
    if (this.originalSubmit) {
      this.originalSubmit.call(form);
    }
  }

  private handleSubmit(event: SubmitEvent): void {
    event.preventDefault();
    event.stopImmediatePropagation();

    const target = event.target;
    if (!(target instanceof HTMLFormElement)) {
      return;
    }

    const form = target;

    if ((form as any)[this.interceptorId] === 'processing') {
      return;
    }
    (form as any)[this.interceptorId] = 'processing';

    const formAction = form.action || window.location.href;
    this.validateAndDecide(form, formAction);
  }

  private async validateAndDecide(form: HTMLFormElement, currentUrl: string): Promise<void> {
    if (!this.validator) return;

    const result = await this.validator(currentUrl);

    (form as any)[this.interceptorId] = 'idle';

    if (result.status === 'valid') {
      this.validHandler?.(form);
    } else {
      this.blockedHandler?.(result.reason, form);
    }
  }

  private patchNativeSubmit(): void {
    if (this.originalSubmit) return;

    this.originalSubmit = HTMLFormElement.prototype.submit;

    const originalSubmitRef = this.originalSubmit;

    HTMLFormElement.prototype.submit = function(this: HTMLFormElement) {
      const event = new SubmitEvent('submit', {
        bubbles: true,
        cancelable: true
      });

      (this as any)[Symbol('cybervault-programmatic')] = true;

      const dispatched = this.dispatchEvent(event);

      if (dispatched && !event.defaultPrevented) {
        originalSubmitRef.call(this);
      }
    };
  }

  private restoreNativeSubmit(): void {
    if (this.originalSubmit) {
      HTMLFormElement.prototype.submit = this.originalSubmit;
      this.originalSubmit = null;
    }
  }
}