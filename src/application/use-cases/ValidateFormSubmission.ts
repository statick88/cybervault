import type { ISubmissionGate } from '../../domain/ports/ISubmissionGate';
import type { IWarningRenderer } from '../../domain/ports/IWarningRenderer';
import type { IDomainNormalizer } from '../../domain/ports/IDomainNormalizer';
import type { ITrustedDomainStore } from '../../domain/ports/ITrustedDomainStore';
import type { IDomainValidationPipeline, PipelineResult } from '../../domain/services/aitm/domain-validation-pipeline';

/**
 * Maps pipeline risk levels to the ISubmissionGate status vocabulary.
 */
function riskToStatus(risk: PipelineResult['overallRisk']): 'valid' | 'suspicious' | 'malicious' {
  switch (risk) {
    case 'low': return 'valid';
    case 'medium': return 'suspicious';
    case 'high': return 'malicious';
  }
}

export class ValidateFormSubmission {
  constructor(
    private readonly submissionGate: ISubmissionGate,
    private readonly warningRenderer: IWarningRenderer,
    private readonly domainPipeline: IDomainValidationPipeline,
    private readonly domainNormalizer: IDomainNormalizer,
    private readonly trustedDomainStore: ITrustedDomainStore
  ) {
    this.initializeGate();
  }

  private initializeGate(): void {
    this.submissionGate.setValidator(async (rawUrl: string) => {
      const result = await this.validateUrl(rawUrl);
      return { status: riskToStatus(result.overallRisk), reason: result.steps[0]?.reason ?? 'unknown' };
    });

    this.submissionGate.onValidSubmission((form) => {
      this.allowSubmission(form);
    });

    this.submissionGate.onBlockedSubmission((reason, _form) => {
      this.warningRenderer.renderBlockingAlert(reason);
      console.error('[CyberVault] Blocked credential submission:', reason);
    });

    this.submissionGate.register();
  }

  async validateUrl(rawUrl: string): Promise<PipelineResult> {
    const normalized = this.domainNormalizer.normalize(rawUrl);
    const trustedDomains = this.trustedDomainStore.getAll();

    return this.domainPipeline.validate(normalized.hostname, trustedDomains[0] ?? normalized.hostname);
  }

  private allowSubmission(form: HTMLFormElement): void {
    this.submissionGate.submitForm(form);
  }

  destroy(): void {
    this.submissionGate.unregister();
    this.warningRenderer.clearAlert();
  }
}