/**
 * IntegrityScore — immutable value object representing browser integrity evaluation.
 *
 * Holds per-dimension scores (0–100) and a computed weighted overall score.
 * Used by IBrowserIntegrityEvaluator to surface integrity evaluation results.
 *
 * Weights (must sum to 1.0):
 *   hostname:0.25, contentHash:0.30, timing:0.15, domIntegrity:0.20, cookieSecurity:0.10
 *
 * @module domain/value-objects/integrity-score
 */

export interface IntegrityScoreProps {
  readonly hostname: number;
  readonly contentHash: number;
  readonly timing: number;
  readonly domIntegrity: number;
  readonly cookieSecurity: number;
}

export interface IntegrityScorePlain extends IntegrityScoreProps {
  readonly overall: number;
  readonly evaluatedAt: number;
}

const WEIGHTS: IntegrityScoreProps = {
  hostname: 0.25,
  contentHash: 0.30,
  timing: 0.15,
  domIntegrity: 0.20,
  cookieSecurity: 0.10,
};

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function computeOverall(props: IntegrityScoreProps): number {
  const weighted =
    props.hostname * WEIGHTS.hostname +
    props.contentHash * WEIGHTS.contentHash +
    props.timing * WEIGHTS.timing +
    props.domIntegrity * WEIGHTS.domIntegrity +
    props.cookieSecurity * WEIGHTS.cookieSecurity;

  return clamp(weighted);
}

export class IntegrityScore {
  readonly hostname: number;
  readonly contentHash: number;
  readonly timing: number;
  readonly domIntegrity: number;
  readonly cookieSecurity: number;
  readonly overall: number;
  readonly evaluatedAt: number;

  private constructor(props: IntegrityScoreProps, evaluatedAt: number) {
    this.hostname = clamp(props.hostname);
    this.contentHash = clamp(props.contentHash);
    this.timing = clamp(props.timing);
    this.domIntegrity = clamp(props.domIntegrity);
    this.cookieSecurity = clamp(props.cookieSecurity);
    this.overall = computeOverall(props);
    this.evaluatedAt = evaluatedAt;
    Object.freeze(this);
  }

  /**
   * Factory — creates a validated, immutable IntegrityScore.
   */
  static create(props: IntegrityScoreProps, evaluatedAt: number): IntegrityScore {
    if (evaluatedAt <= 0) {
      throw new Error('IntegrityScore: evaluatedAt must be positive');
    }

    return new IntegrityScore(props, evaluatedAt);
  }

  toPlainObject(): IntegrityScorePlain {
    return {
      hostname: this.hostname,
      contentHash: this.contentHash,
      timing: this.timing,
      domIntegrity: this.domIntegrity,
      cookieSecurity: this.cookieSecurity,
      overall: this.overall,
      evaluatedAt: this.evaluatedAt,
    };
  }

  static fromPlainObject(obj: IntegrityScorePlain): IntegrityScore {
    return IntegrityScore.create(
      {
        hostname: obj.hostname,
        contentHash: obj.contentHash,
        timing: obj.timing,
        domIntegrity: obj.domIntegrity,
        cookieSecurity: obj.cookieSecurity,
      },
      obj.evaluatedAt,
    );
  }
}
