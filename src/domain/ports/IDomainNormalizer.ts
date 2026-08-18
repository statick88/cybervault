export interface NormalizedDomain {
  readonly hostname: string;
  readonly isPunycode: boolean;
  readonly originalInput: string;
}

export interface IDomainNormalizer {
  normalize(rawUrlOrHostname: string): NormalizedDomain;
}