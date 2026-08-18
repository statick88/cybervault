import type { IDomainNormalizer, NormalizedDomain } from '../../domain/ports/IDomainNormalizer';

export class DomainNormalizerAdapter implements IDomainNormalizer {
  normalize(rawInput: string): NormalizedDomain {
    const originalInput = rawInput;
    let input = rawInput.trim();

    if (!input.includes('://') && !input.startsWith('//')) {
      input = 'https://' + input;
    }

    let url: URL;
    try {
      url = new URL(input);
    } catch {
      return {
        hostname: this.sanitizeHostname(input),
        isPunycode: false,
        originalInput
      };
    }

    let hostname = url.hostname;

    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1);
    }

    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.slice(1, -1);
    }

    const isPunycode = hostname.startsWith('xn--');
    hostname = hostname.toLowerCase();
    hostname = this.sanitizeHostname(hostname);

    return {
      hostname,
      isPunycode,
      originalInput
    };
  }

  private sanitizeHostname(host: string): string {
    return host
      .split('.')
      .map(label => label.replace(/[^a-z0-9-]/g, ''))
      .filter(label => label.length > 0 && label.length <= 63)
      .slice(0, 127)
      .join('.')
      .slice(0, 253);
  }
}