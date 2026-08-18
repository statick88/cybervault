/**
 * Content Fingerprinter — Generación de fingerprints de páginas
 *
 * Genera hashes SHA-256 del DOM normalizado para detectar modificaciones
 * en páginas de login que podrían indicar ataques AiTM o inyección de contenido.
 */

export interface PageFingerprint {
  url: string;
  contentHash: string;
  formStructure: string;
  scriptCount: number;
  externalResources: string[];
  timestamp: number;
}

export class ContentFingerprinter {
  /**
   * Genera fingerprint completo de la página actual
   */
  async generateFingerprint(): Promise<PageFingerprint> {
    const url = window.location.href;
    const contentHash = await this.hashNormalizedDOM();
    const formStructure = this.hashFormStructure();
    const scriptCount = document.querySelectorAll('script').length;
    const externalResources = this.getExternalResources();

    return {
      url,
      contentHash,
      formStructure,
      scriptCount,
      externalResources,
      timestamp: Date.now(),
    };
  }

  /**
   * Compara dos fingerprints y retorna similitud (0-1)
   */
  compareFingerprints(
    a: PageFingerprint,
    b: PageFingerprint
  ): number {
    let matches = 0;
    let total = 0;

    // Content hash match (más importante)
    total += 0.5;
    if (a.contentHash === b.contentHash) matches += 0.5;

    // Form structure match
    total += 0.3;
    if (a.formStructure === b.formStructure) matches += 0.3;

    // Script count similarity
    total += 0.1;
    if (a.scriptCount === b.scriptCount) {
      matches += 0.1;
    } else {
      const maxScripts = Math.max(a.scriptCount, b.scriptCount);
      matches += 0.1 * (1 - Math.abs(a.scriptCount - b.scriptCount) / maxScripts);
    }

    // External resources overlap
    total += 0.1;
    const sharedResources = a.externalResources.filter(
      (r) => b.externalResources.includes(r)
    ).length;
    const maxResources = Math.max(
      a.externalResources.length,
      b.externalResources.length
    );
    matches += 0.1 * (sharedResources / (maxResources || 1));

    return matches / total;
  }

  /**
   * Genera hash SHA-256 del DOM normalizado
   */
  private async hashNormalizedDOM(): Promise<string> {
    const normalizedDOM = this.normalizeDOM(document);
    const encoder = new TextEncoder();
    const data = encoder.encode(normalizedDOM);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Normaliza el DOM para fingerprinting consistente
   * - Elimina contenido dinámico (timestamps, ads)
   * - Mantiene estructura de formularios y scripts
   */
  private normalizeDOM(doc: Document): string {
    const clone = doc.cloneNode(true) as Document;

    // Eliminar elementos dinámicos
    const dynamicSelectors = [
      'script[src*="analytics"]',
      'script[src*="ads"]',
      '[data-timestamp]',
      '.ad-container',
      '.analytics',
    ];

    for (const selector of dynamicSelectors) {
      try {
        clone.querySelectorAll(selector).forEach((el) => el.remove());
      } catch {
        // Selector puede no existir
      }
    }

    // Eliminar atributos dinámicos
    clone.querySelectorAll('*').forEach((el) => {
      el.removeAttribute('data-timestamp');
      el.removeAttribute('data-analytics');
      el.removeAttribute('style');
    });

    // Serializar solo el body
    return clone.body?.innerHTML || '';
  }

  /**
   * Genera hash de la estructura de formularios
   */
  private hashFormStructure(): string {
    const forms = document.querySelectorAll('form');
    const structure: string[] = [];

    forms.forEach((form) => {
      const formStruct: string[] = [];
      formStruct.push(`form[action="${form.getAttribute('action') || ''}"]`);

      form.querySelectorAll('input, select, textarea').forEach((input) => {
        const type = input.getAttribute('type') || 'text';
        const name = input.getAttribute('name') || '';
        const id = input.getAttribute('id') || '';
        formStruct.push(`  input[type="${type}"][name="${name}"][id="${id}"]`);
      });

      structure.push(formStruct.join('\n'));
    });

    return structure.join('\n---\n');
  }

  /**
   * Obtiene lista de recursos externos (scripts, stylesheets, images)
   */
  private getExternalResources(): string[] {
    const resources: string[] = [];
    const origin = window.location.origin;

    // Scripts externos
    document.querySelectorAll('script[src]').forEach((script) => {
      const src = script.getAttribute('src') || '';
      if (src && !src.startsWith(origin)) {
        resources.push(src);
      }
    });

    // Stylesheets externos
    document.querySelectorAll('link[rel="stylesheet"]').forEach((link) => {
      const href = link.getAttribute('href') || '';
      if (href && !href.startsWith(origin)) {
        resources.push(href);
      }
    });

    // Imágenes externas
    document.querySelectorAll('img[src]').forEach((img) => {
      const src = img.getAttribute('src') || '';
      if (src && !src.startsWith(origin) && !src.startsWith('data:')) {
        resources.push(src);
      }
    });

    return resources.sort();
  }
}
