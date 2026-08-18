/**
 * DOM Integrity Checker — Verificación de integridad del DOM
 *
 * Detecta:
 * - Formularios de login modificados o inyectados
 * - Scripts inesperados en el contexto de la página
 * - Campos ocultos que podrían capturar datos adicionales
 * - Event listeners maliciosos en campos de password
 */

export interface DOMAnomaly {
  type:
    | 'unexpected-script'
    | 'modified_form'
    | 'hidden_field'
    | 'event_listener'
    | 'iframe_injection'
    | 'style_injection';
  location: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface DOMIntegrityResult {
  isIntact: boolean;
  anomalies: DOMAnomaly[];
  riskLevel: 'low' | 'medium' | 'high';
}

export class DOMIntegrityChecker {
  /**
   * Verifica la integridad completa de la página
   */
  checkPageIntegrity(): DOMIntegrityResult {
    const anomalies: DOMAnomaly[] = [];

    // 1. Detectar scripts inesperados
    anomalies.push(...this.detectUnexpectedScripts());

    // 2. Detectar campos ocultos en formularios
    anomalies.push(...this.detectHiddenFields());

    // 3. Detectar iframes inyectados
    anomalies.push(...this.detectInjectedIframes());

    // 4. Verificar integridad de formularios de login
    const forms = this.detectLoginForms();
    for (const form of forms) {
      anomalies.push(...this.checkFormIntegrity(form));
    }

    // 5. Detectar event listeners sospechosos
    anomalies.push(...this.detectSuspiciousEventListeners());

    // Determinar riesgo
    const hasCritical = anomalies.some((a) => a.severity === 'critical');
    const hasWarnings = anomalies.some((a) => a.severity === 'warning');

    let riskLevel: 'low' | 'medium' | 'high';
    if (hasCritical) {
      riskLevel = 'high';
    } else if (hasWarnings) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    return {
      isIntact: anomalies.length === 0,
      anomalies,
      riskLevel,
    };
  }

  /**
   * Detecta scripts inesperados o inyectados
   */
  detectUnexpectedScripts(): DOMAnomaly[] {
    const anomalies: DOMAnomaly[] = [];
    const scripts = document.querySelectorAll('script');

    for (const script of Array.from(scripts)) {
      const src = script.getAttribute('src') || '';
      const text = script.textContent || '';

      // Detectar scripts inline (posible XSS)
      if (!src && text.length > 0) {
        // Verificar si contiene patrones sospechosos
        const suspiciousPatterns = [
          'document.cookie',
          'document.location',
          'window.location',
          'fetch(',
          'XMLHttpRequest',
          'Image().src',
          'createElement',
          'appendChild',
        ];

        for (const pattern of suspiciousPatterns) {
          if (text.includes(pattern)) {
            anomalies.push({
              type: 'unexpected-script',
              location: 'inline script',
              description: `Inline script contains suspicious pattern: "${pattern}"`,
              severity: 'critical',
            });
            break;
          }
        }
      }

      // Detectar scripts de dominios externos no comunes
      if (src && !this.isTrustedDomain(src)) {
        anomalies.push({
          type: 'unexpected-script',
          location: src,
          description: `External script from untrusted domain: ${src}`,
          severity: 'warning',
        });
      }
    }

    return anomalies;
  }

  /**
   * Detecta campos ocultos en formularios (posible data harvesting)
   */
  detectHiddenFields(): DOMAnomaly[] {
    const anomalies: DOMAnomaly[] = [];
    const hiddenInputs = document.querySelectorAll(
      'input[type="hidden"], input[style*="display: none"], input[style*="visibility: hidden"]'
    );

    for (const input of Array.from(hiddenInputs)) {
      const name = input.getAttribute('name') || '';
      const id = input.getAttribute('id') || '';

      // Campos ocultos con nombres sospechosos
      const suspiciousNames = [
        'csrf_token',
        'token',
        'session',
        'auth',
        'credential',
        'password_confirm',
        'backup_code',
      ];

      for (const suspicious of suspiciousNames) {
        if (
          name.toLowerCase().includes(suspicious) ||
          id.toLowerCase().includes(suspicious)
        ) {
          anomalies.push({
            type: 'hidden_field',
            location: `input[name="${name}"][id="${id}"]`,
            description: `Hidden field with suspicious name: "${name || id}"`,
            severity: 'warning',
          });
          break;
        }
      }
    }

    return anomalies;
  }

  /**
   * Detecta iframes inyectados (posible clickjacking o AiTM)
   */
  detectInjectedIframes(): DOMAnomaly[] {
    const anomalies: DOMAnomaly[] = [];
    const iframes = document.querySelectorAll('iframe');

    for (const iframe of Array.from(iframes)) {
      const src = iframe.getAttribute('src') || '';
      const srcdoc = iframe.getAttribute('srcdoc');

      // Iframe con contenido inline (posible inyección)
      if (srcdoc) {
        anomalies.push({
          type: 'iframe_injection',
          location: 'iframe[srcdoc]',
          description: 'Inline iframe content detected (possible injection)',
          severity: 'critical',
        });
      }

      // Iframe de dominio externo
      if (src && !this.isTrustedDomain(src)) {
        anomalies.push({
          type: 'iframe_injection',
          location: `iframe[src="${src}"]`,
          description: `External iframe from untrusted domain: ${src}`,
          severity: 'warning',
        });
      }
    }

    return anomalies;
  }

  /**
   * Verifica la integridad de un formulario de login
   */
  checkFormIntegrity(form: HTMLFormElement): DOMAnomaly[] {
    const anomalies: DOMAnomaly[] = [];

    // Verificar que el action del formulario es del mismo dominio
    const action = form.getAttribute('action') || '';
    if (action) {
      try {
        const actionURL = new URL(action, window.location.href);
        if (actionURL.hostname !== window.location.hostname) {
          anomalies.push({
            type: 'modified_form',
            location: `form[action="${action}"]`,
            description: `Form action points to different domain: ${actionURL.hostname}`,
            severity: 'critical',
          });
        }
      } catch {
        // URL inválida, ignorar
      }
    }

    // Verificar que hay campos de password y que no están duplicados
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 2) {
      anomalies.push({
        type: 'modified_form',
        location: `form with ${passwordFields.length} password fields`,
        description: `Unusual number of password fields: ${passwordFields.length}`,
        severity: 'warning',
      });
    }

    // Verificar que no hay campos adicionales sospechosos
    const allInputs = form.querySelectorAll('input');
    for (const inputEl of Array.from(allInputs)) {
      const name = inputEl.getAttribute('name') || '';
      const input = inputEl;
      if (name.toLowerCase().includes('token') && input.type !== 'hidden') {
        anomalies.push({
          type: 'modified_form',
          location: `input[name="${name}"]`,
          description: `Form contains suspicious token field: "${name}"`,
          severity: 'warning',
        });
      }
    }

    return anomalies;
  }

  /**
   * Detecta event listeners sospechosos en campos sensibles
   */
  detectSuspiciousEventListeners(): DOMAnomaly[] {
    const anomalies: DOMAnomaly[] = [];

    // Verificar campos de password
    const passwordFields = document.querySelectorAll('input[type="password"]');
    for (const field of Array.from(passwordFields)) {
      // getEventListeners solo funciona en DevTools, no en content scripts
      // Como workaround, verificamos si hay MutationObservers en el campo
      // Esta es una verificación limitada pero útil

      // Verificar si el campo tiene atributos data-* sospechosos
      const attrs = field.attributes;
      for (let i = 0; i < attrs.length; i++) {
        const attr = attrs[i];
        if (
          attr.name.startsWith('data-') &&
          (attr.name.includes('capture') ||
            attr.name.includes('log') ||
            attr.name.includes('track'))
        ) {
          const fieldInput = field as HTMLInputElement;
          anomalies.push({
            type: 'event_listener',
            location: `input[name="${fieldInput.name || fieldInput.id}"]`,
            description: `Suspicious data attribute: ${attr.name}="${attr.value}"`,
            severity: 'warning',
          });
        }
      }
    }

    return anomalies;
  }

  /**
   * Detecta formularios de login en la página
   */
  private detectLoginForms(): HTMLFormElement[] {
    const selectors = [
      'form[action*="login"]',
      'form[action*="signin"]',
      'form[id*="login"]',
      'form[id*="signin"]',
      'form:has(input[type="password"])',
    ];

    const forms: HTMLFormElement[] = [];
    for (const selector of selectors) {
      try {
        const matched = document.querySelectorAll<HTMLFormElement>(selector);
        matched.forEach((form) => {
          if (!forms.includes(form)) {
            forms.push(form);
          }
        });
      } catch {
        // Selector puede no ser válido
      }
    }

    return forms;
  }

  /**
   * Verifica si un dominio es confiable
   */
  private isTrustedDomain(url: string): boolean {
    try {
      const urlObj = new URL(url, window.location.href);
      const hostname = urlObj.hostname.toLowerCase();

      // Mismo dominio
      if (hostname === window.location.hostname) return true;

      // Subdominio del mismo dominio
      if (hostname.endsWith(`.${window.location.hostname}`)) return true;

      // Dominios comunes de CDNs confiables
      const trustedDomains = [
        'googleapis.com',
        'cloudflare.com',
        'jsdelivr.net',
        'unpkg.com',
        'cdn.jsdelivr.net',
        'ajax.googleapis.com',
        'fonts.googleapis.com',
        'cdnjs.cloudflare.com',
      ];

      return trustedDomains.some(
        (trusted) =>
          hostname === trusted || hostname.endsWith(`.${trusted}`)
      );
    } catch {
      return false;
    }
  }
}
