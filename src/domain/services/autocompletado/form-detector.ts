/**
 * Detección de Formularios de Registro
 * Detecta formularios de creación de cuenta en páginas web
 */

export interface FormField {
  type: string;
  name: string;
  id: string;
  placeholder: string;
  autocomplete: string;
}

export interface DetectedForm {
  fields: FormField[];
  hasEmailField: boolean;
  hasPasswordField: boolean;
  hasPasswordFieldConfirmation: boolean;
  formElement: HTMLFormElement | null;
}

export class FormDetector {
  /**
   * Detecta si un elemento es un formulario de registro
   * @param element Elemento HTML a analizar
   * @returns Información del formulario detectado
   */
  static detectRegistrationForm(element: HTMLElement): DetectedForm | null {
    if (!element) return null;

    // Buscar el formulario padre más cercano
    const formElement = element.closest('form') as HTMLFormElement;
    if (!formElement) return null;

    // Analizar campos del formulario
    const fields = this.extractFormFields(formElement);
    
    // Verificar si es un formulario de registro (tiene email y password)
    const hasEmailField = fields.some(f => 
      f.type === 'email' || 
      f.autocomplete.includes('email') || 
      f.name.toLowerCase().includes('email') ||
      f.id.toLowerCase().includes('email')
    );
    
    const hasPasswordField = fields.some(f => 
      f.type === 'password' || 
      f.autocomplete.includes('password') || 
      f.name.toLowerCase().includes('password') ||
      f.id.toLowerCase().includes('password')
    );
    
    const hasPasswordFieldConfirmation = fields.some(f => 
      f.type === 'password' && 
      (f.autocomplete.includes('new-password') || 
       f.name.toLowerCase().includes('confirm') ||
       f.id.toLowerCase().includes('confirm') ||
       f.name.toLowerCase().includes('repeat'))
    );

    // Patrones para detectar formularios de registro
    const isRegistrationForm = 
      hasEmailField && 
      hasPasswordField && 
      (formElement.action?.includes('register') || 
       formElement.action?.includes('signup') ||
       formElement.action?.includes('sign-up') ||
       formElement.id?.toLowerCase().includes('register') ||
       formElement.id?.toLowerCase().includes('signup') ||
       formElement.querySelector('[type="submit"]')?.textContent?.toLowerCase().includes('register') ||
       formElement.querySelector('[type="submit"]')?.textContent?.toLowerCase().includes('sign up') ||
       formElement.querySelector('[type="submit"]')?.textContent?.toLowerCase().includes('crear cuenta'));

    if (!isRegistrationForm) return null;

    return {
      fields,
      hasEmailField,
      hasPasswordField,
      hasPasswordFieldConfirmation,
      formElement
    };
  }

  /**
   * Extrae todos los campos de un formulario
   * @param formElement Formulario HTML
   * @returns Array de campos del formulario
   */
  private static extractFormFields(formElement: HTMLFormElement): FormField[] {
    const fields: FormField[] = [];
    const inputs = formElement.querySelectorAll('input, select, textarea');

    inputs.forEach(input => {
      if (input instanceof HTMLInputElement || input instanceof HTMLSelectElement || input instanceof HTMLTextAreaElement) {
        const field: FormField = {
          type: input instanceof HTMLInputElement ? input.type || 'text' : 'text',
          name: input.name || '',
          id: input.id || '',
          placeholder: (input instanceof HTMLInputElement || input instanceof HTMLTextAreaElement) ? input.placeholder || '' : '',
          autocomplete: input.getAttribute('autocomplete') || ''
        };
        fields.push(field);
      }
    });

    return fields;
  }

  /**
   * Detecta todos los formularios de registro en la página
   * @returns Array de formularios detectados
   */
  static detectAllRegistrationForms(): DetectedForm[] {
    const forms: DetectedForm[] = [];
    const formElements = document.querySelectorAll('form');

    formElements.forEach(form => {
      const detected = this.detectRegistrationForm(form as HTMLElement);
      if (detected) {
        forms.push(detected);
      }
    });

    return forms;
  }

  /**
   * Obtiene el dominio actual de la página
   * @returns Dominio actual
   */
  static getCurrentDomain(): string {
    return window.location.hostname;
  }

  /**
   * Verifica si la página actual es una de registro
   * @returns true si es una página de registro
   */
  static isRegistrationPage(): boolean {
    const url = window.location.href.toLowerCase();
    const path = window.location.pathname.toLowerCase();
    
    return url.includes('register') || 
           url.includes('signup') || 
           url.includes('sign-up') ||
           path.includes('register') || 
           path.includes('signup') ||
           this.detectAllRegistrationForms().length > 0;
  }
}