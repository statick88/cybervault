/**
 * PopupUIService
 * Servicio para manejar operaciones de UI en el popup de CyberVault.
 * Proporciona métodos seguros para manipular el DOM.
 */

/**
 * Escapa caracteres HTML para prevenir XSS.
 * Implementación本地 ya que @/shared/utils no exporta actualmente escapeHtml.
 */
function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Genera un ID único (para data-id u otros atributos)
 */
function generateId(): string {
  // Usamos Date.now() + random para mayor unicidad
  return `id-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

export class PopupUIService {
  /**
   * Muestra un modal por su ID agregando la clase 'active'
   */
  showModal(modalId: string): void {
    const element = this.getElement(modalId);
    if (element) {
      element.classList.add("active");
    }
  }

  /**
   * Oculta un modal por su ID removiendo la clase 'active'
   */
  hideModal(modalId: string): void {
    const element = this.getElement(modalId);
    if (element) {
      element.classList.remove("active");
    }
  }

  /**
   * Obtiene un elemento del DOM por su ID de forma segura.
   * @param id - ID del elemento
   * @returns El elemento si existe, o null
   */
  getElement<T extends HTMLElement>(id: string): T | null {
    return document.getElementById(id) as T | null;
  }

  /**
   * Escapa un texto para ser insertado de forma segura en HTML.
   * Prevención XSS.
   */
  escapeHtml(text: string): string {
    return escapeHtml(text);
  }

  /**
   * Genera un ID único (para data-id, atributos, etc.)
   */
  generateId(): string {
    return generateId();
  }

  /**
   * Establece el contenido HTML de un elemento.
   * ADVERTENCIA: No escapa automáticamente. Usar escapeHtml previo si es necesario.
   */
  setElementContent(element: HTMLElement, html: string): void {
    element.innerHTML = html;
  }

  /**
   * Agrega un event listener a un elemento con tipo seguro.
   */
  addEventListener<K extends keyof HTMLElementEventMap>(
    element: HTMLElement,
    type: K,
    handler: (e: HTMLElementEventMap[K]) => void,
  ): void {
    element.addEventListener(type, handler);
  }
}
