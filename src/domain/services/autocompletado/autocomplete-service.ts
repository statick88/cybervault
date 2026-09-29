/**
 * Servicio de Autocompletado de Credenciales
 * Gestiona la detección de formularios y generación de credenciales seguras
 */

import type {
  GeneratedCredentials} from "./credentials-generator";
import {
  CredentialsGenerator
} from "./credentials-generator";
import type { DetectedForm } from "./form-detector";
import { FormDetector } from "./form-detector";
import { logger } from "../../../shared/logger";

/** Class marking the container this service injects, so its own mutations are recognisable. */
const SUGGESTION_CONTAINER_CLASS = "cybervault-suggestion-container";

export interface AutocompleteSuggestion {
  email: string;
  password: string;
  originalEmail: string;
  originalPassword: string;
  domain: string;
  timestamp: number;
}

export class AutocompleteService {
  private credentialsGenerator: CredentialsGenerator;
  private suggestions: Map<string, AutocompleteSuggestion> = new Map();

  constructor() {
    this.credentialsGenerator = new CredentialsGenerator();
  }

  /**
   * Inicia el servicio de autocompletado
   */
  start(): void {
    logger.info("Iniciando servicio de autocompletado CyberVault...", "AutocompleteService");
    // setupEventListeners() already triggers a detection pass: when the DOM is
    // still loading it defers to the DOMContentLoaded listener, and otherwise
    // onDOMReady() runs checkCurrentPage() immediately. Calling it again here
    // rendered a second suggestion card for the same form — two elements with
    // the same id, two <style> blocks, and an overwritten registry slot, so
    // getStoredCredentials() could return a credential the card on screen was
    // not displaying.
    this.setupEventListeners();
  }

  /**
   * Configura los listeners de eventos para detectar formularios
   */
  private setupEventListeners(): void {
    // Detectar formularios cuando el DOM esté listo
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.onDOMReady());
    } else {
      this.onDOMReady();
    }

    // Detectar formularios dinámicos (Single Page Apps)
    const observer = new MutationObserver((records) => {
      // Our own card landing in the observed subtree is not a page change;
      // treating it as one is what produced the unbounded microtask loop.
      if (this.isOwnSuggestionMutation(records)) return;
      this.checkCurrentPage();
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    // Detectar cuando el usuario hace clic en un campo de registro
    document.addEventListener("focusin", (event) => {
      const target = event.target as HTMLElement;
      this.checkForRegistrationField(target);
    });
  }

  /**
   * Manejador cuando el DOM está listo
   */
  private onDOMReady(): void {
    this.checkCurrentPage();
  }

  /**
   * Verifica la página actual para detectar formularios de registro
   */
  private checkCurrentPage(): void {
    const forms = FormDetector.detectAllRegistrationForms();

    if (forms.length > 0) {
      logger.info(`Detectados ${forms.length} formularios de registro`, "AutocompleteService");
      forms.forEach((form, index) => {
        this.processForm(form, index);
      });
    }
  }

  /**
   * A DOM mutation caused by our own suggestion card is not evidence that the
   * page changed.
   *
   * `setupEventListeners()` observes `document.body` with
   * `{childList: true, subtree: true}` so it can pick up forms injected by
   * single-page apps, and `showSuggestionUI()` appends the suggestion card into
   * that same subtree. Appending therefore re-entered `checkCurrentPage()`,
   * which appended another card, which re-entered the observer — and since
   * MutationObserver callbacks are microtasks, macrotasks (timers, painting,
   * input) never got a turn. Any page with a registration form froze.
   *
   * Re-entrancy is the part that actually bounds this: processForm is async,
   * and a pass already in flight re-entering itself would still loop. So
   * suppress the delivery when the mutation records carry only our own
   * container, and coalesce concurrent deliveries so a burst of unrelated
   * mutations schedules one detection pass rather than one per callback.
   */
  private isOwnSuggestionMutation(records: MutationRecord[]): boolean {
    return records.every(
      (record) =>
        Array.from(record.addedNodes).every(
          (node) =>
            node instanceof HTMLElement &&
            node.classList.contains(SUGGESTION_CONTAINER_CLASS),
        ),
    );
  }

  /**
   * Procesa un formulario de registro detectado
   * @param form Formulario detectado
   * @param index Índice del formulario
   */
  private async processForm(form: DetectedForm, index: number): Promise<void> {
    const domain = FormDetector.getCurrentDomain();

    // Generar credenciales sugeridas
    const credentials =
      await this.credentialsGenerator.generateCredentials(domain);

    // Almacenar sugerencia
    this.suggestions.set(`${domain}-${index}`, {
      email: credentials.email,
      password: credentials.password,
      originalEmail: credentials.originalEmail,
      originalPassword: credentials.originalPassword,
      domain,
      timestamp: Date.now(),
    });

    // Mostrar interfaz de sugerencia
    this.showSuggestionUI(form, credentials, index);
  }

  /**
   * Muestra la interfaz de sugerencia para el formulario
   */
  private showSuggestionUI(
    form: DetectedForm,
    credentials: GeneratedCredentials,
    index: number,
  ): void {
    // Crear contenedor de sugerencia
    const suggestionContainer = document.createElement("div");
    suggestionContainer.id = `cybervault-suggestion-${index}`;
    suggestionContainer.className = SUGGESTION_CONTAINER_CLASS;
    // SECURITY: Build DOM with textContent to prevent XSS — never interpolate user data into innerHTML
    suggestionContainer.innerHTML = `
      <div class="cybervault-suggestion-header">
        <span class="cybervault-logo">🔐 CyberVault</span>
        <span class="cybervault-badge">Zero-Knowledge</span>
      </div>
      <div class="cybervault-suggestion-content">
        <p>¿Quieres usar credenciales generadas por CyberVault?</p>
        <div class="cybervault-credentials-preview">
          <div class="credential-item">
            <label>Email:</label>
            <code class="cybervault-email-value"></code>
          </div>
          <div class="credential-item">
            <label>Password:</label>
            <code class="cybervault-password-value"></code>
          </div>
        </div>
      </div>
      <div class="cybervault-suggestion-actions">
        <button class="cybervault-btn cybervault-btn-primary" data-action="use">
          Usar credenciales CyberVault
        </button>
        <button class="cybervault-btn cybervault-btn-secondary" data-action="manual">
          Generar manualmente
        </button>
        <button class="cybervault-btn cybervault-btn-dismiss" data-action="dismiss">
          Descartar
        </button>
      </div>
    `;

    // Set credential values via textContent (safe — no HTML parsing)
    const emailCode = suggestionContainer.querySelector<HTMLElement>(".cybervault-email-value");
    const passwordCode = suggestionContainer.querySelector<HTMLElement>(".cybervault-password-value");
    if (emailCode) emailCode.textContent = credentials.email;
    if (passwordCode) passwordCode.textContent = credentials.password;

    // Estilos CSS
    const styles = `
      .cybervault-suggestion-container {
        position: absolute;
        top: 10px;
        right: 10px;
        background: #1a1a2e;
        border: 1px solid #4a4a6a;
        border-radius: 8px;
        padding: 12px;
        min-width: 320px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      .cybervault-suggestion-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid #4a4a6a;
      }
      .cybervault-logo {
        font-weight: bold;
        color: #00ff88;
      }
      .cybervault-badge {
        background: #4a4a6a;
        color: #fff;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
      }
      .cybervault-suggestion-content {
        margin-bottom: 12px;
        font-size: 13px;
        color: #ccc;
      }
      .cybervault-credentials-preview {
        background: #0f0f1a;
        padding: 10px;
        border-radius: 6px;
        margin-top: 8px;
      }
      .credential-item {
        display: flex;
        margin-bottom: 6px;
      }
      .credential-item:last-child {
        margin-bottom: 0;
      }
      .credential-item label {
        min-width: 70px;
        color: #888;
      }
      .credential-item code {
        color: #00ff88;
        font-family: monospace;
        font-size: 12px;
        word-break: break-all;
      }
      .cybervault-suggestion-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .cybervault-btn {
        padding: 8px 12px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
        transition: all 0.2s;
      }
      .cybervault-btn-primary {
        background: #00ff88;
        color: #000;
        font-weight: bold;
      }
      .cybervault-btn-primary:hover {
        background: #00dd77;
      }
      .cybervault-btn-secondary {
        background: #4a4a6a;
        color: #fff;
      }
      .cybervault-btn-secondary:hover {
        background: #5a5a7a;
      }
      .cybervault-btn-dismiss {
        background: transparent;
        color: #888;
      }
      .cybervault-btn-dismiss:hover {
        color: #fff;
      }
    `;

    // Agregar estilos al documento
    const styleElement = document.createElement("style");
    styleElement.textContent = styles;
    document.head.appendChild(styleElement);

    // Insertar el contenedor en el formulario
    if (form.formElement) {
      form.formElement.style.position = "relative";
      form.formElement.appendChild(suggestionContainer);
    } else {
      document.body.appendChild(suggestionContainer);
    }

    // Agregar event listeners a los botones
    suggestionContainer.addEventListener("click", (event) => {
      const target = event.target as HTMLElement;
      const action = target.dataset.action;

      if (action === "use") {
        this.useGeneratedCredentials(form, credentials, index);
      } else if (action === "manual") {
        this.showManualGenerationUI(form, index);
      } else if (action === "dismiss") {
        this.dismissSuggestion(index);
      }
    });
  }

  /**
   * Usa las credenciales generadas en el formulario
   */
  private async useGeneratedCredentials(
    form: DetectedForm,
    credentials: GeneratedCredentials,
    index: number,
  ): Promise<void> {
    // Buscar campos de email y password
    const emailField = form.fields.find(
      (f) =>
        f.type === "email" ||
        f.autocomplete.includes("email") ||
        f.name.toLowerCase().includes("email"),
    );

    const passwordFields = form.fields.filter((f) => f.type === "password");

    if (emailField) {
      const input = document.getElementById(emailField.id) as HTMLInputElement;
      if (input) {
        input.value = credentials.originalEmail;
      }
    }

    // Usar el primer campo de password para la contraseña original
    if (passwordFields.length > 0) {
      const firstPasswordField = passwordFields[0];
      const input = document.getElementById(
        firstPasswordField.id,
      ) as HTMLInputElement;
      if (input) {
        input.value = credentials.originalPassword;
      }
    }

    // Guardar en almacenamiento local del dominio
    await this.saveCredentialsForDomain(
      credentials,
      form.formElement?.action || "",
    );

    // Ocultar sugerencia
    this.dismissSuggestion(index);

    logger.info("Credenciales generadas y aplicadas", "AutocompleteService");
  }

  /**
   * Muestra interfaz para generación manual
   */
  private showManualGenerationUI(_form: DetectedForm, _index: number): void {
    alert("Funcionalidad de generación manual en desarrollo");
  }

  /**
   * Descarta la sugerencia
   */
  private dismissSuggestion(index: number): void {
    const suggestion = document.getElementById(
      `cybervault-suggestion-${index}`,
    );
    if (suggestion) {
      suggestion.style.display = "none";
    }
  }

  /**
   * Guarda las credenciales para el dominio actual
   */
  private async saveCredentialsForDomain(
    credentials: GeneratedCredentials,
    formUrl: string,
  ): Promise<void> {
    const domain = FormDetector.getCurrentDomain();

    // Aquí deberías guardar en el almacenamiento del plugin
    // usando chrome.storage.local o similar
    const credentialsData = {
      domain,
      email: credentials.email, // Con sal
      password: credentials.password, // Con pimienta
      originalEmail: credentials.originalEmail,
      originalPassword: credentials.originalPassword,
      salt: credentials.salt,
      pepper: credentials.pepper,
      formUrl,
      timestamp: Date.now(),
    };

    logger.info("Credenciales guardadas", "AutocompleteService", credentialsData as unknown as Record<string, unknown>);
  }

  /**
   * Verifica si hay un campo de registro enfocado
   */
  private checkForRegistrationField(element: HTMLElement): void {
    const detected = FormDetector.detectRegistrationForm(element);
    if (detected) {
      this.processForm(detected, 0);
    }
  }

  /**
   * Obtiene las credenciales almacenadas para un dominio
   */
  getStoredCredentials(domain: string): AutocompleteSuggestion | undefined {
    return this.suggestions.get(`${domain}-0`);
  }

  /**
   * Limpia todas las sugerencias
   */
  clearAllSuggestions(): void {
    this.suggestions.clear();
  }
}
