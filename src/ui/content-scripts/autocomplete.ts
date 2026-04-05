/**
 * Content Script de Autocompletado
 * Se ejecuta en el contexto de la página web para detectar formularios
 */

import { AutocompleteService } from '../../domain/services/autocompletado/autocomplete-service';

// Inicializar el servicio de autocompletado
const autocompleteService = new AutocompleteService();
autocompleteService.start();

// Escuchar mensajes del background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkRegistrationForms') {
    // Verificar formularios de registro en la página
    sendResponse({ hasRegistrationForms: true });
  } else if (message.action === 'generateCredentials') {
    // Generar credenciales para el dominio actual
    const domain = window.location.hostname;
    autocompleteService['credentialsGenerator']
      .generateCredentials(domain)
      .then(credentials => {
        sendResponse({ credentials });
      })
      .catch(error => {
        sendResponse({ error: error.message });
      });
    return true; // Indicar que la respuesta es asíncrona
  } else if (message.action === 'applyCredentials') {
    // Aplicar credenciales a los campos del formulario
    applyCredentialsToForm(message.credentials);
    sendResponse({ success: true });
  }
});

/**
 * Aplica credenciales a los campos del formulario
 */
function applyCredentialsToForm(credentials: any): void {
  // Buscar campos de email y password
  const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[id*="email"]');
  const passwordInputs = document.querySelectorAll('input[type="password"]');

  // Aplicar email original (sin sal)
  emailInputs.forEach(input => {
    const inputElement = input as HTMLInputElement;
    if (inputElement && !inputElement.value) {
      inputElement.value = credentials.originalEmail;
      inputElement.dispatchEvent(new Event('input', { bubbles: true }));
    }
  });

  // Aplicar password original (sin pimienta)
  passwordInputs.forEach((input, index) => {
    const inputElement = input as HTMLInputElement;
    if (inputElement && !inputElement.value) {
      // El primer campo de password obtiene la contraseña original
      // Los demás campos (confirmación) también obtienen la misma contraseña
      inputElement.value = credentials.originalPassword;
      inputElement.dispatchEvent(new Event('input', { bubbles: true }));
    }
  });
}

// Log de inicialización
console.log('🔐 CyberVault Autocomplete content script loaded');