/**
 * CyberVault UI Utilities
 * Funciones utilitarias compartidas entre los diferentes módulos de UI
 */

/**
 * Escapa caracteres HTML para prevenir XSS
 */
export function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Escapa caracteres para usar en atributos HTML
 * Previene inyección de atributos mediante comillas y caracteres especiales
 */
export function escapeAttribute(value: string): string {
  if (typeof value !== "string") return "";
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/`/g, "&#x60;");
}

/**
 * Sanitiza URLs previniendo protocolos peligrosos (javascript:, data:, etc.)
 * Solo permite http: y https:
 */
export function sanitizeUrl(url: string): string {
  if (!url || typeof url !== "string") return "#";

  const trimmed = url.trim();

  // Validar protocolo explícitamente
  if (!/^https?:/.test(trimmed)) {
    return "#";
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "#";
    }
    return parsed.href;
  } catch {
    return "#";
  }
}

/**
 * Genera una letra para el favicon basada en el título
 */
export function getFaviconLetter(title: string): string {
  return title.charAt(0).toUpperCase();
}

/**
 * Muestra un modal por su ID
 */
export function showModal(modalId: string): void {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
  }
}

/**
 * Oculta un modal por su ID
 */
export function hideModal(modalId: string): void {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("active");
  }
}

/**
 * Copia texto al portapapeles
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Genera un password aleatorio con las opciones especificadas
 */
export function generatePassword(
  length: number,
  options: {
    uppercase?: boolean;
    lowercase?: boolean;
    numbers?: boolean;
    symbols?: boolean;
  } = {},
): string {
  const {
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
  } = options;

  let chars = "";
  if (uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lowercase) chars += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";

  let password = "";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  for (let i = 0; i < length; i++) {
    password += chars.charAt(array[i] % chars.length);
  }

  return password;
}
