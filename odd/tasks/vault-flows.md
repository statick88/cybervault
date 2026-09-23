# Vault Flows: Web App + Plugin Authentication & Unlock

## Objetivo
Implementar los flujos completos de autenticación y desbloqueo de bóveda tanto en la aplicación web como en el plugin de Chrome, incluyendo sincronización entre ambos.

## Estado Actual
- **Web App**: Solo muestra token JWT post-login, sin redirección a vault
- **Plugin**: Tiene vista de passphrase pero sin login ni decrypt funcional
- **API**: Endpoints de auth existentes, falta endpoint de vault decrypt
- **Vault**: Entidad con `encryptedData` que requiere passphrase para decrypt

## Contrato de Estados

```
UNAUTHENTICATED → AUTHENTICATED_LOCKED → VAULT_UNLOCKED
```

- `UNAUTHENTICATED`: No hay token JWT válido
- `AUTHENTICATED_LOCKED`: Token JWT válido, pero vault bloqueado (necesita passphrase)
- `VAULT_UNLOCKED`: Token JWT válido + passphrase correcta, datos descifrados en memoria

## Plan de Implementación

### T1: API - Endpoint de Vault Operations
- [ ] Agregar endpoint `GET /api/v1/vaults` (list vaults del usuario)
- [ ] Agregar endpoint `POST /api/v1/vaults/:id/unlock` (recibe passphrase, retorna encryptedData)
- [ ] Verificar que el endpoint NO retorne la passphrase ni la clave derivada
- [ ] Agregar validación de ownerId para asegurar que solo el propietario acceda

### T2: Web App - Redirección Post-Login
- [ ] Modificar auth.html para redirigir a /vault tras login exitoso
- [ ] Crear vault.html con vista de desbloqueo
- [ ] Implementar derivación de clave PBKDF2 en browser (Web Crypto API)
- [ ] Implementar decrypt local con passphrase del usuario
- [ ] Mostrar credenciales descifradas en tabla

### T3: Plugin - Login Screen
- [ ] Agregar pantalla de login en popup.html (email + password)
- [ ] Implementar llamada a API /auth/login desde plugin
- [ ] Almacenar token JWT en chrome.storage.local
- [ ] Manejar estado de sesión (logged in / logged out)

### T4: Plugin - Vault Unlock
- [ ] Implementar derivación de clave PBKDF2 en plugin context
- [ ] Llamar a API para obtener vault encryptedData
- [ ] Descifrar localmente con passphrase del usuario
- [ ] Mostrar credenciales en popup
- [ ] Implementar auto-lock después de 30 min de inactividad

### T5: Sincronización Web-Plugin
- [ ] Usar chrome.storage.local para compartir token JWT
- [ ] Implementar chrome.runtime.sendMessage para comunicación
- [ ] Asegurar que logout en web cierre sesión en plugin y viceversa
- [ ] Limpiar memoria sensible al cerrar sesión

### T6: Seguridad y Limpieza
- [ ] Asegurar que passphrase nunca se envíe al backend
- [ ] Implementar secureZero para datos sensibles en memoria
- [ ] Verificar .gitignore excluye archivos con secrets
- [ ] Documentar flujo de seguridad en cognitive doc

## Criterios de Aceptación

1. **Web App**: Login → redirige a /vault → ingresa passphrase → ve credenciales
2. **Plugin**: Login → ingresa passphrase → ve credenciales en popup
3. **Sincronización**: Login en web → plugin reconoce sesión; logout en plugin → web pierde acceso
4. **Seguridad**: Passphrase nunca llega al backend; datos se borran de memoria al logout
5. **Auto-lock**: Plugin se bloquea después de 30 min sin actividad

## Dependencias
- EncryptionService (PBKDF2 + AES-GCM-256) ✅ existe
- Auth middleware (JWT) ✅ existe
- Vault entity ✅ existe
- Chrome storage API ✅ disponible

## Riesgos
- PBKDF2 en browser puede ser lento (600k iteraciones) → mitigar con feedback visual
- Chrome extension context tiene limitaciones de storage → usar session storage para unlock state
