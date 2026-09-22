# CyberVault — Guía Integral de Instalación del Plugin Chrome

**Código:** CV-DOC-INST-001  
**Versión:** 1.1.0  
**Fecha:** 2026-09-22  
**Estado:** Verificado con servicios levantados + seguridad auditada

---

## Índice

1. [Prerrequisitos](#1-prerrequisitos)
2. [Arquitectura del Sistema](#2-arquitectura-del-sistema)
3. [Instalación de Servicios Backend](#3-instalación-de-servicios-backend)
4. [Verificación de Servicios](#4-verificación-de-servicios)
5. [Construcción del Plugin Chrome](#5-construcción-del-plugin-chrome)
6. [Instalación del Plugin en Chrome](#6-instalación-del-plugin-en-chrome)
7. [Configuración del Plugin](#7-configuración-del-plugin)
8. [Uso Básico](#8-uso-básico)
9. [Troubleshooting](#9-troubleshooting)
10. [Variables de Entorno](#10-variables-de-entorno)

---

## 1. Prerrequisitos

### 1.1 Software Requerido

| Componente | Versión Mínima | Versión Verificada | Propósito |
|------------|----------------|-------------------|-----------|
| Node.js | 18.x | 20.x | Runtime para build de la extensión |
| npm | 9.x | 10.x | Gestor de paquetes |
| Docker | 24.x | 26.x | Contenedores de servicios |
| Docker Compose | v2.x | v2.29 | Orquestación de servicios |
| Google Chrome | 120+ | — | Navegador para la extensión |

### 1.2 Hardware Mínimo

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| RAM | 4 GB | 8 GB |
| Disco | 2 GB libre | 5 GB libre |
| CPU | 2 cores | 4 cores |

### 1.3 Puertos Requeridos

| Puerto | Servicio | Protocolo |
|--------|----------|-----------|
| 3010 | CyberVault API | HTTP |
| 5432 | PostgreSQL | TCP (interno Docker) |
| 6379 | Redis | TCP (interno Docker) |

---

## 2. Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Chrome Browser                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   CyberVault Extension                       │  │
│  │  ┌─────────┐  ┌──────────────┐  ┌────────────────────────┐ │  │
│  │  │ Popup   │  │ Content      │  │ Background             │ │  │
│  │  │ (UI)    │  │ Scripts      │  │ Service Worker         │ │  │
│  │  │         │  │ - inject.js  │  │ - auditor.js           │ │  │
│  │  │         │  │ - autocomplete│  │ - Detección AITM       │ │  │
│  │  └────┬────┘  └──────┬───────┘  └───────────┬────────────┘ │  │
│  │       │              │                      │              │  │
│  │       └──────────────┼──────────────────────┘              │  │
│  │                      │                                     │  │
│  └──────────────────────┼─────────────────────────────────────┘  │
│                         │ HTTPS/HTTP                              │
└─────────────────────────┼─────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Docker Network (bridge)                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │   API Server    │  │   PostgreSQL    │  │     Redis       │   │
│  │   (Node.js)     │  │   (16-alpine)   │  │   (7-alpine)    │   │
│  │   Puerto: 3000  │  │   Puerto: 5432  │  │   Puerto: 6379  │   │
│  │   Host: 3010    │  │   Interno       │  │   Interno       │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Instalación de Servicios Backend

### 3.1 Clonar el Repositorio

```bash
git clone <URL_DEL_REPOSITORIO>
cd cybervault
```

### 3.2 Configurar Variables de Entorno

```bash
# Copiar plantilla de configuración
cp .env.example .env

# Editar con valores específicos del entorno
nano .env
```

**Variables mínimas requeridas en `.env`:**

```bash
# PostgreSQL
POSTGRES_PASSWORD=<contraseña_segura>

# Redis (opcional, tiene default)
REDIS_PASSWORD=cybervault_redis_secret

# JWT (opcional para desarrollo)
JWT_SECRET=<tu_jwt_secret>

# API Port (default: 3000, mapeado a 3010 en host)
API_PORT=3010
```

### 3.3 Levantar Servicios

```bash
# Opción 1: Solo servicios core (recomendado para desarrollo)
docker compose up -d postgres redis api

# Opción 2: Stack completo con documentación
docker compose --profile docs up -d

# Opción 3: Stack completo con IPFS
docker compose --profile ipfs --profile docs up -d
```

### 3.4 Verificar Estado de Contenedores

```bash
docker compose ps
```

**Salida esperada:**

```
NAME               IMAGE                  STATUS          PORTS
cybervault-api     cybervault-api         Up (healthy)   0.0.0.0:3010->3000/tcp
cybervault-db      postgres:16-alpine     Up (healthy)   5432/tcp
cybervault-redis   redis:7-alpine         Up (healthy)   6379/tcp
```

---

## 4. Verificación de Servicios

### 4.1 Health Check

```bash
curl -s http://localhost:3010/health | python3 -m json.tool
```

**Respuesta esperada:**

```json
{
    "status": "healthy",
    "timestamp": "2026-09-17T23:45:32.338Z",
    "service": "cyber-vault-api",
    "checks": {
        "database": "ok",
        "ipfs": "not_configured"
    },
    "metrics": {
        "uptimeSeconds": 160419,
        "totalRequests": 5,
        "errorRate": 0
    }
}
```

### 4.2 Ready Check

```bash
curl -s http://localhost:3010/ready | python3 -m json.tool
```

**Respuesta esperada:**

```json
{
    "status": "ready",
    "timestamp": "2026-09-17T23:45:32.779Z",
    "checks": {
        "database": "ok",
        "ipfs": "not_configured"
    }
}
```

### 4.3 Verificación de Base de Datos

```bash
# Entrar al contenedor de PostgreSQL
docker exec -it cybervault-db psql -U cybervault -d cybervault

# Verificar tablas
\dt

# Verificar conexión
SELECT 1 AS test;

# Salir
\q
```

### 4.4 Verificación de Redis

```bash
# Entrar al contenedor de Redis
docker exec -it cybervault-redis redis-cli -a cybervault_redis_secret

# Verificar conexión
PING

# Salir
EXIT
```

---

## 5. Construcción del Plugin Chrome

### 5.1 Instalar Dependencias

```bash
npm install
```

### 5.2 Construir la Extensión

```bash
npm run build:all
```

**Nota:** `build:all` ejecuta tanto `build` (tsc para Node.js) como `build:ext` (esbuild para Chrome Extension) en el orden correcto. Esto es importante porque ambos procesos comparten el directorio `dist/`.

**Salida esperada:**

```
> tsc
> node scripts/build-extension.mjs
✓ Background script bundled
✓ Popup built
✓ Content script built
✓ Autocomplete content script built
✓ Options page built
✓ Icons copied
✓ Static files copied
✓ Build complete!
```

### 5.3 Estructura del Build

```
dist/
├── manifest.json          # Manifest V3 de Chrome
├── background/
│   └── auditor.js         # Service Worker (detección AITM)
├── ui/
│   ├── popup/
│   │   ├── popup.html     # Interfaz principal
│   │   ├── popup.js       # Lógica del popup
│   │   └── popup.css      # Estilos
│   ├── options/
│   │   ├── options.html   # Página de configuración
│   │   ├── options.js     # Lógica de opciones
│   │   └── options.css    # Estilos
│   └── content-scripts/
│       ├── inject.js      # Inyección en páginas
│       └── autocomplete.js # Autocompletado seguro
├── icons/
│   ├── icon-16.png        # Icono 16x16
│   ├── icon-48.png        # Icono 48x48
│   └── icon-128.png       # Icono 128x128
└── [archivos .js.map]     # Source maps (desarrollo)
```

---

## 6. Instalación del Plugin en Chrome

### 6.1 Modo Desarrollador

1. Abrir Chrome y navegar a `chrome://extensions/`

2. Habilitar **"Modo desarrollador"** (toggle en la esquina superior derecha)

3. Hacer clic en **"Cargar extensión sin empaquetar"** (Load unpacked)

4. Seleccionar la carpeta `dist/` del proyecto:
   ```
   /home/search14/cybervault/dist/
   ```

5. La extensión aparecerá en la barra de herramientas con el icono de CyberVault

### 6.2 Verificar Instalación

1. Hacer clic en el icono de CyberVault en la barra de herramientas
2. Debería mostrarse el popup con el mensaje "Vault is locked"
3. Verificar en `chrome://extensions/` que no hay errores

### 6.3 Permisos de la Extensión

| Permiso | Propósito |
|---------|-----------|
| `storage` | Almacenamiento local de configuración y vault |
| `alarms` | Verificación periódica de dominios |
| `tabs` | Acceso a información de pestañas para detección AITM |
| Host: `api.pwnedpasswords.com` | Verificación de contraseñas comprometidas |
| Host: `otx.alienvault.com` | Threat intelligence |
| Host: `api.github.com` | Actualizaciones y verificación |

---

## 7. Configuración del Plugin

### 7.1 Página de Configuración

1. Hacer clic derecho en el icono de CyberVault
2.Seleccionar **"Opciones"** (Options)
3. Configurar dominios confiables

### 7.2 Dominios Confiables

Los dominios confiables se saltan la validación AITM:

```
ejemplo.com
gmail.com
github.com
```

### 7.3 Funcionalidades Disponibles

| Función | Descripción |
|---------|-------------|
| **Vault Lock/Unlock** | Bloquear/desbloquear vault con passphrase |
| **Generación de Credenciales** | Generar usuario/contraseña seguros por dominio |
| **Detección AITM** | Alerta en tiempo real de ataques AiTM |
| **Autocompletado** | Relleno seguro de formularios |
| **Verificación HIBP** | Chequeo contra Have I Been Pwned |

---

## 8. Uso Básico

### 8.1 Flujo de Primer Uso

```
1. Instalar extensión (ver Sección 6)
2. Abrir cualquier sitio web
3. Hacer clic en icono CyberVault
4. Establecer passphrase maestra
5. El vault se crea localmente (zero-knowledge)
6. Generar credenciales para el dominio actual
7. Las credenciales se almacenan cifradas
```

### 8.2 Generación de Credenciales

```javascript
// La extensión genera credenciales con:
// - Salt único por dominio
// - Pepper de 128 bits
// - Validación de entropía
// - Almacenamiento AES-256-GCM
```

### 8.3 Detección AITM

El background service worker (`auditor.js`) ejecuta:

1. **Validación de dominio** — exact match, Unicode confusables
2. **Typosquatting** — distancia de Levenshtein
3. **Integridad DOM** — fingerprinting de contenido
4. **Análisis de timing** — detección de proxies
5. **Seguridad de cookies** — flags de seguridad

---

## 9. Troubleshooting

### 9.1 Errores Comunes

| Error | Causa | Solución |
|-------|-------|----------|
| `password authentication failed` | PostgreSQL no acepta la contraseña | Verificar `POSTGRES_PASSWORD` en `.env` y reiniciar DB |
| `Extension failed to load` | Manifest inválido o archivos faltantes | Re-ejecutar `npm run build:ext` |
| `Cannot connect to API` | Servidor API no está corriendo | `docker compose up -d api` |
| `Vault is locked` persiste | Passphrase incorrecta | Reiniciar vault (borrar datos de storage) |

### 9.2 Logs de Servicios

```bash
# Logs de la API
docker compose logs -f api

# Logs de PostgreSQL
docker compose logs -f postgres

# Logs de Redis
docker compose logs -f redis

# Logs recientes (últimas 100 líneas)
docker compose logs --tail 100 api
```

### 9.3 Reiniciar Servicios

```bash
# Reiniciar solo la API
docker compose restart api

# Reiniciar todo
docker compose down && docker compose up -d

# Reiniciar con reconstrucción
docker compose up -d --build api
```

### 9.4 Limpiar Datos

```bash
# ⚠️ ELIMINA TODOS LOS DATOS
docker compose down -v

# Limpiar solo Redis
docker compose exec redis redis-cli FLUSHALL
```

---

## 10. Variables de Entorno

### 10.1 Referencia Completa

| Variable | Default | Descripción |
|----------|---------|-------------|
| `PORT` | `3000` | Puerto del servidor API |
| `API_PORT` | `3000` | Puerto mapeado en host |
| `NODE_ENV` | `development` | Entorno de ejecución |
| `JWT_SECRET` | _(ninguno)_ | Secreto para JWT (sin él, auth deshabilitada) |
| `USE_POSTGRES` | `false` | Usar PostgreSQL en vez de memoria |
| `DATABASE_URL` | — | URL de conexión PostgreSQL |
| `REDIS_URL` | `redis://localhost:6379` | URL de conexión Redis |
| `REDIS_PASSWORD` | `cybervault_redis_secret` | Contraseña Redis |
| `POSTGRES_PASSWORD` | — | Contraseña PostgreSQL |
| `IPFS_API_URL` | `http://localhost:5001` | Endpoint API de IPFS |
| `IPFS_ENABLED` | `false` | Habilitar IPFS |
| `HIBP_ENABLED` | `true` | Verificar contra Have I Been Pwned |
| `RATE_LIMIT_MAX` | `100` | Máximo de requests por ventana |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Ventana de rate limit (15 min) |
| `HTTPS_ENABLED` | `false` | Habilitar HTTPS con TLS |
| `TLS_CERT_PATH` | `./certs/server.crt` | Ruta del certificado TLS |
| `TLS_KEY_PATH` | `./certs/server.key` | Ruta de la clave TLS |

---

## 11. Endpoints de la API

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |
| `POST` | `/api/v1/auth/register` | Registrar usuario |
| `POST` | `/api/v1/auth/login` | Login |
| `GET` | `/api/v1/auth/verify` | Verificar token JWT |
| `POST` | `/api/v1/vaults` | Crear vault |
| `GET` | `/api/v1/vaults` | Listar vaults |
| `GET` | `/api/v1/vaults/:id` | Obtener vault |
| `DELETE` | `/api/v1/vaults/:id` | Eliminar vault |
| `POST` | `/api/v1/credentials/generate` | Generar credenciales |
| `POST` | `/api/v1/credentials/extract` | Extraer credenciales |
| `GET` | `/api/v1/credentials/validate` | Validar formato |
| `GET` | `/api` | Info de la API |

---

## 12. Acceso por Red

### 12.1 Acceso Local (misma máquina)

```
API:        http://localhost:3010
Health:     http://localhost:3010/health
Ready:      http://localhost:3010/ready
Swagger:    http://localhost:3010/api/docs
```

### 12.2 Acceso por LAN

```
API:        http://10.9.9.114:3010
Health:     http://10.9.9.114:3010/health
```

### 12.3 Acceso por Tailscale (remoto)

```
API:        http://100.78.47.108:3010
Health:     http://100.78.47.108:3010/health
```

---

## 13. Seguridad

### 13.1 Características de Seguridad

- **Zero-Knowledge Encryption** — Credenciales cifradas client-side con AES-256-GCM
- **Salt + Pepper** — Aislamiento de credenciales por dominio
- **Argon2 KDF** — Derivación de clave resistente a GPU/ASIC
- **X25519 + Ed25519** — Intercambio de claves y firmas post-cuánticas
- **Rate Limiting** — Throttling por IP
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-XSS-Protection

### 13.2 Permisos de Chrome

La extensión solicita los mínimos permisos necesarios:

- `storage` — Para persistir vault cifrado localmente
- `alarms` — Para verificación periódica de dominios
- `tabs` — Para detectar cambios de URL en tiempo real
- Host permissions — Solo para APIs de verificación de seguridad

---

## 14. Credenciales de Prueba

### 14.1 Usuarios Pre-creados

Los siguientes usuarios están disponibles para pruebas inmediatas:

| Email | Contraseña | Rol | Perfil |
|-------|-----------|-----|--------|
| `admin@cybervault.test` | `Admin2024!` | Admin | Acceso completo |
| `user@cybervault.test` | `User2024!` | Usuario | Acceso estándar |
| `dev@cybervault.test` | `Dev2024!` | Desarrollador | Acceso de desarrollo |
| `test@cybervault.local` | `TestPass123!` | Test | Pruebas automatizadas |

### 14.2 Autenticación vía API

```bash
# Login — obtener token JWT + refresh token
curl -s -X POST http://localhost:3010/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cybervault.test","password":"Admin2024!"}'

# Respuesta esperada:
# {
#   "userId": "0d769a7f-...",
#   "email": "admin@cybervault.test",
#   "token": "eyJhbGciOiJIUzI1NiIs...",
#   "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
#   "message": "Login successful"
# }

# ⚠️ Rate Limiting: 5 intentos fallidos → lockout 1 min, 10 → 5 min, 15+ → 15 min
```

### 14.3 Refresh Token

```bash
# Renovar access token usando refresh token
curl -s -X POST http://localhost:3010/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'

# Respuesta:
# {
#   "token": "nuevo_access_token",
#   "refreshToken": "nuevo_refresh_token",
#   "message": "Tokens refreshed successfully"
# }
```

### 14.4 Autenticación vía UI

1. Navegar a `http://localhost:3010/auth.html`
2. Ingresar email y contraseña
3. El token JWT se muestra en pantalla y se guarda en localStorage

### 14.5 Uso del Token

```bash
# Listar vaults (con token)
curl -s http://localhost:3010/api/v1/vaults \
  -H "Authorization: Bearer <TU_TOKEN>"

# Crear vault
curl -s -X POST http://localhost:3010/api/v1/vaults \
  -H "Authorization: Bearer <TU_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Mi Vault","encryptedData":"...","encryptionKeyId":"key-1"}'
```

### 14.6 Registrar Nuevo Usuario

```bash
curl -s -X POST http://localhost:3010/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"nuevo@ejemplo.com","password":"MiContraseña123!"}'
```

---

## 15. Seguridad Implementada

### 15.1 Controles de Seguridad

| Control | Estado | Descripción |
|---------|--------|-------------|
| JWT_SECRET gate | ✅ | Requiere JWT_SECRET en staging/production |
| CORS explícito | ✅ | Allowlist: `http://localhost:3000` |
| User scoping | ✅ | Vault/credential queries filtradas por ownerId |
| Rate limiting | ✅ | 100 req/15min por IP |
| Brute-force protection | ✅ | 5 intentos → 1min lockout, progresivo |
| JWT access tokens | ✅ | Expira en 15 minutos |
| JWT refresh tokens | ✅ | Expira en 7 días, rotación |
| CSP headers | ✅ | Content-Security-Policy configurado |
| Body limits | ✅ | 1MB max request size |
| Timing-safe compare | ✅ | Comparación resistente a timing attacks |

### 15.2 Endpoints de Seguridad

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Login con rate limiting + lockout |
| `/api/v1/auth/register` | POST | Registro de usuario |
| `/api/v1/auth/refresh` | POST | Renovación de tokens |
| `/api/v1/auth/verify` | GET | Verificar token válido |

---

## Documento Generado

- **Fecha:** 2026-09-22
- **Última actualización:** RDD audit — XSS, brute-force protection, JWT refresh
- **Servicios verificados:** API (healthy), PostgreSQL (healthy), Redis (healthy)
- **Build de extensión:** Completo en `dist/`
- **Tests:** 285/295 passing (10 skipped — Playwright E2E)
- **Seguridad:** 0 CRITICAL, 0 HIGH, 0 MEDIUM (todos corregidos)
- **Estado:** Listo para instalación en Chrome
