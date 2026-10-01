# CyberVault - Guía Completa de Instalación y Uso

## 📋 Resumen del Proyecto

CyberVault es un sistema de gestión de credenciales **Zero-Knowledge** con detección de ataques **AiTM (Adversary-in-the-Middle)**. El código ha pasado por un ciclo completo de análisis de calidad con SonarQube, corrigiendo todos los issues críticos y mayores.

---

## 🔧 Estado de Calidad del Código

| Métrica | Estado |
|---------|--------|
| **Issues Críticos (S3776)** | ✅ 0 (eran 11) |
| **Issues Mayores (S3358, S107, S6324)** | ✅ 0 (eran 23) |
| **Issues Menores** | ✅ 0 reales (solo cache de SonarQube) |
| **Tests** | ✅ 285 pasando |
| **Build** | ✅ TypeScript + Extension compilando |

---

## 🚀 Inicio Rápido

### Prerrequisitos
- Docker & Docker Compose
- Node.js 20+ (para desarrollo)
- Chrome/Edge/Brave (para la extensión)

### 1. Configuración del Entorno

```bash
# Clonar y entrar al proyecto
cd cybervault

# Copiar y editar variables de entorno
cp .env.example .env
# Editar .env con tus valores seguros:
# POSTGRES_PASSWORD, JWT_SECRET, VAULT_MASTER_KEY, VAULT_ENCRYPTION_SALT
```

### 2. Levantar Servicios

```bash
# Levantar PostgreSQL, Redis y API
docker compose up -d postgres redis api

# Verificar salud
curl http://localhost:3010/health
# Debe devolver: {"status":"healthy","checks":{"database":"ok"}}
```

### 3. Construir e Instalar Extensión

```bash
# Instalar dependencias y compilar todo
npm install
npm run build:all

# En Chrome/Edge/Brave:
# 1. Abrir chrome://extensions/
# 2. Activar "Modo desarrollador" (esquina superior derecha)
# 3. Click "Cargar descomprimida"
# 4. Seleccionar carpeta: ./dist
```

### 4. Verificar Instalación

- El icono de CyberVault aparece en la barra de extensiones
- Click derecho → Opciones para configurar
- En cualquier formulario de login, el autocompletado debe aparecer

---

## 📖 Manual Interactivo de Uso

### Paso 1: Configuración Inicial

```
┌─────────────────────────────────────────────────────────────┐
│  🔐 CyberVault - Configuración Inicial                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Click en el icono de la extensión (barra superior)      │
│  2. Selecciona "Opciones"                                   │
│  3. Configura:                                              │
│     ☑ Activar autocompletado                                │
│     ☑ Detección AiTM (recomendado)                          │
│     ☑ Verificación de integridad DOM                        │
│  4. Guarda cambios                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Paso 2: Registrar Usuario (Primera vez)

```bash
# Via API directa
curl -X POST http://localhost:3010/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPass123!"}'

# Respuesta exitosa:
# {"userId":"uuid","email":"usuario@ejemplo.com","token":"jwt...","refreshToken":"jwt..."}
```

### Paso 3: Crear Vault (Almacén de Credenciales)

```bash
# Con token JWT del login
curl -X POST http://localhost:3010/api/v1/vaults \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TU_JWT_TOKEN" \
  -d '{"name":"Personal","description":"Credenciales personales"}'
```

### Paso 4: Generar Credenciales Seguras

```bash
# Generar email+password con sal/pimienta para un dominio
curl -X POST http://localhost:3010/api/v1/credentials/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TU_JWT_TOKEN" \
  -d '{"domain":"github.com","vaultId":"VAULT_UUID"}'
```

### Paso 5: Usar Autocompletado en Navegador

```
┌─────────────────────────────────────────────────────────────┐
│  🌐 Uso en Formularios Web                                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Navega a cualquier sitio de login (github.com, etc.)    │
│  2. Click en campo email/usuario                            │
│  3. Aparece sugerencia CyberVault → selecciona vault        │
│  4. Click en campo password → autocompletado seguro         │
│  5. Badge verde = sitio verificado (AiTM OK)                │
│     Badge rojo = ⚠️ Posible ataque AiTM detectado           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Detección AiTM - Cómo Funciona

### 3 Fases de Validación

| Fase | Qué Verifica | Acción si Falla |
|------|--------------|-----------------|
| **1. ExactMatch** | Hostname coincide con dominio registrado | Continúa a fase 2 |
| **2. ConfusableDetection** | Caracteres Unicode confusables (homógrafos) | **Bloquea** si riesgo alto |
| **3. Typosquatting** | Distancia Levenshtein vs dominios conocidos | Alerta si similar |

### Señales Adicionales
- **Fingerprinting DOM** - Hash SHA-256 del contenido normalizado
- **Análisis de Timing** - Detección de proxy por latencia anómala
- **Integridad DOM** - Scripts inyectados, formularios modificados, iframes
- **Seguridad Cookies** - SameSite, Secure, HttpOnly flags

### Respuesta Visual en Extensión

```
✅ VERDE  - Sitio legítimo, todas las verificaciones pasan
⚠️ AMARILLO - Advertencia (dominio similar, certificado inusual)
🔴 ROJO   - Bloqueado (AiTM detectado, homógrafo, proxy)
```

---

## 📚 API Reference

### Autenticación

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/auth/register` | POST | Registrar usuario |
| `/api/v1/auth/login` | POST | Login, retorna JWT + refresh |
| `/api/v1/auth/refresh` | POST | Renovar access token |
| `/api/v1/auth/verify` | GET | Verificar token válido |

### Vaults

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/vaults` | POST | Crear vault |
| `/api/v1/vaults` | GET | Listar vaults del usuario |
| `/api/v1/vaults/:id` | GET | Obtener vault |
| `/api/v1/vaults/:id` | DELETE | Eliminar vault |
| `/api/v1/vaults/:id/unlock` | POST | Desbloquear (retorna datos cifrados) |

### Credenciales

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/credentials/generate` | POST | Generar credenciales seguras |
| `/api/v1/credentials/extract` | POST | Extraer de vault |
| `/api/v1/credentials/validate` | POST | Validar formato (público) |
| `/api/v1/credentials` | GET | Listar credenciales |

### Sistema

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/health` | GET | Health check (DB + IPFS) |
| `/ready` | GET | Readiness check |
| `/metrics` | GET | Métricas Prometheus |
| `/api` | GET | Info de API |

---

## 🔐 Arquitectura de Seguridad

### Zero-Knowledge
- **Cifrado cliente**: AES-256-GCM con clave derivada (PBKDF2, 100k iteraciones)
- **Clave maestra**: Nunca sale del navegador del usuario
- **Servidor**: Solo ve datos cifrados (blobs opacos)

### Sal y Pimienta (Salting + Peppering)
```
Email generado:   usuario+salt@dominio.com
Password generado: password_real + pepper_derivado
```
- **Sal**: 128 bits aleatorios por credencial
- **Pimienta**: Derivada de clave maestra + dominio (HKDF-SHA256)

### Canal de Binding (Channel Binding)
- **tls-unique**: Vincula sesión TLS a credenciales
- **Nonce**: 32 bytes aleatorios por transacción
- **Timestamp**: Previene replay attacks (ventana 5 min)

---

## 🐳 Despliegue en Producción

### Docker Compose (Producción)

```yaml
# docker-compose.prod.yml
services:
  api:
    image: cybervault-api:latest
    environment:
      - NODE_ENV=production
      - USE_POSTGRES=true
      - JWT_SECRET=${JWT_SECRET}          # 48+ chars aleatorios
      - VAULT_MASTER_KEY=${VAULT_MASTER_KEY}  # 32 bytes base64
      - VAULT_ENCRYPTION_SALT=${VAULT_ENCRYPTION_SALT}  # 16 bytes base64
      - DATABASE_URL=postgresql://cybervault:${POSTGRES_PASSWORD}@postgres:5432/cybervault
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
```

### Generar Secretos Seguros

```bash
# JWT Secret (48 chars para HS256)
openssl rand -base64 48 | tr -d "=+/" | cut -c1-48

# Vault Master Key (32 bytes base64 para AES-256)
openssl rand -base64 32

# Vault Encryption Salt (16 bytes base64)
openssl rand -base64 16

# Postgres Password
openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
```

### Variables de Entorno Requeridas

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | Password BD | `Kx9mP2vL8nQ4wR7tY3uI6oP0aS1dF5gH` |
| `JWT_SECRET` | Firma tokens (48+ chars) | `J8kL2mN4pQ7rT9vX3zC6bM1qW5eR8tY0uI` |
| `VAULT_MASTER_KEY` | Clave maestra AES-256 | `uK3jH6mN9pQ2vX5zA8sD1fG4hJ7kL0` |
| `VAULT_ENCRYPTION_SALT` | Salt derivación claves | `pQ9wE2rT5yU8iO1` |
| `DATABASE_URL` | URL conexión PG | `postgresql://cybervault:PASS@postgres:5432/cybervault` |
| `USE_POSTGRES` | Usar PostgreSQL | `true` |
| `NODE_ENV` | Entorno | `production` |

---

## 🧪 Testing y Calidad

```bash
# Tests unitarios + integración
npm test

# Solo unitarios
npm run test:unit

# Coverage
npm run test:coverage

# Linting
npm run lint

# Formateo
npm run format

# Build completo
npm run build:all
```

### SonarQube (Análisis Continuo)

```bash
# Levantar SonarQube
docker compose -f docker-compose.sonarqube.yml up -d

# Ejecutar scanner
docker run --rm --network cybervault_sonarqube-net \
  -v $(pwd):/usr/src -w /usr/src \
  sonarsource/sonar-scanner-cli:latest \
  -Dsonar.host.url=http://cybervault-sonarqube:9000 \
  -Dsonar.login=TOKEN
```

---

## 🔄 Flujo de Trabajo Recomendado (Paper)

Según el paper de arquitectura CyberVault:

```
┌────────────────────────────────────────────────────────────────────┐
│                    CICLO DE VIDA DE CREDENCIAL                     │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1. GENERACIÓN          2. ALMACENAMIENTO        3. USO           │
│  ┌─────────────┐       ┌─────────────────┐      ┌─────────────┐  │
│  │ Cliente     │       │ Vault (cifrado) │      │ Formulario  │  │
│  │ - Sal aleat.│ ───▶  │ - AES-256-GCM   │ ───▶ │ - Autocomp. │  │
│  │ - Pepper    │       │ - Solo cliente  │      │ - AiTM check│  │
│  │ - HKDF      │       │ - Versionado    │      │ - Bind TLS  │  │
│  └─────────────┘       └─────────────────┘      └─────────────┘  │
│                                                                    │
│  4. VALIDACIÓN CONTINUA                                           │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │ Cada request: Hostname → Content Hash → Timing → DOM    │     │
│  │ Score agregado → DECISIÓN: allow / warn / block         │     │
│  └─────────────────────────────────────────────────────────┘     │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🆘 Troubleshooting

### API no inicia - DB connection failed
```bash
# Verificar volúmenes y red
docker compose down -v
docker compose up -d postgres redis api
```

### Extensión no autocompleta
1. Verificar que la extensión está cargada en `chrome://extensions/`
2. Recargar la página web
3. Verificar consola del content script (F12 → Console)

### AiTM false positives
- Añadir dominio a lista de confianza en Opciones
- Verificar que el certificado TLS es válido

### Puerto 3000 ocupado
```bash
# Cambiar puerto en .env
API_PORT=3010
# Reiniciar
docker compose up -d api
```

---

## 📞 Soporte y Recursos

- **Health Check**: `http://localhost:3010/health`
- **API Docs (Swagger)**: `http://localhost:3001` (con perfil docs)
- **Métricas Prometheus**: `http://localhost:3010/metrics`
- **Adminer (DB)**: `http://localhost:3002` (con perfil dev)

---

## ✅ Checklist de Verificación Final

- [ ] `.env` configurado con secretos seguros
- [ ] `docker compose up -d postgres redis api` → todos healthy
- [ ] `curl localhost:3010/health` → `{"status":"healthy"}`
- [ ] `npm run build:all` → sin errores
- [ ] Extensión cargada en `chrome://extensions/`
- [ ] Registro/login funciona via API
- [ ] Vault creado y credenciales generadas
- [ ] Autocompletado funciona en github.com (test)
- [ ] Badge verde AiTM visible en sitio legítimo

---

**Versión**: 0.1.0  
**Última actualización**: 2026-09-24  
**Estado**: Production Ready ✅