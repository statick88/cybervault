# CyberVault - Desarrollo con Apple Container

Este documento describe cómo configurar y usar Apple Container para el desarrollo local de CyberVault.

## Requisitos

- macOS 26 (Tahoe) o superior
- Apple Silicon (M1, M2, M3, M4, M5)
- Xcode Command Line Tools

## Instalación

### Verificar Apple Container

```bash
# Verificar que Apple Container está disponible
xcrun container --version

# Iniciar el sistema de contenedores
xcrun container system start

# Verificar estado
xcrun container system status

# Verificar builder
xcrun container builder status
```

## Servicios Disponibles

| Servicio    | IP               | Puerto  | Estado    |
|-------------|------------------|---------|-----------|
| API         | 192.168.65.7    | 3000    | ✅        |
| PostgreSQL  | 192.168.65.9    | 5432    | ✅        |
| IPFS       | 192.168.65.10   | 5001    | ✅        |

## Red y Volúmenes

### Crear red personalizada

```bash
xcrun container network create cybervault-net
```

### Crear volúmenes

```bash
xcrun container volume create cybervault-data
xcrun container volume create cybervault-postgres-data
xcrun container volume create cybervault-ipfs-data
```

## Comandos Útiles

### Iniciar Servicios

```bash
# 1. Asegurarse que el sistema de contenedores esté corriendo
xcrun container system start

# 2. Verificar que el builder esté disponible
xcrun container builder status

# 3. Crear red y volúmenes si no existen
xcrun container network create cybervault-net
xcrun container volume create cybervault-data
xcrun container volume create cybervault-postgres-data
xcrun container volume create cybervault-ipfs-data

# 4. Iniciar PostgreSQL
xcrun container run -d \
  --name cybervault-postgres \
  --network cybervault-net \
  --volume cybervault-postgres-data:/var/lib/postgresql \
  -e POSTGRES_DB=cyber_vault \
  -e POSTGRES_USER=cyberuser \
  -e POSTGRES_PASSWORD=cyberpass \
  postgres:15-alpine

# 5. Compilar TypeScript
cd /Users/statick/apps/cybervault
npm run build

# 6. Iniciar API
xcrun container run -d \
  --name cybervault-api \
  --network cybervault-net \
  --volume cybervault-data:/app/data \
  --volume ./dist:/app/dist \
  --volume ./node_modules:/app/node_modules \
  -p 3000:3000 \
  -e NODE_ENV=development \
  -e PORT=3000 \
  node:20-alpine sh -c "cd /app && node dist/infrastructure/api/server.js"

# 7. Iniciar IPFS
xcrun container run -d \
  --name cybervault-ipfs \
  --network cybervault-net \
  --volume cybervault-ipfs-data:/data/ipfs \
  -e IPFS_PROFILE=server \
  -p 4001:4001 \
  -p 5001:5001 \
  -p 8080:8080 \
  ipfs/kubo:latest
```

### Verificar Servicios

```bash
# Ver contenedores
xcrun container list --all

# Ver logs de un servicio
xcrun container logs cybervault-api

# Acceder a la API
curl http://192.168.65.7:3000/health

# Acceder a IPFS (usa POST, no GET)
curl -X POST http://192.168.65.10:5001/api/v0/version

# Obtener IP del contenedor
xcrun container exec <nombre> ip addr show eth0 | grep "inet "
```

### Detener y Limpiar Servicios

```bash
# Detener contenedores
xcrun container stop cybervault-api
xcrun container stop cybervault-postgres
xcrun container stop cybervault-ipfs

# Eliminar contenedores
xcrun container rm cybervault-api cybervault-postgres cybervault-ipfs

# Eliminar volúmenes (¡CUIDADO! Esto borra datos)
xcrun container volume delete cybervault-data
xcrun container volume delete cybervault-postgres-data
xcrun container volume delete cybervault-ipfs-data

# Eliminar red
xcrun container network delete cybervault-net
```

## Chrome Extension

### Desarrollo

```bash
# Compilar TypeScript
npm run build

# Compilar extensión
npm run build:ext

# La extensión se genera en dist/
```

### Cargar en Chrome

1. Abre Chrome y ve a `chrome://extensions`
2. Activa el "Modo desarrollador"
3. Haz clic en "Cargar extensión sin empaquetar"
4. Selecciona el directorio `dist/`

### Solución de Errores

#### Error: "Unable to download all specified images"

Este error ocurre cuando la extensión intenta analizar imágenes en páginas web. Solución:

1. Asegúrate de tener los permisos correctos en `manifest.json`:

```json
{
  "permissions": [
    "storage", 
    "alarms", 
    "notifications", 
    "tabs", 
    "activeTab", 
    "scripting"
  ],
  "host_permissions": [
    "https://api.pwnedpasswords.com/*",
    "https://otx.alienvault.com/*",
    "https://api.github.com/*",
    "http://192.168.65.7:3000/*",
    "https://*/*"
  ]
}
```

2. La CSP debe permitir conexiones a la API local:

```json
{
  "content_security_policy": {
    "extension_pages": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; connect-src 'self' https://api.pwnedpasswords.com https://otx.alienvault.com https://api.github.com https://* http://192.168.65.7:3000; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
  }
}
```

3. Recompila la extensión después de hacer cambios:
```bash
npm run build:ext
```

## API Endpoints

### Credenciales

```bash
# Generar credenciales con sal y pimienta
curl -X POST http://192.168.65.7:3000/api/v1/credentials/generate \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Extraer credenciales originales
curl -X POST http://192.168.65.7:3000/api/v1/credentials/extract \
  -H "Content-Type: application/json" \
  -d '{"email": "...", "password": "..."}'

# Validar formato
curl http://192.168.65.7:3000/api/v1/credentials/validate?credential=...

# Health check
curl http://192.168.65.7:3000/health
```

### Respuestas de Ejemplo

#### Generar credenciales
```json
{
  "email": "usuario+a1b2c3d4e5f6@example.com",
  "password": "P@ssw0rd!123+abc123",
  "originalEmail": "usuario@example.com",
  "originalPassword": "P@ssw0rd!123",
  "domain": "example.com",
  "quality": {
    "isValid": true,
    "entropy": {
      "salt": 128,
      "pepper": 128,
      "passwordBase": 209.7
    }
  }
}
```

## Tests

```bash
# Ejecutar todos los tests
npm run test

# Tests unitarios del módulo de credenciales
npm run test:unit -- tests/unit/domain/services/autocompletado/

# Tests de integración
npm run test:integration

# Coverage
npm run test:coverage
```

## Integración con Apple Container (Build de Imágenes)

### Construir imágenes

```bash
# Verificar builder
xcrun container builder status

# Construir imagen de API (puede tomar varios minutos)
cd /Users/statick/apps/cybervault
xcrun container build -t cybervault-api:latest \
  -f infra/docker/Dockerfile.api .
```

## Variables de Entorno

```bash
# API
NODE_ENV=development
PORT=3000
DATABASE_URL=postgres://cyberuser:cyberpass@192.168.65.9:5432/cyber_vault
IPFS_HOST=192.168.65.10:5001

# PostgreSQL
POSTGRES_DB=cyber_vault
POSTGRES_USER=cyberuser
POSTGRES_PASSWORD=cyberpass

# IPFS
IPFS_PROFILE=server
```

## Notas

- Apple Container usa IPs específicas (192.168.65.x) para acceder a servicios
- La API necesita permisos de host en manifest.json para Chrome Extension
- La CSP debe permitir conexiones a la API local
- IPFS usa POST para la API (no GET)
- PostgreSQL requiere volumen con subdirectorio (/var/lib/postgresql)
- El builder de Apple Container debe estar corriendo para construir imágenes
- Los contenedores deben estar en la misma red para comunicarse entre sí
