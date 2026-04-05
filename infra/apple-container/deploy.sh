#!/bin/bash
# Script de despliegue para Apple Container

set -e

echo "🚀 Desplegando CyberVault con Apple Container..."

# Directorios
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DATA_DIR="$ROOT_DIR/data"
APPLE_DIR="$ROOT_DIR/apple-container"

# Crear directorios de datos
mkdir -p "$DATA_DIR/vault"
mkdir -p "$DATA_DIR/ipfs"
mkdir -p "$DATA_DIR/postgres"
mkdir -p "$DATA_DIR/auditor"

# 1. Construir imágenes con Docker (usando Colima)
echo "📦 Construyendo imágenes..."

# API
echo "  - Construyendo API..."
docker build -t cybervault-api:latest \
  -f "$ROOT_DIR/infra/docker/Dockerfile.api" \
  "$ROOT_DIR"

# IPFS
echo "  - Construyendo IPFS..."
docker build -t cybervault-ipfs:latest \
  -f "$ROOT_DIR/infra/docker/Dockerfile.ipfs" \
  "$ROOT_DIR"

# 2. Crear red personalizada en Apple Container
echo "🌐 Creando red personalizada..."
xcrun container network create cybervault-net 2>/dev/null || echo "Red ya existe"

# 3. Iniciar PostgreSQL con Apple Container
echo "🗄️ Iniciando PostgreSQL..."
xcrun container run -d \
  --name cybervault-postgres \
  --network cybervault-net \
  --volume cybervault-postgres-data:/var/lib/postgresql/data \
  -e POSTGRES_DB=cyber_vault \
  -e POSTGRES_USER=cyberuser \
  -e POSTGRES_PASSWORD=cyberpass \
  postgres:15-alpine

# 4. Iniciar IPFS con Apple Container
echo "🔗 Iniciando IPFS Node..."
xcrun container run -d \
  --name cybervault-ipfs \
  --network cybervault-net \
  --volume cybervault-ipfs-data:/data/ipfs \
  -e IPFS_PROFILE=server \
  cybervault-ipfs:latest

# 5. Iniciar API con Apple Container
echo "⚡ Iniciando API Backend..."
xcrun container run -d \
  --name cybervault-api \
  --network cybervault-net \
  --volume cybervault-data:/app/data \
  -p 3000:3000 \
  -e NODE_ENV=development \
  -e PORT=3000 \
  -e IPFS_HOST=cybervault-ipfs:5001 \
  -e DATABASE_URL=postgres://cyberuser:cyberpass@cybervault-postgres:5432/cyber_vault \
  cybervault-api:latest

# 6. Iniciar Auditor
echo "🔍 Iniciando Auditor..."
xcrun container run -d \
  --name cybervault-auditor \
  --network cybervault-net \
  --volume cybervault-auditor-data:/app/data \
  -e NODE_ENV=development \
  -e AUDITOR_MODE=background \
  -e IPFS_HOST=cybervault-ipfs:5001 \
  cybervault-api:latest

echo ""
echo "✅ CyberVault desplegado con Apple Container"
echo ""
echo "Servicios disponibles:"
echo "  - API Backend:    http://localhost:3000"
echo "  - IPFS API:       http://localhost:5001"
echo "  - IPFS Gateway:   http://localhost:8080"
echo "  - PostgreSQL:     localhost:5432"
echo ""
echo "Comandos útiles:"
echo "  - Ver logs:       xcrun container logs <nombre>"
echo "  - Ver estado:     xcrun container list"
echo "  - Detener:        xcrun container stop <nombre>"
echo "  - Eliminar:       xcrun container rm <nombre>"
