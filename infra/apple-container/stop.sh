#!/bin/bash
# Script para detener servicios de Apple Container

set -e

echo "🛑 Deteniendo servicios de CyberVault..."

# Detener contenedores
for container in cybervault-api cybervault-ipfs cybervault-postgres cybervault-auditor; do
  if xcrun container list | grep -q "$container"; then
    echo "  - Deteniendo $container..."
    xcrun container stop "$container" 2>/dev/null || true
    xcrun container rm "$container" 2>/dev/null || true
  fi
done

# Eliminar red (opcional)
echo "  - Eliminando red..."
xcrun container network rm cybervault-net 2>/dev/null || true

echo ""
echo "✅ Servicios detenidos"
echo ""
echo "Para eliminar datos persistentes, ejecuta:"
echo "  xcrun container volume rm cybervault-postgres-data cybervault-ipfs-data cybervault-data cybervault-auditor-data"
