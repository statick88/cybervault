#!/bin/bash

# Script para detener entorno local
# Uso: ./stop-local.sh [mode]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INFRA_DIR="$PROJECT_ROOT/infra"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

MODE=${1:-docker}
if [[ ! "$MODE" =~ ^(docker|kubernetes|kind)$ ]]; then
    echo -e "${RED}Error: Modo inválido. Usar: docker | kubernetes | kind${NC}"
    exit 1
fi

echo -e "${GREEN}=== Deteniendo Cyber Vault - Modo: $MODE ===${NC}"

if [ "$MODE" = "docker" ]; then
    cd "$INFRA_DIR/docker"
    docker-compose down
    
elif [ "$MODE" = "kubernetes" ]; then
    cd "$INFRA_DIR/kubernetes"
    kubectl delete -f . --ignore-not-found=true
    
elif [ "$MODE" = "kind" ]; then
    kind delete cluster --name cyber-vault
    echo -e "${YELLOW}Cluster Kind eliminado${NC}"
fi

echo -e "${GREEN}=== Entorno detenido ===${NC}"
