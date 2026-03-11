#!/bin/bash

# Script para ejecutar pruebas en entorno local
# Uso: ./test-local.sh [mode]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

MODE=${1:-docker}
if [[ ! "$MODE" =~ ^(docker|kubernetes)$ ]]; then
    echo -e "${RED}Error: Modo inválido. Usar: docker | kubernetes${NC}"
    exit 1
fi

echo -e "${GREEN}=== Ejecutando pruebas - Modo: $MODE ===${NC}"

if [ "$MODE" = "docker" ]; then
    echo -e "${YELLOW}Ejecutando pruebas en contenedores Docker...${NC}"
    
    # Pruebas unitarias
    echo -e "${YELLOW}1. Pruebas unitarias...${NC}"
    docker-compose -f infra/docker/docker-compose.yml run --rm vault-api npm test
    
    # Pruebas de integración
    echo -e "${YELLOW}2. Pruebas de integración...${NC}"
    docker-compose -f infra/docker/docker-compose.yml run --rm vault-api npm run test:integration
    
    # Pruebas de seguridad
    echo -e "${YELLOW}3. Pruebas de seguridad...${NC}"
    ./infra/scripts/security-scan.sh docker
    
elif [ "$MODE" = "kubernetes" ]; then
    echo -e "${YELLOW}Ejecutando pruebas en Kubernetes...${NC}"
    
    # Pruebas unitarias
    echo -e "${YELLOW}1. Pruebas unitarias...${NC}"
    kubectl exec -n cyber-vault-dev deployment/vault-api -- npm test
    
    # Pruebas de integración
    echo -e "${YELLOW}2. Pruebas de integración...${NC}"
    kubectl exec -n cyber-vault-dev deployment/vault-api -- npm run test:integration
    
    # Pruebas de seguridad
    echo -e "${YELLOW}3. Pruebas de seguridad...${NC}"
    ./infra/scripts/security-scan.sh kubernetes
fi

echo -e "${GREEN}=== Pruebas completadas ===${NC}"
