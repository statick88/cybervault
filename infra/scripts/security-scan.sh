#!/bin/bash

# Script para escaneo de seguridad
# Uso: ./security-scan.sh [mode]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

MODE=${1:-docker}

echo -e "${GREEN}=== Escaneo de Seguridad - Modo: $MODE ===${NC}"

if [ "$MODE" = "docker" ]; then
    echo -e "${YELLOW}Escaneando imágenes Docker...${NC}"
    
    # Escaneo de vulnerabilidades con Trivy
    if command -v trivy &> /dev/null; then
        echo "Escaneando imagen vault-api..."
        trivy image --severity HIGH,CRITICAL cyber-vault/api:latest
        
        echo "Escaneando imagen IPFS..."
        trivy image --severity HIGH,CRITICAL ipfs/go-ipfs:v0.13.0
    else
        echo -e "${YELLOW}Trivy no instalado, saltando escaneo de imágenes${NC}"
    fi
    
    # Escaneo de configuración Docker
    echo -e "${YELLOW}Escaneando configuración Docker...${NC}"
    docker-compose -f infra/docker/docker-compose.yml config | grep -i "password\|secret\|key" || true
    
elif [ "$MODE" = "kubernetes" ]; then
    echo -e "${YELLOW}Escaneando recursos Kubernetes...${NC}"
    
    # Verificar secrets
    echo -e "${YELLOW}1. Verificando secrets...${NC}"
    kubectl get secrets -n cyber-vault-dev -o yaml | grep -A5 "kind: Secret" | grep -i "password\|key" || true
    
    # Verificar network policies
    echo -e "${YELLOW}2. Verificando network policies...${NC}"
    kubectl get networkpolicies -n cyber-vault-dev -o yaml
    
    # Escaneo de políticas de seguridad
    echo -e "${YELLOW}3. Verificando security contexts...${NC}"
    kubectl get pods -n cyber-vault-dev -o yaml | grep -A10 "securityContext:" || true
fi

# Escaneo de dependencias Node.js
echo -e "${YELLOW}Escaneando dependencias Node.js...${NC}"
cd "$PROJECT_ROOT"
if command -v npm &> /dev/null; then
    npm audit --audit-level=high
fi

# Escaneo de código estático
echo -e "${YELLOW}Escaneando código estático...${NC}"
if command -v eslint &> /dev/null; then
    npm run lint
fi

echo -e "${GREEN}=== Escaneo de seguridad completado ===${NC}"
