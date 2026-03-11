#!/bin/bash

# Script para iniciar entorno local con Docker Compose
# Uso: ./start-local.sh [mode]
# mode: docker | kubernetes | kind

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INFRA_DIR="$PROJECT_ROOT/infra"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Validar modo
MODE=${1:-docker}
if [[ ! "$MODE" =~ ^(docker|kubernetes|kind)$ ]]; then
    echo -e "${RED}Error: Modo inválido. Usar: docker | kubernetes | kind${NC}"
    exit 1
fi

echo -e "${GREEN}=== Iniciando Cyber Vault - Modo: $MODE ===${NC}"

# Verificar dependencias
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 no está instalado${NC}"
        exit 1
    fi
}

if [ "$MODE" = "docker" ]; then
    check_dependency docker
    check_dependency docker-compose
    
    echo -e "${YELLOW}Iniciando servicios con Docker Compose...${NC}"
    cd "$INFRA_DIR/docker"
    
    # Crear directorios de datos
    mkdir -p data/{vault,ipfs,postgres,auditor}
    
    # Iniciar servicios
    docker-compose up -d --build
    
    echo -e "${GREEN}Servicios iniciados:${NC}"
    echo "  - Vault API: http://localhost:3000"
    echo "  - IPFS API: http://localhost:5001"
    echo "  - IPFS Gateway: http://localhost:8080"
    echo "  - PostgreSQL: localhost:5432"
    
elif [ "$MODE" = "kubernetes" ]; then
    check_dependency kubectl
    
    echo -e "${YELLOW}Iniciando servicios con Kubernetes local...${NC}"
    cd "$INFRA_DIR/kubernetes"
    
    # Aplicar manifestos
    kubectl apply -f namespace.yml
    kubectl apply -f configmap.yml
    kubectl apply -f secrets.yml
    kubectl apply -f persistent-volumes.yml
    kubectl apply -f deployment-ipfs.yml
    kubectl apply -f deployment-vault-api.yml
    kubectl apply -f service-vault.yml
    kubectl apply -f service-ipfs.yml
    kubectl apply -f network-policy.yml
    
    echo -e "${YELLOW}Esperando a que los pods estén listos...${NC}"
    kubectl wait --for=condition=ready pod -l app=vault-api -n cyber-vault-dev --timeout=120s
    kubectl wait --for=condition=ready pod -l app=ipfs-node -n cyber-vault-dev --timeout=120s
    
    echo -e "${GREEN}Servicios Kubernetes iniciados:${NC}"
    kubectl get svc -n cyber-vault-dev
    
elif [ "$MODE" = "kind" ]; then
    check_dependency kind
    check_dependency kubectl
    
    echo -e "${YELLOW}Creando cluster Kind...${NC}"
    cd "$INFRA_DIR/kubernetes"
    
    # Crear cluster si no existe
    if ! kind get clusters | grep -q "cyber-vault"; then
        cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 3000
    protocol: TCP
  - containerPort: 30001
    hostPort: 5001
    protocol: TCP
  - containerPort: 30002
    hostPort: 8080
    protocol: TCP
EOF
    fi
    
    # Construir imagen local
    docker build -t cyber-vault/api:latest -f infra/docker/Dockerfile.api .
    
    # Cargar imagen en Kind
    kind load docker-image cyber-vault/api:latest --name cyber-vault
    
    # Aplicar manifestos
    kubectl apply -f namespace.yml
    kubectl apply -f configmap.yml
    kubectl apply -f secrets.yml
    kubectl apply -f persistent-volumes.yml
    kubectl apply -f deployment-ipfs.yml
    kubectl apply -f deployment-vault-api.yml
    kubectl apply -f service-vault.yml
    kubectl apply -f service-ipfs.yml
    kubectl apply -f network-policy.yml
    
    echo -e "${GREEN}Cluster Kind iniciado y servicios desplegados${NC}"
    echo "  - Vault API: http://localhost:3000"
    echo "  - IPFS API: http://localhost:5001"
    echo "  - IPFS Gateway: http://localhost:8080"
fi

echo -e "${GREEN}=== Entorno listo para pruebas ===${NC}"
