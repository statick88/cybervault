#!/bin/sh

# Script de entrada para IPFS
# Inicializa el repo si no existe

if [ ! -f /data/ipfs/config ]; then
    echo "Inicializando IPFS repo..."
    ipfs init --profile server
    ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
    ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
    ipfs config --json Swarm.RelayClient.Enabled true
    ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'
    ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["GET", "POST", "PUT"]'
    ipfs config --json API.HTTPHeaders.Access-Control-Allow-Headers '["Authorization"]'
else
    echo "IPFS repo ya existe. Continuando..."
fi

# Ejecutar comando IPFS original
exec ipfs "$@"
