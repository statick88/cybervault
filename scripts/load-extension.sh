#!/bin/bash
# Script para cargar la extensión de CyberVault en Chrome

EXTENSION_DIR="/Users/statick/apps/cybervault/dist"

echo "📂 Cargando extensión de CyberVault..."
echo "Directorio: $EXTENSION_DIR"

# Verificar que el directorio existe
if [ ! -d "$EXTENSION_DIR" ]; then
    echo "❌ Error: Directorio de extensión no encontrado"
    exit 1
fi

# Verificar que el manifest.json existe
if [ ! -f "$EXTENSION_DIR/manifest.json" ]; then
    echo "❌ Error: manifest.json no encontrado"
    exit 1
fi

echo "✅ Extensión lista para cargar"
echo ""
echo "Instrucciones manuales:"
echo "1. Abre Chrome y ve a: chrome://extensions"
echo "2. Activa el 'Modo desarrollador' (esquina superior derecha)"
echo "3. Haz clic en 'Cargar extensión sin empaquetar'"
echo "4. Selecciona el directorio: $EXTENSION_DIR"
echo ""
echo "La extensión estará disponible en la barra de herramientas de Chrome."

# Abrir Chrome con la página de extensiones
open -a "Google Chrome" "chrome://extensions"
