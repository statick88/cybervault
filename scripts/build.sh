#!/bin/bash

# CyberVault Build Script
# Build y package para Chrome Web Store

set -e

echo "🔨 Iniciando build de CyberVault..."

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directorios
DIST_DIR="dist"
SRC_DIR="src"

# Limpiar build anterior
echo "🧹 Limpiando build anterior..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Copiar manifest
echo "📋 Copiando manifest..."
mkdir -p "$DIST_DIR"
cp "$SRC_DIR/infrastructure/manifest/manifest.json" "$DIST_DIR/"

# Compilar TypeScript
echo "⚙️ Compilando TypeScript..."
npx tsc --project tsconfig.json --outDir "$DIST_DIR" --declaration false --declarationMap false 2>&1 || true

# Copiar archivos estáticos (solo HTML y CSS)
echo "📄 Copiando archivos estáticos..."
# Popup
mkdir -p "$DIST_DIR/ui/popup"
cp "$SRC_DIR/ui/popup/popup.html" "$DIST_DIR/ui/popup/"
cp "$SRC_DIR/ui/popup/popup.css" "$DIST_DIR/ui/popup/"
# Options
mkdir -p "$DIST_DIR/ui/options"
cp "$SRC_DIR/ui/options/options.html" "$DIST_DIR/ui/options/"
cp "$SRC_DIR/ui/options/options.css" "$DIST_DIR/ui/options/"
# Content scripts - mover los JS compilados
mkdir -p "$DIST_DIR/ui/content-scripts"

# Crear directorio de iconos y copiar
mkdir -p "$DIST_DIR/icons"
cp -r "$SRC_DIR/icons/"* "$DIST_DIR/icons/" 2>/dev/null || true

# Verificar que los archivos esenciales existan
echo "✅ Verificando archivos..."
REQUIRED_FILES=(
    "$DIST_DIR/manifest.json"
    "$DIST_DIR/ui/popup/popup.html"
    "$DIST_DIR/ui/popup/popup.css"
    "$DIST_DIR/ui/popup/popup.js"
    "$DIST_DIR/ui/options/options.html"
    "$DIST_DIR/ui/options/options.css"
    "$DIST_DIR/ui/options/options.js"
    "$DIST_DIR/ui/content-scripts/inject.js"
    "$DIST_DIR/background/auditor.js"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Error: Archivo faltante: $file${NC}"
        exit 1
    fi
done

# Generar ZIP para Chrome Web Store
VERSION=${VERSION:-"1.0.0"}
echo "📦 Generando paquete ZIP..."
cd "$DIST_DIR"
zip -r "cybervault-$VERSION.zip" . -x "*.map" -x "*.zip" || true
cd ..

# Instrucciones finales
echo ""
echo -e "${GREEN}✅ Build completado exitosamente!${NC}"
echo ""
echo "📂 Archivos generados en: $DIST_DIR/"
echo "📦 Paquete ZIP: $DIST_DIR/cybervault-$VERSION.zip"
echo ""
echo "📝 Próximos pasos:"
echo "   1. Ve a Chrome Web Store Developer Dashboard"
echo "   2. Sube el archivo ZIP"
echo "   3. Completa los detalles de la extensión"
echo ""
