# 🔐 CyberVault

> Gestor de Credenciales Zero-Knowledge con 4 Capas de Encriptación y Monitoreo de Vulnerabilidades

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-brightgreen)](https://developer.chrome.com/docs/extensions/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Zero--Knowledge-orange)](https://security.google/)

## 📋 Descripción

CyberVault es un gestor de contraseñas Zero-Knowledge diseñado para ofrecer máxima seguridad mediante un sistema de encriptación de 4 capas. La aplicación funciona como una extensión de Chrome y nunca envía las contraseñas fuera del dispositivo del usuario sin encriptación.

### Características Principales

- 🔒 **Zero-Knowledge**: Las contraseñas nunca salen del dispositivo sin encriptar
- 🛡️ **4 Capas de Encriptación**: AES-256, ChaCha20-Poly1305, Argon2id, X25519
- 🔍 **Monitoreo de Brechas**: Detecta si tus credenciales han sido comprometidas
- 📱 **Sincronización Segura**: IPFS cifrado para backup distribuido
- 🎲 **Generador de Contraseñas**: Contraseñas seguras aleatorias
- 🏷️ **Organización**: Etiquetas, favoritos y búsqueda avanzada

## 🚀 Instalación

### Requisitos Previos

- Node.js 18+ 
- npm 9+
- Chrome 120+ (o cualquier navegador basado en Chromium)

### Pasos de Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/statick88/cybervault.git
cd cybervault

# 2. Instalar dependencias
npm install

# 3. Compilar TypeScript
npm run build

# 4. Cargar en Chrome
# - Abre chrome://extensions/
# - Activa "Developer mode"
# - Click en "Load unpacked"
# - Selecciona la carpeta dist/
```

## 📖 Documentación

| Documento | Descripción |
|------------|-------------|
| [📖 Manual de Usuario](docs/manual-usuario.md) | Guía completa para usuarios finales |
| [👨‍💻 Manual de Desarrollador](docs/manual-desarrollador.md) | Guía para contribuir al proyecto |
| [🏗️ Arquitectura](docs/arquitectura.md) | Documentación técnica de arquitectura |
| [📊 Diagramas](docs/diagramas/) | Diagramas de arquitectura visual |

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                      CyberVault                              │
├─────────────────────────────────────────────────────────────┤
│  UI Layer (Popup, Options, Content Scripts)                │
├─────────────────────────────────────────────────────────────┤
│  Domain Layer (Entities, Services, Repositories)           │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                       │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐ │
│  │   Crypto    │     IPFS    │    API     │   Storage   │ │
│  │   Service   │   Adapter   │   Server   │   Local    │ │
│  └─────────────┴─────────────┴─────────────┴─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Capas de Encriptación

1. **Capa 1 - X25519**: Intercambio de claves Diffie-Hellman
2. **Capa 2 - Argon2id**: Derivación de claves resistente a GPU
3. **Capa 3 - AES-256-GCM**: Encriptación simétrica
4. **Capa 4 - ChaCha20-Poly1305**: Autenticación de datos

## 🛠️ Comandos

```bash
# Desarrollo
npm run dev          # Modo desarrollo con watch
npm run build        # Compilar extensión
npm run build:ext    # Compilar extensión completa

# Testing
npm test             # Ejecutar tests
npm run test:watch  # Tests en modo watch
npm run coverage     # Coverage report

# Calidad de Código
npm run lint         # Linter
npm run format       # Formateo automático

# Seguridad
npm run security     # Escaneo de vulnerabilidades
```

## 📁 Estructura del Proyecto

```
cybervault/
├── src/
│   ├── background/          # Service workers
│   │   ├── auditor.ts       # Auditor de seguridad
│   │   ├── breach-detector.ts
│   │   └── credential-monitor.ts
│   ├── domain/             # Lógica de negocio
│   │   ├── entities/       # Entidades del dominio
│   │   ├── services.ts     # Servicios
│   │   └── repositories.ts # Repositorios
│   ├── infrastructure/      # Implementación técnica
│   │   ├── api/           # Servidor API
│   │   ├── crypto/        # Servicios criptográficos
│   │   └── ipfs/          # Adaptador IPFS
│   └── ui/                # Interfaz de usuario
│       ├── popup/         # Popup principal
│       ├── options/       # Página de opciones
│       └── content-scripts/
├── dist/                  # Extensión compilada
├── scripts/               # Scripts de build
├── docs/                  # Documentación
└── tests/                 # Tests
```

## 🔐 Seguridad

### Modelo de Amenazas

CyberVault está diseñado para proteger contra:

- 💻 **Malware Local**: Credenciales en memoria segura
- 🌐 **Ataques de Red**: Zero-Knowledge, sin exponer plaintext
- 🔓 **Brechas de Servicios**: Detección proactiva de comprometidas
- 👤 **Ingeniería Social**: Autenticación locally

### Auditoría de Seguridad

```bash
# Ejecutar análisis de seguridad
npm run security
```

### Reportar Vulnerabilidades

Si encuentras una vulnerabilidad de seguridad, por favor consulta [SECURITY.md](SECURITY.md).

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) antes de comenzar.

1. Fork el proyecto
2. Crea tu rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver [LICENSE](LICENSE) para más detalles.

## 🙏 Agradecimientos

- [Gentleman Programming](https://gentlemanprogramming.com) - Filosofía de código
- [Chrome Extensions](https://developer.chrome.com/docs/extensions/) - Documentación
- [Node.js Crypto](https://nodejs.org/api/crypto.html) - Criptografía nativa

---

<p align="center">
  <sub>Construido con 🔐 por <a href="https://github.com/statick88">@statick88</a></sub>
</p>
