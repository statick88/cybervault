# 📋 Changelog - CyberVault

Todos los cambios notables de este proyecto se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhieren a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-03-11

### Added
- 🎉 **Lanzamiento inicial de CyberVault MVP**

#### Funcionalidades Core
- Sistema de gestión de credenciales con CRUD completo
- Encriptación de 4 capas (X25519, Argon2id, AES-256, ChaCha20-Poly1305)
- Generador de contraseñas seguras
- Interfaz de usuario en español
- Auditoría básica de seguridad

#### UI/UX
- Popup principal con lista de credenciales
- Modal para agregar nuevas credenciales
- Modal para editar credenciales
- Modal para eliminar credenciales (con confirmación)
- Modal para ver detalles de credenciales
- Sistema de pestañas (Todas, Favoritas, Recientes)
- Buscador de credenciales
- Generador de contraseñas integrado

#### Infraestructura
- Estructura de Chrome Extension (Manifest V3)
- Clean Architecture con TypeScript
- Pipeline CI/CD con GitHub Actions

### Changed
- Migración de estructura plana a Clean Architecture
- Implementación de sistema de capas de encriptación
- Refactorización de servicios del dominio

### Fixed
- Bug: Contraseña no se guardaba al crear credencial
- Mejora en manejo de eventos de modales

---

## [0.0.1] - 2026-02-01

### Added
- Prototipo inicial del popup
- Estructura básica de HTML/CSS
- Primer build de la extensión

---

## Formato de Entradas

```
## [VERSION] - YYYY-MM-DD

### Added
- Nuevas funcionalidades

### Changed
- Cambios en funcionalidades existentes

### Deprecated
- Funcionalidades que serán eliminadas en futuras versiones

### Removed
- Funcionalidades eliminadas en esta versión

### Fixed
- Corrección de bugs

### Security
- Cambios relacionados con seguridad
```

---

## Cómo Contribuir al Changelog

1. Usa tipos de cambio estándar:
   - `Added` para nuevas funcionalidades
   - `Changed` para cambios en funcionalidades existentes
   - `Deprecated` para funcionalidades en desuso
   - `Removed` para funcionalidades eliminadas
   - `Fixed` para corrección de bugs
   - `Security` para cambios de seguridad

2. Sigue el formato de arriba

3. Agrega el PR number si aplica: `([#123])`

---

## Versiones Anteriores

Las versiones anteriores están disponibles en las etiquetas del repositorio.

---

*Este Changelog fue inspirado por Keep a Changelog y las mejores prácticas de código abierto.*
