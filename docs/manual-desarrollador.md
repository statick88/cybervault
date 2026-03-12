# 👨‍💻 Manual del Desarrollador - CyberVault

## Tabla de Contenidos

1. [Introducción](#introducción)
2. [Configuración del Entorno](#configuración-del-entorno)
3. [Estructura del Proyecto](#estructura-del-proyecto)
4. [Arquitectura](#arquitectura)
5. [Desarrollo](#desarrollo)
6. [Testing](#testing)
7. [Build y Deployment](#build-y-deployment)
8. [Seguridad](#seguridad)
9. [Contribuir](#contribuir)

---

## 1. Introducción

Este documento está dirigido a desarrolladores que desean contribuir o extender CyberVault.

### Tecnologías Usadas

| Tecnología | Uso |
|------------|-----|
| **TypeScript 5.3** | Lenguaje principal |
| **Chrome Extensions** | Plataforma destino |
| **Node.js Crypto** | Criptografía nativa |
| **esbuild** | Bundling |
| **Jest** | Testing |
| **IPFS** | Almacenamiento distribuido |

### Requisitos Previos

```bash
# Node.js 18+
node --version  # >= 18.0.0

# npm 9+
npm --version   # >= 9.0.0

# Git
git --version
```

---

## 2. Configuración del Entorno

### Clonar y Instalar

```bash
# 1. Clonar repositorio
git clone https://github.com/statick88/cybervault.git
cd cybervault

# 2. Instalar dependencias
npm install

# 3. Verificar instalación
npm run build
```

### Variables de Entorno

Crea un archivo `.env` en la raíz:

```env
# Desarrollo
NODE_ENV=development

# Producción (no enviar a git)
# NODE_ENV=production

# IPFS (opcional)
# IPFS_API_URL=http://localhost:5001
# IPFS_GATEWAY=https://ipfs.io

# API Externa (para auditorías)
# PWNED_API_KEY=your_key_here
# ALIENVAULT_API_KEY=your_key_here
```

### IDE Recomendado

**VS Code** con extensiones:
- ESLint
- Prettier
- TypeScript Hero
- GitLens

---

## 3. Estructura del Proyecto

```
cybervault/
├── src/
│   ├── background/           # Service Workers
│   │   ├── auditor.ts       # Auditor de seguridad
│   │   ├── breach-detector.ts
│   │   └── credential-monitor.ts
│   │
│   ├── domain/              # Capa de Dominio (Business Logic)
│   │   ├── entities/        # Entidades
│   │   │   ├── credential.ts
│   │   │   ├── vault.ts
│   │   │   └── vulnerability.ts
│   │   ├── services.ts      # Servicios del dominio
│   │   ├── repositories.ts  # Interfaces de repositorios
│   │   └── value-objects/   # Objetos de valor
│   │
│   ├── infrastructure/      # Capa de Infraestructura
│   │   ├── api/           # API server
│   │   ├── crypto/        # Servicios criptográficos
│   │   │   ├── crypto-service.ts
│   │   │   ├── crypto-layered-service.ts
│   │   │   ├── secure-memory.ts
│   │   │   └── layers/    # Capas de encriptación
│   │   └── ipfs/          # Adaptador IPFS
│   │
│   └── ui/                 # Capa de Presentación
│       ├── popup/          # Popup principal
│       │   ├── popup.ts    # Lógica
│       │   ├── popup.html  # Estructura
│       │   └── popup.css  # Estilos
│       ├── options/        # Página de opciones
│       └── content-scripts/# Scripts de contenido
│
├── dist/                   # Extensión compilada
├── scripts/               # Scripts de build
├── tests/                 # Tests
└── docs/                  # Documentación
```

---

## 4. Arquitectura

### Capas (Clean Architecture)

```
┌─────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                        │
│         (Popup, Options, Content Scripts)                   │
├─────────────────────────────────────────────────────────────┤
│                    APPLICATION LAYER                         │
│              (Use Cases, Services)                          │
├─────────────────────────────────────────────────────────────┤
│                      DOMAIN LAYER                            │
│          (Entities, Value Objects, Interfaces)              │
├─────────────────────────────────────────────────────────────┤
│                   INFRASTRUCTURE LAYER                      │
│    (Crypto, Storage, IPFS, External APIs)                  │
└─────────────────────────────────────────────────────────────┘
```

### Flujo de Datos

```
Usuario → Popup → Domain Service → Repository → Crypto → Storage
                ↓
         Background (Auditor)
                ↓
         Breach Detector → External APIs
```

---

## 5. Desarrollo

### Comandos de Desarrollo

```bash
# Desarrollo con watch
npm run dev

# Compilar TypeScript
npm run build

# Compilar extensión completa
npm run build:ext

# Linting
npm run lint

# Formateo
npm run format
```

### Agregar una Nueva Funcionalidad

#### 1. Crear la Entidad (Domain)

```typescript
// src/domain/entities/credential.ts
export interface Credential {
  id: string;
  title: string;
  username: string;
  password: string; // Siempre encriptada
  url?: string;
  favorite: boolean;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}
```

#### 2. Crear el Servicio (Application)

```typescript
// src/domain/services.ts
export class CredentialService {
  async create(data: CreateCredentialDTO): Promise<Credential> {
    // Validar datos
    // Encriptar contraseña
    // Guardar
    // Retornar credencial
  }
  
  async update(id: string, data: UpdateCredentialDTO): Promise<Credential> {
    // Buscar credencial
    // Validar permisos
    // Actualizar
    // Retornar
  }
  
  async delete(id: string): Promise<void> {
    // Buscar
    // Eliminar
  }
}
```

#### 3. Crear la UI (Presentation)

```typescript
// src/ui/popup/popup.ts
async function handleAddCredential(e: Event): Promise<void> {
  e.preventDefault();
  
  const credential = {
    title: getValue('cred-title'),
    username: getValue('cred-username'),
    password: getValue('cred-password'),
    // ...
  };
  
  await credentialService.create(credential);
}
```

### Mensajes entre Componentes

```typescript
// Popup → Background
chrome.runtime.sendMessage({
  action: 'run_audit'
});

// Background → Popup
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === 'audit_complete') {
    // Actualizar UI
  }
});
```

---

## 6. Testing

### Ejecutar Tests

```bash
# Todos los tests
npm test

# Tests en modo watch
npm run test:watch

# Coverage
npm run coverage

# Tests específicos
npm test -- --testPathPattern=credential
```

### Estructura de Tests

```typescript
// tests/unit/credential-service.test.ts
import { CredentialService } from '../../src/domain/services';

describe('CredentialService', () => {
  let service: CredentialService;
  
  beforeEach(() => {
    service = new CredentialService();
  });
  
  describe('create', () => {
    it('should create a credential', async () => {
      const credential = await service.create({
        title: 'Test',
        username: 'test@test.com',
        password: 'password123'
      });
      
      expect(credential.id).toBeDefined();
      expect(credential.title).toBe('Test');
    });
  });
});
```

### Buenas Prácticas

- ✅ Un test por cada caso de uso
- ✅ Arrange-Act-Assert claramente separado
- ✅ Mocks para dependencias externas
- ✅ Tests unitarios > integración > e2e

---

## 7. Build y Deployment

### Compilación

```bash
# Build de producción
npm run build

# Output en dist/
ls dist/
```

### Estructura del Build

```
dist/
├── manifest.json           # Chrome manifest
├── background/
│   └── auditor.js         # Service worker
├── ui/
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js      # Bundled
│   └── options/
│       └── ...
├── icons/
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
└── ...
```

### Cargar en Navegador

1. Abre `chrome://extensions/`
2. Activa **Developer mode**
3. Click **Load unpacked**
4. Selecciona `dist/`

### Publicar en Chrome Web Store

```bash
# 1. Zip el directorio dist
cd dist && zip -r ../cybervault-v1.0.0.zip ./

# 2. Subir a Chrome Developer Dashboard
# https://chrome.google.com/webstore/developer/dashboard
```

---

## 8. Seguridad

### Reglas de Seguridad

1. **Nunca** almacenes passwords en plaintext
2. **Siempre** usen las capas de encriptación
3. **Nunca** envíen datos sin encriptar
4. **Validar** toda entrada de usuario

### Criptografía

```typescript
// Usar siempre las capas de encriptación
import { CryptoLayeredService } from '../infrastructure/crypto';

const crypto = new CryptoLayeredService();

// Encriptar
const encrypted = await crypto.encrypt(plaintext, masterKey);

// Desencriptar
const decrypted = await crypto.decrypt(encrypted, masterKey);
```

### Escaneo de Seguridad

```bash
# Dependencias vulnerables
npm audit

# Secrets en código
npm run security
```

---

## 9. Contribuir

### Flujo de Trabajo

```
1. Fork del repositorio
2. Crear rama feature/
3. Desarrollar con TDD
4. Ejecutar tests y lint
5. Commit con mensajes convencionales
6. Push y abrir PR
```

### Ramas

| Prefijo | Uso |
|---------|-----|
| `feature/*` | Nuevas funcionalidades |
| `bugfix/*` | Corrección de bugs |
| `security/*` | Fixes de seguridad |
| `hotfix/*` | Fixes urgentes |
| `refactor/*` | Refactorización |
| `docs/*` | Documentación |

### Commits Convencionales

```
feat: agregar nuevo генератор паролей
fix: corregir error al guardar credencial
docs: actualizar manual de usuario
refactor: simplificar servicio de credenciales
security: cerrar vulnerabilidad XSS
test: agregar tests para credential-service
```

### Pull Request

1. Título descriptivo
2. Descripción de cambios
3. Screenshots si es UI
4. Tests pasando
5. Sin lint errors

---

## API Reference

### CredentialService

```typescript
class CredentialService {
  // Crear credencial
  create(data: CreateCredentialDTO): Promise<Credential>
  
  // Obtener todas
  findAll(): Promise<Credential[]>
  
  // Buscar por ID
  findById(id: string): Promise<Credential | null>
  
  // Actualizar
  update(id: string, data: UpdateCredentialDTO): Promise<Credential>
  
  // Eliminar
  delete(id: string): Promise<void>
  
  // Buscar
  search(query: string): Promise<Credential[]>
}
```

### CryptoService

```typescript
class CryptoLayeredService {
  // Encriptar (4 capas)
  encrypt(plaintext: string, key: string): Promise<EncryptedData>
  
  // Desencriptar
  decrypt(data: EncryptedData, key: string): Promise<string>
  
  // Derivar clave
  deriveKey(password: string, salt: Uint8Array): Promise<string>
  
  // Generar salt
  generateSalt(): Uint8Array
}
```

---

## Recursos

- [Chrome Extensions Docs](https://developer.chrome.com/docs/extensions/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Node.js Crypto](https://nodejs.org/api/crypto.html)
- [Gentleman Programming](https://gentlemanprogramming.com)

---

*Última actualización: Marzo 2026*
*Versión: 1.0.0*
