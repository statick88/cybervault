# 🏗️ Documentación de Arquitectura - CyberVault

## Tabla de Contenidos

1. [Visión General](#visión-general)
2. [Principios de Diseño](#principios-de-diseño)
3. [Arquitectura de Capas](#arquitectura-de-capas)
4. [Criptografía](#criptografía)
5. [Flujos de Datos](#flujos-de-datos)
6. [Componentes](#componentes)
7. [Modelo de Datos](#modelo-de-datos)
8. [Seguridad](#seguridad)
9. [Decisiones de Diseño](#decisiones-de-diseño)

---

## 1. Visión General

### Propósito

CyberVault es un gestor de contraseñas **Zero-Knowledge** diseñado para ofrecer máxima seguridad mediante:

- 🔐 Encriptación de 4 capas
- 🛡️ Auditoría proactiva
- 📱 Sincuración segura via IPFS

### Objetivos de Arquitectura

| Objetivo | Descripción |
|----------|-------------|
| **Seguridad** | Zero-Knowledge, nunca exponer passwords |
| **Rendimiento** | UI responsiva, crypto optimizado |
| **Mantenibilidad** | Clean Architecture, código testeable |
| **Extensibilidad** | Modular, fácil agregar features |

---

## 2. Principios de Diseño

### Clean Architecture

```
                    ┌─────────────────────┐
                    │   UI Layer          │
                    │ (Popup, Options)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Application Layer   │
                    │ (Use Cases, Svc)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Domain Layer      │
                    │ (Entities, Value)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │Infrastructure Layer │
                    │(Crypto, Storage)    │
                    └─────────────────────┘
```

### Principios SOLID

| Principio | Aplicación |
|----------|-----------|
| **S**ingle Responsibility | Cada clase una responsabilidad |
| **O**pen/Closed | Abierto para extensión, cerrado para modificación |
| **L**iskov Substitution | Interfaces bien definidas |
| **I**nterface Segregation | Múltiples interfaces pequeñas |
| **D**ependency Inversion | Depender de abstracciones, no concreciones |

### Dependency Rule

```
┌─────────────────────────────────────────┐
│  src/                                   │
│  ├── ui/           ← Depende de...      │
│  ├── domain/       ← ...application     │
│  └── infrastructure│ ← ...domain        │
└─────────────────────────────────────────┘
```

---

## 3. Arquitectura de Capas

### Diagrama General

```
┌─────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│
│  │   Popup     │  │   Options   │  │   Content Scripts       ││
│  │  (React)    │  │   (Vue)     │  │   (Inject)              ││
│  └─────────────┘  └─────────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION LAYER                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    CredentialService                        ││
│  │  - create()    - update()    - delete()                   ││
│  │  - search()    - findById()  - findAll()                  ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    VaultService                            ││
│  │  - unlock()    - lock()      - getStatus()                ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                          DOMAIN LAYER                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│
│  │  Credential │  │   Vault     │  │   Vulnerability         ││
│  │  (Entity)   │  │  (Entity)   │  │    (Entity)            ││
│  └─────────────┘  └─────────────┘  └─────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Repositories (Interfaces)                                 ││
│  │  - ICredentialRepository   - IVaultRepository             ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      INFRASTRUCTURE LAYER                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│
│  │   Crypto    │  │   Storage   │  │   IPFS Adapter         ││
│  │   Service   │  │   Local     │  │   (Sync)               ││
│  └─────────────┘  └─────────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Criptografía

### Sistema de 4 Capas

CyberVault implementa un sistema de encriptación por capas:

```
┌────────────────────────────────────────────────────────────┐
│                    ENCRYPTION FLOW                         │
├────────────────────────────────────────────────────────────┤
│                                                             │
│   Plaintext ──► Layer 1 ──► Layer 2 ──► Layer 3 ──► Layer 4
│   Password    X25519      Argon2id    AES-256    ChaCha20
│                                                             │
│   ciphertext ◄── Layer 4 ◄── Layer 3 ◄── Layer 2 ◄── Layer 1
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Capas Detalladas

#### Capa 1: X25519 (Intercambio de Claves)

```
┌─────────────────────────────────────────┐
│ Layer 1: X25519 (Key Exchange)          │
├─────────────────────────────────────────┤
│ Propósito: Establecer clave compartida  │
│ Algoritmo: Curve25519 ECDH             │
│ Seguridad: 256-bit equivalent           │
└─────────────────────────────────────────┘
```

**Código:**
```typescript
// Generar par de claves
const keyPair = crypto.generateKeyPairSync('x25519');

// Derivar clave compartida
const sharedKey = crypto.createKeyPairSync('x25519')
  .export({ type: 'spki', format: 'der' });
```

#### Capa 2: Argon2id (Derivación de Clave)

```
┌─────────────────────────────────────────┐
│ Layer 2: Argon2id (KDF)                 │
├─────────────────────────────────────────┤
│ Propósito: Derivar clave de password    │
│ Algoritmo: Argon2id                     │
│ Parámetros:                             │
│   - Memory: 64 MB                       │
│   - Iterations: 3                       │
│   - Parallelism: 4                       │
│   - Hash length: 32 bytes               │
└─────────────────────────────────────────┘
```

#### Capa 3: AES-256-GCM (Encriptación)

```
┌─────────────────────────────────────────┐
│ Layer 3: AES-256-GCM (Encryption)       │
├─────────────────────────────────────────┤
│ Propósito: Encriptar datos              │
│ Algoritmo: AES-256-GCM                  │
│ IV: 12 bytes (nonce)                    │
│ Tag: 16 bytes (authentication)          │
└─────────────────────────────────────────┘
```

#### Capa 4: ChaCha20-Poly1305 (Autenticación)

```
┌─────────────────────────────────────────┐
│ Layer 4: ChaCha20-Poly1305 (Auth)       │
├─────────────────────────────────────────┤
│ Propósito: Autenticar datos encriptados │
│ Algoritmo: ChaCha20-Poly1305            │
│nonce: 12 bytes                          │
│ Tag: 16 bytes                           │
└─────────────────────────────────────────┘
```

### Memoria Segura

```
┌─────────────────────────────────────────┐
│         Secure Memory Management        │
├─────────────────────────────────────────┤
│                                         │
│  1. Allocación en buffer seguro         │
│  2. Uso único (zeroing después de usar) │
│  3. No swap a disco                    │
│  4. No logging de valores sensibles     │
│                                         │
│  crypto.randomBytes(32)  // ← Seguro   │
│  Buffer.alloc(32)          // ← NO      │
│                                         │
└─────────────────────────────────────────┘
```

---

## 5. Flujos de Datos

### Flujo: Crear Credencial

```
┌─────────────────────────────────────────────────────────────┐
│              CREATE CREDENTIAL FLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  USER           POPUP           SERVICE      CRYPTO   STORAGE│
│   │                │               │           │        │   │
│   │ 1.Fill Form    │               │           │        │   │
│   │───────────────>│               │           │        │   │
│   │                │ 2.Submit      │           │        │   │
│   │                │──────────────>│           │        │   │
│   │                │               │           │        │   │
│   │                │               │ 3.Encrypt│        │   │
│   │                │               │──────────>│        │   │
│   │                │               │           │──►     │   │
│   │                │               │           │        │   │
│   │                │               │ 4.Save    │        │   │
│   │                │               │───────────│────────>│   │
│   │                │               │           │        │   │
│   │                │ 5. Confirm    │           │        │   │
│   │<───────────────│───────────────│           │        │   │
│   │                │               │           │        │   │
└─────────────────────────────────────────────────────────────┘
```

### Flujo: Auditoría

```
┌─────────────────────────────────────────────────────────────┐
│                  AUDIT FLOW                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  USER          POPUP        BACKGROUND    BREACH     API   │
│   │              │              │           DETECTOR  PWNED│
│   │              │               │              │        │   │
│   │ 1.Click      │              │              │        │   │
│   │─────────────>│              │              │        │   │
│   │              │ 2.Send       │              │        │   │
│   │              │─────────────>│              │        │   │
│   │              │              │              │        │   │
│   │              │              │ 3.Check all │        │   │
│   │              │              │────────────>│        │   │
│   │              │              │             │──►    │   │
│   │              │              │             │<─────│   │
│   │              │              │              │        │   │
│   │              │              │ 4.Results   │        │   │
│   │              │<─────────────│─────────────│        │   │
│   │              │               │              │        │   │
│   │ 5.Show       │              │              │        │   │
│   │<─────────────│              │              │        │   │
│   │              │               │              │        │   │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Componentes

### Popup (UI Principal)

```typescript
// src/ui/popup/popup.ts
class PopupController {
  // Elementos del DOM
  private credentialsList: HTMLElement;
  private searchInput: HTMLInputElement;
  private modalAdd: HTMLElement;
  
  // Servicios
  private credentialService: CredentialService;
  private cryptoService: CryptoLayeredService;
  
  // Inicialización
  async init(): Promise<void> {
    await this.loadCredentials();
    this.setupEventListeners();
  }
}
```

### Background Service Worker

```typescript
// src/background/auditor.ts
class AuditorService {
  // Runs periodically to check:
  // 1. Weak passwords
  // 2. Reused passwords  
  // 3. Breached credentials
  
  async runAudit(): Promise<AuditResult> {
    const credentials = await this.getCredentials();
    const results = await Promise.all([
      this.checkWeakPasswords(credentials),
      this.checkReusedPasswords(credentials),
      this.checkBreaches(credentials)
    ]);
    return this.aggregateResults(results);
  }
}
```

---

## 7. Modelo de Datos

### Credential Entity

```typescript
// src/domain/entities/credential.ts

interface Credential {
  /** ID único (UUID v4) */
  id: string;
  
  /** Título para mostrar */
  title: string;
  
  /** Usuario o email */
  username: string;
  
  /** Contraseña encriptada */
  encryptedPassword: EncryptedData;
  
  /** URL del servicio (opcional) */
  url?: string;
  
  /** Notas encriptadas (opcional) */
  encryptedNotes?: EncryptedData;
  
  /** Marcar como favorita */
  favorite: boolean;
  
  /** Etiquetas para organización */
  tags: string[];
  
  /** Timestamp de último uso */
  lastUsed?: string;
  
  /** Timestamp de creación */
  createdAt: string;
  
  /** Timestamp de última modificación */
  updatedAt?: string;
}
```

### Vault Entity

```typescript
// src/domain/entities/vault.ts

interface Vault {
  /** Estado de la bóveda */
  status: 'locked' | 'unlocked' | 'error';
  
  /** Clave maestra hasheada (no la clave real) */
  masterKeyHash: string;
  
  /** Salt para derivar clave */
  keySalt: Uint8Array;
  
  /** Número de credenciales */
  credentialCount: number;
  
  /** Última sincronización */
  lastSync?: string;
}
```

### Vulnerability Entity

```typescript
// src/domain/entities/vulnerability.ts

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface Vulnerability {
  /** ID de la credencial afectada */
  credentialId: string;
  
  /** Tipo de vulnerabilidad */
  type: 'WEAK_PASSWORD' | 'REUSED_PASSWORD' | 'BREACHED_PASSWORD' | 'OLD_PASSWORD';
  
  /** Severidad */
  severity: Severity;
  
  /** Descripción */
  description: string;
  
  /** Recomendación */
  recommendation: string;
}
```

---

## 8. Seguridad

### Modelo de Amenazas

```
┌─────────────────────────────────────────────────────────────┐
│                  THREAT MODEL                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │   MALWARE    │    │   NETWORK    │    │    LOCAL     │ │
│  │   (Local)    │    │   (MITM)     │    │  (Physical)  │ │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘ │
│         │                    │                    │         │
│         ▼                    ▼                    ▼         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              SECURITY CONTROLS                       │   │
│  │  • Secure Memory   • Zero-Knowledge   • Encryption │   │
│  │  • Input Validation• CSP            • Subresource  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Controles de Seguridad

| Control | Implementación |
|---------|---------------|
| **CSP** | `script-src 'self'` |
| **Input Validation** | Zod schemas |
| **Secure Memory** | `crypto.randomBytes` |
| **No Logging** | Secretos nunca en logs |
| **Content Security** | extension_pages policy |

---

## 9. Decisiones de Diseño

### Decisiones Clave

| Decisión | Razón | Alternativa Descartada |
|----------|-------|------------------------|
| **Chrome Extension** | Acceso a storage, portable | PWA standalone |
| **4 capas crypto** | Máxima seguridad | 1 capa AES |
| **IPFS sync** | Descentralizado, seguro | Servidor centralizado |
| **TypeScript** | Seguridad de tipos | JavaScript plano |
| **Clean Architecture** | Testeable, mantenible | MVC tradicional |

### Trade-offs

```
┌─────────────────────────────────────────────────────────────┐
│                    TRADE-OFFS                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  SEGURIDAD ◄─────────────────────► RENDIMIENTO             │
│  │                                    │                     │
│  │  Más capas = más seguro          │  Más capas =        │
│  │  pero más lento                 │  más lento          │
│  │                                    │                     │
│  ▼                                    ▼                     │
│                                                              │
│  EXTENSIBILIDAD ◄────────────────► SIMPLICIDAD             │
│  │                                    │                     │
│  │  Más abstracciones =             │  Código simple =    │
│  │  más flexible pero complejo      │  fácil de mantener  │
│  │                                    │                     │
│  ▼                                    ▼                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Referencias

- [Clean Architecture - Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Chrome Extensions Security](https://developer.chrome.com/docs/extensions/mv3/security/)

---

*Última actualización: Marzo 2026*
*Versión del documento: 1.0.0*
