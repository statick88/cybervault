# 📊 Diagrama 01: Vista General del Sistema

```mermaid
flowchart TB
    subgraph US["Usuario"]
        User[Usuario]
    end

    subgraph EXT["Navegador (Chrome)"]
        Popup[Popup UI]
        Options[Options Page]
        Content[Content Scripts]
        SW[Service Worker]
    end

    subgraph CORE["CyberVault Core"]
        UI[UI Layer]
        Domain[Domain Layer]
        Infra[Infrastructure Layer]
    end

    subgraph CRYPTO["Servicios Criptográficos"]
        Crypto4[4-Layer Crypto]
        SecureMem[Secure Memory]
    end

    subgraph STORAGE["Almacenamiento"]
        Local[Chrome Storage]
        IPFS[IPFS (Sync)]
    end

    subgraph EXTERNAL["APIs Externas"]
        Pwned[Have I Been Pwned]
        AlienVault[AlienVault OTX]
    end

    User -->|Interacciona| Popup
    User -->|Configura| Options
    User -->|Navega| Content

    Popup <-->|Mensajes| SW
    Options <-->|Mensajes| SW
    Content <-->|Inyecta| SW

    SW --> UI
    UI --> Domain
    Domain --> Infra

    Infra --> CRYPTO
    Infra --> STORAGE
    Infra --> EXTERNAL

    CRYPTO -->|Protege| STORAGE

    style CRYPTO fill:#ff6b6b,stroke:#333,color:#fff
    style STORAGE fill:#4ecdc4,stroke:#333,color:#fff
    style EXTERNAL fill:#ffe66d,stroke:#333,color:#333
```

## Descripción

### Componentes Principales

| Componente | Responsabilidad |
|------------|----------------|
| **Popup UI** | Interfaz principal para gestión de credenciales |
| **Options Page** | Configuración de la extensión |
| **Content Scripts** | Detección automática de formularios |
| **Service Worker** | Background tasks, auditorías |
| **Domain Layer** | Lógica de negocio |
| **Infrastructure** | Criptografía, almacenamiento |

### Flujo de Datos

1. Usuario interactúa con Popup
2. Popup envía mensajes al Service Worker
3. Service Worker procesa mediante Domain Layer
4. Domain usa Infrastructure para:
   - Encriptar/desencriptar (Crypto)
   - Persistir datos (Storage)
   - Verificar brechas (External APIs)

---

*Volver a [README.md](README.md)*
