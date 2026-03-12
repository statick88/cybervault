# 📊 Diagrama 02: Arquitectura de Capas

```mermaid
flowchart TB
    subgraph PRESENTATION["Presentation Layer"]
        direction TB
        POPUP[Popup]
        OPTIONS[Options]
        CONTENT[Content Scripts]
    end

    subgraph APPLICATION["Application Layer"]
        direction TB
        CRED_SVC[Credential Service]
        VAULT_SVC[Vault Service]
        AUDITOR[Auditor Service]
        BREACH[Breach Detector]
    end

    subgraph DOMAIN["Domain Layer"]
        direction TB
        ENTITIES[Entities]
        SERVICES[Domain Services]
        REPOS[Repository Interfaces]
        VALUE_OBJ[Value Objects]
    end

    subgraph INFRASTRUCTURE["Infrastructure Layer"]
        direction TB
        CRYPTO[Crypto Service]
        STORAGE[Storage Adapter]
        IPFS[IPFS Adapter]
        API[External API Client]
    end

    PRESENTATION --> APPLICATION
    APPLICATION --> DOMAIN
    DOMAIN --> INFRASTRUCTURE

    style PRESENTATION fill:#74b9ff,stroke:#333,color:#fff
    style APPLICATION fill:#a29bfe,stroke:#333,color:#fff
    style DOMAIN fill:#ffeaa7,stroke:#333,color:#333
    style INFRASTRUCTURE fill:#fd79a8,stroke:#333,color:#fff
```

## Regla de Dependencia

```
┌─────────────────────────────────────────────────────────────┐
│                    DEPENDENCY RULE                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   PRESENTATION ──────────────────────────────────────────►   │
│       │                                                      │
│       │ Depende de                                          │
│       ▼                                                      │
│   APPLICATION ──────────────────────────────────────────►    │
│       │                                                      │
│       │ Depende de interfaces, NO implementaciones           │
│       ▼                                                      │
│   DOMAIN ──────────────────────────────────────────────►     │
│       │                                                      │
│       │ Define interfaces, NO depende de nada                │
│       ▼                                                      │
│   INFRASTRUCTURE ◄────────────────────────────────────────  │
│       │                                                      │
│       │ Implementa las interfaces del dominio              │
│       │                                                      │
└─────────────────────────────────────────────────────────────┘
```

## Detalle por Capa

### Presentation Layer
- No contiene lógica de negocio
- Solo maneja UI y eventos
- Usa servicios de Application Layer

### Application Layer
- Orquestra casos de uso
- No tiene estado
- Usa entidades del Domain Layer

### Domain Layer
- Contiene la lógica de negocio pura
- No tiene dependencias externas
- Define interfaces para infrastructure

### Infrastructure Layer
- Implementa las interfaces definidas
- Maneja detalles técnicos
- Conecta con recursos externos

---

*Volver a [README.md](README.md)*
