# 📊 Diagrama 06: Modelo de Seguridad

```mermaid
flowchart TB
    subgraph THREATS["Amenazas"]
        MALWARE[Malware Local]
        NETWORK[Ataques de Red]
        PHYSICAL[Acceso Físico]
        PHISHING[Phishing]
    end

    subgraph CONTROLS["Controles de Seguridad"]
        ZERO[Zero-Knowledge]
        ENCRYPT[4-Layer Encryption]
        MEMORY[Secure Memory]
        VALIDATION[Input Validation]
        CSP[Content Security Policy]
    end

    THREATS -->|Mitigado por| CONTROLS

    MALWARE --> ZERO
    NETWORK --> ENCRYPT
    PHYSICAL --> MEMORY
    PHISHING --> VALIDATION

    CONTROLS -->|Protege| USER_DATA[Datos del Usuario]

    style ZERO fill:#ff6b6b,stroke:#333,color:#fff
    style ENCRYPT fill:#feca57,stroke:#333,color:#333
    style MEMORY fill:#48dbfb,stroke:#333,color:#fff
```

## Controles de Seguridad

### Zero-Knowledge

```mermaid
flowchart LR
    USER[Usuario] -->|Password| BROWSER
    BROWSER -->|Encriptado| SERVER
    SERVER -->|No puede<br/>desencriptar| SERVER
    SERVER -->|Encriptado| USER

    BROWSER -->|Solo aquí| DECRYPT[Desencriptar]
```

### Content Security Policy

```
┌─────────────────────────────────────────────────────┐
│              CSP Configuration                        │
├─────────────────────────────────────────────────────┤
│  default-src 'self'                                 │
│  script-src 'self'                                  │
│  style-src 'self' 'unsafe-inline'                   │
│  img-src 'self' data:                               │
│  connect-src 'self' https://api.pwnedpasswords.com │
│  object-src 'none'                                  │
│  base-uri 'self'                                    │
│  form-action 'self'                                 │
└─────────────────────────────────────────────────────┘
```

### Validación de Entrada

```mermaid
flowchart TB
    INPUT[Entrada<br/>Usuario] --> VALIDATE[Zod Validator]
    VALIDATE -->|Válido| PROCESS[Procesar]
    VALIDATE -->|Inválido| REJECT[Rechazar<br/>+ Error]
```

---

*Volver a [README.md](README.md)*
