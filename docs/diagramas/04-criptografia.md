# 📊 Diagrama 04: Sistema de Criptografía

```mermaid
flowchart LR
    subgraph ENCRYPT["ENCRIPTAR"]
        P[Plaintext] --> L1
        L1[X25519<br/>Key Exchange] --> L2
        L2[Argon2id<br/>KDF] --> L3
        L3[AES-256-GCM<br/>Encryption] --> L4
        L4[ChaCha20-Poly1305<br/>Authentication] --> E[Encrypted]
    end

    subgraph DECRYPT["DESENCRIPTAR"]
        E --> DL4
        DL4[ChaCha20<br/>Verify] --> DL3
        DL3[AES-256-GCM<br/>Decrypt] --> DL2
        DL2[Argon2id<br/>Derive Key] --> DL1
        DL1[X25519<br/>Key Exchange] --> P2[Plaintext]
    end

    style L1 fill:#ff6b6b,stroke:#333,color:#fff
    style L2 fill:#feca57,stroke:#333,color:#333
    style L3 fill:#48dbfb,stroke:#333,color:#fff
    style L4 fill:#1dd1a1,stroke:#333,color:#fff
```

## Detalle de Cada Capa

### Capa 1: X25519 (Key Exchange)

```mermaid
flowchart TB
    subgraph X25519["X25519 ECDH"]
        A1[Generar par<br/>de claves] --> A2
        B1[Clave maestra<br/>del usuario] --> A2
        A2[Derivar clave<br/>compartida] --> A3[Clave<br/>Compartida]
    end
```

### Capa 2: Argon2id (KDF)

```mermaid
flowchart TB
    subgraph ARGON["Argon2id"]
        P[Password] --> S[Salt]
        S --> A[Argon2id]
        A -->|64MB memory<br/>3 iterations<br/>4 parallelism| K[Clave<br/>Derivada]
    end
```

### Capa 3: AES-256-GCM

```mermaid
flowchart TB
    subgraph AES["AES-256-GCM"]
        K[Clave] --> E
        P[Plaintext] --> E
        E[Encriptar] --> IV[IV<br/>12 bytes]
        E --> CT[Ciphertext]
        E --> TAG[Auth Tag<br/>16 bytes]
    end
```

### Capa 4: ChaCha20-Poly1305

```mermaid
flowchart TB
    subgraph CHACHA["ChaCha20-Poly1305"]
        K[Clave] --> E
        P[Ciphertext<br/>+ IV] --> E
        E[Autenticar] --> TAG2[Poly1305<br/>Tag]
    end
```

---

*Volver a [README.md](README.md)*
