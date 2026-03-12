# 📊 Diagramas de Arquitectura

Esta carpeta contiene los diagramas visuales de la arquitectura de CyberVault.

## Índice de Diagramas

| Diagrama | Descripción |
|----------|-------------|
| [01-general.md](01-general.md) | Vista general del sistema |
| [02-capas.md](02-capas.md) | Capas de Clean Architecture |
| [03-flujo-datos.md](03-flujo-datos.md) | Flujo de datos |
| [04-criptografia.md](04-criptografia.md) | Sistema de encriptación |
| [05-componentes.md](05-componentes.md) | Diagrama de componentes |
| [06-seguridad.md](06-seguridad.md) | Modelo de seguridad |
| [07-estados.md](07-estados.md) | Máquina de estados |

---

## Cómo Ver los Diagramas

Los diagramas están escritos en formato **Mermaid** para facilitar su visualización.

### Opción 1: VS Code

Instala la extensión [Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=vstirbu.vscode-mermaid-preview) y abre los archivos `.md`.

### Opción 2: GitHub

Los diagramas Mermaid se renderizan automáticamente en GitHub.

### Opción 3: Editor Online

Usa [Mermaid Live Editor](https://mermaid.live/) para editar y previsualizar.

---

## Convenciones

```
┌─────────────┐     ───────►     └─────────────┐
│   CAJA     │     FLECHA         │   CAJA     │
└─────────────┘                    └─────────────┘

┌─────────────────────┐
│   GRUPO            │
│  ┌─────────────┐  │
│  │  SUBCAJA   │  │
│  └─────────────┘  │
└─────────────────────┘
```

---

*Para más información, consulta [arquitectura.md](../arquitectura.md)*
