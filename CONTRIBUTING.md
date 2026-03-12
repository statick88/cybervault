# 🤝 Guía de Contribución - CyberVault

¡Gracias por tu interés en contribuir a CyberVault! Este documento te guiará através del proceso de contribución.

## Tabla de Contenidos

1. [Código de Conducta](#código-de-conducta)
2. [¿Cómo Contribuir?](#cómo-contribuir)
3. [Proceso de Desarrollo](#proceso-de-desarrollo)
4. [Estándares de Código](#estándares-de-código)
5. [Commits](#commits)
6. [Pull Requests](#pull-requests)
7. [Reporting Bugs](#reporting-bugs)
8. [Solicitud de Features](#solicitud-de-features)

---

## 1. Código de Conducta

### Nuestro Compromiso

Nosotros, como contribuyentes y mantenedores, nos comprometemos a hacer de la participación en nuestra comunidad una experiencia libre de acoso para todos.

### Estándares de Conducta

- ✅ Lenguaje respetuoso e inclusivo
- ✅ Aceptación de críticas constructivas con gracia
- ✅ Enfocarse en lo que es mejor para la comunidad
- ✅ Mostrar empatía hacia otros miembros

### Comportamiento Inaceptable

- ❌ Comentarios sexuales o de otro tipo de atención no bienvenida
- ❌ Trolling, comentarios insultantes, ataques personales
- ❌ Acoso público o privado
- ❌ Publicar información privada de otros sin permiso

---

## 2. ¿Cómo Contribuir?

### Maneras de Contribuir

| Tipo | Descripción |
|------|-------------|
| 🐛 **Bug Reports** | Reportar errores en el código |
| 💡 **Features** | Proponer nuevas funcionalidades |
| 📖 **Documentación** | Mejorar docs, manuales, README |
| 🎨 **UI/UX** | Mejoras en la interfaz |
| 🔒 **Seguridad** | Reportar vulnerabilidades |

---

## 3. Proceso de Desarrollo

### Entorno Local

```bash
# 1. Fork del repositorio
# Click en "Fork" en GitHub

# 2. Clonar tu fork
git clone https://github.com/TU_USUARIO/cybervault.git
cd cybervault

# 3. Agregar upstream
git remote add upstream https://github.com/statick88/cybervault.git

# 4. Crear rama para tu feature
git checkout -b feature/nueva-funcionalidad
```

### Flujo de Trabajo

```
┌─────────────────────────────────────────────────────────────┐
│                    GIT WORKFLOW                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  upstream/main ─────────────────────►                      │
│        │                                                   │
│        │ fetch + rebase                                    │
│        ▼                                                   │
│  upstream/main ──► develop ──► feature/my-feature          │
│                           │                                │
│                           │ merge                           │
│                           ▼                                │
│                    Pull Request                            │
│                           │                                │
│                           ▼                                │
│                    Code Review                             │
│                           │                                │
│                           ▼                                │
│                    Merge to main                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Estándares de Código

### TypeScript

```typescript
// ✅ Correcto
interface UserCredential {
  id: string;
  username: string;
  password: string;
}

class CredentialService {
  async create(data: CreateCredentialDTO): Promise<Credential> {
    // Implementación
  }
}

// ❌ Incorrecto
class credentialService {
  async Create(data): Promise {
    // Implementación
  }
}
```

### Nombrado

| Tipo | Convención | Ejemplo |
|------|-----------|---------|
| Clases | PascalCase | `CredentialService` |
| Interfaces | PascalCase | `ICredentialRepository` |
| Métodos | camelCase | `createCredential()` |
| Variables | camelCase | `const userName` |
| Constantes | UPPER_SNAKE | `MAX_LENGTH` |
| Archivos | kebab-case | `credential-service.ts` |

### Funciones

```typescript
// ✅ Funciones pequeñas y enfocadas
async function encryptPassword(
  password: string, 
  key: string
): Promise<EncryptedData> {
  const salt = generateSalt();
  const derivedKey = await deriveKey(password, salt);
  return encrypt(derivedKey, password);
}

// ❌ Función demasiado larga
async function doEverything() {
  // 200 líneas...
}
```

### Comentarios

```typescript
// ✅ Explicar EL POR QUÉ, no EL QUÉ
// Usamos Argon2id en lugar de PBKDF2 por su resistencia
// a ataques de GPU (OWASP Recommendation 2023)
const derivedKey = await argon2(password, salt);

// ❌ Comentario innecesario
// Función para encriptar
function encrypt() {}
```

---

## 5. Commits

### Formato

```
<tipo>(<alcance>): <descripción>

[opcional: cuerpo]

[opcional: pie]
```

### Tipos

| Tipo | Descripción |
|------|-------------|
| `feat` | Nueva funcionalidad |
| `fix` | Corrección de bug |
| `docs` | Solo documentación |
| `style` | Formateo, sin cambio de lógica |
| `refactor` | Refactorización |
| `test` | Agregar o corregir tests |
| `chore` | Tareas de mantenimiento |
| `security` | Fix de seguridad |

### Ejemplos

```bash
# Feature
git commit -m "feat: agregar generador de contraseñas seguras"

# Bug Fix
git commit -m "fix: corregir guardado de credencial vacía"

# Documentación
git commit -m "docs: actualizar manual de usuario"

# Refactor
git commit -m "refactor: simplificar servicio de criptografía"

# Seguridad
git commit -m "security: cerrar vulnerabilidad XSS en popup"
```

---

## 6. Pull Requests

### Antes de Crear un PR

```bash
# 1. Asegúrate que los tests pasen
npm test

# 2. Ejecuta lint
npm run lint

# 3. Formatea el código
npm run format

# 4. Build de producción
npm run build
```

### Plantilla de PR

```markdown
## Descripción
[Breve descripción de los cambios]

## Tipo de Cambio
- [ ] Bug fix (corrección)
- [ ] Nueva feature
- [ ] Cambio ruptivo (breaking change)
- [ ] Documentación

## ¿Cómo Testear?
[Pasos para probar el cambio]

## Screenshots
[Si es UI, agregar screenshots]

## Checklist
- [ ] Tests pasando
- [ ] Lint sin errores
- [ ] Documentación actualizada
- [ ] Código probando manualmente
```

### Proceso de Review

```
1. Crear PR
     │
     ▼
2. CI/CD Pipeline
   - ✅ Lint
   - ✅ Tests  
   - ✅ Build
   - ⏳ Security Audit
     │
     ▼
3. Code Review
   - Revisión de pares
   - Solicitar cambios si es necesario
     │
     ▼
4. Aprobación
   - ✅ Mínimo 1 approve
   - ✅ Sin changes requested
     │
     ▼
5. Merge
```

---

## 7. Reporting Bugs

### Cómo Reportar

**Usa GitHub Issues** para reportar bugs.

### Plantilla de Bug Report

```markdown
## Bug: [Título descriptivo]

### Descripción
[Descripción clara del bug]

### Pasos para Reproducir
1. Ir a '...'
2. Click en '...'
3. Scroll down to '...'
4. Ver error

### Comportamiento Esperado
[Lo que debería pasar]

### Comportamiento Actual
[Lo que realmente pasa]

### Screenshots
[Si aplica]

### Entorno
- OS: [e.g., macOS 14.0]
- Navegador: [e.g., Chrome 120]
- Versión: [e.g., 1.0.0]

### Información Adicional
[Cualquier otra información relevante]
```

---

## 8. Solicitud de Features

### Cómo Solicitar

**Usa GitHub Issues** con la etiqueta `enhancement`.

### Plantilla de Feature Request

```markdown
## Feature Request: [Título]

### Problema
[Descripción del problema que resuelve esta feature]

### Solución Propuesta
[Descripción de la solución]

### Alternativas Consideradas
[otras soluciones consideradas]

### Información Adicional
[ cualquier screenshot, mockup, o contexto adicional ]
```

---

## Recursos Adicionales

- [Código de Conducta de Contributor Covenant](https://www.contributor-covenant.org)
- [Guía de Estilos de Gentleman Programming](https://gentlemanprogramming.com)
- [Clean Architecture](docs/arquitectura.md)

---

¿Preguntas? Abre un issue o contacta a los mantenedores.

*Última actualización: Marzo 2026*
