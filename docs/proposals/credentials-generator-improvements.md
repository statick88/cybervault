# Propuestas de Mejora: Credentials Generator

## Propuesta 1: Inyección de Dependencias

**Problema**: El `CredentialsGenerator` instancia `CryptoService` internamente, acoplando el módulo.

**Solución**: Pasar `CryptoService` por el constructor.

**Código Actual**:
```typescript
export class CredentialsGenerator {
  private cryptoService: CryptoService;

  constructor() {
    this.cryptoService = new CryptoService(); // ❌ Acoplamiento
  }
}
```

**Código Propuesto**:
```typescript
export class CredentialsGenerator {
  private cryptoService: CryptoService;

  constructor(cryptoService: CryptoService) {
    this.cryptoService = cryptoService; // ✅ Inyección
  }
}
```

**Beneficios**:
- Facilita testing (mocking)
- Mejora mantenibilidad
- Aplica principio de inversión de dependencias

**Esfuerzo**: Bajo

---

## Propuesta 2: Tests Unitarios

**Problema**: No hay tests unitarios para `CredentialsGenerator`.

**Solución**: Crear suite de tests con Jest.

**Tests Propuestos**:
1. `should generate valid email with salt`
2. `should generate valid password with pepper`
3. `should extract original credentials correctly`
4. `should validate email format correctly`
5. `should validate password format correctly`
6. `should extract salt from email`
7. `should extract pepper from password`
8. `should handle invalid format gracefully`

**Esfuerzo**: Medio

---

## Propuesta 3: Validación de Entropía

**Problema**: No se verifica la calidad de la aleatoriedad.

**Solución**: Agregar validación de entropía mínima.

**Código Propuesto**:
```typescript
async validateEntropy(data: string): Promise<boolean> {
  // Verificar que los caracteres sean aleatorios
  // No patrones repetitivos
  // Entropía mínima de 128 bits
}
```

**Beneficios**:
- Mayor seguridad criptográfica
- Cumple con estándares NIST

**Esfuerzo**: Medio

---

## Propuesta 4: Mejora de Regex de Validación

**Problema**: Regex actual puede ser demasiado permisivo.

**Solución**: Mejorar patrones de validación.

**Regex Propuestos**:
```typescript
// Email con sal (más estricto)
const emailPattern = /^[a-zA-Z0-9]+(?:\+[a-fA-F0-9]{32})?@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Password con pimienta (más estricto)
const passwordPattern = /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+(?:\+[a-fA-F0-9]{32})?$/;
```

**Esfuerzo**: Bajo

---

## Propuesta 5: Tipos de Seguridad

**Problema**: No hay tipos específicos para credenciales.

**Solución**: Definir tipos TypeScript fuertes.

**Código Propuesto**:
```typescript
type EmailWithSalt = string & { readonly brand: 'EmailWithSalt' };
type PasswordWithPepper = string & { readonly brand: 'PasswordWithPepper' };

interface GeneratedCredentials {
  email: EmailWithSalt;
  password: PasswordWithPepper;
  originalEmail: string;
  originalPassword: string;
}
```

**Beneficios**:
- Prevención de errores en tiempo de compilación
- Mejor autocompletado IDE

**Esfuerzo**: Medio

---

## Propuesta 6: Manejo de Errores Mejorado

**Problema**: Excepciones genéricas sin contexto.

**Solución**: Definir errores específicos.

**Código Propuesto**:
```typescript
class InvalidEmailFormatError extends Error {
  constructor(email: string) {
    super(`Formato de email inválido: ${email}`);
  }
}

class InvalidPasswordFormatError extends Error {
  constructor(password: string) {
    super(`Formato de password inválido: ${password}`);
  }
}
```

**Esfuerzo**: Bajo

---

## Priorización

1. **Propuesta 1** (Inyección de Dependencias) - CRÍTICA
2. **Propuesta 2** (Tests Unitarios) - ALTA
3. **Propuesta 6** (Manejo de Errores) - MEDIA
4. **Propuesta 4** (Mejora Regex) - MEDIA
5. **Propuesta 5** (Tipos de Seguridad) - BAJA
6. **Propuesta 3** (Validación Entropía) - BAJA

## Implementación Recomendada

Fase 1: Propuestas 1, 2 y 6
Fase 2: Propuestas 4 y 5
Fase 3: Propuesta 3 (si es necesario según análisis de seguridad)