# Guía de reemplazo de btoa/atob

## Archivos creados

- `src/shared/utils/binary.ts` - Funciones binarias seguras
- `src/shared/utils/index.ts` - Barrel file del directorio utils
- `src/shared/index.ts` - Barrel file del directorio shared

## Funciones disponibles

```typescript
import { binaryToBase64, base64ToBinary, stringToBase64, base64ToString } from '@/shared/utils';

// Uint8Array ↔ base64
binaryToBase64(uint8Array) → string
base64ToBinary(base64String) → Uint8Array

// String ↔ base64 (conveniencia)
stringToBase64(string) → string
base64ToString(base64String) → string
```

## Archivos a actualizar

### 1. `src/ui/popup/popup.ts:1091`

**ANTES:**

```typescript
return btoa(String.fromCharCode(...hashArray));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(hashArray));
```

Nota: `hashArray` ya es un array de números (bytes 0-255), se convierte directamente a Uint8Array.

---

### 2. `src/infrastructure/crypto/master-key-manager.ts`

**Línea 59:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...array));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(array));
```

**Línea 67:**
**ANTES:**

```typescript
atob(base64)
  .split("")
  .map((c) => c.charCodeAt(0));
```

**DESPUÉS:**

```typescript
base64ToBinary(base64);
```

---

### 3. `src/infrastructure/crypto/crypto-service.ts`

**Línea 138:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...combined));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(combined));
```

**Línea 151:**
**ANTES:**

```typescript
atob(encryptedData);
```

**DESPUÉS:**

```typescript
base64ToBinary(encryptedData);
```

**Línea 278:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...derivedArray));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(derivedArray));
```

**Línea 292:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...salt));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(salt));
```

**Línea 329:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...signatureArray));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(signatureArray));
```

**Línea 365:**
**ANTES:**

```typescript
atob(signature);
```

**DESPUÉS:**

```typescript
base64ToBinary(signature);
```

---

### 4. `src/infrastructure/crypto/layers/layer8-advanced.ts`

**Línea 225:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...encrypted));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(encrypted));
```

**Línea 229:**
**ANTES:**

```typescript
const encrypted = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
```

**DESPUÉS:**

```typescript
const encrypted = base64ToBinary(data);
```

---

### 5. `src/infrastructure/crypto/crypto-layered-service.ts`

**Línea 43:**
**ANTES:**

```typescript
return btoa(String.fromCharCode(...combined));
```

**DESPUÉS:**

```typescript
return binaryToBase64(new Uint8Array(combined));
```

**Línea 48:**
**ANTES:**

```typescript
const combined = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
```

**DESPUÉS:**

```typescript
const combined = base64ToBinary(ciphertext);
```

**Línea 139:**
**ANTES:**

```typescript
const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
```

**DESPUÉS:**

```typescript
const header = stringToBase64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
```

**Línea 140:**
**ANTES:**

```typescript
const body = btoa(JSON.stringify(payload));
```

**DESPUÉS:**

```typescript
const body = stringToBase64(JSON.stringify(payload));
```

**Línea 154:**
**ANTES:**

```typescript
return JSON.parse(atob(body));
```

**DESPUÉS:**

```typescript
return JSON.parse(base64ToString(body));
```

---

## Ventajas del enfoque

1. **Seguridad**: Centraliza la lógica de codificación/decodificación
2. **Mantenibilidad**: Un solo punto de modificación si se necesitan cambios
3. **Consistencia**: Asegura que todos los usos sigan el mismo patrón
4. **Testeable**: Las funciones pueden unit-testarse fácilmente
5. **Portabilidad**: Si en el futuro se migra a Node.js, solo semodifica `binary.ts`
