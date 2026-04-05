# Autocompletado con Sal y Pimienta (Salt & Pepper)

## Descripción General

El sistema de autocompletado de CyberVault implementa un mecanismo de seguridad avanzado utilizando los conceptos criptográficos de **sal** (salt) y **pimienta** (pepper) para proteger las credenciales almacenadas en caso de que la base de datos sea comprometida.

## Concepto de Sal y Pimienta

### Sal (Salt)
- **Definición**: Valor aleatorio añadido a cada entrada antes de ser procesada.
- **Propósito**: Asegurar que dos usuarios con la misma contraseña generen hashes diferentes.
- **Implementación**: Añadido al email del usuario.

### Pimienta (Pepper)
- **Definición**: Valor secreto compartido añadido a todas las entradas antes del hash.
- **Propósito**: Añadir una capa adicional de seguridad que no depende de cada usuario.
- **Implementación**: Añadida al password del usuario.

## Funcionamiento del Sistema

### 1. Detección de Formularios
El sistema automáticamente detecta formularios de registro en páginas web:
- Detecta campos de email y password
- Identifica formularios de registro usando patrones de URL y texto
- Monitera cambios en el DOM para detectar formularios dinámicos

### 2. Generación de Credenciales
Cuando se detecta un formulario de registro:

1. **Genera un email con sal**:
   ```
   usuario+salt@dominio.extension
   ```
   Donde:
   - `usuario`: Parte aleatoria del email (ej: `a1b2c3d4`)
   - `salt`: Valor aleatorio de 32 caracteres hexadecimales
   - `dominio.extension`: Dominio del sitio web

2. **Genera un password con pimienta**:
   ```
   password+pepper
   ```
   Donde:
   - `password`: Contraseña aleatoria de 32 caracteres
   - `pepper`: Valor aleatorio de 32 caracteres hexadecimales

### 3. Almacenamiento Seguro
Las credenciales se almacenan en el vault con el formato:
```json
{
  "email": "a1b2c3d4+salt123...@ejemplo.com",
  "password": "password123...+pepper456...",
  "salt": "salt123...",
  "pepper": "pepper456...",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 4. Extracción de Credenciales Originales
Al usar la aplicación:
1. Se extrae el email original quitando la sal
2. Se extrae el password original quitando la pimienta
3. Se usan las credenciales originales en el sitio web

## Ejemplo de Flujo

### Paso 1: Usuario visita sitio de registro
```
URL: https://ejemplo.com/register
```

### Paso 2: CyberVault detecta formulario
```
Formulario detectado con campos:
- Email: <input type="email" name="email">
- Password: <input type="password" name="password">
- Confirm Password: <input type="password" name="password_confirm">
```

### Paso 3: Generación de credenciales
```javascript
// Email original: usuario456@ejemplo.com
// Password original: securepass123

// Email almacenado: usuario456+abc123def456...@ejemplo.com
// Password almacenado: securepass123+xyz789uvw012...
```

### Paso 4: Uso en el sitio web
```javascript
// El sistema quita la sal y pimienta
// Email usado: usuario456@ejemplo.com
// Password usado: securepass123
```

## Beneficios de Seguridad

### 1. Protección ante compromiso de base de datos
- **Sin sal/pimienta**: Un atacante con acceso a la base de datos podría usar directamente las credenciales
- **Con sal/pimienta**: Las credenciales almacenadas son inútiles sin conocer la lógica de extracción

### 2. Unicidad de credenciales
- Cada usuario tiene credenciales únicas incluso si usan el mismo sitio
- La sal asegura que emails similares generen valores diferentes

### 3. Defensa en profundidad
- La pimienta añade una capa de seguridad compartida
- Si la base de datos es comprometida, el atacante necesita额外 información

## Implementación Técnica

### Estructura de Directorios
```
src/domain/services/autocompletado/
├── credentials-generator.ts   # Generación de credenciales con sal/pimienta
├── form-detector.ts           # Detección de formularios de registro
├── autocomplete-service.ts    # Servicio principal de autocompletado
└── index.ts                   # Punto de entrada
```

### Interfaz de Usuario
- **UI de sugerencia**: Aparece en formularios de registro detectados
- **Opciones**:
  - Usar credenciales CyberVault (automático)
  - Generar manualmente
  - Descartar sugerencia

## Configuración

### Activar Autocompletado
1. Instalar la extensión CyberVault
2. Habilitar "Autocompletado de Registro" en opciones
3. Navegar a un sitio de registro

### Personalización
- Longitud de sal: 32 caracteres (configurable)
- Longitud de pimienta: 32 caracteres (configurable)
- Formato de email: `{usuario}+{salt}@{dominio}`

## API del Servicio

### Generar Credenciales
```typescript
const generator = new CredentialsGenerator();
const credentials = await generator.generateCredentials('ejemplo.com');
// Devuelve: { email, password, originalEmail, originalPassword, salt, pepper }
```

### Extraer Credenciales Originales
```typescript
const original = await generator.extractOriginalCredentials(
  'usuario+salt@ejemplo.com',
  'password+pepper'
);
// Devuelve: { email: 'usuario@ejemplo.com', password: 'password' }
```

### Detectar Formularios
```typescript
const forms = FormDetector.detectAllRegistrationForms();
// Devuelve array de formularios detectados
```

## Próximos Pasos

1. [ ] Integrar con almacenamiento seguro del vault
2. [ ] Agregar sincronización entre dispositivos
3. [ ] Implementar recuperación de credenciales
4. [ ] Agregar soporte para múltiples dominios
5. [ ] Mejorar UI de sugerencias