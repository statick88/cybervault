# Especificación: Credentials Generator

## Objetivo
Generar credenciales seguras con el concepto de "sal" (salt) y "pimienta" (pepper) para protección contra compromiso de base de datos.

## Requisitos Funcionales

### 1. Generación de Credenciales
- [ ] Generar email con sal: `usuario+salt@dominio.extension`
- [ ] Generar password con pimienta: `password+pepper`
- [ ] Usar generador criptográficamente seguro (crypto.getRandomValues)
- [ ] Longitud configurable de sal y pimienta (mínimo 32 caracteres hexadecimales)

### 2. Extracción de Credenciales
- [ ] Extraer email original quitando la sal
- [ ] Extraer password original quitando la pimienta
- [ ] Validar formato de email y password antes de extraer

### 3. Validación
- [ ] Validar formato de email con sal (regex)
- [ ] Validar formato de password con pimienta (regex)
- [ ] Extraer sal de email
- [ ] Extraer pimienta de password

## Requisitos No Funcionales

### Seguridad
- [ ] Entropía mínima de 128 bits para sal y pimienta
- [ ] No almacenar credenciales originales en memoria
- [ ] Limpieza segura de buffers después de uso
- [ ] Validación de inputs para prevenir inyección

### Calidad de Código
- [ ] 100% cobertura de tests unitarios
- [ ] Sin warnings de TypeScript
- [ ] Documentación JSDoc completa
- [ ] Patrones SOLID aplicados

### Rendimiento
- [ ] Generación de credenciales < 100ms
- [ ] Extracción de credenciales < 10ms
- [ ] Sin bloqueo de event loop

## Arquitectura Actual vs Propuesta

### Problemas Actuales
1. **Acoplamiento fuerte**: `CryptoService` instanciado internamente
2. **Sin inyección de dependencias**: Dificulta testing y mantenimiento
3. **Sin tests unitarios**: No hay cobertura de tests para el módulo
4. **Validación limitada**: Solo regex simple, sin validación criptográfica

### Propuesta de Mejora
1. **Inyección de dependencias**: Pasar CryptoService por constructor
2. **Interfaz de servicios**: Definir interfaz para CryptoService
3. **Tests unitarios**: Crear suite de tests completa
4. **Validación mejorada**: Agregar validación de entropía y formato

## Especificaciones Técnicas

### Generación de Sal y Pimienta
```typescript
// Longitud: 32 caracteres hexadecimales (128 bits)
const salt = await this.generateRandomString(32);
const pepper = await this.generateRandomString(32);
```

### Formato de Email
```regex
/^[^+]+\+[^@]+@.+/
```

### Formato de Password
```regex
/^[^+]+\+[^+]+$/
```

## Test Cases

### Unit Tests
1. **Generación de credenciales**: Verificar formato correcto
2. **Extracción de credenciales**: Verificar extracción precisa
3. **Validación de formato**: Verificar detección de formatos inválidos
4. **Entropía**: Verificar aleatoriedad de sal y pimienta

### Integration Tests
1. **Con CryptoService**: Verificar integración con criptografía
2. **Con AutocompleteService**: Verificar uso en flujo completo

## Métricas de Éxito

- [ ] Tests unitarios pasando con 100% cobertura
- [ ] Sin vulnerabilidades en análisis de seguridad
- [ ] Performance dentro de especificaciones
- [ ] Documentación completa y actualizada
- [ ] Memoria Engram actualizada con decisiones