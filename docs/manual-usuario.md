# 📖 Manual de Usuario - CyberVault

## Tabla de Contenidos

1. [Introducción](#introducción)
2. [Instalación](#instalación)
3. [Primeros Pasos](#primeros-pasos)
4. [Gestión de Credenciales](#gestión-de-credenciales)
5. [Generador de Contraseñas](#generador-de-contraseñas)
6. [Búsqueda y Organización](#búsqueda-y-organización)
7. [Auditoría de Seguridad](#auditoría-de-seguridad)
8. [Configuración](#configuración)
9. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## 1. Introducción

### ¿Qué es CyberVault?

CyberVault es un gestor de contraseñas **Zero-Knowledge**, lo que significa que:

- 🔒 **Tus contraseñas nunca salen de tu dispositivo** sin encriptar
- 🔑 **Solo tú tienes la clave maestra**
- 🛡️ **Protección de 4 capas** contra ataques

### Características

| Característica | Descripción |
|----------------|-------------|
| Encriptación | 4 capas: X25519, Argon2id, AES-256, ChaCha20 |
| Sincronización | Backup seguro via IPFS cifrado |
| Auditoría | Detecta credenciales comprometidas |
| Generador | Crea contraseñas seguras aleatorias |

---

## 2. Instalación

### Requisitos

- Navegador Chrome 120+ o Chromium
- 50MB de espacio libre

### Pasos

1. **Descarga o clona** el repositorio:
   ```bash
   git clone https://github.com/statick88/cybervault.git
   ```

2. **Instala las dependencias**:
   ```bash
   cd cybervault
   npm install
   ```

3. **Compila la extensión**:
   ```bash
   npm run build
   ```

4. **Carga en Chrome**:
   - Abre `chrome://extensions/`
   - Activa **"Developer mode"** (esquina superior derecha)
   - Click en **"Load unpacked"**
   - Selecciona la carpeta `dist/`

5. **¡Listo!** 🔐

Verás el ícono de CyberVault en tu barra de herramientas.

---

## 3. Primeros Pasos

### Interfaz Principal

```
┌──────────────────────────────────────┐
│ 🔐 CyberVault                    ⚙️  │  ← Header
├──────────────────────────────────────┤
│ 🔒 Bóveda bloqueada  ☁️ Sincronizado │  ← Status
├──────────────────────────────────────┤
│ 🔍 Buscar credenciales...            │  ← Búsqueda
├──────────────────────────────────────┤
│ [Todas] [⭐ Favoritas] [🕐 Recientes]│  ← Tabs
├──────────────────────────────────────┤
│ ┌────────────────────────────────┐  │
│ │ 🔑 Gmail                        │  │  ← Lista de
│ │    usuario@email.com            │  │     Credenciales
│ └────────────────────────────────┘  │
│ ┌────────────────────────────────┐  │
│ │ 🔑 Banco                        │  │
│ │    usuario@banco.com            │  │
│ └────────────────────────────────┘  │
├──────────────────────────────────────┤
│ [+ Nueva Credencial]  [🔍 Audit]    │  ← Acciones
├──────────────────────────────────────┤
│ 🎲 Generador de Contraseñas         │  ← Generador
│ [●●●●●●●●●●●●●●] [📋]                │
│ [==========] 16 caracteres          │
│ ☑ A-Z  ☑ a-z  ☑ 0-9  ☑ !@#$        │
│ [Generar]                            │
└──────────────────────────────────────┘
```

---

## 4. Gestión de Credenciales

### Crear una Nueva Credencial

1. Click en **"+ Nueva Credencial"**
2. Rellena el formulario:

```
┌─────────────────────────────┐
│ Nueva Credencial            │
├─────────────────────────────┤
│ Título: [Gmail personal   ] │
│ URL:   [https://gmail.com] │
│ Usuario:[usuario@email.com] │
│ Contraseña:[●●●●●●●●●●●●] 👁 │
│ Notas:  [                 ] │
│ Etiquetas:[trabajo, google] │
│ ☐ Marcar como favorita     │
├─────────────────────────────┤
│ [Cancelar]  [Guardar]      │
└─────────────────────────────┘
```

3. Click en **"Guardar"**

### Ver Detalles de una Credencial

1. Click en el botón **👁** (ojo) en la tarjeta
2. Verás toda la información:

```
┌─────────────────────────────┐
│ Detalles                   │
├─────────────────────────────┤
│ Título: Gmail personal      │
│ URL: gmail.com             │
│ Usuario: usuario@email.com │
│ Contraseña: •••••••••• [📋]│
│ Notas: Cuenta principal     │
│ Etiquetas: [trabajo][google]│
│ Creada: 11/03/2026 15:30   │
├─────────────────────────────┤
│ [Cerrar]                   │
└─────────────────────────────┘
```

### Editar una Credencial

1. Click en el botón **✏️** (lápiz)
2. Modifica los campos necesarios
3. Click en **"Guardar"**

### Eliminar una Credencial

1. Click en el botón **🗑️** (papelera)
2. Confirma la eliminación:

```
┌─────────────────────────────┐
│ Eliminar Credencial         │
├─────────────────────────────┤
│ ¿Estás seguro de eliminar  │
│ esta credencial?            │
│                            │
│ [Gmail personal]           │
├─────────────────────────────┤
│ [Cancelar]  [Eliminar]     │
└─────────────────────────────┘
```

---

## 5. Generador de Contraseñas

### Cómo Usarlo

1. **Configura las opciones**:
   - **Longitud**: Arrastra el slider (8-64 caracteres)
   - **Tipo de caracteres**:
     - ☑ A-Z (mayúsculas)
     - ☑ a-z (minúsculas)
     - ☑ 0-9 (números)
     - ☑ !@#$ (símbolos)

2. **Click en "Generar"**

3. **Copia la contraseña**:
   - Click en 📋 para copiar
   - O selecciónala manualmente

### Recomendaciones de Seguridad

| Longitud | Uso Recomendado |
|----------|-----------------|
| 12 | Mínimo para cuentas básicas |
| 16 | Recomendado para la mayoría |
| 24+ | Para cuentas críticas (banco) |

**Siempre usa**:
- ✅ Mayúsculas + minúsculas + números + símbolos
- ❌ NO uses palabras del diccionario
- ❌ NO uses información personal

---

## 6. Búsqueda y Organización

### Búsqueda

Escribe en el campo de búsqueda para filtrar por:
- Título de la credencial
- Usuario / Email
- URL
- Etiquetas

### Pestañas

| Pestaña | Muestra |
|---------|---------|
| **Todas** | Todas las credenciales |
| **⭐ Favoritas** | Solo las marcadas como favoritas |
| **🕐 Recientes** | Las últimas usadas |

### Etiquetas

Las etiquetas te permiten organizar tus credenciales:

```
Ejemplos:
- trabajo, personal, banco, social
- importante, temporal, archival
```

---

## 7. Auditoría de Seguridad

### Ejecutar una Auditoría

1. Click en el botón **"🔍 Audit"**
2. La extensión revisará:
   - Contraseñas débiles
   - Contraseñas reutilizadas
   - Credenciales en brechas conocidas

### Ver Resultados

La notificación mostrará un resumen:

```
✅ "Audit: Sin vulnerabilidades detectadas"
⚠️ "Audit: 3 críticos, 2 altos"
```

---

## 8. Configuración

### Acceder a Configuración

1. Click en el botón ⚙️ (engranaje) del header
2. Se abrirá la página de opciones

### Opciones Disponibles

| Opción | Descripción |
|--------|-------------|
| Auto-lock | Bloqueo automático después de X minutos |
| Tema | Claro / Oscuro |
| Notificaciones | Recibir alertas de seguridad |
| Sincronización | Configurar backup IPFS |

---

## 9. Preguntas Frecuentes

### ¿Es seguro CyberVault?

**Sí**. CyberVault implementa:
- ✅ Encriptación **Zero-Knowledge**
- ✅ **4 capas** de cifrado
- ✅ Memoria **segura** para contraseñas
- ✅ Sin envío de datos **sin cifrar**

### ¿Qué pasa si pierdo mi dispositivo?

Tus credenciales están almacenadas localmente. Se recomienda:
1. Hacer backup periódico
2. Usar sincronización IPFS (configurable)

### ¿Puedo importar/exportar credenciales?

Sí, desde la página de opciones puedes:
- **Exportar**: En formato encriptado
- **Importar**: Desde archivos CSV encriptados

### ¿CyberVault envía mis contraseñas a algún servidor?

**NO**. Zero-Knowledge significa que:
- Las contraseñas se encriptan **localmente**
- Solo salen del dispositivo **encriptadas**
- La clave maestra **nunca** sale de tu navegador

### ¿Cómo puedo reporta un problema?

1. Revisa [Issues](https://github.com/statick88/cybervault/issues)
2. Crea un nuevo issue con detalles
3. Para vulnerabilidades, consulta [SECURITY.md](../SECURITY.md)

---

## Glosario

| Término | Definición |
|---------|------------|
| **Zero-Knowledge** | Arquitectura donde el servidor no conoce las contraseñas |
| **Encriptación** | Proceso de codificar información |
| **Capa de Cifrado** | Nivel de protección criptográfico |
| **Master Key** | Clave maestra que protege todas las demás |
| **IPFS** | Sistema de archivos interplanetario (para sync) |

---

*Versión del documento: 1.0.0*
*Última actualización: Marzo 2026*
