# MBCJ OAuth SV

Librería de backend para Node.js diseñada para facilitar la integración con el servicio de OAuth del Ministerio de Bienestar Ciudadano y Justicia. Proporciona las herramientas necesarias para gestionar la autenticación y autorización de usuarios en aplicaciones que utilizan Express.js.

## Características

-   **Autenticación OAuth**: Intercambio de código de autorización por token de acceso.
-   **Gestión de Datos de Usuario**: Obtención de datos del usuario desde el servicio OAuth.
-   **Middleware de Validación**: Middleware para Express que protege rutas verificando la validez de los tokens JWT y los permisos de usuario.
-   **Obtención de Clave Pública**: Script para descargar y almacenar la clave pública necesaria para la verificación de tokens.
-   **Actualización de Datos**: Funcionalidad para actualizar la información del usuario en la base de datos local a partir de los datos de OAuth.

## Tecnologías y Dependencias

-   **Node.js**: Entorno de ejecución para JavaScript.
-   **Express**: Framework para la construcción de aplicaciones web y APIs.
-   **Axios**: Cliente HTTP basado en promesas para realizar peticiones a la API de OAuth.
-   **JSONWebToken**: Librería para la generación y verificación de JSON Web Tokens (JWT).

## Estructura del Proyecto

El proyecto está organizado en los siguientes módulos principales:

-   `index.js`: Archivo principal que exporta todas las funcionalidades de la librería.
-   `oauthRouter.js`: Contiene la lógica de los endpoints de Express para el flujo de OAuth (obtener token, datos de usuario, etc.).
-   `middleware.js`: Proporciona el middleware para la validación de usuarios y tokens en las rutas protegidas.
-   `obtenerClave.js`: Incluye la función para descargar y guardar la clave pública del servicio de OAuth.

## Instalación

Para instalar la librería en tu proyecto, utiliza npm:

```bash
npm install mbcj-oauth-sv
```

## Uso

A continuación se muestran ejemplos de cómo integrar la librería en una aplicación Express.

### 1. Middleware de Autenticación

El middleware permite proteger tus rutas, asegurando que solo los usuarios autenticados y con los permisos adecuados puedan acceder.

```javascript
const express = require('express');
const router = express.Router();
const { middleware } = require('mbcj-oauth-sv');
const Usuario = require('./models/usuario'); // Importa tu modelo de Sequelize para Usuario

// Inicializa el middleware pasándole el modelo de Usuario
const MW = middleware(Usuario);

// Ejemplo de uso en una ruta protegida
// El primer parámetro es un array con los tipo_usuario_id permitidos.
// El segundo parámetro (booleano) indica si el token es requerido.
router.get('/ruta-protegida', MW.validarUsuarioMW([3, 4], true), (req, res) => {
  res.json({ mensaje: 'Acceso concedido', usuario: req.user });
});

module.exports = router;
```

### 2. API de OAuth

El router de OAuth maneja la comunicación con el servicio de autenticación.

```javascript
const express = require('express');
const { oauthRouter } = require('mbcj-oauth-sv');
const Usuario = require('./models/usuario'); // Importa tu modelo de Sequelize para Usuario

const app = express();

// Monta el router de OAuth en la ruta que prefieras, pasándole el modelo de Usuario
app.use('/auth', oauthRouter(Usuario));

app.listen(3000, () => {
  console.log('Servidor escuchando en el puerto 3000');
});
```

### 3. Script para Obtener la Clave Pública

Este script descarga la clave pública de OAuth, necesaria para verificar la firma de los tokens JWT. Es recomendable ejecutarlo durante el despliegue o en un proceso de inicialización.

```javascript
const { obtenerClavePublica } = require('mbcj-oauth-sv');

// Estas variables deberían obtenerse del entorno (.env)
const url_oauth = process.env.OAUTH_CLAVE_URL;
const ruta_directorio = process.env.OAUTH_CLAVE_DIR; // Debe ser una ruta absoluta
const nombre_archivo = process.env.OAUTH_CLAVE_FILE;

obtenerClavePublica(url_oauth, ruta_directorio, nombre_archivo)
  .then(() => {
    console.log('Clave pública descargada y guardada correctamente.');
  })
  .catch((error) => {
    console.error('Error al obtener la clave pública:', error);
  });
```

## Variables de Entorno

Para que la librería funcione correctamente, es necesario configurar las siguientes variables de entorno en un archivo `.env`:

### Para el Middleware

-   `TOKEN_ADMIN`: Token especial para el superadministrador.
-   `OAUTH_CLAVE_DIR`: Ruta absoluta al directorio donde se guardará la clave pública.
-   `OAUTH_CLAVE_FILE`: Nombre del archivo de la clave pública.

### Para la API de OAuth

-   `OAUTH_URL`: URL base del servicio de OAuth.
-   `OAUTH_ID`: ID de cliente proporcionado por el servicio de OAuth.
-   `OAUTH_SECRET`: Secreto de cliente proporcionado por el servicio de OAuth.
-   `OAUTH_VALIDADO`: (Opcional, `TRUE`/`FALSE`) Indica si se debe requerir que el usuario esté validado en OAuth.
-   `OAUTH_REEMPLAZAR_NOMBRE`: (Opcional, `TRUE`/`FALSE`) Indica si el nombre del usuario en la base de datos local debe actualizarse con el de OAuth.

### Para el Script de Obtención de Clave

-   `OAUTH_CLAVE_URL`: URL completa para descargar la clave pública.
-   `OAUTH_CLAVE_DIR`: Ruta absoluta al directorio donde se guardará la clave.
-   `OAUTH_CLAVE_FILE`: Nombre del archivo para la clave.

## Licencia

Este proyecto está bajo la Licencia ISC.

## Contacto

Desarrollado por **damian greco**.