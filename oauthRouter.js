const express = require('express');
const axios = require('axios');

const { OAUTH_URL, OAUTH_ID, OAUTH_SECRET, OAUTH_VALIDADO, OAUTH_REEMPLAZAR_NOMBRE } = process.env;

/**
 * @typedef {import('express').Router} Router
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

// ... (las definiciones de JSDoc para OAuthUserData y UsuarioModel permanecen igual)

/**
 * Extrae y formatea un error de una respuesta de Axios para un mejor registro y depuración.
 * @param {Error} error - El objeto de error de Axios.
 * @returns {{status: number, message: string, data: any}} Un objeto de error formateado.
 */
function formatearErrorAxios(error) {
  if (error.response) {
    // La solicitud se hizo y el servidor respondió con un código de estado fuera del rango 2xx
    return {
      status: error.response.status,
      message: 'La API de OAuth respondió con un error',
      data: error.response.data
    };
  } else if (error.request) {
    // La solicitud se hizo pero no se recibió respuesta
    return {
      status: 500,
      message: 'No se recibió respuesta de la API de OAuth',
      request: error.request
    };
  } else {
    // Algo sucedió al configurar la solicitud que desencadenó un error
    return {
      status: 500,
      message: error.message
    };
  }
}

/**
 * Crea y configura un router de Express para manejar la autenticación OAuth.
 * @param {object} Usuario - El modelo de Sequelize para la entidad de Usuario.
 * @param {string[]} [atributos=['id', 'tipo_usuario_id', 'activo', 'nombre']] - Atributos a obtener del usuario.
 * @param {string[]} [atributosNuevoToken=['tipo_usuario_id']] - Atributos para incrustar en un nuevo token.
 * @param {function(Error|string|null): void} [loggeado=function(error){}] - Callback para registrar el login.
 * @returns {Router} El router de Express configurado.
 */
function oauthRouter(
  Usuario,
  atributos = ['id', 'tipo_usuario_id', 'activo', 'nombre'],
  atributosNuevoToken = ['tipo_usuario_id'],
  loggeado = function (error) { }
) {
  const router = express.Router();

  /**
   * Intercambia un código de autorización por un token de acceso.
   * @param {string} codigo - El código de autorización.
   * @returns {Promise<string>} Promesa que resuelve con el token de acceso.
   */
  function getToken(codigo) {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/token`;
      const data = { codigo, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET };
      axios.post(url, data)
        .then((resp) => {
          if (resp.data.status === "ok") return resolve(resp.data.token);
          return reject(resp.data.error || 'Error desconocido al obtener token');
        })
        .catch((error) => reject(formatearErrorAxios(error)));
    });
  }

  /**
   * Obtiene los datos del usuario desde el servicio OAuth.
   * @param {string} token - El token de acceso.
   * @param {(number|string)} permiso_id - El ID del permiso para solicitar los datos.
   * @returns {Promise<object>} Promesa que resuelve con los datos del usuario.
   */
  function getDatos(token, permiso_id) {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/datos/${permiso_id}`;
      const config = {
        params: { cliente_id: OAUTH_ID },
        headers: { authorization: token }
      };
      axios.get(url, config)
        .then((resp) => {
          if (resp.data.status === "ok") return resolve(resp.data.datos);
          return reject(resp.data.error || 'Error desconocido al obtener datos');
        })
        .catch((error) => reject(formatearErrorAxios(error)));
    });
  }

  /**
   * Valida un usuario local contra los datos de OAuth.
   * @param {object} datos - Los datos del usuario obtenidos de OAuth.
   * @returns {Promise<object>} Promesa que resuelve con la instancia del usuario local.
   */
  function validarUsuario(datos) {
    return new Promise((resolve, reject) => {
      if (OAUTH_VALIDADO?.toUpperCase() === "TRUE" && !datos.persona.validado) {
        return reject("Usuario no validado");
      }
      Usuario.findOne({ where: { documento: datos.persona.documento }, attributes })
        .then((usuario) => {
          if (!usuario) return reject("Usuario no encontrado");
          if (!usuario.activo) return reject("Usuario inactivo");

          const nuevoNombre = (`${datos.persona.apellidos}, ${datos.persona.nombre}`).toUpperCase();
          const debeActualizarNombre = OAUTH_REEMPLAZAR_NOMBRE?.toUpperCase() === "TRUE" && usuario.nombre !== nuevoNombre;

          const updatePromises = [usuario.update({ ultimo_ingreso: new Date() })];
          if (debeActualizarNombre) {
            updatePromises.push(usuario.update({ nombre: nuevoNombre }));
          }

          Promise.all(updatePromises)
            .then(() => resolve(usuario))
            .catch(reject);
        })
        .catch(reject);
    });
  }

  // ... (las funciones obtenerDatosUsuario y getNuevoToken se pueden mejorar de manera similar)

  // --- Rutas del Router ---

  router.post('/token', function (req, res) {
    const { codigo } = req.body;
    if (!codigo) {
      return res.status(400).json({ status: "error", error: "El código es requerido" });
    }

    getToken(codigo)
      .then((token) => {
        loggeado(null);
        res.json({ status: "ok", token });
      })
      .catch((error) => {
        loggeado(error.message || error);
        console.error("Error en /token:", error);
        const status = error.status || 500;
        res.status(status).json({ status: "error", error: error.message || error });
      });
  });

  router.get('/nuevo-token', function (req, res) {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({ status: "error", error: "Token de autorización requerido" });
    }

    getDatos(token, 1) // permiso_id 1 es un ejemplo, podría ser configurable
      .then((datosOAuth) => {
        // Asumiendo que existe una función 'obtenerDatosUsuario' similar a 'validarUsuario' pero sin las validaciones
        obtenerDatosUsuario(datosOAuth, atributosNuevoToken)
          .then((usuarioLocal) => getNuevoToken(token, usuarioLocal))
          .then((nuevoToken) => {
            res.json({ nuevoToken, status: "ok" });
          })
          .catch((error) => {
            console.error("Error en /nuevo-token (interno):", error);
            res.status(500).json({ status: "error", error });
          });
      })
      .catch((error) => {
        console.error("Error en /nuevo-token (getDatos):", error);
        const status = error.status || 500;
        res.status(status).json({ status: "error", error: error.message || error });
      });
  });

  router.get('/datos/:permiso_id', function (req, res) {
    const { permiso_id } = req.params;
    const token = req.headers.authorization;

    if (!token) {
      return res.status(401).json({ status: "error", error: "Token de autorización requerido" });
    }

    getDatos(token, permiso_id)
    .then((datos) => {
      validarUsuario(datos)
      .then((usuario) => {
        res.json({
          status: "ok",
          datos,
          tipo_usuario_id: usuario.tipo_usuario_id, // Asegúrate que este campo exista en el modelo
          id: usuario.id
        });
      })
      .catch((error) => {
        console.error("Error en /datos (validarUsuario):", error);
        // Errores de validación como "Usuario no encontrado" son 403
        res.status(403).json({ status: "error", error });
      });
    })
    .catch((error) => {
      console.error("Error en /datos (getDatos):", error);
      const status = error.status || 500;
      res.status(status).json({ status: "error", error: error.message || error });
    });
  });

  return router;
}

module.exports = oauthRouter;