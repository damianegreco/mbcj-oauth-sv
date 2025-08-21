const express = require('express');
const axios = require('axios');

// Se añade JWT_SECRET para la firma del nuevo token
const { OAUTH_URL, OAUTH_ID, OAUTH_SECRET, OAUTH_VALIDADO, OAUTH_REEMPLAZAR_NOMBRE } = process.env;

/**
 * @typedef {import('express').Router} Router
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

// JSDoc para OAuthUserData y UsuarioModel
/**
 * @typedef {object} OAuthUserData
 * @property {object} persona
 * @property {string} persona.documento
 * @property {string} persona.nombre
 * @property {string} persona.apellidos
 * @property {boolean} persona.validado
 */
/**
 * @typedef {object} UsuarioModel
 * @property {number} id
 * @property {number} tipo_usuario_id
 * @property {boolean} activo
 * @property {string} nombre
 * @property {Date} ultimo_ingreso
 * @property {function} findOne
 * @property {function} update
 */


/**
 * Extrae y formatea un error de una respuesta de Axios para un mejor registro y depuración.
 * @param {Error} error - El objeto de error de Axios.
 * @returns {{status: number, message: string, data: any}} Un objeto de error formateado.
 */
function formatearErrorAxios(error) {
  if (error.response) {
    return {
      status: error.response.status,
      message: 'La API de OAuth respondió con un error',
      data: error.response.data
    };
  } else if (error.request) {
    return {
      status: 500,
      message: 'No se recibió respuesta de la API de OAuth',
      request: error.request
    };
  } else {
    return {
      status: 500,
      message: error.message
    };
  }
}

/**
 * Crea y configura un router de Express para manejar la autenticación OAuth.
 * @param {UsuarioModel} Usuario - El modelo de Sequelize para la entidad de Usuario.
 * @param {string[]} [atributos=['id', 'tipo_usuario_id', 'activo', 'nombre']] - Atributos a obtener del usuario.
 * @param {string[]} [atributosNuevoToken=['id', 'tipo_usuario_id']] - Atributos para incrustar en un nuevo token.
 * @param {function(Error|string|null): void} [loggeado=function(error){}] - Callback para registrar el login.
 * @returns {Router} El router de Express confi gurado.
 */
function oauthRouter(
  Usuario,
  atributos = ['id', 'tipo_usuario_id', 'activo', 'nombre'],
  atributosNuevoToken = ['id', 'tipo_usuario_id'],
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
   * @returns {Promise<OAuthUserData>} Promesa que resuelve con los datos del usuario.
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
   * Valida un usuario local contra los datos de OAuth, actualizando su último ingreso y nombre si es necesario.
   * @param {OAuthUserData} datos - Los datos del usuario obtenidos de OAuth.
   * @returns {Promise<UsuarioModel>} Promesa que resuelve con la instancia del usuario local.
   */
  function validarUsuario(datos) {
    return new Promise((resolve, reject) => {
      if (OAUTH_VALIDADO?.toUpperCase() === "TRUE" && !datos.persona.validado) {
        return reject("Usuario no validado");
      }
      Usuario.findOne({ where: { documento: datos.persona.documento }, attributes: atributos })
        .then((usuario) => {
          if (!usuario) return reject("Usuario no encontrado");
          if (!usuario.activo) return reject("Usuario inactivo");

          const nuevoNombre = (`${datos.persona.apellidos}, ${datos.persona.nombre}`).toUpperCase();
          const debeActualizarNombre = OAUTH_REEMPLAZAR_NOMBRE?.toUpperCase() === "TRUE" && usuario.nombre !== nuevoNombre;

          const updates = { ultimo_ingreso: new Date() };
          if (debeActualizarNombre) {
            updates.nombre = nuevoNombre;
          }

          usuario.update(updates)
            .then(() => resolve(usuario))
            .catch(reject);
        })
        .catch(reject);
    });
  }

  /**
   * Obtiene los datos de un usuario local a partir de los datos de OAuth sin realizar validaciones.
   * @param {OAuthUserData} datosOAuth - Los datos del usuario de OAuth.
   * @param {string[]} atributosUsuario - Los atributos a obtener del modelo Usuario.
   * @returns {Promise<UsuarioModel>} Promesa que resuelve con los datos del usuario local.
   */
  function obtenerDatosUsuario(datosOAuth, atributosUsuario) {
    return new Promise((resolve, reject) => {
      Usuario.findOne({
        where: { documento: datosOAuth.persona.documento },
        attributes: atributosUsuario
      })
      .then(usuario => {
        if (!usuario) return reject("Usuario local no encontrado");
        resolve(usuario);
      })
      .catch(reject);
    });
  }
/**
   * Obtiene un nuevo token desde el servidor OAuth.
   * @param {string} token - El token de acceso original.
   * @param {object} datos - Datos adicionales del usuario local para enviar.
   * @returns {Promise<string>} Promesa que resuelve con el nuevo token.
   */
  const getNuevoToken = (token, datos) => {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/nuevo-token`;
      const data = { token, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET, datos };
      axios.post(url, data)
        .then((resp) => {
          if (resp.data.status === "ok") return resolve(resp.data.token);
          return reject(resp.data.error || 'Error desconocido al obtener el nuevo token');
        })
        .catch((error) => reject(formatearErrorAxios(error))); // Usar el formateador de errores
    });
  };

  // --- Rutas del Router ---

  router.post('/token', function (req, res) {
    const { codigo } = req.body;
    if (!codigo) {
      loggeado("El código es requerido");
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

    getDatos(token, 1) // permiso_id 1 para obtener datos básicos
      .then((datosOAuth) => {
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
          tipo_usuario_id: usuario.tipo_usuario_id,
          id: usuario.id
        });
      })
      .catch((error) => {
        console.error("Error en /datos (validarUsuario):", error);
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