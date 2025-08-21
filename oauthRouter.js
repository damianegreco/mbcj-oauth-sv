const express = require('express');
const axios = require('axios');
const { extraerDatosJWT } = require('./middleware');

const { OAUTH_URL, OAUTH_ID, OAUTH_SECRET, OAUTH_VALIDADO, OAUTH_REEMPLAZAR_NOMBRE } = process.env;

/**
 * @typedef {import('express').Router} Router
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 */

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
 * @property {function} findOne - Método para encontrar un registro.
 * @property {function} update - Método para actualizar un registro.
 */

/**
 * @typedef {object} AxiosErrorFormat
 * @property {number} status - Código de estado HTTP del error.
 * @property {string} message - Mensaje descriptivo del error.
 * @property {object} [data] - Datos de la respuesta de error de la API.
 * @property {object} [request] - Objeto de la solicitud que generó el error.
 */

/**
 * Formatea un error de Axios en un objeto estandarizado.
 * @param {Error & {response?: object, request?: object}} error - El objeto de error de Axios.
 * @returns {AxiosErrorFormat} Un objeto de error formateado.
 */
function formatearErrorAxios(error) {
  if (error.response) return { status: error.response.status, message: 'La API de OAuth respondió con un error', data: error.response.data };
  if (error.request) return { status: 502, message: 'No se recibió respuesta de la API de OAuth', request: error.request };
  return { status: 500, message: error.message };
}

/**
 * Crea y configura un router de Express para la autenticación OAuth.
 * @param {UsuarioModel} Usuario - El modelo de Sequelize para la entidad 'Usuario'.
 * @param {string[]} [atributos=['id', 'tipo_usuario_id', 'activo', 'nombre']] - Atributos a solicitar del modelo Usuario.
 * @param {Array<string|Array<string>>} [atributosNuevoToken=[['id', 'usuario_id'], 'tipo_usuario_id']] - Atributos para incluir en el nuevo token.
 * @param {function(Error|string|null, object=): void} [loggeado=function() {}] - Función de callback para registrar eventos de login.
 * @returns {Router} El router de Express configurado.
 */
function oauthRouter(
  Usuario,
  atributos = ['id', 'tipo_usuario_id', 'activo', 'nombre'],
  atributosNuevoToken = [['id', 'usuario_id'], 'tipo_usuario_id'],
  loggeado = function (error, datos) {}
) {
  const router = express.Router();

  /**
   * Obtiene un token de acceso desde el servicio OAuth utilizando un código de autorización.
   * @param {string} codigo - El código de autorización proporcionado por el servicio OAuth.
   * @returns {Promise<string>} Una promesa que resuelve con el token de acceso.
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
   * Obtiene datos del usuario desde el servicio OAuth utilizando un token de acceso.
   * @param {string} token - El token de acceso JWT.
   * @param {string|number} permiso_id - El ID del permiso que se solicita.
   * @returns {Promise<OAuthUserData>} Una promesa que resuelve con los datos del usuario.
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
   * Valida un usuario contra la base de datos local, verifica su estado y actualiza sus datos si es necesario.
   * @param {OAuthUserData} datos - Los datos del usuario obtenidos del servicio OAuth.
   * @returns {Promise<UsuarioModel>} Una promesa que resuelve con la instancia del usuario local validado y actualizado.
   */
  function validarUsuario(datos) {
    return new Promise((resolve, reject) => {
      if (OAUTH_VALIDADO?.toUpperCase() === "TRUE" && !datos.persona.validado) return reject("Usuario no validado");
      Usuario.findOne({ where: { documento: datos.persona.documento }, attributes: atributos })
        .then((usuario) => {
          if (!usuario) return reject("Usuario no encontrado");
          if (!usuario.activo) return reject("Usuario inactivo");

          const nuevoNombre = (`${datos.persona.apellidos}, ${datos.persona.nombre}`).toUpperCase();
          const debeActualizarNombre = OAUTH_REEMPLAZAR_NOMBRE?.toUpperCase() === "TRUE" && usuario.nombre !== nuevoNombre;
          const updates = { ultimo_ingreso: new Date() };

          if (debeActualizarNombre) updates.nombre = nuevoNombre;

          return usuario.update(updates)
            .then(() => resolve(usuario))
            .catch(reject);
        })
        .catch(reject);
    });
  }

  /**
   * Obtiene los datos de un usuario desde la base de datos local a partir de su documento.
   * @param {string} documento - El número de documento del usuario.
   * @param {Array<string|Array<string>>} atributosUsuario - Los atributos a recuperar del modelo de usuario.
   * @returns {Promise<UsuarioModel>} Una promesa que resuelve con los datos del usuario local.
   */
  function obtenerDatosUsuario(documento, atributosUsuario) {
    return new Promise((resolve, reject) => {
      Usuario.findOne({ where: { documento }, attributes: atributosUsuario })
        .then(usuario => {
          if (!usuario) return reject("Usuario local no encontrado");
          return resolve(usuario);
        })
        .catch(reject);
    });
  }

  /**
   * Solicita un nuevo token JWT al servicio OAuth, enriquecido con datos locales del usuario.
   * @param {string} token - El token de acceso original.
   * @param {object} datos - Datos adicionales para incluir en el nuevo token.
   * @returns {Promise<string>} Una promesa que resuelve con el nuevo token JWT.
   */
  function getNuevoToken(token, datos) {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/nuevo-token`;
      const data = { token, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET, datos };
      axios.post(url, data)
        .then((resp) => {
          if (resp.data.status === "ok") return resolve(resp.data.token);
          return reject(resp.data.error || 'Error desconocido al obtener el nuevo token');
        })
        .catch((error) => reject(formatearErrorAxios(error)));
    });
  };

  /**
   * @api {post} /token Canjear Código por Token
   * @apiName PostToken
   * @apiGroup OAuth
   * @apiDescription Canjea un código de autorización de un solo uso por un token de acceso JWT.
   *
   * @apiBody {String} codigo El código de autorización único proporcionado por el servicio OAuth.
   *
   * @apiSuccess {String} status Siempre será "ok".
   * @apiSuccess {String} token El token de acceso JWT generado.
   *
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   *
   * @apiError (400) {String} status Siempre será "error".
   * @apiError (400) {String} error Mensaje indicando que el código es requerido.
   * @apiError (500) {String} status Siempre será "error".
   * @apiError (500) {String} error Mensaje de error general o del servicio OAuth.
   *
   * @apiErrorExample {json} Error - Código Faltante:
   * HTTP/1.1 400 Bad Request
   * {
   * "status": "error",
   * "error": "El código es requerido"
   * }
   */
  router.post('/token', function (req, res) {
    const { codigo } = req.body;
    if (!codigo) return res.status(400).json({ status: "error", error: "El código es requerido" });

    let tokenObtenido;
    getToken(codigo)
      .then((token) => {
        tokenObtenido = token;
        const decoded = extraerDatosJWT(token);
        return obtenerDatosUsuario(decoded.data.documento, [['id', 'usuario_id']]);
      })
      .then((usuario) => {
        loggeado(null, { usuario_id: usuario.usuario_id });
        res.json({ status: "ok", token: tokenObtenido });
      })
      .catch((error) => {
        const errorMessage = error.message || error;
        loggeado(errorMessage);
        console.error("Error en /token:", error);
        const status = error.status || 500;
        res.status(status).json({ status: "error", error: errorMessage });
      });
  });

  /**
   * @api {get} /nuevo-token Refrescar Token
   * @apiName GetNewToken
   * @apiGroup OAuth
   * @apiDescription Obtiene un nuevo token de acceso enriquecido con datos del sistema local a partir de un token válido existente.
   *
   * @apiHeader {String} Authorization El token de autorización JWT actual. (Ej: "Bearer eyJ...")
   *
   * @apiSuccess {String} status Siempre será "ok".
   * @apiSuccess {String} nuevoToken El nuevo token de acceso JWT.
   *
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "nuevoToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   *
   * @apiError (401) {String} status Siempre será "error".
   * @apiError (401) {String} error Mensaje si el token de autorización no es provisto.
   * @apiError (500) {String} status Siempre será "error".
   * @apiError (500) {String} error Mensaje de error general o del servicio OAuth.
   */
  router.get('/nuevo-token', function (req, res) {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ status: "error", error: "Token de autorización requerido" });

    getDatos(token, 1)
      .then((datosOAuth) => obtenerDatosUsuario(datosOAuth.persona.documento, atributosNuevoToken))
      .then((usuarioLocal) => getNuevoToken(token, usuarioLocal))
      .then((nuevoToken) => res.json({ nuevoToken, status: "ok" }))
      .catch((error) => {
        const errorMessage = error.message || error;
        console.error("Error en /nuevo-token:", error);
        const status = error.status || 500;
        res.status(status).json({ status: "error", error: errorMessage });
      });
  });

  /**
   * @api {get} /datos/:permiso_id Obtener Datos del Usuario
   * @apiName GetUserData
   * @apiGroup OAuth
   * @apiDescription Obtiene datos del usuario desde el servicio OAuth y los valida contra el sistema local, devolviendo una combinación de ambos.
   *
   * @apiHeader {String} Authorization El token de autorización JWT. (Ej: "Bearer eyJ...")
   * @apiParam {Number} permiso_id El ID del conjunto de permisos a solicitar al servicio OAuth.
   *
   * @apiSuccess {String} status Siempre será "ok".
   * @apiSuccess {OAuthUserData} datos Objeto con los datos del usuario provenientes del servicio OAuth.
   * @apiSuccess {Number} tipo_usuario_id ID del tipo de usuario en el sistema local.
   * @apiSuccess {Number} id ID del usuario en el sistema local.
   *
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "datos": {
   * "persona": {
   * "documento": "12345678",
   * "nombre": "Juan",
   * "apellidos": "Perez",
   * "validado": true
   * }
   * },
   * "tipo_usuario_id": 2,
   * "id": 101
   * }
   *
   * @apiError (401) {String} status Siempre será "error".
   * @apiError (401) {String} error Mensaje si el token de autorización no es provisto.
   * @apiError (403) {String} status Siempre será "error".
   * @apiError (403) {String} error Mensaje si el usuario no es encontrado, está inactivo o no está validado.
   * @apiError (500) {String} status Siempre será "error".
   * @apiError (500) {String} error Mensaje de error general o del servicio OAuth.
   */
  router.get('/datos/:permiso_id', function (req, res) {
    const { permiso_id } = req.params;
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ status: "error", error: "Token de autorización requerido" });

    getDatos(token, permiso_id)
      .then((datosOAuth) => {
        return validarUsuario(datosOAuth).then(usuarioValidado => ({ datosOAuth, usuarioValidado }));
      })
      .then(({ datosOAuth, usuarioValidado }) => {
        res.json({
          status: "ok",
          datos: datosOAuth,
          tipo_usuario_id: usuarioValidado.tipo_usuario_id,
          id: usuarioValidado.id
        });
      })
      .catch((error) => {
        const errorMessage = error.message || error;
        console.error("Error en /datos:", error);
        const status = (typeof error === 'string') ? 403 : (error.status || 500);
        res.status(status).json({ status: "error", error: errorMessage });
      });
  });

  return router;
}

module.exports = oauthRouter;