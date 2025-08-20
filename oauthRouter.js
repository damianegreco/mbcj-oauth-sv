const express = require('express');
const axios =require('axios');

const {OAUTH_URL, OAUTH_ID, OAUTH_SECRET, OAUTH_VALIDADO, OAUTH_REEMPLAZAR_NOMBRE} = process.env;

/**
 * @typedef {import('express').Router} Router
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

/**
 * @typedef {object} OAuthUserData
 * @property {object} persona - Contiene los datos personales del usuario.
 * @property {string} persona.documento - Número de documento del usuario.
 * @property {string} persona.nombre - Nombre del usuario.
 * @property {string} persona.apellidos - Apellidos del usuario.
 * @property {boolean} persona.validado - Indica si la identidad del usuario fue validada.
 */

/**
 * @typedef {object} UsuarioModel
 * @property {number} id - ID del usuario en la base de datos local.
 * @property {string} documento - Documento del usuario.
 * @property {string} nombre - Nombre del usuario.
 * @property {any} tipo_usuario - Tipo de usuario.
 * @property {Date} ultimo_ingreso - Fecha del último ingreso.
 * @property {boolean} activo - Estado de actividad del usuario.
 * @property {function} update - Método para actualizar el registro del usuario.
 */

/**
 * Intercambia un código de autorización por un token de acceso en el servicio OAuth.
 * @param {string} codigo - El código de autorización de un solo uso.
 * @returns {Promise<string>} Una promesa que resuelve con el token de acceso.
 * @throws {string|Error} Rechaza con el error si la API de OAuth responde con un error o si hay un problema de red.
 */
function getToken(codigo) {
  return new Promise((resolve, reject) => {
    const url = `${OAUTH_URL}/cliente/obtener/token`;
    const data = {codigo, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET};
    axios.post(url, data)
      .then((resp) => {
        if (resp.data.status === "ok") return resolve(resp.data.token);
        return reject(resp.data.error);
      })
      .catch((error) => reject(error));
  });
}

/**
 * Obtiene los datos del usuario desde el servicio OAuth utilizando un token y un ID de permiso.
 * @param {string} token - El token de acceso.
 * @param {(number|string)} permiso_id - El identificador del permiso para solicitar los datos.
 * @returns {Promise<OAuthUserData>} Una promesa que resuelve con los datos del usuario obtenidos del servicio OAuth.
 * @throws {string|Error} Rechaza con el error si la API de OAuth responde con un error o si hay un problema de red.
 */
function getDatos(token, permiso_id) {
  return new Promise((resolve, reject) => {
    const url = `${OAUTH_URL}/cliente/obtener/datos/${permiso_id}`;
    const config = {
      params: {cliente_id: OAUTH_ID},
      headers: {authorization: token}
    };
    axios.get(url, config)
      .then((resp) => {
        if (resp.data.status === "ok") return resolve(resp.data.datos);
        return reject(resp.data.error);
      })
      .catch((error) => reject(error));
  });
}

/**
 * Valida un usuario local contra los datos obtenidos del OAuth.
 * Verifica si el usuario existe, está activo y, opcionalmente, si está validado en OAuth.
 * Actualiza el nombre y la fecha de último ingreso si está configurado.
 * @param {OAuthUserData} datos - Los datos del usuario obtenidos del servicio OAuth.
 * @param {string[]} atributos - Lista de atributos a recuperar del modelo de usuario local.
 * @returns {Promise<UsuarioModel>} Una promesa que resuelve con la instancia del usuario local encontrada y actualizada.
 * @throws {string} Rechaza con un mensaje de error específico si la validación falla ("Usuario no validado", "Usuario no encontrado", "Usuario inactivo").
 */
function validarUsuario(datos, atributos) {
  return new Promise((resolve, reject) => {
    if (OAUTH_VALIDADO?.toUpperCase() === "TRUE" && !datos.persona.validado) return reject("Usuario no validado");
    Usuario.findOne({where: {documento: datos.persona.documento}, attributes: atributos})
      .then((usuario) => {
        if (usuario === null) return reject("Usuario no encontrado");
        if (!usuario.activo) return reject("Usuario inactivo");
        
        const nuevoNombre = (`${datos.persona.apellidos}, ${datos.persona.nombre}`).toUpperCase();
        const debeActualizarNombre = OAUTH_REEMPLAZAR_NOMBRE?.toUpperCase() === "TRUE" && usuario.nombre !== nuevoNombre;

        const actualizacionNombrePromise = debeActualizarNombre ? usuario.update({nombre: nuevoNombre}) : Promise.resolve();

        actualizacionNombrePromise
          .then(() => usuario.update({ultimo_ingreso: new Date()}))
          .then(() => resolve(usuario))
          .catch((error) => reject(error));
      })
      .catch((error) => reject(error));
  });
}

/**
 * Busca y devuelve un usuario local basado en el documento de los datos del OAuth.
 * @param {OAuthUserData} datos - Los datos del usuario obtenidos del servicio OAuth.
 * @param {string[]} atributos - Lista de atributos a recuperar del modelo de usuario local.
 * @returns {Promise<UsuarioModel>} Una promesa que resuelve con la instancia del usuario local.
 * @throws {string} Rechaza con "Usuario no encontrado" si el usuario no existe en la base de datos local.
 */
function obtenerDatosUsuario(datos, atributos) {
  return new Promise((resolve, reject) => {
    Usuario.findOne({where: {documento: datos.persona.documento}, attributes: atributos})
      .then((usuario) => {
        if (usuario === null) return reject("Usuario no encontrado");
        resolve(usuario);
      })
      .catch((error) => reject(error));
  });
}

/**
 * Solicita un nuevo token al servicio OAuth, incrustando datos adicionales.
 * @param {string} token - El token de acceso original.
 * @param {object} datos - Datos adicionales para incrustar en el nuevo token.
 * @returns {Promise<string>} Una promesa que resuelve con el nuevo token de acceso.
 * @throws {string|Error} Rechaza con el error si la API de OAuth responde con un error o si hay un problema de red.
 */
function getNuevoToken(token, datos) {
  return new Promise((resolve, reject) => {
    const url = `${OAUTH_URL}/cliente/obtener/nuevo-token`;
    const data = {token, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET, datos};
    axios.post(url, data)
      .then((resp) => {
        if (resp.data.status === "ok") return resolve(resp.data.token);
        return reject(resp.data.error);
      })
      .catch((error) => reject(error));
  });
}

/**
 * Crea y configura un router de Express para manejar la autenticación OAuth.
 * @param {object} Usuario - El modelo (Sequelize) para la entidad de Usuario.
 * @param {string[]} [atributos=['id', 'tipo_usuario_id', 'activo', 'nombre']] - Atributos a obtener del usuario al validar.
 * @param {string[]} [atributosNuevoToken=['tipo_usuario_id']] - Atributos a incrustar en un nuevo token.
 * @param {function(Error|string|null): void} [loggeado=function(error){}] - Callback para registrar el resultado del inicio de sesión.
 * @returns {Router} El router de Express configurado con los endpoints de OAuth.
 */
function oauthRouter(
  Usuario, 
  atributos = ['id', 'tipo_usuario_id', 'activo', 'nombre'],
  atributosNuevoToken = ['tipo_usuario_id'],
  loggeado = function(error){}
){
  const router = express.Router();

  /**
   * @api {post} /oauth/token Obtener Token de Acceso
   * @apiName PostOAuthToken
   * @apiGroup Autenticación
   * @apiVersion 1.0.0
   * @apiDescription Intercambia un código de autorización de un solo uso por un token de acceso.
   *
   * @apiBody {String} codigo El código de autorización temporal proporcionado por el servicio OAuth.
   *
   * @apiSuccess {String} status Estado de la operación, siempre "ok".
   * @apiSuccess {String} token El token de acceso para realizar solicitudes autenticadas.
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   *
   * @apiError (403 Forbidden) CodigoInvalido El código de autorización ha expirado, ya fue utilizado o es inválido.
   * @apiErrorExample {string} Error - Código Inválido:
   * HTTP/1.1 403 Forbidden
   * Código vencido
   *
   * @apiError (500 Internal Server Error) ErrorInterno Ocurrió un error inesperado al comunicarse con el servicio OAuth.
   * @apiErrorExample {json} Error - Interno:
   * HTTP/1.1 500 Internal Server Error
   * {
   * "status": "error",
   * "error": "Mensaje de error del servidor"
   * }
   */
  router.post('/token', function(req, res, next) {
    const {codigo} = req.body;
    getToken(codigo)
      .then((token) => {
        loggeado(null);
        res.json({status: "ok", token});
      })
      .catch((error) => {
        if (error?.response?.status === 403) {
          loggeado("Código vencido");
          return res.status(403).send("Código vencido");
        }
        loggeado(error);
        console.error(error);
        res.status(500).json({status: "error", error});
      });
  });

  /**
   * @api {get} /oauth/nuevo-token Refrescar Token con Datos Locales
   * @apiName GetOAuthNuevoToken
   * @apiGroup Autenticación
   * @apiVersion 1.0.0
   * @apiDescription Obtiene datos del usuario local y los utiliza para generar un nuevo token de acceso en el servicio OAuth con la información actualizada.
   *
   * @apiHeader {String} Authorization El token de acceso del usuario.
   *
   * @apiSuccess {String} status Estado de la operación, siempre "ok".
   * @apiSuccess {String} nuevoToken El nuevo token de acceso con los datos locales incrustados.
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "nuevoToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   * }
   *
   * @apiError (500 Internal Server Error) ErrorInterno Ocurrió un error al contactar al servicio OAuth o al buscar al usuario en la base de datos local.
   */
  router.get('/nuevo-token', function(req, res, next){
    const token = req.headers.authorization;
    getDatos(token, 1)
      .then((datosOAuth) => {
        obtenerDatosUsuario(datosOAuth, atributosNuevoToken)
          .then((usuarioLocal) => getNuevoToken(token, usuarioLocal))
          .then((nuevoToken) => {
            res.json({nuevoToken, status: "ok"});
          })
          .catch((error) => {
            console.error(error);
            res.status(500).json({status: "error", error});
          });
      })
      .catch((error) => {
        console.error(error);
        res.status(500).json({status: "error", error});
      });
  });

  /**
   * @api {get} /oauth/datos/:permiso_id Validar Usuario y Obtener Datos
   * @apiName GetOAuthDatos
   * @apiGroup Autenticación
   * @apiVersion 1.0.0
   * @apiDescription Obtiene datos del servicio OAuth, valida al usuario contra la base de datos local, actualiza su información si es necesario y devuelve los datos del perfil junto con identificadores locales.
   *
   * @apiHeader {String} Authorization El token de acceso del usuario.
   * @apiParam {Number} permiso_id ID del conjunto de permisos para los datos que se desean obtener.
   *
   * @apiSuccess {String} status Estado de la operación, siempre "ok".
   * @apiSuccess {OAuthUserData} datos Perfil de usuario obtenido del servicio OAuth.
   * @apiSuccess {Number} tipo_usuario_id El ID del tipo de usuario en el sistema local.
   * @apiSuccess {Number} id El ID del usuario en el sistema local.
   * @apiSuccessExample {json} Respuesta de Éxito:
   * HTTP/1.1 200 OK
   * {
   * "status": "ok",
   * "datos": {
   * "persona": { "documento": "12345678", "nombre": "Juan", "apellidos": "Perez", "validado": true }
   * },
   * "tipo_usuario_id": 2,
   * "id": 101
   * }
   *
   * @apiError (403 Forbidden) ErrorValidacion El usuario no fue encontrado, está inactivo o no está validado en el servicio OAuth (si es requerido).
   * @apiErrorExample {string} Error - Validación:
   * HTTP/1.1 403 Forbidden
   * Usuario no encontrado
   *
   * @apiError (500 Internal Server Error) ErrorInterno Ocurrió un error al comunicarse con el servicio OAuth.
   */
  router.get('/datos/:permiso_id', function(req, res, next){
    const {permiso_id} = req.params;
    const token = req.headers.authorization;
    getDatos(token, permiso_id)
      .then((datos) => {
        validarUsuario(datos, atributos)
          .then((usuario) => {
            res.json({status: "ok", datos, tipo_usuario_id: usuario.tipo_usuario, id: usuario.id});
          })
          .catch((error) => {
            console.error(error);
            res.status(403).send(error);
          });
      })
      .catch((error) => {
        console.error(error);
        res.status(500).json({status: "error", error});
      });
  });

  return router;
}

module.exports = oauthRouter;