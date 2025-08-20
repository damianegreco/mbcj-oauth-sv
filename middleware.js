const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const {TOKEN_ADMIN, OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE} = process.env;

/**
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

// Se lee la clave pública una sola vez al iniciar el módulo para optimizar el rendimiento.
// Si la clave no puede ser leída, la aplicación no puede validar tokens de forma segura,
// por lo que se considera un error fatal y se termina el proceso.
let CLAVE_PUBLICA;
try {
  const clavePublicaPath = path.join(OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE);
  CLAVE_PUBLICA = fs.readFileSync(clavePublicaPath);
} catch (error) {
  console.error('Error fatal: No se pudo cargar la clave pública para la verificación de JWT.', error);
  process.exit(1);
}

/**
 * Verifica y decodifica un token JWT utilizando la clave pública del servicio OAuth.
 * @param {string} token - El token JWT a verificar.
 * @returns {Promise<object>} Una promesa que resuelve con los datos decodificados del token.
 * @rejects {{status: number, msj: string}} Un objeto de error con un código de estado y un mensaje descriptivo.
 */
function extraerDatosJWT(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, CLAVE_PUBLICA, {algorithms: ['ES256']}, function(error, decoded) {
      if (error) return reject({
        status: 403,
        msj: error.name === 'JsonWebTokenError'
          ? `Error en token: ${error.message}`
          : error.name === 'TokenExpiredError'
            ? `Token expirado: ${error.expiredAt}`
            : error.message
      });
      return resolve(decoded);
    });
  });
}

/**
 * Fábrica de middlewares para la autenticación y autorización de usuarios mediante JWT.
 * @param {object} Usuario - El modelo de Sequelize para la entidad de Usuario.
 * @returns {{validarUsuario: function(string, boolean=): Promise<object>, validarUsuarioMW: function(Array<number>|null=, boolean=): function}} Un objeto que contiene las funciones `validarUsuario` y `validarUsuarioMW`.
 */
function middleware(Usuario) {
  /**
   * Representa al usuario administrador con privilegios totales.
   * @type {object}
   */
  const admin = {
    usuario_id: 0,
    user: "admin",
    mail: "admin@admin",
    tipo_usuario_id: 1,
    persona_id: 0,
    area_id: 0,
    documento: "00000000",
    nombre: "ADMIN",
  };

  /**
   * Valida un token, verifica la existencia y estado del usuario en la base de datos.
   * Maneja el caso especial del token de "SUPERADMIN".
   * @param {string} token - El token JWT a validar.
   * @param {boolean} [requerido=true] - Si es `false`, permite que la promesa se resuelva exitosamente aunque no se provea un token.
   * @returns {Promise<{status: string, user: object|null}>} Una promesa que resuelve con el estado de la validación y los datos del usuario.
   * @rejects {{status: number, msj: string}} Un objeto de error en caso de que la validación falle.
   */
  const validarUsuario = function(token, requerido = true) {
    return new Promise((resolve, reject) => {
      if (!token) {
        if (requerido) return reject({status: 401, msj: "Sin autorización: token requerido"});
        return resolve({status: "SIN TOKEN", user: null});
      }

      if (token === TOKEN_ADMIN) return resolve({status: "SUPERADMIN", user: admin});

      extraerDatosJWT(token)
        .then((decoded) => {
          const {documento} = decoded.data;
          Usuario.findOne({where: {documento}, attributes: ['activo']})
            .then(usuario => {
              if (!usuario) return reject({status: 403, msj: "Usuario no encontrado"});
              if (!usuario.activo) return reject({status: 403, msj: "Usuario inactivo"});
              resolve({status: "USUARIO", user: {...decoded.data}});
            })
            .catch(err => reject({status: 500, msj: err.message || 'Error de base de datos'}));
        })
        .catch(reject); // Rechaza con el error formateado por extraerDatosJWT
    });
  };

  /**
   * Genera un middleware de Express para validar un JWT y opcionalmente verificar el tipo de usuario.
   * @param {(Array<number>|null)} [tipos_usuario_id=[1]] - Un array de IDs de tipos de usuario permitidos. Si es `null`, se permite el acceso a cualquier tipo de usuario autenticado.
   * @param {boolean} [requerido=true] - Indica si la autenticación es obligatoria para acceder al recurso.
   * @returns {function(Request, Response, NextFunction): void} El middleware para ser usado en rutas de Express.
   */
  const validarUsuarioMW = function(tipos_usuario_id = [1], requerido = true) {
    return function(req, res, next) {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

      validarUsuario(token, requerido)
        .then(resp => {
          req.user = resp.user;
          if (tipos_usuario_id === null) return next();
          if (resp.user && tipos_usuario_id.includes(resp.user.tipo_usuario_id)) return next();
          res.status(403).json({status: "error", error: "Sin permiso"});
        })
        .catch(error => {
          console.error(error);
          res.status(error.status || 403).json({status: "error", error: error.msj || 'Error de autorización'});
        });
    };
  };

  return {validarUsuario, validarUsuarioMW};
}

module.exports = {middleware, extraerDatosJWT};