const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const { TOKEN_ADMIN, OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE } = process.env;

/**
 * @typedef {import('express').Request} Request
 * @typedef {import('express').Response} Response
 * @typedef {import('express').NextFunction} NextFunction
 */

// Se lee la clave pública una sola vez al iniciar el módulo para optimizar.
// Si la clave no se puede leer, se considera un error fatal, ya que la
// validación de tokens es una función crítica de seguridad.
let CLAVE_PUBLICA;
try {
  const clavePublicaPath = path.join(OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE);
  CLAVE_PUBLICA = fs.readFileSync(clavePublicaPath);
} catch (error) {
  console.error('Error fatal: No se pudo cargar la clave pública para la verificación de JWT.', error);
  process.exit(1); // Termina el proceso si la clave no está disponible.
}

/**
 * Crea un objeto de error estandarizado.
 * @param {number} status - El código de estado HTTP.
 * @param {string} msj - El mensaje de error.
 * @returns {{status: number, msj: string}} El objeto de error.
 */
function crearError(status, msj) {
  return { status, msj };
}

/**
 * Verifica y decodifica un token JWT utilizando la clave pública del servicio OAuth.
 * @param {string} token - El token JWT a verificar.
 * @returns {Promise<object>} Una promesa que resuelve con los datos decodificados del token.
 * @rejects {{status: number, msj: string}} Un objeto de error si la verificación falla.
 */
function extraerDatosJWT(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, CLAVE_PUBLICA, { algorithms: ['ES256'] }, (error, decoded) => {
      if (error) {
        let msj;
        if (error.name === 'JsonWebTokenError') {
          msj = `Error en token: ${error.message}`;
        } else if (error.name === 'TokenExpiredError') {
          msj = `Token expirado: ${error.expiredAt}`;
        } else {
          msj = error.message;
        }
        return reject(crearError(403, msj));
      }
      return resolve(decoded);
    });
  });
}

/**
 * Fábrica de middlewares para la autenticación y autorización de usuarios.
 * @param {object} Usuario - El modelo de Sequelize para la entidad de Usuario.
 * @returns {{validarUsuario: function(string, boolean=): Promise<object>, validarUsuarioMW: function(Array<number>|null=, boolean=): function}}
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
   * Valida un token, y verifica la existencia y estado del usuario en la base de datos.
   * Maneja el caso especial del token de "SUPERADMIN".
   * @param {string | null} token - El token JWT a validar.
   * @param {boolean} [requerido=true] - Si es `false`, permite continuar si no hay token.
   * @returns {Promise<{status: string, user: object|null}>} Una promesa que resuelve con los datos del usuario.
   * @rejects {{status: number, msj: string}} Un objeto de error si la validación falla.
   */
  const validarUsuario = function(token, requerido = true) {
    return new Promise((resolve, reject) => {
      if (!token) {
        if (requerido) return reject(crearError(401, "Sin autorización: token requerido"));
        return resolve({ status: "SIN TOKEN", user: null });
      }

      if (token === TOKEN_ADMIN) {
        return resolve({ status: "SUPERADMIN", user: admin });
      }

      extraerDatosJWT(token)
        .then((decoded) => {
          const { documento } = decoded.data;
          Usuario.findOne({ where: { documento }, attributes: ['activo'] })
            .then(usuario => {
              if (!usuario) return reject(crearError(403, "Usuario no encontrado"));
              if (!usuario.activo) return reject(crearError(403, "Usuario inactivo"));
              resolve({ status: "USUARIO", user: { ...decoded.data } });
            })
            .catch(err => reject(crearError(500, err.message || 'Error de base de datos')));
        })
        .catch(reject); // El error ya viene formateado desde extraerDatosJWT
    });
  };

  /**
   * Genera un middleware de Express para proteger rutas.
   * Verifica el JWT y, opcionalmente, los permisos por tipo de usuario.
   * @param {(Array<number>|null)} [tipos_usuario_id=[1]] - IDs de tipos de usuario permitidos. `null` para cualquier usuario autenticado.
   * @param {boolean} [requerido=true] - Si la autenticación es obligatoria.
   * @returns {function(Request, Response, NextFunction): void} El middleware para Express.
   */
  const validarUsuarioMW = function(tipos_usuario_id = [1], requerido = true) {
    return function(req, res, next) {
      const authHeader = req.headers.authorization;
      let token = null;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7);
      } else if (authHeader) {
        token = authHeader; // Acepta el token directamente
      }

      validarUsuario(token, requerido)
        .then(resp => {
          req.user = resp.user;
          if (tipos_usuario_id === null) {
            return next();
          }
          if (resp.user && tipos_usuario_id.includes(resp.user.tipo_usuario_id)) {
            return next();
          }
          // Usamos el helper para devolver un error estandarizado
          const error = crearError(403, "Sin permiso");
          res.status(error.status).json({ status: "error", error: error.msj });
        })
        .catch(error => {
          console.error(error);
          res.status(error.status || 403).json({ status: "error", error: error.msj || 'Error de autorización' });
        });
    };
  };

  return { validarUsuario, validarUsuarioMW };
}

module.exports = { middleware, extraerDatosJWT };