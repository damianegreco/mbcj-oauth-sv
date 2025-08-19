const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { TOKEN_ADMIN, OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE } = process.env;

/**
 * Middleware de autenticación y autorización basado en JWT.
 * @param {Object} Usuario - Modelo Sequelize para consultar usuarios.
 * @returns {Object} Contiene funciones para validar usuario y middleware de validación.
 */
function middleware(Usuario) {
  /** 
   * Usuario administrador "super admin" hardcodeado 
   * @type {Object}
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
   * Obtiene la clave pública para verificar el token JWT.
   * @returns {Buffer} Clave pública en formato Buffer.
   * @throws {Error} Si no se puede leer la clave pública.
   */
  const obtenerClavePublica = function () {
    const clavePublicaPath = path.join(OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE);
    return fs.readFileSync(clavePublicaPath);
  };

  /**
   * Valida un token JWT y verifica que el usuario esté activo.
   * @param {string} token - Token JWT a validar.
   * @param {boolean} [requerido=true] - Indica si el token es obligatorio.
   * @returns {Promise<Object>} Resuelve con información del usuario validado.
   * @rejects {Object} Objeto con status y mensaje de error en caso de falla.
   */
  const validarUsuario = function (token, requerido = true) {
    return new Promise((resolve, reject) => {
      if (token) {
        if (token === TOKEN_ADMIN) return resolve({ status: "SUPERADMIN", user: admin });
        try {
          const clavePublica = obtenerClavePublica();

          jwt.verify(token, clavePublica, { algorithms: ['ES256'] }, function (error, decoded) {
            if (error) return reject({
              status: 403,
              msj: error.name === 'JsonWebTokenError'
                ? `Error en token: ${error.message}`
                : error.name === 'TokenExpiredError'
                  ? `Token expirado: ${error.expiredAt}`
                  : error.message
            });

            const { usuario_id } = decoded.data;

            Usuario.findOne({ where: { id: usuario_id }, attributes: ['activo', 'area_id'] })
              .then(usuario => {
                if (!usuario) return reject({ status: 403, msj: "Usuario no encontrado" });
                if (!usuario.activo) return reject({ status: 403, msj: "Usuario inactivo" });
                resolve({ status: "USUARIO", user: { ...decoded.data, area_id: usuario.area_id } });
              })
              .catch(err => reject({ status: 403, msj: err.message || err.toString() }));
          });
        } catch (error) {
          reject({ status: 403, msj: `Error interno: ${error.message}` });
        }
      } else {
        if (requerido) return reject({ status: 401, msj: "Sin autorización: token requerido" });
        resolve({ status: "SIN TOKEN", user: null, msj: "Sin autorización" });
      }
    });
  };

  /**
   * Middleware Express para validar usuario basado en JWT y verificar roles.
   * @param {Array<number>|null} [tipos_usuario_id=[1]] - Tipos de usuario permitidos. Null permite todos.
   * @param {boolean} [requerido=true] - Indica si el token es obligatorio.
   * @returns {function} Middleware Express.
   */
  const validarUsuarioMW = function (tipos_usuario_id = [1], requerido = true) {
    return function (req, res, next) {
      // Extraer token del header Authorization tipo "Bearer <token>"
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

      validarUsuario(token, requerido)
        .then(resp => {
          req.user = resp.user; // Se asigna al req para que esté disponible en siguientes middlewares
          if (tipos_usuario_id === null) return next();
          if (resp.user && tipos_usuario_id.includes(resp.user.tipo_usuario_id)) return next();
          res.status(403).json({ status: "error", error: "Sin permiso" });
        })
        .catch(error => {
          res.status(error.status || 403).json({ status: "error", error: error.msj || 'Error de autorización' });
        });
    };
  };

  return { validarUsuario, validarUsuarioMW };
}

module.exports = middleware;
