const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { TOKEN_ADMIN, OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE } = process.env;

/*
  uso: validarUsuarioMW([1], true)
  roles de usuarios
    1 - Agente
    3 - Autoridad
    4 - Administrador
    5 - Agrupaciones

*/
function middleware (Usuario) {

  const admin = {
    usuario_id: 0,
    user: "admin",
    mail: "admin@admin",
    tipo_usuario_id: 1,
    persona_id: 0,
    area_id: 0,
    documento: "00000000",
    nombre: "ADMIN",
  }
  
  const obtenerClavePublica = function(){
    const clavePublicaPath = path(OAUTH_CLAVE_DIR, OAUTH_CLAVE_FILE);
    const clavePublica = fs.readFileSync(clavePublicaPath);
    return clavePublica;
  }
  
  const validarUsuario = function(token, requerido = true){
    return new Promise((resolve, reject) => {
      if (token !== undefined || token !== null && token !== ""){
        if(token === TOKEN_ADMIN) return resolve({status:"SUPERADMIN", user:admin});
        try {
          const clavePublica = obtenerClavePublica();
          
          jwt.verify(token, clavePublica, { algorithms: ['ES256'] }, function(error, decoded){
            if (error) throw(error)
            const {usuario_id} = decoded.data;
            Usuario.findOne({where:{id:usuario_id}, attributes:['activo', 'area_id']})
            .then((usuario) => {
              if (usuario === null) throw new Error("Usuario no encontrado");
              if (!usuario.activo) throw new Error("Usuario inactivo"); 
              return resolve({status:"USUARIO", user: {...decoded.data, area_id: usuario.area_id}})
            })
            .catch((error) =>  {throw new Error(error)});
          });
        } catch (error) { 
          let tokenError = "";
          if (error.name === 'JsonWebTokenError') tokenError = `Error en token: ${error}`;
          else if (error.name === 'TokenExpiredError') tokenError = `Token expirado: ${error.expiredAt}`;
          else tokenError = error;
          reject({status: 403, msj: tokenError});
        }
      }else{
        if (requerido) return reject({status:"SIN TOKEN", user:null, msj:"Sin autorizacion"})
        return resolve({status:"SIN TOKEN", user:null, msj:"Sin autorizacion"})
      }
    })
  }
  
  const validarUsuarioMW = function(tipos_usuario_id = [1], requerido = true){
    return function(req, res, next) {
      const token = req.headers.authorization;
      validarUsuario(token, requerido)
      .then((resp) => {
        res.user = resp.user;
        if (tipos_usuario_id === null) return next();
        if (tipos_usuario_id.includes(resp.user.tipo_usuario_id)) return next();
        res.status(403).json({status:"error", error: "Sin permiso"});
      })
      .catch((error) => {
        res.status(error.status).json({status:"error", error: error.msj});
      })
    }
  }
  return { validarUsuario, validarUsuarioMW }
}


module.exports = middleware;