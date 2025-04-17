const express = require('express');
const axios = require('axios')

const {OAUTH_URL, OAUTH_ID, OAUTH_SECRET, OAUTH_VALIDADO, OAUTH_REEMPLAZAR_NOMBRE} = process.env;

/*
  MODELO USUARIO:
  - id
  - documento (valor clave para matchear con el oauth)
  - nombre (de referencia hasta cambiar por el del oauth en caso de establecer la variable)
  - tipo_usuario
  - ultimo_ingreso
  - activo
*/

function oauthRouter(Usuario){
  const router = express.Router();

  const getToken = (codigo) => {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/token`;
      const data = {codigo, cliente_id: OAUTH_ID, cliente_secreto: OAUTH_SECRET};
      axios.post(url, data)
      .then((resp) => {
        if (resp.data.status === "ok") return resolve(resp.data.token)
        return reject(resp.data.error);
      })
      .catch((error) => reject(error))
    })
  }

  const getDatos = (token, permiso_id) => {
    return new Promise((resolve, reject) => {
      const url = `${OAUTH_URL}/cliente/obtener/datos/${permiso_id}`;
      const config = {
        params:{cliente_id: OAUTH_ID},
        headers: {authorization: token}
      };
      axios.get(url, config)
      .then((resp) => {
        if (resp.data.status === "ok") return resolve(resp.data.datos)
        return reject(resp.data.error);
      })
      .catch((error) => reject(error))
    })
  }

  const validarUsuario = (datos) => {
    return new Promise((resolve, reject) => {
      if (OAUTH_VALIDADO?.toUpperCase() === "TRUE" && !datos.persona.validado) return reject("Usuario no validado");
      Usuario.findOne({
        where: {documento: datos.persona.documento},
        attributes: ['id', 'tipo_usuario', 'activo', 'nombre']
      })
      .then(async (usuario) => {
        if (usuario === null) return reject("Usuario no encontrado");
        if (!usuario.activo) return reject("Usuario inactivo");
        const nuevoNombre = (`${datos.persona.apellidos}, ${datos.persona.nombre}`).toUpperCase();
        if (OAUTH_REEMPLAZAR_NOMBRE?.toUpperCase() === "TRUE" && (usuario.nombre !==  nuevoNombre))
          await usuario.update({nombre: nuevoNombre});
        await usuario.update({ultimo_ingreso: new Date()});
        resolve(usuario)
      })
      .catch((error) => reject(error));
    })
  }

  /**
   * @api {post} /usuarios/oauth/token Obtener token del usuario
   * @apiName PostUsuarioOauthDatos
   * @apiGroup Usuarios
   * @apiVersion 0.1.0
   * 
   * @apiBody {String} codigo Codigo otorgado al loggearse el usuario
   * 
   * @apiSuccess {String} status
   * @apiSuccess {String} token Token obtenido al intercambiar el codigo en el OAuth
   */

  router.post('/token', function(req, res, next) {
    const {codigo} = req.body;
    getToken(codigo)
    .then((token) => {
      res.json({status:"ok", token});
    })
    .catch((error) => {
      if (error.status === 403) {
        res.status(error.status).send("Código vencido");
      } else {
        console.error(error);
        res.status(500).json({status:"error", error});
      }
    })
  })

  /**
   * @api {get} /usuarios/oauth/datos/:permiso_id Guardar domicilio de persona
   * @apiName GetUsuarioOauthDatos
   * @apiGroup Usuarios
   * @apiVersion 0.1.0
   * 
   * @apiParam {Number} permiso_id ID del permiso otorgado para conseguir datos
   * 
   * @apiSuccess {String} status
   * 
   * @apiSuccess {Object} datos Corresponde a los datos conseguidos del OAuth
   * @apiSuccess {Number} tipo_usuario_id ID del tipo de usuario 
   * @apiSuccess {Number} id ID del usuario
   */

  router.get('/datos/:permiso_id', function(req, res, next){
    const {permiso_id} = req.params;
    const token = req.headers.authorization;
    getDatos(token, permiso_id)
    .then((datos) => {
      validarUsuario(datos)
      .then((usuario) => {
        res.json({status:"ok", datos, tipo_usuario_id: usuario.tipo_usuario, id: usuario.id})
      })
      .catch((error) => {
        console.error(error);
        res.status(403).send(error);
      })
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({status:"error", error})
    })

  })

  return router;
}

module.exports = oauthRouter;