const axios = require('axios');
const fs = require('fs');
const path = require('path');

const obtenerClavePublica = function(URL_oauth, ruta_directorio, nombre_archivo){
  const clavePath = path.join(ruta_directorio, nombre_archivo);

  axios.get(URL_oauth)
  .then((res) => {
    const clave_publica = res.data;
    fs.writeFileSync(clavePath, clave_publica, {encoding:'utf8'})
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
}

module.exports = obtenerClavePublica;