const axios = require('axios');
const fs = require('fs');
const path = require('path');

function checkOrCreateDirectorio(ruta_directorio){
  if (fs.existsSync(ruta_directorio)) return;
  fs.mkdirSync(ruta_directorio, { recursive: true });
  return;
}

function obtenerClavePublica(URL_oauth, ruta_directorio, nombre_archivo){
  const clavePath = path.join(ruta_directorio, nombre_archivo);

  axios.get(URL_oauth)
  .then((res) => {
    const clave_publica = res.data;
    checkOrCreateDirectorio(ruta_directorio);
    fs.writeFileSync(clavePath, clave_publica, {encoding:'utf8'})
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
}

module.exports = obtenerClavePublica;