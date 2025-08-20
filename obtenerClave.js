const axios = require('axios');
const fs = require('fs');
const path = require('path');

/**
 * Comprueba si un directorio existe en la ruta especificada y, en caso de no existir, lo crea de forma recursiva.
 * @param {string} rutaDirectorio - La ruta completa del directorio a verificar y/o crear.
 * @returns {void}
 */
function checkOrCreateDirectorio(rutaDirectorio) {
  if (fs.existsSync(rutaDirectorio)) return;
  fs.mkdirSync(rutaDirectorio, {recursive: true});
}

/**
 * Realiza una petición GET a una URL para obtener una clave pública y la guarda en un archivo local.
 * La función devuelve una promesa que se resuelve si la operación es exitosa o se rechaza si ocurre un error.
 * @param {string} urlOAuth - La URL de donde se descargará la clave pública.
 * @param {string} rutaDirectorio - El directorio donde se guardará el archivo de la clave.
 * @param {string} nombreArchivo - El nombre del archivo para guardar la clave.
 * @returns {Promise<void>} Una promesa que se resuelve al completar la escritura del archivo, o se rechaza si ocurre un error.
 */
function obtenerClavePublica(urlOAuth, rutaDirectorio, nombreArchivo) {
  return new Promise((resolve, reject) => {
    const clavePath = path.join(rutaDirectorio, nombreArchivo);

    axios.get(urlOAuth)
      .then((res) => {
        const clavePublica = res.data;
        checkOrCreateDirectorio(rutaDirectorio);
        fs.writeFileSync(clavePath, clavePublica, {encoding: 'utf8'});
        resolve();
      })
      .catch((error) => {
        // En lugar de terminar el proceso, rechazamos la promesa para que el llamador maneje el error.
        console.error('Error al obtener o guardar la clave pública:', error.message);
        reject(error);
      });
  });
}

module.exports = obtenerClavePublica;