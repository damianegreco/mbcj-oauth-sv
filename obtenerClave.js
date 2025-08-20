const axios = require('axios');
const fs = require('fs');
const path = require('path');

/**
 * Extrae y formatea un error de una respuesta de Axios.
 * @param {Error} error - El objeto de error de Axios.
 * @returns {{status: number, message: string, data: any}} Un objeto de error formateado.
 */
function formatearErrorAxios(error) {
  if (error.response) {
    return {
      status: error.response.status,
      message: `La solicitud a la URL de la clave falló con estado ${error.response.status}`,
      data: error.response.data
    };
  } else if (error.request) {
    return {
      status: 500,
      message: 'No se recibió respuesta del servidor al solicitar la clave pública'
    };
  } else {
    return {
      status: 500,
      message: `Error al configurar la solicitud: ${error.message}`
    };
  }
}

/**
 * Comprueba si un directorio existe y, si no, lo crea de forma segura.
 * @param {string} rutaDirectorio - La ruta completa del directorio a crear.
 * @throws {Error} Si ocurre un error al crear el directorio.
 */
function checkOrCreateDirectorio(rutaDirectorio) {
  if (fs.existsSync(rutaDirectorio)) {
    return;
  }
  try {
    fs.mkdirSync(rutaDirectorio, { recursive: true });
  } catch (error) {
    // Lanza un error más descriptivo si falla la creación del directorio.
    throw new Error(`No se pudo crear el directorio '${rutaDirectorio}': ${error.message}`);
  }
}

/**
 * Descarga una clave pública desde una URL y la guarda en un archivo local.
 * @param {string} urlOAuth - La URL para descargar la clave pública.
 * @param {string} rutaDirectorio - El directorio donde se guardará el archivo.
 * @param {string} nombreArchivo - El nombre del archivo para la clave.
 * @returns {Promise<string>} Una promesa que resuelve con la ruta completa al archivo guardado.
 * @rejects {Error} Si ocurre un error durante la descarga o el guardado.
 */
function obtenerClavePublica(urlOAuth, rutaDirectorio, nombreArchivo) {
  return new Promise((resolve, reject) => {
    // Validar que los argumentos no estén vacíos
    if (!urlOAuth || !rutaDirectorio || !nombreArchivo) {
      return reject(new Error("Los parámetros urlOAuth, rutaDirectorio y nombreArchivo son obligatorios."));
    }

    axios.get(urlOAuth)
      .then((res) => {
        const clavePublica = res.data;
        if (!clavePublica) {
          return reject(new Error("La respuesta de la URL no contenía datos para la clave pública."));
        }
        
        try {
          checkOrCreateDirectorio(rutaDirectorio);
          const clavePath = path.join(rutaDirectorio, nombreArchivo);
          fs.writeFileSync(clavePath, clavePublica, { encoding: 'utf8' });
          resolve(clavePath); // Resuelve con la ruta del archivo para confirmación.
        } catch (error) {
          console.error('Error al guardar la clave pública en el archivo:', error.message);
          reject(error);
        }
      })
      .catch((error) => {
        const errorFormateado = formatearErrorAxios(error);
        console.error('Error al obtener la clave pública desde la URL:', errorFormateado.message);
        reject(new Error(errorFormateado.message));
      });
  });
}

module.exports = obtenerClavePublica;