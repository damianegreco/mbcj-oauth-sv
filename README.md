
# OAuth MBCJ backend

Librería para Node.js para utilizar el OAuth del Ministerio de Bienestar Ciduadano y Justicia.

Tiene las funciones para intercambiar el código por token, buscar datos y la del middleware.

Se utiliza junto a express y debe tener las variables de entorno inicializadas.

## Instalación

Instalar la librería con NPM

```bash
  npm install mbcj-oauth-sv
```


## Uso y ejemplo

### Middleare

```javascript
//Al importar la función del middlwarea, se debe enviar el modelo de Usuario de sequelize
const MW = require('mbcj-oauth-sv').middleware(Usuario);

/*
Al declarar la ruta protegida, se debe utilizar como parámetro la validación, indicando la siguiente información:
MW.validarUsuarioMW(
  [3,4],    //tipos de usuario habilitados a acceder al recurso
  true      //requiere contener un token para acceder
)
*/

router.use('/', MW.validarUsuarioMW([3,4], true), rutaProtegida);
```


### API OAuth

```javascript
const oauthRouter = require('mbcj-oauth-sv');

//Al declarar la ruta del OAuth se debe llamar a la función enviando el modelo de Usuario de sequelize
router.use('/oauth', oauthRouter(Usuario));
```


### Script para obtener clave publica OAuth

```javascript
const {obtenerClavePublica} = require('mbcj-oauth-sv');

//Estas variables debrían obtenerse de variables del entorno, del .env
//La ruta donde va a guardarse el archivo, debe ser una ruta absoluta.
obtenerClavePublica(URL_oauth, ruta_directorio, nombre_archivo);
```
## Variables de entorno

Para ejecutar la librería se necesitan las variables del .env 

### Middlware

`TOKEN_ADMIN` 

`OAUTH_SECRET` 

`OAUTH_CLAVE_DIR` 

`OAUTH_CLAVE_FILE`

### API OAuth

`OAUTH_URL` 

`OAUTH_ID` 

`OAUTH_SECRET` 

`OAUTH_VALIDADO` 

`OAUTH_REEMPLAZAR_NOMBRE`

### Script para obtener clave publica OAuth

`OAUTH_CLAVE_URL` 

`OAUTH_CLAVE_DIR`

`OAUTH_CLAVE_FILE`