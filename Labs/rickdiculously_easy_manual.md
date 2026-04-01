# Manual Técnico: VulnHub — Máquina Rickdiculously Easy
### Reconocimiento, Enumeración de Servicios, Explotación Web, Transferencia de Ficheros y Escalada de Privilegios en Entornos Linux

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Preparación del Entorno de Laboratorio](#2-preparación-del-entorno-de-laboratorio)
   - 2.1 [Importación de la Máquina Virtual](#21-importación-de-la-máquina-virtual)
   - 2.2 [Configuración de Red NAT en VirtualBox](#22-configuración-de-red-nat-en-virtualbox)
3. [Reconocimiento y Enumeración](#3-reconocimiento-y-enumeración)
   - 3.1 [Descubrimiento de Hosts con NetDiscover](#31-descubrimiento-de-hosts-con-netdiscover)
   - 3.2 [Escaneo de Puertos con Nmap](#32-escaneo-de-puertos-con-nmap)
   - 3.3 [Escaneo Exhaustivo de Puertos](#33-escaneo-exhaustivo-de-puertos)
4. [Análisis del Servicio FTP — Puerto 21](#4-análisis-del-servicio-ftp--puerto-21)
   - 4.1 [Concepto Teórico: FTP y Anonymous Login](#41-concepto-teórico-ftp-y-anonymous-login)
   - 4.2 [Acceso con Usuario Anónimo](#42-acceso-con-usuario-anónimo)
5. [Análisis de la Aplicación Web — Puertos 80 y 9090](#5-análisis-de-la-aplicación-web--puertos-80-y-9090)
   - 5.1 [Enumeración de Directorios con Dirsearch](#51-enumeración-de-directorios-con-dirsearch)
   - 5.2 [Inspección del Archivo robots.txt](#52-inspección-del-archivo-robotstxt)
   - 5.3 [Análisis del Directorio /passwords](#53-análisis-del-directorio-passwords)
   - 5.4 [Inspección del Código Fuente HTML](#54-inspección-del-código-fuente-html)
6. [Vulnerabilidad: Command Injection](#6-vulnerabilidad-command-injection)
   - 6.1 [Concepto Teórico](#61-concepto-teórico)
   - 6.2 [Concatenación de Comandos](#62-concatenación-de-comandos)
   - 6.3 [Extracción de Usuarios del Sistema](#63-extracción-de-usuarios-del-sistema)
7. [Acceso Remoto con SSH — Puerto 22222](#7-acceso-remoto-con-ssh--puerto-22222)
   - 7.1 [Concepto Teórico: SSH en CTF](#71-concepto-teórico-ssh-en-ctf)
   - 7.2 [Conexión con Credenciales Obtenidas](#72-conexión-con-credenciales-obtenidas)
8. [Transferencia de Ficheros mediante Servidor HTTP con Python](#8-transferencia-de-ficheros-mediante-servidor-http-con-python)
   - 8.1 [Concepto Teórico: Servidor HTTP con Python](#81-concepto-teórico-servidor-http-con-python)
   - 8.2 [Montaje del Servidor en la Máquina Comprometida](#82-montaje-del-servidor-en-la-máquina-comprometida)
   - 8.3 [Descarga de Ficheros desde la Máquina Atacante](#83-descarga-de-ficheros-desde-la-máquina-atacante)
   - 8.4 [Uso de SCP como Alternativa](#84-uso-de-scp-como-alternativa)
9. [Análisis de Ficheros Extraídos](#9-análisis-de-ficheros-extraídos)
   - 9.1 [Esteganografía: Extracción de Datos con Strings](#91-esteganografía-extracción-de-datos-con-strings)
   - 9.2 [Análisis del Fichero ZIP con Contraseña](#92-análisis-del-fichero-zip-con-contraseña)
   - 9.3 [Análisis del Ejecutable en la Carpeta de Rick Sánchez](#93-análisis-del-ejecutable-en-la-carpeta-de-rick-sánchez)
10. [Gestión de Permisos y Movimiento Lateral](#10-gestión-de-permisos-y-movimiento-lateral)
    - 10.1 [Concepto Teórico: Permisos en Linux](#101-concepto-teórico-permisos-en-linux)
    - 10.2 [Copia de Fichero para Evadir Restricciones de Ejecución](#102-copia-de-fichero-para-evadir-restricciones-de-ejecución)
11. [Escalada de Privilegios a Root](#11-escalada-de-privilegios-a-root)
    - 11.1 [Concepto Teórico: Movimiento Lateral vs. Escalada Vertical](#111-concepto-teórico-movimiento-lateral-vs-escalada-vertical)
    - 11.2 [Fuerza Bruta con Hydra sobre SSH](#112-fuerza-bruta-con-hydra-sobre-ssh)
    - 11.3 [Generación de Diccionario Personalizado](#113-generación-de-diccionario-personalizado)
    - 11.4 [Escalada con sudo -l](#114-escalada-con-sudo--l)
12. [Captura de Flags](#12-captura-de-flags)
13. [Resumen de Puntos Clave](#13-resumen-de-puntos-clave)
14. [Inventario Final de Herramientas](#14-inventario-final-de-herramientas)

---

<div style="page-break-after: always;"></div>

## 1. Introducción y Contexto

La máquina **Rickdiculously Easy** es un entorno de práctica de nivel introductorio disponible en plataformas como VulnHub. Está basada en **Linux** y estructurada como un CTF (Capture The Flag) en el que el objetivo es obtener múltiples flags acumulando puntos, a la vez que se avanza desde el reconocimiento inicial hasta la escalada completa de privilegios.

A diferencia de máquinas de mayor dificultad, este entorno está diseñado para que el alumno interiorice la metodología básica de una auditoría interna: descubrimiento de red, enumeración de servicios, análisis de aplicaciones web, explotación de misconfiguraciones y movimiento dentro del sistema comprometido.

Las técnicas y vulnerabilidades trabajadas en esta máquina son:

- **Anonymous FTP Login:** acceso a recursos expuestos por mala configuración del servicio FTP.
- **Enumeración de directorios web:** descubrimiento de rutas ocultas mediante fuerza bruta con diccionario.
- **Command Injection:** ejecución de comandos arbitrarios en el servidor a través de un parámetro web no sanitizado.
- **Transferencia de ficheros vía HTTP (Python) y SCP:** extracción de ficheros desde la máquina comprometida.
- **Esteganografía básica:** extracción de información oculta en imágenes mediante la utilidad `strings`.
- **Explotación de permisos Linux:** copia de ejecutables entre directorios para evadir restricciones.
- **Escalada de privilegios con sudo:** uso de `sudo -l` para identificar comandos ejecutables como root.

El flujo de ataque sigue la metodología estándar: reconocimiento → enumeración → explotación → post-explotación → escalada de privilegios → captura de flags.

---

## 2. Preparación del Entorno de Laboratorio

### 2.1 Importación de la Máquina Virtual

La máquina se distribuye en formato `.ova` o `.zip`. Una vez descargada en la máquina anfitrión (no en Kali Linux), se descomprime y se importa directamente en VirtualBox mediante doble clic sobre el fichero `.ova`, o bien desde el menú: **Archivo → Importar servicio virtualizado**.

> **Nota:** El fichero de definición de máquina virtual (`.ova` o `.vbox`) puede abrirse directamente desde el explorador de archivos. VirtualBox reconoce el formato y lanza el asistente de importación de forma automática.

---

### 2.2 Configuración de Red NAT en VirtualBox

Para que la máquina atacante (Kali Linux) y la máquina víctima tengan visibilidad mutua, ambas deben estar conectadas a la **misma red NAT**. El modo NAT estándar de VirtualBox no permite la comunicación entre máquinas virtuales; es necesario crear una red NAT personalizada.

**Procedimiento de creación de red NAT en VirtualBox:**

1. Navegar a: **Archivo → Herramientas → Red → Redes NAT → Crear**.
2. Asignar un nombre identificativo a la red (por ejemplo: `parque_de_juegos`).
3. Activar el servidor **DHCP** para asignación automática de direcciones IP.
4. Confirmar que el prefijo de red asignado es `10.0.2.0/24`.
5. Aplicar los cambios.

**Asignación de la red NAT a cada máquina virtual:**

Para cada máquina (atacante y víctima): **Configuración → Red → Adaptador 1 → Conectado a: Red NAT → Seleccionar la red creada**.

> **Importante:** Ambas máquinas deben estar apagadas antes de aplicar cambios de red en VirtualBox para garantizar que la configuración se aplique correctamente.

| Elemento | Descripción |
|----------|-------------|
| **Red NAT** | Tipo de red de VirtualBox que permite comunicación entre máquinas virtuales dentro del mismo segmento. |
| **DHCP** | Protocolo de asignación automática de direcciones IP. Elimina la necesidad de configuración manual. |
| **Prefijo `10.0.2.0/24`** | Rango de red que abarca las direcciones `10.0.2.1` a `10.0.2.254`. |

**Resumen de puntos clave — Sección 2:**
- La máquina víctima debe descargarse e importarse en la máquina anfitrión, no dentro de Kali Linux.
- El modo **Red NAT** (no confundir con NAT estándar) es el requerido para que dos máquinas virtuales se comuniquen entre sí.
- Activar DHCP evita errores de configuración manual de IP.

---

## 3. Reconocimiento y Enumeración

### 3.1 Descubrimiento de Hosts con NetDiscover

El primer paso en una auditoría interna es identificar los equipos presentes en el mismo rango de red. Para ello se utiliza **NetDiscover**, herramienta que opera enviando paquetes ARP al segmento de red especificado.

```bash
sudo netdiscover -r 10.0.2.0/24
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `sudo` | Ejecuta el comando con privilegios de root, requeridos para enviar paquetes ARP. |
| `netdiscover` | Herramienta de descubrimiento de hosts mediante protocolo ARP. |
| `-r` | Especifica el rango de red a escanear en notación CIDR. |
| `10.0.2.0/24` | Rango de red NAT configurado. Abarca 254 direcciones utilizables. |

> **Nota sobre entornos cloud:** NetDiscover no funciona en entornos como Amazon Web Services (AWS) porque el protocolo ARP se encuentra desactivado por defecto en estas infraestructuras. En dichos entornos, el descubrimiento de hosts debe realizarse directamente con Nmap.

**Interpretación de la salida:**

NetDiscover muestra una tabla con las IPs detectadas, sus direcciones MAC y el fabricante asociado. Para identificar la máquina víctima entre los resultados, se compara con la IP propia (obtenida con `ifconfig`) y se descarta la dirección del gateway de red.

```bash
ifconfig
```

**Resumen de puntos clave — Sección 3.1:**
- NetDiscover opera a nivel de capa 2 (ARP), por lo que solo detecta equipos en el mismo segmento de red local.
- Ejecutar siempre `ifconfig` previamente para conocer la IP propia y el rango al que pertenece.
- En auditorías reales, es habitual encontrar entre 50 y 80 dispositivos por rango de red `/24`.

---

### 3.2 Escaneo de Puertos con Nmap

Una vez identificada la IP de la máquina víctima, se realiza un escaneo de puertos para obtener información sobre los servicios activos y sus versiones.

```bash
nmap -sCV <IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `-sC` | Ejecuta los scripts NSE (Nmap Scripting Engine) por defecto. Proporciona información adicional sobre cada servicio. |
| `-sV` | Detecta la versión de cada servicio en ejecución. Permite identificar versiones potencialmente vulnerables. |
| `<IP_OBJETIVO>` | Dirección IP del sistema objetivo identificada con NetDiscover. |

> **Nota metodológica:** En entornos de CTF, el escaneo estándar (`-sCV`) sobre los 1000 puertos más comunes ofrece una relación eficacia/tiempo óptima. El escaneo sobre todos los puertos (`-p-`) se reserva para cuando el escaneo inicial no produce resultados suficientes.

**Puertos identificados en el escaneo inicial:**

| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 21 | FTP | File Transfer Protocol. Presenta `Anonymous login allowed`. |
| 22 | SSH | Secure Shell. Acceso remoto cifrado. Reservado para uso posterior. |
| 80 | HTTP | Servidor web Apache. Aplicación web principal. |
| 9090 | HTTP | Puerto web no estándar. Suele corresponder a paneles de administración o aplicaciones secundarias. |

> **Buena práctica:** Cualquier servicio HTTP en un puerto distinto del 80 debe investigarse con prioridad, ya que frecuentemente corresponde a interfaces de administración, paneles de control o aplicaciones con menor nivel de hardening.

**Resumen de puntos clave — Sección 3.2:**
- El flag `-sCV` combina detección de versiones y ejecución de scripts en un único comando.
- La presencia de `Anonymous login allowed` en FTP es una misconfiguración que debe explotarse de inmediato.
- El puerto 22 (SSH) no debe ser objetivo de fuerza bruta en primera instancia; su explotación se aborda una vez obtenidas credenciales válidas por otros vectores.

---

### 3.3 Escaneo Exhaustivo de Puertos

Cuando el escaneo estándar no proporciona vectores de ataque suficientes, se realiza un escaneo sobre la totalidad de los 65535 puertos TCP para descubrir servicios en puertos no estándar.

```bash
nmap -p- <IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `-p-` | Escanea todos los puertos TCP del rango 1 al 65535. |

Una vez obtenida la lista de puertos adicionales, se lanza un escaneo dirigido únicamente sobre los puertos nuevos descubiertos:

```bash
nmap -sCV -p <PUERTOS_NUEVOS> <IP_OBJETIVO>
```

**Puertos adicionales identificados:**

| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 22222 | SSH | Puerto SSH alternativo. El puerto 22 estándar puede actuar como señuelo. |
| 60000 | Unknown | Puerto con mensaje de bienvenida. Requiere análisis específico. |

> **Nota:** La presencia de un servicio SSH en un puerto no estándar como el 22222 es un indicador de que el puerto 22 estándar puede estar configurado como señuelo (bait) para dificultar el acceso por fuerza bruta.

**Resumen de puntos clave — Sección 3.3:**
- El escaneo `-p-` es costoso en tiempo; utilizarlo únicamente cuando el escaneo estándar no produce resultados suficientes.
- Puertos SSH en rangos no estándar indican configuración deliberada para dificultar el acceso no autorizado por el puerto convencional.
- Siempre lanzar un escaneo `-sCV` dirigido sobre los puertos nuevos antes de interactuar con ellos.

---

## 4. Análisis del Servicio FTP — Puerto 21

### 4.1 Concepto Teórico: FTP y Anonymous Login

**FTP (File Transfer Protocol)** es un protocolo de red utilizado para la transferencia de ficheros entre sistemas. Opera sobre los puertos 20 (datos) y 21 (control).

La configuración **Anonymous Login** permite que cualquier usuario se autentique en el servidor FTP utilizando el nombre de usuario `anonymous` o `ftp`, sin necesidad de contraseña válida. Esta misconfiguración es frecuente en servidores web mal configurados y representa un vector de ataque de alta prioridad, ya que puede exponer ficheros sensibles o proporcionar acceso de escritura al directorio raíz del servidor web.

**Vectores de ataque habituales sobre FTP:**

| Vector | Descripción |
|--------|-------------|
| **Anonymous Login** | Acceso sin credenciales por mala configuración. |
| **Fuerza bruta** | Ataque de diccionario sobre credenciales del servicio. |
| **Explotación de versión vulnerable** | Uso de exploits públicos contra versiones desactualizadas del servidor FTP. |

---

### 4.2 Acceso con Usuario Anónimo

```bash
ftp -A <IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `ftp` | Cliente FTP de línea de comandos incluido en Kali Linux. |
| `-A` | Activa el modo de autenticación anónima (Anonymous Login). |
| `<IP_OBJETIVO>` | Dirección IP del servidor FTP objetivo. |

**Comandos de navegación dentro del cliente FTP:**

| Comando | Descripción |
|---------|-------------|
| `ls` | Lista los ficheros y directorios en el directorio actual del servidor. |
| `cd <directorio>` | Cambia al directorio especificado dentro del servidor FTP. |
| `get <fichero>` | Descarga el fichero especificado al directorio de trabajo local. |
| `exit` | Cierra la conexión FTP y sale del cliente. |

**Contenido encontrado:**

Al listar el directorio raíz del servidor FTP se identifican los siguientes elementos:

- `FLAG.txt`: fichero que contiene una flag (10 puntos).
- `/pub/`: directorio vacío. Se registra su existencia para investigación posterior, dado que podría ser accesible desde la aplicación web.

```bash
# Dentro del cliente FTP:
ls
get FLAG.txt
cd pub
ls
exit
```

Una vez descargado el fichero, se visualiza su contenido desde la terminal local:

```bash
cat FLAG.txt
```

**Resumen de puntos clave — Sección 4:**
- La presencia de `Anonymous login allowed` en el escaneo Nmap debe explotarse de forma inmediata.
- Cualquier fichero accesible en el servidor FTP debe descargarse localmente antes de continuar la auditoría.
- El directorio `/pub` vacío debe anotarse: su posible accesibilidad vía web lo convierte en un potencial destino para subida de ficheros maliciosos.

---

## 5. Análisis de la Aplicación Web — Puertos 80 y 9090

### 5.1 Enumeración de Directorios con Dirsearch

Ante cualquier servicio web, el primer paso de la auditoría es la **enumeración de directorios**: proceso de descubrimiento de rutas y ficheros ocultos mediante fuerza bruta con diccionario.

```bash
dirsearch -u http://<IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `dirsearch` | Herramienta de enumeración de directorios y ficheros web. Utiliza un diccionario integrado por defecto. |
| `-u` | Especifica la URL objetivo sobre la que realizar la enumeración. |

> **Nota sobre diccionarios:** Si no se especifica el flag `-w`, Dirsearch utiliza su diccionario interno por defecto. Para auditorías más completas, se recomienda especificar diccionarios de la suite **SecLists** mediante `-w /ruta/al/diccionario.txt`. Es posible que un directorio no aparezca con un diccionario y sí con otro.

**Instalación de SecLists:**

```bash
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/wordlists/SecLists
```

| Elemento | Descripción |
|----------|-------------|
| `git clone` | Descarga el repositorio remoto en el directorio especificado. |
| `danielmiessler/SecLists` | Suite de diccionarios ampliamente utilizada en auditorías de seguridad. |

**Interpretación de resultados:**

Dirsearch muestra el código de respuesta HTTP junto a cada ruta probada. Los códigos `200` indican que el recurso existe y es accesible.

| Código HTTP | Significado |
|-------------|-------------|
| `200` | Recurso encontrado y accesible. |
| `301` / `302` | Redirección. El recurso existe pero apunta a otra ubicación. |
| `403` | Acceso prohibido. El recurso existe pero no es accesible sin autenticación. |
| `404` | Recurso no encontrado. |

**Directorios y ficheros identificados:**

- `/passwords/`: directorio con listado de ficheros accesibles.
- `robots.txt`: fichero de directivas para crawlers de motores de búsqueda.

**Resumen de puntos clave — Sección 5.1:**
- La enumeración de directorios es un paso obligatorio ante cualquier servicio web identificado.
- El uso de múltiples diccionarios puede revelar rutas que un único diccionario no descubriría.
- Los códigos `200` y `301` en la salida de Dirsearch indican recursos que deben investigarse.

---

### 5.2 Inspección del Archivo robots.txt

El fichero `robots.txt` es un estándar utilizado por los propietarios de sitios web para indicar a los crawlers de los motores de búsqueda qué rutas no deben ser indexadas. Para un auditor de seguridad, este fichero es especialmente relevante porque habitualmente revela rutas que el administrador no desea que sean públicas.

**Acceso al fichero:**

```
http://<IP_OBJETIVO>/robots.txt
```

**Directiva relevante encontrada:**

La directiva `Disallow` seguida de una ruta indica que el administrador no quiere que esa ruta aparezca en buscadores, lo que implica frecuentemente que contiene información sensible o funcionalidades no previstas para uso público.

> **Regla práctica:** Toda ruta listada en `robots.txt` con `Disallow` debe ser visitada durante la auditoría, ya que su presencia indica que el administrador la considera relevante y quiere ocultarla de la indexación pública.

**Resumen de puntos clave — Sección 5.2:**
- `robots.txt` no es una medida de seguridad; únicamente indica a los crawlers qué no indexar. No impide el acceso a los recursos.
- Las rutas listadas con `Disallow` son candidatas prioritarias de investigación en auditorías web.

---

### 5.3 Análisis del Directorio /passwords

El directorio `/passwords` identificado durante la enumeración contiene un fichero HTML accesible directamente desde el navegador.

**Acceso al directorio:**

```
http://<IP_OBJETIVO>/passwords/
```

Al acceder al listado del directorio y abrir el fichero HTML disponible, se obtiene la segunda flag (10 puntos adicionales).

**Resumen de puntos clave — Sección 5.3:**
- Los directorios web son equivalentes a carpetas del sistema de ficheros del servidor expuestas públicamente.
- La accesibilidad a listados de directorios (`Directory Listing`) es una misconfiguración frecuente que expone información sensible.

---

### 5.4 Inspección del Código Fuente HTML

Los desarrolladores frecuentemente dejan comentarios en el código fuente HTML que pueden contener información sensible como credenciales, rutas internas o instrucciones de configuración.

**Procedimiento:**

En el navegador, sobre cualquier página web: **clic derecho → Ver código fuente de la página** (o `Ctrl+U`).

**Hallazgo:**

En el código fuente del fichero HTML del directorio `/passwords/` se identifica un comentario HTML con la siguiente estructura:

```html
<!-- Contraseña: Winter -->
```

Este tipo de credencial embebida en comentarios de código es un hallazgo habitual en auditorías de aplicaciones web y representa una misconfiguración grave.

**Resumen de puntos clave — Sección 5.4:**
- La inspección del código fuente debe realizarse sistemáticamente en cada página accesible.
- Las credenciales encontradas deben anotarse junto al contexto en que se hallaron para su uso posterior.
- La contraseña `Winter` se prueba en los servicios de autenticación disponibles (SSH) con cada usuario identificado.

---

## 6. Vulnerabilidad: Command Injection

### 6.1 Concepto Teórico

**Command Injection** (inyección de comandos) es una vulnerabilidad que se produce cuando una aplicación web pasa parámetros controlados por el usuario a una función del sistema operativo sin sanitizarlos correctamente. El servidor ejecuta el comando legítimo más el contenido malicioso inyectado por el atacante.

En el puerto 9090 se identifica una funcionalidad de tipo "traceroute" que acepta una dirección IP como entrada y ejecuta el comando `traceroute <IP>` en el servidor. Si el parámetro no está sanitizado, es posible concatenar comandos adicionales.

**Diferencia clave respecto a la ejecución local:**

El comando se ejecuta en la máquina víctima (servidor), no en la máquina atacante. El resultado se muestra en el navegador del atacante, lo que permite leer el sistema de ficheros del servidor de forma interactiva.

---

### 6.2 Concatenación de Comandos

En sistemas Linux, existen varios operadores para encadenar comandos en una misma línea:

| Operador | Comportamiento |
|----------|----------------|
| `;` | Ejecuta el segundo comando independientemente del resultado del primero. |
| `&&` | Ejecuta el segundo comando únicamente si el primero tuvo éxito. |
| `\|` (pipe) | Utiliza la salida del primer comando como entrada del segundo. |

**Sintaxis de inyección mediante punto y coma:**

```
<IP_CUALQUIERA>; <COMANDO_ADICIONAL>
```

**Ejemplo de prueba de concepto:**

```
127.0.0.1; pwd
```

Si la aplicación es vulnerable, la respuesta mostrará tanto la salida del `traceroute` como el directorio de trabajo actual del servidor.

**Resumen de puntos clave — Sección 6.2:**
- El operador `;` es el más seguro para inyección de comandos, ya que no depende del resultado del comando anterior.
- El pipe (`|`) solo debe usarse cuando se quiere procesar la salida del comando previo.
- Una vez confirmada la vulnerabilidad, el atacante puede ejecutar cualquier comando disponible en el servidor.

---

### 6.3 Extracción de Usuarios del Sistema

Con la vulnerabilidad de Command Injection confirmada, se extrae el fichero `/etc/passwd` del servidor, que contiene la lista de usuarios del sistema Linux.

**Payload de inyección:**

```
127.0.0.1; cat /etc/passwd
```

> **Nota:** Si el comando `cat` está modificado o bloqueado en el servidor objetivo, pueden utilizarse alternativas como `head`, `tail` o `strings`.

```bash
# Alternativa si cat no está disponible:
127.0.0.1; tail -n 30 /etc/passwd
127.0.0.1; head -n 50 /etc/passwd
```

**Estructura del fichero `/etc/passwd`:**

Cada línea sigue el formato:

```
usuario:x:UID:GID:comentario:directorio_home:shell
```

| Campo | Descripción |
|-------|-------------|
| `usuario` | Nombre de usuario en el sistema. |
| `x` | Indica que la contraseña está almacenada en `/etc/shadow`. |
| `UID` | Identificador numérico de usuario. |
| `GID` | Identificador numérico de grupo. |
| `directorio_home` | Ruta al directorio personal del usuario. |
| `shell` | Intérprete de comandos asignado al usuario. |

**Identificación de usuarios con acceso interactivo:**

Los usuarios con shell `/bin/bash` tienen acceso interactivo al sistema y, por ende, pueden iniciar sesión por SSH. Los usuarios con `/sbin/nologin` o `/bin/false` son cuentas de servicio sin acceso a shell.

**Usuarios identificados con `/bin/bash`:**

- `root`
- `RickSanchez`
- `Morty`
- `Summer`

> **Importante:** Respetar siempre las mayúsculas en los nombres de usuario de Linux, ya que el sistema es case-sensitive.

**Resumen de puntos clave — Sección 6.3:**
- El fichero `/etc/passwd` debe consultarse en toda auditoría sobre sistemas Linux para obtener la lista de usuarios válidos.
- Solo los usuarios con shell `/bin/bash` son candidatos a acceso por SSH.
- La combinación de usuario + contraseña obtenida (`Summer` / `Winter`) debe probarse sobre el servicio SSH disponible.

---

## 7. Acceso Remoto con SSH — Puerto 22222

### 7.1 Concepto Teórico: SSH en CTF

**SSH (Secure Shell)** es el protocolo estándar de acceso remoto cifrado en sistemas Linux. Opera habitualmente sobre el puerto 22, aunque puede configurarse en puertos alternativos.

En entornos CTF, el puerto 22 frecuentemente actúa como señuelo. El acceso SSH real suele estar disponible en un puerto alternativo (en este caso, el 22222). Intentar fuerza bruta sobre el puerto 22 sin credenciales previas es ineficiente y genera ruido innecesario.

**Metodología recomendada:**

1. Obtener credenciales válidas a través de otros vectores (FTP, web, Command Injection).
2. Utilizar las credenciales para establecer una sesión SSH legítima.
3. Reservar la fuerza bruta SSH para fases avanzadas, únicamente cuando no hay otras opciones.

---

### 7.2 Conexión con Credenciales Obtenidas

```bash
ssh Summer@<IP_OBJETIVO> -p 22222
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `ssh` | Cliente SSH de línea de comandos. |
| `Summer@<IP_OBJETIVO>` | Usuario e IP del servidor al que se conecta. |
| `-p 22222` | Especifica el puerto de conexión. En SSH, a diferencia de Nmap, el flag `-p` requiere un espacio antes del número de puerto. |

**Contraseña:** `Winter`

Una vez establecida la sesión, el prompt del sistema confirma la identidad activa:

```
summer@localhost:~$
```

**Resumen de puntos clave — Sección 7:**
- El flag `-p` en el cliente SSH requiere el número de puerto separado por espacio (diferente a la sintaxis de Nmap).
- Linux es case-sensitive: el usuario `Summer` es diferente de `summer`.
- Verificar siempre el prompt tras la conexión para confirmar el usuario y el hostname de la máquina comprometida.

---

## 8. Transferencia de Ficheros mediante Servidor HTTP con Python

### 8.1 Concepto Teórico: Servidor HTTP con Python

Python 3 incluye un módulo estándar (`http.server`) que permite levantar un servidor web en cualquier directorio del sistema de forma inmediata, sin instalación adicional. Este servidor expone el contenido del directorio en el que se ejecuta a través del protocolo HTTP.

**Principio de funcionamiento:**

- El servidor se levanta en la máquina comprometida (víctima).
- La máquina atacante realiza peticiones HTTP al servidor para descargar ficheros.
- Esta técnica evita la necesidad de herramientas de transferencia de ficheros adicionales.

**Relación cliente-servidor:**

| Rol | Máquina | Acción |
|-----|---------|--------|
| Servidor | Víctima (comprometida) | Expone una carpeta vía HTTP. |
| Cliente | Atacante (Kali Linux) | Descarga ficheros mediante `wget`. |

---

### 8.2 Montaje del Servidor en la Máquina Comprometida

Desde la sesión SSH activa en la máquina víctima, navegar al directorio que contiene los ficheros a exfiltrar y levantar el servidor:

```bash
cd /home/Morty
python3 -m http.server 8080
```

**Descripción de los parámetros:**

| Elemento | Descripción |
|----------|-------------|
| `python3` | Intérprete de Python 3, disponible en la mayoría de distribuciones Linux. |
| `-m` | Indica que se va a ejecutar un módulo de la biblioteca estándar de Python. |
| `http.server` | Módulo que levanta un servidor HTTP en el directorio actual. |
| `8080` | Puerto en el que se expone el servidor. Se recomienda usar `8080` para evitar conflictos con servicios web activos en los puertos 80 y 443. |

> **Selección del directorio:** El servidor HTTP expone el directorio desde el que se ejecuta el comando. Navegar al directorio que contiene los ficheros objetivo antes de ejecutar el servidor minimiza la ruta requerida en las peticiones de descarga.

> **Puerto recomendado:** Evitar los puertos 80 y 443 para no generar conflictos con servicios web ya activos. El puerto `8080` es una alternativa habitual. Verificar en la salida de Nmap que el puerto seleccionado no esté ya en uso.

La salida del servidor confirma que está en escucha:

```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

La dirección `0.0.0.0` indica que el servidor acepta conexiones desde cualquier IP de la red.

---

### 8.3 Descarga de Ficheros desde la Máquina Atacante

Abrir una nueva terminal en Kali Linux (el servidor HTTP ocupa la terminal SSH actual) y descargar los ficheros:

```bash
wget http://<IP_OBJETIVO>:8080/SafePasswd.jpg
wget http://<IP_OBJETIVO>:8080/journal.txt.zip
```

**Descripción de los parámetros:**

| Elemento | Descripción |
|----------|-------------|
| `wget` | Herramienta de descarga de ficheros desde URLs HTTP/HTTPS. Guarda el fichero en el directorio de trabajo actual. |
| `http://<IP_OBJETIVO>:8080/` | URL base del servidor HTTP levantado en la máquina víctima. |
| `SafePasswd.jpg` / `journal.txt.zip` | Nombre del fichero a descargar. |

> **Diferencia entre `wget` y `curl`:** `wget` descarga el fichero y lo guarda localmente. `curl` muestra el contenido por pantalla sin guardarlo (a menos que se especifique `-o`).

Una vez descargados los ficheros, detener el servidor HTTP en la terminal SSH con `Ctrl+C`.

---

### 8.4 Uso de SCP como Alternativa

**SCP (Secure Copy Protocol)** es una utilidad de transferencia de ficheros que opera sobre SSH. Permite copiar ficheros entre máquinas aprovechando una conexión SSH existente.

```bash
scp -P 22222 Summer@<IP_OBJETIVO>:/home/Morty/journal.txt.zip ./
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `scp` | Herramienta de copia segura mediante SSH. |
| `-P 22222` | Puerto SSH (en SCP, la P es mayúscula, a diferencia del cliente SSH). |
| `Summer@<IP_OBJETIVO>` | Usuario y host remoto. |
| `:/home/Morty/journal.txt.zip` | Ruta al fichero remoto que se desea copiar (precedida de `:`). |
| `./` | Destino local: directorio de trabajo actual. |

> **Nota:** La transferencia debe ejecutarse desde el directorio del usuario con permisos de escritura (por ejemplo, `/home/Summer`). Intentar la transferencia desde un directorio sin permisos de escritura generará un error de permisos.

**Resumen de puntos clave — Sección 8:**
- El servidor HTTP con Python es la técnica más rápida para exfiltrar ficheros desde una máquina comprometida.
- Seleccionar el puerto cuidadosamente para evitar conflictos con servicios ya activos.
- `wget` descarga y guarda el fichero; `curl` muestra el contenido en pantalla.
- SCP es una alternativa válida cuando la conexión SSH está establecida.

---

## 9. Análisis de Ficheros Extraídos

### 9.1 Esteganografía: Extracción de Datos con Strings

La **esteganografía** es la técnica de ocultar información dentro de otro fichero (imagen, audio, vídeo) de forma que no sea perceptible a simple vista. En entornos CTF, es habitual encontrar credenciales o flags embebidas en imágenes mediante sustitución de píxeles o inserción de cadenas de texto en los metadatos del fichero.

**Análisis de metadatos con ExifTool:**

```bash
exiftool SafePasswd.jpg
```

| Elemento | Descripción |
|----------|-------------|
| `exiftool` | Herramienta de lectura y escritura de metadatos EXIF en imágenes y otros ficheros. |
| `SafePasswd.jpg` | Fichero de imagen a analizar. |

**Extracción de cadenas de texto con Strings:**

La utilidad `strings` extrae todas las cadenas de texto legible embebidas en un fichero binario (imagen, ejecutable, etc.), independientemente de su tipo.

```bash
strings SafePasswd.jpg
```

| Elemento | Descripción |
|----------|-------------|
| `strings` | Extrae secuencias de caracteres imprimibles de longitud mínima de un fichero binario. |

**Resultado:** En la salida de `strings` se identifica una referencia al fichero `journal.txt.zip` junto con su contraseña: `Morty`.

> **Principio de la esteganografía por sustitución de píxeles:** Una imagen es un fichero de texto que asigna códigos de color a coordenadas (píxeles). Al reemplazar el código de color de un píxel por datos de texto, el visor de imágenes no puede interpretar ese píxel correctamente y lo renderiza como un punto negro o muerto. La información oculta puede recuperarse con `strings` porque sigue siendo texto legible dentro del fichero binario.

**Resumen de puntos clave — Sección 9.1:**
- La esteganografía es una técnica frecuente en CTF pero prácticamente obsoleta en entornos reales.
- `strings` permite extraer información de cualquier fichero binario sin necesidad de herramientas especializadas.
- `exiftool` proporciona metadatos estructurados (dimensiones, modelo de cámara, coordenadas GPS, etc.) que pueden contener información relevante.

---

### 9.2 Análisis del Fichero ZIP con Contraseña

Con la contraseña obtenida mediante `strings`, se extrae el contenido del archivo comprimido:

```bash
unzip journal.txt.zip
```

Cuando se solicite la contraseña, introducir: `Morty`

El fichero `journal.txt` extraído contiene una flag adicional y una pista sobre la contraseña de **Rick Sánchez**: la contraseña está compuesta por una letra mayúscula, un dígito y una palabra del nombre de su banda de música (*The Flesh Curtains*).

**Resumen de puntos clave — Sección 9.2:**
- Las contraseñas de ficheros ZIP pueden obtenerse mediante esteganografía, análisis de código fuente o fuerza bruta.
- Las pistas en ficheros de texto deben analizarse detenidamente; con frecuencia describen la estructura de la contraseña objetivo.

---

### 9.3 Análisis del Ejecutable en la Carpeta de Rick Sánchez

En el directorio `/home/RickSanchez/RICKS_SAFE/` existe un fichero ejecutable llamado `safe`. Este fichero pertenece al usuario `RickSanchez` y no puede ejecutarse directamente con el usuario `Summer` debido a los permisos de ejecución restringidos.

**Análisis del tipo de fichero:**

```bash
file safe
```

| Elemento | Descripción |
|----------|-------------|
| `file` | Determina el tipo de un fichero analizando su contenido (magic bytes), independientemente de su extensión. |

**Extracción de cadenas legibles:**

```bash
strings safe
```

La salida revela que el ejecutable requiere un argumento numérico para desbloquear su funcionalidad completa.

**Resumen de puntos clave — Sección 9.3:**
- `file` permite identificar el tipo real de un fichero sin depender de su extensión.
- `strings` aplicado sobre ejecutables puede revelar cadenas hardcodeadas como mensajes de error, rutas, argumentos esperados o credenciales.

---

## 10. Gestión de Permisos y Movimiento Lateral

### 10.1 Concepto Teórico: Permisos en Linux

En Linux, cada fichero y directorio tiene asociados tres conjuntos de permisos:

| Categoría | Descripción |
|-----------|-------------|
| **Owner** (propietario) | El usuario que posee el fichero. Tiene control total sobre los permisos. |
| **Group** (grupo) | Los usuarios que pertenecen al grupo asignado al fichero. |
| **Others** (otros) | Cualquier usuario del sistema que no sea el propietario ni miembro del grupo. |

Cada conjunto puede tener los permisos de **lectura** (`r`), **escritura** (`w`) y **ejecución** (`x`).

**Visualización de permisos:**

```bash
ls -la
```

Ejemplo de salida:
```
-rwxr--r-- 1 RickSanchez RickSanchez 8462 safe
```

En este ejemplo, `RickSanchez` (owner) tiene permisos `rwx` (lectura, escritura, ejecución), el grupo tiene `r--` (solo lectura) y otros tienen `r--` (solo lectura). El usuario `Summer` pertenece a la categoría "others" y solo puede leer el fichero, no ejecutarlo.

---

### 10.2 Copia de Fichero para Evadir Restricciones de Ejecución

Dado que `Summer` tiene permiso de **lectura** sobre el fichero `safe` y permiso de **escritura** en su propio directorio (`/home/Summer`), es posible copiar el fichero a un directorio propio y otorgarle permisos de ejecución como propietario de la copia.

```bash
cp /home/RickSanchez/RICKS_SAFE/safe /home/Summer/
cd /home/Summer
chmod +x safe
./safe <ARGUMENTO>
```

**Descripción de los comandos:**

| Comando | Descripción |
|---------|-------------|
| `cp <origen> <destino>` | Copia un fichero de una ruta a otra. El usuario debe tener permisos de lectura en el origen y escritura en el destino. |
| `chmod +x <fichero>` | Añade el permiso de ejecución al fichero. Solo el propietario puede modificar los permisos de un fichero. |
| `./safe` | Ejecuta el fichero `safe` del directorio actual. El argumento numérico desbloquea su funcionalidad. |

> **Principio:** Al copiar un fichero, la copia pertenece al usuario que realizó la copia. Por tanto, `Summer` es propietaria de la copia y puede modificar sus permisos de ejecución, independientemente de los permisos del fichero original.

**Argumento para el ejecutable `safe`:** La cadena numérica `131333` (obtenida del fichero `journal.txt`) desbloquea el ejecutable, que a su vez revela una flag y una pista sobre la contraseña de Rick Sánchez.

```bash
./safe 131333
```

**Resumen de puntos clave — Sección 10:**
- La comprensión del modelo de permisos Linux (owner/group/others) es fundamental para identificar vectores de escalada.
- Un fichero con permisos de lectura para "others" puede copiarse aunque no pueda ejecutarse directamente.
- El propietario de una copia puede asignar permisos de ejecución a la misma, eludiendo las restricciones del fichero original.

---

## 11. Escalada de Privilegios a Root

### 11.1 Concepto Teórico: Movimiento Lateral vs. Escalada Vertical

En post-explotación, existen dos tipos de movimiento dentro de un sistema comprometido:

| Tipo | Descripción |
|------|-------------|
| **Movimiento lateral** | Cambio de un usuario comprometido a otro usuario del mismo nivel de privilegios (por ejemplo, de `Summer` a `Morty` o a `RickSanchez`). |
| **Escalada vertical (de privilegios)** | Paso de un usuario estándar a un usuario con privilegios elevados, típicamente `root`. |

En CTF, el camino habitual es: usuario inicial (bajo privilegio) → movimiento lateral hacia un usuario con más acceso → escalada vertical a root.

---

### 11.2 Fuerza Bruta con Hydra sobre SSH

Con la pista obtenida del ejecutable `safe` (la contraseña de Rick contiene una mayúscula, un dígito y una palabra de la banda *The Flesh Curtains*), se construye un diccionario personalizado y se realiza un ataque de fuerza bruta sobre SSH.

```bash
hydra -l RickSanchez -P diccionario.txt ssh://<IP_OBJETIVO>:22222
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `hydra` | Herramienta de fuerza bruta para múltiples protocolos de autenticación. |
| `-l RickSanchez` | Especifica el nombre de usuario (login) sobre el que realizar el ataque. |
| `-P diccionario.txt` | Especifica el fichero de diccionario con las contraseñas a probar. |
| `ssh://<IP_OBJETIVO>:22222` | Protocolo, IP y puerto del servicio objetivo. |

> **Uso de threads:** El flag `-t <número>` permite especificar el número de hilos concurrentes para acelerar el ataque. Valores altos pueden generar detección o errores de conexión; el valor por defecto (16) es razonable para entornos de laboratorio.

**Resultado:** La contraseña identificada es `P7Curtains`.

---

### 11.3 Generación de Diccionario Personalizado

Cuando se conoce la estructura de la contraseña objetivo, es más eficiente generar un diccionario personalizado que utilizar uno genérico como `rockyou.txt`.

Las reglas de la contraseña de Rick Sánchez son:
- Una letra mayúscula (A-Z).
- Un dígito (0-9).
- Una de las tres palabras de la banda: `The`, `Flesh`, `Curtains`.

El diccionario puede generarse con herramientas como `crunch` o mediante un script en Bash o Python que enumere todas las combinaciones posibles:

```bash
# Ejemplo de estructura de generación (26 letras × 10 dígitos × 3 palabras = 780 combinaciones)
# Formato: <Mayúscula><Dígito><Palabra>
# Ejemplo: A0The, A0Flesh, A0Curtains, A1The, ...
```

> **Principio de mínimo esfuerzo:** La fuerza bruta debe ser siempre el último recurso. Sin embargo, cuando la estructura de la contraseña está acotada (780 combinaciones posibles), el tiempo de ataque es mínimo y está justificado.

---

### 11.4 Escalada con sudo -l

Una vez dentro de la sesión SSH como `RickSanchez`, el primer paso para la escalada de privilegios es verificar qué comandos puede ejecutar el usuario con privilegios de `sudo`.

```bash
sudo -l
```

| Elemento | Descripción |
|----------|-------------|
| `sudo` | Permite ejecutar comandos como otro usuario (habitualmente root). |
| `-l` | Lista todos los comandos que el usuario actual puede ejecutar con `sudo`. |

**Resultado:** `RickSanchez` tiene permiso para ejecutar **todos los comandos** como root (`ALL`).

Con este nivel de acceso, la escalada a root es directa:

```bash
sudo su
```

| Comando | Descripción |
|---------|-------------|
| `sudo su` | Ejecuta el comando `su` (cambio de usuario) con privilegios de root, iniciando una sesión como root sin necesidad de conocer la contraseña de root. |

Una vez como root, se accede al directorio `/root` y se obtiene la flag final:

```bash
cd /root
ls
tail -n 30 FLAG.txt
```

> **Nota:** En esta máquina, el comando `cat` está modificado para mostrar un gato ASCII en lugar del contenido del fichero. Utilizar `tail` o `head` como alternativa.

**Resumen de puntos clave — Sección 11:**
- `sudo -l` es el primer comando a ejecutar tras comprometer cualquier usuario en un sistema Linux.
- Un resultado `ALL` en `sudo -l` implica escalada de privilegios inmediata mediante `sudo su`.
- La fuerza bruta con Hydra sobre SSH es viable cuando la estructura de la contraseña está acotada y el número de combinaciones es manejable.

---

## 12. Captura de Flags

La máquina Rickdiculously Easy contiene un total de **130 puntos** distribuidos en múltiples flags:

| # | Flag | Ubicación | Puntos | Método de obtención |
|---|------|-----------|--------|---------------------|
| 1 | `FLAG.txt` | Raíz del servidor FTP | 10 | Anonymous FTP Login + `get` |
| 2 | `FLAG.txt` | `/passwords/` (web, puerto 80) | 10 | Enumeración de directorios + Directory Listing |
| 3 | Comentario HTML | Código fuente de `/passwords/*.html` | — | Inspección de código fuente (credencial: `Winter`) |
| 4 | Flag en puerto 9090 | `https://<IP>:9090` | 10 | Acceso directo al puerto web no estándar |
| 5 | `user.txt` | `/home/Summer/` | 10 | Sesión SSH como Summer |
| 6 | Flag en imagen | `SafePasswd.jpg` (metadatos/strings) | — | Esteganografía con `strings` |
| 7 | Flag en ZIP | `journal.txt` (dentro de `journal.txt.zip`) | 10 | Extracción del ZIP con contraseña obtenida vía esteganografía |
| 8 | Flag del ejecutable | Salida de `./safe 131333` | 10 | Ejecución del binario con argumento correcto |
| 9 | Flag raíz | `/root/FLAG.txt` | 30 | Escalada de privilegios a root |

> **Nota:** Las flags individuales suman el total de 130 puntos establecido por la máquina.

---

## 13. Resumen de Puntos Clave

**Reconocimiento y Enumeración:**
- La metodología básica de auditoría interna es: NetDiscover → Nmap estándar → Nmap exhaustivo (`-p-`) si es necesario.
- NetDiscover opera mediante ARP y no funciona en entornos cloud (AWS, Azure) donde ARP está desactivado.
- El escaneo `-p-` se reserva para cuando el escaneo estándar no produce vectores de ataque suficientes.

**Servicio FTP:**
- `Anonymous login allowed` en FTP es una misconfiguración crítica que debe explotarse de inmediato.
- Todo fichero encontrado en FTP debe descargarse localmente antes de continuar la auditoría.
- El directorio `/pub` vacío es un indicador potencial de vector de subida de ficheros al servidor web.

**Análisis Web:**
- La enumeración de directorios (`dirsearch`) es obligatoria ante cualquier servicio HTTP.
- `robots.txt` revela rutas que el administrador quiere ocultar de buscadores; todas deben investigarse.
- El código fuente HTML puede contener credenciales hardcodeadas en comentarios.
- Puertos HTTP no estándar (distinto de 80) merecen análisis prioritario.

**Command Injection:**
- Se produce cuando una aplicación web pasa parámetros del usuario a funciones del sistema sin sanitización.
- El operador `;` permite concatenar comandos independientes en Linux.
- `/etc/passwd` debe consultarse siempre que se tenga ejecución de comandos en un sistema Linux.

**Transferencia de Ficheros:**
- Python 3 con `http.server` es el método más rápido para exfiltrar ficheros desde una máquina comprometida.
- El puerto 8080 es una buena alternativa al 80/443 para servidores HTTP temporales.
- `wget` descarga ficheros localmente; `curl` muestra el contenido por pantalla.

**Esteganografía:**
- `strings` extrae cadenas legibles de cualquier fichero binario, incluyendo imágenes.
- `exiftool` proporciona metadatos estructurados que pueden contener información sensible.
- La esteganografía es una técnica exclusiva de CTF; no tiene aplicación práctica en auditorías reales modernas.

**Permisos y Escalada:**
- `sudo -l` es el primer comando a ejecutar tras comprometer cualquier usuario Linux.
- Copiar un fichero con permisos de lectura a un directorio propio permite asignarle permisos de ejecución como propietario.
- `sudo su` con permisos `ALL` proporciona acceso inmediato a root.

---

## 14. Inventario Final de Herramientas

| Herramienta / Utilidad | Tipo | Descripción | Instalación / Disponibilidad |
|------------------------|------|-------------|------------------------------|
| **VirtualBox** | Virtualización | Hipervisor de tipo 2 para ejecutar máquinas virtuales. Permite crear redes NAT internas entre VMs. | Descarga en `https://www.virtualbox.org` |
| **NetDiscover** | Descubrimiento de red | Herramienta de descubrimiento de hosts mediante peticiones ARP. Requiere privilegios de root. | Preinstalado en Kali Linux |
| **Nmap** | Escáner de red | Enumeración de puertos, servicios y versiones. Incluye motor de scripts NSE. | Preinstalado en Kali Linux |
| **FTP (cliente)** | Transferencia de ficheros | Cliente FTP de línea de comandos para conexión a servidores FTP. | Preinstalado en Kali Linux |
| **Dirsearch** | Enumeración web | Herramienta de enumeración de directorios y ficheros web mediante fuerza bruta con diccionario. | `pip install dirsearch` |
| **SecLists** | Diccionarios | Suite de diccionarios para fuerza bruta, fuzzing y enumeración web. | `git clone https://github.com/danielmiessler/SecLists` |
| **SSH (cliente)** | Acceso remoto | Cliente SSH para conexión remota cifrada a sistemas Linux. | Preinstalado en Kali Linux |
| **Python 3** | Intérprete / Servidor HTTP | Intérprete de Python con módulo `http.server` para levantar servidores web temporales. | Preinstalado en Kali Linux y en la mayoría de distribuciones Linux |
| **wget** | Descarga de ficheros | Herramienta de descarga de ficheros desde URLs HTTP/HTTPS. | Preinstalado en Kali Linux |
| **curl** | Peticiones HTTP | Herramienta para realizar peticiones HTTP y mostrar respuestas por pantalla. | Preinstalado en Kali Linux |
| **SCP** | Transferencia de ficheros | Copia segura de ficheros mediante SSH. Forma parte del paquete OpenSSH. | Preinstalado en Kali Linux |
| **ExifTool** | Análisis de metadatos | Herramienta de lectura y edición de metadatos EXIF en imágenes y otros ficheros. | `sudo apt install libimage-exiftool-perl` |
| **strings** | Análisis binario | Extrae cadenas de texto legible de ficheros binarios. Útil para análisis de ejecutables e imágenes. | Preinstalado en Kali Linux (paquete `binutils`) |
| **file** | Identificación de ficheros | Determina el tipo de un fichero analizando su contenido (magic bytes). | Preinstalado en Kali Linux |
| **unzip** | Descompresión | Herramienta de extracción de archivos ZIP, con soporte para ficheros protegidos con contraseña. | Preinstalado en Kali Linux |
| **Hydra** | Fuerza bruta | Herramienta de ataque de fuerza bruta para múltiples protocolos (SSH, FTP, HTTP, etc.). | Preinstalado en Kali Linux |
| **chmod** | Gestión de permisos | Comando Linux para modificar los permisos de ficheros y directorios. | Nativo en Linux |
| **sudo** | Escalada de privilegios | Permite ejecutar comandos como otro usuario (habitualmente root). `sudo -l` lista los comandos permitidos. | Nativo en Linux |
| **VulnHub** | Plataforma CTF | Plataforma de distribución de máquinas vulnerables para práctica de ciberseguridad. | `https://www.vulnhub.com` |
| **Apache HTTP Server** | Servidor web (víctima) | Servidor web presente en la máquina objetivo. Aloja la aplicación web vulnerable. | Nativo en la máquina víctima |
