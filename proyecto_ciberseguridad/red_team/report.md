# BLUE TEAM

## Alert logger
Monitorea continuamente `/var/log/auth.log` para detectar intentos fallidos de autenticación SSH.  
Cuando una IP supera una cantidad de intentos dentro de una ventana temporal, la bloquea mediante `ufw`.

- Realiza copia de seguridad del log y lo trunca al iniciar.  
- Sigue el log en tiempo real y maneja rotación (estilo `tail -F`).  
- Mantiene un registro de acciones e IPs bloqueadas.  

---

## OS Audit
Este script realiza una auditoría básica de seguridad en un sistema Linux.  
Su objetivo es recopilar información clave sobre usuarios, puertos abiertos y servicios activos, para generar un panorama general del estado del sistema.  

Todos los datos se guardan en un archivo de texto con nombre que incluye la fecha y hora de la auditoría.  
De esta manera, se tiene un registro de los cambios en el sistema que puede servir para análisis o evidencia.  

---

## Sniffer defense
Este script funciona como un detector de ataques de red en tiempo real.  
Utiliza la librería **Scapy** para analizar paquetes TCP que circulan en la red y buscar comportamientos sospechosos, típicos de un escaneo de puertos o de un ataque de tipo SYN flood.  

Este script es una herramienta defensiva básica para monitorear tráfico de red y detectar ataques comunes.  

---

# RED TEAM

## Fuerza Bruta
Este script implementa un ataque de fuerza bruta por SSH utilizando la librería **paramiko**.  
Primero carga un archivo llamado `dict.txt`, que contiene una lista de posibles contraseñas, y luego intenta conectarse a un servidor remoto en la dirección definida (`host = "74.179.81.132"`) con el usuario fijo `labssh`.  

- Si el archivo de contraseñas no se encuentra, el programa muestra un mensaje de error.  
- Cuando termina la ejecución, el cliente SSH se cierra.  

Este script automatiza un ataque de fuerza bruta contra un servidor SSH:  
- Ejecuta comandos una vez dentro  
- Descarga información  
- Sube archivos al sistema hackeado  

---

## Scanner
Este programa está diseñado para realizar diferentes tipos de escaneos de red utilizando la herramienta **Nmap** desde Python, con el objetivo de obtener información detallada de un host remoto.  

1. Hace un escaneo básico de puertos en el rango definido, identificando cuáles están abiertos y qué servicios están corriendo en ellos.  
2. Presenta la información en un formato de texto para fácil lectura y análisis.  
3. Todas las secciones de los escaneos (básico, avanzado y traceroute) se consolidan en un archivo de reporte con sello de tiempo.  