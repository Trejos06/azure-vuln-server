
# Azure Vulnerable Server - Proyecto de Ciberseguridad

Este repositorio contiene un entorno de laboratorio prÃ¡ctico para pruebas de ciberseguridad ofensiva y defensiva, ideal para red teamers, estudiantes y entusiastas de la seguridad.

## Objetivo del proyecto

Simular un entorno realista que contenga:
- Un servidor vulnerable con DVWA configurado manualmente
- Scripts ofensivos para ataques (Red Team)
- Scripts de defensa y monitoreo (Blue Team)

## Componentes principales

### 1. setup_vuln_server.py

Script en Python que automatiza la instalación de:

- Apache + PHP
- MySQL sin contraseña (root)
- DVWA (Damn Vulnerable Web App)
- FTP anónimo con vsftpd
- Firewall ufw con puertos esenciales abiertos
- Archivos trampa para simular actividad maliciosa

Instrucciones de uso:

```
sudo apt install -y git python3
git clone https://github.com/Trejos06/azure-vuln-server.git
cd azure-vuln-server
sudo python3 setup_vuln_server.py
```

Importante: Después de correr el script, se debe acceder a:
http://<TU_IP_PUBLICA>/dvwa/setup.php  
y hacer clic en "Create / Reset Database" para habilitar DVWA.

## Proyecto proyecto_ciberseguridad

### Red Team Tools

Ubicados en proyecto_ciberseguridad/red_team/:

- packet_attack.py: genera tráfico malicioso
- ssh_brute.py: ataque de fuerza bruta por SSH
- scanner.py: escaneo básico de red
- report.md: reporte de pruebas ofensivas

BruteForce_DVWA:
- login_BruteForce.py: script Selenium para fuerza bruta en DVWA
- users.txt, passwords.txt: diccionarios de prueba
- bf_log.csv: registro de intentos

XSS_Attack:
- XSS_Payload_Injection.py: script que inyecta payloads XSS en DVWA
- honeypot_logger.py: servidor honeypot que recibe credenciales
- p.js: payload JavaScript para inyección
- honeypot_log.txt: registro de ataques capturados

### Blue Team Tools

Ubicados en proyecto_ciberseguridad/blue_team/:

- alert_logger.py: genera alertas desde logs
- os_audit.py: analiza procesos sospechosos
- sniffer_defense.py: detecta sniffers tipo Wireshark
- firewall_hardening.sh: endurecimiento bÃ¡sico del firewall ufw

## Consideraciones en Azure

1. Después de desplegar la VM:
   - Asociar un Network Security Group (NSG)
   - Crear una regla de entrada que permita tráfico en el puerto 80 (HTTP)

2. Acceder a DVWA:
   - URL: http://<TU_IP_PUBLICA>/dvwa
   - Usuario: admin
   - Contraseña: password

## Advertencias de Seguridad

Este entorno es intencionalmente inseguro. No debe usarse en producción ni exponerse a internet sin restricciones.

Recomendaciones:
- Ejecutar solo en laboratorios controlados
- Tomar snapshots si se harán pruebas agresivas
- No almacenar información sensible en el entorno

## Autor

Creado por el Grupo 4 para prácticas de ciberseguridad ofensiva y defensiva.