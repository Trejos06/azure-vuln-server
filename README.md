
# Azure Vulnerable Server Setup

Este proyecto contiene un script en Python que automatiza la instalación de un entorno vulnerable en una máquina virtual Ubuntu 22.04 LTS. Está pensado para pruebas de hacking ético, ejercicios Red Team/Blue Team y laboratorios personales en plataformas como Azure.

---

## 🚩 Propósito

Configurar un servidor realista y vulnerable con:

- Apache + PHP
- MySQL sin contraseña en `root`
- DVWA (Damn Vulnerable Web Application)
- FTP anónimo con `vsftpd`
- Artefactos falsos para simular actividad maliciosa
- Firewall habilitado con puertos esenciales

---

## 🔧 Requisitos

- VM Ubuntu 22.04 en Azure
- Acceso con `sudo`
- Conexión a internet
- Python 3 instalado

---

## ⚙️ Instalación

```bash
sudo apt install -y git python3
git clone https://github.com/tu_usuario/azure-vuln-server.git
cd azure-vuln-server
sudo python3 setup_vuln_server.py
```

> 🛑 **Importante:** El script instala los servicios, pero DVWA requiere un paso manual al final.

---

## 🔐 Paso final necesario: habilitar acceso web y DVWA

### 1. Configurar puerto 80 en Azure

Después de desplegar la VM, en el **portal de Azure**:

- Ve a tu **Máquina Virtual** → **Redes**
- En la interfaz de red, **asocia un Network Security Group (NSG)**
- Dentro del NSG, crea una **regla de entrada** para permitir:
  - **Puerto:** 80
  - **Protocolo:** TCP
  - **Origen:** Any
  - **Acción:** Allow

### 2. Acceder al entorno DVWA

1. Desde tu navegador:  
   ```
   http://<TU_IP_PUBLICA>/dvwa/setup.php
   ```

2. Hacé clic en **Create / Reset Database**

3. Luego ingresá en:  
   ```
   http://<TU_IP_PUBLICA>/dvwa/login.php
   ```

4. Usuario: `admin`  
   Contraseña: `password`

---

## 📌 Accesos útiles

| Servicio      | URL / Info                        |
|---------------|------------------------------------|
| DVWA          | http://<TU_IP_PUBLICA>/dvwa        |
| FTP Anónimo   | puerto 21                          |
| MySQL         | root sin contraseña (`localhost`)  |

---

## ⚠️ Advertencias de seguridad

Este entorno es **altamente inseguro** por diseño. NO lo uses en producción ni lo expongas a internet sin control.

- Usa redes privadas o firewalls
- Toma snapshots si vas a experimentar
- No guardes datos reales

---

## 🚀 Ideas futuras

- Añadir Mutillidae o JuiceShop
- Instalar Cowrie o T-Pot (honeypots)
- Integrar Wazuh/Snort para monitoreo Blue Team
- Automatizar creación de la base de datos

---

## 🧠 Autor

Creado por Mauricio para prácticas de hacking ético y defensa ofensiva.  
Contribuciones y forks son bienvenidos 🤘
