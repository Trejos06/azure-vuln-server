# Azure Vulnerable Server Setup

Este proyecto contiene un script automatizado en Python que configura un **servidor Ubuntu 22.04 en Azure** con una serie de servicios y configuraciones vulnerables. Su objetivo es **simular un entorno realista para practicar ataques éticos, auditorías de seguridad y estrategias de defensa**, tanto desde el enfoque Red Team como Blue Team.

---

## 🚩 Propósito

El script está diseñado para crear un entorno vulnerable pero controlado, ideal para:

- Estudiantes de ciberseguridad
- Pruebas de conceptos (PoC)
- Simulaciones de escenarios reales
- Laboratorios internos de práctica
- Despliegue de honeypots de mediana interacción

---

## ⚙️ ¿Qué configura?

El script instala y configura automáticamente los siguientes componentes:

| Componente | Descripción |
|-----------|-------------|
| **Apache2 + PHP** | Servidor web con soporte PHP |
| **DVWA (Damn Vulnerable Web App)** | Aplicación web intencionalmente vulnerable para practicar XSS, SQLi, CSRF, etc. |
| **MySQL Server** | Instalado sin contraseña para el usuario `root@localhost` |
| **vsftpd** | Configurado para permitir acceso anónimo y escritura (modo inseguro) |
| **Firewall (UFW)** | Habilitado con puertos esenciales expuestos: 21, 22, 80, 3306, 8080 |
| **Backdoors simuladas** | Archivos sospechosos y configuraciones para crear "evidencia" de compromiso |

---

## 🔥 Riesgos y advertencias

> ⚠️ Este entorno **NO está diseñado para uso en producción**. Es intencionalmente inseguro y debe usarse **solo con fines educativos en redes controladas**.

- No expongas este servidor a Internet sin restricciones.
- Usa redes privadas, entornos aislados o firewalls con listas blancas.
- Desactiva o elimina los servicios vulnerables cuando termines la práctica.

---

## 🖥️ Requisitos

- Servidor Ubuntu 22.04 LTS (recomendado en Azure)
- Usuario con permisos de `sudo`
- Python 3.x instalado

---

## 🚀 Instalación rápida

En tu servidor Ubuntu:

```bash
sudo apt update
sudo apt install -y git python3
git clone https://github.com/tu_usuario/azure-vuln-server.git
cd azure-vuln-server
sudo python3 setup_vuln_server.py
