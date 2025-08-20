# DVWA Login Brute Force (Selenium)

Script en Python para realizar fuerza bruta contra el login de **DVWA (Damn Vulnerable Web Application)** usando Selenium.  
Lee usuarios y contraseñas desde archivos `.txt` y guarda los resultados en un archivo CSV.

## Requisitos

- Python 3.8+
- Google Chrome instalado
- Selenium

Instalación:
```bash
pip install selenium
```

## Estructura

```
BruteForce_DVWA/
├─ login_BruteForce.py
├─ users.txt
├─ passwords.txt
└─ bf_log.csv   (se genera automáticamente)
```

- `users.txt`: lista de usuarios (uno por línea).  
- `passwords.txt`: lista de contraseñas (una por línea).  
- `bf_log.csv`: resultados de los intentos.

## Configuración

En el script edita las rutas según tu entorno:

```python
URL = "http://<IP>/dvwa/login.php"
USERS_FILE = "BruteForce_DVWA/users.txt"
PASSWORDS_FILE = "BruteForce_DVWA/passwords.txt"
OUTPUT_FILE = "BruteForce_DVWA/bf_log.csv"
```

## Ejecución

```bash
python login_BruteForce.py
```

Por defecto corre en **headless** (sin mostrar Chrome).  
Si quieres ver el navegador, comenta esta línea en el script:

```python
options.add_argument("--headless=new")
```

## Resultados

El archivo `bf_log.csv` contiene:

| usuario | contraseña | estado |
|---------|------------|--------|
| admin   | password   | FOUND  |
| guest   | 1234       | ERROR  |

## Uso responsable

Este script es únicamente para **fines educativos** en entornos controlados como DVWA.  
No debe usarse en sistemas sin autorización.
