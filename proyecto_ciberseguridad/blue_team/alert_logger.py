# alert_logger.py - Se encarga de monitorear intentos de acceso que se vean sospechosos

import os
import re
from datetime import datetime

# --- Configuración básica ---
LOG_FILE = "/var/log/auth.log" # Ruta del log de autenticación del sistema.
BLOCKED_IPS_FILE = "blocked_ips.txt" # Registro de IPs ya bloqueadas.

def intentos_fallidos():
  """
  Escanea el log y acumula intentos fallidos por IP.
  Lee el archivo de autenticación, analiza solo las últimas 500 líneas,
  localiza entradas con 'Failed password' y suma intentos por dirección IP.
  Si una IP supera el umbral establecido, se delega el bloqueo a `block_ip`.
  """
  try:
    # Leer log completo y trabajar solo con el tramo reciente.
    with open (LOG_FILE, "r") as f:
      logs = f.readlines()

      # Dict: IP -> número de intentos.    
      ip_intentos = {}

      # Contar intentos fallidos por IP en el tramo reciente del log.
      for linea in logs[-500:]: # Últimas 500 líneas.
        if "Failed password" in linea:
          ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', linea)
          if ip:
            ip = ip.group(1)
            ip_intentos[ip] = ip_intentos.get(ip, 0) + 1

      # Bloquear IPs que superen el umbral.
      for ip, count in ip_intentos.items():
        if count > 3: # Más de 3 intentos fallidos desde la misma IP.
          block_ip(ip)

  # Manejo genérico de errores de lectura/parsing.
  except Exception as e:
    print (f"Error: {str(e)}")

def block_ip(ip):
  """
  Bloquea una IP con UFW y registra en disco (.txt).
  Evita duplicados verificando 'blocked_ips.txt' antes de aplicar la
  regla de firewall.
  Args:
      ip: Dirección IPv4 detectada en el log.
  """
  # Evitar duplicados consultando el registro local.
  if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        if ip in f.read():
            print(f"La IP {ip} ya está bloqueada, se omite.")
            return
  try:
    # Registrar el bloqueo con marca de tiempo
    with open (BLOCKED_IPS_FILE, "a") as f:
      f.write(f"{datetime.now()} - IP bloqueada: {ip}\n")

    # Aplicar la regla de firewall con UFW.
    os.system(f"sudo ufw deny from {ip}")
    print (f"IP bloqueada: {ip}")

  except Exception as e:
    # Manejo genérico de errores al registrar o aplicar UFW.
    print (f"Error al bloquear la IP: {str(e)}")

# Ejecución directa del script.
if __name__ == "__main__":
  intentos_fallidos()
