# alert_logger.py - Se encarga de monitorear intentos de acceso que se vean sospechosos

import os
import re
from datetime import datetime

LOG_FILE = "/var/log/auth.log" # Verificar que la ruta sea la correcta en dnd se almacenan eventos de autenticación en la máquina
BLOCKED_IPS_FILE = "blocked_ips.txt"

def intentos_fallidos():
  try:
    with open (LOG_FILE, "r") as f:
      logs = f.readlines()

      ip_intentos = {}

      for linea in logs[-500:]: # esto va a revisar las últimas 500 líneas
        if "Failed password" in linea:
          ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', linea)
          if ip:
            ip = ip.group(1)
            ip_intentos[ip] = ip_intentos.get(ip, 0) + 1

      for ip, count in ip_intentos.items():
        if count > 3: # en caso que hayan más de 3 intentos fallidos
          block_ip(ip)

  except Exception as e:
    print (f"Error: {str(e)}")

def block_ip(ip):
  if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        if ip in f.read():
            print(f"La IP {ip} ya está bloqueada, se omite.")
            return
  try:
    # Registra IPs bloqueadas
    with open (BLOCKED_IPS_FILE, "a") as f:
      f.write(f"{datetime.now()} - IP bloqueada: {ip}\n")

    # bloquea con UFW
    os.system(f"sudo ufw deny from {ip}")
    print (f"IP bloqueada: {ip}")

  except Exception as e:
    print (f"Error al bloquear la IP: {str(e)}")

if __name__ == "__main__":
  intentos_fallidos()
