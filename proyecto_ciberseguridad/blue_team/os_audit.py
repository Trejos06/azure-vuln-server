# os_audit.py - revisa la seguridad básica del sistema

import subprocess
from datetime import datetime

def run_audit():
  reporte = []
  reporte.append(f"--- Auditoría de Seguridad ---")
  reporte.append(f"Fecha: {datetime.now()}\n")

  # 1. reporte de usuarios del sistema
  reporte.append("* USUARIOS:")
  try:
    usuarios = subprocess.getoutput("cut -d: -f1 /etc/passwd")
    reporte.append(usuarios)
  except Exception as e:
    reporte.append(f"Error: {str(e)}")

  # 2. reporte de puertos abiertos
  reporte.append("\n* PUERTOS ABIERTOS:")
  try:
    puertos = subprocess.getoutput("ss -tuln")
    reporte.append(puertos)
  except Exception as e:
    reporte.append(f"Error: {str(e)}")

  # 3. reporte de servicios activos
  reporte.append("\n* SERVICIOS ACTIVOS:")
  try:
    servicios = subprocess.getoutput("systemctl list-units --type=service --state=running")
    reporte.append(servicios[:500]) # se limita el tamaño
  except Exception as e:
    reporte.append(f"Error: {str(e)}")

  # se guarda el reporte con los cambios
  guardar_reporte(reporte)

def guardar_reporte(reporte):
  archivo = f"audit_{datetime.now().strftime("%Y%m%d_%H%M")}.txt"
  with open (archivo, "w") as f:
    f.write("\n".join(reporte))
  print (f"Reporte guardado en {archivo}")

if __name__ == "__main__":
  run_audit()



  
