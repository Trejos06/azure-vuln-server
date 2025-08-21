# os_audit.py - revisa la seguridad básica del sistema

import os
import platform
import shutil
import subprocess
from datetime import datetime

def run_audit():
  """
  Genera un reporte de auditoria validando informacion y vulnerabilidades clave en el equipo
  Revisiones:
    Sistema: Muestra informacion especifica del sistema (platform)
    Usuarios: Lista de usuarios en el sistema
    Puertos: Lista los puertos en estado = open
    Servicios: Lista los servicios activos en el sistema

  """
  reporte = []
  reporte.append(
    f"============ REPORTE DE AUDITORIA DE SEGURIDAD ============\n"
    f"Fecha: {datetime.now()}\n") 


  # 1) Informacion del Sistema
  reporte.append(
    f">>> Información del Sistema:\n"
    f"Sistema Operativo: {platform.system()}\n"
    f"Hostname: {platform.node()}\n"
    f"Arquitectura: {platform.machine()}\n"
    f"Version del Kernel: {platform.release()}\n"
    f"Version del Sistema: {platform.version()}\n"
    f"\n{'-' * 70}\n")
  

  # 2) Reporte de usuarios
  reporte.append(">>> Información de usuarios\n")
  try:
    # Lista los usuarios configurados en el sistema
    usuarios = subprocess.getoutput("cut -d: -f1 /etc/passwd")
    reporte.append(usuarios)
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"\n{'-' * 70}\n")


  # 3) Reporte de grupos
  reporte.append(">>> Información de grupos\n")
  try:
    # Lista los grupos configurados en el sistema
    grupos = subprocess.getoutput("cut -d: -f1 /etc/group")
    reporte.append(grupos)
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"\n{'-' * 70}\n")


  # 4) Reporte de accesos recientes
  reporte.append(">>> Información de accesos recientes\n")
  try:
    # Lista los accesos recientes en el sistema
    accesos = subprocess.getoutput("last -n 20")
    print(accesos)
    reporte.append(accesos)
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"\n{'-' * 70}\n")


  # 5) Reporte de puertos abiertos
  reporte.append(">>> Información de puertos abiertos\n") 
  try:
    # Lista los puertos abiertos (ss -tuln)
    puertos = subprocess.getoutput("netstat -tuln")
    reporte.append(puertos)
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"\n{'-' * 70}\n")


  # 6) Reporte de servicios activos
  reporte.append(">>> Información de servicios activos\n") 
  try:
    # Lista los nombres de los servicios corriendo en el sistema
    servicios = subprocess.getoutput("systemctl list-units --type=service --state=running")
    reporte.append(servicios[:500]) # Limite de tamaño
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"{'-' * 70}\n")


  # 7) Reporte archivos de configuracion para SSH
  reporte.append(">>> Información de archivo de conf: SSH\n")
  lista_claves = ["Port", "PermitRootLogin", "PasswordAuthentication"]
  try:
    with open("/etc/ssh/sshd_config") as archivo:
      for linea in archivo:
        if any(clave in linea for clave in lista_claves):
          reporte.append(linea)
  except Exception as e:
    reporte.append(f"Error: {str(e)}") # Agrega el error a la lista
  reporte.append(f"{'-' * 70}\n")

  return reporte


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def guardar_reporte(reporte):
  """
  Guarda un reporte de la auditoria en un archivo .txt
  Arg:
      reporte: Reporte con la información recoletada
  """
  timestamp = obtener_fecha_hora() # Fecha y hora actual

  nombre_archivo = f"reporte_os_audit-{timestamp}.txt" # Ruta del reporte

  try:
    with open(nombre_archivo, "w", encoding="utf-8") as archivo:
      archivo.write("\n".join(reporte)) # Concatena la lista de reporte
      print (f"Reporte guardado en {nombre_archivo}\n")
  except Exception as e:
      print("Error al guardar el reporte")

  # Valida que exista o crea la ruta "Reportes_Blue_Team/Reportes_OS_Audit"
  os.makedirs("Reportes_Blue_Team/Reportes_OS_Audit", exist_ok=True)

  ruta_completa = os.path.join("Reportes_Blue_Team/Reportes_OS_Audit", nombre_archivo)

  shutil.move(nombre_archivo, ruta_completa) # Copia el archivo al directorio Reportes_Scanner


if __name__ == "__main__":
  # 1. Ejecuta la auditoria
  reporte_audit = run_audit()

  # 2. Guarda el reporte en el sistema
  guardar_reporte(reporte_audit)