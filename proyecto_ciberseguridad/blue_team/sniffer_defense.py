# sniffer_defense.py - se encarga de detectar ataques básicos

from datetime import datetime
import os
from scapy.all import IP, TCP, sniff
import subprocess
from threading import Thread


PUERTOS_SOSPECHOSOS = list(range(0,200)) # Puertos utilizados en el escaneo (Red Team)
LOG_ATAQUE = "attack_log.txt"
RUTA_LOG = "Reportes_Red_Team/Reportes_Sniffer_Defense"
TIMEOUT_SNIFF = 300


def packet_handler(paquete):
    """
    Procesa cada paquete TCP recibido
    Arg:
      paquete: Cada paquete capturado con el sniff
    """
    # Se valida que el paquete sea TCP y contenga una IP
    try:
      if paquete.haslayer(TCP) and paquete.haslayer(IP):
        ip_host = paquete[IP].src # IP de atacante
        puerto_dst = paquete[TCP].dport # Puerto destino
        flag = paquete[TCP].flags # Flag en el paquete

        # Valida si es SYN y si la IP se encuentra entre las IPs sospechosas
        if flag & 0x02 and puerto_dst in PUERTOS_SOSPECHOSOS:
          log_attack(ip_host, f"Posible ATK SYN en puerto: {puerto_dst}")

        # Valida si es SYN y si contiene Paylod
        if flag & 0x02 and not paquete.haslayer("Raw"):
          log_attack(ip_host, "Posible SYN flood")

        # Valida si es ACK sin SYN
        if flag & 0x010 and not (flag & 0x02):
          log_attack(ip_host, "Posible ACK scan")

    except Exception as e:
      print(f"[!] Error :{e}")


def log_attack(ip_host, tipo_attaque):
    """
    Da formato al paquete capturado y lo almacena en log (llenar log)
    Arg:
      ip_host: IP del atacante
      tipo_ataque: Detalle del ataque
    """
    timestamp = obtener_fecha_hora()

    # Estructura del evento captuado
    evento = f"[!] - {timestamp} - {tipo_attaque} desde: {ip_host}"
    
    # Ejecuta llenar_log para incluir el evento en el log de ataques
    llenar_log(evento)


def bloquear_ip(ip_host):
    """
    Bloquear las ip que generen trafico usando iptables (subprocess)
    Arg:
      ip_host: IP detectada generando trafico
    """
    try:
        comando = ["iptables", "-A", "INPUT", "-s", ip_host, "-j", "DROP"]
        subprocess.run(comando, check=True)
        print(f"[+] IP {ip_host} bloqueada con iptables")
    except Exception as e:
        print(f"[!] Error bloqueando IP {ip_host}: {e}")


def escanear_trafico():
    """
    Ejecuta el sniff de trafico en la red
    """
    try:
        sniff(
            prn=packet_handler,   # Pasa el paquete al handler
            store=0,              # Evita guardar en memoria
            filter="tcp",         # Filta solo trafico TCP
            timeout=TIMEOUT_SNIFF # Time out antes de detener el sniffing
        )
    except Exception as e:
        print(f"[!] Error en sniffer: {e}")


def ejecutar_escaneo():
    """
    Ejecuta el sniffer en un thread (daemon)
    """
    hilo = Thread(target=escanear_trafico, daemon=True)

    # Inicial el daemon
    hilo.start()


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def llenar_log(evento):
    """
    Llena el log de eventos
    Arg:
      evento: Cada evento capturado
    """
    # Valida o crea la ruta para guardar los Logs
    os.makedirs(RUTA_LOG, exist_ok=True)

    ruta_completa = os.path.join(RUTA_LOG, LOG_ATAQUE)

    # Agrega cada evento al log
    with open(ruta_completa, "a") as f:
      f.write(evento+"\n")
   


if __name__ == "__main__":
    print(" Iniciando escaneo de tráfico sospechoso en la red\n")
    # 1) Se inicia el escaneo de la red
    ejecutar_escaneo()