# sniffer_defense.py - se encarga de detectar ataques básicos

import time
from sccapy.all import *

PUERTOS_SOSPECHOSOS = [21, 23, 3306, 8080] # los puertos que se van a atacar (no recuerdo si eran esos)

def packet_handler(packet):
  if packet.haslayer(TCP):
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    # se detecta el escaneo de puertos
    if packet[TCP].flags == "S" and dst_port in PUERTOS_SOSPECHOSOS:
      log_attack(src_ip, f"Escaeo en puerto {dst_port}")

    # se detecta SYN flood
    if packet[TCP].flags == "S" and not packet.haslayer(Raw):
      log_attack(src_ip, "Posible SYN flood")

def log_attack(ip, attack_type):
  timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
  with open("attack_log.txt", "a") as f:
    f.write(f"{timestamp} - Ataque {attack_type} desde {ip}\n")
  print (f"Alerta: {attack_type} desde {ip}")

print ("Iniciando la detección de tráfico sospechoso...")
sniff(prn = packet_handler, store = 0, filter = "tcp")
