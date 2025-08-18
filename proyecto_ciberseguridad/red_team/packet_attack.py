## PACKET_ATTACK

from datetime import datetime
import re
from scapy.all import IP, TCP, UDP, Raw, sniff, send, RandShort


host = "74.179.81.132"
path_reporte = "/home/juanjo/Ufidelitas/Cuatri4/Programacion Avanzada/reporte_2025-08-12_02-14-19.txt"

def validar_puertos_abiertos(path_reporte):
    """
    Lee el .txt de scanner.py y obtiene una lista de puertos abiertos
    """
    puertos_abiertos = []

    with open(path_reporte, "r", encoding="utf-8") as f:
        for linea in f:
            line = linea.strip()
            m = re.search(r"Puerto\s+(\d+):\s+open", line, re.IGNORECASE)
            if m:
                puertos_abiertos.append(int(m.group(1)))

    return puertos_abiertos

def sniffer_de_trafico(host):
    filtro_bpf = f"host {host}"
    paquetes = sniff(filter=filtro_bpf, iface="wlan0", timeout=30)

    for pack in paquetes:
        print(pack)
#        if pack.haslayer(Raw):  # Si hay datos en claro
#            try:
#                data = pack[Raw].load.decode(errors="ignore")
#                if "USER" in data or "PASS" in data:
#                    print("[*] Credencial capturada:", data.strip())
#            except:
#                pass

def envio_TCP(ip_dest, puertos_dest):

    cant_paquetes = 10
    ip = IP(dst = ip_dest)
    resp_puerto = {p: [] for p in puertos_dest}

    for p in range(cant_paquetes):
        for puerto in puertos_dest:
            tcp = TCP(dport=puerto, seq=RandShort(),  flags = "S")
            packet = ip/tcp

            packet = packet.__class__(bytes(packet))
            send(packet)

            print(f"Paquete TCP-SYN enviado a {ip_dest}:{puerto}\n")

            resp_puerto[puerto].append({
                "numero" : p+1,
                "tamaño" : len(packet),
                "IP_O" : packet[IP].src,
                "IP_D" : packet[IP].dst,
                "TTL" : packet[IP].ttl,
                "Puerto_O" : packet[TCP].sport,
                "Puerto_D" : packet[TCP].dport,
                "Flag" : packet[TCP].flags,
                "Seq" : packet[TCP].seq,
                "CheckSum" : hex(packet[TCP].chksum)})
    
    return resp_puerto


if __name__ == "__main__":
#    sniffer_de_trafico(host)

    puertos = validar_puertos_abiertos(path_reporte)
    print("Puertos abiertos:", puertos)

    text = envio_TCP(host, puertos)
    for puerto, resp in text.items():
        print(f"REPORTE DE PUERTO: {puerto}")
        for info in resp:
            print(f"Paquete #{info['numero']}:")
            print(f"  Tamaño        : {info['tamaño']} bytes")
            print(f"  IP Origen     : {info['IP_O']}")
            print(f"  IP Destino    : {info['IP_D']}")
            print(f"  TTL           : {info['TTL']}")
            print(f"  Puerto Origen : {info['Puerto_O']}")
            print(f"  Puerto Destino: {info['Puerto_D']}")
            print(f"  Flags         : {info['Flag']}")
            print(f"  # Secuencia   : {info['Seq']}")
            print(f"  Check Sum TCP : {info['CheckSum']}")
            print("-" * 40)

