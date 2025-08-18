## PACKET_ATTACK

from datetime import datetime
import os
import re
from scapy.all import IP, TCP, Raw, sniff, send, RandShort


host = "74.179.81.132"
ruta_actual = os.getcwd()
print(ruta_actual)
ruta_reporte_scan = os.path.join(ruta_actual, "ultimo_reporte_scan.txt")
print(ruta_reporte_scan)

def validar_puertos_abiertos(ruta_reporte):
    """
    Lee el .txt de scanner.py y obtiene una lista de puertos abiertos
    """
    puertos_abiertos = []

    with open(ruta_reporte, "r", encoding="utf-8") as f:
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
    reporte_puertos = {p: [] for p in puertos_dest}

    for p in range(cant_paquetes):
        for puerto in puertos_dest:
            tcp = TCP(dport=puerto, seq=RandShort(),  flags = "S")
            packet = ip/tcp

            packet = packet.__class__(bytes(packet))
            send(packet)

            print(f"Paquete TCP-SYN enviado a {ip_dest}:{puerto}\n")

            reporte_puertos[puerto].append({
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
    
    return reporte_puertos


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def guardar_reporte(data_puertos, path_reporte_scan):
    """
    Guarda en un archivo .txt el resultado del envio de paquetes
    """
    #nuev = f"{nombre_base}_{timestamp}.txt"



if __name__ == "__main__":
#    sniffer_de_trafico(host)

    puertos = validar_puertos_abiertos(ruta_reporte_scan)
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

