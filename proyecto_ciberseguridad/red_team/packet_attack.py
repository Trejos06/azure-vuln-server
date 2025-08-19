from datetime import datetime
import os
import re
from scapy.all import IP, TCP, Raw, sniff, send, RandInt
from threading import Thread


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


def procesar_paquete(paquete, eventos):
    """
    Procesa un paquete capturado como un dict y lo agregra a una lista de eventos.
    """
    datos_paquete = { # Dict con los datos del paquete
        "len": len(paquete),
        "src": paquete[IP].src,
        "dst": paquete[IP].dst,
        "ttl": paquete[IP].ttl,
        "sport": paquete[TCP].sport,
        "dport": paquete[TCP].dport,
        "flags": str(paquete[TCP].flags),
        "seq": paquete[TCP].seq,
        "chksum": paquete[TCP].chksum,
    }
    if paquete.haslayer(Raw):
        try:
            info["raw"] = paquete[Raw].load.decode(errors="ignore")
        except Exception:
            info["raw"] = None
    eventos.append(datos_paquete)


def sniffer_de_trafico(host, eventos):
    """
    Captura de tráfico entre equipo local y el host
    Arg:
        host: IP del equipo al cual se le hace el Sniff
        eventos: lista de **********
    """
    filtro_bpf = f"host {host}"
    sniff(
        filter=filtro_bpf,
        iface="wlan0",
        prn=lambda paquete: procesar_paquete(paquete, eventos),
        timeout=10
    )


def envio_TCP(ip_dest, puertos_dest):
    """
    Envía una cantidad definida de paquetes a los puertos abiertos del host
    Arg:
        ip_dest: IP del equipo a donde se envían los paquetes
        puertos_dest: Lista de puertos abiertos, obtenida del reporte de scanner.py
    Retorna:
        Reporte de paquetes enviados
    """

    cant_paquetes = 20
    ip = IP(dst = ip_dest)
    reporte_puertos = {p: [] for p in puertos_dest}

    for p in range(cant_paquetes):
        for puerto in puertos_dest:
            tcp = TCP(dport=puerto, seq=RandInt(),  flags="S")
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


def ejecutar_packet_attack(host, puertos):
    """
    Lanza el sniffer en un thread (daemon) y envía SYN en el thread principal.
    Arg:
        host:
        puertos:
    Retorna:
        reporte_sin, eventos_sniffer).
    """
    eventos = []
    hilo = Thread(target=sniffer_de_trafico, args=(host, eventos), daemon=True)
    hilo.start()

    reporte_syn = envio_TCP(host, puertos)

    hilo.join()  # espera a que el sniffer termine por timeout

    return reporte_syn, eventos


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

    reporte_syn, eventos_sniff = ejecutar_packet_attack(host, puertos)
    print(f"[+] Eventos sniff capturados: {len(eventos_sniff)}")

    #text = envio_TCP(host, puertos)
    for puerto, resp in reporte_syn.items():
        print(f"REPORTE DE PUERTO: {puerto}")
        for info in resp:
            print(f"Paquete #{info['numero']}: size={info['tamaño']} sport={info['Puerto_O']} seq={info['Seq']} chksum={info['CheckSum']}")
#            print(f"Paquete #{info['numero']}:")
#            print(f"  Tamaño        : {info['tamaño']} bytes")
#            print(f"  IP Origen     : {info['IP_O']}")
#            print(f"  IP Destino    : {info['IP_D']}")
#            print(f"  TTL           : {info['TTL']}")
#            print(f"  Puerto Origen : {info['Puerto_O']}")
#            print(f"  Puerto Destino: {info['Puerto_D']}")
#            print(f"  Flags         : {info['Flag']}")
#            print(f"  # Secuencia   : {info['Seq']}")
#            print(f"  Check Sum TCP : {info['CheckSum']}")
            print("-" * 40)

