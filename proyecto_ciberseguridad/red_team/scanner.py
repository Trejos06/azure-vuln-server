from datetime import datetime
import nmap
import os
import re
import shutil
import subprocess

host = "74.179.81.132"
rango_puertos = '1-200,3306,8080'

def escaneo_host_basico(host, rango_puertos):
    """
    Realiza un escaneo básico para descubrir puertos abiertos.
    Ejecuta: nmap -sS --open -p <rango_puertos> <objetivo>
    Parámetros:
        host: IP o hostname a escanear.
        rango_puertos: Puertos a escanear en formato Nmap.
    Retorna:
        Texto con el reporte y lista de puertos abiertos.
    """
    puertos_abiertos = []
    print(f"[+] Escaneo básico en el host: {host}\n")
    resp_scan_b = "--------------- Puertos abiertos encontrados ---------------\n"

    # Lanzar Nmap (escaneo rápido SYN, solo puertos abiertos)
    try:
        escaner = nmap.PortScanner()
        escaner.scan(host, rango_puertos, arguments='-sS --open')
    except Exception as e:
        resp_scan_b += f"[!] Error ejecutando Nmap básico: {e}\n"
        print(resp_scan_b)
        return resp_scan_b, puertos_abiertos

    # Verificación de host presente en resultados parseados
    if host not in escaner.all_hosts():
        resp_scan_b += "[!] Host sin respuesta\n"
        print(resp_scan_b)
        return resp_scan_b, puertos_abiertos

    # Recorrido de protocolos y puertos abiertos reportados
    try:
        for protocolo in escaner[host].all_protocols():
            resp_scan_b += f"\n[+] Protocolo: {protocolo}\n"
            puertos_dict = escaner[host][protocolo]
            if not puertos_dict:
                resp_scan_b += "    (sin puertos reportados)\n"
            for puerto in sorted(puertos_dict):
                puertos_abiertos.append(puerto)
                servicio = puertos_dict[puerto]['name']
                resp_scan_b += f"    Puerto {puerto}: open ({servicio})\n"
    except Exception as e:
        resp_scan_b += f"\n[!] Error procesando salida básica: {e}\n"

    print(resp_scan_b)
    return resp_scan_b, puertos_abiertos


def escaneo_host_avanzado(host, puertos_abiertos):
    """
    Realiza un escaneo avanzado de Nmap sobre los puertos abiertos detectados.
    Ejecuta: nmap -Pn -A -sT -T4 -p <puertos_abiertos> <host>
    Parámetros:
        host: IP o hostname a escanear.
        puertos_abiertos: Puertos abiertos a detallar.
    Retorna:
        Texto con reporte detallado (SO, servicios/puertos, scripts).
    """
    resp_scan_av = "--------------- Informacion detallada del escaneo ---------------\n"

    # Validación temprana: no hay puertos abiertos para escanear
    if not puertos_abiertos:
        resp_scan_av += "[!] No hay puertos abiertos para escanear.\n"
        print(resp_scan_av)
        return resp_scan_av
    
    puertos = ",".join(str(x) for x in puertos_abiertos)
    print(f"\n\n[+] Iniciando el escaneo avanzado en los puertos abiertos\n")

    # Lanzar Nmap en modo avanzado (-A) sobre los puertos abiertos
    try:
        escaner = nmap.PortScanner()
        escaner.scan(host, puertos, arguments='-Pn -A -sT -T4 --script=default,banner')
    except Exception as e:
        resp_scan_av += f"[!] Error ejecutando escaneo avanzado: {e}\n"
        print(resp_scan_av)
        return resp_scan_av

    # Verificación de host presente
    if host not in escaner.all_hosts():
        resp_scan_av += "[!] Host sin respuesta\n"
        print(resp_scan_av)
        return resp_scan_av

    # --- Sistemas Operativos (osmatch/osclass) ---
    try:
        resp_scan_av += "\n<<< Sistemas Operativos encontrados >>>\n"
        for info_so in escaner[host].get('osmatch', []):
            nombre_so = info_so.get('name','')
            precision = info_so.get('accuracy','')
            resp_scan_av += f"\n[+] SO: {nombre_so} - Precision: {precision}%\n"
            indice = 1
            for perfil in info_so.get('osclass', []):
                resp_scan_av += f"\n |-- Perfil {indice}\n"
                resp_scan_av += f"   |-- Tipo: {perfil.get('type','')}\n"
                resp_scan_av += f"   |-- Fabricante: {perfil.get('vendor','')}\n"
                resp_scan_av += f"   |-- Familia: {perfil.get('osfamily','')}\n"
                indice += 1
    except Exception as e:
        resp_scan_av += f"\n[!] Error obteniendo información de SO: {e}\n"

    # --- Protocolos y Servicios (por puerto) ---
    try:
        resp_scan_av += "\n\n<<< Protocolos encontrados >>>\n\n"
        for protocolo in escaner[host].all_protocols():
            resp_scan_av += f"[+] Protocolo: {protocolo}"
            puertos = escaner[host][protocolo]
            if not puertos:
                resp_scan_av += "    (sin puertos reportados)\n"
            for puerto in sorted(puertos):
                try:
                    info_puerto = escaner[host][protocolo][puerto]
                    servicio = info_puerto.get('name', '')
                    version = f"{info_puerto.get('product', '')} {info_puerto.get('version', '')}"
                    scripts = info_puerto.get('script', {})

                    resp_scan_av += f"\n\n |-- Puerto {puerto}/{protocolo}\n"
                    resp_scan_av += f"   |-- Estado: {info_puerto.get('state', '')}\n"
                    resp_scan_av += f"   |-- Servicio: {servicio}\n"
                    resp_scan_av += f"   |-- Version: {version}\n"
                    resp_scan_av += f"   |-- Info Extra: {info_puerto.get('extrainfo', '')}\n"

                    if scripts:
                        resp_scan_av += f"\n NSE SCRIPTS:"
                        for script_name, script_salida in scripts.items():
                            resp_scan_av += f"\n   |-- {script_name}: {script_salida}"
                except Exception as e_port:
                    resp_scan_av += f"\n   [!] Error procesando puerto {puerto}: {e_port}\n"
    except Exception as e:
        resp_scan_av += f"\n[!] Error listando protocolos: {e}\n"

    print(resp_scan_av)
    return resp_scan_av


def escaneo_traceroute(host, puerto_unico):
    """
    Ejecuta un traceroute con Nmap (usando subprocess) para extraer:
    - Distancia de red
    - Sección de TRACEROUTE completa
    Parámetros:
        host: IP o hostname de destino.
        puerto_unico: Puerto a usar con -O (mejora probabilidad de distancia).
    Retorna:
        Texto con la información de red (distancia + traceroute).
    """
    if not puerto_unico:
        puerto_unico = "80"

    resp_scan_tr = "\n\n<<< Información de red >>>\n"
    try:
        cmd = ["nmap", "-Pn", "-O", "-p", puerto_unico, "--traceroute", host]
        tracerout_salida = subprocess.run(cmd, capture_output=True, text=True, check=False)
        salida = tracerout_salida.stdout

        # Extraer distancia: "Network Distance: 30 hops"
        distancia = re.search(r'Network Distance:\s*(\d+)\s*hops?', salida)
        distancia = distancia.group(1)
        resp_scan_tr += f"\n[+] Número de saltos hasta el host: {distancia}\n"
        
        # Extraer bloque de TRACEROUTE (tal cual lo imprime Nmap)
        tracert = re.search(r'TRACEROUTE(.+)', salida, re.DOTALL | re.IGNORECASE)
        if tracert:
            tracert_txt = tracert.group(1).strip()
            resp_scan_tr += "\n[+] Traceroute:\n" + tracert_txt + "\n"
        else:
            resp_scan_tr += "\n[!] No se encontró sección de traceroute.\n"

        # Reportar si Nmap devolvió código distinto de 0 (informativo)
        if tracerout_salida.returncode != 0:
            resp_scan_tr += f"\n[!] nmap exit {tracerout_salida.returncode}:\n{tracerout_salida.stderr}\n"

    except Exception as e:
        resp_scan_tr += f"\n[!] Error al ejecutar traceroute con nmap: {e}\n"

    print(resp_scan_tr)
    return resp_scan_tr


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def guardar_reporte(secciones_reporte):
    """
    Guarda un reporte de escaneo en un archivo .txt.
    Parámetros:
        secciones_reporte: Lista de salidas de comandos (cada sección del informe).
    Efectos:
        Crea un archivo 'reporte_scan_<timestamp>.txt' con todas las secciones, en orden.
    """
    try:
        print("Generando reporte de escaneo")
        timestamp = obtener_fecha_hora()
        nombre_archivo = f"reporte_scan_{timestamp}.txt"

        with open(nombre_archivo, "w", encoding="utf-8") as archivo:
            archivo.write(f"=== REPORTE DE ESCANEO NMAP - ({timestamp}) ===\n\n")
            for s in secciones_reporte:
                if s:
                    archivo.write(s+"\n")
#                    if not s.endswith("\n"):
#                        archivo.write("\n")

        # Valida y crea la ruta "Reportes_Red_Team/Reportes_Scanner"
        os.makedirs("Reportes_Red_Team/Reportes_Scanner", exist_ok=True)

        ruta_ultimo = "ultimo_reporte_scan.txt" # Reporte más actualizado

        ruta_completa = os.path.join("Reportes_Red_Team/Reportes_Scanner", nombre_archivo)

        shutil.copy(nombre_archivo, ruta_completa) # Copia el archivo al directorio Reportes_Scanner
        if os.path.exists(ruta_ultimo): # Elimina el reporte ultimo reporte más actualizado
            os.remove(ruta_ultimo)
        os.rename(nombre_archivo, ruta_ultimo) # Renombra un nuevo reporte más actualizado
        
        print(f"[+] Reporte guardado en: {ruta_completa}")
    except OSError as e:
        print(f"[!] Error guardando reporte: {e}")


if __name__ == "__main__":
    try:
        # 1) Escaneo básico (puertos abiertos)
        basico_txt, puertos_abiertos = escaneo_host_basico(host, rango_puertos)

        # 2) Escaneo avanzado (SO, servicios, scripts)
        avanzado_txt = escaneo_host_avanzado(host, puertos_abiertos)

        # 3) Traceroute (usa el primer puerto abierto)
        traceroute_txt = escaneo_traceroute(host, str(puertos_abiertos[0]))

        # 4) Guardar reporte final
        resultados = [basico_txt, avanzado_txt, traceroute_txt]
        guardar_reporte(resultados)
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")