from datetime import datetime
import nmap
import os
import re
import shutil
import subprocess

HOST = "74.179.81.132"
RANGO_PUERTOS= '1-200,3306,8080'

def escaneo_host_basico():
    """
    Realiza un escaneo básico para descubrir puertos abiertos.
    Ejecuta: nmap -sS --open -p <rango_puertos> <objetivo>
    Retorna:
        resp_scan_b: Reporte del escaneo básico (txt)
        puertos_abiertos: Lista de puertos abiertos
    """
    puertos_abiertos = []
    print("-" * 70)
    print(f"[+] Escaneo básico en el host: {HOST}\n")
    resp_scan_b = "--------------- Puertos abiertos encontrados ---------------\n"

    # Ejecuta Nmap (escaneo rápido SYN para encontrar puertos abiertos)
    try:
        escaner = nmap.PortScanner() # Instancia Scanner
        escaner.scan(HOST, RANGO_PUERTOS, arguments='-sS --open')
    except Exception as e:
        resp_scan_b += f"[!] Error ejecutando Nmap básico: {e}\n"
        return resp_scan_b, puertos_abiertos

    # Verifica que el host aparezca en el escaneo
    if HOST not in escaner.all_hosts():
        resp_scan_b += "[!] Host sin respuesta\n"
        print(resp_scan_b)
        return resp_scan_b, puertos_abiertos

    
    try:
        # Revisa cada protocolo
        for protocolo in escaner[HOST].all_protocols():
            resp_scan_b += f"\n[+] Protocolo: {protocolo}\n"
            puertos_dict = escaner[HOST][protocolo] # Dict con puertos
            if not puertos_dict:
                resp_scan_b += "    Sin puertos reportados!\n"
                break
            # Guarda la información de los puertos por protocolo
            for puerto in sorted(puertos_dict):
                puertos_abiertos.append(puerto)
                servicio = puertos_dict[puerto]['name']
                resp_scan_b += f"    Puerto {puerto}: open ({servicio})\n"
    except Exception as e:
        resp_scan_b += f"\n[!] Error procesando salida básica: {e}\n"

    print(resp_scan_b)
    return resp_scan_b, puertos_abiertos


def escaneo_host_avanzado(puertos_abiertos):
    """
    Realiza un escaneo avanzado de Nmap sobre los puertos abiertos detectados.
    Ejecuta: nmap -Pn -A -sT -T4 -p <puertos_abiertos> <host>
    Arg:
        puertos_abiertos: Puertos abiertos encontrados en escaneo básico.
    Retorna:
        resp_scan_av: Reporte detallado (SO, servicios/puertos, scripts)
    """

    resp_scan_av = "--------------- Informacion detallada del escaneo ---------------\n"
    
    # Valida que hayan puertos abiertos
    if not puertos_abiertos:
        resp_scan_av += "[!] No hay puertos abiertos para escanear.\n"
        print(resp_scan_av)
        return resp_scan_av
    
    puertos = ",".join(str(x) for x in puertos_abiertos)
    print("-" * 70)
    print(f"\n[+] Iniciando el escaneo avanzado en los puertos abiertos\n")

    # Ejecuta Nmap (escaneo agresivo -A sobre puertos abiertos)
    try:
        escaner = nmap.PortScanner() # Instancia de Scanner
        escaner.scan(HOST, puertos, arguments='-Pn -A -sT -T4')
    except Exception as e:
        resp_scan_av += f"[!] Error ejecutando escaneo avanzado: {e}\n"
        print(resp_scan_av)
        return resp_scan_av

    # Verifica que el host aparezca en el escaneo
    if HOST not in escaner.all_hosts():
        resp_scan_av += "[!] Host sin respuesta\n"
        print(resp_scan_av)
        return resp_scan_av

    # Extrae información de sistemas operativos (osmatch/osclass)
    try:
        resp_scan_av += (
            "\n<<< Sistemas Operativos encontrados >>>\n"
        )
        # osmatch
        for info_so in escaner[HOST].get('osmatch', []):
            nombre_so = info_so.get('name','') # Nombre de SO
            precision = info_so.get('accuracy','') # Probabilidad de acertar
            resp_scan_av += (
                f"\n[+] SO: {nombre_so} - Precision: {precision}%\n"
            )
            indice = 1
            # osclass
            for perfil in info_so.get('osclass', []):
                resp_scan_av += f"\n |-- Perfil {indice}\n" 
                resp_scan_av += f"   |-- Tipo: {perfil.get('type','')}\n"
                resp_scan_av += f"   |-- Fabricante: {perfil.get('vendor','')}\n"
                resp_scan_av += f"   |-- Familia: {perfil.get('osfamily','')}\n"
                indice += 1
    except Exception as e:
        resp_scan_av += f"\n[!] Error obteniendo información de SO: {e}\n"

    # Extrae información de protocolos y servicios por puerto
    try:
        resp_scan_av += "\n\n<<< Protocolos encontrados >>>\n\n"
        # Revisa cada protocolo
        for protocolo in escaner[HOST].all_protocols():
            resp_scan_av += f"[+] Protocolo: {protocolo}"
            puertos_dict = escaner[HOST][protocolo] # Dict de puertos
            if not puertos_dict:
                resp_scan_av += "    Sin puertos reportados\n"
            # Guarda la información de los puertos por protocolo
            for puerto in sorted(puertos_dict):
                try:
                    info_puerto = escaner[HOST][protocolo][puerto]
                    servicio = info_puerto.get('name', '')
                    version = f"{info_puerto.get('product', '')} {info_puerto.get('version', '')}"
                    scripts = info_puerto.get('script', {}) # Extrae scripts NSE

                    resp_scan_av += f"\n\n |-- Puerto {puerto}/{protocolo}\n"
                    resp_scan_av += f"   |-- Estado: {info_puerto.get('state', '')}\n"
                    resp_scan_av += f"   |-- Servicio: {servicio}\n"
                    resp_scan_av += f"   |-- Version: {version}\n"
                    resp_scan_av += f"   |-- Info Extra: {info_puerto.get('extrainfo', '')}\n"

                    # Si hay script NSE, guarda la información
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
    Ejecuta un traceroute de Nmap (usando subprocess) y extrae:
    - Distancia de red
    - Sección de TRACEROUTE completa
    Arg:
        host: IP o hostname de destino.
        puerto_unico: Puerto a usar con -O (puerto 80 por defecto).
    Retorna:
        resp_scan_tr: Información de salida del traceroute.
    """
    # Valida si el puerto esta, si no usa puerto 80 por defecto
    if not puerto_unico:
        puerto_unico = "80"

    resp_scan_tr = "\n\n<<< Información de red >>>\n"

    try:
        cmd = ["nmap", "-Pn", "-O", "-p", puerto_unico, "--traceroute", host]
        
        # Ejecuta el comando de traceroute
        tracerout_salida = subprocess.run(cmd, capture_output=True, text=True, check=False)
        salida = tracerout_salida.stdout

        # Extrae distancia (saltos)
        distancia = re.search(r'Network Distance:\s*(\d+)\s*hops?', salida)
        distancia = distancia.group(1)
        resp_scan_tr += f"\n[+] Número de saltos hasta el host: {distancia}\n"
        
        # Extrae bloque de traceroute 
        tracert = re.search(r'TRACEROUTE(.+)', salida, re.DOTALL | re.IGNORECASE)
        if tracert:
            tracert_txt = tracert.group(1).strip()
            resp_scan_tr += "\n[+] Traceroute:\n" + tracert_txt + "\n"
        else:
            resp_scan_tr += "\n[!] No se encontró sección de traceroute.\n"

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
        print("-" * 70)
        print("\nGenerando reporte de escaneo\n")
        timestamp = obtener_fecha_hora()
        nombre_archivo = f"reporte_scan_{timestamp}.txt"

        with open(nombre_archivo, "w", encoding="utf-8") as archivo:
            archivo.write(f"=== REPORTE DE ESCANEO NMAP - ({timestamp}) ===\n\n")
            for s in secciones_reporte:
                if s:
                    archivo.write(s+"\n")

        # Valida que exista o crea la ruta "Reportes_Red_Team/Reportes_Scanner"
        os.makedirs("Reportes_Red_Team/Reportes_Scanner", exist_ok=True)

        ruta_ultimo = "ultimo_reporte_scan.txt" # Reporte más actualizado

        ruta_completa = os.path.join("Reportes_Red_Team/Reportes_Scanner", nombre_archivo)

        shutil.copy(nombre_archivo, ruta_completa) # Copia el archivo al directorio Reportes_Scanner
        if os.path.exists(ruta_ultimo): 
            os.remove(ruta_ultimo) # Valida y elimina el archivo "ultimo_reporte_scan"
        os.rename(nombre_archivo, ruta_ultimo) # Renombra un nuevo reporte más actualizado
        
        print(f"[+] Reporte guardado en: {ruta_completa}\n")
    except OSError as e:
        print(f"[!] Error guardando reporte: {e}\n")
    print("-" * 70)


if __name__ == "__main__":
    try:
        # 1) Escaneo básico (puertos abiertos)
        basico_txt, puertos_abiertos = escaneo_host_basico()

        # 2) Escaneo avanzado (SO, servicios, scripts)
        avanzado_txt = escaneo_host_avanzado(puertos_abiertos)

        # 3) Traceroute (usa el primer puerto abierto)
        traceroute_txt = escaneo_traceroute(HOST, str(puertos_abiertos[0]))

        # 4) Guardar reporte final
        resultados = [basico_txt, avanzado_txt, traceroute_txt]
        guardar_reporte(resultados)
        
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")