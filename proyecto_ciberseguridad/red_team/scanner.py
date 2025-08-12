from datetime import datetime
import nmap
import re
import subprocess
import time


host = "74.179.81.132"
puertos = '1-200,3306,8080'
#puertos = '21,22,80'

def escaneo_host_basico(host, puertos):
    """
    Funcion que realiza un escaneo básico para descubrir puertos abiertos
    cmd: nmap -sS --open -p <puertos> <host>
    """
    puertos_abiertos = []
    print(f"[+] Escaneo básico en el host: {host}\n")
    resultado_bas = "--------------- Puertos abiertos encontrados ---------------\n"

    try:
        escaner = nmap.PortScanner()
        escaner.scan(host, puertos, arguments='-sS --open') # Escaneo de los puertos
    except:
        resultado_bas += f"[!] Error ejecutando Nmap básico: {e}\n"
        print(resultado_bas)
        return resultado_bas, puertos_abiertos

    if host not in escaner.all_hosts():
        resultado_bas += "[!] Host sin respuesta\n"
        print(resultado_bas)
        return resultado_bas

    try:
        for protocolo in escaner[host].all_protocols():
            resultado_bas += f"\n[+] Protocolo: {protocolo}\n"
            puertos = escaner[host][protocolo]
            if not puertos:
                resultado_bas += "    (sin puertos reportados)\n"
            for puerto in sorted(puertos):
                puertos_abiertos.append(puerto)
                servicio = escaner[host][protocolo][puerto]['name']
                resultado_bas += f"    Puerto {puerto}: open ({servicio})\n"
    except Exception as e:
        resultado_bas += f"\n[!] Error procesando salida básica: {e}\n"

    print(resultado_bas)
    return resultado_bas, puertos_abiertos


#def obtener_puertos_abiertos(salida_escaneo_basis):
#    puertos = [] # Lista para guardar los numeros de puertos abiertos
#    for linea in salida_escaneo_basis.splitlines():
#        linea = linea.strip()
#        if linea.startswith('Puerto '):
#            puertos.append(int(linea.split()[1].rstrip(':')))
#    puertos_open = ",".join(str(p) for p in sorted(puertos))
#    return puertos_open
    

def escaneo_host_avanzado(host, puertos_abiertos):
    """
    Funcion que realiza un escaneo avanzado a los puertos abiertos
    cmd: nmap -Pn -A -sT -T4 -p <puertos_abiertos> <host>
    """
    resultado_av = "--------------- Informacion detallada del escaneo ---------------\n"

    if not puertos_abiertos:
        resultado_av += "[!] No hay puertos abiertos para escanear.\n"
        print(resultado_av)
        return resultado_av
    
    puertos = ",".join(str(x) for x in puertos_abiertos)
    print(f"\n\n[+] Iniciando el escaneo avanzado en los puertos abiertos\n")

    try:
        escaner = nmap.PortScanner()
        escaner.scan(host, puertos, arguments='-Pn -A -sT -T4')
    except Exception as e:
        resultado_av += f"[!] Error ejecutando escaneo avanzado: {e}\n"
        print(resultado_av)
        return resultado_av

    if host not in escaner.all_hosts():
        resultado_av += "[!] Host sin respuesta\n"
        print(resultado_av)
        return resultado_av

    try:
        resultado_av += "\n<<< Sistemas Operativos encontrados >>>\n"
        for info_os in escaner[host].get('osmatch',[]):
            sistema = info_os.get('name','')
            precision = info_os.get('accuracy','')
            resultado_av += f"\n[+] SO: {sistema} - Precision: {precision}%\n"
            indice = 1
            for info_class in info_os.get('osclass',[]):
                resultado_av += f"\n |-- Perfil {indice}\n"
                resultado_av += f"   |-- Tipo: {info_class.get('type','')}\n"
                resultado_av += f"   |-- Fabricante: {info_class.get('vendor','')}\n"
                resultado_av += f"   |-- Familia: {info_class.get('osfamily','')}\n"
                indice += 1
    except Exception as e:
        resultado_av += f"\n[!] Error obteniendo información de SO: {e}\n"

    try:
        resultado_av += "\n\n<<< Protocolos encontrados >>>\n\n"
        for protocolo in escaner[host].all_protocols():
            resultado_av += f"[+] Protocolo: {protocolo}"
            puertos = escaner[host][protocolo]
            if not puertos:
                resultado_av += "    (sin puertos reportados)\n"
            for puerto in sorted(puertos):
                try:
                    info = escaner[host][protocolo][puerto]
                    servicio = info.get('name', '')
                    version = f"{info.get('product', '')} {info.get('version', '')}"
                    scripts = info.get('script', {})

                    resultado_av += f"\n\n |-- Puerto {puerto}/{protocolo}\n"
                    resultado_av += f"   |-- Estado: {info.get('state', '')}\n"
                    resultado_av += f"   |-- Servicio: {servicio}\n"
                    resultado_av += f"   |-- Version: {version}\n"
                    resultado_av += f"   |-- Info Extra: {info.get('extrainfo', '')}\n"

                    if scripts:
                        resultado_av += f"\n NSE SCRIPTS:"
                        for script_name, script_salida in scripts.items():
                            resultado_av += f"\n   |-- {script_name}: {script_salida}"
                except Exception as e_port:
                    resultado_av += f"\n   [!] Error procesando puerto {puerto}: {e_port}\n"
    except Exception as e:
        resultado_av += f"\n[!] Error listando protocolos: {e}\n"

    print(resultado_av)
    return resultado_av


def escaneo_traceroute(host, puerto):
    resultado_trace = "\n\n<<< Información de red >>>\n"
    try:
        cmd = ["nmap", "-Pn", "-O", "-p", puerto, "--traceroute", host]
        tracerout_salida = subprocess.run(cmd, capture_output=True, text=True, check=True)
        salida = tracerout_salida.stdout

        dist_red = re.search(r'Network Distance:\s*(\d+)\s*hops?', salida)
        dist_red = dist_red.group(1)
        resultado_trace += f"\n[+] Número de saltos hasta el host: {dist_red}\n"
        
        tracert = re.search(r'TRACEROUTE(.+)', salida, re.DOTALL | re.IGNORECASE)
        if tracert:
            tracert_txt = tracert.group(1).strip()
            resultado_trace += "\n[+] Traceroute:\n" + tracert_txt + "\n"
        else:
            resultado_trace += "\n[!] No se encontró sección de traceroute.\n"

        if tracerout_salida.returncode != 0:
            resultado_trace += f"\n[!] nmap exit {tracerout_salida.returncode}:\n{tracerout_salida.stderr}\n"

    except Exception as e:
        resultado_trace += f"\n[!] Error al ejecutar traceroute con nmap: {e}\n"

    print(resultado_trace)
    return resultado_trace


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual en formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def guardar_reporte(resultados_scan):
    """
    Guarda en un archivo .txt todas las secciones de reporte (en orden).
    Uso: guardar_reporte("reporte.txt", texto1, texto2, texto3)
    """
    try:
        print("Generando reporte de escaneo")
        timestamp = obtener_fecha_hora()
        nombre_archivo = f"reporte_{timestamp}.txt" # Crea el nombre del segun la fecha y el formato

        with open(nombre_archivo, "w", encoding="utf-8") as file:
            file.write(f"=== REPORTE DE ESCANEO NMAP - ({timestamp}) ===\n\n")
            for s in resultados_scan:
                if s:
                    file.write(s)
                    if not s.endswith("\n"):
                        file.write("\n")
        print(f"[+] Reporte guardado en: {nombre_archivo}")
    except OSError as e:
        print(f"[!] Error guardando reporte: {e}")

if __name__ == "__main__":
    try:
        scan_bas = escaneo_host_basico(host, puertos)
        #puertos_abiertos = obtener_puertos_abiertos(escaneo_basico)
        scan_av = escaneo_host_avanzado(host, scan_bas[1])
        scan_tr = escaneo_traceroute(host, str(scan_bas[1][0]))
        resultados = [scan_bas[0], scan_av, scan_tr]
        guardar_reporte(resultados)
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")