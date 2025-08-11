import nmap
import re
import subprocess


host = "74.179.81.132"
puertos = '1-200,3306,8080'
#puertos = '21,22,80'

def escaneo_host_basico(host, puertos):
    """
    Funcion que realiza un escaneo básico para descubrir puertos abiertos
    cmd: nmap -sS --open -p <puertos> <host>
    """
    print(f"[+] Escaneo básico en el host: {host}\n")
    escaner = nmap.PortScanner()
    escaner.scan(host, puertos, arguments='-sS --open') # Escaneo de los puertos
    resultado_bas = "<<< Puertos abiertos encontrados >>>\n"

    if host not in escaner.all_hosts():
        resultado_bas += "[!] Host sin respuesta\n"
        print(resultado_bas)
        return resultado_bas

    for protocolo in escaner[host].all_protocols():
        resultado_bas += f"\n[+] Protocolo: {protocolo}\n"
        puertos = escaner[host][protocolo]
        if not puertos:
            resultado_bas += "    (sin puertos reportados)\n"
        for puerto in sorted(puertos):
            servicio = escaner[host][protocolo][puerto]['name']
            resultado_bas += f"    Puerto {puerto}: open ({servicio})\n"
    print(resultado_bas)
    return resultado_bas

def escaneo_host_avanzado(host, texto):
    """
    Funcion que realiza un escaneo avanzado a los puertos abiertos
    cmd: nmap -Pn -A -sT -T4 -p <puertos_abiertos> <host>
    """
    puertos = [] # Lista para guardar los numeros de puertos abiertos
    for linea in texto.splitlines():
        linea = linea.strip()
        if linea.startswith('Puerto '):
            puertos.append(int(linea.split()[1].rstrip(':')))
    puertos_open = ",".join(str(p) for p in sorted(puertos))
    resultado_av = "<<< Informacion detallada del escaneo >>>\n"

    print(f"\n\n[+] Iniciando el escaneo avanzado en los puertos abiertos\n")
    escaner = nmap.PortScanner()
    escaner.scan(host, puertos_open, arguments='-Pn -A -sT -T4 --traceroute')

    if host not in escaner.all_hosts():
        resultado_av += "[!] Host sin respuesta\n"
        print(resultado_av)
        return resultado_av

    resultado_av += "\n\n\n<<< Sistemas Operativos encontrados >>>\n"
    for info_os in escaner[host].get('osmatch',[]):
        sistema = info_os.get('name','')
        precision = info_os.get('accuracy','')
        resultado_av += f"\n[+] Sistema Operativo: {sistema} - Precision: {precision}%\n"
        indice = 1
        for info_class in info_os.get('osclass',[]):
            resultado_av += f"\n |-- Perfil {indice}\n"
            resultado_av += f"   |-- Tipo: {info_class.get('type','')}\n"
            resultado_av += f"   |-- Fabricante: {info_class.get('vendor','')}\n"
            resultado_av += f"   |-- Familia: {info_class.get('osfamily','')}\n"
            indice += 1

    resultado_av += "\n\n\n<<< Protocolos encontrados >>>\n\n"
    for protocolo in escaner[host].all_protocols():
        resultado_av += f"[+] Protocolo: {protocolo}"
        puertos = escaner[host][protocolo]
        if not puertos:
            resultado_av += "    (sin puertos reportados)\n"
        for puerto in sorted(puertos):
            info = escaner[host][protocolo][puerto]
            servicio = info.get('name', '')
            version = info.get('product', '')+info.get('version', '')
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



    resultado_av += f"\n\n\n<<< Información de red >>>\n"
    try:
        cmd = ["nmap", "-Pn", "-O", "-p", puertos_open, "--traceroute", host]
        tracerout_salida = subprocess.run(cmd, capture_output=True, text=True)
        dist_red = re.search(r'Network Distance:\s*(\d+)\s*hops?', tracerout_salida.stdout)
        dist_red = dist_red.group(1)
        resultado_av += f"[+] Número de saltos hasta el host: {dist_red}\n"

    except subprocess.CalledProcessError as e:
        resultado_av += "\n[!] Error al ejecutar traceroute con nmap.\n"
        resultado_av += e.output if e.output else str(e)


#    resultado_av += f"\n\n\n<<< Información de red >>>\n"
#    dist_red = escaner[host]['distance']
#    resultado_av += f"[+] Número de saltos hasta el host: {dist_red}\n"

#    traceroute = escaner[host]['trace']
#    if traceroute:
#        resultado_av += "\n[+] Traceroute:\n"
#        for hop_num, hop_info in traceroute.items():
#            resultado_av += f"Salto {hop_num}: {hop_info.get('ipaddr', '')} ({hop_info.get('rtt', '')} ms)\n"
#    else:
#        resultado_av += "\n[!] No se obtuvo información de traceroute.\n"


    print(resultado_av)
    return resultado_av

if __name__ == "__main__":
    try:
        texto = escaneo_host_basico(host, puertos)
        escaneo_host_avanzado(host, texto)
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")