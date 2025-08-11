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
    resultado = "<<< Puertos abiertos encontrados >>>\n"

    if host not in escaner.all_hosts():
        resultado += "[!] Host sin respuesta\n"
        print(resultado)
        return resultado

    for protocolo in escaner[host].all_protocols():
        resultado += f"\n[+] Protocolo: {protocolo}\n"
        puertos = escaner[host][protocolo]
        if not puertos:
            resultado += "    (sin puertos reportados)\n"
        for puerto in sorted(puertos):
            servicio = escaner[host][protocolo][puerto]['name']
            resultado += f"    Puerto {puerto}: open ({servicio})\n"
    print(resultado)
    return resultado

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

    print(f"[+] Iniciando el escaneo avanzado en los puertos abiertos\n")
    escaner = nmap.PortScanner()
    escaner.scan(host, puertos_open, arguments='-Pn -A -sT -T4')
    resultado = "<<< Informacion detallada del escaneo >>>\n"

    if host not in escaner.all_hosts():
        resultado += "[!] Host sin respuesta\n"
        print(resultado)
        return resultado
    
    os_dict = {} # Diccionario con los SOs encontrados en el escaneo
    print()
    for info_os in escaner[host]['osmatch']:
        os_dict[info_os["name"]] = int(info_os['accuracy'])
    
    os_probable = max(os_dict, key=os_dict.get) # Obetener el SO más probable
    acc_percent = os_dict[os_probable] 

    resultado += f"\n Sistema Operativo encontrado: {os_probable} - Precision: {acc_percent}%\n"

    for protocolo in escaner[host].all_protocols():
        resultado += f"\n[+] Protocolo: {protocolo}\n"
        puertos = escaner[host][protocolo]
        if not puertos:
            resultado += "    (sin puertos reportados)\n"
        for puerto in sorted(puertos):
            info = escaner[host][protocolo][puerto]
            servicio = info.get('name', '')
            version = info.get('product', '')+info.get('version', '')
            scripts = info.get('script', {})

            resultado += f"\n\n + Puerto {puerto}/{protocolo}"
            resultado += f"\n |-- Estado: {info.get('state', '')}"
            resultado += f"\n |-- Servicio: {servicio}"
            resultado += f"\n |-- Version: {version}"
            resultado += f"\n |-- Info Extra: {info.get('extrainfo', '')}\n"

            if scripts:
                resultado += f"\n NSE SCRIPTS:"
                for script_name, script_salida in scripts.items():
                    resultado += f"\n |-- {script_name}: {script_salida}"
    print(resultado)
    return resultado

if __name__ == "__main__":
    try:
        texto = escaneo_host_basico(host, puertos)
        escaneo_host_avanzado(host, texto)
    except Exception as e:
        print(f"[!] Error durante el escaneo: {e}")