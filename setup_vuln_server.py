import subprocess
import os
import sys

# Función para ejecutar comandos en la terminal y mostrar su salida
def run(cmd):
    print(f"\n[+] Ejecutando: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"[!] Error: {result.stderr}")
    else:
        print(result.stdout)

# Actualiza los paquetes del sistema
def update_system():
    run("apt update && apt upgrade -y")

# Instala paquetes necesarios: servidor web, PHP, MySQL, vsftpd, etc.
def install_packages():
    run("apt install -y apache2 php php-mysqli git mysql-server unzip vsftpd")

# Configura MySQL eliminando la contraseña de root (modo inseguro, solo local)
def setup_mysql():
    run("mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY ''; FLUSH PRIVILEGES;\"")

# Configura el servidor FTP para permitir acceso anónimo y escritura
def configure_vsftpd():
    run("cp /etc/vsftpd.conf /etc/vsftpd.conf.bak")  # Crea respaldo de la configuración original
    run("sed -i 's/^anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf")  # Habilita acceso anónimo
    run("sed -i 's/^#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf")  # Permite escritura
    run("systemctl restart vsftpd")  # Reinicia el servicio FTP

# Instala DVWA (aplicación web vulnerable) y la configura
def install_dvwa():
    run("git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa")  # Clona el repositorio DVWA
    run("chown -R www-data:www-data /var/www/html/dvwa")  # Cambia el dueño de los archivos a Apache
    run("cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php")  # Copia el archivo de configuración base

    # Reemplaza líneas del archivo para que no use variables de entorno
    config_file = "/var/www/html/dvwa/config/config.inc.php"
    with open(config_file, "r") as file:
        lines = file.readlines()

    with open(config_file, "w") as file:
        for line in lines:
            if "$_DVWA[ 'db_user' ]" in line:
                file.write("$_DVWA[ 'db_user' ]     = 'root';\n")
            elif "$_DVWA[ 'db_password' ]" in line:
                file.write("$_DVWA[ 'db_password' ] = '';\n")
            else:
                file.write(line)

    run("systemctl restart apache2")  # Reinicia Apache para aplicar cambios

# Configura el firewall UFW para permitir puertos necesarios
def configure_firewall():
    run("ufw allow 22")    # SSH
    run("ufw allow 21")    # FTP
    run("ufw allow 80")    # HTTP
    run("ufw allow 3306")  # MySQL
    run("ufw allow 8080")  # HTTP alternativo (por si se usa otro puerto)
    run("ufw --force enable")  # Habilita el firewall sin confirmar

# Crea artefactos falsos para simular actividad sospechosa
def fake_artifacts():
    run("mkdir -p /opt/.hidden_data/")  # Carpeta oculta
    run("echo 'root:toor' >> /opt/.hidden_data/shadow_bkp")  # Archivo simulado de contraseñas
    run("echo '192.168.0.1 internal-db' >> /etc/hosts")  # Entrada falsa en el archivo hosts
    run("touch /var/log/apache2/access.log && echo 'GET /login.php?user=admin&pass=1234' >> /var/log/apache2/access.log")  # Acceso sospechoso en log

# Función principal que coordina todas las tareas de instalación y configuración
def main():
    if os.geteuid() != 0:
        print("[!] Este script debe ejecutarse como root (sudo).")
        sys.exit(1)

    update_system()
    install_packages()
    setup_mysql()
    configure_vsftpd()
    install_dvwa()
    fake_artifacts()
    configure_firewall()

    print("\n[✅] Servidor vulnerable configurado.")
    print("DVWA disponible en: http://<TU_IP>/dvwa")
    print("MySQL root sin contraseña (local)")
    print("FTP anónimo habilitado en puerto 21")
    
main()
