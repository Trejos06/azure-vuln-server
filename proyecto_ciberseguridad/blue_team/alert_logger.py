"""Alert Logger

Monitorea continuamente ``/var/log/auth.log`` para detectar intentos
fallidos de autenticación SSH. Cuando una IP supera una cantidad de
intentos dentro de una ventana temporal, la bloquea mediante ``ufw``.

Características:
- Realiza copia de seguridad del log y lo trunca al iniciar.
- Sigue el log en tiempo real y maneja rotación (estilo ``tail -F``).
- Mantiene un registro de acciones e IPs bloqueadas.

Ejecutar como root (necesita leer ``/var/log/auth.log`` y ejecutar ``ufw``).
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
import os
import re
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

# Archivo de autenticación a monitorear.
LOG_FILE = "/var/log/auth.log"

# Carpeta para copias de seguridad del log.
BACKUP_DIR = "/var/log/alert_logger_backups"

# Archivo con el historial de IPs bloqueadas.
BLOCKED_IPS_FILE = "/var/log/alert_logger_blocked_ips.txt"

# Archivo de log propio del script (acciones realizadas).
ACTIONS_LOG = "/var/log/alert_logger_actions.log"

# Número de intentos fallidos permitidos antes de bloquear una IP.
THRESHOLD = 5

# Ventana de tiempo (minutos) para contar intentos por IP.
WINDOW_MINUTES = 10

# Pausa entre lecturas cuando no hay líneas nuevas (segundos).
MAX_TAIL_SLEEP = 1.0

# Límite de timestamps a recordar por IP (control de memoria).
RECENT_LINES_WINDOW = 2000

# Expresión regular: detecta líneas del tipo
# "Failed password ... from <IPv4>" y captura la IP (grupo 1).
FAILED_REGEX = re.compile(
    r"Failed password.* from (\d+\.\d+\.\d+\.\d+)"
)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def require_root():
    """Finaliza el programa si no se ejecuta como root."""
    if os.geteuid() != 0:
        print("Este script debe ejecutarse como root (sudo).")
        sys.exit(1)


def log_action(message):
    """Anexa una línea al log de acciones con marca de tiempo."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} - {message}\n"
    try:
        with open(ACTIONS_LOG, "a", encoding="utf-8") as file:
            file.write(line)
    except Exception:
        print(line, end="")


def ensure_paths():
    """Crea directorios/archivos requeridos si no existen."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for path in [BLOCKED_IPS_FILE, ACTIONS_LOG]:
        if not os.path.exists(path):
            open(path, "a", encoding="utf-8").close()


def backup_and_truncate_log():
    """Copia el log actual a ``BACKUP_DIR`` y lo deja vacío."""
    if not os.path.exists(LOG_FILE):
        return

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"auth.log.{stamp}")

    try:
        shutil.copy2(LOG_FILE, backup_path)
        with open(LOG_FILE, "w", encoding="utf-8"):
            pass
        log_action(f"Backup realizado: {backup_path} y log limpio para nuevos registros.")
    except Exception as exc:
        log_action(f"ERROR al respaldar log: {exc}")


def load_blocked_ips():
    """Devuelve un conjunto de IPs previamente bloqueadas."""
    ips = set()
    try:
        with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as file:
            for line in file:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    ips.add(match.group(1))
    except Exception as exc:
        log_action(f"ERROR leyendo {BLOCKED_IPS_FILE}: {exc}")
    return ips


def append_blocked_ip(ip):
    """Registra una IP bloqueada con marca de tiempo."""
    try:
        with open(BLOCKED_IPS_FILE, "a", encoding="utf-8") as file:
            file.write(f"{datetime.now()} - IP bloqueada: {ip}\n")
    except Exception as exc:
        log_action(f"ERROR registrando IP bloqueada {ip}: {exc}")


def ufw_block_ip(ip):
    """Bloquea la IP mediante UFW y registra la salida del comando."""
    try:
        cmd = ["ufw", "deny", "from", ip]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output = result.stdout.strip() or result.stderr.strip()
        log_action(f"UFW: {' '.join(cmd)} -> {output}")
    except Exception as exc:
        log_action(f"ERROR ejecutando UFW para {ip}: {exc}")


def get_file_id(path):
    """Devuelve (st_dev, st_ino) del archivo o ``None`` si no existe."""
    try:
        stats = os.stat(path)
        return stats.st_dev, stats.st_ino
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------

def follow_auth_log():
    """Lee ``auth.log`` en tiempo real y bloquea IPs que superen el limite."""
    ip_attempts = defaultdict(lambda: deque())
    blocked_ips = load_blocked_ips()

    while not os.path.exists(LOG_FILE):
        log_action(f"{LOG_FILE} no existe todavía. Esperando...")
        time.sleep(2)

    current_file_id = get_file_id(LOG_FILE)
    file = open(LOG_FILE, "r", encoding="utf-8", errors="ignore")
    file.seek(0, os.SEEK_END)

    log_action(
        f"Monitoreando {LOG_FILE} (limite={THRESHOLD} intentos / "
        f"{WINDOW_MINUTES} min)."
    )

    window = timedelta(minutes=WINDOW_MINUTES)

    try:
        while True:
            line = file.readline()
            if not line:
                new_file_id = get_file_id(LOG_FILE)
                if new_file_id != current_file_id:
                    try:
                        file.close()
                    except Exception:
                        pass
                    time.sleep(0.2)
                    file = open(LOG_FILE, "r", encoding="utf-8", errors="ignore")
                    current_file_id  = new_file_id
                    log_action("Detectada rotación de log. Reabriendo archivo.")
                else:
                    time.sleep(MAX_TAIL_SLEEP)
                continue

            match = FAILED_REGEX.search(line)
            if not match:
                continue

            ip = match.group(1)
            now = datetime.now()

            attempts = ip_attempts[ip]
            attempts.append(now)

            cutoff = now - window
            while attempts and attempts[0] < cutoff:
                attempts.popleft()

            if len(attempts) > RECENT_LINES_WINDOW:
                while len(attempts) > RECENT_LINES_WINDOW:
                    attempts.popleft()

            if len(attempts) >= THRESHOLD and ip not in blocked_ips:
                log_action(
                    f"Limite superado por {ip}: {len(attempts)} intentos en "
                    f"{WINDOW_MINUTES} min. Bloqueando..."
                )
                ufw_block_ip(ip)
                append_blocked_ip(ip)
                blocked_ips.add(ip)

    except KeyboardInterrupt:
        log_action("Interrupción manual (Ctrl+C). Saliendo.")
    finally:
        try:
            file.close()
        except Exception:
            pass


def main():
    """Punto de entrada del programa."""

def main():
    """Punto de entrada del programa."""
    require_root()
    print("Corriendo en root")
    ensure_paths()
    print("Log Paths validados")
    backup_and_truncate_log()
    print("Backup realizado de manera correcta")
    print("Validando Logs en vivo")
    follow_auth_log()

if __name__ == "__main__":
    main()
