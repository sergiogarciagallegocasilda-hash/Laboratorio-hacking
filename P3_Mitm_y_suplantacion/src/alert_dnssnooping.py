#!/usr/bin/env python3
"""
alert_dnssnooping.py - Detector de DNS Snooping / Kaminsky Attack
Detecta ráfagas de consultas DNS a subdominios inexistentes (threshold)
"""

from scapy.all import sniff, DNS, DNSQR, IP, UDP
from datetime import datetime
from collections import defaultdict
import time

# Configuración
THRESHOLD = 10       # número de consultas sospechosas para disparar alerta
WINDOW = 5           # ventana de tiempo en segundos
IFACE = "br-dafe511130b7"

# Contadores por IP origen
query_count  = defaultdict(list)   # {ip: [timestamps]}
alerted_ips  = set()

def alert_dnssnooping(packet):
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return
    if packet[DNS].qr != 0:   # solo queries (qr=0), no respuestas
        return

    ip_src = packet[IP].src
    qname  = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
    now    = time.time()

    # Limpia timestamps fuera de la ventana
    query_count[ip_src] = [t for t in query_count[ip_src] if now - t < WINDOW]
    query_count[ip_src].append(now)

    total = len(query_count[ip_src])
    ts    = datetime.now().strftime("%H:%M:%S")

    print(f"[*] [{ts}] Consulta DNS: {ip_src} -> {qname} ({total}/{THRESHOLD})")

    if total >= THRESHOLD and ip_src not in alerted_ips:
        alerted_ips.add(ip_src)
        print(f"\n[!] [{ts}] DNS SNOOPING DETECTADO")
        print(f"    Origen  : {ip_src}")
        print(f"    Consultas en {WINDOW}s: {total} (umbral: {THRESHOLD})")
        print(f"    Último subdominio: {qname}")
        print(f"    Posible ataque de Kaminsky o enumeración DNS\n")

    # Reset para permitir re-alertar tras nueva ráfaga
    if total >= THRESHOLD:
        alerted_ips.discard(ip_src)
        query_count[ip_src] = []

print(f"[*] Detector DNS activo en {IFACE} (umbral={THRESHOLD} consultas/{WINDOW}s)")
print("[*] Esperando tráfico DNS... (Ctrl+C para detener)\n")
sniff(filter="udp port 53", iface=IFACE, prn=alert_dnssnooping, store=0)
